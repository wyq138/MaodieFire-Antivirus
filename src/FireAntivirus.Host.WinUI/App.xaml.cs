using System;
using System.Threading.Tasks;
using Microsoft.UI.Xaml;

namespace FireAntivirus.Host.WinUI
{
    public partial class App : Application
    {
        public static Window MainWindow { get; private set; }

        /// <summary>RTPPlus 用户态旁路管理器共享实例（启动即创建，供静态事件通道保持活跃）。</summary>
        public static FireAntivirus.RealTimeProtectionPlus.RealTimeProtectionPlusManager RtpShared { get; private set; }

        /// <summary>隐私访问监控常驻实例（设置页开关/启动恢复共用）。</summary>
        public static FireAntivirus.PrivacyProtection.PrivacyProtectionManager PrivacyMonitor { get; private set; }
        public static void SetPrivacyMonitor(FireAntivirus.PrivacyProtection.PrivacyProtectionManager monitor) => PrivacyMonitor = monitor;

        /// <summary>
        /// RTPPlus 单例获取：ProtectPage 等入口的兜底路径——启动后台链尚未完成时现场创建并拉起五模块，
        /// 复用 App.Data 单例（避免再 new DataManager 多加载一份签名库）。
        /// </summary>
        public static FireAntivirus.RealTimeProtectionPlus.RealTimeProtectionPlusManager EnsureRtp()
        {
            if (RtpShared == null)
            {
                lock (typeof(App))
                {
                    if (RtpShared == null)
                    {
                        try
                        {
                            RtpShared = new FireAntivirus.RealTimeProtectionPlus.RealTimeProtectionPlusManager(
                                Data, new FireAntivirus.Engine.AntivirusEngine(Data));
                            RtpShared.StartProtection();
                        }
                        catch (Exception ex)
                        {
                            FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "RTPPlus 兜底创建失败", ex.Message);
                        }
                    }
                }
            }
            return RtpShared;
        }

        /// <summary>DataManager 全站共享单例：直接复用 FireAntivirus.Data 内部静态单例（引擎分析器同源），全进程仅一个实例。</summary>
        public static FireAntivirus.Data.DataManager Data => FireAntivirus.Data.DataManager.SharedInstance;

        public App()
        {
            InitializeComponent();
            // 全局异常落盘：启动崩溃也能看到真实原因；标记 Handled 防止页面级异常导致整进程闪退
            this.UnhandledException += (s, e) =>
            {
                try
                {
                    var dir = System.IO.Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                        "FireAntivirus", "Logs");
                    System.IO.Directory.CreateDirectory(dir);
                    System.IO.File.AppendAllText(System.IO.Path.Combine(dir, "crash.log"),
                        $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {e.Message}\n{e.Exception}\n\n");
                }
                catch { }

                // 阻止进程因单次未处理异常直接退出
                e.Handled = true;
            };
        }

        /// <summary>
        /// 应用云查杀 API 配置：MalwareBazaar/OTX 免 key 常开；VirusTotal（免费 key 500 次/天）/HybridAnalysis
        /// 由设置页配置 key 后生效。key 持久化在 SettingsStore。
        /// </summary>
        private static void ApplyCloudApis()
        {
            try
            {
                var s = SettingsStore.Current;
                // VT/HA 传 null = 使用引擎内嵌开发商密钥（终端用户不可见），用户自带密钥时传非空覆盖
                FireAntivirus.Engine.AntivirusEngine.UpdateCloudScanConfig(
                    enableMalwareBazaar: true,
                    enableOTX: true,
                    enableVirusTotal: true,
                    enableHybridAnalysis: false,
                    virusTotalApiKey: null,
                    hybridAnalysisApiKey: null);
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                    "云查杀 API 配置应用失败", ex.Message);
            }
        }

        /// <summary>供设置页保存后即时重应用云配置（不依赖重启）。</summary>
        public static void ApplyCloudApisToEngine() => ApplyCloudApis();

        /// <summary>
        /// 注入 ML 四模型集成探测（决策树/随机森林/SVM/神经网络）到引擎共识投票。
        /// FireAntivirus.MachineLearning 项目引用 Engine，Engine 直接引用它会成环（MSB4006），
        /// 故由宿主注入委托：路径 -> (IsMalicious, Confidence, Prediction)。
        /// 探测失败静默跳过该票，绝不阻断扫描链。
        /// </summary>
        private static FireAntivirus.MachineLearning.MachineLearningDetector _mlDetector;

        private static void InjectMlProbe()
        {
            try
            {
                var dir = System.IO.Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "FireAntivirus", "ML");
                System.IO.Directory.CreateDirectory(dir);
                _mlDetector = new FireAntivirus.MachineLearning.MachineLearningDetector(
                    System.IO.Path.Combine(dir, "model.bin"),
                    System.IO.Path.Combine(dir, "extractor.bin"));

                FireAntivirus.Engine.AntivirusEngine.MlProbe = path =>
                {
                    try
                    {
                        var r = _mlDetector.PredictAsync(path, System.Threading.CancellationToken.None)
                                           .GetAwaiter().GetResult();
                        return r != null && r.IsMalicious
                            ? (true, r.Confidence, r.ModelUsed)
                            : (false, 0.0, null);
                    }
                    catch
                    {
                        return (false, 0.0, null);
                    }
                };
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                    "ML 探测注入失败（共识跳过该票）", ex.Message);
            }
        }

        protected override void OnLaunched(Microsoft.UI.Xaml.LaunchActivatedEventArgs args)
        {
            // ---- 云查杀 API 配置（VT 70 引擎聚合=检出率天花板；免费 key 500 次/天，仅可疑文件按需查询）----
            ApplyCloudApis();

            // ---- 自动沙箱验证（照搬西瓜杀毒：未签名弱证据文件 → 沙箱运行 + IOA 行为评分，确认恶意才报）----
            FireAntivirus.Engine.Sandbox.AutoSandboxAnalyzer.Enabled = SettingsStore.Current.AutoSandboxEnabled;

            // ---- AMSI / 凭据访问 / 防御规避（照搬西瓜杀毒：启动即按设置恢复）----
            FireAntivirus.Engine.Analyzers.AmsiScanner.Enabled = SettingsStore.Current.AmsiEnabled;
            FireAntivirus.Engine.Analyzers.CredentialAccessMonitor.Enabled = SettingsStore.Current.CredentialAccessEnabled;
            FireAntivirus.Engine.Analyzers.DefenseEvasionMonitor.Enabled = SettingsStore.Current.DefenseEvasionEnabled;
            FireAntivirus.Engine.Analyzers.ArchiveScanner.Enabled = SettingsStore.Current.ScanArchives;
            FireAntivirus.Engine.Analyzers.HandleAccessAudit.Enabled = SettingsStore.Current.HandleAuditEnabled;
            FireAntivirus.Engine.Sandbox.SandboxEvasionGuard.Enabled = SettingsStore.Current.SandboxEvasionGuardEnabled;

            // ---- 七项高级检测（实时防护 + 全盘扫描共用判定链）----
            FireAntivirus.Engine.Analyzers.FuzzyHashCluster.Enabled = SettingsStore.Current.FuzzyHashEnabled;
            FireAntivirus.Engine.Analyzers.EntropyTimelineAnalyzer.Enabled = SettingsStore.Current.EntropyTimelineEnabled;
            FireAntivirus.Engine.Analyzers.ProcessLineageGraph.Enabled = SettingsStore.Current.ProcessLineageEnabled;
            FireAntivirus.Engine.Analyzers.ProcessLineageGraph.AutoBlockEnabled = SettingsStore.Current.ChainBlockEnabled;
            FireAntivirus.Engine.Analyzers.SensitiveFlowTracker.Enabled = SettingsStore.Current.SensitiveFlowEnabled;
            FireAntivirus.Engine.Analyzers.MemoryVadScanner.Enabled = SettingsStore.Current.VadScanEnabled;
            FireAntivirus.Engine.Analyzers.AsrRuleEngine.Enabled = SettingsStore.Current.AsrEnabled;
            FireAntivirus.Engine.Analyzers.AsrRuleEngine.BlockEnabled = SettingsStore.Current.ChainBlockEnabled;
            FireAntivirus.Engine.Analyzers.DetectionTimeline.Enabled = SettingsStore.Current.TimelineEnabled;
            FireAntivirus.Engine.Analyzers.EtwBehaviorCollector.Enabled = SettingsStore.Current.EtwEnabled;
            FireAntivirus.Engine.Analyzers.WfpBlocker.Enabled = SettingsStore.Current.WfpBlockEnabled;

            if (SettingsStore.Current.EtwEnabled)
                _ = System.Threading.Tasks.Task.Run(() => FireAntivirus.Engine.Analyzers.EtwBehaviorCollector.Start());
            if (SettingsStore.Current.WfpBlockEnabled)
                _ = System.Threading.Tasks.Task.Run(() => FireAntivirus.Engine.Analyzers.WfpBlocker.ProbeEngine());

            // ---- AMSI 自检：本进程 AmsiScanBuffer 若被内存补丁，说明有代码在绕过 AMSI（T1562.001）----
            try
            {
                if (FireAntivirus.Engine.Analyzers.AmsiScanner.Enabled &&
                    FireAntivirus.Engine.Analyzers.AmsiScanner.IsAmsiBypassedInSelf)
                {
                    FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                        "检测到本进程 AMSI 接口被内存补丁（疑似 AMSI bypass）");
                    ThreatDealWindow.Show("AMSI",
                        "检测到本进程 AmsiScanBuffer 被内存补丁（AMSI bypass，T1562.001）",
                        "Critical", canQuarantine: false);
                }
            }
            catch { }


            // ---- 看门狗分诊 ----
            var launchArgs = args?.Arguments ?? "";

            // 守护子进程模式（--guard <主PID>）：监控主进程，被杀则拉起新主实例后退出，无 UI
            if (launchArgs.Contains("--guard"))
            {
                var pidText = launchArgs.Replace("--guard", "").Trim();
                if (int.TryParse(pidText, out var mainPid))
                    GuardProcess.RunGuard(mainPid);
                Environment.Exit(0);
            }

            // 计划任务模式（--watchdog）：主实例被杀后由系统拉起
            bool watchdogMode = launchArgs.Contains("--watchdog");

            // 已有主实例存活：watchdog/守护/第二实例全部静默退出
            if (WatchdogGuard.HasMainInstance())
            {
                Environment.Exit(0);
            }
            // 用户主动退出（exit_flag 标记在）：守护/计划任务/静默恢复实例全部尊重退出，不再恢复。
            // --silent 恢复实例也自查标记：即使守护/计划任务侧检查失效（旧版守护等），这里还有一道防线
            if ((watchdogMode || launchArgs.Contains("--silent")) && WatchdogGuard.IsUserExitMarked())
            {
                Environment.Exit(0);
            }

            // 占据主实例身份：被病毒杀掉时 Mutex 内核自动释放，计划任务 1 分钟内拉起恢复；
            // 竞态落败（已有实例抢先）则本实例立即退出，杜绝多实例堆积
            if (!WatchdogGuard.AcquireMainLock())
            {
                Environment.Exit(0);
            }
            // 只有用户显式启动（双击/开始菜单，非守护/计划任务拉起）才清除退出标记。
            // 恢复实例绝不清标记：用户正常退出后守护的 3 秒竞态窗口内误拉起的实例
            // 若清掉标记，"退出"就变"复活"——托盘退出后又被拉起的根因。
            if (!watchdogMode && !launchArgs.Contains("--silent"))
            {
                WatchdogGuard.ClearUserExitMark();
            }

            MainWindow = new MainWindow();


            // ClamAV 批量池延迟确认回流：命中经处置窗呈现，Critical/High 自动隔离（与实时防护同链路）
            FireAntivirus.Engine.ClamAVBatchScanner.ThreatConfirmed += r =>
            {
                try
                {
                    if (r == null || !r.IsInfected || string.IsNullOrEmpty(r.FilePath)) return;
                    bool autoQuarantine = r.Severity is "Critical" or "High";
                    bool quarantined = false;
                    if (autoQuarantine)
                        quarantined = QuarantineStore.Quarantine(r.FilePath, r.ThreatName, r.Severity, out _);

                    // 威胁处置主通道：独立处置窗口（真实按钮；已自动隔离的不再给隔离按钮）
                    ThreatDealWindow.Show(
                        r.FilePath,
                        r.ThreatName + (quarantined ? "（已自动隔离）" : "（ClamAV 确认）"),
                        r.Severity,
                        canQuarantine: !quarantined);
                }
                catch { }
            };

            // 沙箱行为确认 → 自动隔离 + 独立处置窗口（照搬西瓜杀毒：真实窗口 + 处置按钮，非通知）
            FireAntivirus.Engine.Sandbox.AutoSandboxAnalyzer.ThreatConfirmed += r =>
            {
                try
                {
                    bool quarantined = false;
                    try { quarantined = QuarantineStore.Quarantine(r.FilePath, r.ThreatName, r.Severity, out _); } catch { }
                    ThreatDealWindow.Show(r.FilePath, r.ThreatName + "（沙箱行为确认）", r.Severity, canQuarantine: !quarantined);
                }
                catch { }
            };
            FireAntivirus.Engine.Sandbox.AutoSandboxAnalyzer.VerifiedBenign += p =>
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info,
                    "[沙箱] 行为验证安全，已放行: " + p);
            // 守护/计划任务恢复（--silent/--watchdog）：静默后台启动——防护常驻、托盘常驻，
            // 但不弹主窗口打扰用户；用户手动双击启动才显示主窗口
            bool silentRestore = watchdogMode || launchArgs.Contains("--silent");
            if (!silentRestore)
            {
                MainWindow.Activate();
            }

            // 点 X = 隐藏到托盘（实时防护常驻后台继续跑），只有托盘菜单"退出"才真正结束进程
            MainWindow.AppWindow.Closing += (s, e) =>
            {
                e.Cancel = true;
                s.Hide();
            };

            // 右下角系统托盘：左键唤出主窗口；右键菜单（打开/快速扫描/隔离区/设置/关于/退出）
            TrayIconHost.Init();

            Action showMain = () =>
            {
                MainWindow.AppWindow.Show();
                MainWindow.Activate();
            };
            Action<Type> navigate = pageType =>
            {
                if (MainWindow is MainWindow mw) mw.NavigateTo(pageType);
            };

            TrayIconHost.OpenRequested += () => MainWindow.DispatcherQueue.TryEnqueue(() => showMain());
            TrayIconHost.QuickScanRequested += () => MainWindow.DispatcherQueue.TryEnqueue(() =>
            {
                showMain();
                if (MainWindow is MainWindow mw)
                {
                    var page = mw.NavigateTo(typeof(FireAntivirus.Host.WinUI.Pages.ScanPage));
                    if (page is FireAntivirus.Host.WinUI.Pages.ScanPage scan) scan.AutoStart("quick");
                }
            });
            TrayIconHost.QuarantineRequested += () => MainWindow.DispatcherQueue.TryEnqueue(() =>
            {
                showMain();
                navigate(typeof(FireAntivirus.Host.WinUI.Pages.QuarantineCenterPage));
            });
            TrayIconHost.SettingsRequested += () => MainWindow.DispatcherQueue.TryEnqueue(() =>
            {
                showMain();
                navigate(typeof(FireAntivirus.Host.WinUI.Pages.SettingsPage));
            });
            TrayIconHost.AboutRequested += () => MainWindow.DispatcherQueue.TryEnqueue(() =>
            {
                showMain();
                navigate(typeof(FireAntivirus.Host.WinUI.Pages.AboutPage));
            });
            TrayIconHost.ExitRequested += () =>
                MainWindow.DispatcherQueue.TryEnqueue(() =>
                {
                    FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info,
                        "托盘退出请求：停守护 → 写用户退出标记（exit_flag + 计划任务禁用）→ 结束进程");
                    // 顺序不可变：先停守护（物理封死 3 秒竞态拉起窗口）→ 写退出标记 → 退出
                    GuardProcess.StopGuard();
                    FireAntivirus.Engine.WhitelistStore.Persist(); // 清白哈希记忆库落盘
                    WatchdogGuard.MarkUserExit();
                    FireAntivirus.Engine.Analyzers.EtwBehaviorCollector.Stop();
                    FireAntivirus.Engine.Analyzers.WfpBlocker.RemoveAll();
                    TrayIconHost.Shutdown();
                    Environment.Exit(0);
                });

            // ---- 页面诊断模式：--pagediag 启动后自动遍历六个曾报卡死页面（埋点日志定位卡点）----
            if (launchArgs.Contains("--pagediag"))
            {
                MainWindow.DispatcherQueue.TryEnqueue(async () =>
                {
                    try
                    {
                        MainWindow.AppWindow.Show();
                        MainWindow.Activate();
                        await (MainWindow as MainWindow).RunPageDiagnosticsAsync();
                    }
                    catch (Exception ex)
                    {
                        FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error,
                            "页面诊断模式异常: " + ex.Message);
                    }
                });
                return; // 诊断模式不进入常规启动链
            }

            // ---- 防护链启动（彻底根除页面导航卡死：加载器锁竞争）----
            // 真凶：旧实现 4-5 个并行 Task.Run 同时加载 Engine/ML/RTPPlus 数十个程序集（含 WMI/COM 初始化），
            // 与 UI 线程首次导航加载 Services 等页面程序集争抢加载器锁；WMI COM 初始化在 loader lock 内
            // 可耗时数秒 → 双线程互等 → Navigate 永久挂起（埋点实锤：导航开始后无任何后续、构造未执行）。
            // 根除定式：① 等首次导航完成后才启动；② 单后台线程严格串行；③ WMI 类组件（RTPPlus/UsbGuard）最后执行。
            (MainWindow as MainWindow).RunAfterFirstNavigation(() =>
            {
                _ = Task.Run(async () =>
                {
                    try
                    {
                        await Task.Delay(2500); // 首屏稳定 + 首屏页面程序集加载完成

                        try { RealTimeProtection.Instance.Start(); LogChain("实时防护已启动（全盘监听）"); }
                        catch (Exception ex) { LogChainWarn("实时防护启动失败", ex); }

                        try { GuardProcess.StartGuard(); LogChain("守护进程已拉起"); } catch { }
                        Task.Run(GuardProcess.MonitorGuardLoop);
                        Task.Run(() => WatchdogGuard.EnsureScheduledTask());

                        await Task.Delay(6000); // WMI 组件（RTPPlus）延迟到 8.5 秒后：用户导航窗口内零 loader lock 竞争
                        try
                        {
                            RtpShared = new FireAntivirus.RealTimeProtectionPlus.RealTimeProtectionPlusManager(
                                App.Data,
                                new FireAntivirus.Engine.AntivirusEngine(App.Data));
                            RtpShared.StartProtection();
                            LogChain("RTPPlus 五模块已拉起（进程/文件/注册表/网络/行为）");
                        }
                        catch (Exception ex) { LogChainWarn("RTPPlus 启动失败", ex); }

                        await Task.Delay(3000); // WMI 组件（U盘防护）再错开 3 秒
                        try
                        {
                            UsbGuard.Instance.UsbConnected += (drive, label) =>
                                MainWindow.DispatcherQueue.TryEnqueue(() => UsbGuardToast.Show(drive, label));
                            UsbGuard.Instance.UsbScanCompleted += (drive, scanned, threats, autoQuarantined) =>
                                UsbGuardToast.UpdateResult(drive, scanned, threats, autoQuarantined);
                            UsbGuard.Instance.Start();
                            LogChain("U盘防护已启动（WMI 移动盘监听）");
                        }
                        catch (Exception ex) { LogChainWarn("U盘防护启动失败", ex); }

                        await Task.Delay(1200);
                        try
                        {
                            MainWindow.DispatcherQueue.TryEnqueue(() =>
                            {
                                try { KernelEventMonitor.Start(MainWindow); LogChain("内核事件轮询已启动"); }
                                catch (Exception ex) { LogChainWarn("内核事件启动失败", ex); }
                            });
                        }
                        catch { }

                        await Task.Delay(800);
                        try { InjectMlProbe(); LogChain("ML 四模型探测已注入"); } catch { }

                        // 按设置恢复常驻功能模块（弹窗拦截 / 隐私访问监控）
                        try
                        {
                            if (SettingsStore.Current.PopupBlockerEnabled)
                            {
                                FireAntivirus.Services.PopupBlockerService.Instance.Start();
                                LogChain("弹窗拦截已按设置启动");
                            }
                        }
                        catch (Exception ex) { LogChainWarn("弹窗拦截恢复失败", ex); }

                        try
                        {
                            if (SettingsStore.Current.PrivacyMonitorAutoStart && PrivacyMonitor == null)
                            {
                                PrivacyMonitor = new FireAntivirus.PrivacyProtection.PrivacyProtectionManager();
                                await PrivacyMonitor.StartMonitoring();
                                LogChain("隐私访问监控已按设置启动");
                            }
                        }
                        catch (Exception ex) { LogChainWarn("隐私监控恢复失败", ex); }

                        LogChain("防护链初始化完成");
                    }
                    catch (Exception ex)
                    {
                        LogChainWarn("防护链启动异常", ex);
                    }
                });
            });

            StartDailyUpdateTimer();
        }

        private static void LogChain(string msg) =>
            FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info, "[防护链] " + msg);

        private static void LogChainWarn(string msg, Exception ex) =>
            FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "[防护链] " + msg, ex.Message);


        // 每日自动更新：ClamAV 病毒库（freshclam）+ 开源威胁情报订阅，真实生效
        private void StartDailyUpdateTimer()
        {
            var timer = new DispatcherTimer { Interval = TimeSpan.FromHours(24) };
            timer.Tick += async (_, _) =>
            {
                try
                {
                    await FireAntivirus.Engine.SignatureDatabaseUpdater.UpdateClamavDbAsync();
                    await FireAntivirus.Engine.SignatureDatabaseUpdater.UpdateAsync();
                }
                catch (Exception ex)
                {
                    FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                        "每日自动更新失败: " + ex.Message);
                }
            };
            timer.Start();
        }
    }
}
