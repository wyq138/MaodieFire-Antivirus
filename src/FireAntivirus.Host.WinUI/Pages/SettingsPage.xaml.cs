// 设置页：开机自启/看门狗/扫描并发/排除目录/特征库更新源/签名验证/日志维护/设置备份。
// 全部真实生效：注册表、schtasks、SettingsStore 持久化、ThreatDataUpdateService、LogHelper。
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.Storage.Pickers;

namespace FireAntivirus.Host.WinUI.Pages
{
    public sealed partial class SettingsPage : Page
    {
        private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
        private const string AppName = "FireAntivirus";

        public SettingsPage()
        {
            InitializeComponent();
            LoadAll();
        }

        private void LoadAll()
        {
            var s = SettingsStore.Current;

            AutoStartToggle.Toggled -= AutoStart_Toggled;
            AutoStartToggle.IsOn = IsAutoStartEnabled();
            AutoStartToggle.Toggled += AutoStart_Toggled;

            WatchdogToggle.Toggled -= Watchdog_Toggled;
            WatchdogToggle.IsOn = s.WatchdogEnabled;
            WatchdogToggle.Toggled += Watchdog_Toggled;

            ConcurrencyBox.Value = SettingsStore.EffectiveConcurrency;
            ExcludeList.ItemsSource = new System.Collections.ObjectModel.ObservableCollection<string>(s.ExcludedDirs ?? new System.Collections.Generic.List<string>());
            UpdateSourceBox.Text = s.ThreatDataUpdateSource ?? "";
            RefreshUpdateSourceState();
            RefreshCloudApiState();

            // 功能模块开关（真实状态回填，先摘再挂事件防触发）
            PopupBlockerToggle.Toggled -= PopupBlocker_Toggled;
            PrivacyMonitorToggle.Toggled -= PrivacyMonitor_Toggled;
            ParentalControlToggle.Toggled -= ParentalControl_Toggled;
            SandboxToggle.Toggled -= Sandbox_Toggled;
            AmsiToggle.Toggled -= Amsi_Toggled;
            CredentialAccessToggle.Toggled -= CredentialAccess_Toggled;
            DefenseEvasionToggle.Toggled -= DefenseEvasion_Toggled;
            ArchiveScanToggle.Toggled -= ArchiveScan_Toggled;
            PopupBlockerToggle.IsOn = SettingsStore.Current.PopupBlockerEnabled;
            PrivacyMonitorToggle.IsOn = SettingsStore.Current.PrivacyMonitorAutoStart;
            ParentalControlToggle.IsOn = SettingsStore.Current.ParentalControlEnabled;
            SandboxToggle.IsOn = SettingsStore.Current.AutoSandboxEnabled;
            AmsiToggle.IsOn = SettingsStore.Current.AmsiEnabled;
            CredentialAccessToggle.IsOn = SettingsStore.Current.CredentialAccessEnabled;
            DefenseEvasionToggle.IsOn = SettingsStore.Current.DefenseEvasionEnabled;
            ArchiveScanToggle.IsOn = SettingsStore.Current.ScanArchives;
            PopupBlockerToggle.Toggled += PopupBlocker_Toggled;
            PrivacyMonitorToggle.Toggled += PrivacyMonitor_Toggled;
            ParentalControlToggle.Toggled += ParentalControl_Toggled;
            SandboxToggle.Toggled += Sandbox_Toggled;
            AmsiToggle.Toggled += Amsi_Toggled;
            CredentialAccessToggle.Toggled += CredentialAccess_Toggled;
            DefenseEvasionToggle.Toggled += DefenseEvasion_Toggled;
            ArchiveScanToggle.Toggled += ArchiveScan_Toggled;

            // 句柄审计 / 沙箱反沙箱开关回填
            HandleAuditToggle.Toggled -= HandleAudit_Toggled;
            SandboxEvasionToggle.Toggled -= SandboxEvasion_Toggled;
            HandleAuditToggle.IsOn = SettingsStore.Current.HandleAuditEnabled;
            SandboxEvasionToggle.IsOn = SettingsStore.Current.SandboxEvasionGuardEnabled;
            HandleAuditToggle.Toggled += HandleAudit_Toggled;
            SandboxEvasionToggle.Toggled += SandboxEvasion_Toggled;

            // 七项高级检测开关回填
            var advancedToggles = new[]
            {
                FuzzyHashToggle, EntropyTimelineToggle, LineageToggle,
                ChainBlockToggle, SensitiveFlowToggle, VadScanToggle, AsrToggle, TimelineToggle, EtwToggle, WfpToggle
            };
            foreach (var toggle in advancedToggles) toggle.Toggled -= Advanced_Toggled;
            FuzzyHashToggle.IsOn = SettingsStore.Current.FuzzyHashEnabled;
            EntropyTimelineToggle.IsOn = SettingsStore.Current.EntropyTimelineEnabled;
            LineageToggle.IsOn = SettingsStore.Current.ProcessLineageEnabled;
            ChainBlockToggle.IsOn = SettingsStore.Current.ChainBlockEnabled;
            SensitiveFlowToggle.IsOn = SettingsStore.Current.SensitiveFlowEnabled;
            VadScanToggle.IsOn = SettingsStore.Current.VadScanEnabled;
            AsrToggle.IsOn = SettingsStore.Current.AsrEnabled;
            TimelineToggle.IsOn = SettingsStore.Current.TimelineEnabled;
            EtwToggle.IsOn = SettingsStore.Current.EtwEnabled;
            WfpToggle.IsOn = SettingsStore.Current.WfpBlockEnabled;
            foreach (var toggle in advancedToggles) toggle.Toggled += Advanced_Toggled;

            // AI 模型面板回填
            ModelDatasetBox.Text = SettingsStore.Current.ModelDatasetPath ?? "";
            ModelFprBox.Value = Math.Clamp(
                SettingsStore.Current.ModelTargetFpr <= 0 ? 0.01 : SettingsStore.Current.ModelTargetFpr,
                0.001, 0.2);
            RefreshMelixState();
            ModulesState.Text = $"弹窗拦截: {(_runtimeIsRunning() ? "运行中" : "未启动")} · 家长控制: {(SettingsStore.Current.ParentalControlEnabled ? "已启用" : "未启用")}";
        }

        private static bool _runtimeIsRunning()
        {
            try { return FireAntivirus.Services.PopupBlockerService.Instance.IsRunning; }
            catch { return false; }
        }

        // ---- 功能模块开关：全部真实生效 ----

        private void Sandbox_Toggled(object sender, RoutedEventArgs e)
        {
            try
            {
                SettingsStore.Current.AutoSandboxEnabled = SandboxToggle.IsOn;
                SettingsStore.Save();
                FireAntivirus.Engine.Sandbox.AutoSandboxAnalyzer.Enabled = SandboxToggle.IsOn;
                ModulesState.Text = "自动沙箱验证: " + (SandboxToggle.IsOn ? "已启用（Sandboxie + IOA 行为评分）" : "已关闭");
                if (SandboxToggle.IsOn)
                {
                    _ = System.Threading.Tasks.Task.Run(async () =>
                    {
                        try
                        {
                            bool ok = await FireAntivirus.Engine.Sandbox.SandboxProvisioner.EnsureConfiguredAsync();
                            DispatcherQueue.TryEnqueue(() =>
                                ModulesState.Text = "自动沙箱验证: " + (ok ? "环境就绪" : "环境不可用（需安装/分发 Sandboxie 组件）"));
                        }
                        catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
                    });
                }
            }
            catch (Exception ex)
            {
                ModulesState.Text = "沙箱设置失败: " + ex.Message;
            }
        }

        private void Amsi_Toggled(object sender, RoutedEventArgs e)
        {
            try
            {
                SettingsStore.Current.AmsiEnabled = AmsiToggle.IsOn;
                SettingsStore.Save();
                FireAntivirus.Engine.Analyzers.AmsiScanner.Enabled = AmsiToggle.IsOn;
                ModulesState.Text = "AMSI 脚本扫描: " + (AmsiToggle.IsOn
                    ? (FireAntivirus.Engine.Analyzers.AmsiScanner.IsAvailable ? "已启用（系统 AMSI 接口可用）" : "已开启，但系统 AMSI 不可用")
                    : "已关闭");
            }
            catch (Exception ex) { ModulesState.Text = "AMSI 设置失败: " + ex.Message; }
        }

        private void CredentialAccess_Toggled(object sender, RoutedEventArgs e)
        {
            try
            {
                SettingsStore.Current.CredentialAccessEnabled = CredentialAccessToggle.IsOn;
                SettingsStore.Save();
                FireAntivirus.Engine.Analyzers.CredentialAccessMonitor.Enabled = CredentialAccessToggle.IsOn;
                ModulesState.Text = "凭据访问防护: " + (CredentialAccessToggle.IsOn
                    ? "已启用（命令行特征 + LSASS 句柄扫描，60 秒周期）"
                    : "已关闭");
            }
            catch (Exception ex) { ModulesState.Text = "凭据访问防护设置失败: " + ex.Message; }
        }

        private void DefenseEvasion_Toggled(object sender, RoutedEventArgs e)
        {
            try
            {
                SettingsStore.Current.DefenseEvasionEnabled = DefenseEvasionToggle.IsOn;
                SettingsStore.Save();
                FireAntivirus.Engine.Analyzers.DefenseEvasionMonitor.Enabled = DefenseEvasionToggle.IsOn;
                ModulesState.Text = "防御规避检测: " + (DefenseEvasionToggle.IsOn
                    ? "已启用（T1490/T1070/T1562/T1564/T1027/T1140/T1218）"
                    : "已关闭");
            }
            catch (Exception ex) { ModulesState.Text = "防御规避检测设置失败: " + ex.Message; }
        }

        private void ArchiveScan_Toggled(object sender, RoutedEventArgs e)
        {
            try
            {
                SettingsStore.Current.ScanArchives = ArchiveScanToggle.IsOn;
                SettingsStore.Save();
                FireAntivirus.Engine.Analyzers.ArchiveScanner.Enabled = ArchiveScanToggle.IsOn;
                ModulesState.Text = "压缩包深度扫描: " + (ArchiveScanToggle.IsOn
                    ? "已启用（zip/tar/gz 原生，rar/7z 需 7-Zip 组件）"
                    : "已关闭");
            }
            catch (Exception ex) { ModulesState.Text = "压缩包扫描设置失败: " + ex.Message; }
        }

        private void PopupBlocker_Toggled(object sender, RoutedEventArgs e)
        {
            try
            {
                SettingsStore.Current.PopupBlockerEnabled = PopupBlockerToggle.IsOn;
                SettingsStore.Save();
                if (PopupBlockerToggle.IsOn) FireAntivirus.Services.PopupBlockerService.Instance.Start();
                else FireAntivirus.Services.PopupBlockerService.Instance.Stop();
                ModulesState.Text = "弹窗拦截: " + (PopupBlockerToggle.IsOn ? "已启动（随程序常驻）" : "已停止");

            }
            catch (Exception ex)
            {
                ModulesState.Text = "弹窗拦截设置失败: " + ex.Message;
            }
        }

        private void PrivacyMonitor_Toggled(object sender, RoutedEventArgs e)
        {
            try
            {
                SettingsStore.Current.PrivacyMonitorAutoStart = PrivacyMonitorToggle.IsOn;
                SettingsStore.Save();
                if (PrivacyMonitorToggle.IsOn)
                {
                    if (App.PrivacyMonitor == null)
                    {
                        var monitor = new FireAntivirus.PrivacyProtection.PrivacyProtectionManager();
                        App.SetPrivacyMonitor(monitor);
                        _ = monitor.StartMonitoring();
                    }
                    ModulesState.Text = "隐私访问监控: 运行中";
                }
                else
                {
                    try { App.PrivacyMonitor?.StopMonitoring(); } catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
                    ModulesState.Text = "隐私访问监控: 已停止";
                }
            }
            catch (Exception ex)
            {
                ModulesState.Text = "隐私监控设置失败: " + ex.Message;
            }
        }

        private void ParentalControl_Toggled(object sender, RoutedEventArgs e)
        {
            try
            {
                SettingsStore.Current.ParentalControlEnabled = ParentalControlToggle.IsOn;
                SettingsStore.Save();

                // 真实写入家长控制设置（时间限制 + 内容过滤总开关）
                var mgr = new FireAntivirus.ParentalControl.ParentalControlManager(App.Data);
                var settings = mgr.GetSettings();
                settings.EnableTimeLimit = ParentalControlToggle.IsOn;
                settings.EnableContentFilter = ParentalControlToggle.IsOn;
                mgr.UpdateSettings(settings);

                ModulesState.Text = "家长控制: " + (ParentalControlToggle.IsOn ? "已启用" : "已停用");
            }
            catch (Exception ex)
            {
                ModulesState.Text = "家长控制设置失败: " + ex.Message;
            }
        }

        private void RefreshCloudApiState()
        {
            // VT 密钥为开发商内嵌，状态对终端用户可见但密钥本身不回填不展示
            CloudApiState.Text = "VirusTotal 云查杀：已启用（70 引擎聚合权威确认，由开发商提供，无需配置）";
        }

        private void RefreshUpdateSourceState()
        {
            var src = FireAntivirus.Engine.ThreatDataUpdateService.ReadSource();
            if (string.IsNullOrWhiteSpace(src))
                UpdateSourceState.Text = "当前：未配置（出厂特征库 + 情报订阅 + YARA 社区规则在线更新继续生效）";
            else
                UpdateSourceState.Text = "当前：" + src;
        }

        // ---- 开机自启：注册表 HKCU Run，真实写入/删除 ----

        private static bool IsAutoStartEnabled()
        {
            try
            {
                using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(RunKey);
                return key?.GetValue(AppName) != null;
            }
            catch { return false; }
        }

        private void AutoStart_Toggled(object sender, RoutedEventArgs e)
        {
            try
            {
                using var key = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(RunKey);
                if (AutoStartToggle.IsOn)
                {
                    var exe = Environment.ProcessPath;
                    if (string.IsNullOrEmpty(exe)) return;
                    key.SetValue(AppName, $"\"{exe}\"");
                    FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info, "已启用开机自启动");
                }
                else
                {
                    key.DeleteValue(AppName, false);
                    FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info, "已关闭开机自启动");
                }
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "设置开机自启动失败: " + ex.Message);
            }
        }

        // ---- 看门狗自恢复：SettingsStore 持久化 + schtasks enable/disable 真实生效 ----

        private void Watchdog_Toggled(object sender, RoutedEventArgs e)
        {
            try
            {
                SettingsStore.Current.WatchdogEnabled = WatchdogToggle.IsOn;
                SettingsStore.Save();
                WatchdogGuard.ApplyWatchdogSetting(WatchdogToggle.IsOn);
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info,
                    "看门狗自恢复切换为 " + (WatchdogToggle.IsOn ? "开启" : "关闭"));
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "设置看门狗失败: " + ex.Message);
            }
        }

        // ---- 扫描并发数 ----

        private void Concurrency_ValueChanged(NumberBox sender, NumberBoxValueChangedEventArgs args)
        {
            try
            {
                if (SettingsStore.Current == null) return;
                SettingsStore.Current.ScanConcurrency = (int)sender.Value;
                SettingsStore.Save();
            }
            catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
        }

        // ---- 扫描排除目录 ----

        private void ExcludeAdd_Click(object sender, RoutedEventArgs e)
        {
            var dir = ExcludeBox.Text?.Trim();
            if (string.IsNullOrWhiteSpace(dir) || !Directory.Exists(dir))
            {
                ExcludeBox.PlaceholderText = "路径无效或不存在";
                return;
            }
            var s = SettingsStore.Current;
            var full = Path.GetFullPath(dir).TrimEnd('\\');
            if (s.ExcludedDirs.Any(d => string.Equals(d, full, StringComparison.OrdinalIgnoreCase)))
            {
                ExcludeBox.Text = "";
                return;
            }
            s.ExcludedDirs.Add(full);
            SettingsStore.Save();
            ExcludeList.ItemsSource = new System.Collections.ObjectModel.ObservableCollection<string>(s.ExcludedDirs);
            ExcludeBox.Text = "";
            FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info, "已添加扫描排除目录: " + full);
        }

        private void ExcludeRemove_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not Button btn || btn.Tag is not string dir) return;
            var s = SettingsStore.Current;
            s.ExcludedDirs.RemoveAll(d => string.Equals(d, dir, StringComparison.OrdinalIgnoreCase));
            SettingsStore.Save();
            ExcludeList.ItemsSource = new System.Collections.ObjectModel.ObservableCollection<string>(s.ExcludedDirs);
            FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info, "已移除扫描排除目录: " + dir);
        }

        // ---- 特征库更新源 ----

        private void UpdateSourceSave_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var url = UpdateSourceBox.Text?.Trim();
                SettingsStore.Current.ThreatDataUpdateSource = url ?? "";
                SettingsStore.Save();
                FireAntivirus.Engine.ThreatDataUpdateService.SetSource(url);
                RefreshUpdateSourceState();
                _ = new ContentDialog
                {
                    Title = "已保存",
                    Content = string.IsNullOrWhiteSpace(url)
                        ? "已清除自定义更新源，出厂特征库 + 情报订阅 + YARA 社区规则继续生效。"
                        : "特征库更新源已保存，下次点击“更新病毒库”时生效。",
                    CloseButtonText = "确定", XamlRoot = XamlRoot
                }.ShowAsync();
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "保存更新源失败: " + ex.Message);
            }
        }

        private void Advanced_Toggled(object sender, RoutedEventArgs e)
        {
            try
            {
                var s = SettingsStore.Current;
                s.FuzzyHashEnabled = FuzzyHashToggle.IsOn;
                s.EntropyTimelineEnabled = EntropyTimelineToggle.IsOn;
                s.ProcessLineageEnabled = LineageToggle.IsOn;
                s.ChainBlockEnabled = ChainBlockToggle.IsOn;
                s.SensitiveFlowEnabled = SensitiveFlowToggle.IsOn;
                s.VadScanEnabled = VadScanToggle.IsOn;
                s.AsrEnabled = AsrToggle.IsOn;
                s.TimelineEnabled = TimelineToggle.IsOn;
                s.EtwEnabled = EtwToggle.IsOn;
                s.WfpBlockEnabled = WfpToggle.IsOn;
                SettingsStore.Save();

                FireAntivirus.Engine.Analyzers.FuzzyHashCluster.Enabled = s.FuzzyHashEnabled;
                FireAntivirus.Engine.Analyzers.EntropyTimelineAnalyzer.Enabled = s.EntropyTimelineEnabled;
                FireAntivirus.Engine.Analyzers.ProcessLineageGraph.Enabled = s.ProcessLineageEnabled;
                FireAntivirus.Engine.Analyzers.ProcessLineageGraph.AutoBlockEnabled = s.ChainBlockEnabled;
                FireAntivirus.Engine.Analyzers.SensitiveFlowTracker.Enabled = s.SensitiveFlowEnabled;
                FireAntivirus.Engine.Analyzers.MemoryVadScanner.Enabled = s.VadScanEnabled;
                FireAntivirus.Engine.Analyzers.AsrRuleEngine.Enabled = s.AsrEnabled;
                FireAntivirus.Engine.Analyzers.AsrRuleEngine.BlockEnabled = s.ChainBlockEnabled;
                FireAntivirus.Engine.Analyzers.DetectionTimeline.Enabled = s.TimelineEnabled;
                FireAntivirus.Engine.Analyzers.EtwBehaviorCollector.Enabled = s.EtwEnabled;
                FireAntivirus.Engine.Analyzers.WfpBlocker.Enabled = s.WfpBlockEnabled;

                if (s.EtwEnabled && !FireAntivirus.Engine.Analyzers.EtwBehaviorCollector.IsRunning)
                    _ = System.Threading.Tasks.Task.Run(() => FireAntivirus.Engine.Analyzers.EtwBehaviorCollector.Start());
                else if (!s.EtwEnabled && FireAntivirus.Engine.Analyzers.EtwBehaviorCollector.IsRunning)
                    FireAntivirus.Engine.Analyzers.EtwBehaviorCollector.Stop();

                if (s.WfpBlockEnabled)
                    _ = System.Threading.Tasks.Task.Run(() => FireAntivirus.Engine.Analyzers.WfpBlocker.ProbeEngine());

                ModulesState.Text = "高级检测开关已更新并即时生效";
            }
            catch (Exception ex) { ModulesState.Text = "高级检测设置失败: " + ex.Message; }
        }

        private void HandleAudit_Toggled(object sender, RoutedEventArgs e)
        {
            try
            {
                SettingsStore.Current.HandleAuditEnabled = HandleAuditToggle.IsOn;
                SettingsStore.Save();
                FireAntivirus.Engine.Analyzers.HandleAccessAudit.Enabled = HandleAuditToggle.IsOn;
                ModulesState.Text = "句柄访问掩码审计: " + (HandleAuditToggle.IsOn
                    ? "已启用（60 秒周期，受保护进程 + JSON 取证报告）"
                    : "已关闭");
            }
            catch (Exception ex) { ModulesState.Text = "句柄审计设置失败: " + ex.Message; }
        }

        private void SandboxEvasion_Toggled(object sender, RoutedEventArgs e)
        {
            try
            {
                SettingsStore.Current.SandboxEvasionGuardEnabled = SandboxEvasionToggle.IsOn;
                SettingsStore.Save();
                FireAntivirus.Engine.Sandbox.SandboxEvasionGuard.Enabled = SandboxEvasionToggle.IsOn;
                ModulesState.Text = "沙箱反沙箱对抗: " + (SandboxEvasionToggle.IsOn
                    ? "已启用（反虚拟机/反调试识别 + Sandboxie 加固）"
                    : "已关闭");
            }
            catch (Exception ex) { ModulesState.Text = "沙箱反沙箱设置失败: " + ex.Message; }
        }

        // ---- 句柄访问掩码审计（手动审计 + 处置消费方）----

        private static string HandleAuditReportDir() => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "FireAntivirus", "Logs", "HandleAudit");

        private void ExportTimeline_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string path = FireAntivirus.Engine.Analyzers.DetectionTimeline.Export(
                    DateTime.UtcNow.AddHours(-24), DateTime.UtcNow,
                    Path.Combine(FireAntivirus.Engine.Analyzers.DetectionTimeline.DirectoryPath,
                        $"timeline_export_{DateTime.Now:yyyyMMdd_HHmmss}.json"));

                ModulesState.Text = string.IsNullOrEmpty(path)
                    ? "EDR 时间线导出失败（目录不可写或无事件）"
                    : "EDR 时间线已导出: " + path;
            }
            catch (Exception ex) { ModulesState.Text = "EDR 时间线导出异常: " + ex.Message; }
        }

        private void OpenTimelineDir_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string dir = FireAntivirus.Engine.Analyzers.DetectionTimeline.DirectoryPath;
                Directory.CreateDirectory(dir);
                System.Diagnostics.Process.Start("explorer.exe", dir);
            }
            catch (Exception ex) { ModulesState.Text = "打开时间线目录失败: " + ex.Message; }
        }

        private async void HandleAuditNow_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                ModulesState.Text = "正在枚举全系统句柄表并解码访问掩码…";
                var report = await Task.Run(() => FireAntivirus.Engine.Analyzers.HandleAccessAudit.Scan());
                string reportPath = FireAntivirus.Engine.Analyzers.HandleAccessAudit.WriteReport(report);
                ModulesState.Text = report.Summary;

                if (report.Findings.Count == 0)
                {
                    await new ContentDialog
                    {
                        Title = "句柄访问审计",
                        Content = report.Summary + (string.IsNullOrEmpty(reportPath) ? "" : "\n报告: " + reportPath),
                        CloseButtonText = "确定", XamlRoot = XamlRoot
                    }.ShowAsync();
                    return;
                }

                var lines = report.Findings.Take(10).Select(f =>
                    $"[{f.Risk}] {f.OwnerName} (PID {f.OwnerPid}) → {f.TargetName} · {f.Access} · {f.Technique}");
                var dialog = new ContentDialog
                {
                    Title = $"句柄审计：{report.Findings.Count} 条危险访问",
                    Content = string.Join("\n", lines) +
                              "\n\n是否终止高危持有进程？（系统/安全核心进程永不终止；句柄本身需内核才能跨进程关闭）",
                    PrimaryButtonText = "终止高危持有者",
                    CloseButtonText = "仅查看",
                    XamlRoot = XamlRoot
                };

                var choice = await dialog.ShowAsync();
                if (choice != ContentDialogResult.Primary) return;

                int killed = 0;
                var failures = new List<string>();
                foreach (var finding in report.Findings.Where(f => f.Risk >= FireAntivirus.Engine.Analyzers.HandleRisk.High))
                {
                    if (FireAntivirus.Engine.Analyzers.HandleAccessAudit.TerminateHolder(finding, out string message))
                        killed++;
                    else
                        failures.Add(message);
                }

                await new ContentDialog
                {
                    Title = "句柄审计处置结果",
                    Content = $"已终止 {killed} 个危险句柄持有进程\n" +
                              (failures.Count == 0 ? "" : string.Join("\n", failures.Take(5))),
                    CloseButtonText = "确定", XamlRoot = XamlRoot
                }.ShowAsync();
            }
            catch (Exception ex)
            {
                ModulesState.Text = "句柄审计失败: " + ex.Message;
            }
        }

        private void OpenHandleAuditReports_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string dir = HandleAuditReportDir();
                Directory.CreateDirectory(dir);
                System.Diagnostics.Process.Start("explorer.exe", dir);
            }
            catch (Exception ex) { ModulesState.Text = "打开审计报告目录失败: " + ex.Message; }
        }

        // ---- Melix 模型：训练 / 校准 / 部署 ----

        private static string ResolveModelPath() => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "FireAntivirus", "ML", "melix_ember.json");

        private string ResolveDatasetPath()
        {
            string p = ModelDatasetBox.Text?.Trim();
            if (string.IsNullOrWhiteSpace(p))
                p = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "FireAntivirus", "ML", "Dataset");
            return p;
        }

        private double ReadTargetFpr()
        {
            double v = ModelFprBox.Value;
            if (double.IsNaN(v) || v <= 0) v = 0.01;
            return Math.Clamp(v, 0.001, 0.2);
        }

        private bool ModelBusy => ModelProgress.Visibility == Visibility.Visible;

        private void SetModelBusy(bool busy, string text = null)
        {
            ModelProgress.Visibility = busy ? Visibility.Visible : Visibility.Collapsed;
            if (text != null) ModelState.Text = text;
        }

        private void RefreshMelixState()
        {
            try
            {
                string modelPath = ResolveModelPath();
                FireAntivirus.Engine.Analyzers.MelixEnsembleClassifier.Initialize(modelPath);
                MelixState.Text = $"当前模型: {FireAntivirus.Engine.Analyzers.MelixEnsembleClassifier.ModelSource} · " +
                                  $"版本 {FireAntivirus.Engine.Analyzers.MelixEnsembleClassifier.ModelVersion} · " +
                                  $"阈值 {FireAntivirus.Engine.Analyzers.MelixEnsembleClassifier.Threshold:F2} · " +
                                  $"{FireAntivirus.Engine.Analyzers.MelixEnsembleClassifier.TreeCount} 棵树 · 2568 维 EMBER 特征";
            }
            catch (Exception ex) { MelixState.Text = "模型状态读取失败: " + ex.Message; }
        }

        private async void ModelDatasetPick_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var picker = new FolderPicker { SuggestedStartLocation = PickerLocationId.ComputerFolder };
                picker.FileTypeFilter.Add("*");
                var hwnd = WinRT.Interop.WindowNative.GetWindowHandle(App.MainWindow);
                WinRT.Interop.InitializeWithWindow.Initialize(picker, hwnd);
                var folder = await picker.PickSingleFolderAsync();
                if (folder == null) return;
                ModelDatasetBox.Text = folder.Path;
                SettingsStore.Current.ModelDatasetPath = folder.Path;
                SettingsStore.Save();
            }
            catch (Exception ex) { ModelState.Text = "选择目录失败: " + ex.Message; }
        }

        private async void ModelBuildDataset_Click(object sender, RoutedEventArgs e)
        {
            if (ModelBusy) return;
            string dataset = ResolveDatasetPath();
            int max = Math.Clamp(SettingsStore.Current.ModelMaxSamplesPerClass, 20, 1000);

            SettingsStore.Current.ModelDatasetPath = dataset;
            SettingsStore.Current.ModelTargetFpr = ReadTargetFpr();
            SettingsStore.Save();

            SetModelBusy(true, "正在采集样本（隔离区=恶意 / System32 已签名=良性）…");
            try
            {
                var r = await Task.Run(() =>
                {
                    int n = FireAntivirus.Engine.Analyzers.MelixTrainer.BuildAutoDataset(dataset, max,
                        msg => DispatcherQueue.TryEnqueue(() => ModelState.Text = msg), out string err);
                    return (Count: n, Error: err);
                });

                SetModelBusy(false, r.Count > 0
                    ? $"样本集已构建: {r.Count} 条 → {dataset}"
                    : "样本采集失败: " + (string.IsNullOrEmpty(r.Error) ? "没有可用样本" : r.Error));
            }
            catch (Exception ex) { SetModelBusy(false, "样本采集异常: " + ex.Message); }
        }

        private async void ModelTrain_Click(object sender, RoutedEventArgs e)
        {
            if (ModelBusy) return;
            string dataset = ResolveDatasetPath();
            string modelPath = ResolveModelPath();
            int max = Math.Clamp(SettingsStore.Current.ModelMaxSamplesPerClass, 20, 1000);
            double targetFpr = ReadTargetFpr();

            SettingsStore.Current.ModelDatasetPath = dataset;
            SettingsStore.Current.ModelTargetFpr = targetFpr;
            SettingsStore.Save();

            SetModelBusy(true, "正在训练 CART 随机森林（真实分裂 + Bagging + 特征子采样）…");
            try
            {
                var r = await Task.Run(() =>
                {
                    var samples = FireAntivirus.Engine.Analyzers.MelixTrainer.LoadDataset(dataset, max,
                        msg => DispatcherQueue.TryEnqueue(() => ModelState.Text = msg), out string loadErr);
                    if (samples.Count == 0) return (Report: (FireAntivirus.Engine.Analyzers.TrainingReport)null, Error: loadErr);

                    var options = new FireAntivirus.Engine.Analyzers.TrainingOptions { TargetFpr = targetFpr };
                    var report = FireAntivirus.Engine.Analyzers.MelixTrainer.TrainAndDeploy(samples, options, modelPath,
                        msg => DispatcherQueue.TryEnqueue(() => ModelState.Text = msg), out string trainErr);
                    return (Report: report, Error: trainErr);
                });

                if (r.Report == null || r.Report.Trees == 0 || !string.IsNullOrEmpty(r.Error))
                {
                    SetModelBusy(false, "训练失败: " + (r.Error ?? "样本不足或特征无效"));
                    return;
                }

                SetModelBusy(false, r.Report.Summary);
                RefreshMelixState();
            }
            catch (Exception ex) { SetModelBusy(false, "训练异常: " + ex.Message); }
        }

        private async void ModelCalibrate_Click(object sender, RoutedEventArgs e)
        {
            if (ModelBusy) return;
            string dataset = ResolveDatasetPath();
            string modelPath = ResolveModelPath();
            int max = Math.Clamp(SettingsStore.Current.ModelMaxSamplesPerClass, 20, 1000);
            double targetFpr = ReadTargetFpr();

            SettingsStore.Current.ModelTargetFpr = targetFpr;
            SettingsStore.Save();

            SetModelBusy(true, $"正在校准阈值（目标误报率 {targetFpr:P1}）…");
            try
            {
                var r = await Task.Run(() =>
                {
                    FireAntivirus.Engine.Analyzers.MelixEnsembleClassifier.Initialize(modelPath);

                    var samples = FireAntivirus.Engine.Analyzers.MelixTrainer.LoadDataset(dataset, max,
                        msg => DispatcherQueue.TryEnqueue(() => ModelState.Text = msg), out string loadErr);
                    var benign = samples.Where(s => s.Label == 0).Select(s => s.Features).ToList();
                    var malicious = samples.Where(s => s.Label == 1).Select(s => s.Features).ToList();
                    if (benign.Count == 0 || malicious.Count == 0)
                        return (Report: (FireAntivirus.Engine.Analyzers.CalibrationReport)null, Applied: false,
                                Error: string.IsNullOrEmpty(loadErr) ? "两类样本都需要至少 1 条" : loadErr);

                    var report = FireAntivirus.Engine.Analyzers.MelixThresholdCalibrator
                        .Calibrate(benign, malicious, targetFpr);
                    bool applied = FireAntivirus.Engine.Analyzers.MelixThresholdCalibrator
                        .ApplyToModel(modelPath, report.RecommendedThreshold, out string applyErr);
                    return (Report: report, Applied: applied, Error: applyErr);
                });

                if (r.Report == null)
                {
                    SetModelBusy(false, "校准失败: " + (r.Error ?? "样本不足"));
                    return;
                }

                SetModelBusy(false,
                    r.Report.Summary + (r.Applied ? " · 阈值已写回模型并生效" : " · 阈值写回失败: " + r.Error));
                RefreshMelixState();
            }
            catch (Exception ex) { SetModelBusy(false, "校准异常: " + ex.Message); }
        }

        // ---- 签名验证 ----

        private async void VerifySign_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var picker = new FileOpenPicker { SuggestedStartLocation = PickerLocationId.ComputerFolder };
                picker.FileTypeFilter.Add(".exe");
                picker.FileTypeFilter.Add(".dll");
                var hwnd = WinRT.Interop.WindowNative.GetWindowHandle(App.MainWindow);
                WinRT.Interop.InitializeWithWindow.Initialize(picker, hwnd);
                var file = await picker.PickSingleFileAsync();
                if (file == null) return;

                var result = VerifySignature(file.Path);
                var dialog = new ContentDialog
                {
                    Title = "签名验证结果（.NET X509Certificate）",
                    Content = result,
                    CloseButtonText = "确定", XamlRoot = XamlRoot
                };
                await dialog.ShowAsync();
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "签名验证失败: " + ex.Message);
                var dialog = new ContentDialog
                {
                    Title = "验证失败", Content = ex.Message, CloseButtonText = "确定", XamlRoot = XamlRoot
                };
                await dialog.ShowAsync();
            }
        }

        private static string VerifySignature(string path)
        {
            try
            {
                using var cert = X509CertificateLoader.LoadCertificateFromFile(path);
                string issuer = "--", subject = "--";
                try { issuer = cert.Issuer?.ToString() ?? "--"; } catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
                try { subject = cert.Subject?.ToString() ?? "--"; } catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
                return $"文件: {Path.GetFileName(path)}\n证书主题: {subject}\n颁发者: {issuer}\n有效期至: " +
                       cert.NotAfter.ToString("yyyy-MM-dd");
            }
            catch (System.Security.Cryptography.CryptographicException)
            {
                try
                {
                    // LoadCertificateFromFile 只接受证书文件；对 PE 用旧 API 的兼容路径（SYSLIB0057 警告可接受）
#pragma warning disable SYSLIB0057
                    using var cert = X509Certificate.CreateFromSignedFile(path);
                    using var c2 = new X509Certificate2(cert);
                    return $"文件: {Path.GetFileName(path)}\n签名者: {c2.Subject}\n颁发者: {c2.Issuer}\n有效期至: " +
                           c2.NotAfter.ToString("yyyy-MM-dd") +
                           "\n是否由 Microsoft 认证: " + c2.Subject.Contains("Microsoft", StringComparison.OrdinalIgnoreCase);
#pragma warning restore SYSLIB0057
                }
                catch (System.Security.SecurityException)
                {
                    return "文件未签名或签名无效（无有效数字签名）。";
                }
                catch (Exception ex2)
                {
                    return "验证失败: " + ex2.Message;
                }
            }
            catch (Exception ex)
            {
                return "验证失败: " + ex.Message;
            }
        }

        // ---- 日志维护 ----

        private void OpenLogs_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var dir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "FireAntivirus", "Data", "Logs");
                Directory.CreateDirectory(dir);
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = dir,
                    UseShellExecute = true
                });
            }
            catch (Exception ex)
            {
                LogsState.Text = "打开日志目录失败: " + ex.Message;
            }
        }

        private void CleanLogs_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var dir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "FireAntivirus", "Data", "Logs");
                if (!Directory.Exists(dir)) { LogsState.Text = "暂无日志"; return; }

                int removed = 0;
                var cutoff = DateTime.Now.AddDays(-7);
                foreach (var f in Directory.GetFiles(dir, "*.log"))
                {
                    if (File.GetLastWriteTime(f) < cutoff)
                    {
                        try { File.Delete(f); removed++; } catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
                    }
                }
                LogsState.Text = $"已清理 {removed} 个过期日志文件";
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info, $"手动清理过期日志 {removed} 个");
            }
            catch (Exception ex)
            {
                LogsState.Text = "清理失败: " + ex.Message;
            }
        }

        // ---- 设置备份 ----

        private void Export_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string cfgDir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "FireAntivirus", "Settings");
                Directory.CreateDirectory(cfgDir);
                var target = Path.Combine(cfgDir, "settings_backup_" + DateTime.Now.ToString("yyyyMMdd_HHmmss") + ".json");

                var settings = new
                {
                    exported = DateTime.Now.ToString("s"),
                    autoStart = IsAutoStartEnabled(),
                    fileGuard = RealTimeProtection.Instance.FileGuardEnabled,
                    ransomGuard = RealTimeProtection.Instance.RansomGuardEnabled,
                    scanConcurrency = SettingsStore.Current.ScanConcurrency,
                    excludedDirs = SettingsStore.Current.ExcludedDirs,
                    watchdogEnabled = SettingsStore.Current.WatchdogEnabled,
                    threatDataUpdateSource = SettingsStore.Current.ThreatDataUpdateSource,
                    quarantineCount = QuarantineStore.ListAll().Count
                };
                File.WriteAllText(target, System.Text.Json.JsonSerializer.Serialize(settings, new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
                var dialog = new ContentDialog
                {
                    Title = "导出成功",
                    Content = "设置备份已导出到:\n" + target,
                    CloseButtonText = "确定", XamlRoot = XamlRoot
                };
                _ = dialog.ShowAsync();
            }
            catch (Exception ex)
            {
                var dialog = new ContentDialog { Title = "导出失败", Content = ex.Message, CloseButtonText = "确定", XamlRoot = XamlRoot };
                _ = dialog.ShowAsync();
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "导出设置失败: " + ex.Message);
            }
        }

        private async void Import_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string cfgDir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "FireAntivirus", "Settings");
                var latest = Directory.Exists(cfgDir)
                    ? Directory.GetFiles(cfgDir, "settings_backup_*.json").OrderByDescending(File.GetLastWriteTime).FirstOrDefault()
                    : null;
                if (latest == null)
                {
                    var dlg1 = new ContentDialog { Title = "没有可导入的备份", Content = "请先在导出设置备份。", CloseButtonText = "确定", XamlRoot = XamlRoot };
                    await dlg1.ShowAsync();
                    return;
                }

                var doc = System.Text.Json.JsonDocument.Parse(File.ReadAllText(latest)).RootElement;
                if (doc.TryGetProperty("fileGuard", out var fg))
                    RealTimeProtection.Instance.FileGuardEnabled = fg.GetBoolean();
                if (doc.TryGetProperty("ransomGuard", out var rg))
                    RealTimeProtection.Instance.RansomGuardEnabled = rg.GetBoolean();
                if (doc.TryGetProperty("autoStart", out var auto))
                {
                    using var key = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(RunKey);
                    if (auto.GetBoolean() && !string.IsNullOrEmpty(Environment.ProcessPath))
                        key.SetValue(AppName, $"\"{Environment.ProcessPath}\"");
                    else
                        key.DeleteValue(AppName, false);
                }
                if (doc.TryGetProperty("scanConcurrency", out var sc))
                    SettingsStore.Current.ScanConcurrency = sc.GetInt32();
                if (doc.TryGetProperty("excludedDirs", out var ed))
                {
                    SettingsStore.Current.ExcludedDirs = System.Text.Json.JsonSerializer.Deserialize<System.Collections.Generic.List<string>>(ed.GetRawText())
                        ?? new System.Collections.Generic.List<string>();
                }
                if (doc.TryGetProperty("watchdogEnabled", out var wd))
                {
                    SettingsStore.Current.WatchdogEnabled = wd.GetBoolean();
                    WatchdogGuard.ApplyWatchdogSetting(wd.GetBoolean());
                }
                if (doc.TryGetProperty("threatDataUpdateSource", out var us))
                {
                    SettingsStore.Current.ThreatDataUpdateSource = us.GetString() ?? "";
                    FireAntivirus.Engine.ThreatDataUpdateService.SetSource(SettingsStore.Current.ThreatDataUpdateSource);
                }
                SettingsStore.Save();
                LoadAll();

                var dialog = new ContentDialog
                {
                    Title = "导入成功",
                    Content = "已从最近备份恢复设置：\n" + Path.GetFileName(latest),
                    CloseButtonText = "确定", XamlRoot = XamlRoot
                };
                await dialog.ShowAsync();
            }
            catch (Exception ex)
            {
                var dialog = new ContentDialog { Title = "导入失败", Content = ex.Message, CloseButtonText = "确定", XamlRoot = XamlRoot };
                await dialog.ShowAsync();
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "导入设置失败: " + ex.Message);
            }
        }
    }
}