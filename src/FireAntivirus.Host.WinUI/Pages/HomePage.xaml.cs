using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace FireAntivirus.Host.WinUI.Pages
{
    public sealed partial class HomePage : Page
    {
        // 注意：不要在页面构造里同步 new AntivirusEngine()/DataManager()（构造重会卡首页），
        // 重资源统一走 App.Data / 后台任务预热。

        public HomePage()
        {
            InitializeComponent();
            _ = LoadCatImageAsync();
            try
            {
                LoadStatus();
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "WinUI 首页初始化失败: " + ex.Message);
            }
        }

        private void LoadStatus()
        {
            try
            {
                // 内嵌特征库自检：确认 YARA/PE/文件名/白名单数据全部加载
                var (ok, yara, pe, kf, pub, err) = FireAntivirus.Engine.Data.EmbeddedThreatDatabase.SelfCheck();
                if (!ok)
                    FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "内嵌特征库自检失败: " + err);

                StatusText.Text = ok ? "你的设备受保护" : "防护组件部分异常";

                // 病毒引擎版本（程序集版本 + 构建日期）
                try
                {
                    var asm = typeof(HomePage).Assembly.GetName().Version;
                    string exePath = Environment.ProcessPath;
                    var buildTime = !string.IsNullOrEmpty(exePath) && File.Exists(exePath) ? File.GetLastWriteTime(exePath) : DateTime.MinValue;
                    EngineVersion.Text = $"病毒引擎 v{asm.Major}.{asm.Minor}.{asm.Build}"
                        + (buildTime != DateTime.MinValue ? $"（{buildTime:yyyy-MM-dd} 构建）" : "");
                }
                catch { }

                RefreshDbVersion();

                // 开关直接反映 RealTimeProtection 真实状态（避免回写触发 Toggled）
                var rt = RealTimeProtection.Instance;
                RealTimeToggle.Toggled -= RealTimeToggle_Toggled;
                RansomToggle.Toggled -= RansomToggle_Toggled;
                RealTimeToggle.IsOn = rt.FileGuardEnabled;
                RansomToggle.IsOn = rt.RansomGuardEnabled;
                RealTimeToggle.Toggled += RealTimeToggle_Toggled;
                RansomToggle.Toggled += RansomToggle_Toggled;

                // 防护组件真实状态（内核驱动 / ClamAV 本地库 / 云查杀通道）
                bool driverLoaded = false;
                try { driverLoaded = FireAntivirus.Engine.Kernel.KernelProtectionInterface.IsDriverLoaded(); } catch { }
                var clam = FireAntivirus.Engine.SignatureDatabaseUpdater.GetClamavDbStatus();
                string cloudState = FireAntivirus.Engine.AntivirusEngine.IsVirusTotalEnabled
                    ? "VirusTotal + MalwareBazaar + OTX 已启用"
                    : (FireAntivirus.Engine.AntivirusEngine.IsMalwareBazaarEnabled ? "MalwareBazaar + OTX 已启用" : "云查杀未启用");

                GuardStatus.Text = $"实时防护运行中：{rt.CoverageText}\n" +
                    $"内核驱动: {(driverLoaded ? "已加载（双层防控生效）" : "未加载（仅用户态防护）")} · " +
                    $"ClamAV: {(clam.Available ? $"{clam.Files.Count} 个库已就绪" : "库未就绪（请点“更新病毒库”）")} · " +
                    $"云查杀: {cloudState}";
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "WinUI 首页状态加载失败: " + ex.Message);
            }
        }

        /// <summary>刷新病毒库版本卡：特征库（在线/出厂）版本与更新日期 + 情报订阅规模与更新时间。</summary>
        private void RefreshDbVersion()
        {
            try
            {
                var td = FireAntivirus.Engine.ThreatDataUpdateService.GetStatus();
                var intel = FireAntivirus.Engine.SignatureDatabaseUpdater.LastUpdate;

                DbVersion.Text = td.HasRuntimeDb
                    ? $"在线库 · {td.FileCount} 文件"
                    : $"出厂库 · {FireAntivirus.Engine.SignatureDatabaseUpdater.HashCount}+ 哈希";

                string tdLine = td.HasRuntimeDb
                    ? (td.Updated.HasValue ? $"特征库: {td.Updated.Value:yyyy-MM-dd HH:mm}" : "特征库: 运行时库")
                    : "特征库: 出厂内置";
                string intelLine = intel > DateTime.MinValue
                    ? $"情报库: {intel:yyyy-MM-dd HH:mm} · {FireAntivirus.Engine.SignatureDatabaseUpdater.HashCount:N0} 哈希 / {FireAntivirus.Engine.SignatureDatabaseUpdater.UrlCount:N0} URL / {FireAntivirus.Engine.SignatureDatabaseUpdater.IpCount:N0} IP"
                    : "情报库: 未更新（联网后自动拉取）";

                // ClamAV 本地病毒库真实状态（main/daily/bytecode.cvd 文件数、体积、更新时间）
                var clam = FireAntivirus.Engine.SignatureDatabaseUpdater.GetClamavDbStatus();
                string clamLine = clam.Available
                    ? $"ClamAV: {clam.Files.Count} 个库 · {clam.TotalMB:F0} MB" + (clam.Updated.HasValue ? $" · {clam.Updated:MM-dd HH:mm}" : "")
                    : "ClamAV: 未就绪";

                DbUpdated.Text = tdLine + "\n" + intelLine + "\n" + clamLine;
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "WinUI 病毒库版本刷新失败: " + ex.Message);
            }
        }

        private async System.Threading.Tasks.Task LoadCatImageAsync()
        {
            var image = await UiKit.LoadAssetAsync("cat_home.png");
            if (image != null) HomeCatBrush.ImageSource = image;
        }

        private void QuickScan_Click(object sender, RoutedEventArgs e) => NavigateToScan("quick");
        private void FullScan_Click(object sender, RoutedEventArgs e) => NavigateToScan("full");

        private void NavigateToScan(string mode)
        {
            try
            {
                if (App.MainWindow is MainWindow mw)
                {
                    var page = mw.NavigateTo(typeof(ScanPage));
                    if (page is ScanPage scan) scan.AutoStart(mode);
                }
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "WinUI 跳转扫描页失败: " + ex.Message);
            }
        }

        private async void UpdateDb_Click(object sender, RoutedEventArgs e)
        {
            var btn = sender as Button;
            try
            {
                if (btn != null)
                {
                    btn.IsEnabled = false;
                    btn.Content = "更新中...";
                }
                // 更新期间暂停实时扫描与批扫：防下载解压与扫描抢 CPU/IO 把机器卡死
                RealTimeProtection.UpdateInProgress = true;
                FireAntivirus.Engine.SignatureDatabaseUpdater.DbUpdateInProgress = true;
                UpdateProgress.Visibility = Visibility.Visible;
                UpdateProgress.IsIndeterminate = false;
                UpdateProgress.Value = 0;
                UpdateState.Visibility = Visibility.Visible;

                // 1) 威胁情报订阅（MalwareBazaar/URLhaus/Feodo/LMD，真实下载 + jsDelivr 镜像回退）
                UpdateState.Text = "阶段 1/4：更新开源威胁情报订阅（MalwareBazaar / URLhaus / Feodo / LMD）...";
                UpdateProgress.Value = 8;
                var result = await FireAntivirus.Engine.SignatureDatabaseUpdater.UpdateAsync();
                // 逐源真实明细：成功显示条数、失败显示"失败"，不再出现笼统的"+0 哈希"
                string info = result.Sources != null && result.Sources.Count > 0
                    ? string.Join(" · ", result.Sources.Select(s => s.Ok ? $"{s.Name} +{s.Added}" : $"{s.Name} 失败"))
                    : (result.Succeeded
                        ? $"情报: +{result.HashesAdded}哈希 +{result.UrlsAdded}URL +{result.IpsAdded}IP"
                        : "情报源全部不可达");

                // 2) ClamAV 病毒库（freshclam 真实下载 main/daily/bytecode.cvd）
                UpdateState.Text = "阶段 2/4：下载 ClamAV 病毒库（main / daily / bytecode）...";
                UpdateProgress.Value = 30;
                bool cvdOk = await FireAntivirus.Engine.SignatureDatabaseUpdater.UpdateClamavDbAsync();
                var clam = FireAntivirus.Engine.SignatureDatabaseUpdater.GetClamavDbStatus();
                string clamInfo = clam.Available
                    ? $"ClamAV {(cvdOk ? "已更新" : "库已就绪（本次无需更新）")} · {clam.Files.Count} 个库 · {clam.TotalMB:F0}MB"
                      + (clam.Updated.HasValue ? $" · {clam.Updated:MM-dd HH:mm}" : "")
                    : (cvdOk ? "ClamAV 已更新" : "ClamAV 未就绪（未找到 ClamAV 组件或网络失败）");

                // 3) 特征库（家族/哈希/YARA/勒索签名等 8 个 JSON）在线更新，带真实百分比进度
                UpdateProgress.Value = 55;
                var tdProgress = new Progress<(int Percent, string Stage)>(p =>
                {
                    UpdateProgress.Value = 55 + p.Percent * 0.3;
                    UpdateState.Text = $"阶段 3/4（特征库在线更新）：{p.Stage}";
                });
                var tdResult = await FireAntivirus.Engine.ThreatDataUpdateService.UpdateAsync(tdProgress);

                // 4) YARA 规则库（真实公开社区源 signature-base）在线更新
                UpdateProgress.Value = 85;
                var yaraProgress = new Progress<(int Percent, string Stage)>(p =>
                {
                    UpdateProgress.Value = 85 + p.Percent * 0.15;
                    UpdateState.Text = $"阶段 4/4（YARA 规则库）：{p.Stage}";
                });
                var yaraResult = await FireAntivirus.Engine.Analyzers.YaraRuleEngine.UpdateRulesFromPublicSourceAsync(yaraProgress);

                UpdateProgress.Value = 100;
                RefreshDbVersion();

                bool anyOk = result.Succeeded || cvdOk || tdResult.Succeeded || yaraResult.Updated > 0;
                DbVersion.Text = result.Succeeded
                    ? $"已更新 · 共 {FireAntivirus.Engine.SignatureDatabaseUpdater.HashCount:N0} 哈希"
                    : "情报源不可达";
                UpdateState.Text =
                    $"① 威胁情报：{info}\n" +
                    $"② {clamInfo}\n" +
                    $"③ 特征库：{tdResult.Message}\n" +
                    $"④ YARA 规则：{yaraResult.Message}\n" +
                    (anyOk
                        ? $"更新完成 · {DateTime.Now:HH:mm:ss}"
                        : "更新失败：所有数据源均不可达（请检查网络/代理后重试）");
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "WinUI 病毒库更新失败: " + ex.Message);
                UpdateState.Text = "更新失败: " + ex.Message;
            }
            finally
            {
                RealTimeProtection.UpdateInProgress = false;
                FireAntivirus.Engine.SignatureDatabaseUpdater.DbUpdateInProgress = false;
                if (btn != null)
                {
                    btn.Content = "更新病毒库";
                    btn.IsEnabled = true;
                }
                UpdateProgress.Visibility = Visibility.Collapsed;
            }
        }

        // 开关直接驱动 RealTimeProtection，真实生效
        private void RealTimeToggle_Toggled(object sender, RoutedEventArgs e)
        {
            RealTimeProtection.Instance.FileGuardEnabled = RealTimeToggle.IsOn;
            GuardStatus.Text = RealTimeProtection.Instance.CoverageText;
            FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info,
                $"实时文件防护切换为 {(RealTimeToggle.IsOn ? "开启" : "关闭")}");
        }

        private void RansomToggle_Toggled(object sender, RoutedEventArgs e)
        {
            RealTimeProtection.Instance.RansomGuardEnabled = RansomToggle.IsOn;
            FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info,
                $"勒索防护切换为 {(RansomToggle.IsOn ? "开启" : "关闭")}");
        }
    }
}
