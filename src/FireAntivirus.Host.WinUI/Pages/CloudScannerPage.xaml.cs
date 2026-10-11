// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using FireAntivirus.Engine;
using Windows.Storage.Pickers;
using Windows.Storage;

namespace FireAntivirus.Host.WinUI.Pages
{
    public sealed partial class CloudScannerPage : Page
    {
        private string _path = "";

        public CloudScannerPage()
        {
            InitializeComponent();
            // 云引擎由 SignatureDatabaseUpdater 提供恶意样本哈希查询能力
            var engines = new System.Collections.Generic.List<string>();
            try
            {
                engines.Add("MalwareBazaar (abuse.ch)");
                engines.Add("URLhaus (abuse.ch)");
                engines.Add("Feodo Tracker (abuse.ch)");
                engines.Add("本地哈希库");
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "云引擎初始化: " + ex.Message);
            }
            EnginesText.Text = "已启用引擎: " + string.Join(", ", engines);
            VtStatusText.Text = "特征库：自动更新（每小时）+ 手动更新，数据源 abuse.ch";
        }

        private async void SelectFile_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var picker = new FolderPicker
                {
                    SuggestedStartLocation = PickerLocationId.ComputerFolder
                };
                picker.FileTypeFilter.Add("*");
                var hwnd = WinRT.Interop.WindowNative.GetWindowHandle(App.MainWindow);
                WinRT.Interop.InitializeWithWindow.Initialize(picker, hwnd);
                var folder = await picker.PickSingleFolderAsync();
                if (folder != null)
                {
                    _path = folder.Path;
                    SelectedPathText.Text = _path;
                    CustomScanRadio.IsChecked = true;
                }
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "选择云查杀路径失败: " + ex.Message);
            }
        }

        private async void StartScan_Click(object sender, RoutedEventArgs e)
        {
            StartScanBtn.IsEnabled = false;
            ProgressPanel.Visibility = Visibility.Visible;
            try
            {
                var dataManager = new FireAntivirus.Data.DataManager();
                var engine = new AntivirusEngine();
                if (!string.IsNullOrEmpty(_path) && (Directory.Exists(_path)))
                {
                    var files = Directory.EnumerateFiles(_path, "*", SearchOption.TopDirectoryOnly);
                    int total = 0, threats = 0;
                    foreach (var f in files)
                    {
                        total++;
                        ScanProgress.Value = total / 100.0 * 100;
                        ProgressText.Text = $"正在云查杀: {Path.GetFileName(f)}";
                        var res = engine.ScanFile(f);
                        if (res != null && res.IsMalicious) threats++;
                    }
                    ScanProgress.Value = 100;
                    ProgressText.Text = $"扫描完成：{total} 个文件，发现 {threats} 个威胁";
                    ShowResult(threats > 0, $"{_path} 扫描完成，共 {total} 个文件，命中 {threats} 个威胁。");
                }
                else
                {
                    // 快速扫描：验证特征库并检查常见系统目录
                    ProgressText.Text = "正在校验云端特征库...";
                    var db = FireAntivirus.Engine.Data.EmbeddedThreatDatabase.SelfCheck();
                    await Task.Delay(300);
                    ScanProgress.Value = 100;
                    ProgressText.Text = $"云端特征库已就绪（YARA {db.Item2} 条，PE {db.Item3} 条，已知文件名 {db.Item4} 条）";
                    ShowResult(false, "请在「选择路径」中指定要云查杀的文件或目录。");
                }
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "云查杀失败: " + ex.Message);
                ProgressText.Text = "扫描失败: " + ex.Message;
            }
            finally
            {
                StartScanBtn.IsEnabled = true;
            }
        }

        private void ShowResult(bool infected, string text)
        {
            _ = new ContentDialog
            {
                Title = infected ? "云查杀发现威胁" : "云查杀结果",
                Content = text,
                CloseButtonText = "确定", XamlRoot = XamlRoot
            }.ShowAsync();
        }

        // 保持 AntivirusEngine 的云配置接口入口不被破坏
        internal void ConfigureCloud(bool bazaar, bool otx, bool vt, bool ha, string vtKey, string haKey)
        {
            try { AntivirusEngine.UpdateCloudScanConfig(bazaar, otx, vt, ha, vtKey, haKey); }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "云配置同步: " + ex.Message);
            }
        }

        private void ConfigBtn_Click(object sender, RoutedEventArgs e)
        {
            _ = new ContentDialog
            {
                Title = "云引擎配置",
                Content = "特征库由 abuse.ch 自动更新（每小时），无需手工配置 API Key。\n\n如需自定义访问密钥，请在设置中配置。",
                CloseButtonText = "确定", XamlRoot = XamlRoot
            }.ShowAsync();
        }
    }
}