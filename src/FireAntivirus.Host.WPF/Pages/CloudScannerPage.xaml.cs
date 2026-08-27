// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Threading.Tasks;
using FireAntivirus.Services;
using FireAntivirus.Common.Localization;
using FireAntivirus.CloudScanner;

using FireAntivirus.Host.WPF;

namespace FireAntivirus.Host.WPF.Pages
{
    public partial class CloudScannerPage : Page, IThemed
    {
        private Theme currentTheme = Theme.Light;
        private System.Threading.CancellationTokenSource _cts = new();
        private bool _isLoaded = false;
        private CloudScannerService cloudScanner;
        private LanguageManager _languageManager = LanguageManager.Instance;
        private string customScanPath = "";
        private bool _isInitialized = false;
        private CloudScanConfig _cloudConfig;

        public CloudScannerPage()
        {
            InitializeComponent();

                    // 页面卸载时停止后台任务
                    Unloaded += (s, e) =>
                    {
                        _isLoaded = false;
                        _cts?.Cancel();
                    };
            _languageManager.LanguageChanged += (sender, e) => UpdateLanguage();

            // 异步初始化
            Loaded += async (s, e) =>
            {
                if (_isInitialized) return;
                _isInitialized = true;
                await Task.Run(() => InitializeService());
                RefreshEngineStatus();
            };
        }

        private void InitializeService()
        {
            try
            {
                var dataManager = new FireAntivirus.Data.DataManager();
                var antivirusEngine = new FireAntivirus.Engine.AntivirusEngine();
                cloudScanner = new CloudScannerService(dataManager, antivirusEngine);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error initializing CloudScannerService: {ex.Message}");
            }
        }

        /// <summary>加载云查杀配置并刷新 UI 显示</summary>
        private CloudScanConfig LoadConfig()
        {
            try
            {
                _cloudConfig = CloudScanConfig.Load();
                // 同步到 AntivirusEngine,让本地扫描也使用配置
                try
                {
                    FireAntivirus.Engine.AntivirusEngine.UpdateCloudScanConfig(
                        _cloudConfig.EnableMalwareBazaar,
                        _cloudConfig.EnableOTX,
                        _cloudConfig.EnableVirusTotal,
                        _cloudConfig.EnableHybridAnalysis,
                        _cloudConfig.VirusTotalApiKey,
                        _cloudConfig.HybridAnalysisApiKey);
                }
                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "CloudScannerPage.xaml.cs 捕获异常", ex.Message); }
                return _cloudConfig;
            }
            catch
            {
                _cloudConfig = new CloudScanConfig();
                return _cloudConfig;
            }
        }

        /// <summary>刷新引擎状态显示</summary>
        private void RefreshEngineStatus()
        {
            try
            {
                var cfg = LoadConfig();
                var engines = new List<string>();
                if (cfg.EnableMalwareBazaar) engines.Add("MalwareBazaar");
                if (cfg.EnableOTX) engines.Add("AlienVault OTX");
                if (cfg.EnableVirusTotal && !string.IsNullOrWhiteSpace(cfg.VirusTotalApiKey))
                    engines.Add("VirusTotal (70+ 引擎)");
                if (cfg.EnableHybridAnalysis && !string.IsNullOrWhiteSpace(cfg.HybridAnalysisApiKey))
                    engines.Add("HybridAnalysis");

                EnginesText.Text = $"已启用引擎: {string.Join(", ", engines)}";

                bool vtConfigured = !string.IsNullOrWhiteSpace(cfg.VirusTotalApiKey);
                VtStatusText.Text = vtConfigured
                    ? $"VirusTotal: 已配置 API Key ({cfg.VirusTotalApiKey.Substring(0, Math.Min(8, cfg.VirusTotalApiKey.Length))}..., 70+ 引擎已启用)"
                    : "VirusTotal: 未配置 API Key (仅使用免费引擎)";
                VtStatusText.Foreground = vtConfigured
                    ? new SolidColorBrush(Colors.Green)
                    : new SolidColorBrush(Colors.Orange);
            }
            catch (Exception ex)
            {
                EnginesText.Text = $"引擎状态加载失败: {ex.Message}";
            }
        }

        /// <summary>配置 API Key 按钮</summary>
        private void ConfigBtn_Click(object sender, RoutedEventArgs e)
        {
            var cfg = LoadConfig();

            // 弹出自定义输入对话框
            var dlg = new Window
            {
                Title = "云查杀 API Key 配置",
                Width = 480,
                Height = 360,
                WindowStartupLocation = WindowStartupLocation.CenterScreen,
                ResizeMode = ResizeMode.NoResize,
                Background = new SolidColorBrush(Color.FromRgb(245, 245, 245))
            };

            var panel = new StackPanel { Margin = new Thickness(20) };

            panel.Children.Add(new TextBlock
            {
                Text = "VirusTotal API Key",
                FontWeight = FontWeights.Bold,
                Margin = new Thickness(0, 0, 0, 5)
            });
            panel.Children.Add(new TextBlock
            {
                Text = "免费申请: https://www.virustotal.com/gui/my-apikey",
                FontSize = 10,
                Foreground = new SolidColorBrush(Color.FromRgb(100, 100, 100)),
                Margin = new Thickness(0, 0, 0, 5)
            });
            var vtBox = new TextBox
            {
                Text = cfg.VirusTotalApiKey ?? "",
                Height = 28,
                Margin = new Thickness(0, 0, 0, 15)
            };
            panel.Children.Add(vtBox);

            panel.Children.Add(new TextBlock
            {
                Text = "HybridAnalysis API Key (可选)",
                FontWeight = FontWeights.Bold,
                Margin = new Thickness(0, 0, 0, 5)
            });
            panel.Children.Add(new TextBlock
            {
                Text = "免费注册: https://www.hybrid-analysis.com",
                FontSize = 10,
                Foreground = new SolidColorBrush(Color.FromRgb(100, 100, 100)),
                Margin = new Thickness(0, 0, 0, 5)
            });
            var haBox = new TextBox
            {
                Text = cfg.HybridAnalysisApiKey ?? "",
                Height = 28,
                Margin = new Thickness(0, 0, 0, 15)
            };
            panel.Children.Add(haBox);

            var enableVt = new CheckBox
            {
                Content = "启用 VirusTotal (建议)",
                IsChecked = cfg.EnableVirusTotal,
                Margin = new Thickness(0, 0, 0, 5)
            };
            panel.Children.Add(enableVt);

            var enableHa = new CheckBox
            {
                Content = "启用 HybridAnalysis 沙箱",
                IsChecked = cfg.EnableHybridAnalysis,
                Margin = new Thickness(0, 0, 0, 15)
            };
            panel.Children.Add(enableHa);

            var btnPanel = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                HorizontalAlignment = HorizontalAlignment.Right
            };
            var okBtn = new Button
            {
                Content = "保存",
                Width = 80,
                Height = 30,
                Margin = new Thickness(0, 0, 10, 0)
            };
            var cancelBtn = new Button
            {
                Content = "取消",
                Width = 80,
                Height = 30
            };
            btnPanel.Children.Add(okBtn);
            btnPanel.Children.Add(cancelBtn);
            panel.Children.Add(btnPanel);

            okBtn.Click += (s, ev) =>
            {
                cfg.VirusTotalApiKey = vtBox.Text.Trim();
                cfg.HybridAnalysisApiKey = haBox.Text.Trim();
                cfg.EnableVirusTotal = enableVt.IsChecked == true && !string.IsNullOrWhiteSpace(cfg.VirusTotalApiKey);
                cfg.EnableHybridAnalysis = enableHa.IsChecked == true && !string.IsNullOrWhiteSpace(cfg.HybridAnalysisApiKey);
                cfg.Save();

                // 同步到 AntivirusEngine
                try
                {
                    FireAntivirus.Engine.AntivirusEngine.UpdateCloudScanConfig(
                        cfg.EnableMalwareBazaar,
                        cfg.EnableOTX,
                        cfg.EnableVirusTotal,
                        cfg.EnableHybridAnalysis,
                        cfg.VirusTotalApiKey,
                        cfg.HybridAnalysisApiKey);
                }
                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "CloudScannerPage.xaml.cs 捕获异常", ex.Message); }

                dlg.DialogResult = true;
                dlg.Close();
            };
            cancelBtn.Click += (s, ev) => { dlg.DialogResult = false; dlg.Close(); };

            dlg.Content = panel;

            if (dlg.ShowDialog() == true)
            {
                RefreshEngineStatus();
                MessageBox.Show("配置已保存。\n\n说明:\n- 免费引擎(MalwareBazaar+OTX)无需配置即可使用\n- VirusTotal 配置后可启用 70+ 国际杀毒引擎查杀\n- 下次扫描将自动使用新配置",
                    "配置已更新", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private void SelectFile_Click(object sender, RoutedEventArgs e)
        {
            var folderDialog = new System.Windows.Forms.FolderBrowserDialog();
            folderDialog.Description = "选择要扫描的文件夹";
            
            if (folderDialog.ShowDialog() == System.Windows.Forms.DialogResult.OK)
            {
                customScanPath = folderDialog.SelectedPath;
                SelectFileBtn.Content = System.IO.Path.GetFileName(customScanPath);
            }
        }

        private async void StartScan_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                StartScanBtn.IsEnabled = false;
                StopScanBtn.IsEnabled = true;
                ProgressPanel.Visibility = Visibility.Visible;

                // 确保 cloudScanner 已初始化
                if (cloudScanner == null)
                {
                    ProgressText.Text = "正在初始化云查杀服务...";
                    await Task.Run(() => InitializeService());
                }

                if (cloudScanner == null)
                {
                    MessageBox.Show("云查杀服务初始化失败, 请检查网络连接", "错误",
                        MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                string scanPath = "";
                if (QuickScanRadio.IsChecked == true)
                    scanPath = "quick";
                else if (FullScanRadio.IsChecked == true)
                    scanPath = "full";
                else
                    scanPath = customScanPath;

                // 显示已启用的云引擎
                var engines = cloudScanner?.GetEnabledEngines() ?? new List<string>();
                ProgressText.Text = $"云引擎: {string.Join(", ", engines)}";

                await Task.Delay(300);

                // 真实云查杀: 扫描选定的目录或文件
                if (!string.IsNullOrEmpty(scanPath) && scanPath != "quick" && scanPath != "full"
                    && System.IO.File.Exists(scanPath))
                {
                    // 单文件扫描
                    ScanProgress.Value = 50;
                    ProgressText.Text = $"正在云查杀: {System.IO.Path.GetFileName(scanPath)}...";
                    var fileResult = await cloudScanner.ScanFile(scanPath);
                    ScanProgress.Value = 100;

                    if (fileResult != null && fileResult.IsInfected)
                    {
                        ProgressText.Text = $"发现威胁: {fileResult.ThreatName}";
                        MessageBox.Show(
                            $"文件: {System.IO.Path.GetFileName(scanPath)}\n威胁: {fileResult.ThreatName}\n" +
                            $"引擎: {fileResult.PositiveEngines}/{fileResult.TotalEngines}\n" +
                            $"哈希: {fileResult.FileHash?.Substring(0, Math.Min(16, fileResult.FileHash?.Length ?? 0))}...",
                            "云查杀发现威胁", MessageBoxButton.OK, MessageBoxImage.Warning);
                    }
                    else
                    {
                        ProgressText.Text = $"扫描完成, 未发现威胁 ({fileResult?.TotalEngines ?? 0} 引擎查询)";
                        MessageBox.Show(
                            $"文件: {System.IO.Path.GetFileName(scanPath)}\n云查杀未发现威胁\n" +
                            $"查询引擎数: {fileResult?.TotalEngines ?? 0}",
                            "扫描结果", MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                }
                else if (!string.IsNullOrEmpty(scanPath) && scanPath != "quick" && scanPath != "full"
                         && System.IO.Directory.Exists(scanPath))
                {
                    // 目录扫描
                    var cts = System.Threading.CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
                    cloudScanner.ScanProgressChanged += (currentFile, scanned, total) =>
                    {
                        Dispatcher.Invoke(() =>
                        {
                            ScanProgress.Value = total > 0 ? (double)scanned / total * 100 : 0;
                            ProgressText.Text = $"[{scanned}/{total}] {System.IO.Path.GetFileName(currentFile)}";
                        });
                    };

                    var dirResult = await cloudScanner.ScanDirectory(scanPath, cts.Token);
                    ScanProgress.Value = 100;

                    if (dirResult.IsInfected)
                    {
                        ProgressText.Text = $"发现 {dirResult.PositiveEngines} 个威胁文件";
                        MessageBox.Show(
                            $"目录: {System.IO.Path.GetFileName(scanPath)}\n" +
                            $"发现威胁文件数: {dirResult.PositiveEngines}\n" +
                            $"扫描文件总数: {dirResult.TotalEngines}",
                            "云查杀发现威胁", MessageBoxButton.OK, MessageBoxImage.Warning);
                    }
                    else
                    {
                        ProgressText.Text = $"扫描完成, 未发现威胁 (共{dirResult.TotalEngines}个文件)";
                        MessageBox.Show(
                            $"目录: {System.IO.Path.GetFileName(scanPath)}\n云查杀未发现威胁\n" +
                            $"扫描文件总数: {dirResult.TotalEngines}",
                            "扫描结果", MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                }
                else
                {
                    // 快速/全盘扫描: 用本地引擎扫描常见位置
                    ScanProgress.Value = 100;
                    ProgressText.Text = "云查杀服务已就绪, 请选择具体文件或目录进行扫描";
                    MessageBox.Show(
                        $"已启用云引擎:\n{string.Join("\n", engines)}\n\n" +
                        "请在右侧选择具体文件或目录进行云查杀",
                        "云查杀就绪", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"扫描失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                StartScanBtn.IsEnabled = true;
                StopScanBtn.IsEnabled = false;
            }
        }

        private void StopScan_Click(object sender, RoutedEventArgs e)
        {
            ProgressText.Text = "扫描已停止";
            StartScanBtn.IsEnabled = true;
            StopScanBtn.IsEnabled = false;
        }

        public void ApplyTheme(Theme theme)
        {
            currentTheme = theme;
            if (theme == Theme.Dark)
            {
                MainGrid.Background = new SolidColorBrush(Color.FromRgb(30, 30, 30));
            }
            else
            {
                MainGrid.Background = new SolidColorBrush(Colors.White);
            }
        }

        private void UpdateLanguage()
        {
            try
            {
                TitleText.Text = _languageManager.GetString("CloudScanner", "云查杀");
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "CloudScannerPage.xaml.cs 捕获异常", ex.Message); }
        }
    }
}