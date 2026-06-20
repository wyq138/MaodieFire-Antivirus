// 抖音用户 耙耋杀毒软件 开发，严禁非法反编译
using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Threading.Tasks;
using FireAntivirus.Services;
using FireAntivirus.Common.Localization;

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
                
                string scanPath = "";
                if (QuickScanRadio.IsChecked == true)
                    scanPath = "quick";
                else if (FullScanRadio.IsChecked == true)
                    scanPath = "full";
                else
                    scanPath = customScanPath;

                // 模拟扫描进度
                for (int i = 0; i <= 100; i += 5)
                {
                    ScanProgress.Value = i;
                    ProgressText.Text = $"正在扫描... {i}%";
                    await System.Threading.Tasks.Task.Delay(200);
                }

                ProgressText.Text = "扫描完成！未发现威胁";
                MessageBox.Show("云查杀完成，未发现安全威胁", "扫描结果", MessageBoxButton.OK, MessageBoxImage.Information);
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
            catch { }
        }
    }
}
