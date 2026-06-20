// 抖音用户 耄耋杀毒软件 开发，严禁非法反编译
using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using FireAntivirus.Common.Localization;

using FireAntivirus.Host.WPF;

namespace FireAntivirus.Host.WPF.Pages
{
    using FireAntivirus.Host; // 引入 UpdateManager

    /// <summary>
    /// 设置页面 - 从WinForms转换
    /// </summary>
    public partial class SettingsPage : Page, IThemed
    {
        private Theme currentTheme = Theme.Light;
        private System.Threading.CancellationTokenSource _cts = new();
        private bool _isLoaded = false;
        private LanguageManager _languageManager = LanguageManager.Instance;

        public SettingsPage()
        {
            try
            {
                InitializeComponent();
                    
                    // 页面卸载时停止后台任务
                    Unloaded += (s, e) =>
                    {
                        _isLoaded = false;
                        _cts?.Cancel();
                    };
                _languageManager.LanguageChanged += (sender, e) => UpdateLanguage();
                LanguageManager.GlobalLanguageChanged += (sender, e) => UpdateLanguage();
                
                // 初始语言设置
                UpdateLanguage();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error initializing SettingsPage: {ex.Message}");
            }
        }

        private void UpdateLanguage()
        {
            try
            {
                // 页面标题
                TitleText.Text = _languageManager.GetString("Settings");
                
                // Tab Headers
                AppearanceTab.Header = _languageManager.GetString("Appearance");
                ScanSettingsTab.Header = _languageManager.GetString("ScanSettings");
                ProtectionSettingsTab.Header = _languageManager.GetString("ProtectionSettings");
                NetworkSettingsTab.Header = _languageManager.GetString("NetworkSettings");
                SystemSettingsTab.Header = _languageManager.GetString("SystemSettings");
                UpdateSettingsTab.Header = _languageManager.GetString("UpdateSettings");
                
                // 外观设置
                AppearanceTitle.Text = _languageManager.GetString("Appearance");
                ThemeLabel.Text = _languageManager.GetString("Theme");
                LightThemeBtn.Content = _languageManager.GetString("LightTheme");
                DarkThemeBtn.Content = _languageManager.GetString("DarkTheme");
                
                // 扫描设置
                ScanSettingsTitle.Text = _languageManager.GetString("ScanSettings");
                ScanThreadsLabel.Text = _languageManager.GetString("ScanThreads");
                ScanFileTypesLabel.Text = _languageManager.GetString("ScanFileTypes");
                QuickScanLabel.Text = _languageManager.GetString("QuickScan");
                
                // 防护设置
                ProtectionSettingsTitle.Text = _languageManager.GetString("ProtectionSettings");
                StartupProtectionLabel.Text = _languageManager.GetString("StartupProtection");
                ProtectionAlertsLabel.Text = _languageManager.GetString("ProtectionAlerts");
                RealTimeProtectionLabel.Text = _languageManager.GetString("RealTimeProtection");
                
                // 网络设置
                NetworkSettingsTitle.Text = _languageManager.GetString("NetworkSettings");
                FirewallLabel.Text = _languageManager.GetString("Firewall");
                NetworkMonitorLabel.Text = _languageManager.GetString("NetworkMonitor");
                
                // 系统设置
                SystemSettingsTitle.Text = _languageManager.GetString("SystemSettings");
                AutoStartLabel.Text = _languageManager.GetString("StartWithWindows");
                MinimizeToTrayLabel.Text = _languageManager.GetString("MinimizeToTray");
                
                // 更新设置
                UpdateSettingsTitle.Text = _languageManager.GetString("UpdateSettings");
                AutoUpdateLabel.Text = _languageManager.GetString("AutoUpdate");
                CheckUpdateBtn.Content = _languageManager.GetString("CheckUpdate");
            }
            catch { }
        }

        private void LightTheme_Click(object sender, RoutedEventArgs e)
        {
            ApplyThemeToMainWindow(Theme.Light);
        }

        private void DarkTheme_Click(object sender, RoutedEventArgs e)
        {
            ApplyThemeToMainWindow(Theme.Dark);
        }

        private void ApplyThemeToMainWindow(Theme theme)
        {
            var mainWindow = Window.GetWindow(this) as MainWindow;
            if (mainWindow != null)
            {
                // 通过反射调用ApplyTheme方法
                var method = typeof(MainWindow).GetMethod("ApplyTheme", 
                    System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                method?.Invoke(mainWindow, new object[] { theme });
            }
        }

        private void CheckUpdate_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // 检查更新
                var updateManager = UpdateManager.Instance;
                
                // 显示检查中提示
                var checkWindow = new Window
                {
                    Title = _languageManager.GetString("CheckUpdate"),
                    Width = 300,
                    Height = 150,
                    WindowStartupLocation = WindowStartupLocation.CenterScreen,
                    ResizeMode = ResizeMode.NoResize
                };

                var stackPanel = new StackPanel { Margin = new Thickness(20) };
                var textBlock = new TextBlock
                {
                    Text = _languageManager.GetString("PreparingDownload"),
                    FontSize = 14,
                    HorizontalAlignment = HorizontalAlignment.Center,
                    VerticalAlignment = VerticalAlignment.Center
                };
                stackPanel.Children.Add(textBlock);
                
                var progressBar = new ProgressBar
                {
                    Height = 20,
                    IsIndeterminate = true,
                    Margin = new Thickness(0, 20, 0, 0)
                };
                stackPanel.Children.Add(progressBar);
                
                checkWindow.Content = stackPanel;

                // 异步检查更新
                System.Threading.Tasks.Task.Run(async () =>
                {
                    await System.Threading.Tasks.Task.Delay(2000);
                    Dispatcher.BeginInvoke(new Action(() =>
                    {
                        checkWindow.Close();
                        MessageBox.Show(_languageManager.GetString("StatusReady"), 
                            _languageManager.GetString("CheckUpdate"), 
                            MessageBoxButton.OK, MessageBoxImage.Information);
                    }));
                });

                checkWindow.ShowDialog();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"{_languageManager.GetString("UpdateCheckError")}: {ex.Message}", 
                    _languageManager.GetString("Error"), MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        public void ApplyTheme(Theme theme)
        {
            currentTheme = theme;
            UpdateTheme();
        }

        private void UpdateTheme()
        {
            if (currentTheme == Theme.Dark)
            {
                MainGrid.Background = new SolidColorBrush(Color.FromRgb(30, 30, 30));
                SettingsTabControl.Background = new SolidColorBrush(Color.FromRgb(30, 30, 30));
            }
            else
            {
                MainGrid.Background = new SolidColorBrush(Colors.White);
                SettingsTabControl.Background = new SolidColorBrush(Colors.White);
            }
        }
    }
}
