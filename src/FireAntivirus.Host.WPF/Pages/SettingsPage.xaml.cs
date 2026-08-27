// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using FireAntivirus.Common.Localization;
using Microsoft.Win32;

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

        // 开机自启动注册表路径
        private const string StartupRegistryPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
        private const string AppName = "FireAntivirus";

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

                // 页面加载后读取开机自启动状态
                Loaded += (s, e) =>
                {
                    if (!_isLoaded)
                    {
                        _isLoaded = true;
                        LoadAutoStartStatus();
                    }
                };
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error initializing SettingsPage: {ex.Message}");
            }
        }

        /// <summary>
        /// 加载开机自启动状态
        /// </summary>
        private void LoadAutoStartStatus()
        {
            try
            {
                bool isAutoStartEnabled = IsAutoStartEnabled();
                AutoStartCheckBox.IsChecked = isAutoStartEnabled;
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SettingsPage 加载开机自启动状态失败", ex.Message);
            }
        }

        /// <summary>
        /// 检查开机自启动是否已启用
        /// </summary>
        private bool IsAutoStartEnabled()
        {
            try
            {
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(StartupRegistryPath, false))
                {
                    if (key != null)
                    {
                        string value = key.GetValue(AppName) as string;
                        return !string.IsNullOrEmpty(value);
                    }
                }
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "检查开机自启动状态失败", ex.Message);
            }
            return false;
        }

        /// <summary>
        /// 设置开机自启动
        /// </summary>
        private void SetAutoStart(bool enable)
        {
            try
            {
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(StartupRegistryPath, true))
                {
                    if (key != null)
                    {
                        if (enable)
                        {
                            // 获取当前程序路径
                            string exePath = System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName;
                            if (!string.IsNullOrEmpty(exePath))
                            {
                                key.SetValue(AppName, $"\"{exePath}\"");
                                FireAntivirus.Common.LogHelper.Info("开机自启动已启用", $"路径: {exePath}");
                            }
                        }
                        else
                        {
                            key.DeleteValue(AppName, false);
                            FireAntivirus.Common.LogHelper.Info("开机自启动已禁用", "");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "设置开机自启动失败", ex.Message);
                MessageBox.Show($"设置开机自启动失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// 开机自启动复选框状态改变事件
        /// </summary>
        private void AutoStartCheckBox_Changed(object sender, RoutedEventArgs e)
        {
            if (_isLoaded && AutoStartCheckBox.IsChecked.HasValue)
            {
                SetAutoStart(AutoStartCheckBox.IsChecked.Value);
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
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SettingsPage.xaml.cs 捕获异常", ex.Message); }
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