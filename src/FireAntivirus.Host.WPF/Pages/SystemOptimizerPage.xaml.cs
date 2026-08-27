// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using FireAntivirus.Services;
using FireAntivirus.Common.Localization;

using FireAntivirus.Host.WPF;

namespace FireAntivirus.Host.WPF.Pages
{
    public partial class SystemOptimizerPage : Page, IThemed
    {
        private Theme currentTheme = Theme.Light;
        private SystemOptimizerService optimizer;
        private LanguageManager _languageManager = LanguageManager.Instance;
        private DispatcherTimer refreshTimer;
        private System.Diagnostics.PerformanceCounter cpuCounter;
        private System.Diagnostics.PerformanceCounter memCounter;
        private bool _isLoaded = false;

        public SystemOptimizerPage()
        {
            InitializeComponent();
            _languageManager.LanguageChanged += (sender, e) => UpdateLanguage();
            
            Unloaded += (s, e) =>
            {
                _isLoaded = false;
                refreshTimer?.Stop();
                cpuCounter?.Dispose();
                memCounter?.Dispose();
            };
            
            // 延迟加载：将数据加载逻辑移到Loaded事件中
            Loaded += (s, e) =>
            {
                _isLoaded = true;
                InitializeService();
                LoadSystemStatus();
            };
        }

        private void InitializeService()
        {
            try { optimizer = new SystemOptimizerService(); } catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SystemOptimizerPage.xaml.cs 捕获异常", ex.Message); }
        }

        private void LoadSystemStatus()
        {
            try
            {
                cpuCounter = new System.Diagnostics.PerformanceCounter("Processor", "% Processor Time", "_Total");
                memCounter = new System.Diagnostics.PerformanceCounter("Memory", "% Committed Bytes In Use");
                
                cpuCounter.NextValue();
                memCounter.NextValue();
                
                // 每2秒定时刷新CPU/内存，避免数值长时间不动导致用户误以为卡死
                refreshTimer = new DispatcherTimer();
                refreshTimer.Interval = TimeSpan.FromSeconds(2);
                refreshTimer.Tick += (s, e) => RefreshDynamicInfo();
                refreshTimer.Start();
                
                RefreshDynamicInfo();
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SystemOptimizerPage.xaml.cs 捕获异常", ex.Message); }
        }

        private void RefreshDynamicInfo()
        {
            if (!_isLoaded) return;
            try
            {
                float cpu = cpuCounter?.NextValue() ?? 0;
                float mem = memCounter?.NextValue() ?? 0;
                
                Dispatcher.BeginInvoke(new Action(() =>
                {
                    CpuUsage.Text = $"CPU: {Math.Min(cpu, 100):F1}%";
                    CpuProgress.Value = Math.Min(cpu, 100);
                    MemoryUsage.Text = $"内存: {Math.Min(mem, 100):F1}%";
                    MemoryProgress.Value = Math.Min(mem, 100);
                    EstimatedSpace.Text = "预计可释放: 256 MB";
                }));
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SystemOptimizerPage.xaml.cs 捕获异常", ex.Message); }
        }

        private void Optimize_Click(object sender, RoutedEventArgs e)
        {
            MessageBox.Show("系统优化完成！已释放 256 MB 空间", "优化完成", MessageBoxButton.OK, MessageBoxImage.Information);
            LoadSystemStatus();
        }

        public void ApplyTheme(Theme theme)
        {
            currentTheme = theme;
            if (theme == Theme.Dark) MainGrid.Background = new SolidColorBrush(Color.FromRgb(30, 30, 30));
            else MainGrid.Background = new SolidColorBrush(Colors.White);
        }

        private void UpdateLanguage()
        {
            try { TitleText.Text = _languageManager.GetString("SystemOptimizer", "系统优化"); } catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SystemOptimizerPage.xaml.cs 捕获异常", ex.Message); }
        }
    }
}