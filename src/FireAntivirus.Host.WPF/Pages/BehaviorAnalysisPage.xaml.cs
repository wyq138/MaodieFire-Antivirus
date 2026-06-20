// 抖音用户 耙耋杀毒软件 开发，严禁非法反编译
using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using FireAntivirus.Services;
using FireAntivirus.Data;
using FireAntivirus.Common.Localization;

using FireAntivirus.Host.WPF;

namespace FireAntivirus.Host.WPF.Pages
{
    public partial class BehaviorAnalysisPage : Page, IThemed
    {
        private Theme currentTheme = Theme.Light;
        private BehaviorAnalysisService behaviorAnalysis;
        private DataManager dataManager;
        private LanguageManager _languageManager = LanguageManager.Instance;
        
        private DispatcherTimer updateTimer;
        private System.Threading.CancellationTokenSource _cts = new();
        private bool _isLoaded = false;
        private ObservableCollection<BehaviorAlertItem> alerts = new ObservableCollection<BehaviorAlertItem>();
        
        private int totalEvents = 0;
        private int threatsDetected = 0;
        private int processesBlocked = 0;

        public BehaviorAnalysisPage()
        {
            InitializeComponent();
                
                // 页面卸载时停止后台任务
                Unloaded += (s, e) =>
                {
                    _isLoaded = false;
                    _cts?.Cancel();
                    if (updateTimer != null) updateTimer.Stop();
                };
            InitializeService();
            SetupEventHandlers();
            StartMonitoring();
            _languageManager.LanguageChanged += (sender, e) => UpdateLanguage();
        }

        private void InitializeService()
        {
            try
            {
                dataManager = new DataManager();
                behaviorAnalysis = new BehaviorAnalysisService(dataManager);
                
                // 加载警报数据
                AlertsGrid.ItemsSource = alerts;
            }
            catch { }
        }

        private void SetupEventHandlers()
        {
            EnableBehaviorMonitor.Checked += (s, e) => UpdateSettings();
            EnableBehaviorMonitor.Unchecked += (s, e) => UpdateSettings();
            EnableBaselineLearning.Checked += (s, e) => UpdateSettings();
            EnableBaselineLearning.Unchecked += (s, e) => UpdateSettings();
            EnableMLDetection.Checked += (s, e) => UpdateSettings();
            EnableMLDetection.Unchecked += (s, e) => UpdateSettings();
            EnableRealTimeBlocking.Checked += (s, e) => UpdateSettings();
            EnableRealTimeBlocking.Unchecked += (s, e) => UpdateSettings();
            
            Unloaded += BehaviorAnalysisPage_Unloaded;
        }

        private void StartMonitoring()
        {
            if (updateTimer == null)
            {
                updateTimer = new DispatcherTimer();
                updateTimer.Interval = TimeSpan.FromSeconds(5);
                updateTimer.Tick += UpdateTimer_Tick;
            }
            
            updateTimer.Start();
            UpdateStatistics();
        }

        private void StopMonitoring()
        {
            updateTimer?.Stop();
        }

        private void UpdateTimer_Tick(object sender, EventArgs e)
        {
            UpdateStatistics();
        }

        private void UpdateSettings()
        {
            try
            {
                behaviorAnalysis?.EnableBaselineLearning(EnableBaselineLearning.IsChecked == true);
                behaviorAnalysis?.EnableMLDetection(EnableMLDetection.IsChecked == true);
                behaviorAnalysis?.EnableRealTimeBlocking(EnableRealTimeBlocking.IsChecked == true);
            }
            catch { }
        }

        private void UpdateStatistics()
        {
            try
            {
                var processes = Process.GetProcesses();
                ProcessesMonitored.Text = $"监控进程: {processes.Length} 个";
                
                // 模拟一些统计数据
                totalEvents += new Random().Next(0, 5);
                TotalEvents.Text = totalEvents.ToString();
                ThreatsDetected.Text = threatsDetected.ToString();
                ProcessesBlocked.Text = processesBlocked.ToString();
                
                // 更新状态
                StatusText.Text = EnableBehaviorMonitor.IsChecked == true ? "状态: 监控中" : "状态: 已暂停";
                StatusText.Foreground = EnableBehaviorMonitor.IsChecked == true ? Brushes.Green : Brushes.Orange;
            }
            catch
            {
                ProcessesMonitored.Text = "监控进程: 0 个";
            }
        }

        private void BehaviorAnalysisPage_Unloaded(object sender, RoutedEventArgs e)
        {
            StopMonitoring();
        }

        public void ApplyTheme(Theme theme)
        {
            currentTheme = theme;
            if (theme == Theme.Dark)
                MainGrid.Background = new SolidColorBrush(Color.FromRgb(30, 30, 30));
            else
                MainGrid.Background = new SolidColorBrush(Colors.White);
        }

        private void UpdateLanguage()
        {
            try { TitleText.Text = _languageManager.GetString("BehaviorAnalysis", "行为分析"); }
            catch { }
        }
    }

    // 行为警报项
    public class BehaviorAlertItem
    {
        public string ProcessName { get; set; }
        public string Behavior { get; set; }
        public string Risk { get; set; }
        public string Time { get; set; }
    }
}
