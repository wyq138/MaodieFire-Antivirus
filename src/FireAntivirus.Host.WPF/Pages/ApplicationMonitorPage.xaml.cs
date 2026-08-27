// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using FireAntivirus.Services;
using FireAntivirus.Data;
using FireAntivirus.Common.Localization;
using FireAntivirus.ApplicationMonitor;

namespace FireAntivirus.Host.WPF.Pages
{
    public partial class ApplicationMonitorPage : Page, IThemed
    {
        private Theme currentTheme = Theme.Light;
        private ApplicationMonitorManager appMonitor;
        private LanguageManager _languageManager = LanguageManager.Instance;
        private List<ProcessInfo> processList = new List<ProcessInfo>();
        private DispatcherTimer updateTimer;
        private System.Threading.CancellationTokenSource _cts = new();
        private bool _isLoaded = false;
        private System.Diagnostics.PerformanceCounter cpuCounter;
        private System.Diagnostics.PerformanceCounter memCounter;
        private Dictionary<int, TimeSpan> processCpuTime = new Dictionary<int, TimeSpan>();
        private DateTime lastCpuCheck;
        private bool isInitialized = false;

        public ApplicationMonitorPage()
        {
            InitializeComponent();
                
                // 页面卸载时停止后台任务
                Unloaded += (s, e) =>
                {
                    _isLoaded = false;
                    _cts?.Cancel();
                    if (updateTimer != null) updateTimer.Stop();
                };
            Loaded += OnPageLoaded;
            _languageManager.LanguageChanged += (sender, e) => UpdateLanguage();
            ProcessGrid.SelectionChanged += ProcessGrid_SelectionChanged;
        }

        private void OnPageLoaded(object sender, RoutedEventArgs e)
        {
            if (isInitialized) return;
            isInitialized = true;
            
            _ = System.Threading.Tasks.Task.Run(() =>
            {
                InitializeService();
                InitializePerformanceCounters();
                LoadProcessesAsync();
            });
            
            SetupTimer();
            updateTimer.Start(); // 自动启动定时器
        }

        private void InitializeService()
        {
            try { appMonitor = new ApplicationMonitorManager(new DataManager()); } catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ApplicationMonitorPage.xaml.cs 捕获异常", ex.Message); }
        }

        private void InitializePerformanceCounters()
        {
            try
            {
                cpuCounter = new System.Diagnostics.PerformanceCounter("Processor", "% Processor Time", "_Total");
                cpuCounter.NextValue();
                memCounter = new System.Diagnostics.PerformanceCounter("Memory", "% Committed Bytes In Use");
                memCounter.NextValue();
                lastCpuCheck = DateTime.Now;
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ApplicationMonitorPage.xaml.cs 捕获异常", ex.Message); }
        }

        private void SetupTimer()
        {
            updateTimer = new DispatcherTimer();
            updateTimer.Interval = TimeSpan.FromSeconds(1);
            updateTimer.Tick += UpdateTimer_Tick;
            updateTimer.Start();
        }

        private void UpdateTimer_Tick(object sender, EventArgs e)
        {
            UpdateResourceOverview();
        }

        private void LoadProcessesAsync()
        {
            var list = new List<ProcessInfo>();
            var currentTime = DateTime.Now;
            
            try
            {
                var processes = Process.GetProcesses();
                
                foreach (var p in processes)
                {
                    try
                    {
                        string cpuUsage = "0%";
                        
                        try
                        {
                            var totalTime = p.TotalProcessorTime;
                            if (processCpuTime.ContainsKey(p.Id))
                            {
                                var elapsed = (currentTime - lastCpuCheck).TotalMilliseconds;
                                if (elapsed > 0)
                                {
                                    var cpuTime = (totalTime - processCpuTime[p.Id]).TotalMilliseconds;
                                    var cpuPercent = (cpuTime / elapsed) * 100 / Environment.ProcessorCount;
                                    cpuUsage = $"{Math.Min(cpuPercent, 100):F1}%";
                                }
                            }
                            processCpuTime[p.Id] = totalTime;
                        }
                        catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ApplicationMonitorPage.xaml.cs 捕获异常", ex.Message); }
                        
                        list.Add(new ProcessInfo
                        {
                            ProcessName = p.ProcessName,
                            PID = p.Id,
                            CPU = cpuUsage,
                            Memory = FormatBytes(p.WorkingSet64),
                            Status = p.Responding ? "运行中" : "无响应",
                            Path = TryGetProcessPath(p)
                        });
                    }
                    catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ApplicationMonitorPage.xaml.cs 捕获异常", ex.Message); }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ApplicationMonitorPage.xaml.cs 捕获异常", ex.Message); }
            
            lastCpuCheck = currentTime;
            
            Dispatcher.BeginInvoke(new Action(() =>
            {
                processList = list;
                ProcessGrid.ItemsSource = null;
                ProcessGrid.ItemsSource = processList;
            }));
        }

        private string TryGetProcessPath(Process p)
        {
            try { return p.MainModule?.FileName ?? "--"; }
            catch { return "--"; }
        }

        private void UpdateResourceOverview()
        {
            try
            {
                float cpuUsage = cpuCounter?.NextValue() ?? 0;
                float memUsage = memCounter?.NextValue() ?? 0;
                
                CpuUsageText.Text = $"{cpuUsage:F0}%";
                CpuProgressBar.Value = Math.Min(cpuUsage, 100);
                MemoryUsageText.Text = $"{memUsage:F0}%";
                MemoryProgressBar.Value = Math.Min(memUsage, 100);
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ApplicationMonitorPage.xaml.cs 捕获异常", ex.Message); }
        }

        private string FormatBytes(long bytes)
        {
            string[] suffixes = { "B", "KB", "MB", "GB" };
            int i = 0;
            double size = bytes;
            while (size >= 1024 && i < suffixes.Length - 1) { size /= 1024; i++; }
            return $"{size:F1} {suffixes[i]}";
        }

        private void ProcessGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (ProcessGrid.SelectedItem is ProcessInfo info)
            {
                DetailProcessName.Text = $"进程名: {info.ProcessName}";
                DetailProcessPath.Text = $"路径: {info.Path}";
                DetailProcessUser.Text = $"状态: {info.Status}";
                DetailProcessThreads.Text = $"PID: {info.PID}";
                DetailProcessHandles.Text = $"内存: {info.Memory}";
                DetailProcessStartTime.Text = $"CPU: {info.CPU}";
            }
        }

        private void RefreshProcess_Click(object sender, RoutedEventArgs e)
        {
            _ = System.Threading.Tasks.Task.Run(() => LoadProcessesAsync());
        }

        /// <summary>
        /// 查看可疑进程详情：优先显示列表中选中进程的详情，否则提示先选择
        /// </summary>
        private void ShowSuspiciousDetails_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (ProcessGrid.SelectedItem is ProcessInfo info)
                {
                    // 已选中进程，刷新详情面板并滚动到详情区域
                    DetailProcessName.Text = $"进程名: {info.ProcessName}";
                    DetailProcessPath.Text = $"路径: {info.Path}";
                    DetailProcessUser.Text = $"状态: {info.Status}";
                    DetailProcessThreads.Text = $"PID: {info.PID}";
                    DetailProcessHandles.Text = $"内存: {info.Memory}";
                    DetailProcessStartTime.Text = $"CPU: {info.CPU}";
                    ProcessDetailPanel.Visibility = Visibility.Visible;
                }
                else
                {
                    System.Windows.MessageBox.Show("请先在进程列表中选择一个进程，再点击查看详情。", "提示",
                        MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ApplicationMonitorPage.xaml.cs 捕获异常", ex.Message); }
        }

        private void EndProcess_Click(object sender, RoutedEventArgs e)
        {
            if (ProcessGrid.SelectedItem is ProcessInfo info)
            {
                var result = MessageBox.Show($"确定要结束进程: {info.ProcessName} (PID: {info.PID})?", "确认结束进程", MessageBoxButton.YesNo, MessageBoxImage.Warning);
                if (result == MessageBoxResult.Yes)
                {
                    try
                    {
                        var process = Process.GetProcessById(info.PID);
                        process.Kill();
                        _ = System.Threading.Tasks.Task.Run(() => LoadProcessesAsync());
                        MessageBox.Show("进程已结束", "成功", MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show($"无法结束进程: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                    }
                }
            }
            else
            {
                MessageBox.Show("请先选择一个进程", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

public void ApplyTheme(Theme theme)
        {
            currentTheme = theme;
            if (theme == Theme.Dark) MainGrid.Background = new SolidColorBrush(Color.FromRgb(30, 30, 30));
            else MainGrid.Background = new SolidColorBrush(Colors.White);
        }

        private void UpdateLanguage()
        {
            try { TitleText.Text = _languageManager.GetString("ApplicationMonitor", "应用监控"); } catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ApplicationMonitorPage.xaml.cs 捕获异常", ex.Message); }
        }
    }

    public class ProcessInfo
    {
        public string ProcessName { get; set; }
        public int PID { get; set; }
        public string CPU { get; set; }
        public string Memory { get; set; }
        public string Status { get; set; }
        public string Path { get; set; }
    }
}