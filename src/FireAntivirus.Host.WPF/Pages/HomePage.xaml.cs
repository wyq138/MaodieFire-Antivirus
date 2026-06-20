// 抖音用户 耄耋杀毒软件 开发，严禁非法反编译
using System;
using System.IO;
using System.Reflection;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using System.Diagnostics;
using System.Collections.Generic;
using FireAntivirus.Common.Localization;
using FireAntivirus.Data;
using FireAntivirus.Engine;
using FireAntivirus.Services;

using FireAntivirus.Host.WPF;

namespace FireAntivirus.Host.WPF.Pages
{
    /// <summary>
    /// 主页 - 完整实现
    /// </summary>
    public partial class HomePage : Page, IThemed
    {
        private Theme currentTheme = Theme.Light;
        private LanguageManager _languageManager;  // 延迟初始化
        private DispatcherTimer statusTimer;
        private System.Threading.CancellationTokenSource _cts = new();
        private bool _isLoaded = false;
        private Process[] _cachedProtectionProcesses;
        private DateTime _lastProcessUpdate = DateTime.MinValue;
        private const int PROCESS_CACHE_MINUTES = 0;
        private static readonly object _cacheLock = new object();
        private DataManager dataManager;
        private SecurityScoreService scoreService;
        private Process[] protectionProcesses;

        private static readonly string LogFilePath = Path.Combine(
            Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) ?? ".", 
            "homepage.log");
        
        private Stopwatch _loadingStopwatch = new Stopwatch();
        private int _loadingStep = 0;

        public HomePage()
        {
            try
            {
                InitializeComponent();
                
                // 所有初始化延迟到 Loaded 事件，避免阻塞UI
                Loaded += HomePage_Loaded;
                
                // 页面卸载时停止后台任务
                Unloaded += (s, e) =>
                {
                    _isLoaded = false;
                    _cts?.Cancel();
                    statusTimer?.Stop();
                };
            }
            catch (Exception ex)
            {
                System.Windows.MessageBox.Show($"HomePage初始化失败: {ex.Message}", "错误", 
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void HomePage_Loaded(object sender, RoutedEventArgs e)
        {
            _isLoaded = true;
            _loadingStopwatch.Start();
            UpdateLoadingStatus(10, "初始化界面...");
            
            // 使用ConfigureAwait(false)优化异步初始化，避免不必要的上下文切换
            _ = Task.Run(async () =>
            {
                // 后台线程初始化LanguageManager
                UpdateLoadingStatus(20, "加载语言设置...");
                try 
                { 
                    _languageManager = LanguageManager.Instance;
                    Dispatcher.BeginInvoke(() =>
                    {
                        _languageManager.LanguageChanged += (s, ev) => UpdateLanguage();
                    });
                } 
                catch { }
                
                await Task.Delay(100).ConfigureAwait(false);
                UpdateLoadingStatus(40, "初始化服务...");
                await InitializeServicesAsync().ConfigureAwait(false);
                
                // 回到UI线程初始化定时器
                Dispatcher.BeginInvoke(() =>
                {
                    UpdateLoadingStatus(70, "启动状态监控...");
                    InitializeTimer();
                    // 使用完全异步的模式更新状态
                    _ = UpdateStatsAsync(_cts.Token);
                    UpdateLoadingStatus(100, "准备完成...");
                    _loadingStopwatch.Stop();
                });
            });
        }

        private async Task InitializeServicesAsync()
        {
            try
            {
                // 并行初始化服务以加速启动
                var dataManagerTask = Task.Run(() =>
                {
                    try { return new DataManager(); } catch { return null; }
                }, _cts.Token);
                
                var scoreServiceTask = Task.Run(() =>
                {
                    try { return new SecurityScoreService(); } catch { return null; }
                }, _cts.Token);
                
                await Task.WhenAll(dataManagerTask, scoreServiceTask).ConfigureAwait(false);
                
                // 赋值结果
                dataManager = await dataManagerTask;
                scoreService = await scoreServiceTask;
            }
            catch (OperationCanceledException)
            {
                // 任务被取消，正常退出
            }
            catch (Exception ex)
            {
                Log($"InitializeServicesAsync error: {ex.Message}");
            }
        }

        private void UpdateLoadingStatus(int progress, string message)
        {
            // 使用BeginInvoke异步更新UI，避免阻塞
            Dispatcher.BeginInvoke(() =>
            {
                try
                {
                    // 这里可以添加进度条或其他加载指示器的更新逻辑
                    // 例如：LoadingProgress.Value = progress;
                    // LoadingText.Text = message;
                    _loadingStep = progress;
                    
                    // 记录加载时间用于性能监控
                    Debug.WriteLine($"Loading step {progress}: {message} - {_loadingStopwatch.ElapsedMilliseconds}ms");
                }
                catch { }
            });
        }

        private void InitializeTimer()
        {
            statusTimer = new DispatcherTimer();
            statusTimer.Interval = TimeSpan.FromSeconds(10);
            statusTimer.Tick += async (s, e) => await UpdateStatsAsync(_cts.Token);
            statusTimer.Start();
        }

        private async System.Threading.Tasks.Task<bool> GetCachedProtectionStatusAsync(System.Threading.CancellationToken cancellationToken)
        {
            if (cancellationToken.IsCancellationRequested)
                return false;

            lock (_cacheLock)
            {
                // 使用缓存，避免频繁调用Process.GetProcessesByName()
                if (_cachedProtectionProcesses != null && 
                    (DateTime.Now - _lastProcessUpdate).TotalMinutes < PROCESS_CACHE_MINUTES)
                {
                    return _cachedProtectionProcesses.Length > 0;
                }
            }

            return await System.Threading.Tasks.Task.Run(() =>
            {
                if (cancellationToken.IsCancellationRequested)
                    return false;

                try
                {
                    var processes = Process.GetProcessesByName("FireAntivirus.Service");
                    
                    lock (_cacheLock)
                    {
                        _cachedProtectionProcesses = processes;
                        _lastProcessUpdate = DateTime.Now;
                    }
                    
                    return processes.Length > 0;
                }
                catch (Exception)
                {
                    return false;
                }
            }, cancellationToken);
        }

        private async System.Threading.Tasks.Task UpdateStatsAsync(System.Threading.CancellationToken cancellationToken)
        {
            if (!_isLoaded || cancellationToken.IsCancellationRequested)
                return;
            
            try
            {
                // 并行执行所有独立的数据获取任务
                var protectionTask = GetCachedProtectionStatusAsync(cancellationToken);
                var virusDbTask = System.Threading.Tasks.Task.Run(() => GetVirusDbStatus(cancellationToken), cancellationToken);
                var systemStatusTask = System.Threading.Tasks.Task.Run(() => GetSystemStatus(cancellationToken), cancellationToken);
                var recentActivityTask = System.Threading.Tasks.Task.Run(() => GetRecentActivity(cancellationToken), cancellationToken);

                // 等待所有任务完成并获取结果
                var isProtected = await protectionTask;
                var (virusStatus, virusVersion, virusColor) = await virusDbTask;
                var (sysStatus, sysDesc, sysColor) = await systemStatusTask;
                var recentActivity = await recentActivityTask;

                if (cancellationToken.IsCancellationRequested)
                    return;

                // 使用BeginInvoke异步更新UI，避免阻塞
                Dispatcher.BeginInvoke(new Action(() =>
                {
                    if (!_isLoaded) return;

                    // 更新防护状态
                    ProtectionStatusValue.Text = isProtected ? "已启用" : "未运行";
                    ProtectionStatusValue.Foreground = new SolidColorBrush(isProtected ? Colors.Green : Colors.Orange);
                    ProtectionStatusDesc.Text = isProtected ? "后台防护服务运行中" : "后台防护服务未启动";

                    // 更新病毒库信息
                    VirusDatabaseStatus.Text = virusStatus;
                    VirusDatabaseStatus.Foreground = new SolidColorBrush(virusColor);
                    VirusDatabaseVersion.Text = virusVersion;

                    // 更新系统状态
                    SystemStatusValue.Text = sysStatus;
                    SystemStatusValue.Foreground = new SolidColorBrush(sysColor);
                    SystemStatusDesc.Text = sysDesc;

                    // 更新最近活动
                    RecentActivityText.Text = recentActivity;
                }));
            }
            catch (System.OperationCanceledException)
            {
                // 任务被取消，正常退出
            }
            catch (Exception ex)
            {
                Log($"UpdateStats error: {ex.Message}");
            }
        }

        private (string status, string version, Color color) GetVirusDbStatus(System.Threading.CancellationToken cancellationToken)
        {
            if (cancellationToken.IsCancellationRequested)
                return ("未知", "检查取消", Colors.Gray);

            try
            {
                string baseDir = AppDomain.CurrentDomain.BaseDirectory;
                if (string.IsNullOrEmpty(baseDir))
                {
                    baseDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) ?? ".";
                }
                
                string[] possibleDbPaths = new string[]
                {
                    Path.Combine(baseDir, "ClamAV", "db"),
                    Path.Combine(baseDir, "clamav", "db"),
                    Path.Combine(baseDir, "engine", "db"),
                    Path.Combine(baseDir, "FireAntivirus.ClamAV", "ClamAV", "db"),
                    Path.Combine(baseDir, "..", "ClamAV", "db"),
                };
                
                string dbPath = null;
                foreach (var path in possibleDbPaths)
                {
                    string fullPath = Path.GetFullPath(path);
                    if (Directory.Exists(fullPath))
                    {
                        var cvdCheck = new[] { "daily.cvd", "main.cvd", "bytecode.cvd" };
                        foreach (var cvd in cvdCheck)
                        {
                            if (File.Exists(Path.Combine(fullPath, cvd)))
                            {
                                dbPath = fullPath;
                                break;
                            }
                        }
                        if (dbPath != null) break;
                        
                        if (Directory.GetFiles(fullPath, "*.cvd").Length > 0 || 
                            Directory.GetFiles(fullPath, "*.cld").Length > 0)
                        {
                            dbPath = fullPath;
                            break;
                        }
                    }
                }
                
                if (dbPath == null)
                {
                    return ("未安装", "病毒库文件不存在", Colors.Red);
                }
                
                var cvdFiles = new[] { "daily.cvd", "main.cvd", "bytecode.cvd" };
                DateTime latestUpdate = DateTime.MinValue;
                
                foreach (var cvd in cvdFiles)
                {
                    if (cancellationToken.IsCancellationRequested)
                        return ("未知", "检查取消", Colors.Gray);

                    var file = Path.Combine(dbPath, cvd);
                    if (File.Exists(file))
                    {
                        var lastWrite = File.GetLastWriteTime(file);
                        if (lastWrite > latestUpdate)
                            latestUpdate = lastWrite;
                    }
                }
                
                if (latestUpdate != DateTime.MinValue)
                {
                    var daysSinceUpdate = (DateTime.Now - latestUpdate).TotalDays;
                    if (daysSinceUpdate < 7)
                        return ("已更新", $"更新于: {latestUpdate:yyyy-MM-dd}", Colors.Green);
                    else
                        return ("需更新", $"更新于: {latestUpdate:yyyy-MM-dd}", Colors.Orange);
                }
                else
                {
                    return ("未安装", "病毒库文件不存在", Colors.Red);
                }
            }
            catch
            {
                return ("未知", "无法获取病毒库信息", Colors.Gray);
            }
        }

        private (string status, string desc, Color color) GetSystemStatus(System.Threading.CancellationToken cancellationToken)
        {
            if (cancellationToken.IsCancellationRequested)
                return ("未知", "检查取消", Colors.Gray);

            try
            {
                if (scoreService != null)
                {
                    var result = scoreService.CalculateSecurityScore();
                    if (result.TotalScore >= 80)
                        return ("安全", $"安全评分: {result.TotalScore:F0}", Colors.Green);
                    else if (result.TotalScore >= 60)
                        return ("良好", $"安全评分: {result.TotalScore:F0}", Colors.Orange);
                    else
                        return ("风险", $"安全评分: {result.TotalScore:F0}", Colors.Red);
                }
                
                // 备选检查方式
                if (dataManager != null)
                {
                    var logs = dataManager.LoadLogs();
                    var recentThreats = logs.FindAll(l => 
                        l.Type.Contains("Threat") || l.Type.Contains("威胁") ||
                        l.Type.Contains("Virus") || l.Type.Contains("病毒"));
                    
                    return recentThreats.Count == 0 
                        ? ("安全", "未发现安全威胁", Colors.Green)
                        : ("有威胁", $"发现 {recentThreats.Count} 个威胁", Colors.Red);
                }
                
                return ("安全", "系统运行正常", Colors.Green);
            }
            catch
            {
                return ("安全", "系统运行正常", Colors.Green);
            }
        }

        private string GetRecentActivity(System.Threading.CancellationToken cancellationToken)
        {
            if (cancellationToken.IsCancellationRequested)
                return "系统运行正常，无异常活动";

            try
            {
                if (dataManager != null)
                {
                    var logs = dataManager.LoadLogs();
                    var recentLogs = new List<string>();
                    int count = Math.Min(5, logs.Count);
                    for (int i = logs.Count - 1; i >= 0 && recentLogs.Count < count; i--)
                    {
                        var log = logs[i];
                        recentLogs.Add($"[{log.Time:HH:mm:ss}] {log.Message}");
                    }
                    if (recentLogs.Count > 0)
                        return string.Join("\n", recentLogs);
                }
                return "系统运行正常，无异常活动";
            }
            catch
            {
                return "系统运行正常，无异常活动";
            }
        }

        private void UpdateVirusDatabaseInfo()
        {
            try
            {
                string baseDir = AppDomain.CurrentDomain.BaseDirectory;
                if (string.IsNullOrEmpty(baseDir))
                {
                    baseDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) ?? ".";
                }
                
                string[] possibleDbPaths = new string[]
                {
                    Path.Combine(baseDir, "ClamAV", "db"),
                    Path.Combine(baseDir, "clamav", "db"),
                    Path.Combine(baseDir, "engine", "db"),
                    Path.Combine(baseDir, "FireAntivirus.ClamAV", "ClamAV", "db"),
                    Path.Combine(baseDir, "..", "ClamAV", "db"),
                };
                
                string dbPath = null;
                foreach (var path in possibleDbPaths)
                {
                    string fullPath = Path.GetFullPath(path);
                    if (Directory.Exists(fullPath))
                    {
                        if (Directory.GetFiles(fullPath, "*.cvd").Length > 0 || 
                            Directory.GetFiles(fullPath, "*.cld").Length > 0)
                        {
                            dbPath = fullPath;
                            break;
                        }
                    }
                }

                if (dbPath == null)
                {
                    VirusDatabaseStatus.Text = "未安装";
                    VirusDatabaseStatus.Foreground = new SolidColorBrush(Colors.Red);
                    VirusDatabaseVersion.Text = "病毒库文件不存在";
                    return;
                }

                var cvdFiles = new[] { "daily.cvd", "main.cvd", "bytecode.cvd" };
                DateTime latestUpdate = DateTime.MinValue;
                
                foreach (var cvd in cvdFiles)
                {
                    var file = Path.Combine(dbPath, cvd);
                    if (File.Exists(file))
                    {
                        var lastWrite = File.GetLastWriteTime(file);
                        if (lastWrite > latestUpdate)
                            latestUpdate = lastWrite;
                    }
                }
                
                if (latestUpdate != DateTime.MinValue)
                {
                    var daysSinceUpdate = (DateTime.Now - latestUpdate).TotalDays;
                    if (daysSinceUpdate < 7)
                    {
                        VirusDatabaseStatus.Text = "已更新";
                        VirusDatabaseStatus.Foreground = new SolidColorBrush(Colors.Green);
                    }
                    else
                    {
                        VirusDatabaseStatus.Text = "需更新";
                        VirusDatabaseStatus.Foreground = new SolidColorBrush(Colors.Orange);
                    }
                    VirusDatabaseVersion.Text = $"更新于: {latestUpdate:yyyy-MM-dd}";
                }
                else
                {
                    VirusDatabaseStatus.Text = "未安装";
                    VirusDatabaseStatus.Foreground = new SolidColorBrush(Colors.Red);
                    VirusDatabaseVersion.Text = "病毒库文件不存在";
                }
            }
            catch
            {
                VirusDatabaseStatus.Text = "未知";
                VirusDatabaseVersion.Text = "无法获取病毒库信息";
            }
        }

        private void UpdateSystemStatus()
        {
            try
            {
                // 获取安全评分
                if (scoreService != null)
                {
                    var result = scoreService.CalculateSecurityScore();
                    if (result.TotalScore >= 80)
                    {
                        SystemStatusValue.Text = "安全";
                        SystemStatusValue.Foreground = new SolidColorBrush(Colors.Green);
                    }
                    else if (result.TotalScore >= 60)
                    {
                        SystemStatusValue.Text = "良好";
                        SystemStatusValue.Foreground = new SolidColorBrush(Colors.Orange);
                    }
                    else
                    {
                        SystemStatusValue.Text = "风险";
                        SystemStatusValue.Foreground = new SolidColorBrush(Colors.Red);
                    }
                    SystemStatusDesc.Text = $"安全评分: {result.TotalScore:F0}";
                }
                else
                {
                    // 检查最近威胁
                    if (dataManager != null)
                    {
                        var logs = dataManager.LoadLogs();
                        var recentThreats = logs.FindAll(l => 
                            l.Type.Contains("Threat") || l.Type.Contains("威胁") ||
                            l.Type.Contains("Virus") || l.Type.Contains("病毒"));
                        
                        if (recentThreats.Count == 0)
                        {
                            SystemStatusValue.Text = "安全";
                            SystemStatusValue.Foreground = new SolidColorBrush(Colors.Green);
                            SystemStatusDesc.Text = "未发现安全威胁";
                        }
                        else
                        {
                            SystemStatusValue.Text = "有威胁";
                            SystemStatusValue.Foreground = new SolidColorBrush(Colors.Red);
                            SystemStatusDesc.Text = $"发现 {recentThreats.Count} 个威胁";
                        }
                    }
                }
            }
            catch
            {
                SystemStatusValue.Text = "安全";
                SystemStatusValue.Foreground = new SolidColorBrush(Colors.Green);
                SystemStatusDesc.Text = "系统运行正常";
            }
        }

        private void UpdateRecentActivity()
        {
            try
            {
                if (dataManager != null)
                {
                    var logs = dataManager.LoadLogs();
                    var recentLogs = new List<string>();
                    
                    // 获取最近5条日志
                    int count = Math.Min(5, logs.Count);
                    for (int i = logs.Count - 1; i >= 0 && recentLogs.Count < count; i--)
                    {
                        var log = logs[i];
                        string time = log.Time.ToString("HH:mm:ss");
                        string message = log.Message;
                        recentLogs.Add($"[{time}] {message}");
                    }
                    
                    if (recentLogs.Count > 0)
                    {
                        RecentActivityText.Text = string.Join("\n", recentLogs);
                    }
                    else
                    {
                        RecentActivityText.Text = "系统运行正常，无异常活动";
                    }
                }
            }
            catch
            {
                RecentActivityText.Text = "系统运行正常，无异常活动";
            }
        }

        private void Log(string message)
        {
            try
            {
                string logMessage = $"[{DateTime.Now}] {message}\n";
                File.AppendAllText(LogFilePath, logMessage);
            }
            catch { }
        }

        private async void QuickScan_Click(object sender, RoutedEventArgs e)
        {
            // 导航到扫描页面，设置扫描类型为快速扫描
            var mainWindow = Window.GetWindow(this) as MainWindow;
            if (mainWindow != null)
            {
                await mainWindow.LoadPageAsync("scan");
            }
        }

        private async void FullScan_Click(object sender, RoutedEventArgs e)
        {
            // 导航到扫描页面，设置扫描类型为全盘扫描
            var mainWindow = Window.GetWindow(this) as MainWindow;
            if (mainWindow != null)
            {
                await mainWindow.LoadPageAsync("scan");
            }
        }

        private void CheckUpdate_Click(object sender, RoutedEventArgs e)
        {
            UpdateVirusDatabase();
        }

        private void UpdateVirusDatabase()
        {
            try
            {
                var antivirusEngine = new AntivirusEngine();
                var clamAVEngine = new ClamAVEngine(dataManager, antivirusEngine);

                // 显示更新进度窗口
                var updateWindow = new Window
                {
                    Title = "更新病毒库",
                    Width = 400,
                    Height = 150,
                    WindowStartupLocation = WindowStartupLocation.CenterScreen,
                    ResizeMode = ResizeMode.NoResize
                };

                var stackPanel = new StackPanel { Margin = new Thickness(20) };

                var label = new TextBlock
                {
                    Text = "正在更新ClamAV病毒库...",
                    FontSize = 14,
                    Margin = new Thickness(0, 0, 0, 15)
                };
                stackPanel.Children.Add(label);

                var progressBar = new ProgressBar
                {
                    Height = 20,
                    IsIndeterminate = true
                };
                stackPanel.Children.Add(progressBar);

                updateWindow.Content = stackPanel;

                // 异步更新病毒库
                System.Threading.Tasks.Task.Run(() =>
                {
                    bool success = clamAVEngine.UpdateVirusDatabase();
                    Dispatcher.BeginInvoke(new Action(() =>
                    {
                        updateWindow.Close();
                        if (success)
                        {
                            MessageBox.Show("ClamAV病毒库更新成功", "成功", 
                                MessageBoxButton.OK, MessageBoxImage.Information);
                            UpdateVirusDatabaseInfo();
                        }
                        else
                        {
                            MessageBox.Show("ClamAV病毒库更新失败，请检查网络连接", "错误", 
                                MessageBoxButton.OK, MessageBoxImage.Error);
                        }
                    }));
                });

                updateWindow.ShowDialog();
            }
            catch (Exception ex)
            {
                Log($"更新病毒库失败: {ex.Message}");
                MessageBox.Show($"更新病毒库时发生错误: {ex.Message}", "错误", 
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void UpdateLanguage()
        {
            if (_languageManager == null) return;
            try
            {
                TitleText.Text = _languageManager.GetString("AppTitle", "耄耋安全软件");
                SubtitleText.Text = _languageManager.GetString("HomeSubtitle", "v1.1.0 Beta - 全方位保护您的电脑安全");
                
                // 防护状态卡片
                ProtectionStatusTitle.Text = _languageManager.GetString("ProtectionStatus", "防护状态");
                ProtectionStatusValue.Text = _languageManager.GetString("ProtectionEnabled", "已启用");
                ProtectionStatusDesc.Text = _languageManager.GetString("ProtectionDesc", "后台防护服务运行中");
                
                // 病毒库卡片
                VirusDatabaseTitle.Text = _languageManager.GetString("VirusDatabase", "病毒库");
                VirusDatabaseStatus.Text = _languageManager.GetString("VirusDbStatus", "已更新");
                VirusDatabaseVersion.Text = _languageManager.GetString("VirusDbVersion", "病毒库版本：最新");
                
                // 系统状态卡片
                SystemStatusTitle.Text = _languageManager.GetString("SystemStatus", "系统状态");
                SystemStatusValue.Text = _languageManager.GetString("SystemSafe", "安全");
                SystemStatusDesc.Text = _languageManager.GetString("SystemDesc", "未发现安全威胁");
                
                // 快捷操作按钮
                QuickScanText.Text = _languageManager.GetString("QuickScan", "快速扫描");
                FullScanText.Text = _languageManager.GetString("FullScan", "全盘扫描");
                CheckUpdateText.Text = _languageManager.GetString("CheckUpdate", "检查更新");
                
                // 最近活动
                RecentActivityTitle.Text = _languageManager.GetString("RecentActivity", "最近活动");
                RecentActivityText.Text = _languageManager.GetString("NoAbnormalActivity", "系统运行正常，无异常活动");
            }
            catch { }
        }

        public void ApplyTheme(Theme theme)
        {
            currentTheme = theme;
            if (theme == Theme.Dark)
                MainGrid.Background = new SolidColorBrush(Color.FromRgb(30, 30, 30));
            else
                MainGrid.Background = new SolidColorBrush(Colors.White);
        }
    }
}
