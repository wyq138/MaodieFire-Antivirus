using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Interop;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using System.Windows.Forms;
using System.Runtime;
using System.Threading;
using FireAntivirus.Host.WPF.Pages;
using FireAntivirus.Host.Services;
using FireAntivirus.Services;
using FireAntivirus.Data;
using FireAntivirus.Engine;
using Application = System.Windows.Application;
using ContextMenuStrip = System.Windows.Forms.ContextMenuStrip;
using ToolStripMenuItem = System.Windows.Forms.ToolStripMenuItem;
using MessageBox = System.Windows.MessageBox;
using WpfBrushes = System.Windows.Media.Brushes;
using WpfColor = System.Windows.Media.Color;
using WpfColorConverter = System.Windows.Media.ColorConverter;

namespace FireAntivirus.Host.WPF
{
public partial class MainWindow : Window
    {
        private Theme _currentTheme = Theme.Light;
        private Process _serviceProcess;
        private string _serviceExePath;
        private DispatcherTimer _protectionTimer;
        private DispatcherTimer _monitoringTimer;
        private bool _trayIconInitialized = false;
        private DateTime _lastServiceStartAttempt = DateTime.MinValue;
        private int _serviceRestartAttempts = 0;
        private const int SERVICE_RESTART_INTERVAL_SECONDS = 60;
        private const int MAX_SERVICE_RESTART_ATTEMPTS = 3;
        
        // 页面缓存管理器
        private PageCacheManager _pageCacheManager = new PageCacheManager(8);
        
        // UI响应性优化器
        private UIResponsivenessOptimizer _uiOptimizer = new UIResponsivenessOptimizer();
        
        // 异步数据加载器
        private AsyncDataLoader _asyncDataLoader = new AsyncDataLoader();
        
        // 资源优化管理器
        private ResourceOptimizationManager _resourceOptimizer = ResourceOptimizationManager.Instance;
        
        // 性能监控器
        private PerformanceMonitor _performanceMonitor = new PerformanceMonitor();
        
        // 内存监控器
        private MemoryMonitor _memoryMonitor = new MemoryMonitor();
        
        // GC优化助手
        private GcOptimizationHelper _gcOptimizer = new GcOptimizationHelper();
        
        // 性能分析器
        private PerformanceAnalyzer _performanceAnalyzer = new PerformanceAnalyzer();
        
        // 高级内存监控器
        private AdvancedMemoryMonitor _advancedMemoryMonitor = new AdvancedMemoryMonitor();
        
        // 性能测试套件
        private PerformanceTestSuite _performanceTestSuite = new PerformanceTestSuite();
        
        // 系统托盘相关
        private NotifyIcon? _notifyIcon;
        private bool _isReallyClosing = false;
        private ContextMenuStrip? _trayContextMenu;
        private bool _hasShownMinimizeTip = false;

        // 病毒数据库管理器
        private VirusDatabaseManager? _virusDatabaseManager;

        public MainWindow()
        {
            string startupLogPath = Path.Combine(
                Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) ?? 
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                "startup.log"
            );
            
            try
            {
                // 清空启动日志
                File.WriteAllText(startupLogPath, $"=== FireAntivirus 启动日志 {DateTime.Now} ===\n");
                
                File.AppendAllText(startupLogPath, "[1] 开始初始化...\n");
                
                InitializeComponent();
                
                File.AppendAllText(startupLogPath, "[2] InitializeComponent 完成\n");
                
                // 获取服务程序路径（优先从libs目录查找）
                string baseDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
                string libsServicePath = Path.Combine(baseDir ?? "", "libs", "FireAntivirus.ServiceHost.exe");
                if (File.Exists(libsServicePath))
                {
                    _serviceExePath = libsServicePath;
                }
                else
                {
                    _serviceExePath = Path.Combine(baseDir ?? "", "FireAntivirus.ServiceHost.exe");
                }
                
                File.AppendAllText(startupLogPath, $"[3] 服务路径: {_serviceExePath}\n");
                File.AppendAllText(startupLogPath, $"[4] 服务文件存在: {File.Exists(_serviceExePath)}\n");
                
                Loaded += MainWindow_Loaded;
                Closing += MainWindow_Closing;
                Closed += MainWindow_Closed;
                
                File.AppendAllText(startupLogPath, "[5] 事件处理器已注册\n");
            }
            catch (Exception ex)
            {
                string errorMsg = $"初始化失败: {ex.GetType().Name} - {ex.Message}\n堆栈: {ex.StackTrace}";
                File.AppendAllText(startupLogPath, $"[ERROR] {errorMsg}\n");
                MessageBox.Show(errorMsg, "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            // 初始化系统托盘
            InitializeTrayIcon();

            // 强制设置窗口/任务栏图标，规避 XAML pack 资源解析失效导致的默认图标问题
            ForceSetWindowIcon();

            // 启动看门狗客户端
            StartWatchdogClient();
            
            // 异步初始化，避免阻塞UI
            _ = InitializeAsync();
        }

        private async Task InitializeAsync()
        {
            string startupLogPath = Path.Combine(
                Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) ?? 
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                "startup.log"
            );
            
            try
            {
                await System.Threading.Tasks.Task.Delay(100);
                
                File.AppendAllText(startupLogPath, "[6] 开始异步初始化\n");
                
                // 异步预加载关键资源（不阻塞主线程）
                File.AppendAllText(startupLogPath, "[7] 预加载关键资源...\n");
                await PreloadCriticalResourcesAsync();
                File.AppendAllText(startupLogPath, "[8] 关键资源预加载完成\n");

                // 初始化病毒数据库（下载或更新）
                File.AppendAllText(startupLogPath, "[8.1] 初始化病毒数据库...\n");
                await InitializeVirusDatabaseAsync();
                File.AppendAllText(startupLogPath, "[8.2] 病毒数据库初始化完成\n");
                
                // 初始化内存监控和GC优化
                File.AppendAllText(startupLogPath, "[9] 初始化内存监控...\n");
                InitializeMemoryMonitoring();
                File.AppendAllText(startupLogPath, "[10] 内存监控初始化完成\n");
                
                // 初始化性能分析器
                File.AppendAllText(startupLogPath, "[11] 初始化性能分析器...\n");
                InitializePerformanceAnalysis();
                File.AppendAllText(startupLogPath, "[12] 性能分析器初始化完成\n");
                
                // 初始化高级内存监控和测试套件
                File.AppendAllText(startupLogPath, "[13] 初始化高级监控...\n");
                InitializeAdvancedMonitoring();
                File.AppendAllText(startupLogPath, "[14] 高级监控初始化完成\n");
                
                // 在UI线程上异步初始化
                await Dispatcher.BeginInvoke(new Func<Task>(async () =>
                {
                    File.AppendAllText(startupLogPath, "[15] 初始化导航...\n");
                    InitializeNavigation();
                    await LoadPageAsync("home");
                    File.AppendAllText(startupLogPath, "[16] 首页加载完成\n");
                    
                    // 启动后台防护服务
                    File.AppendAllText(startupLogPath, "[17] 启动后台防护服务...\n");
                    StartBackgroundService();
                    File.AppendAllText(startupLogPath, "[18] 后台防护服务启动完成\n");
                    
                    File.AppendAllText(startupLogPath, "[19] 启动防护监控...\n");
                    StartProtectionMonitor();
                    File.AppendAllText(startupLogPath, "[20] 防护监控启动完成\n");
                    
                    File.AppendAllText(startupLogPath, "[21] ===== 初始化完成 =====\n");
                }));
            }
            catch (Exception ex)
            {
                string errorMsg = $"初始化失败: {ex.GetType().Name}\n消息: {ex.Message}\n堆栈: {ex.StackTrace}";
                File.AppendAllText(startupLogPath, $"[INIT_ERROR] {errorMsg}\n");
                
                Debug.WriteLine("初始化异常: " + ex.Message);
            }
        }
        
        /// <summary>
        /// 预加载关键资源
        /// </summary>
        private async Task PreloadCriticalResourcesAsync()
        {
            try
            {
                var criticalResources = ResourceOptimizationHelper.GetCriticalStartupResources().ToList();
                
                System.Diagnostics.Debug.WriteLine($"开始预加载 {criticalResources.Count} 个关键资源...");
                
                await _resourceOptimizer.PreloadCriticalResourcesAsync(criticalResources, (completed, total) =>
                {
                    System.Diagnostics.Debug.WriteLine($"资源预加载进度: {completed}/{total}");
                });
                
                System.Diagnostics.Debug.WriteLine("关键资源预加载完成");
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"资源预加载错误: {ex.Message}");
            }
        }

        /// <summary>
        /// 初始化病毒数据库
        /// </summary>
        private async Task InitializeVirusDatabaseAsync()
        {
            string startupLogPath = Path.Combine(
                Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) ?? 
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                "startup.log"
            );

            try
            {
                File.AppendAllText(startupLogPath, "[VDB_1] 初始化病毒数据库管理器...\n");
                System.Diagnostics.Debug.WriteLine("开始初始化病毒数据库...");

                // 创建数据管理器和引擎
                var dataManager = new DataManager();
                var engine = new AntivirusEngine(dataManager);

                // 创建病毒数据库管理器
                _virusDatabaseManager = new VirusDatabaseManager(dataManager, engine);

                // 检查是否需要更新病毒库
                if (_virusDatabaseManager.IsDatabaseUpToDate())
                {
                    File.AppendAllText(startupLogPath, "[VDB_2] 病毒库已是最新版本\n");
                    System.Diagnostics.Debug.WriteLine("病毒库已是最新版本");
                }
                else
                {
                    File.AppendAllText(startupLogPath, "[VDB_3] 开始更新病毒库...\n");
                    System.Diagnostics.Debug.WriteLine("开始更新病毒库...");

                    // 在后台更新病毒库（不阻塞UI）
                    await Task.Run(() => _virusDatabaseManager.UpdateVirusDatabase());

                    File.AppendAllText(startupLogPath, "[VDB_4] 病毒库更新完成\n");
                    System.Diagnostics.Debug.WriteLine("病毒库更新完成");
                }
            }
            catch (Exception ex)
            {
                File.AppendAllText(startupLogPath, $"[VDB_ERROR] {ex.Message}\n");
                System.Diagnostics.Debug.WriteLine($"病毒数据库初始化失败: {ex.Message}");
            }
        }
        
        /// <summary>
        /// 初始化内存监控和GC优化
        /// </summary>
        private void InitializeMemoryMonitoring()
        {
            try
            {
                // 订阅内存使用变化事件
                _memoryMonitor.MemoryUsageChanged += OnMemoryUsageChanged;
                _memoryMonitor.GcAdviceGenerated += OnGcAdviceGenerated;
                
                Debug.WriteLine("内存监控系统已初始化");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"内存监控初始化失败: {ex.Message}");
            }
        }
        
        /// <summary>
        /// 内存使用变化事件处理
        /// </summary>
        private void OnMemoryUsageChanged(MemoryUsageInfo memoryInfo)
        {
            // 更新性能监控器中的内存指标
            _performanceMonitor.RecordMetric("MemoryUsage", memoryInfo.WorkingSetMB);
            _performanceMonitor.RecordMetric("PrivateMemory", memoryInfo.PrivateMemoryMB);
            _performanceMonitor.RecordMetric("LargeObjectHeap", memoryInfo.LargeObjectHeapSize);
            
            // 内存使用超过阈值时触发GC优化
            if (memoryInfo.WorkingSetMB > 800)
            {
                _ = Task.Run(async () =>
                {
                    await _memoryMonitor.ForceCleanupAsync();
                    Debug.WriteLine("内存清理完成");
                });
            }
        }
        
        /// <summary>
        /// GC优化建议事件处理
        /// </summary>
        private void OnGcAdviceGenerated(GcOptimizationAdvice advice)
        {
            Debug.WriteLine($"GC优化建议 [{advice.Severity}]: {advice.Message}");
            
            // 高优先级建议立即执行
            if (advice.Severity == GcAdviceSeverity.High)
            {
                var result = _gcOptimizer.ApplyOptimizationStrategy(GcOptimizationStrategy.Aggressive);
                Debug.WriteLine($"自动GC优化执行: {result.Success}");
            }
        }
        
        /// <summary>
        /// 页面切换时触发内存优化
        /// </summary>
        private void OptimizeMemoryOnPageSwitch()
        {
            _ = Task.Run(async () =>
            {
                // 页面切换时运行内存检测
                var leakResult = _memoryMonitor.DetectMemoryLeaks();
                if (leakResult.DetectedLeaks)
                {
                    Debug.WriteLine($"检测到潜在内存泄漏，可疑对象: {leakResult.TotalSuspiciousObjects}");
                }
                
                // 如果是高内存使用场景，执行平衡优化
                var currentMemory = _memoryMonitor.GetCurrentMemoryUsage();
                if (currentMemory.WorkingSetMB > 600)
                {
                    var result = _gcOptimizer.ApplyOptimizationStrategy(GcOptimizationStrategy.Balanced);
                    Debug.WriteLine($"页面切换内存优化: 释放 {result.FreedMemoryMB:F2} MB");
                }
            });
        }
        
        /// <summary>
        /// 初始化性能分析器
        /// </summary>
        private void InitializePerformanceAnalysis()
        {
            try
            {
                // 启动性能分析
                _performanceAnalyzer.StartAnalysis();
                
                // 订阅性能监控事件
                _performanceMonitor.PerformanceMetricsUpdated += OnPerformanceMetricsUpdated;
                
                Debug.WriteLine("性能分析器已初始化");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"性能分析器初始化失败: {ex.Message}");
            }
        }
        
        /// <summary>
        /// 性能监控数据更新事件处理
        /// </summary>
        private void OnPerformanceMetricsUpdated(object sender, EventArgs e)
        {
            // 性能指标更新通知
            Debug.WriteLine("性能指标已更新");
        }

        /// <summary>
        /// 初始化高级内存监控和测试套件
        /// </summary>
        private void InitializeAdvancedMonitoring()
        {
            try
            {
                // 定期运行内存分析和测试
                _monitoringTimer = new DispatcherTimer();
                _monitoringTimer.Interval = TimeSpan.FromMinutes(5); // 每5分钟检查一次
                _monitoringTimer.Tick += async (s, e) => await RunPeriodicPerformanceChecksAsync();
                _monitoringTimer.Start();
                
                Debug.WriteLine("高级监控系统已初始化");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"高级监控初始化失败: {ex.Message}");
            }
        }
        
        /// <summary>
        /// 定期性能检查和优化
        /// </summary>
        private async Task RunPeriodicPerformanceChecksAsync()
        {
            try
            {
                Debug.WriteLine("开始定期性能检查...");
                
                // 1. 检查内存使用情况
                var memoryAnalysis = _advancedMemoryMonitor.GetDetailedAnalysis();
                if (memoryAnalysis.LeakDetection.HasPossibleLeak)
                {
                    Debug.WriteLine($"检测到潜在内存泄漏，得分: {memoryAnalysis.LeakDetection.LeakScore:F2}");
                    
                    // 自动执行内存优化
                    var optimizationResult = await _advancedMemoryMonitor.OptimizeMemoryAsync();
                    Debug.WriteLine($"自动内存优化完成，释放内存: {optimizationResult.MemoryFreedMB:F2}MB");
                }
                
                // 2. 生成性能建议
                var suggestions = _performanceAnalyzer.GenerateAutomaticSuggestions();
                if (suggestions.Any(s => s.Priority == SuggestionPriority.High))
                {
                    var highPrioritySuggestions = suggestions.Where(s => s.Priority >= SuggestionPriority.High).ToList();
                    Debug.WriteLine($"发现 {highPrioritySuggestions.Count} 个高优先级性能建议");
                }
                
                // 3. 页面加载性能分析
                var comparison = _performanceAnalyzer.ComparePages("home", "scan", "protection");
                if (comparison.AverageLoadTime > 300)
                {
                    Debug.WriteLine($"页面平均加载时间偏高: {comparison.AverageLoadTime:F0}ms，最慢页面: {comparison.SlowestPage}");
                }
                
                Debug.WriteLine("定期性能检查完成");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"定期性能检查错误: {ex.Message}");
            }
        }
        
        /// <summary>
        /// 执行完整的性能测试（可通过UI或程序调用）
        /// </summary>
        public async Task<PerformanceTestReport> RunCompletePerformanceTestAsync()
        {
            Debug.WriteLine("开始完整性能测试...");
            
            try
            {
                var report = await _performanceTestSuite.RunCompleteTestSuiteAsync();
                
                if (report.Success)
                {
                    Debug.WriteLine($"性能测试完成，综合得分: {report.OverallScore:F1}");
                    
                    // 报告关键发现
                    var slowPages = report.PageLoadTests.Where(p => p.LoadTimeMs > 300).ToList();
                    if (slowPages.Any())
                    {
                        Debug.WriteLine($"发现 {slowPages.Count} 个慢速页面");
                    }
                }
                else
                {
                    Debug.WriteLine($"性能测试失败: {report.ErrorMessage}");
                }
                
                return report;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"性能测试过程错误: {ex.Message}");
                throw;
            }
        }
        
        /// <summary>
        /// 执行快速性能诊断
        /// </summary>
        public async Task<QuickDiagnosticResult> RunQuickDiagnosticAsync()
        {
            var result = new QuickDiagnosticResult
            {
                Timestamp = DateTime.Now
            };
            
            try
            {
                // 检查当前内存使用
                var currentMemory = _memoryMonitor.GetCurrentMemoryUsage();
                result.MemoryUsageMB = currentMemory.WorkingSetMB;
                result.MemoryStatus = currentMemory.WorkingSetMB > 800 ? "高" : "正常";
                
                // 检查页面加载性能
                var pageComparison = _performanceAnalyzer.ComparePages("home", "scan");
                result.AveragePageLoadMs = pageComparison.AverageLoadTime;
                result.PageLoadStatus = pageComparison.AverageLoadTime > 300 ? "慢" : "正常";
                
                // 检查CPU性能
                result.CpuUsagePercent = await GetCurrentCpuUsageAsync();
                result.CpuStatus = result.CpuUsagePercent > 80 ? "高" : "正常";
                
                // 生成总体健康评分
                result.HealthScore = CalculateHealthScore(result);
                result.OverallStatus = result.HealthScore > 80 ? "健康" : result.HealthScore > 60 ? "警告" : "需要关注";
                
                result.Success = true;
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Error = ex.Message;
            }
            
            return result;
        }
        
        /// <summary>
        /// 获取当前CPU使用率
        /// </summary>
        private async Task<double> GetCurrentCpuUsageAsync()
        {
            return await Task.Run(() =>
            {
                try
                {
                    var process = Process.GetCurrentProcess();
                    var startTime = DateTime.Now;
                    var startCpuTime = process.TotalProcessorTime;
                    
                    Thread.Sleep(500); // 采样500ms
                    
                    var endTime = DateTime.Now;
                    var endCpuTime = process.TotalProcessorTime;
                    
                    var cpuUsedMs = (endCpuTime - startCpuTime).TotalMilliseconds;
                    var totalMsPassed = (endTime - startTime).TotalMilliseconds;
                    var cpuUsageTotal = cpuUsedMs / (Environment.ProcessorCount * totalMsPassed);
                    
                    return cpuUsageTotal * 100;
                }
                catch
                {
                    return 0.0;
                }
            });
        }
        
        /// <summary>
        /// 计算健康评分
        /// </summary>
        private double CalculateHealthScore(QuickDiagnosticResult result)
        {
            double score = 100.0;
            
            // 基于内存使用扣分
            if (result.MemoryUsageMB > 800) score -= 20;
            else if (result.MemoryUsageMB > 600) score -= 10;
            
            // 基于页面加载扣分
            if (result.AveragePageLoadMs > 500) score -= 25;
            else if (result.AveragePageLoadMs > 300) score -= 15;
            
            // 基于CPU使用扣分
            if (result.CpuUsagePercent > 80) score -= 15;
            else if (result.CpuUsagePercent > 60) score -= 5;
            
            return Math.Max(0, Math.Min(100, score));
        }
        
        // 快速诊断结果类
        public class QuickDiagnosticResult
        {
            public DateTime Timestamp { get; set; }
            public double MemoryUsageMB { get; set; }
            public string MemoryStatus { get; set; }
            public double AveragePageLoadMs { get; set; }
            public string PageLoadStatus { get; set; }
            public double CpuUsagePercent { get; set; }
            public string CpuStatus { get; set; }
            public double HealthScore { get; set; }
            public string OverallStatus { get; set; }
            public bool Success { get; set; }
            public string Error { get; set; }
        }
        
        #region 系统托盘
        /// <summary>
        /// 初始化系统托盘图标
        /// </summary>
private void InitializeTrayIcon()
        {
            // 防止重复初始化
            if (_trayIconInitialized)
            {
                return;
            }
            _trayIconInitialized = true;
            
            string startupLogPath = Path.Combine(
                Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) ?? 
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                "startup.log"
            );
            
            try
            {
                File.AppendAllText(startupLogPath, "[托盘] 初始化托盘图标...\n");
                
                _notifyIcon = new NotifyIcon();
                
                // 设置托盘图标 - 使用正确的路径
                string baseDir = AppDomain.CurrentDomain.BaseDirectory;
                string iconPath = GetIconPath();
                
                // 备用路径：检查libs/ClamAV目录下的ico文件
                string[] backupIconPaths = new string[]
                {
                    Path.Combine(baseDir, "ClamAV", "antivirus.ico"),
                    Path.Combine(baseDir, "..", "Resources", "cat_icon.ico"),
                    Path.Combine(baseDir, "Resources", "cat_icon.ico"),
                };
                
                // 如果GetIconPath返回空，尝试备用路径
                if (string.IsNullOrEmpty(iconPath))
                {
                    foreach (var backup in backupIconPaths)
                    {
                        string normalizedPath = Path.GetFullPath(backup);
                        if (File.Exists(normalizedPath))
                        {
                            iconPath = normalizedPath;
                            File.AppendAllText(startupLogPath, $"[托盘] 使用备用图标: {iconPath}\n");
                            break;
                        }
                    }
                }
                
                File.AppendAllText(startupLogPath, $"[托盘] 图标路径: {iconPath}, 存在: {(!string.IsNullOrEmpty(iconPath) && File.Exists(iconPath))}\n");
                
                if (!string.IsNullOrEmpty(iconPath) && File.Exists(iconPath))
                {
                    try
                    {
                        string ext = Path.GetExtension(iconPath).ToLower();
                        if (ext == ".ico")
                        {
                            _notifyIcon.Icon = new Icon(iconPath);
                            File.AppendAllText(startupLogPath, "[托盘] 使用ICO图标\n");
                        }
                        else
                        {
                            // PNG或非ICO格式 - 使用系统图标
                            _notifyIcon.Icon = SystemIcons.Shield;
                            File.AppendAllText(startupLogPath, "[托盘] 图标格式不支持，使用系统图标\n");
                        }
                    }
                    catch (Exception iconEx)
                    {
                        File.AppendAllText(startupLogPath, $"[托盘图标异常] {iconEx.Message}\n");
                        _notifyIcon.Icon = SystemIcons.Shield;
                        File.AppendAllText(startupLogPath, "[托盘] 回退到系统图标\n");
                    }
                }
                else
                {
                    // 使用系统默认盾牌图标
                    _notifyIcon.Icon = SystemIcons.Shield;
                    File.AppendAllText(startupLogPath, "[托盘] 使用系统图标\n");
                }
                
                _notifyIcon.Text = "耄耋安全软件";
                _notifyIcon.Visible = true;
                
                File.AppendAllText(startupLogPath, "[托盘] 托盘图标初始化完成\n");
                
                // 创建右键菜单
                CreateTrayContextMenu();
                
                _notifyIcon.ContextMenuStrip = _trayContextMenu;
                
                File.AppendAllText(startupLogPath, "[托盘] 右键菜单已创建\n");
                
                // 双击显示主窗口
                _notifyIcon.DoubleClick += (s, e) =>
                {
                    ShowMainWindow();
                };
                
                File.AppendAllText(startupLogPath, "[托盘] 双击事件已注册\n");
            }
            catch (Exception ex)
            {
                File.AppendAllText(startupLogPath, $"[托盘异常] {ex.GetType().Name}: {ex.Message}\n堆栈: {ex.StackTrace}\n");
                Debug.WriteLine($"初始化托盘图标失败: {ex.Message}");
            }
        }
        
        /// <summary>
        /// 创建托盘右键菜单
        /// </summary>
        private void CreateTrayContextMenu()
        {
            _trayContextMenu = new ContextMenuStrip();
            
            // 打开主程序
            var openItem = new ToolStripMenuItem("打开主程序");
            openItem.Click += (s, e) => ShowMainWindow();
            _trayContextMenu.Items.Add(openItem);
            
            // 分隔线
            _trayContextMenu.Items.Add(new ToolStripSeparator());
            
            // 病毒扫描
            var scanItem = new ToolStripMenuItem("病毒扫描");
            scanItem.Click += async (s, e) =>
            {
                ShowMainWindow();
                await LoadPageAsync("scan");
            };
            _trayContextMenu.Items.Add(scanItem);
            
            // 实时防护状态
            var protectionItem = new ToolStripMenuItem("实时防护");
            protectionItem.Click += async (s, e) =>
            {
                ShowMainWindow();
                await LoadPageAsync("protection");
            };
            _trayContextMenu.Items.Add(protectionItem);
            
            // 分隔线
            _trayContextMenu.Items.Add(new ToolStripSeparator());
            
            // 退出程序 - 唯一的退出入口
            var exitItem = new ToolStripMenuItem("退出程序");
            exitItem.ForeColor = System.Drawing.Color.Red;
            exitItem.Click += OnTrayExitClick;
            _trayContextMenu.Items.Add(exitItem);
        }
        
/// <summary>
        /// 获取图标路径
        /// </summary>
        private string GetIconPath()
        {
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            
            // 尝试多个可能的图标路径
            string[] iconPaths = new string[]
            {
                // 主程序在libs目录，所以先检查父目录的Resources
                Path.Combine(baseDir, "..", "Resources", "cat_icon.ico"),
                Path.Combine(baseDir, "..", "Resources", "cat_icon.png"),
                // 主程序同级Resources
                Path.Combine(baseDir, "Resources", "cat_icon.ico"),
                Path.Combine(baseDir, "cat_icon.ico"),
                Path.Combine(baseDir, "Resources", "cat_icon.png"),
                Path.Combine(baseDir, "antivirus.ico"),
            };
            
            foreach (var path in iconPaths)
            {
                // 规范化路径，处理..等
                string normalizedPath = Path.GetFullPath(path);
                if (File.Exists(normalizedPath))
                {
                    return normalizedPath;
                }
            }
            
            return "";
        }
        
        /// <summary>
        /// 强制设置窗口图标（标题栏 + 任务栏 + Alt+Tab）。
        /// 直接从 cat_icon.ico 文件生成窗口图标，避免 XAML pack URI 资源解析失败时任务栏显示默认图标。
        /// </summary>
        private void ForceSetWindowIcon()
        {
            string startupLogPath = Path.Combine(
                Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) ?? 
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                "startup.log"
            );

            try
            {
                string iconPath = GetIconPath();
                if (string.IsNullOrEmpty(iconPath) || !File.Exists(iconPath))
                {
                    File.AppendAllText(startupLogPath, "[窗口图标] 未找到图标文件，保持默认\n");
                    return;
                }

                using (var ico = new System.Drawing.Icon(iconPath))
                {
                    Icon = Imaging.CreateBitmapSourceFromHIcon(
                        ico.Handle,
                        System.Windows.Int32Rect.Empty,
                        BitmapSizeOptions.FromEmptyOptions());
                }
                File.AppendAllText(startupLogPath, $"[窗口图标] 已设置: {iconPath}\n");
            }
            catch (Exception ex)
            {
                File.AppendAllText(startupLogPath, $"[窗口图标异常] {ex.GetType().Name}: {ex.Message}\n");
            }
        }
        
        /// <summary>
        /// 显示主窗口
        /// </summary>
        private void ShowMainWindow()
        {
            Show();
            WindowState = WindowState.Normal;
            Activate();
            Focus();
        }
        
        /// <summary>
        /// 托盘退出点击事件
        /// </summary>
        private void OnTrayExitClick(object? sender, EventArgs e)
        {
            // 确保在主线程中显示对话框
            if (Dispatcher.CheckAccess())
            {
                ShowExitConfirmation();
            }
            else
            {
                Dispatcher.Invoke(new Action(ShowExitConfirmation));
            }
        }
        
/// <summary>
        /// 显示退出确认对话框
        /// </summary>
        private void ShowExitConfirmation()
        {
            // 检查后台服务状态
            bool serviceRunning = false;
            try
            {
                var processes = Process.GetProcessesByName("FireAntivirus.ServiceHost");
                serviceRunning = processes.Length > 0;
                foreach (var p in processes) p.Dispose();
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "MainWindow.xaml.cs 捕获异常", ex.Message); }

            string warningMsg = serviceRunning
                ? "确定要退出耄耋安全软件吗？\n\n退出后实时防护将停止，电脑将失去病毒防护。\n\n注意：后台防护服务正在运行，退出后将停止防护。"
                : "确定要退出耄耋安全软件吗？\n\n退出后实时防护将停止，电脑将失去病毒防护。";

            var result = MessageBox.Show(
                warningMsg,
                "确认退出",
                MessageBoxButton.YesNo,
                serviceRunning ? MessageBoxImage.Warning : MessageBoxImage.Question,
                MessageBoxResult.No
            );
            
            if (result == MessageBoxResult.Yes)
            {
                PerformExit();
            }
        }
        
        /// <summary>
        /// 执行退出操作
        /// </summary>
        private void PerformExit()
        {
            _isReallyClosing = true;
            
            // 通知看门狗退出
            App.WatchdogClient?.RequestExit();
            
            // 隐藏托盘图标
            if (_notifyIcon != null)
            {
                _notifyIcon.Visible = false;
                _notifyIcon.Dispose();
                _notifyIcon = null;
            }
            
            // 停止后台服务
            try
            {
                var serviceProcesses = Process.GetProcessesByName("FireAntivirus.ServiceHost");
                foreach (var proc in serviceProcesses)
                {
                    try { proc.Kill(); } catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "MainWindow.xaml.cs 捕获异常", ex.Message); }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "MainWindow.xaml.cs 捕获异常", ex.Message); }
            
            // 退出程序
            Application.Current.Shutdown();
        }
        
        #endregion

        #region 看门狗客户端
        
        /// <summary>
        /// 启动看门狗客户端
        /// </summary>
        private void StartWatchdogClient()
        {
            try
            {
                App.WatchdogClient?.Start();
                
                if (App.WatchdogClient != null)
                {
                    App.WatchdogClient.ConnectionStateChanged += (s, connected) =>
                    {
                        Debug.WriteLine($"[MainWindow] Watchdog connection: {connected}");
                    };
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"启动看门狗客户端失败: {ex.Message}");
            }
        }
        
        #endregion

        private void MainWindow_Closing(object sender, CancelEventArgs e)
        {
            // 解决双重退出问题：统一退出逻辑
            // 如果已经有退出请求或者用户主动关闭系统托盘菜单中的"退出程序"，则直接退出
            // 否则最小化到托盘
            if (!_isReallyClosing)
            {
                e.Cancel = true;
                Hide();
                
                // 仅在首次最小化时显示提示
                if (_notifyIcon != null && !_hasShownMinimizeTip)
                {
                    _notifyIcon.ShowBalloonTip(2000, "耄耋安全软件", "程序已最小化到系统托盘，右键点击图标可退出程序。", ToolTipIcon.Info);
                    _hasShownMinimizeTip = true;
                }
            }
        }
        
        private void MainWindow_Closed(object? sender, EventArgs e)
        {
            // 清理托盘图标
            if (_notifyIcon != null)
            {
                _notifyIcon.Visible = false;
                _notifyIcon.Dispose();
                _notifyIcon = null;
            }
            
            // 停止并释放防护监控定时器
            try
            {
                if (_protectionTimer != null)
                {
                    _protectionTimer.Stop();
                    _protectionTimer.IsEnabled = false;
                    _protectionTimer = null;
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "MainWindow.xaml.cs 捕获异常", ex.Message); }
            
            // 停止并释放高级监控定时器
            try
            {
                if (_monitoringTimer != null)
                {
                    _monitoringTimer.Stop();
                    _monitoringTimer.IsEnabled = false;
                    _monitoringTimer = null;
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "MainWindow.xaml.cs 捕获异常", ex.Message); }
            
            // 清理所有性能监控组件
            try
            {
                _memoryMonitor?.Dispose();
                _advancedMemoryMonitor?.Dispose();
                _gcOptimizer?.GetType(); // 确保引用保持，但GC优化器不需要显式释放
                // 性能分析器和测试套件不需要显式释放
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "MainWindow.xaml.cs 捕获异常", ex.Message); }
        }

        private void StartBackgroundService()
        {
            string startupLogPath = Path.Combine(
                Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) ?? 
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                "startup.log"
            );
            
            try
            {
                File.AppendAllText(startupLogPath, "[启动服务] 检查服务状态...\n");
                
                // 检查重试次数限制
                if (_serviceRestartAttempts >= MAX_SERVICE_RESTART_ATTEMPTS)
                {
                    File.AppendAllText(startupLogPath, $"[启动服务] 已达到最大重试次数 ({MAX_SERVICE_RESTART_ATTEMPTS})，停止自动重试\n");
                    Dispatcher.BeginInvoke(new Action(() =>
                    {
                        ProtectionStatusDot.Foreground = WpfBrushes.Red;
                        ProtectionStatusText.Text = "防护服务启动失败，请手动检查";
                    }));
                    return;
                }
                
                // 检查是否已经在运行
                var existingProcesses = Process.GetProcessesByName("FireAntivirus.ServiceHost");
                if (existingProcesses.Length > 0)
                {
                    File.AppendAllText(startupLogPath, $"[启动服务] 服务已在运行，进程数: {existingProcesses.Length}\n");
                    
                    foreach (var p in existingProcesses) p.Dispose();
                    
                    _serviceRestartAttempts = 0; // 重置重试计数
                    
                    Dispatcher.BeginInvoke(new Action(() =>
                    {
                        ProtectionStatusDot.Foreground = WpfBrushes.Green;
                        ProtectionStatusText.Text = "防护已开启";
                    }));
                    return;
                }

                // 启动后台服务（独立进程，使用 -console 参数）
                if (File.Exists(_serviceExePath))
                {
                    File.AppendAllText(startupLogPath, $"[启动服务] 启动服务进程: {_serviceExePath}\n");
                    
                    _lastServiceStartAttempt = DateTime.Now;
                    _serviceRestartAttempts++;
                    
                    File.AppendAllText(startupLogPath, $"[启动服务] 重试次数: {_serviceRestartAttempts}/{MAX_SERVICE_RESTART_ATTEMPTS}\n");
                    
                    var startInfo = new ProcessStartInfo
                    {
                        FileName = _serviceExePath,
                        Arguments = "-run",  // 使用控制台模式，独立运行不随主程序退出
                        UseShellExecute = true,
                        CreateNoWindow = true,
                        WindowStyle = ProcessWindowStyle.Hidden,
                        WorkingDirectory = Path.GetDirectoryName(_serviceExePath)
                    };
                    
                    Process.Start(startInfo);
                    File.AppendAllText(startupLogPath, "[启动服务] 服务进程已启动\n");
                    
                    Dispatcher.BeginInvoke(new Action(() =>
                    {
                        ProtectionStatusDot.Foreground = WpfBrushes.Green;
                        ProtectionStatusText.Text = "正在启动防护...";
                    }));
                }
                else
                {
                    File.AppendAllText(startupLogPath, $"[启动服务错误] 服务文件不存在: {_serviceExePath}\n");
                    
                    Dispatcher.BeginInvoke(new Action(() =>
                    {
                        ProtectionStatusDot.Foreground = WpfBrushes.Orange;
                        ProtectionStatusText.Text = "防护服务未找到";
                    }));
                }
            }
            catch (Exception ex)
            {
                File.AppendAllText(startupLogPath, $"[启动服务异常] {ex.GetType().Name}: {ex.Message}\n堆栈: {ex.StackTrace}\n");
                
                Dispatcher.BeginInvoke(new Action(() =>
                {
                        ProtectionStatusDot.Foreground = WpfBrushes.Red;
                        ProtectionStatusText.Text = "启动防护失败";
                }));
                Debug.WriteLine("启动后台服务失败: " + ex.Message);
            }
        }

        private void InitializeNavigation()
        {
            UpdateNavigationState("home");
        }

        private async void NavButton_Click(object sender, RoutedEventArgs e)
        {
            if (sender is System.Windows.Controls.Button btn && btn.Tag != null)
            {
                string pageName = btn.Tag.ToString();
                
                // 禁用按钮防止重复点击
                btn.IsEnabled = false;
                
                try
                {
                    // 异步加载页面
                    await LoadPageAsync(pageName);
                    UpdateNavigationState(pageName);
                }
                finally
                {
                    // 重新启用按钮
                    btn.IsEnabled = true;
                }
            }
        }

        public async Task LoadPageAsync(string pageName)
        {
            try
            {
                // 创建Page对象必须在UI线程上执行
                Page page = await Dispatcher.InvokeAsync<Page>(() =>
                {
                    return pageName switch
                    {
                        "home" => new HomePage(),
                        "scan" => new ScanPage(),
                        "protection" => new ProtectionPage(),
                        "network" => new NetworkPage(),
                        "popup" => new PopupBlockerPage(),
                        "ransomware" => new RansomwareProtectionPage(),
                        "privacy" => new PrivacyProtectionPage(),
                        "parental" => new ParentalControlPage(),
                        "web" => new WebProtectionPage(),
                        "email" => new EmailSecurityPage(),
                        "password" => new PasswordManagerPage(),
                        "firewall" => new NetworkFirewallPage(),
                        "device" => new DeviceControlPage(),
                        "vulnerability" => new VulnerabilityScannerPage(),
                        "cloud" => new CloudScannerPage(),
                        "browser" => new SecureBrowserPage(),
                        "mobile" => new MobileSecurityPage(),
                        "optimizer" => new SystemOptimizerPage(),
                        "backup" => new BackupPage(),
                        "score" => new SecurityScorePage(),
                        "traffic" => new NetworkTrafficAnalyzerPage(),
                        "app" => new ApplicationMonitorPage(),
                        "startup" => new StartupManagerPage(),
                        "report" => new SecurityReportPage(),
                        "behavior" => new BehaviorAnalysisPage(),
                        "tools" => new ToolsPage(),
                        "systeminfo" => new SystemInfoPage(),
                        "quarantine" => new QuarantinePage(),
                        "trust" => new TrustZonePage(),
                        "logs" => new LogsPage(),
                        "settings" => new SettingsPage(),
                        "about" => new AboutPage(),
                        "performance" => new PerformanceDiagnosticsPage(),
                        "donation" => new DonationPage(),
                        _ => new PlaceholderPage(pageName)
                    };
                });

                // 直接设置ContentFrame内容，不使用动画
                ContentFrame.Content = page;

                // 触发页面激活事件
                if (page is IPageWithLifecycle lifecyclePage)
                {
                    lifecyclePage.OnPageActivated();
                }

                // 设置页面标题
                PageTitle.Text = GetPageTitle(pageName);
            }
            catch (Exception ex)
            {
                // 发生错误时使用占位页面
                Debug.WriteLine($"页面加载错误 [{pageName}]: " + ex.Message);
                var placeholderPage = new PlaceholderPage(pageName);
                ContentFrame.Content = placeholderPage;
                PageTitle.Text = pageName;
            }
        }

        // 保持原有同步方法用于向后兼容
        public void LoadPage(string pageName)
        {
            try
            {
                _ = LoadPageWithErrorHandlingAsync(pageName);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"LoadPage 调用异常 [{pageName}]: {ex.Message}");
            }
        }
        
        private async Task LoadPageWithErrorHandlingAsync(string pageName)
        {
            try
            {
                await LoadPageAsync(pageName);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"LoadPageAsync 异常 [{pageName}]: {ex.Message}");
                try
                {
                    var placeholderPage = new PlaceholderPage(pageName);
                    ContentFrame.Content = placeholderPage;
                    PageTitle.Text = pageName;
                }
                catch (System.Exception ex2) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "MainWindow.xaml.cs 捕获异常", ex2.Message); }
            }
        }
        private string GetPageTitle(string pageName)
        {
            return pageName switch
            {
                "home" => "首页",
                "scan" => "病毒扫描",
                "protection" => "实时防护",
                "network" => "网络防护",
                "popup" => "弹窗拦截",
                "ransomware" => "勒索防护",
                "privacy" => "隐私保护",
                "parental" => "家长控制",
                "web" => "网页防护",
                "email" => "邮件安全",
                "password" => "密码管理",
                "firewall" => "防火墙",
                "device" => "设备控制",
                "vulnerability" => "漏洞扫描",
                "cloud" => "云扫描",
                "browser" => "安全浏览器",
                "mobile" => "移动安全",
                "optimizer" => "系统优化",
                "backup" => "备份恢复",
                "score" => "安全评分",
                "traffic" => "流量分析",
                "app" => "应用监控",
                "startup" => "启动项管理",
                "report" => "安全报告",
                "behavior" => "行为分析",
                "tools" => "工具箱",
                "systeminfo" => "系统信息",
                "quarantine" => "隔离区",
                "trust" => "信任区",
                "logs" => "日志",
                "settings" => "设置",
                "about" => "关于",
                "performance" => "性能诊断",
                "donation" => "捐赠支持",
                _ => pageName
            };
        }

        private void UpdateNavigationState(string activePage)
        {
            foreach (var child in NavigationPanel.Children)
            {
                if (child is System.Windows.Controls.Button btn)
                {
                    if (btn.Tag?.ToString() == activePage)
                    {
                        btn.Background = new SolidColorBrush((WpfColor)WpfColorConverter.ConvertFromString("#E3F2FD"));
                    }
                }
            }
        }

        private void ThemeToggleBtn_Click(object sender, RoutedEventArgs e)
        {
            _currentTheme = _currentTheme == Theme.Light ? Theme.Dark : Theme.Light;
            ApplyTheme(_currentTheme);
            ThemeToggleBtn.Content = _currentTheme == Theme.Light ? "🌙" : "☀️";
        }

        private void ApplyTheme(Theme theme)
        {
            try
            {
                var resources = Application.Current.Resources;
                
                if (theme == Theme.Dark)
                {
                    resources["BgPrimary"] = new SolidColorBrush(WpfColor.FromRgb(30, 30, 30));
                    resources["BgSecondary"] = new SolidColorBrush(WpfColor.FromRgb(45, 45, 45));
                    resources["BgTertiary"] = new SolidColorBrush(WpfColor.FromRgb(60, 60, 60));
                    resources["TextPrimary"] = new SolidColorBrush(Colors.White);
                    resources["TextSecondary"] = new SolidColorBrush(WpfColor.FromRgb(180, 180, 180));
                    resources["BorderColor"] = new SolidColorBrush(WpfColor.FromRgb(80, 80, 80));
                }
                else
                {
                    resources["BgPrimary"] = new SolidColorBrush(WpfColor.FromRgb(245, 245, 245));
                    resources["BgSecondary"] = new SolidColorBrush(Colors.White);
                    resources["BgTertiary"] = new SolidColorBrush(WpfColor.FromRgb(232, 232, 232));
                    resources["TextPrimary"] = new SolidColorBrush(WpfColor.FromRgb(51, 51, 51));
                    resources["TextSecondary"] = new SolidColorBrush(WpfColor.FromRgb(102, 102, 102));
                    resources["BorderColor"] = new SolidColorBrush(WpfColor.FromRgb(221, 221, 221));
                }

                if (ContentFrame.Content is IThemed themedPage)
                {
                    themedPage.ApplyTheme(theme);
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "MainWindow.xaml.cs 捕获异常", ex.Message); }
        }

private void StartProtectionMonitor()
        {
            _protectionTimer = new DispatcherTimer();
            _protectionTimer.Interval = TimeSpan.FromSeconds(10);
            _protectionTimer.Tick += (s, e) => CheckProtectionStatus();
            _protectionTimer.Start();
            
            // 延迟10秒再检查，让服务有时间启动
            var delayTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(10)
            };
            delayTimer.Tick += (s, e) =>
            {
                delayTimer.Stop();
                CheckProtectionStatus();
            };
            delayTimer.Start();
        }

         public void CheckProtectionStatus()
        {
            try
            {
                var processes = Process.GetProcessesByName("FireAntivirus.ServiceHost");
                bool isProtected = processes.Length > 0;
                foreach (var p in processes) p.Dispose();
                
                Dispatcher.BeginInvoke(new Action(() =>
                {
                    if (isProtected)
                    {
                        ProtectionStatusDot.Foreground = WpfBrushes.Green;
                        ProtectionStatusText.Text = "防护已开启";
                        _serviceRestartAttempts = 0; // 重置重试计数
                    }
                    else
                    {
                        ProtectionStatusDot.Foreground = WpfBrushes.Orange;
                        ProtectionStatusText.Text = "防护未运行";
                        
                        var timeSinceLastAttempt = (DateTime.Now - _lastServiceStartAttempt).TotalSeconds;
                        if (timeSinceLastAttempt >= SERVICE_RESTART_INTERVAL_SECONDS
                            && _serviceRestartAttempts < MAX_SERVICE_RESTART_ATTEMPTS)
                        {
                            StartBackgroundService();
                        }
                        else if (_serviceRestartAttempts >= MAX_SERVICE_RESTART_ATTEMPTS)
                        {
                            ProtectionStatusDot.Foreground = WpfBrushes.Red;
                            ProtectionStatusText.Text = "防护服务启动失败，请手动检查";
                        }
                    }
                }));
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "MainWindow.xaml.cs 捕获异常", ex.Message); }
        }
        
        public void UpdateProtectionStatus(Dictionary<string, bool> status)
        {
            bool allEnabled = status != null && status.Values.All(v => v);
            Dispatcher.BeginInvoke(new Action(() =>
            {
                ProtectionStatusDot.Foreground = allEnabled ? WpfBrushes.Green : WpfBrushes.Orange;
                ProtectionStatusText.Text = allEnabled ? "防护已开启" : "部分防护未开启";
            }));
        }
    }

    public enum Theme { Light, Dark }

    public interface IThemed
    {
        void ApplyTheme(Theme theme);
    }
}