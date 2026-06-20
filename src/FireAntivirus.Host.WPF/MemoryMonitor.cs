using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime;
using System.Threading;
using System.Threading.Tasks;

namespace FireAntivirus.Host.WPF
{
    /// <summary>
    /// 内存监控和垃圾收集优化器
    /// </summary>
    public class MemoryMonitor : IDisposable
    {
        private readonly ConcurrentDictionary<string, MemoryMetric> _metrics;
        private Timer _monitoringTimer;
        private Timer _gcOptimizationTimer;
        private readonly long _gcLatencyThresholdMs = 100;
        private readonly long _memoryThresholdMb = 500;
        private bool _isMonitoring = false;
        private bool _isDisposed = false;

        /// <summary>
        /// 内存使用状态变化事件
        /// </summary>
        public event Action<MemoryUsageInfo> MemoryUsageChanged;

        /// <summary>
        /// GC优化建议事件
        /// </summary>
        public event Action<GcOptimizationAdvice> GcAdviceGenerated;

        public MemoryMonitor()
        {
            _metrics = new ConcurrentDictionary<string, MemoryMetric>();
            InitializeMetrics();
            StartMonitoring();
        }

        /// <summary>
        /// 获取当前内存使用信息
        /// </summary>
        public MemoryUsageInfo GetCurrentMemoryUsage()
        {
            var process = Process.GetCurrentProcess();
            var gcInfo = GetGcInfo();

            return new MemoryUsageInfo
            {
                Timestamp = DateTime.Now,
                WorkingSetMB = process.WorkingSet64 / 1024.0 / 1024.0,
                PrivateMemoryMB = process.PrivateMemorySize64 / 1024.0 / 1024.0,
                Gen0CollectionCount = GC.CollectionCount(0),
                Gen1CollectionCount = GC.CollectionCount(1),
                Gen2CollectionCount = GC.CollectionCount(2),
                TotalMemory = GC.GetTotalMemory(false) / 1024.0 / 1024.0,
                IsServerGC = GCSettings.IsServerGC,
                LatencyMode = GCSettings.LatencyMode,
                LargeObjectHeapSize = GetLargeObjectHeapSize(),
                HandleCount = process.HandleCount,
                ThreadCount = process.Threads.Count
            };
        }

        /// <summary>
        /// 优化垃圾收集设置
        /// </summary>
        public MemoryGcOptimizationResult OptimizeGarbageCollection()
        {
            var startMemory = GC.GetTotalMemory(false);
            var originalLatencyMode = GCSettings.LatencyMode;

            try
            {
                // 仅在需要时切换到低延迟模式
                if (GCSettings.LatencyMode != GCLatencyMode.LowLatency &&
                    GetCurrentMemoryUsage().WorkingSetMB < _memoryThresholdMb)
                {
                    GCSettings.LatencyMode = GCLatencyMode.LowLatency;
                }

                // 对Gen2进行一次垃圾回收（仅在必要时）
                if (GC.GetTotalMemory(false) > 1024 * 1024 * 1024) // 1GB以上
                {
                    GC.Collect(2, GCCollectionMode.Optimized, false);
                }

                var endMemory = GC.GetTotalMemory(false);
                var freedMemory = (startMemory - endMemory) / 1024.0 / 1024.0; // MB

                return new MemoryGcOptimizationResult
                {
                    Success = true,
                    FreedMemoryMB = Math.Max(0, freedMemory),
                    LatencyMode = GCSettings.LatencyMode,
                    RecommendedActions = GetRecommendedActions()
                };
            }
            catch (Exception ex)
            {
                return new MemoryGcOptimizationResult
                {
                    Success = false,
                    ErrorMessage = ex.Message,
                    FreedMemoryMB = 0
                };
            }
        }

        /// <summary>
        /// 检测潜在的内存泄漏
        /// </summary>
        public MemoryLeakDetectionResult DetectMemoryLeaks()
        {
            var currentUsage = GetCurrentMemoryUsage();
            var baseline = GetMemoryBaseline();
            
            // 分析内存增长趋势
            var trends = AnalyzeMemoryTrends();
            var suspiciousObjects = FindSuspiciousObjects();

            var result = new MemoryLeakDetectionResult
            {
                DetectedLeaks = trends.Any(t => t.GrowthRate > 0.1), // 超过10%增长
                TotalSuspiciousObjects = suspiciousObjects.Count,
                MemoryTrends = trends,
                Recommendations = GenerateLeakPreventionRecommendations()
            };

            GcAdviceGenerated?.Invoke(new GcOptimizationAdvice
            {
                Severity = result.DetectedLeaks ? GcAdviceSeverity.High : GcAdviceSeverity.Low,
                Message = result.DetectedLeaks ? "检测到潜在内存泄漏风险" : "内存使用正常",
                RecommendedActions = result.Recommendations
            });

            return result;
        }

        /// <summary>
        /// 强制执行资源清理
        /// </summary>
        public async Task ForceCleanupAsync()
        {
            await Task.Run(() =>
            {
                // 清理事件处理程序
                ForceEventCleanup();
                
                // 清理大对象
                ForceLargeObjectCleanup();
                
                // 执行完整的垃圾回收
                GC.Collect();
                GC.WaitForPendingFinalizers();
                GC.Collect();
            });
        }

        private void StartMonitoring()
        {
            _isMonitoring = true;
            
            // 内存监控定时器（每5秒）
            _monitoringTimer = new Timer(_ =>
            {
                if (!_isMonitoring) return;
                
                var memoryInfo = GetCurrentMemoryUsage();
                UpdateMetrics(memoryInfo);
                MemoryUsageChanged?.Invoke(memoryInfo);
                
                // 检测内存泄漏
                if (DateTime.Now.Second % 30 == 0) // 每30秒检测一次
                {
                    DetectMemoryLeaks();
                }
            }, null, TimeSpan.Zero, TimeSpan.FromSeconds(5));

            // GC优化定时器（每60秒）
            _gcOptimizationTimer = new Timer(_ =>
            {
                if (!_isMonitoring) return;
                
                OptimizeGarbageCollection();
            }, null, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(60));
        }

        private void UpdateMetrics(MemoryUsageInfo info)
        {
            var timestamp = DateTime.Now;
            
            UpdateMetric("WorkingSet", info.WorkingSetMB, timestamp);
            UpdateMetric("PrivateMemory", info.PrivateMemoryMB, timestamp);
            UpdateMetric("TotalMemory", info.TotalMemory, timestamp);
            UpdateMetric("LargeObjectHeap", info.LargeObjectHeapSize, timestamp);
        }

        private void UpdateMetric(string name, double value, DateTime timestamp)
        {
            _metrics.AddOrUpdate(name, 
                _ => new MemoryMetric { Name = name, Values = new List<(DateTime, double)> { (timestamp, value) } },
                (_, metric) =>
                {
                    metric.Values.Add((timestamp, value));
                    // 保留最近100个数据点
                    if (metric.Values.Count > 100)
                        metric.Values.RemoveAt(0);
                    return metric;
                });
        }

        private GcInfo GetGcInfo()
        {
            return new GcInfo
            {
                Gen0Count = GC.CollectionCount(0),
                Gen1Count = GC.CollectionCount(1),
                Gen2Count = GC.CollectionCount(2),
                TotalMemory = GC.GetTotalMemory(false),
                MaxGeneration = GC.MaxGeneration
            };
        }

        private double GetLargeObjectHeapSize()
        {
            try
            {
                // 通过分析GC统计信息估算LOH大小
                var gen2Before = GC.CollectionCount(2);
                GC.Collect(2, GCCollectionMode.Forced, true);
                var gen2After = GC.CollectionCount(2);
                
                if (gen2After > gen2Before)
                {
                    var beforeMemory = GC.GetTotalMemory(true);
                    GC.Collect(2, GCCollectionMode.Forced, true);
                    var afterMemory = GC.GetTotalMemory(true);
                    return (beforeMemory - afterMemory) / 1024.0 / 1024.0;
                }
                return 0;
            }
            catch
            {
                return 0;
            }
        }

        private MemoryBaseline GetMemoryBaseline()
        {
            // 实现内存基线计算逻辑
            return new MemoryBaseline();
        }

        private List<MemoryTrend> AnalyzeMemoryTrends()
        {
            // 分析内存使用趋势
            return new List<MemoryTrend>();
        }

        private List<SuspiciousObject> FindSuspiciousObjects()
        {
            // 查找可疑对象（如事件处理程序、大对象等）
            return new List<SuspiciousObject>();
        }

        private void ForceEventCleanup()
        {
            // 强制清理事件处理程序
        }

        private void ForceLargeObjectCleanup()
        {
            // 强制清理大对象
        }

        private List<string> GetRecommendedActions()
        {
            var actions = new List<string>();
            var memoryInfo = GetCurrentMemoryUsage();

            if (memoryInfo.WorkingSetMB > 800)
                actions.Add("建议减少图像缓存大小");

            if (memoryInfo.HandleCount > 1000)
                actions.Add("检测到句柄使用较多，建议检查资源释放");

            if (memoryInfo.LargeObjectHeapSize > 100)
                actions.Add("大对象堆占用较高，考虑优化大数组使用");

            return actions;
        }

        private List<string> GenerateLeakPreventionRecommendations()
        {
            return new List<string>
            {
                "确保事件处理程序正确注销",
                "及时释放大型数据结构",
                "使用using语句管理IDisposable资源",
                "考虑使用WeakReference引用大型临时对象"
            };
        }

        private void InitializeMetrics()
        {
            var initialMetrics = new[]
            {
                "WorkingSet", "PrivateMemory", "TotalMemory", "LargeObjectHeap"
            };

            foreach (var metric in initialMetrics)
            {
                _metrics[metric] = new MemoryMetric { Name = metric, Values = new List<(DateTime, double)>() };
            }
        }

        public void Dispose()
        {
            if (_isDisposed) return;
            
            _isMonitoring = false;
            _monitoringTimer?.Dispose();
            _gcOptimizationTimer?.Dispose();
            _isDisposed = true;
        }
    }

    #region 数据模型类
    
    public class MemoryUsageInfo
    {
        public DateTime Timestamp { get; set; }
        public double WorkingSetMB { get; set; }
        public double PrivateMemoryMB { get; set; }
        public int Gen0CollectionCount { get; set; }
        public int Gen1CollectionCount { get; set; }
        public int Gen2CollectionCount { get; set; }
        public double TotalMemory { get; set; }
        public bool IsServerGC { get; set; }
        public GCLatencyMode LatencyMode { get; set; }
        public double LargeObjectHeapSize { get; set; }
        public int HandleCount { get; set; }
        public int ThreadCount { get; set; }
    }

    public class MemoryGcOptimizationResult
    {
        public bool Success { get; set; }
        public double FreedMemoryMB { get; set; }
        public GCLatencyMode LatencyMode { get; set; }
        public List<string> RecommendedActions { get; set; }
        public string ErrorMessage { get; set; }
    }

    public class MemoryLeakDetectionResult
    {
        public bool DetectedLeaks { get; set; }
        public int TotalSuspiciousObjects { get; set; }
        public List<MemoryTrend> MemoryTrends { get; set; }
        public List<string> Recommendations { get; set; }
    }

    public class MemoryMetric
    {
        public string Name { get; set; }
        public List<(DateTime Timestamp, double Value)> Values { get; set; }
    }

    public class GcInfo
    {
        public int Gen0Count { get; set; }
        public int Gen1Count { get; set; }
        public int Gen2Count { get; set; }
        public long TotalMemory { get; set; }
        public int MaxGeneration { get; set; }
    }

    public class MemoryBaseline { }
    public class MemoryTrend { public double GrowthRate { get; set; } public string Category { get; set; } }
    public class SuspiciousObject { }
    
    public class GcOptimizationAdvice
    {
        public GcAdviceSeverity Severity { get; set; }
        public string Message { get; set; }
        public List<string> RecommendedActions { get; set; }
    }

    public enum GcAdviceSeverity
    {
        Low,
        Medium,
        High
    }

    #endregion
}