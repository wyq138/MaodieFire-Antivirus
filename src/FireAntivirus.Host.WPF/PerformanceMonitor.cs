using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Threading;

namespace FireAntivirus.Host.WPF
{
    /// <summary>
    /// 性能监控器，用于跟踪页面加载时间、内存使用和响应性
    /// </summary>
    public class PerformanceMonitor
    {
        private readonly Dictionary<string, List<long>> _loadTimes;
        private readonly Dictionary<string, PagePerformanceCounter> _counters;
        private readonly DispatcherTimer _monitoringTimer;
        private readonly object _lockObject = new object();

        public PerformanceMonitor()
        {
            _loadTimes = new Dictionary<string, List<long>>();
            _counters = new Dictionary<string, PagePerformanceCounter>();
            
            _monitoringTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(5)
            };
            _monitoringTimer.Tick += OnMonitoringTimerTick;
            _monitoringTimer.Start();
        }

        /// <summary>
        /// 开始跟踪页面加载时间
        /// </summary>
        public void StartPageLoadTracking(string pageName)
        {
            var counter = new PagePerformanceCounter
            {
                PageName = pageName,
                StartTime = Stopwatch.GetTimestamp(),
                MemoryBefore = GetCurrentMemoryUsageMB()
            };

            lock (_lockObject)
            {
                _counters[pageName] = counter;
            }
        }

        /// <summary>
        /// 结束页面加载时间跟踪
        /// </summary>
        public void EndPageLoadTracking(string pageName)
        {
            lock (_lockObject)
            {
                if (_counters.ContainsKey(pageName))
                {
                    var counter = _counters[pageName];
                    counter.EndTime = Stopwatch.GetTimestamp();
                    counter.MemoryAfter = GetCurrentMemoryUsageMB();
                    
                    var elapsedMilliseconds = (counter.EndTime - counter.StartTime) * 1000.0 / Stopwatch.Frequency;
                    
                    // 记录加载时间
                    if (!_loadTimes.ContainsKey(pageName))
                        _loadTimes[pageName] = new List<long>();
                    
                    _loadTimes[pageName].Add((long)elapsedMilliseconds);
                    
                    // 限制每个页面的记录数量
                    if (_loadTimes[pageName].Count > 100)
                        _loadTimes[pageName].RemoveAt(0);
                    
                    LogPerformanceEvent(pageName, elapsedMilliseconds, 
                        counter.MemoryAfter - counter.MemoryBefore);
                }
            }
        }

        /// <summary>
        /// 异步记录页面加载时间
        /// </summary>
        public async Task RecordPageLoadTime(string pageName, long loadTimeMs)
        {
            await Task.Run(() =>
            {
                lock (_lockObject)
                {
                    if (!_loadTimes.ContainsKey(pageName))
                        _loadTimes[pageName] = new List<long>();
                    
                    _loadTimes[pageName].Add(loadTimeMs);
                    
                    // 限制每个页面的记录数量
                    if (_loadTimes[pageName].Count > 100)
                        _loadTimes[pageName].RemoveAt(0);
                    
                    LogPerformanceEvent(pageName, loadTimeMs, 0);
                }
            }).ConfigureAwait(false);
        }

        /// <summary>
        /// 记录性能事件
        /// </summary>
        private void LogPerformanceEvent(string pageName, double loadTimeMs, double memoryDeltaMB)
        {
            var performanceLevel = loadTimeMs switch
            {
                < 100 => "优秀",
                < 300 => "良好", 
                < 1000 => "一般",
                _ => "需要优化"
            };

            var message = $"页面 {pageName} 加载完成: {loadTimeMs:F0}ms ({performanceLevel}), " +
                         $"内存变化: {memoryDeltaMB:F2}MB";
            
            Debug.WriteLine($"[性能监控] {message}");
            
            // 触发性能事件
            PerformanceEvent?.Invoke(this, new PerformanceEventArgs
            {
                PageName = pageName,
                LoadTimeMs = loadTimeMs,
                MemoryDeltaMB = memoryDeltaMB,
                PerformanceLevel = performanceLevel,
                Timestamp = DateTime.Now
            });
        }

        /// <summary>
        /// 获取当前内存使用量（MB）
        /// </summary>
        private float GetCurrentMemoryUsageMB()
        {
            using (var process = Process.GetCurrentProcess())
            {
                return process.PrivateMemorySize64 / (1024.0f * 1024.0f);
            }
        }

        /// <summary>
        /// 获取页面加载统计
        /// </summary>
        public PageLoadStatistics GetPageLoadStatistics(string pageName = null)
        {
            lock (_lockObject)
            {
                var relevantTimes = pageName != null 
                    ? (_loadTimes.TryGetValue(pageName, out var times) ? times : new List<long>())
                    : _loadTimes.Values.SelectMany(t => t).ToList();

                if (!relevantTimes.Any())
                    return new PageLoadStatistics();

                var timesInMs = relevantTimes.Select(t => (double)t).ToList();
                
                return new PageLoadStatistics
                {
                    AverageLoadTimeMs = timesInMs.Average(),
                    MaxLoadTimeMs = timesInMs.Max(),
                    MinLoadTimeMs = timesInMs.Min(),
                    LoadTime95Percentile = CalculatePercentile(timesInMs, 0.95),
                    TotalLoads = relevantTimes.Count,
                    RecentLoads = relevantTimes.TakeLast(10).ToList()
                };
            }
        }

        /// <summary>
        /// 计算百分位数
        /// </summary>
        private double CalculatePercentile(List<double> values, double percentile)
        {
            var sorted = values.OrderBy(v => v).ToList();
            var index = (int)Math.Ceiling(percentile * sorted.Count) - 1;
            return sorted[Math.Max(0, Math.Min(index, sorted.Count - 1))];
        }

        /// <summary>
        /// 生成性能报告
        /// </summary>
        public PerformanceReport GenerateReport()
        {
            lock (_lockObject)
            {
                var pageStats = _loadTimes.Keys.ToDictionary(
                    pageName => pageName,
                    pageName => GetPageLoadStatistics(pageName));

                var totalStats = GetPageLoadStatistics();

                return new PerformanceReport
                {
                    Timestamp = DateTime.Now,
                    TotalPagesTracked = _loadTimes.Count,
                    OverallPerformance = totalStats.AverageLoadTimeMs switch
                    {
                        < 100 => "优秀",
                        < 300 => "良好",
                        < 500 => "一般",
                        _ => "需要优化"
                    },
                    AverageLoadTimeMs = totalStats.AverageLoadTimeMs,
                    WorstPerformingPage = pageStats.OrderByDescending(p => p.Value.AverageLoadTimeMs)
                                                   .FirstOrDefault().Key,
                    BestPerformingPage = pageStats.OrderBy(p => p.Value.AverageLoadTimeMs)
                                                  .FirstOrDefault().Key,
                    PageStatistics = pageStats,
                    Recommendations = GenerateOptimizationRecommendations(totalStats, pageStats)
                };
            }
        }

        /// <summary>
        /// 生成优化建议
        /// </summary>
        private List<string> GenerateOptimizationRecommendations(PageLoadStatistics totalStats, 
            Dictionary<string, PageLoadStatistics> pageStats)
        {
            var recommendations = new List<string>();

            if (totalStats.AverageLoadTimeMs > 500)
                recommendations.Add("整体加载时间较长，建议优化数据预加载策略");

            var slowPages = pageStats.Where(p => p.Value.AverageLoadTimeMs > 300)
                                    .OrderByDescending(p => p.Value.AverageLoadTimeMs)
                                    .ToList();

            if (slowPages.Any())
                recommendations.Add($"以下页面加载较慢，建议优化: {string.Join(", ", slowPages.Select(p => p.Key))}");

            if (totalStats.TotalLoads < 10)
                recommendations.Add("数据样本较少，建议收集更多性能数据后再进行优化");

            return recommendations;
        }

        /// <summary>
        /// 监控定时器回调
        /// </summary>
        private void OnMonitoringTimerTick(object sender, EventArgs e)
        {
            // 定期记录系统资源使用情况
            var memoryUsage = GetCurrentMemoryUsageMB();
            if (memoryUsage > 500) // 500MB警告阈值
            {
                Debug.WriteLine($"[性能监控] 内存使用较高: {memoryUsage:F1}MB");
            }
        }

        /// <summary>
        /// 释放资源
        /// </summary>
        public void Dispose()
        {
            _monitoringTimer?.Stop();
        }

        /// <summary>
        /// 性能事件
        /// </summary>
        public event EventHandler<PerformanceEventArgs> PerformanceEvent;

        /// <summary>
        /// 性能指标更新事件
        /// </summary>
        public event EventHandler PerformanceMetricsUpdated;

        /// <summary>
        /// 记录性能指标
        /// </summary>
        public void RecordMetric(string metricName, double value)
        {
            PerformanceMetricsUpdated?.Invoke(this, EventArgs.Empty);
        }
    }

/// <summary>
/// 性能计数器（页面计时用）
/// </summary>
public class PagePerformanceCounter
{
    public string PageName { get; set; }
    public long StartTime { get; set; }
    public long EndTime { get; set; }
    public float MemoryBefore { get; set; }
    public float MemoryAfter { get; set; }
}

    /// <summary>
    /// 页面加载统计
    /// </summary>
    public class PageLoadStatistics
    {
        public double AverageLoadTimeMs { get; set; }
        public double MaxLoadTimeMs { get; set; }
        public double MinLoadTimeMs { get; set; }
        public double LoadTime95Percentile { get; set; }
        public int TotalLoads { get; set; }
        public List<long> RecentLoads { get; set; } = new List<long>();
    }

    /// <summary>
    /// 性能报告
    /// </summary>
    public class PerformanceReport
    {
        public DateTime Timestamp { get; set; }
        public int TotalPagesTracked { get; set; }
        public string OverallPerformance { get; set; }
        public double AverageLoadTimeMs { get; set; }
        public string WorstPerformingPage { get; set; }
        public string BestPerformingPage { get; set; }
        public Dictionary<string, PageLoadStatistics> PageStatistics { get; set; }
        public List<string> Recommendations { get; set; }
    }

    /// <summary>
    /// 性能事件参数
    /// </summary>
    public class PerformanceEventArgs : EventArgs
    {
        public string PageName { get; set; }
        public double LoadTimeMs { get; set; }
        public double MemoryDeltaMB { get; set; }
        public string PerformanceLevel { get; set; }
        public DateTime Timestamp { get; set; }
    }
}