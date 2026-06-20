using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;

namespace FireAntivirus.Host.WPF
{
    /// <summary>
    /// 性能瓶颈分析器 - 检测和优化性能问题
    /// </summary>
    public class PerformanceAnalyzer
    {
        private readonly ConcurrentDictionary<string, PerformanceMetric> _metrics;
        private readonly List<PerformanceBottleneck> _detectedBottlenecks;
        private readonly Stopwatch _analysisTimer;
        private readonly int _analysisThresholdMs = 100;

        public event Action<PerformanceIssueArgs> OnPerformanceIssueDetected;

        public PerformanceAnalyzer()
        {
            _metrics = new ConcurrentDictionary<string, PerformanceMetric>();
            _detectedBottlenecks = new List<PerformanceBottleneck>();
            _analysisTimer = new Stopwatch();
        }

        /// <summary>
        /// 开始性能监控和分析
        /// </summary>
        public void StartAnalysis()
        {
            _analysisTimer.Restart();
        }

        /// <summary>
        /// 结束性能监控并生成分析报告
        /// </summary>
        public PerformanceAnalysisReport CompleteAnalysis()
        {
            _analysisTimer.Stop();
            
            var report = new PerformanceAnalysisReport
            {
                AnalysisDuration = _analysisTimer.Elapsed,
                TotalMetrics = _metrics.Count,
                DetectedBottlenecks = AnalyzeBottlenecks()
            };

            // 生成性能优化建议
            report.OptimizationRecommendations = GenerateOptimizationRecommendations(report);
            
            return report;
        }

        /// <summary>
        /// 记录性能指标
        /// </summary>
        public void RecordMetric(string operationName, long durationMs, string context = null)
        {
            var metric = new PerformanceMetric
            {
                OperationName = operationName,
                DurationMs = durationMs,
                Context = context,
                Timestamp = DateTime.Now,
                ThreadId = Environment.CurrentManagedThreadId
            };

            _metrics.AddOrUpdate(operationName, 
                metric, 
                (key, existing) => 
                {
                    existing.History.Add(metric);
                    if (existing.History.Count > 100) // 保留最近100个记录
                        existing.History.RemoveAt(0);
                    return existing;
                });

            // 检测性能瓶颈
            DetectBottleneck(metric);
        }

        /// <summary>
        /// 分析页面加载性能
        /// </summary>
        public async Task<PageLoadAnalysis> AnalyzePageLoadAsync(string pageName, Func<Task> loadAction)
        {
            var analysis = new PageLoadAnalysis { PageName = pageName };
            var stopwatch = Stopwatch.StartNew();

            try
            {
                await loadAction();
                
                analysis.LoadTimeMs = stopwatch.ElapsedMilliseconds;
                analysis.IsOverThreshold = analysis.LoadTimeMs > _analysisThresholdMs;
                
                // 记录内存使用情况
                analysis.MemoryUsageMB = Process.GetCurrentProcess().WorkingSet64 / 1024.0 / 1024.0;
                
                // 分析性能瓶颈
                analysis.Bottlenecks = await AnalyzePageBottlenecks(pageName);
                
                // 生成优化建议
                analysis.OptimizationSuggestions = GeneratePageOptimizations(analysis);
                
                return analysis;
            }
            finally
            {
                stopwatch.Stop();
                RecordMetric($"PageLoad_{pageName}", analysis.LoadTimeMs);
            }
        }

        /// <summary>
        /// 比较不同页面的性能
        /// </summary>
        public AnalysisPerformanceComparison ComparePages(params string[] pageNames)
        {
            var comparison = new AnalysisPerformanceComparison
            {
                ComparedPages = pageNames,
                ComparisonDate = DateTime.Now
            };

            var pageMetrics = pageNames.Select(name => 
            {
                var key = $"PageLoad_{name}";
                return _metrics.TryGetValue(key, out var metric) ? metric : null;
            }).Where(m => m != null).ToList();

            if (pageMetrics.Any())
            {
                comparison.AverageLoadTime = pageMetrics.Average(m => m.DurationMs);
                comparison.FastestPage = pageMetrics.OrderBy(m => m.DurationMs).First().OperationName.Replace("PageLoad_", "");
                comparison.SlowestPage = pageMetrics.OrderByDescending(m => m.DurationMs).First().OperationName.Replace("PageLoad_", "");
                comparison.PerformanceVariance = CalculateVariance(pageMetrics.Select(m => (double)m.DurationMs));
            }

            return comparison;
        }

        /// <summary>
        /// 生成自动性能建议
        /// </summary>
        public List<PerformanceSuggestion> GenerateAutomaticSuggestions()
        {
            var suggestions = new List<PerformanceSuggestion>();

            // 分析长期性能趋势
            var slowOperations = _metrics.Values
                .Where(m => m.DurationMs > _analysisThresholdMs)
                .OrderByDescending(m => m.DurationMs)
                .Take(5);

            foreach (var operation in slowOperations)
            {
                var suggestion = new PerformanceSuggestion
                {
                    Priority = CalculateSuggestionPriority(operation),
                    Description = $"优化操作 '{operation.OperationName}'，当前耗时 {operation.DurationMs}ms",
                    RecommendedAction = GetRecommendedAction(operation),
                    EstimatedImpact = EstimateImpact(operation)
                };
                suggestions.Add(suggestion);
            }

            return suggestions.OrderByDescending(s => s.Priority).ToList();
        }

        #region 私有方法

        private List<PerformanceBottleneck> AnalyzeBottlenecks()
        {
            var bottlenecks = new List<PerformanceBottleneck>();

            // 分析长时间运行的页面加载
            var slowPageLoads = _metrics.Values
                .Where(m => m.OperationName.StartsWith("PageLoad_") && m.DurationMs > _analysisThresholdMs)
                .Select(m => new PerformanceBottleneck
                {
                    Type = BottleneckType.PageLoad,
                    Location = m.OperationName.Replace("PageLoad_", ""),
                    Severity = CalculateSeverity(m.DurationMs),
                    AverageDurationMs = m.DurationMs,
                    OccurrenceCount = m.History.Count + 1
                });

            bottlenecks.AddRange(slowPageLoads);

            // 检测内存使用瓶颈
            var highMemoryOperations = _metrics.Values
                .Where(m => m.Context?.Contains("Memory") == true && m.DurationMs > 50)
                .Select(m => new PerformanceBottleneck
                {
                    Type = BottleneckType.Memory,
                    Location = m.OperationName,
                    Severity = BottleneckSeverity.Medium,
                    AverageDurationMs = m.DurationMs
                });

            bottlenecks.AddRange(highMemoryOperations);

            return bottlenecks;
        }

        private void DetectBottleneck(PerformanceMetric metric)
        {
            if (metric.DurationMs <= _analysisThresholdMs) return;

            var bottleneck = new PerformanceBottleneck
            {
                Type = GetBottleneckType(metric.OperationName),
                Location = metric.OperationName,
                Severity = CalculateSeverity(metric.DurationMs),
                AverageDurationMs = metric.DurationMs,
                Timestamp = metric.Timestamp
            };

            lock (_detectedBottlenecks)
            {
                _detectedBottlenecks.Add(bottleneck);
                
                // 保持最近50个瓶颈记录
                if (_detectedBottlenecks.Count > 50)
                    _detectedBottlenecks.RemoveAt(0);
            }
        }

        private async Task<List<PerformanceBottleneck>> AnalyzePageBottlenecks(string pageName)
        {
            await Task.Delay(10); // 模拟分析过程
            
            var bottlenecks = _detectedBottlenecks
                .Where(b => b.Location.Contains(pageName))
                .ToList();

            return bottlenecks;
        }

        private List<string> GenerateOptimizationRecommendations(PerformanceAnalysisReport report)
        {
            var recommendations = new List<string>();

            if (report.DetectedBottlenecks.Any(b => b.Type == BottleneckType.PageLoad))
            {
                recommendations.Add("优化页面加载时间，考虑实现预加载机制");
            }

            if (report.DetectedBottlenecks.Any(b => b.Type == BottleneckType.Memory))
            {
                recommendations.Add("减少内存分配，优化大对象使用");
            }

            if (report.DetectedBottlenecks.Count > 10)
            {
                recommendations.Add("性能问题较多，建议进行系统性优化");
            }

            return recommendations;
        }

        private List<string> GeneratePageOptimizations(PageLoadAnalysis analysis)
        {
            var optimizations = new List<string>();

            if (analysis.LoadTimeMs > 200)
                optimizations.Add("页面加载超过200ms，考虑异步数据加载");

            if (analysis.MemoryUsageMB > 100)
                optimizations.Add("内存占用较高，优化资源使用");

            if (analysis.Bottlenecks.Any(b => b.Severity == BottleneckSeverity.High))
                optimizations.Add("检测到严重性能瓶颈，需要立即优化");

            return optimizations;
        }

        private BottleneckType GetBottleneckType(string operationName)
        {
            if (operationName.StartsWith("PageLoad_")) return BottleneckType.PageLoad;
            if (operationName.Contains("Memory")) return BottleneckType.Memory;
            if (operationName.Contains("Network")) return BottleneckType.Network;
            if (operationName.Contains("Database")) return BottleneckType.Database;
            return BottleneckType.General;
        }

        private BottleneckSeverity CalculateSeverity(long durationMs)
        {
            if (durationMs > 500) return BottleneckSeverity.Critical;
            if (durationMs > 200) return BottleneckSeverity.High;
            if (durationMs > 100) return BottleneckSeverity.Medium;
            return BottleneckSeverity.Low;
        }

        private double CalculateVariance(IEnumerable<double> values)
        {
            var list = values.ToList();
            if (list.Count < 2) return 0;

            var mean = list.Average();
            var variance = list.Select(x => Math.Pow(x - mean, 2)).Average();
            return variance;
        }

        private SuggestionPriority CalculateSuggestionPriority(PerformanceMetric metric)
        {
            if (metric.DurationMs > 500) return SuggestionPriority.High;
            if (metric.DurationMs > 200) return SuggestionPriority.Medium;
            return SuggestionPriority.Low;
        }

        private string GetRecommendedAction(PerformanceMetric metric)
        {
            return metric.OperationName switch
            {
                var name when name.StartsWith("PageLoad_") => "实现页面缓存或预加载机制",
                var name when name.Contains("Memory") => "优化内存分配和垃圾回收",
                _ => "分析具体实现并优化算法"
            };
        }

        private ImpactLevel EstimateImpact(PerformanceMetric metric)
        {
            return metric.DurationMs > 200 ? ImpactLevel.High : ImpactLevel.Medium;
        }

        #endregion
    }

    #region 数据模型和枚举

    public enum BottleneckType
    {
        PageLoad,
        Memory,
        Network,
        Database,
        General
    }

    public enum BottleneckSeverity
    {
        Low,
        Medium,
        High,
        Critical
    }

    public enum SuggestionPriority
    {
        Low,
        Medium,
        High,
        Critical
    }

    public enum ImpactLevel
    {
        Low,
        Medium,
        High
    }

    public class PerformanceMetric
    {
        public string OperationName { get; set; }
        public long DurationMs { get; set; }
        public string Context { get; set; }
        public DateTime Timestamp { get; set; }
        public int ThreadId { get; set; }
        public List<PerformanceMetric> History { get; set; } = new List<PerformanceMetric>();
    }

    public class PerformanceBottleneck
    {
        public BottleneckType Type { get; set; }
        public string Location { get; set; }
        public BottleneckSeverity Severity { get; set; }
        public double AverageDurationMs { get; set; }
        public int OccurrenceCount { get; set; }
        public DateTime Timestamp { get; set; }
    }

    public class PerformanceAnalysisReport
    {
        public TimeSpan AnalysisDuration { get; set; }
        public int TotalMetrics { get; set; }
        public List<PerformanceBottleneck> DetectedBottlenecks { get; set; }
        public List<string> OptimizationRecommendations { get; set; }
    }

    public class PageLoadAnalysis
    {
        public string PageName { get; set; }
        public long LoadTimeMs { get; set; }
        public bool IsOverThreshold { get; set; }
        public double MemoryUsageMB { get; set; }
        public List<PerformanceBottleneck> Bottlenecks { get; set; }
        public List<string> OptimizationSuggestions { get; set; }
    }

    public class AnalysisPerformanceComparison
    {
        public string[] ComparedPages { get; set; }
        public DateTime ComparisonDate { get; set; }
        public double AverageLoadTime { get; set; }
        public string FastestPage { get; set; }
        public string SlowestPage { get; set; }
        public double PerformanceVariance { get; set; }
    }

    public class PerformanceSuggestion
    {
        public SuggestionPriority Priority { get; set; }
        public string Description { get; set; }
        public string RecommendedAction { get; set; }
        public ImpactLevel EstimatedImpact { get; set; }
    }

    #endregion
}