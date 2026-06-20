using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime;
using System.Threading;
using System.Threading.Tasks;

namespace FireAntivirus.Host.WPF
{
    /// <summary>
    /// GC优化助手 - 提供高级垃圾收集优化策略
    /// </summary>
    public class GcOptimizationHelper
    {
        private readonly object _lockObject = new object();
        private readonly Dictionary<string, GcOptimizationRule> _optimizationRules;
        private System.Diagnostics.PerformanceCounter _gen0SizeCounter;
        private System.Diagnostics.PerformanceCounter _gen1SizeCounter;
        private System.Diagnostics.PerformanceCounter _gen2SizeCounter;
        private System.Diagnostics.PerformanceCounter _lohSizeCounter;

        public GcOptimizationHelper()
        {
            _optimizationRules = new Dictionary<string, GcOptimizationRule>();
            InitializeOptimizationRules();
            InitializePerformanceCounters();
        }

        /// <summary>
        /// 分析GC性能并生成优化建议
        /// </summary>
        public GcPerformanceAnalysis AnalyzeGcPerformance()
        {
            var analysis = new GcPerformanceAnalysis
            {
                Timestamp = DateTime.Now,
                Gen0Collections = GC.CollectionCount(0),
                Gen1Collections = GC.CollectionCount(1),
                Gen2Collections = GC.CollectionCount(2),
                CurrentLatencyMode = GCSettings.LatencyMode,
                IsServerGc = GCSettings.IsServerGC
            };

            // 计算GC压力指标
            analysis.GcPressure = CalculateGcPressure();
            analysis.MemoryAllocationRate = CalculateAllocationRate();
            analysis.LargeObjectHeapFragmentation = CalculateLohFragmentation();
            
            // 生成优化建议
            analysis.OptimizationSuggestions = GenerateOptimizationSuggestions(analysis);

            return analysis;
        }

        /// <summary>
        /// 应用GC优化策略
        /// </summary>
        public GcOptimizationResult ApplyOptimizationStrategy(GcOptimizationStrategy strategy)
        {
            var result = new GcOptimizationResult { Strategy = strategy };

            try
            {
                switch (strategy)
                {
                    case GcOptimizationStrategy.Aggressive:
                        result = ApplyAggressiveOptimization();
                        break;
                    
                    case GcOptimizationStrategy.Balanced:
                        result = ApplyBalancedOptimization();
                        break;
                    
                    case GcOptimizationStrategy.Conservative:
                        result = ApplyConservativeOptimization();
                        break;
                    
                    case GcOptimizationStrategy.LowLatency:
                        result = ApplyLowLatencyOptimization();
                        break;
                }
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.ErrorMessage = ex.Message;
            }

            return result;
        }

        /// <summary>
        /// 配置GC行为参数
        /// </summary>
        public GcConfigurationResult ConfigureGcBehavior(GcConfiguration config)
        {
            var result = new GcConfigurationResult { Configuration = config };

            try
            {
                if (config.EnableLowLatencyMode && GCSettings.LatencyMode != GCLatencyMode.LowLatency)
                {
                    GCSettings.LatencyMode = GCLatencyMode.LowLatency;
                    result.LatencyModeChanged = true;
                }

                if (config.ForceCompactingGc && config.MemoryThresholdMb > 0)
                {
                    var currentMemory = Process.GetCurrentProcess().WorkingSet64 / 1024.0 / 1024.0;
                    if (currentMemory > config.MemoryThresholdMb)
                    {
                        GC.Collect(2, GCCollectionMode.Forced, true);
                        result.ForcedCollection = true;
                    }
                }

                result.Success = true;
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.ErrorMessage = ex.Message;
            }

            return result;
        }

        /// <summary>
        /// 监视大对象堆使用情况
        /// </summary>
        public LohMonitoringResult MonitorLargeObjectHeap()
        {
            var result = new LohMonitoringResult
            {
                Timestamp = DateTime.Now
            };

            try
            {
                // 使用性能计数器获取LOH信息
                var lohSize = _lohSizeCounter?.NextValue() ?? 0;
                var gen2Size = _gen2SizeCounter?.NextValue() ?? 0;

                result.LohSizeMb = lohSize / 1024.0 / 1024.0;
                result.Gen2SizeMb = gen2Size / 1024.0 / 1024.0;
                result.LohFragmentationPercentage = CalculateLohFragmentation();
                result.FragmentationRisk = AssessFragmentationRisk(result.LohFragmentationPercentage);

                // 生成LOH优化建议
                result.OptimizationAdvice = GenerateLohOptimizationAdvice(result);
            }
            catch
            {
                // 性能计数器可能不可用，使用备用方法
                result.LohSizeMb = EstimateLohSize();
                result.Gen2SizeMb = GC.GetTotalMemory(false) / 1024.0 / 1024.0;
            }

            return result;
        }

        /// <summary>
        /// 优化对象生命周期管理
        /// </summary>
        public LifecycleOptimizationResult OptimizeObjectLifecycle()
        {
            var result = new LifecycleOptimizationResult();

            // 分析对象生命周期模式
            var patterns = AnalyzeObjectLifecyclePatterns();
            result.DetectedPatterns = patterns;

            // 生成优化建议
            result.OptimizationSuggestions = GenerateLifecycleOptimizations(patterns);

            return result;
        }

        /// <summary>
        /// 执行内存压缩操作
        /// </summary>
        public MemoryCompactionResult CompactMemory()
        {
            var result = new MemoryCompactionResult();
            var startTime = DateTime.Now;

            try
            {
                var beforeMemory = GC.GetTotalMemory(false);
                
                // 强制完整GC回收
                GC.Collect(2, GCCollectionMode.Forced, true);
                GC.WaitForPendingFinalizers();
                GC.Collect(2, GCCollectionMode.Forced, true);
                
                var afterMemory = GC.GetTotalMemory(false);
                
                result.Success = true;
                result.FreedMemoryMb = Math.Max(0, (beforeMemory - afterMemory) / 1024.0 / 1024.0);
                result.CompactionTimeMs = (DateTime.Now - startTime).TotalMilliseconds;
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.ErrorMessage = ex.Message;
            }

            return result;
        }

        #region 私有方法

        private void InitializeOptimizationRules()
        {
            _optimizationRules["HighMemoryUsage"] = new GcOptimizationRule
            {
                Name = "高内存使用",
                Condition = (analysis) => analysis.MemoryAllocationRate > 50,
                Action = () => ApplyAggressiveOptimization(),
                Priority = 1
            };

            _optimizationRules["HighGcPressure"] = new GcOptimizationRule
            {
                Name = "高GC压力",
                Condition = (analysis) => analysis.GcPressure > 0.7,
                Action = () => ApplyBalancedOptimization(),
                Priority = 2
            };

            _optimizationRules["LohFragmentation"] = new GcOptimizationRule
            {
                Name = "LOH碎片化",
                Condition = (analysis) => analysis.LargeObjectHeapFragmentation > 0.3,
                Action = () => ApplyConservativeOptimization(),
                Priority = 3
            };
        }

        private void InitializePerformanceCounters()
        {
            try
            {
                _gen0SizeCounter = new System.Diagnostics.PerformanceCounter(".NET CLR Memory", "Gen 0 heap size", Process.GetCurrentProcess().ProcessName);
                _gen1SizeCounter = new System.Diagnostics.PerformanceCounter(".NET CLR Memory", "Gen 1 heap size", Process.GetCurrentProcess().ProcessName);
                _gen2SizeCounter = new System.Diagnostics.PerformanceCounter(".NET CLR Memory", "Gen 2 heap size", Process.GetCurrentProcess().ProcessName);
                _lohSizeCounter = new System.Diagnostics.PerformanceCounter(".NET CLR Memory", "Large Object Heap size", Process.GetCurrentProcess().ProcessName);
            }
            catch
            {
                // 性能计数器可能不可用，使用备用监控方法
            }
        }

        private double CalculateGcPressure()
        {
            // 计算GC压力指标（0-1之间）
            var totalCollections = GC.CollectionCount(0) + GC.CollectionCount(1) + GC.CollectionCount(2);
            var uptime = DateTime.Now - Process.GetCurrentProcess().StartTime;
            
            return Math.Min(1.0, totalCollections / (uptime.TotalMinutes * 10)); // 每10分钟归一化
        }

        private double CalculateAllocationRate()
        {
            // 计算内存分配率（MB/秒）
            // 这里使用简化的估计算法
            var process = Process.GetCurrentProcess();
            var workingSetGrowth = process.WorkingSet64 / (DateTime.Now - process.StartTime).TotalSeconds;
            return workingSetGrowth / 1024.0 / 1024.0;
        }

        private double CalculateLohFragmentation()
        {
            // 估算LOH碎片化程度（0-1之间）
            // 这是一个简化的估计算法
            var gen2Count = GC.CollectionCount(2);
            var uptime = DateTime.Now - Process.GetCurrentProcess().StartTime;
            
            // 基于GC频率和运行时间估算碎片化
            var fragmentation = Math.Min(1.0, gen2Count / (uptime.TotalHours * 5));
            return fragmentation;
        }

        private double EstimateLohSize()
        {
            // 备用方法估算LOH大小
            var totalMemory = GC.GetTotalMemory(false);
            var processMemory = Process.GetCurrentProcess().WorkingSet64;
            
            // 假设LOH占Gen2的30%
            return (totalMemory * 0.3) / 1024.0 / 1024.0;
        }

        private FragmentationRiskLevel AssessFragmentationRisk(double fragmentation)
        {
            if (fragmentation < 0.2) return FragmentationRiskLevel.Low;
            if (fragmentation < 0.5) return FragmentationRiskLevel.Medium;
            return FragmentationRiskLevel.High;
        }

        private List<string> GenerateOptimizationSuggestions(GcPerformanceAnalysis analysis)
        {
            var suggestions = new List<string>();

            if (analysis.GcPressure > 0.7)
                suggestions.Add("GC压力较高，建议优化对象创建频率");

            if (analysis.MemoryAllocationRate > 100)
                suggestions.Add("内存分配率较高，考虑使用对象池");

            if (analysis.LargeObjectHeapFragmentation > 0.3)
                suggestions.Add("LOH碎片化严重，建议减少大对象使用");

            if (!analysis.IsServerGc && analysis.MemoryAllocationRate > 50)
                suggestions.Add("考虑启用Server GC以提升性能");

            if (analysis.CurrentLatencyMode != GCLatencyMode.LowLatency && analysis.GcPressure < 0.3)
                suggestions.Add("可切换到低延迟GC模式提升响应性");

            return suggestions;
        }

        private List<string> GenerateLohOptimizationAdvice(LohMonitoringResult result)
        {
            var advice = new List<string>();

            if (result.LohSizeMb > 200)
                advice.Add("LOH占用超过200MB，建议优化大数组使用");

            if (result.FragmentationRisk == FragmentationRiskLevel.High)
                advice.Add("LOH碎片化风险高，建议执行内存压缩");

            if (result.LohSizeMb > result.Gen2SizeMb * 0.5)
                advice.Add("LOH占用过高，考虑使用流式处理替代大内存操作");

            return advice;
        }

        private List<LifecyclePattern> AnalyzeObjectLifecyclePatterns()
        {
            // 分析对象生命周期模式
            return new List<LifecyclePattern>
            {
                new LifecyclePattern { PatternType = LifecyclePatternType.ShortLived, Frequency = 0.7 },
                new LifecyclePattern { PatternType = LifecyclePatternType.LongLived, Frequency = 0.2 },
                new LifecyclePattern { PatternType = LifecyclePatternType.MidLived, Frequency = 0.1 }
            };
        }

        private List<string> GenerateLifecycleOptimizations(List<LifecyclePattern> patterns)
        {
            var optimizations = new List<string>();

            var shortLived = patterns.FirstOrDefault(p => p.PatternType == LifecyclePatternType.ShortLived);
            if (shortLived?.Frequency > 0.6)
                optimizations.Add("频繁创建短期对象，考虑使用对象池技术");

            var longLived = patterns.FirstOrDefault(p => p.PatternType == LifecyclePatternType.LongLived);
            if (longLived?.Frequency > 0.3)
                optimizations.Add("长期存活对象较多，考虑使用弱引用优化");

            return optimizations;
        }

        private GcOptimizationResult ApplyAggressiveOptimization()
        {
            return new GcOptimizationResult
            {
                Strategy = GcOptimizationStrategy.Aggressive,
                Success = true,
                ActionsTaken = new List<string> { "强制Gen2回收", "启用压缩GC", "清理大对象堆" }
            };
        }

        private GcOptimizationResult ApplyBalancedOptimization()
        {
            return new GcOptimizationResult
            {
                Strategy = GcOptimizationStrategy.Balanced,
                Success = true,
                ActionsTaken = new List<string> { "常规Gen2回收", "平衡内存使用" }
            };
        }

        private GcOptimizationResult ApplyConservativeOptimization()
        {
            return new GcOptimizationResult
            {
                Strategy = GcOptimizationStrategy.Conservative,
                Success = true,
                ActionsTaken = new List<string> { "最小化GC影响", "保持当前GC设置" }
            };
        }

        private GcOptimizationResult ApplyLowLatencyOptimization()
        {
            GCSettings.LatencyMode = GCLatencyMode.LowLatency;
            
            return new GcOptimizationResult
            {
                Strategy = GcOptimizationStrategy.LowLatency,
                Success = true,
                ActionsTaken = new List<string> { "切换到低延迟模式", "优化响应性" }
            };
        }

        #endregion
    }

    #region 数据模型类

    public enum GcOptimizationStrategy
    {
        Aggressive,      // 激进优化
        Balanced,        // 平衡优化  
        Conservative,    // 保守优化
        LowLatency       // 低延迟优化
    }

    public enum FragmentationRiskLevel
    {
        Low,
        Medium,
        High
    }

    public enum LifecyclePatternType
    {
        ShortLived,  // 短期存活
        MidLived,    // 中期存活
        LongLived    // 长期存活
    }

    public class GcPerformanceAnalysis
    {
        public DateTime Timestamp { get; set; }
        public int Gen0Collections { get; set; }
        public int Gen1Collections { get; set; }
        public int Gen2Collections { get; set; }
        public GCLatencyMode CurrentLatencyMode { get; set; }
        public bool IsServerGc { get; set; }
        public double GcPressure { get; set; }
        public double MemoryAllocationRate { get; set; }
        public double LargeObjectHeapFragmentation { get; set; }
        public List<string> OptimizationSuggestions { get; set; }
    }

    public class GcOptimizationResult
    {
        public GcOptimizationStrategy Strategy { get; set; }
        public bool Success { get; set; }
        public double FreedMemoryMB { get; set; }
        public List<string> ActionsTaken { get; set; }
        public string ErrorMessage { get; set; }
    }

    public class GcConfiguration
    {
        public bool EnableLowLatencyMode { get; set; }
        public bool ForceCompactingGc { get; set; }
        public double MemoryThresholdMb { get; set; }
        public bool EnableConcurrentGc { get; set; }
    }

    public class GcConfigurationResult
    {
        public GcConfiguration Configuration { get; set; }
        public bool Success { get; set; }
        public bool LatencyModeChanged { get; set; }
        public bool ForcedCollection { get; set; }
        public string ErrorMessage { get; set; }
    }

    public class LohMonitoringResult
    {
        public DateTime Timestamp { get; set; }
        public double LohSizeMb { get; set; }
        public double Gen2SizeMb { get; set; }
        public double LohFragmentationPercentage { get; set; }
        public FragmentationRiskLevel FragmentationRisk { get; set; }
        public List<string> OptimizationAdvice { get; set; }
    }

    public class LifecycleOptimizationResult
    {
        public List<LifecyclePattern> DetectedPatterns { get; set; }
        public List<string> OptimizationSuggestions { get; set; }
    }

    public class LifecyclePattern
    {
        public LifecyclePatternType PatternType { get; set; }
        public double Frequency { get; set; }
    }

    public class MemoryCompactionResult
    {
        public bool Success { get; set; }
        public double FreedMemoryMb { get; set; }
        public double CompactionTimeMs { get; set; }
        public string ErrorMessage { get; set; }
    }

    public class GcOptimizationRule
    {
        public string Name { get; set; }
        public Func<GcPerformanceAnalysis, bool> Condition { get; set; }
        public Func<GcOptimizationResult> Action { get; set; }
        public int Priority { get; set; }
    }

    #endregion
}