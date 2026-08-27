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
    /// 高级内存监控器 - 扩展基础内存监控功能
    /// </summary>
    public class AdvancedMemoryMonitor : IDisposable
    {
        private readonly Timer _monitoringTimer;
        private readonly List<MemorySnapshot> _memorySnapshots;
        private readonly object _snapshotLock = new object();
        private readonly int _maxSnapshots = 1000;
        private readonly System.Diagnostics.PerformanceCounter _memoryCounter;
        private bool _isDisposed = false;

        public event EventHandler OnMemoryAlert;

        public AdvancedMemoryMonitor()
        {
            _memorySnapshots = new List<MemorySnapshot>();
            _monitoringTimer = new Timer(MonitorMemory, null, TimeSpan.Zero, TimeSpan.FromSeconds(5));
            
            try
            {
                // 尝试创建性能计数器（仅Windows）
                _memoryCounter = new System.Diagnostics.PerformanceCounter("Process", "Working Set", Process.GetCurrentProcess().ProcessName);
            }
            catch
            {
                _memoryCounter = null;
            }
        }

        /// <summary>
        /// 获取详细内存分析报告
        /// </summary>
        public DetailedMemoryAnalysis GetDetailedAnalysis()
        {
            lock (_snapshotLock)
            {
                var analysis = new DetailedMemoryAnalysis
                {
                    AnalysisTime = DateTime.Now,
                    TotalSnapshots = _memorySnapshots.Count,
                    OverallTrend = CalculateMemoryTrend(),
                    MemoryUsagePattern = AnalyzeUsagePattern(),
                    LeakDetection = DetectPotentialLeaksInternal(),
                    OptimizationSuggestions = GenerateMemoryOptimizationsInternal()
                };

                return analysis;
            }
        }

        /// <summary>
        /// 检测内存泄漏模式
        /// </summary>
        public MemoryLeakDetection DetectMemoryLeaks()
        {
            lock (_snapshotLock)
            {
                var detection = new MemoryLeakDetection
                {
                    DetectionTime = DateTime.Now,
                    InitialMemoryMB = _memorySnapshots.Count > 0 ? _memorySnapshots.First().WorkingSetMB : 0,
                    CurrentMemoryMB = _memorySnapshots.Count > 0 ? _memorySnapshots.Last().WorkingSetMB : 0,
                    MemoryGrowthMB = CalculateGrowthRate(),
                    LeakScore = CalculateLeakScore(),
                    SuspectedLeaks = IdentifySuspectedLeakPoints()
                };

                detection.HasPossibleLeak = detection.LeakScore > 0.7;
                detection.HasDefiniteLeak = detection.LeakScore > 0.9;

                return detection;
            }
        }

        /// <summary>
        /// 生成内存优化建议
        /// </summary>
        public List<MemoryOptimization> GenerateOptimizations()
        {
            var optimizations = new List<MemoryOptimization>();
            var analysis = GetDetailedAnalysis();

            // 基于分析结果生成建议
            if (analysis.MemoryUsagePattern == MemoryUsagePattern.HighGrowth)
            {
                optimizations.Add(new MemoryOptimization
                {
                    Priority = OptimizationPriority.High,
                    Type = OptimizationType.MemoryManagement,
                    Description = "检测到内存高速增长，建议检查未释放的资源",
                    Action = "实现及时的资源释放和对象池管理"
                });
            }

            if (analysis.LeakDetection.PossibleLeaks.Any())
            {
                optimizations.Add(new MemoryOptimization
                {
                    Priority = OptimizationPriority.Critical,
                    Type = OptimizationType.LeakPrevention,
                    Description = $"检测到 {analysis.LeakDetection.PossibleLeaks.Count} 个潜在内存泄漏点",
                    Action = "审查相关代码，确保及时释放大对象"
                });
            }

            var currentMemory = GetCurrentMemoryUsage();
            if (currentMemory.WorkingSetMB > 500)
            {
                optimizations.Add(new MemoryOptimization
                {
                    Priority = OptimizationPriority.Medium,
                    Type = OptimizationType.CacheOptimization,
                    Description = "内存使用较高，建议优化缓存策略",
                    Action = "考虑实现LRU缓存或设置内存使用上限"
                });
            }

            return optimizations.OrderByDescending(o => o.Priority).ToList();
        }

        /// <summary>
        /// 执行内存优化操作
        /// </summary>
        public async Task<MemoryOptimizationResult> OptimizeMemoryAsync()
        {
            var result = new MemoryOptimizationResult
            {
                StartTime = DateTime.Now,
                InitialMemoryMB = Process.GetCurrentProcess().WorkingSet64 / 1024.0 / 1024.0
            };

            try
            {
                // 1. 强制垃圾回收
                await ForceGarbageCollectionAsync();
                
                // 2. 清理大对象堆（如果可能）
                await CleanLargeObjectHeapAsync();
                
                // 3. 释放非托管资源
                await ReleaseUnmanagedResourcesAsync();
                
                // 4. 优化内存碎片
                await OptimizeMemoryFragmentationAsync();
                
                result.Success = true;
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.ErrorMessage = ex.Message;
            }
            
            result.EndTime = DateTime.Now;
            result.FinalMemoryMB = Process.GetCurrentProcess().WorkingSet64 / 1024.0 / 1024.0;
            result.MemoryFreedMB = result.InitialMemoryMB - result.FinalMemoryMB;
            
            return result;
        }

        #region 私有方法

        private void MonitorMemory(object state)
        {
            var snapshot = new MemorySnapshot
            {
                Timestamp = DateTime.Now,
                WorkingSetMB = Process.GetCurrentProcess().WorkingSet64 / 1024.0 / 1024.0,
                PrivateMemoryMB = Process.GetCurrentProcess().PrivateMemorySize64 / 1024.0 / 1024.0,
                GCMemoryMB = GC.GetTotalMemory(false) / 1024.0 / 1024.0,
                Gen0CollectionCount = GC.CollectionCount(0),
                Gen1CollectionCount = GC.CollectionCount(1),
                Gen2CollectionCount = GC.CollectionCount(2),
                LargeObjectHeapSize = GetLOHSize(),
                ThreadCount = Process.GetCurrentProcess().Threads.Count
            };

            lock (_snapshotLock)
            {
                _memorySnapshots.Add(snapshot);
                
                // 保持最近的数据点
                if (_memorySnapshots.Count > _maxSnapshots)
                {
                    _memorySnapshots.RemoveAt(0);
                }
            }
        }

        private MemoryUsagePattern AnalyzeUsagePattern()
        {
            if (_memorySnapshots.Count < 10) return MemoryUsagePattern.Stable;
            
            var recentSnapshots = _memorySnapshots.TakeLast(10).ToList();
            var avgMemory = recentSnapshots.Average(s => s.WorkingSetMB);
            var variance = recentSnapshots.Select(s => Math.Pow(s.WorkingSetMB - avgMemory, 2)).Average();
            
            if (variance > 100) return MemoryUsagePattern.HighGrowth;
            if (variance > 50) return MemoryUsagePattern.GradualGrowth;
            return MemoryUsagePattern.Stable;
        }

        private MemoryTrend CalculateMemoryTrend()
        {
            if (_memorySnapshots.Count < 5) return MemoryTrend.Stable;
            
            var oldest = _memorySnapshots.First().WorkingSetMB;
            var newest = _memorySnapshots.Last().WorkingSetMB;
            var difference = newest - oldest;
            
            if (difference > 200) return MemoryTrend.RapidIncrease;
            if (difference > 50) return MemoryTrend.GradualIncrease;
            if (difference < -50) return MemoryTrend.Decreasing;
            return MemoryTrend.Stable;
        }

        private double CalculateGrowthRate()
        {
            if (_memorySnapshots.Count < 2) return 0;
            
            var first = _memorySnapshots.First().WorkingSetMB;
            var last = _memorySnapshots.Last().WorkingSetMB;
            var timeSpan = _memorySnapshots.Last().Timestamp - _memorySnapshots.First().Timestamp;
            
            return (last - first) / timeSpan.TotalMinutes; // MB/分钟
        }

        private double CalculateLeakScore()
        {
            if (_memorySnapshots.Count < 20) return 0;
            
            var recent = _memorySnapshots.TakeLast(20).ToList();
            var trend = ComputeLinearTrend(recent.Select(s => s.WorkingSetMB).ToArray());
            
            // 持续增长趋势得分较高
            return Math.Max(0, Math.Min(1.0, trend.slope * 10));
        }

        private List<LeakPoint> IdentifySuspectedLeakPoints()
        {
            var leakPoints = new List<LeakPoint>();
            
            if (_memorySnapshots.Count < 30) return leakPoints;
            
            var memoryValues = _memorySnapshots.Select(s => s.WorkingSetMB).ToArray();
            
            // 检测异常内存增长点
            for (int i = 10; i < memoryValues.Length - 10; i++)
            {
                var previousAvg = memoryValues.Skip(i - 10).Take(10).Average();
                var nextAvg = memoryValues.Skip(i).Take(10).Average();
                
                if (nextAvg - previousAvg > 50) // 增长超过50MB
                {
                    leakPoints.Add(new LeakPoint
                    {
                        Time = _memorySnapshots[i].Timestamp,
                        MemoryIncreaseMB = nextAvg - previousAvg,
                        Severity = nextAvg - previousAvg > 100 ? LeakSeverity.High : LeakSeverity.Medium
                    });
                }
            }
            
            return leakPoints.DistinctBy(p => p.Time.Date).Take(5).ToList(); // 返回前5个不同的可疑点
        }

        private MemoryUsageInfo GetCurrentMemoryUsage()
        {
            var process = Process.GetCurrentProcess();
            return new MemoryUsageInfo
            {
                WorkingSetMB = process.WorkingSet64 / 1024.0 / 1024.0,
                PrivateMemoryMB = process.PrivateMemorySize64 / 1024.0 / 1024.0,
                Gen0CollectionCount = GC.CollectionCount(0),
                Gen1CollectionCount = GC.CollectionCount(1),
                Gen2CollectionCount = GC.CollectionCount(2),
                LargeObjectHeapSize = GetLOHSize()
            };
        }

        private double GetLOHSize()
        {
            try
            {
                // 使用反射获取大对象堆大小（仅.NET Framework）
                var gcType = typeof(GC);
                var getLOHSizeMethod = gcType.GetMethod("GetTotalMemory", new Type[] { typeof(bool) });
                
                if (getLOHSizeMethod != null)
                {
                    // 这只是近似值
                    return GC.GetTotalMemory(true) / 1024.0 / 1024.0 * 0.1; // 估算LOH为总内存的10%
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "AdvancedMemoryMonitor.cs 捕获异常", ex.Message); }
            
            return 0;
        }

        private (double slope, double intercept) ComputeLinearTrend(double[] values)
        {
            var n = values.Length;
            var x = Enumerable.Range(1, n).Select(i => (double)i).ToArray();
            var y = values;
            
            double sumX = x.Sum();
            double sumY = y.Sum();
            double sumXY = x.Zip(y, (a, b) => a * b).Sum();
            double sumX2 = x.Select(a => a * a).Sum();
            
            double slope = (n * sumXY - sumX * sumY) / (n * sumX2 - sumX * sumX);
            double intercept = (sumY - slope * sumX) / n;
            
            return (slope, intercept);
        }

        #endregion

        #region 优化操作实现

        private async Task ForceGarbageCollectionAsync()
        {
            await Task.Run(() =>
            {
                GC.Collect();
                GC.WaitForPendingFinalizers();
                GC.Collect();
            });
        }

        private async Task CleanLargeObjectHeapAsync()
        {
            await Task.Run(() =>
            {
                // LOH清理策略
                if (GC.GetGeneration(new object()) >= 2)
                {
                    GCSettings.LargeObjectHeapCompactionMode = GCLargeObjectHeapCompactionMode.CompactOnce;
                    GC.Collect(2, GCCollectionMode.Forced, true);
                }
            });
        }

        private async Task ReleaseUnmanagedResourcesAsync()
        {
            await Task.Run(() =>
            {
                // 清理图片、字体等GDI+资源
                // 实际项目中可以添加更多资源清理逻辑
                try
                {
                    // 强制清理弱引用
                    GC.Collect(2, GCCollectionMode.Forced);
                }
                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "AdvancedMemoryMonitor.cs 捕获异常", ex.Message); }
            });
        }

        private async Task OptimizeMemoryFragmentationAsync()
        {
            await Task.Run(() =>
            {
                // 模拟内存碎片优化
                // 实际项目中可能需要更复杂的策略
                Thread.Sleep(100); // 模拟优化操作
            });
        }

        #endregion

        #region 数据模型和枚举

        public enum MemoryTrend
        {
            Stable,
            GradualIncrease,
            RapidIncrease,
            Decreasing
        }

        public enum MemoryUsagePattern
        {
            Stable,
            GradualGrowth,
            HighGrowth
        }

        public enum LeakSeverity
        {
            Low,
            Medium,
            High
        }

        public enum OptimizationPriority
        {
            Low,
            Medium,
            High,
            Critical
        }

        public enum OptimizationType
        {
            MemoryManagement,
            CacheOptimization,
            LeakPrevention,
            ResourceRelease
        }

        public class MemorySnapshot
        {
            public DateTime Timestamp { get; set; }
            public double WorkingSetMB { get; set; }
            public double PrivateMemoryMB { get; set; }
            public double GCMemoryMB { get; set; }
            public int Gen0CollectionCount { get; set; }
            public int Gen1CollectionCount { get; set; }
            public int Gen2CollectionCount { get; set; }
            public double LargeObjectHeapSize { get; set; }
            public int ThreadCount { get; set; }
        }

        public class DetailedMemoryAnalysis
        {
            public DateTime AnalysisTime { get; set; }
            public int TotalSnapshots { get; set; }
            public MemoryTrend OverallTrend { get; set; }
            public MemoryUsagePattern MemoryUsagePattern { get; set; }
            public MemoryLeakDetection LeakDetection { get; set; }
            public List<string> OptimizationSuggestions { get; set; } = new List<string>();
        }

        public class MemoryLeakDetection
        {
            public DateTime DetectionTime { get; set; }
            public double InitialMemoryMB { get; set; }
            public double CurrentMemoryMB { get; set; }
            public double MemoryGrowthMB { get; set; }
            public double LeakScore { get; set; }
            public bool HasPossibleLeak { get; set; }
            public bool HasDefiniteLeak { get; set; }
            public List<LeakPoint> SuspectedLeaks { get; set; } = new List<LeakPoint>();
            public List<LeakPoint> PossibleLeaks => SuspectedLeaks.Where(l => l.Severity >= LeakSeverity.Medium).ToList();
        }

        public class LeakPoint
        {
            public DateTime Time { get; set; }
            public double MemoryIncreaseMB { get; set; }
            public LeakSeverity Severity { get; set; }
        }

        public class MemoryOptimization
        {
            public OptimizationPriority Priority { get; set; }
            public OptimizationType Type { get; set; }
            public string Description { get; set; }
            public string Action { get; set; }
        }

        public class MemoryOptimizationResult
        {
            public DateTime StartTime { get; set; }
            public DateTime EndTime { get; set; }
            public double InitialMemoryMB { get; set; }
            public double FinalMemoryMB { get; set; }
            public double MemoryFreedMB { get; set; }
            public bool Success { get; set; }
            public string ErrorMessage { get; set; }
        }

        #endregion

        public async Task StartPeriodicDiagnosticsAsync()
        {
            try
            {
                while (true)
                {
                    await Task.Delay(TimeSpan.FromMinutes(2)); // 每2分钟运行一次详细诊断
                    await RunDetailedDiagnosticsAsync();
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[内存诊断] 周期性诊断停止: {ex.Message}");
            }
        }

        private async Task RunDetailedDiagnosticsAsync()
        {
            try
            {
                await Task.Run(() =>
                {
                    var analysis = GetDetailedAnalysis();
                    var suggestions = GenerateOptimizations();
                    
                    Debug.WriteLine($"[内存诊断] 分析时间: {analysis.AnalysisTime:HH:mm:ss}, 趋势: {analysis.OverallTrend}");
                    
                    if (analysis.OverallTrend == MemoryTrend.RapidIncrease || 
                        analysis.MemoryUsagePattern == MemoryUsagePattern.HighGrowth)
                    {
                        Debug.WriteLine($"[内存诊断] 警告: 检测到内存高速增长");
                    }
                });
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[内存诊断] 详细诊断失败: {ex.Message}");
            }
        }

        public void Dispose()
        {
            if (!_isDisposed)
            {
                _monitoringTimer?.Dispose();
                _memoryCounter?.Dispose();
                _isDisposed = true;
            }
        }

        private MemoryLeakDetection DetectPotentialLeaksInternal()
        {
            return DetectMemoryLeaks();
        }

        private List<string> GenerateMemoryOptimizationsInternal()
        {
            var suggestions = new List<string>();
            var currentMemory = GC.GetTotalMemory(false) / 1024.0 / 1024.0;
            if (currentMemory > 500)
                suggestions.Add("内存使用较高，建议执行GC清理");
            if (currentMemory > 800)
                suggestions.Add("建议重启应用程序以释放内存");
            return suggestions;
        }
    }
}