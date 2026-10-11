using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Threading;
using FireAntivirus.Engine;
using FireAntivirus.Engine.Intelligence;
using FireAntivirus.Engine.Detection;

namespace FireAntivirus.Engine.Coordinator
{
    /// <summary>
    /// 多引擎协调器 - 智能协调多个检测引擎的协作和结果融合
    /// </summary>
    public class MultiEngineCoordinator
    {
        private readonly List<IDetectionEngine> _engines;
        private readonly DetectionResultAggregator _aggregator;
        private readonly EnginePerformanceMonitor _performanceMonitor;
        private readonly ThreatIntelligenceService _threatIntelligence;

        public MultiEngineCoordinator()
        {
            _engines = new List<IDetectionEngine>();
            _aggregator = new DetectionResultAggregator();
            _performanceMonitor = new EnginePerformanceMonitor();
            _threatIntelligence = new ThreatIntelligenceService();

            InitializeEngines();
        }

        /// <summary>
        /// 初始化所有检测引擎
        /// </summary>
        private void InitializeEngines()
        {
            // 注册所有可用的检测引擎
            _engines.AddRange(new IDetectionEngine[]
            {
                new SignatureEngine(),
                new HeuristicEngine(),
                new BehaviorEngine(),
                new YaraEngine(),
                new MachineLearningEngine(),
                new CloudAnalysisEngine()
            });

            // 为每个引擎设置权重和配置
            foreach (var engine in _engines)
            {
                var config = GetEngineConfiguration(engine.GetType());
                engine.Initialize(config);
                _performanceMonitor.RegisterEngine(engine);
            }
        }

        /// <summary>
        /// 综合分析文件（多引擎并行检测）
        /// </summary>
        public async Task<CoordinatedScanResult> AnalyzeFileAsync(string filePath, ScanStrategy strategy = ScanStrategy.Balanced)
        {
            var scanContext = new ScanContext
            {
                FilePath = filePath,
                Strategy = strategy,
                StartTime = DateTime.Now
            };

            try
            {
                // 1. 执行并行引擎扫描
                var engineTasks = ExecuteParallelEngineScans(scanContext);
                var engineResults = await Task.WhenAll(engineTasks);

                // 2. 合并和评估结果
                var aggregatedResult = _aggregator.AggregateResults(engineResults.ToList(), strategy);

                // 3. 威胁情报关联
                await EnhanceWithThreatIntelligence(aggregatedResult, filePath);

                // 4. 性能分析和反馈
                UpdateEnginePerformance(engineResults.ToList());

                scanContext.EndTime = DateTime.Now;
                scanContext.Success = true;

                return new CoordinatedScanResult
                {
                    Context = scanContext,
                    AggregatedResult = aggregatedResult,
                    EngineResults = engineResults.ToList(),
                    FinalVerdict = DetermineFinalVerdict(aggregatedResult)
                };
            }
            catch (Exception ex)
            {
                scanContext.Error = ex.Message;
                scanContext.Success = false;
                
                return new CoordinatedScanResult
                {
                    Context = scanContext,
                    FinalVerdict = ScanVerdict.Error
                };
            }
        }

        /// <summary>
        /// 执行并行引擎扫描
        /// </summary>
        private IEnumerable<Task<EngineScanResult>> ExecuteParallelEngineScans(ScanContext context)
        {
            var parallelOptions = GetParallelOptions(context.Strategy);
            var selectedEngines = SelectEnginesForScan(context.Strategy);

            // 为每个选定的引擎创建扫描任务
            return selectedEngines.Select(engine => Task.Run(async () =>
            {
                var result = await engine.ScanFileAsync(context.FilePath);
                result.EngineName = engine.Name;
                result.ScanDuration = DateTime.Now - context.StartTime;
                
                return result;
            }, parallelOptions.CancellationToken));
        }

        /// <summary>
        /// 根据扫描策略获取并行选项
        /// </summary>
        private ParallelOptions GetParallelOptions(ScanStrategy strategy)
        {
            var cts = new CancellationTokenSource(TimeSpan.FromMinutes(5)); // 5分钟超时
            
            return strategy switch
            {
                ScanStrategy.Fast => new ParallelOptions
                {
                    MaxDegreeOfParallelism = Environment.ProcessorCount / 2,
                    CancellationToken = cts.Token
                },
                ScanStrategy.Thorough => new ParallelOptions
                {
                    MaxDegreeOfParallelism = Environment.ProcessorCount,
                    CancellationToken = cts.Token
                },
                _ => new ParallelOptions
                {
                    MaxDegreeOfParallelism = Math.Max(1, Environment.ProcessorCount - 1),
                    CancellationToken = cts.Token
                }
            };
        }

        /// <summary>
        /// 根据策略选择引擎
        /// </summary>
        private IEnumerable<IDetectionEngine> SelectEnginesForScan(ScanStrategy strategy)
        {
            var performanceData = _performanceMonitor.GetEngineStats();
            
            return strategy switch
            {
                ScanStrategy.Fast => _engines
                    .Where(e => performanceData[e.Name].PerformanceRating >= 0.8)
                    .OrderByDescending(e => performanceData[e.Name].DetectionRate)
                    .Take(3),
                    
                ScanStrategy.Balanced => _engines
                    .Where(e => performanceData[e.Name].PerformanceRating >= 0.6)
                    .OrderByDescending(e => performanceData[e.Name].WeightedScore)
                    .Take(4),
                    
                ScanStrategy.Thorough => _engines
                    .OrderByDescending(e => performanceData[e.Name].DetectionRate)
                    .Take(6),
                    
                _ => _engines.Take(4)
            };
        }

        /// <summary>
        /// 用威胁情报增强检测结果
        /// </summary>
        private async Task EnhanceWithThreatIntelligence(AggregatedResult result, string filePath)
        {
            var intelResult = await _threatIntelligence.AnalyzeFileAsync(filePath);
            
            if (intelResult.ThreatLevel > ThreatLevel.Medium)
            {
                result.PriorityLevel = ThreatPriority.Critical;
                result.Confidence = Math.Max(result.Confidence, 0.9);
                result.ThreatIntelligenceData = intelResult;
            }
        }

        /// <summary>
        /// 更新引擎性能数据
        /// </summary>
        private void UpdateEnginePerformance(List<EngineScanResult> results)
        {
            foreach (var result in results)
            {
                _performanceMonitor.RecordScanResult(result);
            }
        }

        /// <summary>
        /// 确定最终判定
        /// </summary>
        private ScanVerdict DetermineFinalVerdict(AggregatedResult result)
        {
            if (result.OverallThreatScore >= 0.8) return ScanVerdict.Malicious;
            if (result.OverallThreatScore >= 0.6) return ScanVerdict.Suspicious;
            if (result.OverallThreatScore >= 0.3) return ScanVerdict.PotentiallyUnsafe;
            return ScanVerdict.Clean;
        }

        /// <summary>
        /// 获取引擎配置
        /// </summary>
        private EngineConfiguration GetEngineConfiguration(Type engineType)
        {
            return engineType.Name switch
            {
                nameof(SignatureEngine) => new EngineConfiguration
                {
                    Weight = 0.25,
                    TimeoutSeconds = 30,
                    EnableRealTimeUpdates = true
                },
                nameof(HeuristicEngine) => new EngineConfiguration
                {
                    Weight = 0.20,
                    TimeoutSeconds = 45,
                    Sensitivity = 0.7
                },
                nameof(BehaviorEngine) => new EngineConfiguration
                {
                    Weight = 0.15,
                    TimeoutSeconds = 60,
                    EnableDynamicAnalysis = true
                },
                nameof(YaraEngine) => new EngineConfiguration
                {
                    Weight = 0.18,
                    TimeoutSeconds = 40,
                    UpdateFrequency = TimeSpan.FromHours(6)
                },
                nameof(MachineLearningEngine) => new EngineConfiguration
                {
                    Weight = 0.12,
                    TimeoutSeconds = 20,
                    ModelVersion = "v2.1.0"
                },
                nameof(CloudAnalysisEngine) => new EngineConfiguration
                {
                    Weight = 0.10,
                    TimeoutSeconds = 15,
                    RequireInternet = true
                },
                _ => new EngineConfiguration { Weight = 0.1, TimeoutSeconds = 30 }
            };
        }

        /// <summary>
        /// 实时监控和自适应调整
        /// </summary>
        public async Task StartAdaptiveMonitoringAsync()
        {
            while (true)
            {
                try
                {
                    await Task.Delay(TimeSpan.FromMinutes(5));
                    
                    // 分析引擎性能并调整权重
                    var stats = _performanceMonitor.GetEngineStats();
                    AdjustEngineWeights(stats);
                    
                    // 清理过时的性能数据
                    _performanceMonitor.CleanupOldData();
                }
                catch (Exception ex)
                {
                    // 记录错误但继续运行
                    Console.WriteLine($"自适应监控错误: {ex.Message}");
                }
            }
        }

        /// <summary>
        /// 根据性能数据调整引擎权重
        /// </summary>
        private void AdjustEngineWeights(Dictionary<string, EnginePerformanceStats> stats)
        {
            var totalWeight = _engines.Sum(e => 
                stats.ContainsKey(e.Name) ? stats[e.Name].WeightedScore : 0.1);
            
            if (totalWeight == 0) return;

            foreach (var engine in _engines)
            {
                if (stats.TryGetValue(engine.Name, out var engineStats))
                {
                    var newWeight = (engineStats.WeightedScore / totalWeight) * _engines.Sum(e => e.Configuration.Weight);
                    engine.Configuration.Weight = Math.Max(0.05, Math.Min(0.3, newWeight));
                }
            }
        }

        /// <summary>
        /// 获取协调器状态报告
        /// </summary>
        public CoordinatorStatusReport GetStatusReport()
        {
            var stats = _performanceMonitor.GetEngineStats();
            
            return new CoordinatorStatusReport
            {
                ActiveEngines = _engines.Count,
                TotalScansCompleted = stats.Values.Sum(s => s.TotalScans),
                AverageScanTime = stats.Values.Average(s => s.AverageScanTimeMs),
                OverallDetectionRate = stats.Values.Average(s => s.DetectionRate),
                EnginesStatus = stats.ToDictionary(
                    s => s.Key, 
                    s => new EngineStatus
                    {
                        Weight = s.Value.CurrentWeight,
                        PerformanceRating = s.Value.PerformanceRating,
                        LastScanTime = s.Value.LastScanTime
                    })
            };
        }
    }

    // 支持的类型定义
    public enum ScanStrategy
    {
        Fast,       // 快速扫描
        Balanced,   // 平衡扫描
        Thorough    // 深度扫描
    }

    public enum ScanVerdict
    {
        Clean,
        PotentiallyUnsafe,
        Suspicious,
        Malicious,
        Error
    }

    public enum ThreatPriority
    {
        Low,
        Medium,
        High,
        Critical
    }

    public class CoordinatedScanResult
    {
        public ScanContext Context { get; set; }
        public AggregatedResult AggregatedResult { get; set; }
        public List<EngineScanResult> EngineResults { get; set; }
        public ScanVerdict FinalVerdict { get; set; }
    }

    public class ScanContext
    {
        public string FilePath { get; set; }
        public ScanStrategy Strategy { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public bool Success { get; set; }
        public string Error { get; set; }
    }

    public class EngineConfiguration
    {
        public double Weight { get; set; }
        public int TimeoutSeconds { get; set; }
        public double Sensitivity { get; set; }
        public bool EnableRealTimeUpdates { get; set; }
        public bool EnableDynamicAnalysis { get; set; }
        public TimeSpan UpdateFrequency { get; set; }
        public string ModelVersion { get; set; }
        public bool RequireInternet { get; set; }
    }

    public class CoordinatorStatusReport
    {
        public int ActiveEngines { get; set; }
        public long TotalScansCompleted { get; set; }
        public double AverageScanTime { get; set; }
        public double OverallDetectionRate { get; set; }
        public Dictionary<string, EngineStatus> EnginesStatus { get; set; }
    }

    public class EngineStatus
    {
        public double Weight { get; set; }
        public double PerformanceRating { get; set; }
        public DateTime LastScanTime { get; set; }
    }

    // 已定义的类型（简化实现）
    public interface IDetectionEngine
    {
        string Name { get; }
        EngineConfiguration Configuration { get; }
        Task<bool> Initialize(EngineConfiguration config);
        Task<EngineScanResult> ScanFileAsync(string filePath);
    }

    public class EngineScanResult
    {
        public string EngineName { get; set; }
        public ScanVerdict Verdict { get; set; }
        public double Confidence { get; set; }
        public TimeSpan ScanDuration { get; set; }
        public List<DetectionDetail> DetectionDetails { get; set; }
        public string Error { get; set; }
    }

    public class DetectionDetail
    {
        public string RuleId { get; set; }
        public string Description { get; set; }
        public ThreatLevel Severity { get; set; }
    }

        public class AggregatedResult
        {
            public double OverallThreatScore { get; set; }
            public double Confidence { get; set; }
            public ThreatPriority PriorityLevel { get; set; }
            public List<ThreatIndicator> ThreatIndicators { get; set; }
            public object ThreatIntelligenceData { get; set; } // 改为object类型以容纳不同类型的威胁智能数据
        }

    public class ThreatIndicator
    {
        public string Type { get; set; }
        public string Description { get; set; }
        public double Score { get; set; }
        public ThreatLevel Severity { get; set; }
    }

    // 引擎实现类（简化）
    public class SignatureEngine : IDetectionEngine
    {
        public string Name => "SignatureEngine";
        public EngineConfiguration Configuration { get; private set; }
        
        public Task<bool> Initialize(EngineConfiguration config)
        {
            Configuration = config;
            return Task.FromResult(true);
        }
        
        public Task<EngineScanResult> ScanFileAsync(string filePath)
        {
            return Task.FromResult(new EngineScanResult
            {
                Verdict = ScanVerdict.Clean,
                Confidence = 0.95
            });
        }
    }

    public class HeuristicEngine : IDetectionEngine
    {
        public string Name => "HeuristicEngine";
        public EngineConfiguration Configuration { get; private set; }
        
        public Task<bool> Initialize(EngineConfiguration config)
        {
            Configuration = config;
            return Task.FromResult(true);
        }
        
        public Task<EngineScanResult> ScanFileAsync(string filePath)
        {
            return Task.FromResult(new EngineScanResult
            {
                Verdict = ScanVerdict.Clean,
                Confidence = 0.85
            });
        }
    }

    public class BehaviorEngine : IDetectionEngine
    {
        public string Name => "BehaviorEngine";
        public EngineConfiguration Configuration { get; private set; }
        
        public Task<bool> Initialize(EngineConfiguration config)
        {
            Configuration = config;
            return Task.FromResult(true);
        }
        
        public Task<EngineScanResult> ScanFileAsync(string filePath)
        {
            return Task.FromResult(new EngineScanResult
            {
                Verdict = ScanVerdict.Clean,
                Confidence = 0.80
            });
        }
    }

    public class YaraEngine : IDetectionEngine
    {
        public string Name => "YaraEngine";
        public EngineConfiguration Configuration { get; private set; }
        
        public Task<bool> Initialize(EngineConfiguration config)
        {
            Configuration = config;
            return Task.FromResult(true);
        }
        
        public Task<EngineScanResult> ScanFileAsync(string filePath)
        {
            return Task.FromResult(new EngineScanResult
            {
                Verdict = ScanVerdict.Clean,
                Confidence = 0.90
            });
        }
    }

    public class MachineLearningEngine : IDetectionEngine
    {
        public string Name => "MachineLearningEngine";
        public EngineConfiguration Configuration { get; private set; }
        
        public Task<bool> Initialize(EngineConfiguration config)
        {
            Configuration = config;
            return Task.FromResult(true);
        }
        
        public Task<EngineScanResult> ScanFileAsync(string filePath)
        {
            return Task.FromResult(new EngineScanResult
            {
                Verdict = ScanVerdict.Clean,
                Confidence = 0.75
            });
        }
    }

    public class CloudAnalysisEngine : IDetectionEngine
    {
        public string Name => "CloudAnalysisEngine";
        public EngineConfiguration Configuration { get; private set; }
        
        public Task<bool> Initialize(EngineConfiguration config)
        {
            Configuration = config;
            return Task.FromResult(true);
        }
        
        public Task<EngineScanResult> ScanFileAsync(string filePath)
        {
            return Task.FromResult(new EngineScanResult
            {
                Verdict = ScanVerdict.Clean,
                Confidence = 0.88
            });
        }
    }

    // 支持类实现
    public class DetectionResultAggregator
    {
        /// <summary>
        /// 真实多阶段评分聚合：按照权重融合所有引擎信号，计算最终总分。
        /// 规则：总分 >= 60% （0.60），或已经检测到破坏性动作（加密/注入/删除影子拷贝），触发动作。
        /// </summary>
        public AggregatedResult AggregateResults(List<EngineScanResult> results, ScanStrategy strategy)
        {
            double totalScore = 0.0;
            double totalWeight = 0.0;
            double maxConfidence = 0.0;
            bool hasDestructiveAction = false;
            var indicators = new List<ThreatIndicator>();
            ThreatLevel maxSeverity = ThreatLevel.Safe;

            foreach (var engineResult in results)
            {
                if (engineResult.Verdict == ScanVerdict.Error)
                    continue;

                double weight = GetVerdictWeight(engineResult.Verdict);
                double score = (double)engineResult.Verdict / (double)ScanVerdict.Malicious;
                totalScore += engineResult.Confidence * weight * score;
                totalWeight += weight;

                if (engineResult.Confidence > maxConfidence)
                    maxConfidence = engineResult.Confidence;

                // 检查破坏性动作（即使总分不够也触发）
                if (engineResult.DetectionDetails != null)
                {
                    foreach (var detail in engineResult.DetectionDetails)
                    {
                        indicators.Add(new ThreatIndicator
                        {
                            Type = detail.RuleId,
                            Description = detail.Description,
                            Score = detail.Severity switch
                            {
                                ThreatLevel.Critical => 1.0,
                                ThreatLevel.High => 0.8,
                                ThreatLevel.Medium => 0.5,
                                _ => 0.2
                            },
                            Severity = detail.Severity
                        });

                        // 破坏性动作检测 —— 只要出现一个，直接触发动作
                        if (IsDestructiveSignal(detail.Description))
                            hasDestructiveAction = true;

                        if ((int)detail.Severity > (int)maxSeverity)
                            maxSeverity = detail.Severity;
                    }
                }
            }

            double overall = totalWeight > 0 ? totalScore / totalWeight : 0;

            // 破坏性动作强制拉高总分到触发阈值以上
            if (hasDestructiveAction && overall < 0.6)
                overall = Math.Max(0.62, overall + 0.25);

            return new AggregatedResult
            {
                OverallThreatScore = overall,
                Confidence = maxConfidence,
                PriorityLevel = overall >= 0.8 ? ThreatPriority.Critical
                                 : overall >= 0.6 ? ThreatPriority.High
                                 : overall >= 0.3 ? ThreatPriority.Medium
                                 : ThreatPriority.Low,
                ThreatIndicators = indicators
            };
        }

        private double GetVerdictWeight(ScanVerdict verdict)
            => verdict switch
            {
                ScanVerdict.Malicious => 1.0,
                ScanVerdict.Suspicious => 0.6,
                ScanVerdict.PotentiallyUnsafe => 0.3,
                _ => 0.0
            };

        private bool IsDestructiveSignal(string description)
        {
            if (string.IsNullOrEmpty(description)) return false;
            var lower = description.ToLowerInvariant();
            return lower.Contains("encrypt") || lower.Contains("crypt")
                || lower.Contains("delete shadow") || lower.Contains("vssadmin")
                || lower.Contains("inject") || lower.Contains("remote thread")
                || lower.Contains("hollow") || lower.Contains("injection");
        }
    }

    public class EnginePerformanceMonitor
    {
        private readonly Dictionary<string, EnginePerformanceStats> _performanceStats = new Dictionary<string, EnginePerformanceStats>();

        public void RegisterEngine(IDetectionEngine engine)
        {
            _performanceStats[engine.Name] = new EnginePerformanceStats();
        }

        public void RecordScanResult(EngineScanResult result)
        {
            if (_performanceStats.ContainsKey(result.EngineName))
            {
                var stats = _performanceStats[result.EngineName];
                stats.TotalScans++;
                stats.LastScanTime = DateTime.Now;
                
                if (result.Verdict != ScanVerdict.Error)
                {
                    stats.SuccessfulScans++;
                }
            }
        }

        public Dictionary<string, EnginePerformanceStats> GetEngineStats()
        {
            return _performanceStats.ToDictionary(p => p.Key, p => p.Value);
        }

        public void CleanupOldData()
        {
            // 清理一周前的数据
            var cutoffDate = DateTime.Now.AddDays(-7);
            
            foreach (var stats in _performanceStats.Values)
            {
                if (stats.LastScanTime < cutoffDate)
                {
                    // 重置统计数据
                    stats.TotalScans = 0;
                    stats.SuccessfulScans = 0;
                }
            }
        }
    }

    public class EnginePerformanceStats
    {
        public long TotalScans { get; set; }
        public long SuccessfulScans { get; set; }
        public double DetectionRate => TotalScans > 0 ? (double)SuccessfulScans / TotalScans : 0;
        public double AverageScanTimeMs { get; set; }
        public double PerformanceRating => Math.Min(DetectionRate * 0.8 + (1.0 - AverageScanTimeMs / 60000.0) * 0.2, 1.0);
        public double WeightedScore => DetectionRate * 0.6 + PerformanceRating * 0.4;
        public double CurrentWeight { get; set; } = 0.1;
        public DateTime LastScanTime { get; set; } = DateTime.Now;
    }
}