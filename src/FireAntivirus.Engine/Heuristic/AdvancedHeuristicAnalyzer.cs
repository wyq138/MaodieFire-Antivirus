using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace FireAntivirus.Engine.Heuristic
{
    /// <summary>
    /// 高级启发式分析器 - 基于行为特征和人工智能的智能检测
    /// </summary>
    public class AdvancedHeuristicAnalyzer
    {
        private readonly HeuristicRuleEngine _ruleEngine;
        private readonly BehaviorAnalyzer _behaviorAnalyzer;
        private readonly MachineLearningModel _mlModel;
        private readonly ThreatIntelligenceService _threatIntelligence;

        public AdvancedHeuristicAnalyzer()
        {
            _ruleEngine = new HeuristicRuleEngine();
            _behaviorAnalyzer = new BehaviorAnalyzer();
            _mlModel = new MachineLearningModel();
            _threatIntelligence = new ThreatIntelligenceService();
        }

        /// <summary>
        /// 综合分析文件威胁
        /// </summary>
        public async Task<HeuristicAnalysisResult> AnalyzeFileAsync(string filePath)
        {
            var result = new HeuristicAnalysisResult
            {
                FilePath = filePath,
                AnalysisStartTime = DateTime.Now
            };

            try
            {
                if (!File.Exists(filePath))
                {
                    result.Error = "文件不存在";
                    return result;
                }

                // 1. 静态特征分析
                var staticFeatures = await PerformStaticAnalysisAsync(filePath);
                result.StaticFeatures = staticFeatures;

                // 2. 行为规则分析
                var behaviorScore = await _behaviorAnalyzer.AnalyzeBehaviorAsync(filePath);
                result.BehaviorScore = behaviorScore;

                // 3. 启发式规则匹配
                var ruleMatches = await _ruleEngine.AnalyzeWithRulesAsync(filePath, staticFeatures);
                result.RuleMatches = ruleMatches;

                // 4. 机器学习模型分析
                var mlPrediction = await _mlModel.PredictThreatAsync(staticFeatures, behaviorScore);
                result.MachineLearningScore = mlPrediction;

                // 5. 威胁情报关联
                var intelData = await _threatIntelligence.CheckFileAsync(filePath);
                result.ThreatIntelligence = intelData;

                // 计算综合威胁评分
                CalculateFinalThreatScore(result);

                result.AnalysisEndTime = DateTime.Now;
                result.Success = true;
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
                result.Success = false;
            }

            return result;
        }

        /// <summary>
        /// 执行静态特征分析
        /// </summary>
        private async Task<StaticFeatures> PerformStaticAnalysisAsync(string filePath)
        {
            var features = new StaticFeatures();
            
            try
            {
                var fileInfo = new FileInfo(filePath);
                var fileContent = await File.ReadAllBytesAsync(filePath);

                features.FileSize = fileInfo.Length;
                features.FileExtension = Path.GetExtension(filePath).ToLower();
                features.IsExecutable = IsExecutableFile(filePath);
                features.Entropy = CalculateEntropy(fileContent);
                features.HasDigitalSignature = CheckDigitalSignature(filePath);
                features.ContainsSuspiciousStrings = CheckSuspiciousStrings(fileContent);
                features.SectionCount = CountPESections(fileContent);
                features.ImportCount = CountImports(fileContent);
                features.HasPackedCode = DetectPacking(fileContent);
                features.SuspiciousApiCount = CountSuspiciousApis(fileContent);

                return features;
            }
            catch (Exception ex)
            {
                features.AnalysisError = ex.Message;
                return features;
            }
        }

        /// <summary>
        /// 计算文件熵值
        /// </summary>
        private double CalculateEntropy(byte[] data)
        {
            if (data.Length == 0) return 0.0;

            var frequency = new int[256];
            foreach (byte b in data)
            {
                frequency[b]++;
            }

            double entropy = 0.0;
            for (int i = 0; i < 256; i++)
            {
                if (frequency[i] > 0)
                {
                    double probability = (double)frequency[i] / data.Length;
                    entropy -= probability * Math.Log(probability, 2);
                }
            }

            return entropy;
        }

        /// <summary>
        /// 检查是否为可执行文件
        /// </summary>
        private bool IsExecutableFile(string filePath)
        {
            var executableExtensions = new HashSet<string>
            {
                ".exe", ".dll", ".com", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js"
            };
            
            return executableExtensions.Contains(Path.GetExtension(filePath).ToLower());
        }

        /// <summary>
        /// 检查数字签名
        /// </summary>
        private bool CheckDigitalSignature(string filePath)
        {
            try
            {
                // 简化的数字签名检查
                // 实际实现需要使用Windows API验证签名
                return Path.GetExtension(filePath).ToLower() == ".exe";
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// 检查可疑字符串
        /// </summary>
        private bool CheckSuspiciousStrings(byte[] data)
        {
            var suspiciousPatterns = new[]
            {
                "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory",
                "RegCreateKeyEx", "RegSetValueEx", "InternetOpen",
                "socket", "connect", "send", "recv",
                "malware", "trojan", "virus", "ransom",
                "keylogger", "backdoor", "rootkit", "botnet"
            };

            string text = System.Text.Encoding.UTF8.GetString(data);
            return suspiciousPatterns.Any(pattern => 
                text.IndexOf(pattern, StringComparison.OrdinalIgnoreCase) >= 0);
        }

        /// <summary>
        /// 计算PE节区数量
        /// </summary>
        private int CountPESections(byte[] data)
        {
            // 简化的PE节区计数
            try
            {
                if (data.Length < 64 || data[0] != 0x4D || data[1] != 0x5A) // MZ头
                    return 0;

                // 读取PE头中的节区数量
                int peHeaderOffset = BitConverter.ToInt32(data, 0x3C);
                if (peHeaderOffset + 6 >= data.Length)
                    return 0;

                return BitConverter.ToUInt16(data, peHeaderOffset + 6);
            }
            catch
            {
                return 0;
            }
        }

        /// <summary>
        /// 计算导入函数数量
        /// </summary>
        private int CountImports(byte[] data)
        {
            // 简化的导入函数计数
            try
            {
                string text = System.Text.Encoding.UTF8.GetString(data);
                
                var importKeywords = new[]
                {
                    "kernel32.dll", "user32.dll", "advapi32.dll", "ws2_32.dll"
                };

                return importKeywords.Count(keyword => 
                    text.IndexOf(keyword, StringComparison.OrdinalIgnoreCase) >= 0);
            }
            catch
            {
                return 0;
            }
        }

        /// <summary>
        /// 检测代码加壳
        /// </summary>
        private bool DetectPacking(byte[] data)
        {
            // 基于熵值的简单加壳检测
            if (data.Length < 100) return false;
            
            double entropy = CalculateEntropy(data);
            return entropy > 7.0; // 高熵值可能表示加壳
        }

        /// <summary>
        /// 计算可疑API数量
        /// </summary>
        private int CountSuspiciousApis(byte[] data)
        {
            var suspiciousApis = new[]
            {
                "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory",
                "SetWindowsHookEx", "GetAsyncKeyState", "RegCreateKeyEx",
                "InternetOpen", "socket", "connect"
            };

            string text = System.Text.Encoding.UTF8.GetString(data);
            return suspiciousApis.Count(api => 
                text.IndexOf(api, StringComparison.OrdinalIgnoreCase) >= 0);
        }

        /// <summary>
        /// 计算综合威胁评分
        /// </summary>
        private void CalculateFinalThreatScore(HeuristicAnalysisResult result)
        {
            double totalScore = 0.0;
            int factorCount = 0;

            // 静态特征评分
            if (result.StaticFeatures != null)
            {
                totalScore += CalculateStaticFeatureScore(result.StaticFeatures);
                factorCount++;
            }

            // 行为评分
            if (result.BehaviorScore > 0)
            {
                totalScore += result.BehaviorScore * 0.3;
                factorCount++;
            }

            // 规则匹配评分
            if (result.RuleMatches.Any())
            {
                totalScore += result.RuleMatches.Sum(m => (int)m.Severity) * 0.2;
                factorCount++;
            }

            // 机器学习评分
            if (result.MachineLearningScore > 0)
            {
                totalScore += result.MachineLearningScore * 0.4;
                factorCount++;
            }

            // 威胁情报评分
            if (result.ThreatIntelligence != null && result.ThreatIntelligence.ThreatLevel > 0)
            {
                totalScore += (int)result.ThreatIntelligence.ThreatLevel * 0.1;
                factorCount++;
            }

            // 计算平均分
            if (factorCount > 0)
            {
                result.FinalThreatScore = totalScore / factorCount;
            }
            else
            {
                result.FinalThreatScore = 0;
            }

            // 确定威胁级别
            if (result.FinalThreatScore >= 80) result.ThreatLevel = ThreatLevel.Critical;
            else if (result.FinalThreatScore >= 60) result.ThreatLevel = ThreatLevel.High;
            else if (result.FinalThreatScore >= 40) result.ThreatLevel = ThreatLevel.Medium;
            else if (result.FinalThreatScore >= 20) result.ThreatLevel = ThreatLevel.Low;
            else result.ThreatLevel = ThreatLevel.Safe;

            result.Confidence = Math.Min(result.FinalThreatScore / 100.0, 1.0);
        }

        /// <summary>
        /// 计算静态特征评分
        /// </summary>
        private double CalculateStaticFeatureScore(StaticFeatures features)
        {
            double score = 0.0;

            // 文件大小异常
            if (features.FileSize < 1024 || features.FileSize > 100 * 1024 * 1024)
                score += 10;

            // 高熵值（可能加壳）
            if (features.Entropy > 7.5)
                score += 25;

            // 无数字签名
            if (!features.HasDigitalSignature && features.IsExecutable)
                score += 15;

            // 包含可疑字符串
            if (features.ContainsSuspiciousStrings)
                score += 20;

            // 异常节区数量
            if (features.SectionCount > 10 || features.SectionCount == 0)
                score += 15;

            // 加壳检测
            if (features.HasPackedCode)
                score += 30;

            // 可疑API数量
            if (features.SuspiciousApiCount > 5)
                score += features.SuspiciousApiCount * 3;

            return Math.Min(score, 100.0);
        }

        /// <summary>
        /// 实时进程行为监控
        /// </summary>
        public async Task<ProcessBehaviorAnalysis> MonitorProcessBehaviorAsync(int processId)
        {
            var analysis = new ProcessBehaviorAnalysis
            {
                ProcessId = processId,
                StartTime = DateTime.Now
            };

            try
            {
                // 实现实时进程行为监控
                analysis.SuspiciousActivities = await DetectSuspiciousProcessActivities(processId);
                analysis.ThreatScore = CalculateProcessThreatScore(analysis.SuspiciousActivities);
                analysis.EndTime = DateTime.Now;
            }
            catch (Exception ex)
            {
                analysis.Error = ex.Message;
            }

            return analysis;
        }

        /// <summary>
        /// 检测可疑进程活动
        /// </summary>
        private async Task<List<SuspiciousActivity>> DetectSuspiciousProcessActivities(int processId)
        {
            var activities = new List<SuspiciousActivity>();

            // 简化的可疑活动检测
            // 实际实现需要深度系统监控
            
            await Task.CompletedTask;
            
            // 示例检测结果
            activities.Add(new SuspiciousActivity
            {
                Type = "PROCESS_INJECTION",
                Description = "检测到可能的进程注入行为",
                Severity = ThreatLevel.High,
                Timestamp = DateTime.Now
            });

            return activities;
        }

        /// <summary>
        /// 计算进程威胁评分
        /// </summary>
        private double CalculateProcessThreatScore(List<SuspiciousActivity> activities)
        {
            if (!activities.Any()) return 0.0;

            double totalScore = activities.Sum(a => (int)a.Severity * 10);
            return Math.Min(totalScore / activities.Count, 100.0);
        }
    }

    // 支持的类型定义
    public class HeuristicAnalysisResult
    {
        public string FilePath { get; set; }
        public DateTime AnalysisStartTime { get; set; }
        public DateTime AnalysisEndTime { get; set; }
        public StaticFeatures StaticFeatures { get; set; }
        public double BehaviorScore { get; set; }
        public List<HeuristicRuleMatch> RuleMatches { get; set; } = new List<HeuristicRuleMatch>();
        public double MachineLearningScore { get; set; }
        public ThreatIntelligenceData ThreatIntelligence { get; set; }
        public double FinalThreatScore { get; set; }
        public ThreatLevel ThreatLevel { get; set; }
        public double Confidence { get; set; }
        public bool Success { get; set; }
        public string Error { get; set; }
    }

    public class StaticFeatures
    {
        public long FileSize { get; set; }
        public string FileExtension { get; set; }
        public bool IsExecutable { get; set; }
        public double Entropy { get; set; }
        public bool HasDigitalSignature { get; set; }
        public bool ContainsSuspiciousStrings { get; set; }
        public int SectionCount { get; set; }
        public int ImportCount { get; set; }
        public bool HasPackedCode { get; set; }
        public int SuspiciousApiCount { get; set; }
        public string AnalysisError { get; set; }
    }

    public class ProcessBehaviorAnalysis
    {
        public int ProcessId { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public List<SuspiciousActivity> SuspiciousActivities { get; set; } = new List<SuspiciousActivity>();
        public double ThreatScore { get; set; }
        public string Error { get; set; }
    }

    public class SuspiciousActivity
    {
        public string Type { get; set; }
        public string Description { get; set; }
        public ThreatLevel Severity { get; set; }
        public DateTime Timestamp { get; set; }
    }

    // 支持类：基于真实静态特征执行规则/行为/模型/情报分析
    public class HeuristicRuleEngine
    {
        public async Task<List<HeuristicRuleMatch>> AnalyzeWithRulesAsync(string filePath, StaticFeatures features)
        {
            await Task.CompletedTask;

            var matches = new List<HeuristicRuleMatch>();
            if (features == null) return matches;

            // 规则 R001：高熵值（加壳/加密内容）
            if (features.Entropy > 7.5)
            {
                matches.Add(new HeuristicRuleMatch
                {
                    RuleId = "R001",
                    Description = $"文件熵值过高 ({features.Entropy:F2}/8.0)，疑似加壳或加密载荷",
                    Severity = ThreatLevel.Medium,
                    Confidence = 0.75
                });
            }

            // 规则 R002：可疑 API 调用密集
            if (features.SuspiciousApiCount >= 5)
            {
                matches.Add(new HeuristicRuleMatch
                {
                    RuleId = "R002",
                    Description = $"检测到 {features.SuspiciousApiCount} 个可疑 API 调用",
                    Severity = ThreatLevel.High,
                    Confidence = 0.8
                });
            }

            // 规则 R003：可执行文件体积异常小（释放器/下载器常见特征）
            if (features.IsExecutable && features.FileSize > 0 && features.FileSize < 20 * 1024)
            {
                matches.Add(new HeuristicRuleMatch
                {
                    RuleId = "R003",
                    Description = "可执行文件体积异常小（<20KB）",
                    Severity = ThreatLevel.Medium,
                    Confidence = 0.6
                });
            }

            // 规则 R004：检测到打包代码节
            if (features.HasPackedCode)
            {
                matches.Add(new HeuristicRuleMatch
                {
                    RuleId = "R004",
                    Description = "检测到打包/加壳代码节",
                    Severity = ThreatLevel.Medium,
                    Confidence = 0.7
                });
            }

            // 规则 R005：导入表极少（运行时动态解析 API 的典型特征）
            if (features.IsExecutable && features.ImportCount <= 3)
            {
                matches.Add(new HeuristicRuleMatch
                {
                    RuleId = "R005",
                    Description = $"导入表项过少 ({features.ImportCount})，疑似运行时动态解析 API",
                    Severity = ThreatLevel.Medium,
                    Confidence = 0.65
                });
            }

            // 规则 R006：包含可疑字符串但无数字签名
            if (features.ContainsSuspiciousStrings && !features.HasDigitalSignature)
            {
                matches.Add(new HeuristicRuleMatch
                {
                    RuleId = "R006",
                    Description = "文件包含可疑字符串且无数字签名",
                    Severity = ThreatLevel.Medium,
                    Confidence = 0.6
                });
            }

            return matches;
        }
    }

    public class BehaviorAnalyzer
    {
        public async Task<double> AnalyzeBehaviorAsync(string filePath)
        {
            await Task.CompletedTask;

            // 基于文件真实属性的静态行为风险评分（0-1）
            double score = 0.0;
            try
            {
                if (!File.Exists(filePath)) return 0.0;

                var fileInfo = new FileInfo(filePath);
                var ext = fileInfo.Extension.ToLowerInvariant();

                // 脚本类型文件具备即时执行能力
                if (ext == ".bat" || ext == ".cmd" || ext == ".ps1" || ext == ".vbs" || ext == ".js")
                    score += 0.4;

                // 位于临时/下载目录的文件
                var path = filePath.ToLowerInvariant();
                if (path.Contains("\\temp\\") || path.Contains("\\tmp\\") ||
                    path.Contains("\\downloads\\") || path.Contains("\\appdata\\local\\temp\\"))
                    score += 0.3;

                // 文件名含双重扩展名伪装（如 invoice.pdf.exe）
                if (Path.GetFileNameWithoutExtension(filePath).Contains('.'))
                    score += 0.3;
            }
            catch
            {
            }

            return Math.Min(score, 1.0);
        }
    }

    public class MachineLearningModel
    {
        public async Task<double> PredictThreatAsync(StaticFeatures features, double behaviorScore)
        {
            await Task.CompletedTask;

            if (features == null) return Math.Min(behaviorScore, 1.0);

            // 线性加权组合：熵值、可疑 API 密度、打包标记与行为分数
            double entropyScore = Math.Max(0, (features.Entropy - 6.0) / 2.0);
            double apiScore = Math.Min(features.SuspiciousApiCount / 10.0, 1.0);
            double packedScore = features.HasPackedCode ? 1.0 : 0.0;

            double threatScore = entropyScore * 0.25 + apiScore * 0.35 + packedScore * 0.2 + behaviorScore * 0.2;

            return Math.Min(Math.Max(threatScore, 0.0), 1.0);
        }
    }

    public class ThreatIntelligenceService
    {
        public async Task<ThreatIntelligenceData> CheckFileAsync(string filePath)
        {
            await Task.CompletedTask;

            // 真实查询本地威胁情报哈希库（threat_hashes.txt 每行一个 SHA256，可由云端同步更新）
            try
            {
                if (!File.Exists(filePath)) return new ThreatIntelligenceData();

                string hash;
                using (var sha256 = System.Security.Cryptography.SHA256.Create())
                using (var stream = File.OpenRead(filePath))
                {
                    hash = BitConverter.ToString(sha256.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
                }

                var hashFile = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "FireAntivirus", "threat_hashes.txt");

                if (File.Exists(hashFile))
                {
                    foreach (var line in File.ReadLines(hashFile))
                    {
                        if (line.Trim().Equals(hash, StringComparison.OrdinalIgnoreCase))
                        {
                            return new ThreatIntelligenceData
                            {
                                ThreatLevel = ThreatLevel.High,
                                DetectionCount = 1,
                                LastSeen = DateTime.Now,
                                ThreatType = "KnownThreat"
                            };
                        }
                    }
                }
            }
            catch
            {
            }

            return new ThreatIntelligenceData();
        }
    }

    public class HeuristicRuleMatch
    {
        public string RuleId { get; set; }
        public string Description { get; set; }
        public ThreatLevel Severity { get; set; }
        public double Confidence { get; set; }
    }

    public class ThreatIntelligenceData
    {
        public ThreatLevel ThreatLevel { get; set; }
        public int DetectionCount { get; set; }
        public DateTime LastSeen { get; set; }
        public string ThreatType { get; set; }
    }

    public enum ThreatLevel
    {
        Safe = 0,
        Low = 1,
        Medium = 2,
        High = 3,
        Critical = 4
    }
}