using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace FireAntivirus.Engine.Detection
{
    /// <summary>
    /// YARA规则引擎集成 - 提供强大的模式匹配检测能力
    /// </summary>
    public class YaraEngine
    {
        private readonly List<YaraRule> _rules;
        private readonly string _rulesDirectory;
        private bool _initialized;

        public YaraEngine()
        {
            _rules = new List<YaraRule>();
            _rulesDirectory = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "FireAntivirus", "YaraRules");
            _initialized = false;
        }

        /// <summary>
        /// 初始化YARA引擎
        /// </summary>
        public async Task<bool> InitializeAsync()
        {
            try
            {
                // 确保规则目录存在
                Directory.CreateDirectory(_rulesDirectory);

                // 加载内置规则
                await LoadBuiltinRulesAsync();

                // 检查并下载最新规则
                await CheckForRuleUpdatesAsync();

                _initialized = true;
                Console.WriteLine("YARA引擎初始化完成，已加载规则数: " + _rules.Count);
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"YARA引擎初始化失败: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// 扫描文件使用YARA规则
        /// </summary>
        public async Task<YaraScanResult> ScanFileAsync(string filePath)
        {
            if (!_initialized)
            {
                throw new InvalidOperationException("YARA引擎未初始化");
            }

            var result = new YaraScanResult
            {
                FilePath = filePath,
                ScanTime = DateTime.Now
            };

            try
            {
                if (!File.Exists(filePath))
                {
                    result.Error = "文件不存在";
                    return result;
                }

                var fileContent = await File.ReadAllBytesAsync(filePath);
                var matches = new List<YaraMatch>();

                // 对每个规则进行匹配
                foreach (var rule in _rules)
                {
                    var match = await MatchRuleAsync(rule, fileContent, filePath);
                    if (match != null)
                    {
                        matches.Add(match);
                    }
                }

                result.Matches = matches;
                result.IsThreatDetected = matches.Any(m => m.Severity >= ThreatSeverity.Medium);
                result.Confidence = CalculateConfidence(matches);
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
            }

            return result;
        }

        /// <summary>
        /// 单个规则匹配
        /// </summary>
        private async Task<YaraMatch> MatchRuleAsync(YaraRule rule, byte[] fileContent, string filePath)
        {
            try
            {
                // 实现简化的YARA模式匹配逻辑
                bool isMatch = await Task.Run(() =>
                {
                    // 检查字符串模式
                    foreach (var pattern in rule.Patterns)
                    {
                        if (ContainsPattern(fileContent, pattern))
                        {
                            return true;
                        }
                    }

                    // 检查十六进制模式
                    foreach (var hexPattern in rule.HexPatterns)
                    {
                        if (ContainsHexPattern(fileContent, hexPattern))
                        {
                            return true;
                        }
                    }

                    return false;
                });

                if (isMatch)
                {
                    return new YaraMatch
                    {
                        RuleName = rule.Name,
                        Description = rule.Description,
                        Severity = rule.Severity,
                        MatchedPatterns = rule.Patterns.Count + rule.HexPatterns.Count
                    };
                }

                return null;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// 检查字节模式
        /// </summary>
        private bool ContainsPattern(byte[] data, string pattern)
        {
            var patternBytes = System.Text.Encoding.UTF8.GetBytes(pattern);
            return ContainsBytes(data, patternBytes);
        }

        /// <summary>
        /// 检查十六进制模式
        /// </summary>
        private bool ContainsHexPattern(byte[] data, string hexPattern)
        {
            try
            {
                var patternBytes = HexStringToByteArray(hexPattern);
                return ContainsBytes(data, patternBytes);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// 字节数组包含检查
        /// </summary>
        private bool ContainsBytes(byte[] data, byte[] pattern)
        {
            for (int i = 0; i <= data.Length - pattern.Length; i++)
            {
                bool found = true;
                for (int j = 0; j < pattern.Length; j++)
                {
                    if (data[i + j] != pattern[j])
                    {
                        found = false;
                        break;
                    }
                }
                if (found) return true;
            }
            return false;
        }

        /// <summary>
        /// 十六进制字符串转字节数组
        /// </summary>
        private byte[] HexStringToByteArray(string hex)
        {
            hex = hex.Replace(" ", "").Replace("-", "").Replace("?", "00");
            int length = hex.Length;
            byte[] bytes = new byte[length / 2];
            for (int i = 0; i < length; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }
            return bytes;
        }

        private void LoadBuiltinRules()
        {
            // YARA 规则从外部 JSON 加载（ThreatData/yara_rules.json），不把规则串编译进 DLL，
            // 既避免杀软误报，也便于联网更新规则覆盖变种。
            try
            {
                var file = Path.Combine(AppContext.BaseDirectory, "ThreatData", "yara_rules.json");
                if (!File.Exists(file)) return;
                var list = System.Text.Json.JsonSerializer.Deserialize<List<YaraRuleFileEntry>>(File.ReadAllText(file));
                if (list == null) return;
                foreach (var e in list)
                {
                    _rules.Add(new YaraRule
                    {
                        Name = e.Name,
                        Description = e.Description,
                        Severity = e.SeverityEnum,
                        Patterns = e.Patterns ?? new List<string>(),
                        HexPatterns = e.HexPatterns ?? new List<string>()
                    });
                }
            }
            catch
            {
                // 外部规则损坏时保持空，不崩引擎
            }
        }

        /// <summary>
        /// 加载内置规则
        /// </summary>
        private async Task LoadBuiltinRulesAsync()
        {
            LoadBuiltinRules();
            await Task.CompletedTask;
        }

        /// <summary>
        /// 检查规则更新
        /// 规则通过特征库更新器联网拉取最新版本，此处无需内置下载逻辑
        /// </summary>
        private async Task CheckForRuleUpdatesAsync()
        {
            try
            {
                var updateFile = Path.Combine(AppContext.BaseDirectory, "ThreatData", "yara_rules.json");
                // 若更新器已刷新外置规则文件，重新加载即可
                if (File.Exists(updateFile))
                {
                    _rules.Clear();
                    LoadBuiltinRules();
                }
                await Task.CompletedTask;
            }
            catch
            {
                // 更新失败则继续使用当前已加载规则
            }
        }

        /// <summary>
        /// 保存规则到文件
        /// </summary>
        private async Task SaveRulesToFileAsync()
        {
            var rulesFile = Path.Combine(_rulesDirectory, "rules.json");
            // 实现规则序列化保存
            await Task.CompletedTask;
        }

        /// <summary>
        /// 计算检测置信度
        /// </summary>
        private double CalculateConfidence(List<YaraMatch> matches)
        {
            if (!matches.Any()) return 0.0;

            double totalScore = matches.Sum(m => (int)m.Severity);
            double maxPossibleScore = matches.Count * (int)ThreatSeverity.Critical;
            
            return Math.Min(totalScore / maxPossibleScore, 1.0);
        }
    }

    /// <summary>
    /// YARA规则定义
    /// </summary>
    public class YaraRule
    {
        public string Name { get; set; }
        public string Description { get; set; }
        public ThreatSeverity Severity { get; set; }
        public List<string> Patterns { get; set; } = new List<string>();
        public List<string> HexPatterns { get; set; } = new List<string>();
    }

    /// <summary>外置 YARA 规则条目（ThreatData/yara_rules.json）</summary>
    public class YaraRuleFileEntry
    {
        public string Name { get; set; }
        public string Description { get; set; }
        public string Severity { get; set; }
        public List<string> Patterns { get; set; } = new List<string>();
        public List<string> HexPatterns { get; set; } = new List<string>();

        public ThreatSeverity SeverityEnum
        {
            get
            {
                return Severity?.ToLowerInvariant() switch
                {
                    "low" => ThreatSeverity.Low,
                    "medium" => ThreatSeverity.Medium,
                    "high" => ThreatSeverity.High,
                    "critical" => ThreatSeverity.Critical,
                    _ => ThreatSeverity.Medium
                };
            }
        }
    }

    /// <summary>
    /// YARA扫描结果
    /// </summary>
    public class YaraScanResult
    {
        public string FilePath { get; set; }
        public DateTime ScanTime { get; set; }
        public List<YaraMatch> Matches { get; set; } = new List<YaraMatch>();
        public bool IsThreatDetected { get; set; }
        public double Confidence { get; set; }
        public string Error { get; set; }
    }

    /// <summary>
    /// YARA匹配结果
    /// </summary>
    public class YaraMatch
    {
        public string RuleName { get; set; }
        public string Description { get; set; }
        public ThreatSeverity Severity { get; set; }
        public int MatchedPatterns { get; set; }
    }

    /// <summary>
    /// 威胁严重程度
    /// </summary>
    public enum ThreatSeverity
    {
        Low = 1,
        Medium = 2,
        High = 3,
        Critical = 4
    }
}