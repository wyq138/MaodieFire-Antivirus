using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace FireAntivirus.Engine.Analyzers.Security
{
    /// <summary>
    /// 威胁情报分析器 - 分析威胁情报和IOC
    /// </summary>
    public class ThreatIntelligenceAnalyzer
    {
        private readonly Dictionary<string, ThreatIndicator> _indicators;
        private readonly HashSet<string> _maliciousHashes;
        private readonly HashSet<string> _maliciousIPs;
        private readonly HashSet<string> _maliciousDomains;
        private readonly List<ThreatSignature> _signatures;
        private readonly List<string> _feedWarnings;

        /// <summary>已从外部特征库加载到的家族特征数量（用于自检，防止外置后杀毒效果被无声削弱）</summary>
        public int LoadedSignatureCount => _signatures.Count;

        /// <summary>外部特征库加载是否成功（配置缺失/损坏时返回 false，不再静默降级）</summary>
        public bool ThreatFeedLoaded { get; private set; }

        public ThreatIntelligenceAnalyzer()
        {
            _indicators = new Dictionary<string, ThreatIndicator>();
            _maliciousHashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _maliciousIPs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _maliciousDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _signatures = new List<ThreatSignature>();
            _feedWarnings = new List<string>();
            InitializeThreatIndicators();
        }

        private void InitializeThreatIndicators()
        {
            // 已知恶意软件家族特征（数据外置到外部 JSON，避免在 DLL 内内嵌恶意命令串，详见 ThreatData/threat_signatures.json）
            LoadThreatSignatures();

            // 已知恶意IP地址 - 来源：威胁情报数据库
            _maliciousIPs.UnionWith(new[]
            {
                // Tor出口节点
                "185.220.101.0", "185.220.101.1", "185.220.101.2", "185.220.101.3",
                "185.220.102.0", "185.220.102.1", "185.220.102.2", "185.220.102.3",
                "198.96.155.0", "198.96.155.1", "198.96.155.2", "198.96.155.3",
                "199.184.246.0", "199.184.246.1",
                
                // 已知C&C服务器
                "23.129.64.0", "23.129.64.1", "23.129.64.2", "23.129.64.3",
                "45.155.205.0", "45.155.205.1", "45.155.205.2", "45.155.205.3",
                "91.219.29.0", "91.219.29.1", "91.219.29.2",
                "185.141.63.0", "185.141.63.1", "185.141.63.2",
                "194.163.142.0", "194.163.142.1", "194.163.142.2",
                "45.153.240.0", "45.153.240.1", "45.153.240.2",
                
                // 已知恶意软件基础设施
                "104.244.72.0", "104.244.72.1", "104.244.72.2",
                "162.247.74.0", "162.247.74.1", "162.247.74.2",
                "171.22.28.0", "171.22.28.1", "171.22.28.2",
                "179.43.175.0", "179.43.175.1", "179.43.175.2",
                
                // 垃圾邮件和钓鱼服务器
                "45.33.32.0", "45.33.32.1", "45.33.32.2",
                "64.113.32.0", "64.113.32.1", "64.113.32.2",
                "69.162.69.0", "69.162.69.1", "69.162.69.2",
                "74.91.19.0", "74.91.19.1", "74.91.19.2",
                
                // 挖矿恶意软件
                "141.98.10.0", "141.98.10.1", "141.98.10.2",
                "185.199.108.0", "185.199.108.1", "185.199.108.2",
                "45.9.148.0", "45.9.148.1", "45.9.148.2",
                
                // 勒索软件C&C
                "5.188.86.0", "5.188.86.1", "5.188.86.2",
                "37.139.0.0", "37.139.0.1", "37.139.0.2",
                "185.217.0.0", "185.217.0.1", "185.217.0.2"
            });
        }

        public ThreatIntelligenceResult Analyze(string filePath)
        {
            var result = new ThreatIntelligenceResult
            {
                FilePath = filePath,
                Indicators = new List<IndicatorMatch>(),
                Threats = new List<ThreatMatch>(),
                RiskScore = 0,
                Warnings = new List<string>()
            };

            try
            {
                if (!File.Exists(filePath)) return result;

                var fileContent = File.ReadAllBytes(filePath);
                var fileText = Encoding.UTF8.GetString(fileContent, 0, Math.Min(fileContent.Length, 100000));
                var fileHash = ComputeHash(fileContent);

                // 检查文件哈希
                if (_maliciousHashes.Contains(fileHash))
                {
                    result.Threats.Add(new ThreatMatch
                    {
                        Type = "恶意文件哈希",
                        Value = fileHash,
                        Risk = "严重"
                    });
                    result.RiskScore += 100;
                }

                // 检查威胁签名
                foreach (var sig in _signatures)
                {
                    foreach (var pattern in sig.Patterns)
                    {
                        if (fileText.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                        {
                            result.Threats.Add(new ThreatMatch
                            {
                                Type = sig.Family,
                                Name = sig.Name,
                                Value = pattern,
                                Risk = sig.RiskLevel
                            });

                            result.RiskScore += sig.RiskLevel switch
                            {
                                "严重" => 30,
                                "高" => 20,
                                "中" => 10,
                                _ => 5
                            };
                        }
                    }
                }

                // 检查IP地址
                var ipMatches = Regex.Matches(fileText, @"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b");
                foreach (Match match in ipMatches)
                {
                    if (_maliciousIPs.Contains(match.Value))
                    {
                        result.Threats.Add(new ThreatMatch
                        {
                            Type = "恶意IP",
                            Value = match.Value,
                            Risk = "高"
                        });
                        result.RiskScore += 20;
                    }
                    else
                    {
                        result.Indicators.Add(new IndicatorMatch
                        {
                            Type = "IP地址",
                            Value = match.Value
                        });
                    }
                }

                // 检查域名
                var domainMatches = Regex.Matches(fileText, @"\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}\b");
                foreach (Match match in domainMatches)
                {
                    if (_maliciousDomains.Contains(match.Value.ToLower()))
                    {
                        result.Threats.Add(new ThreatMatch
                        {
                            Type = "恶意域名",
                            Value = match.Value,
                            Risk = "高"
                        });
                        result.RiskScore += 20;
                    }
                }

                // 检查可疑字符串
                CheckSuspiciousStrings(fileText, result);

                // 计算最终风险评分
                result.RiskScore = Math.Min(100, result.RiskScore);

                if (result.Threats.Count > 0)
                {
                    result.Warnings.Add($"发现 {result.Threats.Count} 个威胁指标");
                }

                // 特征库加载异常必须透出，避免静默降级导致漏报
                foreach (var w in _feedWarnings)
                {
                    result.Warnings.Add(w);
                }
            }
            catch (Exception ex)
            {
                result.Warnings.Add($"威胁分析错误: {ex.Message}");
            }

            return result;
        }

        /// <summary>
        /// 从外部 JSON 加载恶意软件家族特征（不内嵌于 DLL）。
        /// 这是杀毒效果的一部分，缺失/损坏必须暴露为告警，绝不静默降级导致漏报。
        /// </summary>
        private void LoadThreatSignatures()
        {
            var dataPath = Path.Combine(AppContext.BaseDirectory, "ThreatData", "threat_signatures.json");

            if (!File.Exists(dataPath))
            {
                _feedWarnings.Add("威胁特征库缺失，请将 ThreatData/threat_signatures.json 部署到程序目录");
                return;
            }

            try
            {
                var json = File.ReadAllText(dataPath);
                var loaded = System.Text.Json.JsonSerializer.Deserialize<List<ThreatSignature>>(json);
                if (loaded == null || loaded.Count == 0)
                {
                    _feedWarnings.Add("威胁特征库内容为空或无法解析");
                    return;
                }

                _signatures.AddRange(loaded);
                ThreatFeedLoaded = true;
            }
            catch (Exception ex)
            {
                _feedWarnings.Add($"威胁特征库加载失败: {ex.Message}");
            }
        }

        private void CheckSuspiciousStrings(string content, ThreatIntelligenceResult result)
        {
            var suspiciousPatterns = new Dictionary<string, string>
            {
                { "VirtualAlloc", "内存分配API" },
                { "CreateRemoteThread", "远程线程创建" },
                { "WriteProcessMemory", "进程内存写入" },
                { "NtUnmapViewOfSection", "进程注入" },
                { "SetWindowsHookEx", "全局钩子" },
                { "RegSetValue", "注册表修改" },
                { "ShellExecute", "命令执行" },
                { "WinExec", "命令执行" },
                { "URLDownloadToFile", "文件下载" },
                { "InternetOpen", "网络连接" },
                { "socket", "网络套接字" },
                { "connect", "网络连接" },
                { "base64", "Base64编码" },
                { "AES", "AES加密" },
                { "RSA", "RSA加密" },
                { "powershell", "PowerShell" },
                { "cmd.exe", "命令行" },
                { "wscript", "脚本执行" },
                { "mshta", "HTA执行" },
            };

            foreach (var pattern in suspiciousPatterns)
            {
                if (content.Contains(pattern.Key, StringComparison.OrdinalIgnoreCase))
                {
                    result.Indicators.Add(new IndicatorMatch
                    {
                        Type = pattern.Value,
                        Value = pattern.Key
                    });
                }
            }
        }

        private string ComputeHash(byte[] data)
        {
            using var sha256 = System.Security.Cryptography.SHA256.Create();
            var hash = sha256.ComputeHash(data);
            return BitConverter.ToString(hash).Replace("-", "").ToLower();
        }

        public void AddMaliciousHash(string hash)
        {
            _maliciousHashes.Add(hash.ToLower());
        }

        public void AddMaliciousIP(string ip)
        {
            _maliciousIPs.Add(ip);
        }

        public void AddMaliciousDomain(string domain)
        {
            _maliciousDomains.Add(domain.ToLower());
        }

        public void LoadThreatFeed(string feedPath)
        {
            try
            {
                if (File.Exists(feedPath))
                {
                    var lines = File.ReadAllLines(feedPath);
                    foreach (var line in lines)
                    {
                        var parts = line.Split(',');
                        if (parts.Length >= 2)
                        {
                            var type = parts[0].Trim().ToLower();
                            var value = parts[1].Trim();

                            switch (type)
                            {
                                case "hash":
                                    _maliciousHashes.Add(value.ToLower());
                                    break;
                                case "ip":
                                    _maliciousIPs.Add(value);
                                    break;
                                case "domain":
                                    _maliciousDomains.Add(value.ToLower());
                                    break;
                            }
                        }
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ThreatIntelligenceAnalyzer.cs 捕获异常", ex.Message); }
        }
    }

    public class ThreatIntelligenceResult
    {
        public string FilePath { get; set; }
        public List<IndicatorMatch> Indicators { get; set; }
        public List<ThreatMatch> Threats { get; set; }
        public int RiskScore { get; set; }
        public List<string> Warnings { get; set; }
    }

    public class IndicatorMatch
    {
        public string Type { get; set; }
        public string Value { get; set; }
    }

    public class ThreatMatch
    {
        public string Type { get; set; }
        public string Name { get; set; }
        public string Value { get; set; }
        public string Risk { get; set; }
    }

    public class ThreatIndicator
    {
        public string Type { get; set; }
        public string Value { get; set; }
        public string Source { get; set; }
        public DateTime LastSeen { get; set; }
    }

    public class ThreatSignature
    {
        public string Name { get; set; }
        public string Family { get; set; }
        public string[] Patterns { get; set; }
        public string RiskLevel { get; set; }
    }
}