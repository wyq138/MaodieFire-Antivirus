// 抖音用户 耄耋杀毒软件 开发，严禁非法反编译
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;

namespace FireAntivirus.Engine.Analyzers.Protection
{
    /// <summary>
    /// 网页防护分析器 - 分析网页威胁和恶意URL
    /// </summary>
    public class WebProtectionAnalyzer
    {
        private readonly HashSet<string> _maliciousDomains;
        private readonly HashSet<string> _phishingPatterns;
        private readonly Dictionary<string, string> _categoryDatabase;
        private readonly List<URLPattern> _urlPatterns;

        public WebProtectionAnalyzer()
        {
            _maliciousDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _phishingPatterns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _categoryDatabase = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            _urlPatterns = new List<URLPattern>();
            InitializeThreatData();
        }

        private void InitializeThreatData()
        {
            // 恶意域名
            _maliciousDomains.UnionWith(new[]
            {
                "malware.com", "virus.com", "phishing.com",
                "bit.ly", "tinyurl.com", "goo.gl" // 短链接可能是钓鱼
            });

            // 钓鱼模式
            _phishingPatterns.UnionWith(new[]
            {
                "login", "verify", "confirm", "update", "secure",
                "account", "password", "bank", "paypal", "amazon"
            });

            // URL模式
            _urlPatterns.AddRange(new[]
            {
                new URLPattern { Pattern = @"^https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", Type = "IP地址URL", Risk = "高" },
                new URLPattern { Pattern = @"@.*@", Type = "URL中的@", Risk = "高" },
                new URLPattern { Pattern = @"[^a-zA-Z0-9\-\.]", Type = "特殊字符域名", Risk = "中" },
                new URLPattern { Pattern = @"\.(ru|cn|tk|ml|ga|cf)/", Type = "高风险TLD", Risk = "中" },
                new URLPattern { Pattern = @"data:text/html", Type = "Data URL", Risk = "高" },
                new URLPattern { Pattern = @"javascript:", Type = "JavaScript URL", Risk = "严重" }
            });

            // 分类数据库
            var categories = new Dictionary<string, string>
            {
                { "facebook.com", "社交媒体" },
                { "twitter.com", "社交媒体" },
                { "instagram.com", "社交媒体" },
                { "youtube.com", "视频" },
                { "google.com", "搜索引擎" },
                { "bing.com", "搜索引擎" },
                { "baidu.com", "搜索引擎" },
                { "github.com", "开发" },
                { "microsoft.com", "技术" },
                { "apple.com", "技术" }
            };
            foreach (var cat in categories)
            {
                _categoryDatabase[cat.Key] = cat.Value;
            }
        }

        public WebProtectionResult AnalyzeURL(string url)
        {
            var result = new WebProtectionResult
            {
                URL = url,
                IsSafe = true,
                RiskScore = 0,
                Threats = new List<URLThreat>(),
                Warnings = new List<string>()
            };

            try
            {
                var uri = new Uri(url);
                result.Domain = uri.Host;
                result.Path = uri.PathAndQuery;

                // 检查恶意域名
                if (_maliciousDomains.Contains(uri.Host))
                {
                    result.Threats.Add(new URLThreat
                    {
                        Type = "恶意域名",
                        Value = uri.Host,
                        Risk = "严重"
                    });
                    result.RiskScore += 50;
                }

                // 检查URL模式
                foreach (var pattern in _urlPatterns)
                {
                    if (Regex.IsMatch(url, pattern.Pattern, RegexOptions.IgnoreCase))
                    {
                        result.Threats.Add(new URLThreat
                        {
                            Type = pattern.Type,
                            Value = pattern.Pattern,
                            Risk = pattern.Risk
                        });
                        result.RiskScore += pattern.Risk switch
                        {
                            "严重" => 30,
                            "高" => 20,
                            "中" => 10,
                            _ => 5
                        };
                    }
                }

                // 检查钓鱼模式
                foreach (var phishing in _phishingPatterns)
                {
                    if (url.Contains(phishing, StringComparison.OrdinalIgnoreCase))
                    {
                        // 需要结合其他因素判断
                        result.RiskScore += 2;
                    }
                }

                // 检查HTTPS
                if (uri.Scheme != "https")
                {
                    result.Threats.Add(new URLThreat
                    {
                        Type = "不安全连接",
                        Value = "HTTP",
                        Risk = "低"
                    });
                    result.RiskScore += 5;
                }

                // 检查可疑参数
                if (!string.IsNullOrEmpty(uri.Query))
                {
                    CheckSuspiciousParameters(uri.Query, result);
                }

                // 获取分类
                result.Category = GetCategory(uri.Host);

                // 确定安全性
                result.IsSafe = result.RiskScore < 30;
                result.RiskLevel = GetRiskLevel(result.RiskScore);

                if (!result.IsSafe)
                {
                    result.Warnings.Add($"URL风险评分: {result.RiskScore}");
                }
            }
            catch (Exception ex)
            {
                result.Warnings.Add($"URL分析错误: {ex.Message}");
                result.IsSafe = false;
            }

            return result;
        }

        private void CheckSuspiciousParameters(string query, WebProtectionResult result)
        {
            var suspiciousParams = new[] { "password", "pwd", "token", "key", "secret", "auth" };
            
            foreach (var param in suspiciousParams)
            {
                if (query.Contains(param, StringComparison.OrdinalIgnoreCase))
                {
                    result.Threats.Add(new URLThreat
                    {
                        Type = "可疑参数",
                        Value = param,
                        Risk = "中"
                    });
                    result.RiskScore += 10;
                }
            }
        }

        private string GetCategory(string host)
        {
            foreach (var entry in _categoryDatabase)
            {
                if (host.Contains(entry.Key, StringComparison.OrdinalIgnoreCase))
                {
                    return entry.Value;
                }
            }
            return "未知";
        }

        private string GetRiskLevel(int score)
        {
            return score switch
            {
                >= 50 => "严重",
                >= 30 => "高",
                >= 15 => "中",
                >= 5 => "低",
                _ => "安全"
            };
        }

        public HTMLAnalysisResult AnalyzeHTML(string html)
        {
            var result = new HTMLAnalysisResult
            {
                Threats = new List<HTMLThreat>(),
                SuspiciousScripts = new List<string>()
            };

            try
            {
                // 检查恶意脚本
                var scriptPatterns = new Dictionary<string, string>
                {
                    { @"eval\s*\(", "eval函数调用" },
                    { @"document\.write", "document.write调用" },
                    { @"<iframe", "内嵌框架" },
                    { @"<object", "对象嵌入" },
                    { @"<embed", "嵌入元素" },
                    { @"<script[^>]*src\s*=\s*[""']http", "外部脚本引用" },
                    { @"onerror\s*=", "onerror事件" },
                    { @"onload\s*=", "onload事件" },
                    { @"onclick\s*=", "onclick事件" }
                };

                foreach (var pattern in scriptPatterns)
                {
                    if (Regex.IsMatch(html, pattern.Key, RegexOptions.IgnoreCase))
                    {
                        result.Threats.Add(new HTMLThreat
                        {
                            Type = pattern.Value,
                            Pattern = pattern.Key
                        });
                    }
                }

                // 提取所有URL
                var urlMatches = Regex.Matches(html, @"https?://[^\s""'<>]+");
                foreach (Match match in urlMatches)
                {
                    var urlAnalysis = AnalyzeURL(match.Value);
                    if (!urlAnalysis.IsSafe)
                    {
                        result.SuspiciousScripts.Add(match.Value);
                    }
                }
            }
            catch { }

            return result;
        }

        public void AddMaliciousDomain(string domain)
        {
            _maliciousDomains.Add(domain.ToLower());
        }

        public void AddPhishingPattern(string pattern)
        {
            _phishingPatterns.Add(pattern.ToLower());
        }
    }

    public class WebProtectionResult
    {
        public string URL { get; set; }
        public string Domain { get; set; }
        public string Path { get; set; }
        public bool IsSafe { get; set; }
        public int RiskScore { get; set; }
        public string RiskLevel { get; set; }
        public string Category { get; set; }
        public List<URLThreat> Threats { get; set; }
        public List<string> Warnings { get; set; }
    }

    public class URLThreat
    {
        public string Type { get; set; }
        public string Value { get; set; }
        public string Risk { get; set; }
    }

    public class URLPattern
    {
        public string Pattern { get; set; }
        public string Type { get; set; }
        public string Risk { get; set; }
    }

    public class HTMLAnalysisResult
    {
        public List<HTMLThreat> Threats { get; set; }
        public List<string> SuspiciousScripts { get; set; }
    }

    public class HTMLThreat
    {
        public string Type { get; set; }
        public string Pattern { get; set; }
    }
}
