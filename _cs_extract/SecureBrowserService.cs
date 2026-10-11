// 耄耋软件工作室 开发，严禁非法反编译
// 专业级安全浏览器引擎 - 对标Safe Browsing/SmartScreen能力
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace FireAntivirus.Services
{
    public class SecureBrowserService
    {
        private readonly string _hostsPath = Path.Combine(Environment.SystemDirectory, "drivers", "etc", "hosts");
        private readonly string _configPath;
        private readonly string _cachePath;
        private readonly HttpClient _httpClient;

        // 缓存
        private ConcurrentDictionary<string, UrlReputationCache> _reputationCache = new ConcurrentDictionary<string, UrlReputationCache>();
        private ConcurrentDictionary<string, DomainInfo> _domainCache = new ConcurrentDictionary<string, DomainInfo>();
        private ConcurrentDictionary<string, ThreatIndicator> _urlThreats = new ConcurrentDictionary<string, ThreatIndicator>();

        // 广告拦截规则
        private List<AdBlockRule> _adBlockRules = new List<AdBlockRule>();
        private List<TrackerPattern> _trackerPatterns = new List<TrackerPattern>();

        // 钓鱼检测模型
        private List<PhishingPattern> _phishingPatterns = new List<PhishingPattern>();
        private HashSet<string> _trustedDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private HashSet<string> _knownPhishingDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // 网银保护
        private HashSet<string> _bankingDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private bool _bankingProtectionActive = false;
        private string _currentBankingDomain = null;

        public event EventHandler<ThreatDetectedEventArgs> ThreatDetected;
        public event EventHandler<PhishingDetectedEventArgs> PhishingDetected;
        public event EventHandler<SslWarningEventArgs> SslWarning;

        public SecureBrowserService()
        {
            _configPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "FireAntivirus", "Browser");
            _cachePath = Path.Combine(_configPath, "Cache");

            foreach (var path in new[] { _configPath, _cachePath })
            {
                if (!Directory.Exists(path))
                    Directory.CreateDirectory(path);
            }

            _httpClient = new HttpClient(new HttpClientHandler
            {
                AllowAutoRedirect = false,
                MaxAutomaticRedirections = 0
            });
            _httpClient.Timeout = TimeSpan.FromSeconds(10);

            InitializeThreatData();
            InitializeAdBlockRules();
            InitializeTrackerPatterns();
            InitializePhishingPatterns();
            InitializeTrustedDomains();
            InitializeBankingDomains();
        }

        #region 初始化

        private void InitializeThreatData()
        {
            // 已知恶意域名模式
            _knownPhishingDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                // 示例钓鱼域名模式（实际应用中应从威胁情报源加载）
                "paypa1.com", "amaz0n.com", "bank0famerica.com", "we1lsfargo.com",
                "chase-bank.com", "micros0ft.com", "g00gle.com", "faceb00k.com"
            };
        }

        private void InitializeAdBlockRules()
        {
            _adBlockRules = new List<AdBlockRule>
            {
                // 广告网络
                new AdBlockRule { Pattern = "*googlesyndication.com*", Type = BlockType.AdNetwork },
                new AdBlockRule { Pattern = "*doubleclick.net*", Type = BlockType.AdNetwork },
                new AdBlockRule { Pattern = "*googleadservices.com*", Type = BlockType.AdNetwork },
                new AdBlockRule { Pattern = "*facebook.com/tr*", Type = BlockType.Tracker },
                new AdBlockRule { Pattern = "*analytics.google.com*", Type = BlockType.Tracker },
                new AdBlockRule { Pattern = "*google-analytics.com*", Type = BlockType.Tracker },
                new AdBlockRule { Pattern = "*scorecardresearch.com*", Type = BlockType.Tracker },
                new AdBlockRule { Pattern = "*quantserve.com*", Type = BlockType.Tracker },
                new AdBlockRule { Pattern = "*newrelic.com*", Type = BlockType.Tracker },
                new AdBlockRule { Pattern = "*hotjar.com*", Type = BlockType.Tracker },
                new AdBlockRule { Pattern = "*crazyegg.com*", Type = BlockType.Tracker },
                new AdBlockRule { Pattern = "*adroll.com*", Type = BlockType.AdNetwork },
                new AdBlockRule { Pattern = "*taboola.com*", Type = BlockType.AdNetwork },
                new AdBlockRule { Pattern = "*outbrain.com*", Type = BlockType.AdNetwork },
                new AdBlockRule { Pattern = "*criteo.com*", Type = BlockType.AdNetwork },
                new AdBlockRule { Pattern = "*adnxs.com*", Type = BlockType.AdNetwork },
                new AdBlockRule { Pattern = "*rubiconproject.com*", Type = BlockType.AdNetwork },
                new AdBlockRule { Pattern = "*pubmatic.com*", Type = BlockType.AdNetwork },
                new AdBlockRule { Pattern = "*openx.net*", Type = BlockType.AdNetwork },

                // 弹窗广告
                new AdBlockRule { Pattern = "*popup*", Type = BlockType.Popup },
                new AdBlockRule { Pattern = "*popunder*", Type = BlockType.Popup },
                new AdBlockRule { Pattern = "*popads*", Type = BlockType.Popup },
                new AdBlockRule { Pattern = "*popcash*", Type = BlockType.Popup },

                // 恶意广告
                new AdBlockRule { Pattern = "*malware*", Type = BlockType.Malware },
                new AdBlockRule { Pattern = "*adware*", Type = BlockType.Malware }
            };
        }

        private void InitializeTrackerPatterns()
        {
            _trackerPatterns = new List<TrackerPattern>
            {
                new TrackerPattern
                {
                    Name = "Google Analytics",
                    Patterns = new[] { "google-analytics.com", "googletagmanager.com" },
                    Category = "Analytics"
                },
                new TrackerPattern
                {
                    Name = "Facebook Pixel",
                    Patterns = new[] { "facebook.com/tr", "connect.facebook.net" },
                    Category = "Social"
                },
                new TrackerPattern
                {
                    Name = "Twitter Pixel",
                    Patterns = new[] { "t.co", "twitter.com/i/adsct" },
                    Category = "Social"
                },
                new TrackerPattern
                {
                    Name = "LinkedIn Insight",
                    Patterns = new[] { "linkedin.com/li", "snap.licdn.com" },
                    Category = "Social"
                },
                new TrackerPattern
                {
                    Name = "Hotjar",
                    Patterns = new[] { "hotjar.com" },
                    Category = "Session Recording"
                },
                new TrackerPattern
                {
                    Name = "FullStory",
                    Patterns = new[] { "fullstory.com" },
                    Category = "Session Recording"
                },
                new TrackerPattern
                {
                    Name = "MouseFlow",
                    Patterns = new[] { "mouseflow.com" },
                    Category = "Session Recording"
                },
                new TrackerPattern
                {
                    Name = "Chartbeat",
                    Patterns = new[] { "chartbeat.com", "chartbeat.net" },
                    Category = "Analytics"
                },
                new TrackerPattern
                {
                    Name = "Mixpanel",
                    Patterns = new[] { "mixpanel.com" },
                    Category = "Analytics"
                },
                new TrackerPattern
                {
                    Name = "Segment",
                    Patterns = new[] { "segment.com", "segment.io" },
                    Category = "Analytics"
                }
            };
        }

        private void InitializePhishingPatterns()
        {
            _phishingPatterns = new List<PhishingPattern>
            {
                // 品牌钓鱼模式
                new PhishingPattern
                {
                    TargetBrand = "PayPal",
                    LegitimateDomains = new[] { "paypal.com", "paypalobjects.com" },
                    SuspiciousPatterns = new[] { "paypa1", "paypaI", "pay-pal", "paypаl", "pаypal" }
                },
                new PhishingPattern
                {
                    TargetBrand = "Amazon",
                    LegitimateDomains = new[] { "amazon.com", "amazonpay.com" },
                    SuspiciousPatterns = new[] { "amaz0n", "amazоn", "amazon-", "amazon.", "amazn" }
                },
                new PhishingPattern
                {
                    TargetBrand = "Microsoft",
                    LegitimateDomains = new[] { "microsoft.com", "live.com", "outlook.com", "office.com" },
                    SuspiciousPatterns = new[] { "micros0ft", "micrоsoft", "mircosoft", "microsoft-", "msn-support" }
                },
                new PhishingPattern
                {
                    TargetBrand = "Google",
                    LegitimateDomains = new[] { "google.com", "gstatic.com", "googleapis.com" },
                    SuspiciousPatterns = new[] { "g00gle", "googlе", "googIe", "google-", "google." }
                },
                new PhishingPattern
                {
                    TargetBrand = "Facebook",
                    LegitimateDomains = new[] { "facebook.com", "fb.com", "fbcdn.net" },
                    SuspiciousPatterns = new[] { "faceb00k", "faceboоk", "facbook", "facebook-", "fb-login" }
                },
                new PhishingPattern
                {
                    TargetBrand = "Apple",
                    LegitimateDomains = new[] { "apple.com", "icloud.com", "itunes.com" },
                    SuspiciousPatterns = new[] { "applе", "appIe", "apple-", "apple-support", "icloud-" }
                },
                new PhishingPattern
                {
                    TargetBrand = "Bank of America",
                    LegitimateDomains = new[] { "bankofamerica.com" },
                    SuspiciousPatterns = new[] { "bank0famerica", "bankofamericа", "bofa-", "boa-" }
                },
                new PhishingPattern
                {
                    TargetBrand = "Chase",
                    LegitimateDomains = new[] { "chase.com" },
                    SuspiciousPatterns = new[] { "chasе", "chase-", "chasebank" }
                }
            };
        }

        private void InitializeTrustedDomains()
        {
            _trustedDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                // 常见可信域名
                "google.com", "microsoft.com", "apple.com", "amazon.com",
                "facebook.com", "twitter.com", "linkedin.com", "github.com",
                "paypal.com", "ebay.com", "netflix.com", "spotify.com",
                "adobe.com", "mozilla.org", "cloudflare.com", "akamai.com",
                "office.com", "live.com", "outlook.com", "gmail.com",
                "yahoo.com", "bing.com", "duckduckgo.com", "wikipedia.org",
                "reddit.com", "stackoverflow.com", "w3.org", "ietf.org"
            };
        }

        private void InitializeBankingDomains()
        {
            _bankingDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                // 中国银行
                "icbc.com.cn", "boc.cn", "ccb.com", "abchina.com", "bankcomm.com",
                "psbc.com", "cmbchina.com", "spdb.com.cn", "cebbank.com",
                "cib.com.cn", "cmbc.com.cn", "citicbank.com", "cgbchina.com.cn",
                "hxb.com.cn", "pdb.com.cn", "bob.cn",
                // 国际银行
                "chase.com", "bankofamerica.com", "wellsfargo.com", "citi.com",
                "usbank.com", "pnc.com", "capitalone.com", "td.com",
                "hsbc.com", "barclays.com", "lloydsbank.com", "natwest.com",
                "deutsche-bank.de", "bnpparibas.com", "ing.com",
                // 支付平台
                "paypal.com", "stripe.com", "square.com", "venmo.com",
                "alipay.com", "wxpay.com.cn", "tenpay.com",
                // 证券
                "etrade.com", "fidelity.com", "vanguard.com", "schwab.com",
                "tdameritrade.com", "interactivebrokers.com"
            };
        }

        #endregion

        #region URL安全检测

        /// <summary>
        /// 全面URL安全检测
        /// </summary>
        public async Task<UrlSafetyResult> CheckUrlSafetyAsync(string url)
        {
            var result = new UrlSafetyResult
            {
                Url = url,
                CheckTime = DateTime.Now
            };

            try
            {
                var uri = new Uri(url);
                var host = uri.Host.ToLower();

                // 1. 基础检查
                result.BasicCheck = PerformBasicCheck(url);

                // 2. 域名分析
                result.DomainAnalysis = AnalyzeDomain(host);

                // 3. SSL证书检查
                if (uri.Scheme == "https")
                {
                    result.SslCheck = await CheckSslCertificateAsync(host, uri.Port);
                }

                // 4. 钓鱼检测
                result.PhishingCheck = DetectPhishing(host, url);

                // 5. 追踪器检测
                result.TrackerCheck = DetectTrackers(url);

                // 6. 广告检测
                result.AdCheck = DetectAds(url);

                // 7. 恶意脚本检测
                result.ScriptCheck = DetectMaliciousScripts(url);

                // 8. 云端信誉查询
                result.CloudReputation = await QueryCloudReputationAsync(url);

                // 计算综合评分
                CalculateOverallScore(result);

                // 触发威胁告警
                if (result.OverallRiskLevel >= RiskLevel.High)
                {
                    ThreatDetected?.Invoke(this, new ThreatDetectedEventArgs
                    {
                        Url = url,
                        RiskLevel = result.OverallRiskLevel,
                        Threats = result.GetAllThreats()
                    });
                }
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
                result.OverallRiskLevel = RiskLevel.Unknown;
            }

            return result;
        }

        private BasicCheckResult PerformBasicCheck(string url)
        {
            var result = new BasicCheckResult();

            try
            {
                var uri = new Uri(url);

                // HTTPS检查
                result.IsHttps = uri.Scheme == "https";
                if (!result.IsHttps)
                {
                    result.Warnings.Add("未使用HTTPS加密连接");
                }

                // 端口检查
                if (uri.Port != 80 && uri.Port != 443 && uri.Port != -1)
                {
                    result.Warnings.Add($"非标准端口: {uri.Port}");
                }

                // IP地址检查
                if (IPAddress.TryParse(uri.Host, out _))
                {
                    result.Warnings.Add("直接使用IP地址访问");
                    result.RiskScore += 20;
                }

                // URL长度检查
                if (url.Length > 2000)
                {
                    result.Warnings.Add("URL长度异常");
                    result.RiskScore += 10;
                }

                // 特殊字符检查
                var suspiciousChars = new[] { "@", "//", "\\\\", "..", "%00", "%0d", "%0a" };
                foreach (var ch in suspiciousChars)
                {
                    if (url.Contains(ch))
                    {
                        result.Warnings.Add($"URL包含可疑字符: {ch}");
                        result.RiskScore += 15;
                    }
                }

                // Punycode检查
                if (uri.Host.StartsWith("xn--"))
                {
                    result.Warnings.Add("域名使用Punycode编码，可能是钓鱼网站");
                    result.RiskScore += 30;
                }

                // 查询参数检查
                if (!string.IsNullOrEmpty(uri.Query))
                {
                    if (uri.Query.Length > 500)
                    {
                        result.Warnings.Add("查询参数过长");
                        result.RiskScore += 10;
                    }

                    // 检查可疑参数
                    var suspiciousParams = new[] { "password", "pwd", "pass", "credit", "card", "ssn", "social" };
                    foreach (var param in suspiciousParams)
                    {
                        if (uri.Query.ToLower().Contains(param))
                        {
                            result.Warnings.Add($"查询参数包含敏感词: {param}");
                            result.RiskScore += 20;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
            }

            return result;
        }

        private DomainAnalysisResult AnalyzeDomain(string domain)
        {
            var result = new DomainAnalysisResult
            {
                Domain = domain
            };

            try
            {
                // 检查是否在黑名单
                var blacklist = GetBlacklistedDomains();
                foreach (var blocked in blacklist)
                {
                    if (domain.Contains(blocked.ToLower()))
                    {
                        result.IsBlacklisted = true;
                        result.BlacklistMatch = blocked;
                        result.RiskScore += 50;
                    }
                }

                // 检查是否在可信列表
                result.IsTrusted = _trustedDomains.Contains(domain);

                // 检查是否是钓鱼域名
                if (_knownPhishingDomains.Contains(domain))
                {
                    result.IsKnownPhishing = true;
                    result.RiskScore += 100;
                }

                // 域名年龄估算（简化实现）
                result.EstimatedDomainAge = EstimateDomainAge(domain);
                if (result.EstimatedDomainAge < 30)
                {
                    result.Warnings.Add("域名注册时间较短");
                    result.RiskScore += 15;
                }

                // 检查可疑模式
                result.SuspiciousPatterns = FindSuspiciousPatterns(domain);
                result.RiskScore += result.SuspiciousPatterns.Count * 10;

                // 子域名检查
                var parts = domain.Split('.');
                if (parts.Length > 4)
                {
                    result.Warnings.Add("子域名层级过多");
                    result.RiskScore += 10;
                }

                // 检查免费域名
                var freeTlds = new[] { ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".xyz", ".top", ".click" };
                foreach (var tld in freeTlds)
                {
                    if (domain.EndsWith(tld))
                    {
                        result.IsFreeTld = true;
                        result.Warnings.Add($"使用免费顶级域名: {tld}");
                        result.RiskScore += 15;
                        break;
                    }
                }

                // 检查数字替换
                var homoglyphs = DetectHomoglyphs(domain);
                if (homoglyphs.Count > 0)
                {
                    result.HomoglyphsDetected = homoglyphs;
                    result.RiskScore += homoglyphs.Count * 20;
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecureBrowserService.cs 捕获异常", ex.Message); }

            return result;
        }

        private async Task<SslCheckResult> CheckSslCertificateAsync(string host, int port)
        {
            var result = new SslCheckResult();

            try
            {
                using (var client = new TcpClient())
                {
                    var connectTask = client.ConnectAsync(host, port);
                    await Task.WhenAny(connectTask, Task.Delay(5000));

                    if (!client.Connected)
                    {
                        result.ConnectionFailed = true;
                        return result;
                    }

                    using (var sslStream = new SslStream(client.GetStream(), false, ValidateServerCertificate))
                    {
                        await sslStream.AuthenticateAsClientAsync(host, null, System.Security.Authentication.SslProtocols.None, false);

                        var cert = sslStream.RemoteCertificate as X509Certificate2;
                        if (cert != null)
                        {
                            result.HasCertificate = true;
                            result.Issuer = cert.Issuer;
                            result.Subject = cert.Subject;
                            result.ValidFrom = cert.NotBefore;
                            result.ValidTo = cert.NotAfter;
                            result.DaysUntilExpiry = (cert.NotAfter - DateTime.Now).Days;

                            // 检查证书是否过期
                            if (DateTime.Now > cert.NotAfter)
                            {
                                result.IsExpired = true;
                                result.RiskScore += 30;
                            }
                            else if (result.DaysUntilExpiry < 30)
                            {
                                result.Warnings.Add($"证书即将过期（{result.DaysUntilExpiry}天后）");
                                result.RiskScore += 10;
                            }

                            // 检查自签名证书
                            if (cert.Issuer == cert.Subject)
                            {
                                result.IsSelfSigned = true;
                                result.Warnings.Add("自签名证书");
                                result.RiskScore += 20;
                            }

                            // 检查证书链
                            var chain = new X509Chain();
                            chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
                            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;

                            if (!chain.Build(cert))
                            {
                                result.ChainIsValid = false;
                                result.ChainErrors = chain.ChainStatus.Select(s => s.StatusInformation).ToList();
                                result.RiskScore += 25;
                            }
                            else
                            {
                                result.ChainIsValid = true;
                            }

                            // 检查证书透明性
                            result.SupportsCT = CheckCertificateTransparency(cert);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
                result.RiskScore += 20;
            }

            return result;
        }

        private bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            return true; // 允许所有证书，我们自己验证
        }

        private bool CheckCertificateTransparency(X509Certificate2 cert)
        {
            // 检查证书透明性扩展
            foreach (var ext in cert.Extensions)
            {
                if (ext.Oid.Value == "1.3.6.1.4.1.11129.2.4.2") // CT SCT OID
                {
                    return true;
                }
            }
            return false;
        }

        private PhishingCheckResult DetectPhishing(string domain, string url)
        {
            var result = new PhishingCheckResult();

            // 检查品牌钓鱼
            foreach (var pattern in _phishingPatterns)
            {
                // 检查是否是合法域名
                if (pattern.LegitimateDomains.Any(d => domain.Equals(d, StringComparison.OrdinalIgnoreCase) || domain.EndsWith("." + d)))
                {
                    continue; // 是合法域名，跳过
                }

                // 检查可疑模式
                foreach (var suspicious in pattern.SuspiciousPatterns)
                {
                    if (domain.Contains(suspicious, StringComparison.OrdinalIgnoreCase))
                    {
                        result.DetectedPhishing = true;
                        result.TargetBrand = pattern.TargetBrand;
                        result.MatchPattern = suspicious;
                        result.RiskScore += 80;
                        result.Warnings.Add($"疑似钓鱼网站，模仿品牌: {pattern.TargetBrand}");

                        PhishingDetected?.Invoke(this, new PhishingDetectedEventArgs
                        {
                            Domain = domain,
                            TargetBrand = pattern.TargetBrand,
                            MatchPattern = suspicious
                        });
                    }
                }

                // 检查域名变体
                foreach (var legitimateDomain in pattern.LegitimateDomains)
                {
                    var similarity = CalculateDomainSimilarity(domain, legitimateDomain);
                    if (similarity > 0.7 && similarity < 1.0)
                    {
                        result.DomainSimilarity = similarity;
                        result.SimilarToDomain = legitimateDomain;
                        result.RiskScore += (int)(similarity * 50);
                        result.Warnings.Add($"域名与{legitimateDomain}相似度: {similarity:P}");
                    }
                }
            }

            // 检查URL特征
            if (url.ToLower().Contains("login") || url.ToLower().Contains("signin") || url.ToLower().Contains("verify"))
            {
                result.SuspiciousKeywords.Add("login/signin/verify");
                result.RiskScore += 10;
            }

            // 检查表单目标
            if (url.ToLower().Contains("password") || url.ToLower().Contains("credential"))
            {
                result.RequestsSensitiveInfo = true;
                result.RiskScore += 20;
            }

            return result;
        }

        private double CalculateDomainSimilarity(string domain1, string domain2)
        {
            // Levenshtein距离
            int n = domain1.Length;
            int m = domain2.Length;
            int[,] d = new int[n + 1, m + 1];

            if (n == 0) return m == 0 ? 1 : 0;
            if (m == 0) return 0;

            for (int i = 0; i <= n; d[i, 0] = i++) ;
            for (int j = 0; j <= m; d[0, j] = j++) ;

            for (int i = 1; i <= n; i++)
            {
                for (int j = 1; j <= m; j++)
                {
                    int cost = domain1[i - 1] == domain2[j - 1] ? 0 : 1;
                    d[i, j] = Math.Min(
                        Math.Min(d[i - 1, j] + 1, d[i, j - 1] + 1),
                        d[i - 1, j - 1] + cost);
                }
            }

            int maxLen = Math.Max(n, m);
            return 1.0 - (double)d[n, m] / maxLen;
        }

        private TrackerCheckResult DetectTrackers(string url)
        {
            var result = new TrackerCheckResult();

            foreach (var pattern in _trackerPatterns)
            {
                foreach (var p in pattern.Patterns)
                {
                    if (url.Contains(p, StringComparison.OrdinalIgnoreCase))
                    {
                        result.DetectedTrackers.Add(new DetectedTracker
                        {
                            Name = pattern.Name,
                            Category = pattern.Category,
                            MatchPattern = p
                        });
                    }
                }
            }

            result.TrackerCount = result.DetectedTrackers.Count;
            if (result.TrackerCount > 0)
            {
                result.RiskScore = Math.Min(result.TrackerCount * 5, 30);
            }

            return result;
        }

        private AdCheckResult DetectAds(string url)
        {
            var result = new AdCheckResult();

            foreach (var rule in _adBlockRules)
            {
                if (MatchPattern(url, rule.Pattern))
                {
                    result.BlockedItems.Add(new BlockedItem
                    {
                        Pattern = rule.Pattern,
                        Type = rule.Type.ToString()
                    });
                }
            }

            result.AdCount = result.BlockedItems.Count(i => i.Type == "AdNetwork");
            result.TrackerCount = result.BlockedItems.Count(i => i.Type == "Tracker");
            result.PopupCount = result.BlockedItems.Count(i => i.Type == "Popup");

            return result;
        }

        private bool MatchPattern(string url, string pattern)
        {
            var regex = "^" + pattern.Replace("*", ".*").Replace("?", ".") + "$";
            return Regex.IsMatch(url, regex, RegexOptions.IgnoreCase);
        }

        private ScriptCheckResult DetectMaliciousScripts(string url)
        {
            var result = new ScriptCheckResult();

            // 检查XSS模式
            var xssPatterns = new[]
            {
                @"<script", @"javascript:", @"onerror=", @"onload=", @"onclick=",
                @"eval\(", @"document\.write", @"innerHTML", @"\.innerHTML\s*=",
                @"document\.cookie", @"window\.location", @"\.href\s*="
            };

            foreach (var pattern in xssPatterns)
            {
                if (Regex.IsMatch(url, pattern, RegexOptions.IgnoreCase))
                {
                    result.XssPatterns.Add(pattern);
                    result.RiskScore += 20;
                }
            }

            // 检查点击劫持相关
            if (url.Contains("frame") || url.Contains("iframe"))
            {
                result.PotentialClickjacking = true;
                result.RiskScore += 10;
            }

            return result;
        }

        private async Task<CloudReputationResult> QueryCloudReputationAsync(string url)
        {
            var result = new CloudReputationResult();

            try
            {
                var uri = new Uri(url);
                var host = uri.Host.ToLower();
                var hash = ComputeUrlHash(url);

                // 检查缓存
                if (_reputationCache.TryGetValue(hash, out var cached))
                {
                    if (DateTime.Now - cached.Timestamp < TimeSpan.FromHours(1))
                    {
                        return cached.Result;
                    }
                }

                // 模拟云端查询（实际应用中连接真实的威胁情报API）
                // 如 Google Safe Browsing, PhishTank, VirusTotal 等

                result.QueryTime = DateTime.Now;
                result.IsQueried = true;

                // 基于本地数据库的简化判断
                result.Reputation = (int)DetermineReputation(host);
                result.Confidence = 0.8;

                // 缓存结果
                _reputationCache[hash] = new UrlReputationCache
                {
                    Timestamp = DateTime.Now,
                    Result = result
                };
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
            }

            return result;
        }

        private string ComputeUrlHash(string url)
        {
            using (var sha256 = SHA256.Create())
            {
                var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(url));
                return Convert.ToBase64String(bytes);
            }
        }

        private UrlReputation DetermineReputation(string host)
        {
            if (_trustedDomains.Contains(host))
                return UrlReputation.Safe;

            if (_knownPhishingDomains.Contains(host))
                return UrlReputation.Malicious;

            if (_bankingDomains.Contains(host))
                return UrlReputation.TrustedFinancial;

            // 检查可疑模式
            if (FindSuspiciousPatterns(host).Any())
                return UrlReputation.Suspicious;

            return UrlReputation.Unknown;
        }

        private void CalculateOverallScore(UrlSafetyResult result)
        {
            int totalRisk = 0;

            totalRisk += result.BasicCheck?.RiskScore ?? 0;
            totalRisk += result.DomainAnalysis?.RiskScore ?? 0;
            totalRisk += result.SslCheck?.RiskScore ?? 0;
            totalRisk += result.PhishingCheck?.RiskScore ?? 0;
            totalRisk += result.TrackerCheck?.RiskScore ?? 0;
            totalRisk += result.ScriptCheck?.RiskScore ?? 0;

            result.TotalRiskScore = Math.Min(totalRisk, 100);

            if (totalRisk >= 70)
                result.OverallRiskLevel = RiskLevel.Critical;
            else if (totalRisk >= 50)
                result.OverallRiskLevel = RiskLevel.High;
            else if (totalRisk >= 30)
                result.OverallRiskLevel = RiskLevel.Medium;
            else if (totalRisk >= 10)
                result.OverallRiskLevel = RiskLevel.Low;
            else
                result.OverallRiskLevel = RiskLevel.Safe;

            result.SafeScore = 100 - result.TotalRiskScore;
            result.IsSafe = result.OverallRiskLevel <= RiskLevel.Low;
        }

        #endregion

        #region 辅助方法

        private List<string> FindSuspiciousPatterns(string domain)
        {
            var patterns = new List<string>();

            // 长数字串
            if (Regex.IsMatch(domain, @"\d{6,}"))
                patterns.Add("长数字串");

            // 超长字母串
            if (Regex.IsMatch(domain, @"[a-z]{15,}", RegexOptions.IgnoreCase))
                patterns.Add("超长字母串");

            // 连续数字分隔符
            if (Regex.IsMatch(domain, @"-\d+-"))
                patterns.Add("数字分隔符");

            // 多个连字符
            if (Regex.Matches(domain, "-").Count > 3)
                patterns.Add("多个连字符");

            return patterns;
        }

        private int EstimateDomainAge(string domain)
        {
            // 简化实现：基于缓存中的数据或默认值
            if (_domainCache.TryGetValue(domain, out var info))
            {
                return info.EstimatedAge;
            }

            // 默认返回一个假设值（实际应通过WHOIS查询）
            return 365; // 假设1年
        }

        private List<string> DetectHomoglyphs(string domain)
        {
            var homoglyphs = new List<string>();

            // 常见的字符替换
            var substitutions = new Dictionary<char, char>
            {
                {'a', 'а'}, // 西里尔字母a
                {'c', 'с'}, // 西里尔字母c
                {'e', 'е'}, // 西里尔字母e
                {'o', 'о'}, // 西里尔字母o
                {'p', 'р'}, // 西里尔字母p
                {'x', 'х'}, // 西里尔字母x
                {'y', 'у'}, // 西里尔字母y
                {'0', 'о'},
                {'1', 'l'},
                {'i', 'l'}
            };

            foreach (var kvp in substitutions)
            {
                if (domain.Contains(kvp.Value))
                {
                    homoglyphs.Add($"检测到视觉欺骗字符: {kvp.Value} -> {kvp.Key}");
                }
            }

            return homoglyphs;
        }

        #endregion

        #region 黑名单管理

        public List<string> GetBlacklistedDomains()
        {
            var domains = new List<string>();

            try
            {
                var blacklistFile = Path.Combine(_configPath, "blacklist.txt");
                if (File.Exists(blacklistFile))
                {
                    domains.AddRange(File.ReadAllLines(blacklistFile)
                        .Where(line => !string.IsNullOrWhiteSpace(line) && !line.StartsWith("#")));
                }

                domains.AddRange(_knownPhishingDomains);
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecureBrowserService.cs 捕获异常", ex.Message); }

            return domains.Distinct().ToList();
        }

        public bool IsUrlSafe(string url)
        {
            var result = CheckUrlSafetyAsync(url).Result;
            return result.IsSafe;
        }

        public UrlCheckResult CheckUrl(string url)
        {
            var fullResult = CheckUrlSafetyAsync(url).Result;

            return new UrlCheckResult
            {
                Url = url,
                Domain = fullResult.DomainAnalysis?.Domain,
                Protocol = new Uri(url).Scheme,
                IsSafe = fullResult.IsSafe,
                RiskLevel = (int)fullResult.OverallRiskLevel,
                SafeScore = fullResult.SafeScore,
                Warnings = fullResult.GetAllWarnings(),
                Threats = fullResult.GetAllThreats()
            };
        }

        public void AddToBlacklist(string domain)
        {
            try
            {
                var blacklistFile = Path.Combine(_configPath, "blacklist.txt");
                var domains = new HashSet<string>();

                if (File.Exists(blacklistFile))
                {
                    domains = new HashSet<string>(
                        File.ReadAllLines(blacklistFile)
                            .Where(l => !string.IsNullOrWhiteSpace(l)));
                }

                domains.Add(domain);
                File.WriteAllLines(blacklistFile, domains);

                _knownPhishingDomains.Add(domain);
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecureBrowserService.cs 捕获异常", ex.Message); }
        }

        public void RemoveFromBlacklist(string domain)
        {
            try
            {
                var blacklistFile = Path.Combine(_configPath, "blacklist.txt");
                if (File.Exists(blacklistFile))
                {
                    var domains = File.ReadAllLines(blacklistFile)
                        .Where(l => l.Trim().ToLower() != domain.Trim().ToLower())
                        .ToList();
                    File.WriteAllLines(blacklistFile, domains);
                }

                _knownPhishingDomains.Remove(domain);
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecureBrowserService.cs 捕获异常", ex.Message); }
        }

        #endregion

        #region 网银保护

        public bool IsBankingSite(string url)
        {
            try
            {
                var uri = new Uri(url);
                return _bankingDomains.Contains(uri.Host.ToLower()) ||
                       _bankingDomains.Any(d => uri.Host.ToLower().EndsWith("." + d));
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecureBrowserService.cs 捕获异常", ex.Message); }

            return false;
        }

        public void EnableBankingProtection(string domain)
        {
            _bankingProtectionActive = true;
            _currentBankingDomain = domain;
        }

        public void DisableBankingProtection()
        {
            _bankingProtectionActive = false;
            _currentBankingDomain = null;
        }

        public BankingProtectionStatus GetBankingProtectionStatus()
        {
            return new BankingProtectionStatus
            {
                IsActive = _bankingProtectionActive,
                CurrentDomain = _currentBankingDomain,
                ProtectedDomains = _bankingDomains.ToList()
            };
        }

        #endregion

        #region Hosts文件管理

        public void AddToHostsFile(string domain)
        {
            try
            {
                var entry = $"\n127.0.0.1 {domain}  # FireAntivirus Blocked";
                File.AppendAllText(_hostsPath, entry);
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecureBrowserService.cs 捕获异常", ex.Message); }
        }

        public void RemoveFromHostsFile(string domain)
        {
            try
            {
                if (File.Exists(_hostsPath))
                {
                    var lines = File.ReadAllLines(_hostsPath)
                        .Where(l => !l.Contains(domain) || !l.Contains("FireAntivirus"))
                        .ToArray();
                    File.WriteAllLines(_hostsPath, lines);
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecureBrowserService.cs 捕获异常", ex.Message); }
        }

        #endregion

        #region 浏览器设置

        public BrowserSettings GetBrowserSettings()
        {
            var settings = new BrowserSettings();

            try
            {
                using (var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings"))
                {
                    if (key != null)
                    {
                        settings.ProxyEnabled = (int?)key.GetValue("ProxyEnable") == 1;
                        settings.ProxyServer = key.GetValue("ProxyServer")?.ToString();
                    }
                }

                using (var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Internet Explorer\New Windows"))
                {
                    if (key != null)
                    {
                        settings.PopupBlockerEnabled = (int?)key.GetValue("PopupMgr") == 1;
                    }
                }

                using (var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Internet Explorer\Privacy"))
                {
                    if (key != null)
                    {
                        var privacy = (int?)key.GetValue("PrivacySetting") ?? 2;
                        settings.PrivacyLevel = privacy;
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecureBrowserService.cs 捕获异常", ex.Message); }

            return settings;
        }

        public void ApplyBrowserSettings(BrowserSettings settings)
        {
            try
            {
                using (var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings", true))
                {
                    if (key != null)
                    {
                        key.SetValue("ProxyEnable", settings.ProxyEnabled ? 1 : 0);
                        if (settings.ProxyEnabled && !string.IsNullOrEmpty(settings.ProxyServer))
                        {
                            key.SetValue("ProxyServer", settings.ProxyServer);
                        }
                    }
                }

                using (var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Internet Explorer\New Windows", true))
                {
                    if (key != null)
                    {
                        key.SetValue("PopupMgr", settings.PopupBlockerEnabled ? 1 : 0);
                    }
                }

                using (var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Internet Explorer\Privacy", true))
                {
                    if (key != null)
                    {
                        key.SetValue("PrivacySetting", settings.PrivacyLevel);
                    }
                }

                if (settings.ClearCacheOnExit)
                {
                    using (var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings\Cache", true))
                    {
                        key?.SetValue("Persistent", 0);
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecureBrowserService.cs 捕获异常", ex.Message); }
        }

        #endregion

        #region 浏览器历史和缓存

        public List<BrowserHistoryItem> GetBrowserHistory()
        {
            var history = new List<BrowserHistoryItem>();

            try
            {
                var historyPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    @"Microsoft\Windows\History");

                if (Directory.Exists(historyPath))
                {
                    foreach (var file in Directory.GetFiles(historyPath, "*.url", SearchOption.AllDirectories))
                    {
                        try
                        {
                            var content = File.ReadAllLines(file);
                            var urlLine = content.FirstOrDefault(l => l.StartsWith("URL="));
                            if (urlLine != null)
                            {
                                history.Add(new BrowserHistoryItem
                                {
                                    Url = urlLine.Substring(4),
                                    Title = Path.GetFileNameWithoutExtension(file),
                                    VisitTime = File.GetLastWriteTime(file)
                                });
                            }
                        }
                        catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecureBrowserService.cs 捕获异常", ex.Message); }
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecureBrowserService.cs 捕获异常", ex.Message); }

            return history.OrderByDescending(h => h.VisitTime).Take(100).ToList();
        }

        public void ClearBrowserCache()
        {
            try
            {
                var paths = new[]
                {
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Microsoft\Windows\INetCache"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Microsoft\Windows\Temporary Internet Files"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Microsoft\Windows\INetCookies")
                };

                foreach (var path in paths)
                {
                    if (Directory.Exists(path))
                    {
                        foreach (var file in Directory.GetFiles(path, "*.*", SearchOption.AllDirectories))
                        {
                            try { File.Delete(file); } catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecureBrowserService.cs 捕获异常", ex.Message); }
                        }
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecureBrowserService.cs 捕获异常", ex.Message); }
        }

        #endregion
    }

    #region 数据模型

    public enum UrlReputation
    {
        Safe,
        Trusted,
        TrustedFinancial,
        Unknown,
        Suspicious,
        Malicious
    }

    public enum BlockType
    {
        AdNetwork,
        Tracker,
        Popup,
        Malware
    }

    public class UrlSafetyResult
    {
        public string Url { get; set; }
        public DateTime CheckTime { get; set; }
        public BasicCheckResult BasicCheck { get; set; }
        public DomainAnalysisResult DomainAnalysis { get; set; }
        public SslCheckResult SslCheck { get; set; }
        public PhishingCheckResult PhishingCheck { get; set; }
        public TrackerCheckResult TrackerCheck { get; set; }
        public AdCheckResult AdCheck { get; set; }
        public ScriptCheckResult ScriptCheck { get; set; }
        public CloudReputationResult CloudReputation { get; set; }

        public int TotalRiskScore { get; set; }
        public int SafeScore { get; set; }
        public RiskLevel OverallRiskLevel { get; set; }
        public bool IsSafe { get; set; }
        public string Error { get; set; }

        public List<string> GetAllWarnings()
        {
            var warnings = new List<string>();
            warnings.AddRange(BasicCheck?.Warnings ?? new List<string>());
            warnings.AddRange(DomainAnalysis?.Warnings ?? new List<string>());
            warnings.AddRange(SslCheck?.Warnings ?? new List<string>());
            warnings.AddRange(PhishingCheck?.Warnings ?? new List<string>());
            return warnings;
        }

        public List<string> GetAllThreats()
        {
            var threats = new List<string>();
            if (DomainAnalysis?.IsBlacklisted == true)
                threats.Add($"域名在黑名单中: {DomainAnalysis.BlacklistMatch}");
            if (DomainAnalysis?.IsKnownPhishing == true)
                threats.Add("已知钓鱼域名");
            if (PhishingCheck?.DetectedPhishing == true)
                threats.Add($"疑似钓鱼网站，目标品牌: {PhishingCheck.TargetBrand}");
            if (SslCheck?.IsExpired == true)
                threats.Add("SSL证书已过期");
            if (SslCheck?.IsSelfSigned == true)
                threats.Add("自签名SSL证书");
            return threats;
        }
    }

    public class BasicCheckResult
    {
        public bool IsHttps { get; set; }
        public int RiskScore { get; set; }
        public List<string> Warnings { get; set; } = new List<string>();
        public string Error { get; set; }
    }

    public class DomainAnalysisResult
    {
        public string Domain { get; set; }
        public bool IsBlacklisted { get; set; }
        public string BlacklistMatch { get; set; }
        public bool IsTrusted { get; set; }
        public bool IsKnownPhishing { get; set; }
        public bool IsFreeTld { get; set; }
        public int EstimatedDomainAge { get; set; }
        public List<string> SuspiciousPatterns { get; set; } = new List<string>();
        public List<string> HomoglyphsDetected { get; set; } = new List<string>();
        public int RiskScore { get; set; }
        public List<string> Warnings { get; set; } = new List<string>();
    }

    public class SslCheckResult
    {
        public bool HasCertificate { get; set; }
        public bool ConnectionFailed { get; set; }
        public string Issuer { get; set; }
        public string Subject { get; set; }
        public DateTime ValidFrom { get; set; }
        public DateTime ValidTo { get; set; }
        public int DaysUntilExpiry { get; set; }
        public bool IsExpired { get; set; }
        public bool IsSelfSigned { get; set; }
        public bool ChainIsValid { get; set; }
        public List<string> ChainErrors { get; set; } = new List<string>();
        public bool SupportsCT { get; set; }
        public int RiskScore { get; set; }
        public List<string> Warnings { get; set; } = new List<string>();
        public string Error { get; set; }
    }

    public class PhishingCheckResult
    {
        public bool DetectedPhishing { get; set; }
        public string TargetBrand { get; set; }
        public string MatchPattern { get; set; }
        public double DomainSimilarity { get; set; }
        public string SimilarToDomain { get; set; }
        public bool RequestsSensitiveInfo { get; set; }
        public List<string> SuspiciousKeywords { get; set; } = new List<string>();
        public int RiskScore { get; set; }
        public List<string> Warnings { get; set; } = new List<string>();
    }

    public class TrackerCheckResult
    {
        public List<DetectedTracker> DetectedTrackers { get; set; } = new List<DetectedTracker>();
        public int TrackerCount { get; set; }
        public int RiskScore { get; set; }
    }

    public class DetectedTracker
    {
        public string Name { get; set; }
        public string Category { get; set; }
        public string MatchPattern { get; set; }
    }

    public class AdCheckResult
    {
        public List<BlockedItem> BlockedItems { get; set; } = new List<BlockedItem>();
        public int AdCount { get; set; }
        public int TrackerCount { get; set; }
        public int PopupCount { get; set; }
    }

    public class BlockedItem
    {
        public string Pattern { get; set; }
        public string Type { get; set; }
    }

    public class ScriptCheckResult
    {
        public List<string> XssPatterns { get; set; } = new List<string>();
        public bool PotentialClickjacking { get; set; }
        public int RiskScore { get; set; }
    }

    public class AdBlockRule
    {
        public string Pattern { get; set; }
        public BlockType Type { get; set; }
    }

    public class TrackerPattern
    {
        public string Name { get; set; }
        public string[] Patterns { get; set; }
        public string Category { get; set; }
    }

    public class PhishingPattern
    {
        public string TargetBrand { get; set; }
        public string[] LegitimateDomains { get; set; }
        public string[] SuspiciousPatterns { get; set; }
    }

    public class UrlReputationCache
    {
        public DateTime Timestamp { get; set; }
        public CloudReputationResult Result { get; set; }
    }

    public class PhishingDetectedEventArgs : EventArgs
    {
        public string Domain { get; set; }
        public string TargetBrand { get; set; }
        public string MatchPattern { get; set; }
    }

    public class SslWarningEventArgs : EventArgs
    {
        public string Domain { get; set; }
        public string Warning { get; set; }
        public int RiskScore { get; set; }
    }

    public class BankingProtectionStatus
    {
        public bool IsActive { get; set; }
        public string CurrentDomain { get; set; }
        public List<string> ProtectedDomains { get; set; }
    }

    public class UrlCheckResult
    {
        public string Url { get; set; }
        public string Domain { get; set; }
        public string Protocol { get; set; }
        public bool IsSafe { get; set; }
        public int RiskLevel { get; set; }
        public int SafeScore { get; set; }
        public List<string> Warnings { get; set; } = new List<string>();
        public List<string> Threats { get; set; } = new List<string>();
    }

    public class BrowserSettings
    {
        public bool ProxyEnabled { get; set; }
        public string ProxyServer { get; set; }
        public bool PopupBlockerEnabled { get; set; } = true;
        public int PrivacyLevel { get; set; } = 2;
        public bool ClearCacheOnExit { get; set; }
        public bool BlockThirdPartyCookies { get; set; } = true;
        public bool DoNotTrack { get; set; } = true;
    }

    public class BrowserHistoryItem
    {
        public string Url { get; set; }
        public string Title { get; set; }
        public DateTime VisitTime { get; set; }
    }

    #endregion
}
