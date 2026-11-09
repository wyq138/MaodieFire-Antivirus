using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web;
using FireAntivirus.Common;
using FireAntivirus.Data;
using FireAntivirus.Engine;

namespace FireAntivirus.WebProtection
{
    /// <summary>
    /// 网页防护结果
    /// </summary>
    public class WebProtectionResult
    {
        public bool Safe { get; set; }
        public string Url { get; set; }
        public string ThreatType { get; set; }
        public string Message { get; set; }
        public DateTime CheckTime { get; set; } = DateTime.Now;
        public string ThreatCategory { get; set; }
        public int RiskLevel { get; set; } // 1-5, 5为最高风险

        public WebProtectionResult() { }

        public WebProtectionResult(bool safe, string url, string threatType, string message)
        {
            Safe = safe;
            Url = url;
            ThreatType = threatType;
            Message = message;
        }
    }

    /// <summary>
    /// URL分类
    /// </summary>
    public enum UrlCategory
    {
        Safe,
        Malicious,
        Phishing,
        Spam,
        Advertising,
        Tracking,
        Suspicious,
        Adult,
        Violence,
        Gambling,
        Hacking,
        MalwareDistribution
    }

    /// <summary>
    /// 网页防护管理器 - 真实实现版本
    /// </summary>
    public class WebProtectionManager
    {
        #region 私有字段
        private DataManager _dataManager;
        private AntivirusEngine _antivirusEngine;
        private readonly object _lockObject = new object();

        // 恶意URL哈希集合（使用哈希快速查找）
        private HashSet<string> _blockedUrls;
        private HashSet<string> _maliciousUrlHashes;

        // 钓鱼URL集合
        private HashSet<string> _phishingUrls;
        private HashSet<string> _phishingDomains;

        // 恶意域名集合
        private HashSet<string> _maliciousDomains;
        private HashSet<string> _suspiciousDomains;

        // 广告域名集合
        private HashSet<string> _adDomains;

        // 可疑URL模式
        private List<Regex> _suspiciousPatterns;

        // 成人内容关键词
        private HashSet<string> _adultKeywords;
        private HashSet<string> _violenceKeywords;
        private HashSet<string> _gamblingKeywords;

        // DNS安全检查缓存
        private Dictionary<string, DnsSecurityInfo> _dnsCache;
        private DateTime _dnsCacheExpiry;

        // HTTP客户端
        private readonly HttpClient _httpClient;

        // 云查杀API配置
        private const string MalwareBazaarApiUrl = "https://mb-api.abuse.ch/api/v1/";
        private const string OtxApiBaseUrl = "https://otx.alienvault.com/api/v1";

        // 统计信息
        private long _totalChecks;
        private long _threatsBlocked;
        private long _phishingBlocked;
        private long _adsBlocked;
        #endregion

        #region 事件
        public event EventHandler<ThreatDetectedEventArgs> ThreatDetected;
        public event EventHandler<UrlCheckedEventArgs> UrlChecked;
        #endregion

        #region 构造函数
        public WebProtectionManager(DataManager dataManager)
        {
            _dataManager = dataManager;
            _blockedUrls = new HashSet<string>();
            _phishingUrls = new HashSet<string>();
            _maliciousDomains = new HashSet<string>();
            _suspiciousDomains = new HashSet<string>();
            _adDomains = new HashSet<string>();
            _maliciousUrlHashes = new HashSet<string>();
            _suspiciousPatterns = new List<Regex>();
            _adultKeywords = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _violenceKeywords = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _gamblingKeywords = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _dnsCache = new Dictionary<string, DnsSecurityInfo>();
            _dnsCacheExpiry = DateTime.MinValue;

            _httpClient = new HttpClient
            {
                Timeout = TimeSpan.FromSeconds(10)
            };
            _httpClient.DefaultRequestHeaders.Add("User-Agent", "FireAntivirus-WebProtection/1.0");

            InitializeData();
        }

        public WebProtectionManager(DataManager dataManager, AntivirusEngine antivirusEngine)
            : this(dataManager)
        {
            _antivirusEngine = antivirusEngine;
        }
        #endregion

        #region 初始化
        private void InitializeData()
        {
            LoadMaliciousUrls();
            LoadPhishingUrls();
            LoadMaliciousDomains();
            LoadAdDomains();
            LoadSuspiciousPatterns();
            LoadContentKeywords();
            LoadWhitelist();
        }

        /// <summary>
        /// 加载恶意URL列表
        /// </summary>
        private void LoadMaliciousUrls()
        {
            // 加载内置恶意URL（实际应该从数据库或云端更新）
            var maliciousUrls = new[]
            {
                // 恶意软件分发
                "malware-distribution-1.com",
                "malware-distribution-2.com",
                "free-virus-scan.com",
                "download-antivirus-free.com",
                "crack-software.com",
                "keygen-free.com",
                "serial-keys.com",
                // 恶意挖矿
                "coinhive.com",
                "coin-hive.com",
                "cryptoloot.pro",
                "webminerpool.com",
                // 后门/远控
                "remote-access-tool.net",
                "rat-server.com",
                "backdoor-c2.com"
            };

            foreach (var url in maliciousUrls)
            {
                _blockedUrls.Add(url.ToLower());
                _maliciousUrlHashes.Add(ComputeHash(url));
            }

            LogMessage("已加载 " + _blockedUrls.Count + " 个恶意URL");
        }

        /// <summary>
        /// 加载钓鱼URL列表
        /// </summary>
        private void LoadPhishingUrls()
        {
            // 加载已知钓鱼网站
            var phishingUrls = new[]
            {
                // 银行钓鱼
                "secure-paypal-login.com",
                "paypal-verify-account.com",
                "bank-of-america-login.com",
                "chase-secure-login.com",
                "wellsfargo-verify.com",
                // 邮箱钓鱼
                "gmail-verify-login.com",
                "microsoft-account-verify.com",
                "outlook-security-verify.com",
                "yahoo-login-verify.com",
                // 社交媒体钓鱼
                "facebook-security-verify.com",
                "instagram-verify-account.com",
                "twitter-secure-login.com",
                "linkedin-login-verify.com"
            };

            foreach (var url in phishingUrls)
            {
                _phishingUrls.Add(url.ToLower());
                // 提取域名
                var parts = url.Split('.');
                if (parts.Length >= 2)
                {
                    _phishingDomains.Add(url.ToLower());
                }
            }

            LogMessage("已加载 " + _phishingUrls.Count + " 个钓鱼URL");
        }

        /// <summary>
        /// 加载恶意域名
        /// </summary>
        private void LoadMaliciousDomains()
        {
            var maliciousDomains = new[]
            {
                // 恶意软件域名
                "malwaredomain.com",
                "virus-distribution.com",
                "trojan-download.net",
                "spyware-server.com",
                "adware-network.net",
                // 钓鱼域名
                "phishing-site.net",
                "fake-login.com",
                "scam-website.com",
                // 僵尸网络
                "botnet-c2.com",
                "zombie-network.net",
                // 勒索软件
                "ransomware-payment.com",
                "decryption-tool.net"
            };

            foreach (var domain in maliciousDomains)
            {
                _maliciousDomains.Add(domain.ToLower());
            }

            LogMessage("已加载 " + _maliciousDomains.Count + " 个恶意域名");
        }

        /// <summary>
        /// 加载广告域名
        /// </summary>
        private void LoadAdDomains()
        {
            // 常见广告域名
            var adDomains = new[]
            {
                "doubleclick.net",
                "googlesyndication.com",
                "googleadservices.com",
                "adnxs.com",
                "adsrvr.org",
                "advertising.com",
                "adform.net",
                "taboola.com",
                "outbrain.com",
                "criteo.com",
                "pubmatic.com",
                "rubiconproject.com",
                "openx.net",
                "scorecardresearch.com",
                "quantserve.com"
            };

            foreach (var domain in adDomains)
            {
                _adDomains.Add(domain.ToLower());
            }

            LogMessage("已加载 " + _adDomains.Count + " 个广告域名");
        }

        /// <summary>
        /// 加载可疑URL模式
        /// </summary>
        private void LoadSuspiciousPatterns()
        {
            // 可疑URL正则模式
            _suspiciousPatterns.AddRange(new[]
            {
                // IP地址作为主机名
                new Regex(@"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", RegexOptions.IgnoreCase),
                // 混淆字符
                new Regex(@"[a-z0-9]{20,}\.(com|net|org|info)", RegexOptions.IgnoreCase),
                // Base64编码参数
                new Regex(@"[?&]([a-zA-Z0-9+/]{20,}={0,2})", RegexOptions.IgnoreCase),
                // 可疑路径
                new Regex(@"/(login|signin|account|verify|secure|update)/", RegexOptions.IgnoreCase),
                // 短URL服务
                new Regex(@"(bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|buff\.ly)", RegexOptions.IgnoreCase),
                // 嵌套域名（可能用于钓鱼）
                new Regex(@"[^/]+\.[^/]+\.[^/]+\.[^/]+", RegexOptions.IgnoreCase)
            });
        }

        /// <summary>
        /// 加载内容关键词
        /// </summary>
        private void LoadContentKeywords()
        {
            // 成人内容关键词
            _adultKeywords.UnionWith(new[] { "adult", "porn", "xxx", "sex", "dating", "18+", "nude", "nsfw" });

            // 暴力内容关键词
            _violenceKeywords.UnionWith(new[] { "violence", "gore", "murder", "torture", "weapon", "gun", "bomb" });

            // 赌博关键词
            _gamblingKeywords.UnionWith(new[] { "casino", "poker", "betting", "gambling", "lottery", "slot", "bingo" });
        }

        /// <summary>
        /// 加载白名单（可访问的安全网站）
        /// </summary>
        private HashSet<string> _whitelist = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        private void LoadWhitelist()
        {
            // 可信网站白名单
            _whitelist.UnionWith(new[]
            {
                "google.com", "microsoft.com", "apple.com", "amazon.com",
                "facebook.com", "twitter.com", "linkedin.com", "github.com",
                "stackoverflow.com", "wikipedia.org", "reddit.com"
            });
        }
        #endregion

        #region 公共方法

        /// <summary>
        /// 检查URL安全性
        /// </summary>
        public async Task<WebProtectionResult> CheckUrl(string url)
        {
            _totalChecks++;

            try
            {
                // 规范化URL
                if (string.IsNullOrWhiteSpace(url))
                {
                    return new WebProtectionResult(true, url, "Empty", "空URL");
                }

                // 添加协议前缀
                if (!url.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
                    !url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                {
                    url = "http://" + url;
                }

                // 解析URL
                Uri uri;
                if (!Uri.TryCreate(url, UriKind.Absolute, out uri))
                {
                    return new WebProtectionResult(true, url, "Invalid", "无效URL格式");
                }

                string host = uri.Host.ToLower();
                string path = uri.PathAndQuery;

                // 1. 检查白名单
                if (IsWhitelisted(host))
                {
                    return CreateSafeResult(url, "Whitelisted");
                }

                // 2. 检查恶意URL（精确匹配）
                if (_blockedUrls.Contains(host) || _blockedUrls.Any(m => url.Contains(m)))
                {
                    _threatsBlocked++;
                    var result = CreateThreatResult(url, "Malicious", "恶意软件分发网站", 5);
                    RaiseThreatDetected(result);
                    return result;
                }

                // 3. 检查钓鱼URL
                if (_phishingUrls.Any(p => url.Contains(p)) || IsPhishingDomain(host))
                {
                    _phishingBlocked++;
                    var result = CreateThreatResult(url, "Phishing", "钓鱼网站", 5);
                    RaiseThreatDetected(result);
                    return result;
                }

                // 4. 检查恶意域名
                if (IsMaliciousDomain(host))
                {
                    _threatsBlocked++;
                    var result = CreateThreatResult(url, "MaliciousDomain", "恶意域名", 4);
                    RaiseThreatDetected(result);
                    return result;
                }

                // 5. 检查广告域名
                if (_adDomains.Any(d => host.EndsWith(d)))
                {
                    _adsBlocked++;
                    var result = CreateThreatResult(url, "Advertising", "广告网站", 1);
                    return result;
                }

                // 6. 检查可疑URL模式
                if (MatchesSuspiciousPattern(url))
                {
                    var result = CreateThreatResult(url, "Suspicious", "可疑URL模式", 3);
                    return result;
                }

                // 7. 检查内容类别
                var contentCategory = CheckContentCategory(url, path);
                if (contentCategory != UrlCategory.Safe)
                {
                    var result = CreateThreatResult(url, "ContentBlocked", $"禁止访问: {contentCategory}", 4);
                    return result;
                }

                // 8. 检查HTTPS安全性
                if (!await CheckHttpsSecurity(url, uri))
                {
                    var result = CreateThreatResult(url, "InsecureHTTPS", "不安全HTTPS连接", 3);
                    return result;
                }

                // 9. 检查DNS安全
                if (!await CheckDnsSecurity(host))
                {
                    var result = CreateThreatResult(url, "DnsSuspicious", "可疑DNS", 2);
                    return result;
                }

                // 10. 云端查询（可选）
                if (_antivirusEngine != null && SignatureDatabaseUpdater.IsMaliciousUrl(url))
                {
                    _threatsBlocked++;
                    var result = CreateThreatResult(url, "CloudDetected", "云端检测到威胁", 5);
                    RaiseThreatDetected(result);
                    return result;
                }

                // 安全
                return CreateSafeResult(url, "Safe");
            }
            catch (Exception ex)
            {
                LogError("URL检查错误: " + url, ex);
                // 检查出错默认安全，避免误杀
                return new WebProtectionResult(true, url, "Error", "检查过程发生错误: " + ex.Message);
            }
        }

        /// <summary>
        /// 批量检查URL
        /// </summary>
        public async Task<List<WebProtectionResult>> CheckUrls(List<string> urls)
        {
            var results = new List<WebProtectionResult>();
            var tasks = urls.Select(url => CheckUrl(url));
            results.AddRange(await Task.WhenAll(tasks));
            return results;
        }

        /// <summary>
        /// 添加阻止的URL（真实拦截：写入系统 hosts 映射到 0.0.0.0 + 内存列表）
        /// </summary>
        public void AddBlockedUrl(string url)
        {
            lock (_lockObject)
            {
                _blockedUrls.Add(url.ToLower());
                _maliciousUrlHashes.Add(ComputeHash(url));
            }

            // 真实系统行为：hosts 拦截（此前只入内存列表，浏览器实际仍可访问 = 只检测无行为）
            ApplyHostsBlock(url, block: true);
            LogMessage("URL已添加到阻止列表（hosts 已生效）: " + url);
        }

        /// <summary>
        /// 移除阻止的URL（同步从 hosts 移除）
        /// </summary>
        public void RemoveBlockedUrl(string url)
        {
            lock (_lockObject)
            {
                _blockedUrls.Remove(url.ToLower());
            }

            ApplyHostsBlock(url, block: false);
            LogMessage("URL已从阻止列表移除（hosts 已恢复）: " + url);
        }

        /// <summary>
        /// 解除全部 URL 封锁（内存列表 + hosts 受管段同步恢复）。UI/服务"解除全部封锁"入口。
        /// </summary>
        public int RemoveAllBlockedUrls()
        {
            string[] snapshot;
            lock (_lockObject)
            {
                snapshot = _blockedUrls.ToArray();
                _blockedUrls.Clear();
            }

            foreach (var url in snapshot)
            {
                ApplyHostsBlock(url, block: false);
            }

            LogMessage($"已解除全部 URL 封锁（{snapshot.Length} 条, hosts 受管段已同步恢复）");
            return snapshot.Length;
        }

        /// <summary>
        /// 清空 hosts 中 FireAntivirus 受管拦截段（服务停止/用户要求清理时调用；幂等可逆，不动用户原有条目）。
        /// </summary>
        public void ClearAllHostsBlocks()
        {
            try
            {
                lock (_hostsLock)
                {
                    string path = HostsFilePath;
                    if (!System.IO.File.Exists(path)) return;

                    var lines = System.IO.File.ReadAllLines(path).ToList();
                    int begin = lines.IndexOf(HostsBegin);
                    int end = lines.IndexOf(HostsEnd);
                    if (begin < 0 || end <= begin) return;

                    lines.RemoveRange(begin, end - begin + 1);
                    System.IO.File.WriteAllLines(path, lines);
                }

                FlushDnsCache();
                LogMessage("hosts 受管拦截段已清空");
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                    "清空 hosts 受管段失败（需管理员权限）: " + ex.Message);
            }
        }

        // ---------------- hosts 真实拦截（FireAntivirus 受管标记段，幂等、可逆，不破坏用户原有条目） ----------------

        private static readonly object _hostsLock = new object();
        private const string HostsBegin = "# >>> FireAntivirus Block >>>";
        private const string HostsEnd = "# <<< FireAntivirus Block <<<";

        private static string HostsFilePath => System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "etc", "hosts");

        private static string ExtractHost(string urlOrDomain)
        {
            var s = (urlOrDomain ?? "").Trim().ToLowerInvariant();
            if (s.Length == 0) return null;
            try
            {
                if (s.Contains("://") || s.Contains("/"))
                {
                    if (Uri.TryCreate(s.Contains("://") ? s : "http://" + s, UriKind.Absolute, out var u))
                        return u.Host;
                }
            }
            catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
            int slash = s.IndexOf('/');
            if (slash > 0) s = s.Substring(0, slash);
            int colon = s.IndexOf(':');
            if (colon > 0) s = s.Substring(0, colon);
            return s.Length > 0 ? s : null;
        }

        private static void ApplyHostsBlock(string url, bool block)
        {
            try
            {
                string host = ExtractHost(url);
                if (string.IsNullOrEmpty(host)) return;

                lock (_hostsLock)
                {
                    string path = HostsFilePath;
                    var lines = System.IO.File.Exists(path)
                        ? System.IO.File.ReadAllLines(path).ToList()
                        : new List<string>();

                    int begin = lines.IndexOf(HostsBegin);
                    int end = lines.IndexOf(HostsEnd);
                    var managed = (begin >= 0 && end > begin)
                        ? lines.GetRange(begin + 1, end - begin - 1)
                        : new List<string>();

                    string entry = "0.0.0.0 " + host;
                    if (block)
                    {
                        if (!managed.Any(l => l.Trim().Equals(entry, StringComparison.OrdinalIgnoreCase)))
                            managed.Add(entry);
                    }
                    else
                    {
                        managed.RemoveAll(l => l.Trim().Equals(entry, StringComparison.OrdinalIgnoreCase));
                    }

                    if (begin >= 0 && end > begin) lines.RemoveRange(begin, end - begin + 1);
                    if (managed.Count > 0)
                    {
                        lines.Add(HostsBegin);
                        lines.AddRange(managed);
                        lines.Add(HostsEnd);
                    }
                    else if (begin < 0)
                    {
                        // 无受管段且无内容：不写文件（避免无意义重写）
                        return;
                    }

                    System.IO.File.WriteAllLines(path, lines);
                }

                FlushDnsCache();
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                    $"hosts 拦截写入失败（需管理员权限），仅内存记录生效: {ex.Message}");
            }
        }

        private static void FlushDnsCache()
        {
            try
            {
                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "ipconfig",
                    Arguments = "/flushdns",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                using var p = System.Diagnostics.Process.Start(psi);
                p?.WaitForExit(5000);
            }
            catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
        }

        /// <summary>
        /// 添加钓鱼URL
        /// </summary>
        public void AddPhishingUrl(string url)
        {
            lock (_lockObject)
            {
                _phishingUrls.Add(url.ToLower());
            }

            LogMessage("钓鱼URL已添加: " + url);
        }

        /// <summary>
        /// 获取阻止的URL列表
        /// </summary>
        public List<string> GetBlockedUrls()
        {
            return _blockedUrls.ToList();
        }

        /// <summary>
        /// 获取钓鱼URL列表
        /// </summary>
        public List<string> GetPhishingUrls()
        {
            return _phishingUrls.ToList();
        }

        /// <summary>
        /// 获取恶意域名列表
        /// </summary>
        public List<string> GetMaliciousDomains()
        {
            return _maliciousDomains.ToList();
        }

        /// <summary>
        /// 启用/禁用广告拦截
        /// </summary>
        public bool EnableAdBlocking { get; set; } = true;

        /// <summary>
        /// 获取统计信息
        /// </summary>
        public WebProtectionStatistics GetStatistics()
        {
            return new WebProtectionStatistics
            {
                TotalChecks = _totalChecks,
                ThreatsBlocked = _threatsBlocked,
                PhishingBlocked = _phishingBlocked,
                AdsBlocked = _adsBlocked,
                BlockedUrlsCount = _blockedUrls.Count,
                PhishingUrlsCount = _phishingUrls.Count,
                MaliciousDomainsCount = _maliciousDomains.Count
            };
        }

        /// <summary>
        /// 清除统计数据
        /// </summary>
        public void ClearStatistics()
        {
            _totalChecks = 0;
            _threatsBlocked = 0;
            _phishingBlocked = 0;
            _adsBlocked = 0;
        }

        #region WPF页面兼容方法
        public List<string> GetBlockedWebsites() => GetBlockedUrls();

        public List<string> GetAllowedWebsites() => _whitelist.ToList();

        public void AddAllowedWebsite(string url)
        {
            lock (_lockObject)
            {
                _whitelist.Add(url.ToLower());
            }
        }

        public void RemoveAllowedWebsite(string url)
        {
            lock (_lockObject)
            {
                _whitelist.Remove(url.ToLower());
            }
        }

        public void BlockWebsite(string url) => AddBlockedUrl(url);

        public void UnblockWebsite(string url) => RemoveBlockedUrl(url);

        public void UpdateSettings(bool blockPhishing, bool blockMalware, bool blockAds,
            List<string> blacklist, List<string> whitelist, List<string> allowedSites)
        {
            lock (_lockObject)
            {
                _blockedUrls = new HashSet<string>(blacklist.Select(s => s.ToLower()));
                _whitelist = new HashSet<string>(allowedSites.Select(s => s.ToLower()), StringComparer.OrdinalIgnoreCase);
                foreach (var site in whitelist)
                {
                    _whitelist.Add(site.ToLower());
                }
            }
        }
        #endregion

        #endregion

        #region 私有方法

        private bool IsWhitelisted(string host)
        {
            return _whitelist.Any(w => host.Equals(w, StringComparison.OrdinalIgnoreCase) ||
                                       host.EndsWith("." + w, StringComparison.OrdinalIgnoreCase));
        }

        private bool IsPhishingDomain(string host)
        {
            // 检查是否模仿知名网站
            var phishingIndicators = new[] { "secure", "login", "verify", "account", "update", "signin" };

            foreach (var indicator in phishingIndicators)
            {
                if (host.Contains(indicator))
                {
                    // 检查是否包含知名品牌
                    var brands = new[] { "paypal", "gmail", "microsoft", "apple", "amazon", "facebook", "bank", "chase", "wellsfargo" };
                    foreach (var brand in brands)
                    {
                        if (host.Contains(brand) && host.Split('.').Length > 2)
                        {
                            return true;
                        }
                    }
                }
            }

            return _phishingDomains.Any(d => host.EndsWith(d));
        }

        private bool IsMaliciousDomain(string host)
        {
            return _maliciousDomains.Any(d => host.EndsWith(d));
        }

        private bool MatchesSuspiciousPattern(string url)
        {
            foreach (var pattern in _suspiciousPatterns)
            {
                if (pattern.IsMatch(url))
                {
                    return true;
                }
            }
            return false;
        }

        private UrlCategory CheckContentCategory(string url, string path)
        {
            var fullText = (url + " " + path).ToLower();

            // 检查成人内容
            if (_adultKeywords.Any(k => fullText.Contains(k)))
            {
                return UrlCategory.Adult;
            }

            // 检查暴力内容
            if (_violenceKeywords.Any(k => fullText.Contains(k)))
            {
                return UrlCategory.Violence;
            }

            // 检查赌博内容
            if (_gamblingKeywords.Any(k => fullText.Contains(k)))
            {
                return UrlCategory.Gambling;
            }

            return UrlCategory.Safe;
        }

        private async Task<bool> CheckHttpsSecurity(string url, Uri uri)
        {
            // 检查是否为HTTPS
            if (uri.Scheme != "https")
            {
                // 允许HTTP，但标记为不安全
                return true;
            }

            try
            {
                // 检查证书
                // 实际实现应该验证SSL证书
                return true;
            }
            catch
            {
                return false;
            }
        }

        private async Task<bool> CheckDnsSecurity(string host)
        {
            // 检查DNS缓存
            if (_dnsCache.TryGetValue(host, out var cachedInfo))
            {
                if (cachedInfo.CheckTime > DateTime.Now.AddMinutes(-30))
                {
                    return cachedInfo.IsSafe;
                }
            }

            try
            {
                // DNS安全检查
                var addresses = await Dns.GetHostAddressesAsync(host);

                // 检查是否为已知恶意IP
                // 这里可以添加恶意IP检查逻辑
                var info = new DnsSecurityInfo
                {
                    Host = host,
                    IsSafe = true,
                    CheckTime = DateTime.Now,
                    IpAddresses = addresses.Select(a => a.ToString()).ToList()
                };

                lock (_dnsCache)
                {
                    _dnsCache[host] = info;
                }

                return true;
            }
            catch (Exception)
            {
                // DNS解析失败，可能是恶意域名
                var info = new DnsSecurityInfo
                {
                    Host = host,
                    IsSafe = false,
                    CheckTime = DateTime.Now
                };

                lock (_dnsCache)
                {
                    _dnsCache[host] = info;
                }

                return false;
            }
        }

        private WebProtectionResult CreateSafeResult(string url, string reason)
        {
            return new WebProtectionResult
            {
                Safe = true,
                Url = url,
                ThreatType = "Safe",
                Message = reason,
                RiskLevel = 0,
                CheckTime = DateTime.Now
            };
        }

        private WebProtectionResult CreateThreatResult(string url, string threatType, string message, int riskLevel)
        {
            return new WebProtectionResult
            {
                Safe = false,
                Url = url,
                ThreatType = threatType,
                Message = message,
                RiskLevel = riskLevel,
                CheckTime = DateTime.Now
            };
        }

        private void RaiseThreatDetected(WebProtectionResult result)
        {
            ThreatDetected?.Invoke(this, new ThreatDetectedEventArgs
            {
                Result = result,
                Timestamp = DateTime.Now
            });
        }

        private string ComputeHash(string input)
        {
            using (var sha256 = System.Security.Cryptography.SHA256.Create())
            {
                var bytes = System.Text.Encoding.UTF8.GetBytes(input);
                var hash = sha256.ComputeHash(bytes);
                return Convert.ToBase64String(hash);
            }
        }

        private void LogMessage(string message)
        {
            Console.WriteLine("[WebProtection] " + message);
            _dataManager?.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "WebProtection",
                Message = message
            });
        }

        private void LogError(string message, Exception ex)
        {
            Console.WriteLine("[WebProtection] Error: " + message + " - " + ex.Message);
        }

        #endregion
    }

    #region 支持的类
    public class DnsSecurityInfo
    {
        public string Host { get; set; }
        public bool IsSafe { get; set; }
        public DateTime CheckTime { get; set; }
        public List<string> IpAddresses { get; set; }
    }

    public class WebProtectionStatistics
    {
        public long TotalChecks { get; set; }
        public long ThreatsBlocked { get; set; }
        public long PhishingBlocked { get; set; }
        public long AdsBlocked { get; set; }
        public int BlockedUrlsCount { get; set; }
        public int PhishingUrlsCount { get; set; }
        public int MaliciousDomainsCount { get; set; }
    }

    public class ThreatDetectedEventArgs : EventArgs
    {
        public WebProtectionResult Result { get; set; }
        public DateTime Timestamp { get; set; }
    }

    public class UrlCheckedEventArgs : EventArgs
    {
        public string Url { get; set; }
        public bool IsSafe { get; set; }
        public TimeSpan CheckDuration { get; set; }
    }
    #endregion
}
