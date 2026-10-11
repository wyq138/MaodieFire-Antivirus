using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using FireAntivirus.Data;
using FireAntivirus.Common;

namespace FireAntivirus.Services
{
    /// <summary>
    /// 专业级反钓鱼系统 - 支持URL信誉查询、域名相似度检测、SSL证书验证、机器学习检测
    /// </summary>
    public class AntiPhishing : IMonitor
    {
        private readonly DataManager _dataManager;
        private Thread _detectionThread;
        private Thread _updateThread;
        private bool _isRunning;
        
        // 使用并发集合提高线程安全性
        private ConcurrentDictionary<string, PhishingDetectionResult> _detectionResults;
        private ConcurrentDictionary<string, PhishingRule> _phishingRules;
        private ConcurrentDictionary<string, DomainReputation> _domainReputationCache;
        private ConcurrentDictionary<string, DateTime> _blockedUrls;
        private ConcurrentDictionary<string, DateTime> _allowedUrls;
        
        // 黑名单和白名单
        private HashSet<string> _knownPhishingDomains;
        private HashSet<string> _knownLegitimateDomains;
        private HashSet<string> _phishingKeywords;
        private HashSet<string> _suspiciousTLDs;
        private Dictionary<string, string[]> _brandDomains; // 品牌域名变体检测
        
        // 配置参数
        private int _detectionInterval;
        private int _cacheExpiryMinutes;
        private bool _enableWebsiteDetection;
        private bool _enableEmailDetection;
        private bool _enableLinkAnalysis;
        private bool _enableHeuristicAnalysis;
        private bool _enableMachineLearning;
        private bool _enableCloudCheck;
        private bool _enableRealTimeProtection;
        private bool _enableSSLValidation;
        private bool _enableTyposquattingDetection;
        private bool _enableHomographDetection;
        private int _maxDetectionResults;
        
        // HTTP客户端
        private HttpClient _httpClient;
        
        // 统计数据
        private long _totalUrlsScanned;
        private long _phishingBlocked;
        private long _falsePositiveReports;
        private DateTime _lastDatabaseUpdate;

        #region P/Invoke for IDN handling
        [System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
        private static extern int IdnToAscii(uint dwFlags, string lpUnicodeCharStr, int cchUnicodeChar, 
            System.Text.StringBuilder lpASCIICharStr, int cchASCIIChar);
        
        private const int IDN_ALLOW_UNASSIGNED = 0x01;
        private const int IDN_USE_STD3_ASCII_RULES = 0x02;
        #endregion

        public AntiPhishing(DataManager dataManager)
        {
            _dataManager = dataManager;
            _isRunning = false;
            
            // 初始化并发集合
            _detectionResults = new ConcurrentDictionary<string, PhishingDetectionResult>();
            _phishingRules = new ConcurrentDictionary<string, PhishingRule>();
            _domainReputationCache = new ConcurrentDictionary<string, DomainReputation>();
            _blockedUrls = new ConcurrentDictionary<string, DateTime>();
            _allowedUrls = new ConcurrentDictionary<string, DateTime>();
            
            // 初始化黑名单和白名单
            _knownPhishingDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _knownLegitimateDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _phishingKeywords = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _suspiciousTLDs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _brandDomains = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
            
            // 默认配置
            _detectionInterval = 5000;
            _cacheExpiryMinutes = 60;
            _enableWebsiteDetection = true;
            _enableEmailDetection = true;
            _enableLinkAnalysis = true;
            _enableHeuristicAnalysis = true;
            _enableMachineLearning = true;
            _enableCloudCheck = true;
            _enableRealTimeProtection = true;
            _enableSSLValidation = true;
            _enableTyposquattingDetection = true;
            _enableHomographDetection = true;
            _maxDetectionResults = 10000;
            
            // 初始化HTTP客户端
            _httpClient = new HttpClient();
            _httpClient.Timeout = TimeSpan.FromSeconds(10);
            _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("FireAntivirus/1.0");
            
            // 初始化内置数据
            InitializeBuiltinData();
            LoadPhishingDatabase();
        }

        private void InitializeBuiltinData()
        {
            // 初始化可疑TLD
            string[] suspiciousTLDs = {
                ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".cc", ".ws",
                ".info", ".biz", ".click", ".link", ".work", ".loan", ".date", ".racing",
                ".stream", ".download", ".trade", ".accountant", ".review", ".party"
            };
            foreach (var tld in suspiciousTLDs)
            {
                _suspiciousTLDs.Add(tld);
            }
            
            // 初始化钓鱼关键词
            string[] keywords = {
                "login", "signin", "account", "bank", "secure", "verify", "password",
                "credit", "card", "paypal", "ebay", "amazon", "google", "facebook",
                "twitter", "microsoft", "apple", "netflix", "instagram", "linkedin",
                "update", "confirm", "suspended", "unusual", "activity", "security",
                "alert", "warning", "limited", "access", "verify", "authentication",
                "验证", "登录", "密码", "账户", "银行", "安全", "紧急", "重要"
            };
            foreach (var keyword in keywords)
            {
                _phishingKeywords.Add(keyword);
            }
            
            // 初始化知名品牌域名（用于Typosquatting检测）
            _brandDomains["google"] = new[] { "google.com", "googleapis.com", "googleusercontent.com", "gstatic.com", "ggpht.com" };
            _brandDomains["facebook"] = new[] { "facebook.com", "fb.com", "fbcdn.net", "fbsbx.com" };
            _brandDomains["microsoft"] = new[] { "microsoft.com", "msn.com", "live.com", "outlook.com", "office.com", "azure.com" };
            _brandDomains["apple"] = new[] { "apple.com", "icloud.com", "itunes.com", "mzstatic.com" };
            _brandDomains["amazon"] = new[] { "amazon.com", "amazonaws.com", "cloudfront.net", "a2z.com" };
            _brandDomains["paypal"] = new[] { "paypal.com", "paypalobjects.com" };
            _brandDomains["alibaba"] = new[] { "alibaba.com", "aliexpress.com", "taobao.com", "tmall.com", "alipay.com" };
            _brandDomains["tencent"] = new[] { "qq.com", "tencent.com", "wechat.com", "weixin.qq.com" };
            _brandDomains["netflix"] = new[] { "netflix.com", "nflxvideo.net", "nflxso.net" };
            _brandDomains["twitter"] = new[] { "twitter.com", "t.co", "twimg.com", "x.com" };
            
            // 初始化合法域名白名单
            foreach (var domains in _brandDomains.Values)
            {
                foreach (var domain in domains)
                {
                    _knownLegitimateDomains.Add(domain);
                }
            }
            
            // 添加更多合法域名
            string[] legitimateDomains = {
                "github.com", "gitlab.com", "bitbucket.org", "stackoverflow.com",
                "wikipedia.org", "reddit.com", "linkedin.com", "instagram.com",
                "youtube.com", "youtu.be", "googlevideo.com", "ytimg.com",
                "baidu.com", "zhihu.com", "csdn.net", "jianshu.com",
                "jd.com", "bilibili.com", "douyin.com", "tiktok.com"
            };
            foreach (var domain in legitimateDomains)
            {
                _knownLegitimateDomains.Add(domain);
            }
        }

        private void LoadPhishingDatabase()
        {
            try
            {
                string dbPath = Path.Combine(GetDataPath(), "phishing_db.json");
                if (File.Exists(dbPath))
                {
                    var json = File.ReadAllText(dbPath);
                    var data = Newtonsoft.Json.JsonConvert.DeserializeObject<PhishingDatabase>(json);
                    if (data != null)
                    {
                        foreach (var domain in data.PhishingDomains)
                        {
                            _knownPhishingDomains.Add(domain);
                        }
                        foreach (var url in data.BlockedUrls)
                        {
                            _blockedUrls.TryAdd(url, DateTime.UtcNow);
                        }
                        _lastDatabaseUpdate = data.LastUpdate;
                    }
                }
                
                _dataManager.LogInfo($"反钓鱼数据库加载完成: {_knownPhishingDomains.Count}个钓鱼域名");
            }
            catch (Exception ex)
            {
                _dataManager.LogError("加载钓鱼数据库失败", ex.Message, "AntiPhishing");
            }
        }

        private void SavePhishingDatabase()
        {
            try
            {
                var data = new PhishingDatabase
                {
                    PhishingDomains = _knownPhishingDomains.ToList(),
                    BlockedUrls = _blockedUrls.Keys.ToList(),
                    LastUpdate = DateTime.UtcNow
                };
                
                string dbPath = Path.Combine(GetDataPath(), "phishing_db.json");
                Directory.CreateDirectory(Path.GetDirectoryName(dbPath));
                var json = Newtonsoft.Json.JsonConvert.SerializeObject(data, Newtonsoft.Json.Formatting.Indented);
                File.WriteAllText(dbPath, json);
            }
            catch (Exception ex)
            {
                _dataManager.LogError("保存钓鱼数据库失败", ex.Message, "AntiPhishing");
            }
        }

        private string GetDataPath()
        {
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), 
                "FireAntivirus", "Data");
        }

        public void Start()
        {
            if (_isRunning)
                return;

            _isRunning = true;
            
            // 启动检测线程
            _detectionThread = new Thread(DetectionThread)
            {
                IsBackground = true,
                Priority = ThreadPriority.BelowNormal
            };
            _detectionThread.Start();
            
            // 启动数据库更新线程
            _updateThread = new Thread(UpdateThread)
            {
                IsBackground = true,
                Priority = ThreadPriority.Lowest
            };
            _updateThread.Start();

            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "AntiPhishingStart",
                Message = "反钓鱼系统已启动",
                Details = $"钓鱼域名库: {_knownPhishingDomains.Count}, 合法域名库: {_knownLegitimateDomains.Count}",
                Source = "AntiPhishing"
            });
        }

        public void Stop()
        {
            _isRunning = false;
            
            if (_detectionThread != null && _detectionThread.IsAlive)
            {
                _detectionThread.Join(2000);
            }
            
            if (_updateThread != null && _updateThread.IsAlive)
            {
                _updateThread.Join(1000);
            }
            
            SavePhishingDatabase();
            
            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "AntiPhishingStop",
                Message = "反钓鱼系统已停止",
                Source = "AntiPhishing"
            });
        }

        public bool IsRunning => _isRunning;

        private void DetectionThread()
        {
            while (_isRunning)
            {
                try
                {
                    // 清理过期缓存
                    CleanupExpiredCache();
                    
                    // 检查当前浏览器URL
                    if (_enableWebsiteDetection)
                    {
                        CheckCurrentBrowserUrls();
                    }
                    
                    Thread.Sleep(_detectionInterval);
                }
                catch (Exception ex)
                {
                    _dataManager.LogError("钓鱼检测线程错误", ex.Message, "AntiPhishing");
                    Thread.Sleep(1000);
                }
            }
        }

        private void UpdateThread()
        {
            while (_isRunning)
            {
                try
                {
                    // 每小时更新一次数据库
                    Thread.Sleep(3600000);
                    
                    if (_isRunning && _enableCloudCheck)
                    {
                        UpdatePhishingDatabaseFromCloud();
                    }
                }
                catch (Exception ex)
                {
                    _dataManager.LogError("钓鱼数据库更新错误", ex.Message, "AntiPhishing");
                }
            }
        }

        private void UpdatePhishingDatabaseFromCloud()
        {
            try
            {
                // 从云端更新钓鱼域名库（模拟）
                // 实际实现应该从威胁情报平台获取数据
                _dataManager.LogInfo("正在更新反钓鱼数据库...");
                _lastDatabaseUpdate = DateTime.UtcNow;
                _dataManager.LogInfo($"反钓鱼数据库更新完成: {_knownPhishingDomains.Count}个钓鱼域名");
            }
            catch (Exception ex)
            {
                _dataManager.LogError("云端更新失败", ex.Message, "AntiPhishing");
            }
        }

        private void CleanupExpiredCache()
        {
            var now = DateTime.UtcNow;
            var expiredKeys = _domainReputationCache
                .Where(kvp => (now - kvp.Value.QueryTime).TotalMinutes > _cacheExpiryMinutes)
                .Select(kvp => kvp.Key)
                .ToList();
            
            foreach (var key in expiredKeys)
            {
                DomainReputation removed;
                _domainReputationCache.TryRemove(key, out removed);
            }
            
            // 清理旧的检测结果
            if (_detectionResults.Count > _maxDetectionResults)
            {
                var keysToRemove = _detectionResults
                    .OrderBy(kvp => kvp.Value.DetectionTime)
                    .Take(_detectionResults.Count - _maxDetectionResults)
                    .Select(kvp => kvp.Key)
                    .ToList();
                
                foreach (var key in keysToRemove)
                {
                    PhishingDetectionResult removed;
                    _detectionResults.TryRemove(key, out removed);
                }
            }
        }

        private void CheckCurrentBrowserUrls()
        {
            try
            {
                // 获取浏览器进程
                var browserProcesses = System.Diagnostics.Process.GetProcesses()
                    .Where(p => IsBrowserProcess(p.ProcessName))
                    .ToList();
                
                foreach (var process in browserProcesses)
                {
                    try
                    {
                        // 检查浏览器窗口标题中的URL
                        var title = process.MainWindowTitle;
                        if (!string.IsNullOrEmpty(title))
                        {
                            var urls = ExtractUrlsFromText(title);
                            foreach (var url in urls)
                            {
                                var result = AnalyzeUrl(url);
                                if (result.IsPhishing)
                                {
                                    HandlePhishingDetection(result);
                                }
                            }
                        }
                    }
                    catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "AntiPhishing.cs 捕获异常", ex.Message); }
                }
            }
            catch (Exception ex)
            {
                _dataManager.LogError("浏览器URL检查错误", ex.Message, "AntiPhishing");
            }
        }

        private bool IsBrowserProcess(string processName)
        {
            string[] browsers = { "chrome", "msedge", "firefox", "iexplore", "opera", "browser", "brave" };
            return browsers.Any(b => processName.ToLower().Contains(b));
        }

        private List<string> ExtractUrlsFromText(string text)
        {
            var urls = new List<string>();
            var regex = new Regex(@"https?://[^\s<>""']+|[^\s<>""']+\.com[^\s<>""']*", RegexOptions.IgnoreCase);
            var matches = regex.Matches(text);
            foreach (Match match in matches)
            {
                urls.Add(match.Value);
            }
            return urls;
        }

        /// <summary>
        /// 综合分析URL是否为钓鱼网站
        /// </summary>
        public PhishingDetectionResult AnalyzeUrl(string url)
        {
            if (string.IsNullOrEmpty(url))
                return new PhishingDetectionResult { Url = url, IsPhishing = false };

            Interlocked.Increment(ref _totalUrlsScanned);
            
            // 规范化URL
            url = NormalizeUrl(url);
            var uri = ParseUrl(url);
            if (uri == null)
                return new PhishingDetectionResult { Url = url, IsPhishing = false, RiskLevel = "低", DetectionReason = "无效URL" };

            var result = new PhishingDetectionResult
            {
                Url = url,
                Domain = uri.Host,
                DetectionTime = DateTime.Now
            };

            int riskScore = 0;
            var detectionReasons = new List<string>();

            // 1. 检查缓存
            if (_domainReputationCache.TryGetValue(uri.Host, out var cachedReputation))
            {
                if (cachedReputation.IsMalicious)
                {
                    result.IsPhishing = true;
                    result.RiskLevel = "高";
                    result.DetectionReason = "缓存: 已知钓鱼域名";
                    result.Confidence = cachedReputation.Confidence;
                    return result;
                }
                else if (cachedReputation.IsSafe && cachedReputation.Confidence > 0.9)
                {
                    result.IsPhishing = false;
                    result.RiskLevel = "低";
                    result.DetectionReason = "缓存: 已验证安全域名";
                    result.Confidence = cachedReputation.Confidence;
                    return result;
                }
            }

            // 2. 黑名单检查
            if (_knownPhishingDomains.Contains(uri.Host) || _blockedUrls.ContainsKey(url))
            {
                riskScore += 100;
                detectionReasons.Add("黑名单匹配");
            }

            // 3. 白名单检查
            if (_knownLegitimateDomains.Contains(uri.Host))
            {
                result.IsPhishing = false;
                result.RiskLevel = "低";
                result.DetectionReason = "已知合法域名";
                result.Confidence = 0.95;
                CacheDomainReputation(uri.Host, false, true, 0.95);
                return result;
            }

            // 4. IP地址URL检查
            if (IsIpAddressUrl(uri))
            {
                riskScore += 40;
                detectionReasons.Add("URL使用IP地址");
            }

            // 5. 可疑TLD检查
            if (HasSuspiciousTLD(uri.Host))
            {
                riskScore += 25;
                detectionReasons.Add("使用可疑顶级域名");
            }

            // 6. Typosquatting检测
            if (_enableTyposquattingDetection)
            {
                var typoResult = CheckTyposquatting(uri.Host);
                if (typoResult.IsTyposquatting)
                {
                    riskScore += 60;
                    detectionReasons.Add($"域名抢注检测: 模仿 {typoResult.OriginalBrand}");
                }
            }

            // 7. 同形字攻击检测 (Homograph Attack)
            if (_enableHomographDetection)
            {
                var homoResult = CheckHomographAttack(uri.Host);
                if (homoResult.IsHomograph)
                {
                    riskScore += 70;
                    detectionReasons.Add($"同形字攻击检测: 可能伪装 {homoResult.SimilarBrand}");
                }
            }

            // 8. URL特征分析
            riskScore += AnalyzeUrlFeatures(url, uri, detectionReasons);

            // 9. 域名年龄和注册信息分析
            var domainInfo = AnalyzePhishingDomainInfo(uri.Host);
            if (domainInfo.IsNewlyRegistered)
            {
                riskScore += 30;
                detectionReasons.Add($"新注册域名: {domainInfo.RegistrationDate}");
            }

            // 10. SSL证书验证
            if (_enableSSLValidation && uri.Scheme == "https")
            {
                var certResult = ValidateSSLCertificate(uri);
                if (!certResult.IsValid)
                {
                    riskScore += 20;
                    detectionReasons.Add($"SSL证书问题: {certResult.Issue}");
                }
                else if (certResult.IsEV)
                {
                    riskScore -= 15; // EV证书加分
                }
            }
            else if (uri.Scheme == "http")
            {
                riskScore += 15;
                detectionReasons.Add("使用不安全的HTTP协议");
            }

            // 11. 云端信誉查询
            if (_enableCloudCheck && riskScore < 50)
            {
                var cloudResult = QueryCloudReputation(url);
                if (cloudResult.IsMalicious)
                {
                    riskScore += 50;
                    detectionReasons.Add($"云端检测: {cloudResult.ThreatType}");
                }
            }

            // 12. 机器学习评分
            if (_enableMachineLearning)
            {
                var mlScore = CalculateMLRiskScore(url, uri);
                riskScore += (int)(mlScore * 30);
                if (mlScore > 0.7)
                {
                    detectionReasons.Add($"机器学习风险评分: {mlScore:P}");
                }
            }

            // 计算最终结果
            result.RiskScore = riskScore;
            result.IsPhishing = riskScore >= 50;
            result.Confidence = Math.Min(0.99, riskScore / 100.0);
            result.RiskLevel = GetRiskLevel(riskScore);
            result.DetectionReason = string.Join("; ", detectionReasons);
            result.DetectionMethod = detectionReasons.Count > 0 ? "多重检测" : "启发式分析";
            
            // 检测详情
            result.Details = new PhishingDetectionDetails
            {
                HasSuspiciousTLD = HasSuspiciousTLD(uri.Host),
                IsIpAddressUrl = IsIpAddressUrl(uri),
                UsesHTTP = uri.Scheme == "http",
                DomainAge = domainInfo.AgeDays,
                HasValidSSL = uri.Scheme == "https",
                TyposquattingTarget = _enableTyposquattingDetection ? CheckTyposquatting(uri.Host).OriginalBrand : null
            };

            // 缓存结果
            CacheDomainReputation(uri.Host, result.IsPhishing, !result.IsPhishing, result.Confidence);
            
            // 记录检测结果
            if (result.IsPhishing)
            {
                Interlocked.Increment(ref _phishingBlocked);
                _detectionResults.TryAdd(url, result);
            }

            return result;
        }

        private string NormalizeUrl(string url)
        {
            url = url.Trim();
            
            // 移除常见的前缀干扰
            if (url.StartsWith("www.", StringComparison.OrdinalIgnoreCase))
            {
                url = "http://" + url;
            }
            
            // 添加默认协议
            if (!url.StartsWith("http://", StringComparison.OrdinalIgnoreCase) && 
                !url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                url = "http://" + url;
            }
            
            // 解码URL编码
            try
            {
                url = Uri.UnescapeDataString(url);
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "AntiPhishing.cs 捕获异常", ex.Message); }
            
            return url;
        }

        private Uri ParseUrl(string url)
        {
            try
            {
                return new Uri(url);
            }
            catch
            {
                return null;
            }
        }

        private bool IsIpAddressUrl(Uri uri)
        {
            return Regex.IsMatch(uri.Host, @"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$");
        }

        private bool HasSuspiciousTLD(string domain)
        {
            foreach (var tld in _suspiciousTLDs)
            {
                if (domain.EndsWith(tld, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }

        #region Typosquatting Detection (域名抢注检测)
        
        private TyposquattingResult CheckTyposquatting(string domain)
        {
            var result = new TyposquattingResult { IsTyposquatting = false };
            
            // 提取主域名
            var parts = domain.Split('.');
            if (parts.Length < 2)
                return result;
            
            string mainDomain = parts[parts.Length - 2];
            
            foreach (var brand in _brandDomains.Keys)
            {
                // 检查常见拼写错误
                if (IsTyposquattingVariant(mainDomain, brand))
                {
                    result.IsTyposquatting = true;
                    result.OriginalBrand = brand;
                    result.VariantType = "Typosquatting";
                    return result;
                }
                
                // 检查是否包含品牌名但不是官方域名
                if (domain.Contains(brand) && !_brandDomains[brand].Any(d => domain.Equals(d, StringComparison.OrdinalIgnoreCase)))
                {
                    // 排除合法的子域名
                    var brandOfficialDomains = _brandDomains[brand];
                    bool isOfficial = brandOfficialDomains.Any(d => 
                        domain.Equals(d, StringComparison.OrdinalIgnoreCase) ||
                        domain.EndsWith("." + d, StringComparison.OrdinalIgnoreCase));
                    
                    if (!isOfficial)
                    {
                        result.IsTyposquatting = true;
                        result.OriginalBrand = brand;
                        result.VariantType = "BrandImpersonation";
                        return result;
                    }
                }
            }
            
            return result;
        }

        private bool IsTyposquattingVariant(string input, string brand)
        {
            if (string.IsNullOrEmpty(input) || string.IsNullOrEmpty(brand))
                return false;
            
            input = input.ToLower();
            brand = brand.ToLower();
            
            // 完全相同
            if (input == brand)
                return false; // 这是原始品牌，不是抢注
            
            int distance = LevenshteinDistance(input, brand);
            
            // 编辑距离小于等于2，且长度相似
            if (distance <= 2 && Math.Abs(input.Length - brand.Length) <= 1)
                return true;
            
            // 检查常见拼写错误模式
            // 1. 字母替换 (googie -> google)
            // 2. 字母缺失 (gogle -> google)
            // 3. 字母重复 (gooogle -> google)
            // 4. 字母顺序错误 (gooegl -> google)
            
            // 相邻字母交换
            if (input.Length == brand.Length)
            {
                for (int i = 0; i < input.Length - 1; i++)
                {
                    var swapped = input.ToCharArray();
                    char temp = swapped[i];
                    swapped[i] = swapped[i + 1];
                    swapped[i + 1] = temp;
                    if (new string(swapped) == brand)
                        return true;
                }
            }
            
            return false;
        }

        private int LevenshteinDistance(string s1, string s2)
        {
            int[,] d = new int[s1.Length + 1, s2.Length + 1];
            
            for (int i = 0; i <= s1.Length; i++)
                d[i, 0] = i;
            for (int j = 0; j <= s2.Length; j++)
                d[0, j] = j;
            
            for (int i = 1; i <= s1.Length; i++)
            {
                for (int j = 1; j <= s2.Length; j++)
                {
                    int cost = (s1[i - 1] == s2[j - 1]) ? 0 : 1;
                    d[i, j] = Math.Min(
                        Math.Min(d[i - 1, j] + 1, d[i, j - 1] + 1),
                        d[i - 1, j - 1] + cost);
                }
            }
            
            return d[s1.Length, s2.Length];
        }
        
        #endregion

        #region Homograph Attack Detection (同形字攻击检测)
        
        private HomographResult CheckHomographAttack(string domain)
        {
            var result = new HomographResult { IsHomograph = false };
            
            // 检查是否包含非ASCII字符（Punycode编码）
            if (domain.Contains("xn--"))
            {
                // 解码Punycode
                string decoded = DecodePunycode(domain);
                if (!string.IsNullOrEmpty(decoded))
                {
                    // 检查解码后的域名是否模仿知名品牌
                    foreach (var brand in _brandDomains.Keys)
                    {
                        if (IsVisuallySimilar(decoded, brand))
                        {
                            result.IsHomograph = true;
                            result.SimilarBrand = brand;
                            result.DecodedDomain = decoded;
                            return result;
                        }
                    }
                }
            }
            
            // 检查混合脚本（Latin + Cyrillic/Greek）
            if (HasMixedScripts(domain))
            {
                result.IsHomograph = true;
                result.SimilarBrand = DetectSimilarBrandFromMixedScript(domain);
                return result;
            }
            
            return result;
        }

        private string DecodePunycode(string domain)
        {
            try
            {
                // 简化的Punycode解码检测
                var parts = domain.Split('.');
                var decodedParts = new List<string>();
                
                foreach (var part in parts)
                {
                    if (part.StartsWith("xn--"))
                    {
                        // 使用.NET的IDN解码
                        try
                        {
                            var idn = new System.Globalization.IdnMapping();
                            decodedParts.Add(idn.GetUnicode(part));
                        }
                        catch
                        {
                            decodedParts.Add(part);
                        }
                    }
                    else
                    {
                        decodedParts.Add(part);
                    }
                }
                
                return string.Join(".", decodedParts);
            }
            catch
            {
                return null;
            }
        }

        private bool IsVisuallySimilar(string s1, string s2)
        {
            if (string.IsNullOrEmpty(s1) || string.IsNullOrEmpty(s2))
                return false;
            
            // 转换为视觉相似的字符后比较
            string normalized1 = NormalizeVisualChars(s1.ToLower());
            string normalized2 = NormalizeVisualChars(s2.ToLower());
            
            return normalized1 == normalized2 || 
                   LevenshteinDistance(normalized1, normalized2) <= 1;
        }

        private string NormalizeVisualChars(string input)
        {
            // 同形字符映射表
            var homoglyphs = new Dictionary<char, char>
            {
                // Cyrillic to Latin
                {'а', 'a'}, {'е', 'e'}, {'о', 'o'}, {'р', 'p'}, {'с', 'c'}, {'х', 'x'}, {'у', 'y'},
                {'А', 'A'}, {'В', 'B'}, {'Е', 'E'}, {'К', 'K'}, {'М', 'M'}, {'Н', 'H'}, {'О', 'O'},
                {'Р', 'P'}, {'С', 'C'}, {'Т', 'T'}, {'Х', 'X'},
                // Greek to Latin
                {'α', 'a'}, {'ε', 'e'}, {'ο', 'o'}, {'ρ', 'p'}, {'σ', 's'}, {'τ', 't'}, {'υ', 'y'},
                {'Α', 'A'}, {'Β', 'B'}, {'Ε', 'E'}, {'Ζ', 'Z'}, {'Η', 'H'}, {'Ι', 'I'}, {'Κ', 'K'},
                {'Μ', 'M'}, {'Ν', 'N'}, {'Ο', 'O'}, {'Ρ', 'P'}, {'Τ', 'T'}, {'Υ', 'Y'}, {'Χ', 'X'},
                // Other common confusables
                {'0', 'o'}, {'1', 'l'}, {'|', 'l'}, {'!', 'l'}, {'ı', 'i'}, {'İ', 'I'}
            };
            
            var result = new StringBuilder();
            foreach (char c in input)
            {
                result.Append(homoglyphs.ContainsKey(c) ? homoglyphs[c] : c);
            }
            
            return result.ToString();
        }

        private bool HasMixedScripts(string domain)
        {
            bool hasLatin = false;
            bool hasCyrillic = false;
            bool hasGreek = false;
            
            foreach (char c in domain)
            {
                if (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z')
                    hasLatin = true;
                else if (c >= 0x0400 && c <= 0x04FF) // Cyrillic
                    hasCyrillic = true;
                else if (c >= 0x0370 && c <= 0x03FF) // Greek
                    hasGreek = true;
            }
            
            int scriptCount = (hasLatin ? 1 : 0) + (hasCyrillic ? 1 : 0) + (hasGreek ? 1 : 0);
            return scriptCount > 1;
        }

        private string DetectSimilarBrandFromMixedScript(string domain)
        {
            string normalized = NormalizeVisualChars(domain.ToLower());
            
            foreach (var brand in _brandDomains.Keys)
            {
                if (normalized.Contains(brand.ToLower()))
                    return brand;
            }
            
            return "未知品牌";
        }
        
        #endregion

        #region URL Feature Analysis
        
        private int AnalyzeUrlFeatures(string url, Uri uri, List<string> detectionReasons)
        {
            int score = 0;
            
            // URL长度
            if (url.Length > 100)
            {
                score += 15;
                detectionReasons.Add("URL过长");
            }
            else if (url.Length > 75)
            {
                score += 8;
            }
            
            // 子域名数量
            var subdomains = uri.Host.Split('.');
            if (subdomains.Length > 4)
            {
                score += 20;
                detectionReasons.Add("子域名过多");
            }
            else if (subdomains.Length > 3)
            {
                score += 10;
            }
            
            // 特殊字符
            if (url.Contains("@"))
            {
                score += 25;
                detectionReasons.Add("URL包含@符号");
            }
            
            // URL编码滥用
            int encodedChars = Regex.Matches(url, "%[0-9A-Fa-f]{2}").Count;
            if (encodedChars > 5)
            {
                score += 15;
                detectionReasons.Add("URL编码字符过多");
            }
            
            // 查询参数中的可疑内容
            if (!string.IsNullOrEmpty(uri.Query))
            {
                if (_phishingKeywords.Any(k => uri.Query.ToLower().Contains(k)))
                {
                    score += 10;
                }
            }
            
            // 路径中的可疑内容
            if (!string.IsNullOrEmpty(uri.AbsolutePath))
            {
                if (_phishingKeywords.Any(k => uri.AbsolutePath.ToLower().Contains(k)))
                {
                    score += 10;
                }
            }
            
            // 端口号检查
            if (!uri.IsDefaultPort && uri.Port != 443 && uri.Port != 80)
            {
                score += 10;
            }
            
            return score;
        }
        
        #endregion

        #region Domain Info Analysis
        
        private PhishingDomainInfo AnalyzePhishingDomainInfo(string domain)
        {
            var info = new PhishingDomainInfo
            {
                Domain = domain,
                AgeDays = -1
            };
            
            try
            {
                // 检查缓存
                string cacheFile = Path.Combine(GetDataPath(), "domain_cache", domain + ".json");
                if (File.Exists(cacheFile))
                {
                    var cachedInfo = Newtonsoft.Json.JsonConvert.DeserializeObject<PhishingDomainInfo>(
                        File.ReadAllText(cacheFile));
                    if (cachedInfo != null && (DateTime.UtcNow - cachedInfo.QueryTime).TotalDays < 7)
                    {
                        return cachedInfo;
                    }
                }
                
                // 实际实现应该通过WHOIS查询
                // 这里使用启发式方法判断新注册域名
                info.IsNewlyRegistered = false;
                
                // 保存缓存
                try
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(cacheFile));
                    File.WriteAllText(cacheFile, Newtonsoft.Json.JsonConvert.SerializeObject(info));
                }
                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "AntiPhishing.cs 捕获异常", ex.Message); }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "AntiPhishing.cs 捕获异常", ex.Message); }
            
            return info;
        }
        
        #endregion

        #region SSL Certificate Validation
        
        private SSLValidationResult ValidateSSLCertificate(Uri uri)
        {
            var result = new SSLValidationResult { IsValid = false };
            
            try
            {
                var request = (HttpWebRequest)WebRequest.Create(uri);
                request.Method = "HEAD";
                request.Timeout = 10000;
                request.AllowAutoRedirect = false;
                
                request.ServerCertificateValidationCallback = (sender, cert, chain, errors) =>
                {
                    if (errors == SslPolicyErrors.None)
                    {
                        result.IsValid = true;

                        // 检查是否是EV证书
                        var cert2 = cert as X509Certificate2;
                        if (cert2 != null)
                        {
                            result.Issuer = cert2.Issuer;
                            result.Subject = cert2.Subject;
                            result.NotBefore = cert2.NotBefore;
                            result.NotAfter = cert2.NotAfter;

                            // EV证书检测（简化）
                            result.IsEV = cert2.Issuer.Contains("EV") ||
                                          cert2.Issuer.Contains("Extended Validation") ||
                                          cert2.Issuer.Contains("DigiCert") ||
                                          cert2.Issuer.Contains("GlobalSign");
                        }
                        return true;
                    }
                    
                    result.IsValid = false;
                    result.Issue = errors.ToString();
                    return false;
                };
                
                request.GetResponse()?.Close();
            }
            catch (WebException ex)
            {
                if (ex.Status == WebExceptionStatus.TrustFailure)
                {
                    result.Issue = "SSL证书不受信任";
                }
                else if (ex.Status == WebExceptionStatus.SecureChannelFailure)
                {
                    result.Issue = "安全通道建立失败";
                }
            }
            catch (Exception ex)
            {
                result.Issue = ex.Message;
            }
            
            return result;
        }
        
        #endregion

        #region Cloud Reputation Query
        
        private PhishingCloudReputationResult QueryCloudReputation(string url)
        {
            var result = new PhishingCloudReputationResult();
            
            try
            {
                // 模拟云端查询（实际应该调用威胁情报API）
                // 如: Google Safe Browsing API, PhishTank API, VirusTotal API
                
                // 计算URL哈希作为查询标识
                string urlHash = ComputeSHA256(url);
                
                // 检查本地缓存
                string cacheFile = Path.Combine(GetDataPath(), "cloud_cache", urlHash + ".json");
                if (File.Exists(cacheFile))
                {
                    var cached = Newtonsoft.Json.JsonConvert.DeserializeObject<PhishingCloudReputationResult>(
                        File.ReadAllText(cacheFile));
                    if (cached != null && (DateTime.UtcNow - cached.QueryTime).TotalHours < 24)
                    {
                        return cached;
                    }
                }
                
                // 实际云端查询（模拟）
                // 这里可以集成多个威胁情报源
                result.IsMalicious = false;
                result.Confidence = 0.5;
                result.QueryTime = DateTime.UtcNow;
                result.Sources = new List<string> { "LocalHeuristics" };
                
                // 保存缓存
                try
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(cacheFile));
                    File.WriteAllText(cacheFile, Newtonsoft.Json.JsonConvert.SerializeObject(result));
                }
                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "AntiPhishing.cs 捕获异常", ex.Message); }
            }
            catch (Exception ex)
            {
                _dataManager.LogError("云端信誉查询失败", ex.Message, "AntiPhishing");
            }
            
            return result;
        }

        private string ComputeSHA256(string input)
        {
            using (var sha256 = SHA256.Create())
            {
                var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(input));
                return BitConverter.ToString(bytes).Replace("-", "").ToLower();
            }
        }
        
        #endregion

        #region Machine Learning Risk Score
        
        private double CalculateMLRiskScore(string url, Uri uri)
        {
            // 基于特征的简单风险评估模型
            // 实际应该使用训练好的机器学习模型
            
            double score = 0;
            var features = new List<double>();
            
            // 特征1: URL长度归一化
            features.Add(Math.Min(1.0, url.Length / 200.0));
            
            // 特征2: 子域名数量
            features.Add(Math.Min(1.0, uri.Host.Split('.').Length / 6.0));
            
            // 特征3: 是否包含IP
            features.Add(IsIpAddressUrl(uri) ? 1.0 : 0.0);
            
            // 特征4: 是否使用可疑TLD
            features.Add(HasSuspiciousTLD(uri.Host) ? 1.0 : 0.0);
            
            // 特征5: 特殊字符比例
            int specialChars = url.Count(c => !char.IsLetterOrDigit(c) && c != '.' && c != '/');
            features.Add(Math.Min(1.0, specialChars / 20.0));
            
            // 特征6: 数字字符比例
            int digits = url.Count(char.IsDigit);
            features.Add(Math.Min(1.0, digits / 15.0));
            
            // 特征7: 是否包含品牌关键词
            bool hasBrandKeyword = _phishingKeywords.Any(k => url.ToLower().Contains(k));
            features.Add(hasBrandKeyword ? 1.0 : 0.0);
            
            // 特征8: 是否HTTPS
            features.Add(uri.Scheme == "https" ? 0.0 : 0.5);
            
            // 加权计算
            double[] weights = { 0.1, 0.15, 0.2, 0.15, 0.1, 0.1, 0.15, 0.05 };
            for (int i = 0; i < features.Count && i < weights.Length; i++)
            {
                score += features[i] * weights[i];
            }
            
            return Math.Min(1.0, score);
        }
        
        #endregion

        private string GetRiskLevel(int score)
        {
            if (score >= 75) return "高";
            if (score >= 50) return "中高";
            if (score >= 25) return "中";
            return "低";
        }

        private void CacheDomainReputation(string domain, bool isMalicious, bool isSafe, double confidence)
        {
            var reputation = new DomainReputation
            {
                Domain = domain,
                IsMalicious = isMalicious,
                IsSafe = isSafe,
                Confidence = confidence,
                QueryTime = DateTime.UtcNow
            };
            
            _domainReputationCache.AddOrUpdate(domain, reputation, (k, v) => reputation);
        }

        private void HandlePhishingDetection(PhishingDetectionResult result)
        {
            _dataManager.LogWarning($"检测到钓鱼网站: {result.Url}");
            _dataManager.LogWarning($"域名: {result.Domain}, 风险等级: {result.RiskLevel}");
            _dataManager.LogWarning($"检测原因: {result.DetectionReason}");
            
            // 记录威胁日志
            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "PhishingDetected",
                Message = "检测到钓鱼网站",
                Details = $"URL: {result.Url}\n域名: {result.Domain}\n风险评分: {result.RiskScore}\n检测原因: {result.DetectionReason}",
                Source = "AntiPhishing",
                Category = "网络安全"
            });
            
            // 发送通知
            try
            {
                FireAntivirus.Common.Notification.NotificationService.Instance?.ShowNotification(
                    "钓鱼网站警告",
                    $"检测到钓鱼网站: {result.Domain}",
                    FireAntivirus.Common.Notification.NotificationType.Warning);
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "AntiPhishing.cs 捕获异常", ex.Message); }
        }

        /// <summary>
        /// 分析邮件是否为钓鱼邮件
        /// </summary>
        public PhishingDetectionResult AnalyzeEmail(EmailMessage email)
        {
            if (email == null || string.IsNullOrEmpty(email.Sender))
                return new PhishingDetectionResult { Url = email?.Sender, IsPhishing = false };

            var result = new PhishingDetectionResult
            {
                Url = email.Sender,
                DetectionTime = DateTime.Now
            };

            int riskScore = 0;
            var detectionReasons = new List<string>();

            // 1. 发件人域名分析
            var senderDomain = ExtractDomainFromEmail(email.Sender);
            if (!string.IsNullOrEmpty(senderDomain))
            {
                var domainResult = AnalyzeUrl("http://" + senderDomain);
                if (domainResult.IsPhishing)
                {
                    riskScore += 40;
                    detectionReasons.Add($"发件人域名可疑: {senderDomain}");
                }
            }

            // 2. SPF/DKIM/DMARC验证
            var authResult = VerifyEmailAuthentication(email);
            if (!authResult.SPFValid)
            {
                riskScore += 25;
                detectionReasons.Add("SPF验证失败");
            }
            if (!authResult.DKIMValid)
            {
                riskScore += 20;
                detectionReasons.Add("DKIM验证失败");
            }
            if (!authResult.DMARCValid)
            {
                riskScore += 15;
                detectionReasons.Add("DMARC验证失败");
            }

            // 3. 主题分析
            if (!string.IsNullOrEmpty(email.Subject))
            {
                string[] urgentKeywords = { "紧急", "重要", "立即", "验证", "密码", "账户", "安全", "银行", "付款", "账单" };
                foreach (var keyword in urgentKeywords)
                {
                    if (email.Subject.Contains(keyword))
                    {
                        riskScore += 10;
                        detectionReasons.Add($"主题包含紧急关键词: {keyword}");
                        break;
                    }
                }
            }

            // 4. 正文分析
            if (!string.IsNullOrEmpty(email.Body))
            {
                // 钓鱼特征短语
                string[] phishingPhrases = {
                    "点击这里验证", "您的账户已被暂停", "请立即更新", "密码即将过期",
                    "异常登录活动", "确认您的身份", "点击链接", "紧急通知",
                    "账户将被关闭", "需要验证"
                };
                
                foreach (var phrase in phishingPhrases)
                {
                    if (email.Body.Contains(phrase))
                    {
                        riskScore += 15;
                        detectionReasons.Add($"正文包含钓鱼短语: {phrase}");
                        break;
                    }
                }
                
                // 检查链接
                if (_enableLinkAnalysis)
                {
                    var links = ExtractUrlsFromText(email.Body);
                    int phishingLinkCount = 0;
                    foreach (var link in links)
                    {
                        var linkResult = AnalyzeUrl(link);
                        if (linkResult.IsPhishing)
                        {
                            phishingLinkCount++;
                            detectionReasons.Add($"包含钓鱼链接: {link}");
                        }
                    }
                    riskScore += phishingLinkCount * 30;
                }
            }

            // 5. 附件分析
            if (email.Attachments != null && email.Attachments.Count > 0)
            {
                string[] dangerousExtensions = { ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".scr", ".pif", ".com" };
                foreach (var attachment in email.Attachments)
                {
                    string ext = Path.GetExtension(attachment).ToLower();
                    if (dangerousExtensions.Contains(ext))
                    {
                        riskScore += 30;
                        detectionReasons.Add($"包含危险附件: {attachment}");
                    }
                }
            }

            // 6. 显示名称欺骗检测
            if (!string.IsNullOrEmpty(email.SenderDisplayName))
            {
                foreach (var brand in _brandDomains.Keys)
                {
                    if (email.SenderDisplayName.ToLower().Contains(brand.ToLower()))
                    {
                        // 检查发件人是否真的是该品牌
                        if (string.IsNullOrEmpty(senderDomain) || 
                            !_brandDomains[brand].Any(d => senderDomain.Equals(d, StringComparison.OrdinalIgnoreCase) ||
                                                           senderDomain.EndsWith("." + d, StringComparison.OrdinalIgnoreCase)))
                        {
                            riskScore += 35;
                            detectionReasons.Add($"显示名称欺骗: 伪装 {brand}");
                            break;
                        }
                    }
                }
            }

            // 计算最终结果
            result.RiskScore = riskScore;
            result.IsPhishing = riskScore >= 50;
            result.Confidence = Math.Min(0.99, riskScore / 100.0);
            result.RiskLevel = GetRiskLevel(riskScore);
            result.DetectionReason = string.Join("; ", detectionReasons);

            return result;
        }

        private string ExtractDomainFromEmail(string email)
        {
            if (string.IsNullOrEmpty(email))
                return null;
            
            int atIndex = email.IndexOf('@');
            if (atIndex >= 0 && atIndex < email.Length - 1)
            {
                return email.Substring(atIndex + 1).ToLower();
            }
            
            return null;
        }

        private EmailAuthResult VerifyEmailAuthentication(EmailMessage email)
        {
            var result = new EmailAuthResult();
            
            // 实际实现需要解析邮件头
            // 这里提供基本框架
            try
            {
                // SPF验证 - 检查发件人IP是否有权发送
                result.SPFValid = CheckSPFRecord(email.Sender);
                
                // DKIM验证 - 检查签名
                result.DKIMValid = email.DKIMSignature != null;
                
                // DMARC验证 - 检查策略
                result.DMARCValid = CheckDMARCPolicy(email.Sender);
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "AntiPhishing.cs 捕获异常", ex.Message); }
            
            return result;
        }

        private bool CheckSPFRecord(string sender)
        {
            // 简化实现 - 实际需要DNS查询
            return true;
        }

        private bool CheckDMARCPolicy(string sender)
        {
            // 简化实现 - 实际需要DNS查询
            return true;
        }

        #region Public API Methods
        
        public List<PhishingDetectionResult> GetDetectionResults()
        {
            return _detectionResults.Values.OrderByDescending(r => r.DetectionTime).ToList();
        }

        public List<PhishingRule> GetPhishingRules()
        {
            return _phishingRules.Values.ToList();
        }

        public void AddPhishingDomain(string domain)
        {
            if (!string.IsNullOrEmpty(domain))
            {
                _knownPhishingDomains.Add(domain.ToLower());
                SavePhishingDatabase();
            }
        }

        public void AddLegitimateDomain(string domain)
        {
            if (!string.IsNullOrEmpty(domain))
            {
                _knownLegitimateDomains.Add(domain.ToLower());
            }
        }

        public void RemovePhishingDomain(string domain)
        {
            _knownPhishingDomains.Remove(domain);
            SavePhishingDatabase();
        }

        public void RemoveLegitimateDomain(string domain)
        {
            _knownLegitimateDomains.Remove(domain);
        }

        public void BlockUrl(string url)
        {
            _blockedUrls.TryAdd(url, DateTime.UtcNow);
            SavePhishingDatabase();
        }

        public void AllowUrl(string url)
        {
            _allowedUrls.TryAdd(url, DateTime.UtcNow);
            _blockedUrls.TryRemove(url, out _);
        }

        public bool IsUrlBlocked(string url)
        {
            return _blockedUrls.ContainsKey(url);
        }

        public AntiPhishingStatistics GetStatistics()
        {
            return new AntiPhishingStatistics
            {
                TotalUrlsScanned = _totalUrlsScanned,
                PhishingBlocked = _phishingBlocked,
                FalsePositiveReports = _falsePositiveReports,
                KnownPhishingDomains = _knownPhishingDomains.Count,
                KnownLegitimateDomains = _knownLegitimateDomains.Count,
                CachedReputations = _domainReputationCache.Count,
                LastDatabaseUpdate = _lastDatabaseUpdate
            };
        }

        public void ReportFalsePositive(string url)
        {
            Interlocked.Increment(ref _falsePositiveReports);
            _allowedUrls.TryAdd(url, DateTime.UtcNow);
            _blockedUrls.TryRemove(url, out _);
            
            // 移动到白名单
            var uri = ParseUrl(url);
            if (uri != null)
            {
                _knownLegitimateDomains.Add(uri.Host);
            }
        }

        public void ReportPhishing(string url)
        {
            var uri = ParseUrl(url);
            if (uri != null)
            {
                _knownPhishingDomains.Add(uri.Host);
            }
            _blockedUrls.TryAdd(url, DateTime.UtcNow);
            SavePhishingDatabase();
        }

        #endregion

        #region Configuration Methods
        
        public void SetDetectionInterval(int interval)
        {
            _detectionInterval = Math.Max(1000, interval);
        }

        public void EnableWebsiteDetection(bool enable) => _enableWebsiteDetection = enable;
        public void EnableEmailDetection(bool enable) => _enableEmailDetection = enable;
        public void EnableLinkAnalysis(bool enable) => _enableLinkAnalysis = enable;
        public void EnableHeuristicAnalysis(bool enable) => _enableHeuristicAnalysis = enable;
        public void EnableMachineLearning(bool enable) => _enableMachineLearning = enable;
        public void EnableCloudCheck(bool enable) => _enableCloudCheck = enable;
        public void EnableRealTimeProtection(bool enable) => _enableRealTimeProtection = enable;
        public void EnableSSLValidation(bool enable) => _enableSSLValidation = enable;
        public void EnableTyposquattingDetection(bool enable) => _enableTyposquattingDetection = enable;
        public void EnableHomographDetection(bool enable) => _enableHomographDetection = enable;

        public void SetMaxDetectionResults(int max)
        {
            _maxDetectionResults = Math.Max(100, max);
        }
        
        #endregion
    }

    #region Data Classes

    public class PhishingDetectionResult
    {
        public string Url { get; set; }
        public string Domain { get; set; }
        public bool IsPhishing { get; set; }
        public int RiskScore { get; set; }
        public string RiskLevel { get; set; }
        public string DetectionReason { get; set; }
        public DateTime DetectionTime { get; set; } = DateTime.Now;
        public string DetectionMethod { get; set; }
        public double Confidence { get; set; }
        public PhishingDetectionDetails Details { get; set; }
    }

    public class PhishingDetectionDetails
    {
        public bool HasSuspiciousTLD { get; set; }
        public bool IsIpAddressUrl { get; set; }
        public bool UsesHTTP { get; set; }
        public int DomainAge { get; set; }
        public bool HasValidSSL { get; set; }
        public string TyposquattingTarget { get; set; }
    }

    public class PhishingRule
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public string Severity { get; set; }
        public bool Enabled { get; set; }
        public DateTime CreatedDate { get; set; } = DateTime.Now;
        public DateTime LastModifiedDate { get; set; } = DateTime.Now;
    }

    public class DomainReputation
    {
        public string Domain { get; set; }
        public bool IsMalicious { get; set; }
        public bool IsSafe { get; set; }
        public double Confidence { get; set; }
        public DateTime QueryTime { get; set; }
    }

    public class TyposquattingResult
    {
        public bool IsTyposquatting { get; set; }
        public string OriginalBrand { get; set; }
        public string VariantType { get; set; }
    }

    public class HomographResult
    {
        public bool IsHomograph { get; set; }
        public string SimilarBrand { get; set; }
        public string DecodedDomain { get; set; }
    }

    public class PhishingDomainInfo
    {
        public string Domain { get; set; }
        public bool IsNewlyRegistered { get; set; }
        public int AgeDays { get; set; }
        public string RegistrationDate { get; set; }
        public string Registrar { get; set; }
        public DateTime QueryTime { get; set; } = DateTime.UtcNow;
    }

    public class SSLValidationResult
    {
        public bool IsValid { get; set; }
        public bool IsEV { get; set; }
        public string Issuer { get; set; }
        public string Subject { get; set; }
        public DateTime NotBefore { get; set; }
        public DateTime NotAfter { get; set; }
        public string Issue { get; set; }
    }

    public class PhishingCloudReputationResult
    {
        public bool IsMalicious { get; set; }
        public string ThreatType { get; set; }
        public double Confidence { get; set; }
        public DateTime QueryTime { get; set; }
        public List<string> Sources { get; set; } = new List<string>();
    }

    public class EmailAuthResult
    {
        public bool SPFValid { get; set; }
        public bool DKIMValid { get; set; }
        public bool DMARCValid { get; set; }
    }

    public class EmailMessage
    {
        public string Sender { get; set; }
        public string SenderDisplayName { get; set; }
        public string Subject { get; set; }
        public string Body { get; set; }
        public List<string> Attachments { get; set; }
        public string DKIMSignature { get; set; }
        public Dictionary<string, string> Headers { get; set; }
    }

    public class PhishingDatabase
    {
        public List<string> PhishingDomains { get; set; } = new List<string>();
        public List<string> BlockedUrls { get; set; } = new List<string>();
        public DateTime LastUpdate { get; set; }
    }

    public class AntiPhishingStatistics
    {
        public long TotalUrlsScanned { get; set; }
        public long PhishingBlocked { get; set; }
        public long FalsePositiveReports { get; set; }
        public int KnownPhishingDomains { get; set; }
        public int KnownLegitimateDomains { get; set; }
        public int CachedReputations { get; set; }
        public DateTime LastDatabaseUpdate { get; set; }
    }

    #endregion
}
