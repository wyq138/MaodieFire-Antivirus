// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace FireAntivirus.NativeIntegration
{
    /// <summary>
    /// 浏览器保护模块
    /// 保护用户浏览器免受恶意网站、钓鱼攻击、隐私泄露等威胁
    /// </summary>
    public class NativeBrowserProtection : IDisposable
    {
        #region 私有字段
        private readonly NativeSecurityCoreWrapper _core;
        private bool _isMonitoring;
        private bool _disposed;

        // 保护的浏览器列表
        private readonly HashSet<string> _protectedBrowsers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        // 恶意URL列表
        private readonly HashSet<string> _maliciousUrls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        // 钓鱼URL列表
        private readonly HashSet<string> _phishingUrls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        // 可疑URL模式
        private readonly List<string> _suspiciousUrlPatterns = new List<string>();
        #endregion

        #region 事件
        public event EventHandler<BrowserThreatEventArgs> ThreatDetected;
        public event EventHandler<BrowserEventArgs> BrowserLaunched;
        public event EventHandler<BrowserEventArgs> BrowserClosed;
        public event EventHandler<BrowserDataEventArgs> DataCollected;
        #endregion

        #region 构造函数
        public NativeBrowserProtection(NativeSecurityCoreWrapper core)
        {
            _core = core ?? throw new ArgumentNullException(nameof(core));
            InitializeDefaultProtection();
        }

        ~NativeBrowserProtection()
        {
            Dispose(false);
        }
        #endregion

        #region 公共属性
        public bool IsEnabled
        {
            get => _core.BrowserProtectionEnabled;
            set => _core.BrowserProtectionEnabled = value;
        }

        public bool IsMonitoring
        {
            get => _isMonitoring;
        }

        public IReadOnlyList<string> ProtectedBrowsers
        {
            get
            {
                lock (_protectedBrowsers)
                {
                    return _protectedBrowsers.ToList().AsReadOnly();
                }
            }
        }

        public int MaliciousUrlCount => _maliciousUrls.Count;
        public int PhishingUrlCount => _phishingUrls.Count;
        #endregion

        #region 公共方法

        /// <summary>
        /// 开始浏览器保护监控
        /// </summary>
        public void StartMonitoring()
        {
            if (_isMonitoring)
                return;

            _isMonitoring = true;
            // 启动浏览器进程监控
            StartBrowserProcessMonitor();
        }

        /// <summary>
        /// 停止浏览器保护监控
        /// </summary>
        public void StopMonitoring()
        {
            if (!_isMonitoring)
                return;

            _isMonitoring = false;
            StopBrowserProcessMonitor();
        }

        /// <summary>
        /// 添加恶意URL
        /// </summary>
        public void AddMaliciousUrl(string url)
        {
            if (string.IsNullOrWhiteSpace(url))
                return;

            lock (_maliciousUrls)
            {
                _maliciousUrls.Add(NormalizeUrl(url));
            }
        }

        /// <summary>
        /// 批量添加恶意URL
        /// </summary>
        public void AddMaliciousUrls(IEnumerable<string> urls)
        {
            foreach (var url in urls)
            {
                AddMaliciousUrl(url);
            }
        }

        /// <summary>
        /// 移除恶意URL
        /// </summary>
        public void RemoveMaliciousUrl(string url)
        {
            if (string.IsNullOrWhiteSpace(url))
                return;

            lock (_maliciousUrls)
            {
                _maliciousUrls.Remove(NormalizeUrl(url));
            }
        }

        /// <summary>
        /// 添加钓鱼URL
        /// </summary>
        public void AddPhishingUrl(string url)
        {
            if (string.IsNullOrWhiteSpace(url))
                return;

            lock (_phishingUrls)
            {
                _phishingUrls.Add(NormalizeUrl(url));
            }
        }

        /// <summary>
        /// 移除钓鱼URL
        /// </summary>
        public void RemovePhishingUrl(string url)
        {
            if (string.IsNullOrWhiteSpace(url))
                return;

            lock (_phishingUrls)
            {
                _phishingUrls.Remove(NormalizeUrl(url));
            }
        }

        /// <summary>
        /// 检查URL安全性
        /// </summary>
        public UrlCheckResult CheckUrl(string url)
        {
            var result = new UrlCheckResult
            {
                Url = url,
                CheckTime = DateTime.Now
            };

            if (string.IsNullOrWhiteSpace(url))
            {
                result.IsSafe = true;
                return result;
            }

            var normalizedUrl = NormalizeUrl(url);

            // 检查恶意URL
            lock (_maliciousUrls)
            {
                if (_maliciousUrls.Contains(normalizedUrl))
                {
                    result.IsSafe = false;
                    result.ThreatType = "Malicious";
                    result.ThreatDescription = "恶意网站";
                    return result;
                }

                // 检查是否包含恶意URL的域名
                foreach (var maliciousUrl in _maliciousUrls)
                {
                    if (normalizedUrl.Contains(GetDomain(maliciousUrl)))
                    {
                        result.IsSafe = false;
                        result.ThreatType = "Malicious";
                        result.ThreatDescription = "恶意网站域名";
                        return result;
                    }
                }
            }

            // 检查钓鱼URL
            lock (_phishingUrls)
            {
                if (_phishingUrls.Contains(normalizedUrl))
                {
                    result.IsSafe = false;
                    result.ThreatType = "Phishing";
                    result.ThreatDescription = "钓鱼网站";
                    return result;
                }

                foreach (var phishingUrl in _phishingUrls)
                {
                    if (normalizedUrl.Contains(GetDomain(phishingUrl)))
                    {
                        result.IsSafe = false;
                        result.ThreatType = "Phishing";
                        result.ThreatDescription = "钓鱼网站域名";
                        return result;
                    }
                }
            }

            // 检查可疑URL模式
            if (MatchesSuspiciousPattern(url))
            {
                result.IsSafe = false;
                result.ThreatType = "Suspicious";
                result.ThreatDescription = "可疑URL模式";
                return result;
            }

            // 检查钓鱼特征
            if (HasPhishingIndicators(url))
            {
                result.IsSafe = false;
                result.ThreatType = "Phishing";
                result.ThreatDescription = "具有钓鱼特征";
                return result;
            }

            result.IsSafe = true;
            return result;
        }

        /// <summary>
        /// 扫描浏览器数据
        /// </summary>
        public List<BrowserDataInfo> ScanBrowserData()
        {
            var data = new List<BrowserDataInfo>();

            try
            {
                // 扫描Chrome数据
                var chromeData = ScanChromeData();
                data.AddRange(chromeData);

                // 扫描Edge数据
                var edgeData = ScanEdgeData();
                data.AddRange(edgeData);

                // 扫描Firefox数据
                var firefoxData = ScanFirefoxData();
                data.AddRange(firefoxData);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"扫描浏览器数据失败: {ex.Message}");
            }

            return data;
        }

        /// <summary>
        /// 清理浏览器数据
        /// </summary>
        public bool ClearBrowserData(BrowserDataType dataType)
        {
            try
            {
                switch (dataType)
                {
                    case BrowserDataType.History:
                        ClearBrowserHistory();
                        break;
                    case BrowserDataType.Cookies:
                        ClearBrowserCookies();
                        break;
                    case BrowserDataType.Cache:
                        ClearBrowserCache();
                        break;
                    case BrowserDataType.Passwords:
                        // 警告：密码清理需要特殊处理
                        return false;
                    case BrowserDataType.All:
                        ClearBrowserHistory();
                        ClearBrowserCookies();
                        ClearBrowserCache();
                        break;
                }

                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// 获取浏览器信息
        /// </summary>
        public List<BrowserInfo> GetInstalledBrowsers()
        {
            var browsers = new List<BrowserInfo>();

            // Chrome
            var chromePath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Google", "Chrome", "Application", "chrome.exe");

            if (File.Exists(chromePath))
            {
                browsers.Add(new BrowserInfo
                {
                    Name = "Google Chrome",
                    Path = chromePath,
                    Version = GetFileVersion(chromePath),
                    IsInstalled = true
                });
            }

            // Edge
            var edgePath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                "Microsoft", "Edge", "Application", "msedge.exe");

            if (File.Exists(edgePath))
            {
                browsers.Add(new BrowserInfo
                {
                    Name = "Microsoft Edge",
                    Path = edgePath,
                    Version = GetFileVersion(edgePath),
                    IsInstalled = true
                });
            }

            // Firefox
            var firefoxPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                "Mozilla Firefox", "firefox.exe");

            if (File.Exists(firefoxPath))
            {
                browsers.Add(new BrowserInfo
                {
                    Name = "Mozilla Firefox",
                    Path = firefoxPath,
                    Version = GetFileVersion(firefoxPath),
                    IsInstalled = true
                });
            }

            // 360浏览器
            var360Path = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                "360", "360se6", "Application", "360se.exe");

            if (File.Exists(360Path))
            {
                browsers.Add(new BrowserInfo
                {
                    Name = "360安全浏览器",
                    Path = 360Path,
                    Version = GetFileVersion(360Path),
                    IsInstalled = true
                });
            }

            return browsers;
        }

        #endregion

        #region 私有方法
        private void InitializeDefaultProtection()
        {
            // 添加默认保护的浏览器
            _protectedBrowsers.Add("chrome.exe");
            _protectedBrowsers.Add("msedge.exe");
            _protectedBrowsers.Add("firefox.exe");
            _protectedBrowsers.Add("360se.exe");
            _protectedBrowsers.Add("opera.exe");
            _protectedBrowsers.Add("brave.exe");

            // 添加可疑URL模式
            _suspiciousUrlPatterns.Add(@"\.tk$");
            _suspiciousUrlPatterns.Add(@"\.ml$");
            _suspiciousUrlPatterns.Add(@"\.ga$");
            _suspiciousUrlPatterns.Add(@"\.cf$");
            _suspiciousUrlPatterns.Add(@"\.gq$");
            _suspiciousUrlPatterns.Add(@"-free-.*\.com");
            _suspiciousUrlPatterns.Add(@"download-.*\.exe");
            _suspiciousUrlPatterns.Add(@"[a-z]{10,}\.com");

            // 添加示例恶意URL（实际应该从数据库加载）
            AddMaliciousUrl("malware-example.com");
            AddMaliciousUrl("virus-test.com");
        }

        private void StartBrowserProcessMonitor()
        {
            // 简化实现：定期检查浏览器进程
        }

        private void StopBrowserProcessMonitor()
        {
            // 停止监控
        }

        private string NormalizeUrl(string url)
        {
            if (string.IsNullOrWhiteSpace(url))
                return string.Empty;

            try
            {
                // 移除协议和尾部斜杠
                url = url.Trim().ToLower();
                if (url.StartsWith("http://"))
                    url = url.Substring(7);
                if (url.StartsWith("https://"))
                    url = url.Substring(8);
                if (url.EndsWith("/"))
                    url = url.TrimEnd('/');

                return url;
            }
            catch
            {
                return url;
            }
        }

        private string GetDomain(string url)
        {
            try
            {
                if (!url.StartsWith("http"))
                    url = "http://" + url;

                var uri = new Uri(url);
                return uri.Host;
            }
            catch
            {
                return url;
            }
        }

        private bool MatchesSuspiciousPattern(string url)
        {
            foreach (var pattern in _suspiciousUrlPatterns)
            {
                try
                {
                    if (Regex.IsMatch(url, pattern, RegexOptions.IgnoreCase))
                        return true;
                }
                catch
                {
                    // 忽略无效的正则表达式
                }
            }

            return false;
        }

        private bool HasPhishingIndicators(string url)
        {
            var lowerUrl = url.ToLower();

            // IP地址作为主机名
            if (Regex.IsMatch(lowerUrl, @"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"))
                return true;

            // 过长URL
            if (url.Length > 200)
                return true;

            // 包含多个域名
            var parts = lowerUrl.Split('.');
            if (parts.Length > 5)
                return true;

            // 包含可疑关键词
            var phishingKeywords = new[] { "login", "signin", "account", "verify", "secure", "update", "confirm" };
            if (phishingKeywords.Any(k => lowerUrl.Contains(k)) && lowerUrl.Contains("@"))
                return true;

            // 混淆字符
            if (url.Contains("0") || url.Contains("1") || url.Contains("l") || url.Contains("i"))
            {
                // 可能的域名混淆
            }

            return false;
        }

        private List<BrowserDataInfo> ScanChromeData()
        {
            var data = new List<BrowserDataInfo>();

            var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var chromePath = Path.Combine(localAppData, "Google", "Chrome", "User Data");

            if (!Directory.Exists(chromePath))
                return data;

            // 扫描历史记录
            var historyPath = Path.Combine(chromePath, "Default", "History");
            if (File.Exists(historyPath))
            {
                data.Add(new BrowserDataInfo
                {
                    BrowserName = "Chrome",
                    DataType = BrowserDataType.History,
                    Path = historyPath,
                    Size = new FileInfo(historyPath).Length
                });
            }

            // 扫描Cookies
            var cookiesPath = Path.Combine(chromePath, "Default", "Cookies");
            if (File.Exists(cookiesPath))
            {
                data.Add(new BrowserDataInfo
                {
                    BrowserName = "Chrome",
                    DataType = BrowserDataType.Cookies,
                    Path = cookiesPath,
                    Size = new FileInfo(cookiesPath).Length
                });
            }

            return data;
        }

        private List<BrowserDataInfo> ScanEdgeData()
        {
            var data = new List<BrowserDataInfo>();

            var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var edgePath = Path.Combine(localAppData, "Microsoft", "Edge", "User Data");

            if (!Directory.Exists(edgePath))
                return data;

            var historyPath = Path.Combine(edgePath, "Default", "History");
            if (File.Exists(historyPath))
            {
                data.Add(new BrowserDataInfo
                {
                    BrowserName = "Edge",
                    DataType = BrowserDataType.History,
                    Path = historyPath,
                    Size = new FileInfo(historyPath).Length
                });
            }

            return data;
        }

        private List<BrowserDataInfo> ScanFirefoxData()
        {
            var data = new List<BrowserDataInfo>();

            var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            var firefoxPath = Path.Combine(appData, "Mozilla", "Firefox", "Profiles");

            if (!Directory.Exists(firefoxPath))
                return data;

            foreach (var profile in Directory.GetDirectories(firefoxPath))
            {
                var historyPath = Path.Combine(profile, "places.sqlite");
                if (File.Exists(historyPath))
                {
                    data.Add(new BrowserDataInfo
                    {
                        BrowserName = "Firefox",
                        DataType = BrowserDataType.History,
                        Path = historyPath,
                        Size = new FileInfo(historyPath).Length
                    });
                }
            }

            return data;
        }

        private void ClearBrowserHistory()
        {
            // 简化实现：删除历史记录数据库
            try
            {
                var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

                // Chrome
                var chromeHistory = Path.Combine(localAppData, "Google", "Chrome", "User Data", "Default", "History");
                if (File.Exists(chromeHistory))
                {
                    File.Delete(chromeHistory);
                }

                // Edge
                var edgeHistory = Path.Combine(localAppData, "Microsoft", "Edge", "User Data", "Default", "History");
                if (File.Exists(edgeHistory))
                {
                    File.Delete(edgeHistory);
                }
            }
            catch
            {
                // 忽略错误
            }
        }

        private void ClearBrowserCookies()
        {
            try
            {
                var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

                var chromeCookies = Path.Combine(localAppData, "Google", "Chrome", "User Data", "Default", "Cookies");
                if (File.Exists(chromeCookies))
                {
                    File.Delete(chromeCookies);
                }
            }
            catch
            {
                // 忽略错误
            }
        }

        private void ClearBrowserCache()
        {
            try
            {
                var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

                // Chrome缓存
                var chromeCache = Path.Combine(localAppData, "Google", "Chrome", "User Data", "Default", "Cache");
                if (Directory.Exists(chromeCache))
                {
                    Directory.Delete(chromeCache, true);
                    Directory.CreateDirectory(chromeCache);
                }
            }
            catch
            {
                // 忽略错误
            }
        }

        private string GetFileVersion(string filePath)
        {
            try
            {
                var versionInfo = System.Diagnostics.FileVersionInfo.GetVersionInfo(filePath);
                return versionInfo.FileVersion ?? "Unknown";
            }
            catch
            {
                return "Unknown";
            }
        }
        #endregion

        #region IDisposable
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                StopMonitoring();
            }

            _disposed = true;
        }
        #endregion
    }

    #region 支持的类
    public class UrlCheckResult
    {
        public string Url { get; set; }
        public bool IsSafe { get; set; }
        public string ThreatType { get; set; }
        public string ThreatDescription { get; set; }
        public DateTime CheckTime { get; set; }
    }

    public class BrowserInfo
    {
        public string Name { get; set; }
        public string Path { get; set; }
        public string Version { get; set; }
        public bool IsInstalled { get; set; }
    }

    public class BrowserDataInfo
    {
        public string BrowserName { get; set; }
        public BrowserDataType DataType { get; set; }
        public string Path { get; set; }
        public long Size { get; set; }
    }

    public class BrowserEventArgs : EventArgs
    {
        public string BrowserName { get; set; }
        public int ProcessId { get; set; }
    }

    public class BrowserThreatEventArgs : EventArgs
    {
        public string Url { get; set; }
        public string ThreatType { get; set; }
        public string Description { get; set; }
    }

    public class BrowserDataEventArgs : EventArgs
    {
        public BrowserDataInfo Data { get; set; }
    }

    public enum BrowserDataType
    {
        History,
        Cookies,
        Cache,
        Passwords,
        All
    }
    #endregion
}
