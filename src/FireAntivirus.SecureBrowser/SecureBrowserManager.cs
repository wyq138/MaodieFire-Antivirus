using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using FireAntivirus.Common;
using FireAntivirus.Data;

namespace FireAntivirus.SecureBrowser
{
    public class SecureBrowserManager
    {
        private DataManager _dataManager;
        private HttpClient _httpClient;
        private List<string> _blockedUrls;
        private List<string> _safeUrls;
        private List<string> _trackingDomains;
        private bool _isEnabled;

        public SecureBrowserManager(DataManager dataManager)
        {
            _dataManager = dataManager;
            _httpClient = new HttpClient();
            _blockedUrls = new List<string>();
            _safeUrls = new List<string>();
            _trackingDomains = new List<string>();
            _isEnabled = true;
            InitializeSecureBrowser();
        }

        private void InitializeSecureBrowser()
        {
            LoadBlockedUrls();
            LoadSafeUrls();
            LoadTrackingDomains();
        }

        private void LoadBlockedUrls()
        {
            // 模拟加载阻止的URL列表
            _blockedUrls.Add("http://malicious-site.com");
            _blockedUrls.Add("http://phishing-site.com");
            _blockedUrls.Add("http://malware-download.com");
        }

        private void LoadSafeUrls()
        {
            // 模拟加载安全的URL列表
            _safeUrls.Add("https://google.com");
            _safeUrls.Add("https://bing.com");
            _safeUrls.Add("https://microsoft.com");
        }

        private void LoadTrackingDomains()
        {
            // 模拟加载跟踪域名列表
            _trackingDomains.Add("google-analytics.com");
            _trackingDomains.Add("doubleclick.net");
            _trackingDomains.Add("facebook.com");
        }

        public void Enable()
        {
            _isEnabled = true;
            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "SecureBrowserEnabled",
                Message = "安全浏览器已启用"
            });
        }

        public void Disable()
        {
            _isEnabled = false;
            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "SecureBrowserDisabled",
                Message = "安全浏览器已禁用"
            });
        }

        public bool IsEnabled()
        {
            return _isEnabled;
        }

        public SecureBrowserResult CheckUrl(string url)
        {
            var result = new SecureBrowserResult
            {
                Url = url,
                CheckTime = DateTime.Now
            };

            if (!_isEnabled)
            {
                result.Safe = true;
                result.Message = "安全浏览器已禁用";
                return result;
            }

            try
            {
                // 检查URL是否在安全列表中
                if (_safeUrls.Any(safeUrl => url.Contains(safeUrl))) {
                    result.Safe = true;
                    result.Message = "URL在安全列表中";
                    return result;
                }

                // 检查URL是否在阻止列表中
                if (_blockedUrls.Any(blockedUrl => url.Contains(blockedUrl))) {
                    result.Safe = false;
                    result.Message = "URL已被阻止";
                    result.ThreatType = "BlockedUrl";
                    return result;
                }

                // 检查URL是否包含跟踪域名
                foreach (var trackingDomain in _trackingDomains)
                {
                    if (url.Contains(trackingDomain))
                    {
                        result.Safe = true;
                        result.HasTracking = true;
                        result.Message = "URL包含跟踪域名";
                        return result;
                    }
                }

                // 检查URL是否包含恶意关键词
                if (ContainsMaliciousKeywords(url))
                {
                    result.Safe = false;
                    result.Message = "URL包含恶意关键词";
                    result.ThreatType = "SuspiciousUrl";
                    return result;
                }

                // 模拟实时检查
                var realTimeResult = CheckUrlRealTime(url);
                if (!realTimeResult)
                {
                    result.Safe = false;
                    result.Message = "实时检查发现URL存在安全风险";
                    result.ThreatType = "RealTimeBlock";
                    return result;
                }

                result.Safe = true;
                result.Message = "URL安全";
            }
            catch (Exception ex)
            {
                result.Safe = true; // 默认安全，避免误报
                result.Message = $"检查过程中发生错误: {ex.Message}";
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "SecureBrowserError",
                    Message = "安全浏览器检查错误",
                    Details = $"URL: {url}, 错误: {ex.Message}"
                });
            }

            return result;
        }

        private bool ContainsMaliciousKeywords(string url)
        {
            string[] maliciousKeywords = { "hack", "crack", "keygen", "serial", "malware", "virus", "trojan", "ransomware" };
            return maliciousKeywords.Any(keyword => url.ToLower().Contains(keyword));
        }

        private bool CheckUrlRealTime(string url)
        {
            // 模拟实时检查
            // 实际实现中应该调用云服务进行检查
            return true; // 默认安全
        }

        public void AddBlockedUrl(string url)
        {
            if (!_blockedUrls.Contains(url))
            {
                _blockedUrls.Add(url);
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "UrlBlocked",
                    Message = "URL已被添加到阻止列表",
                    Details = $"URL: {url}"
                });
            }
        }

        public void RemoveBlockedUrl(string url)
        {
            if (_blockedUrls.Contains(url))
            {
                _blockedUrls.Remove(url);
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "UrlUnblocked",
                    Message = "URL已从阻止列表中移除",
                    Details = $"URL: {url}"
                });
            }
        }

        public void AddSafeUrl(string url)
        {
            if (!_safeUrls.Contains(url))
            {
                _safeUrls.Add(url);
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "UrlMarkedSafe",
                    Message = "URL已被标记为安全",
                    Details = $"URL: {url}"
                });
            }
        }

        public List<string> GetBlockedUrls()
        {
            return _blockedUrls;
        }

        public List<string> GetSafeUrls()
        {
            return _safeUrls;
        }

        public List<string> GetTrackingDomains()
        {
            return _trackingDomains;
        }

        public string GetSafeBrowsingTips()
        {
            return "1. 始终检查URL是否以https://开头\n2. 不要点击可疑链接\n3. 使用强密码并定期更换\n4. 启用双因素认证\n5. 定期更新浏览器和安全软件";
        }
    }
}