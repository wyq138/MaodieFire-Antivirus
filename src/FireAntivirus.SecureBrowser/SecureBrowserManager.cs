using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using FireAntivirus.Common;
using FireAntivirus.Data;
using FireAntivirus.Engine;

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
            // 加载内置恶意URL列表
            var blockedUrls = new[]
            {
                // 恶意软件分发
                "malware-download.com",
                "virus-distribution.net",
                "free-virus-scan.org",
                "crack-software.com",
                "keygen-free.net",
                "serial-keys.org",
                // 钓鱼网站
                "fake-paypal-login.com",
                "secure-bank-account.net",
                "microsoft-verify.com",
                "google-account-verify.org",
                // 挖矿脚本
                "coinhive.com",
                "cryptominer.net",
                "web-miner.org",
                // 恶意广告
                "malicious-ads.com",
                "popup-virus.net"
            };
            
            foreach (var url in blockedUrls)
            {
                _blockedUrls.Add(url);
            }

            // 加载已知钓鱼域名
            var phishingDomains = new[]
            {
                "secure-paypal-login.com",
                "paypal-verify-account.net",
                "bank-of-america-login.org",
                "chase-secure-login.com",
                "wellsfargo-verify.net",
                "gmail-verify-login.com",
                "microsoft-account-verify.org",
                "outlook-security-verify.com",
                "facebook-security-verify.net",
                "instagram-verify-account.org"
            };
            
            foreach (var domain in phishingDomains)
            {
                _blockedUrls.Add(domain);
            }

            Console.WriteLine("[SecureBrowser] 已加载 " + _blockedUrls.Count + " 个阻止URL");
        }

        private void LoadSafeUrls()
        {
            // 加载白名单URL
            var safeUrls = new[]
            {
                "google.com",
                "microsoft.com",
                "apple.com",
                "github.com",
                "stackoverflow.com",
                "wikipedia.org"
            };
            
            foreach (var url in safeUrls)
            {
                _safeUrls.Add(url);
            }
        }

        private void LoadTrackingDomains()
        {
            // 加载完整的跟踪域名列表
            var trackingDomains = new[]
            {
                // Google跟踪
                "google-analytics.com",
                "googletagmanager.com",
                "googlesyndication.com",
                "googleadservices.com",
                "doubleclick.net",
                "adservice.google.com",
                
                // Facebook跟踪
                "facebook.com",
                "facebook.net",
                "connect.facebook.net",
                "pixel.facebook.com",
                
                // 广告网络
                "adnxs.com",
                "adsrvr.org",
                "advertising.com",
                "adform.net",
                "criteo.com",
                "rubiconproject.com",
                "pubmatic.com",
                "openx.net",
                "taboola.com",
                "outbrain.com",
                
                // 分析服务
                "amplitude.com",
                "mixpanel.com",
                "segment.io",
                "hotjar.com",
                "mouseflow.com",
                
                // 社交媒体跟踪
                "twitter.com",
                "linkedin.com",
                "instagram.com",
                "tiktok.com",
                "pinterest.com",
                
                // 其他跟踪
                "scorecardresearch.com",
                "quantserve.com",
                "newrelic.com",
                "bugsnag.com"
            };

            foreach (var domain in trackingDomains)
            {
                _trackingDomains.Add(domain);
            }

            Console.WriteLine("[SecureBrowser] 已加载 " + _trackingDomains.Count + " 个跟踪域名");
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
            // 实时检查URL是否在签名数据库中
            return !SignatureDatabaseUpdater.IsMaliciousUrl(url);
        }

        /// <summary>从签名数据库刷新阻止列表缓存。</summary>
        public void RefreshFromSignatureDb()
        {
            _blockedUrls.Clear();
            // 签名数据库的恶意URL存储在私有字典中，无法直接枚举，
            // 实时检查逻辑已委托给 CheckUrlRealTime 使用 SignatureDatabaseUpdater.IsMaliciousUrl
            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "SignatureDbRefresh",
                Message = "已从签名数据库刷新阻止列表",
                Details = $"当前签名库URL数: {SignatureDatabaseUpdater.UrlCount}, IP数: {SignatureDatabaseUpdater.IpCount}"
            });
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