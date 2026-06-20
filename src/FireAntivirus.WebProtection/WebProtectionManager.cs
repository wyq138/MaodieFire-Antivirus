using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using FireAntivirus.Common;
using FireAntivirus.Data;

namespace FireAntivirus.WebProtection
{
    public class WebProtectionManager
    {
        private DataManager _dataManager;
        private HashSet<string> _blockedUrls;
        private HashSet<string> _phishingUrls;
        private HashSet<string> _maliciousDomains;

        public WebProtectionManager(DataManager dataManager)
        {
            _dataManager = dataManager;
            _blockedUrls = new HashSet<string>();
            _phishingUrls = new HashSet<string>();
            _maliciousDomains = new HashSet<string>();
            InitializeWebProtection();
        }

        private void InitializeWebProtection()
        {
            // 加载恶意URL和域名列表
            LoadBlockedUrls();
            LoadPhishingUrls();
            LoadMaliciousDomains();
        }

        private void LoadBlockedUrls()
        {
            // 模拟加载阻止的URL列表
            _blockedUrls.Add("http://malicious-site.com");
            _blockedUrls.Add("http://phishing-site.com");
            _blockedUrls.Add("http://malware-download.com");
        }

        private void LoadPhishingUrls()
        {
            // 模拟加载钓鱼网站URL列表
            _phishingUrls.Add("http://fake-bank.com");
            _phishingUrls.Add("http://login-fake.com");
            _phishingUrls.Add("http://secure-login.com");
        }

        private void LoadMaliciousDomains()
        {
            // 模拟加载恶意域名列表
            _maliciousDomains.Add("malicious-domain.com");
            _maliciousDomains.Add("phishing-domain.com");
            _maliciousDomains.Add("malware-domain.com");
        }

        public async Task<WebProtectionResult> CheckUrl(string url)
        {
            try
            {
                Uri uri = new Uri(url);
                string domain = uri.Host;

                // 检查URL是否在阻止列表中
                if (_blockedUrls.Contains(url))
                {
                    return new WebProtectionResult
                    {
                        Safe = false,
                        Url = url,
                        ThreatType = "BlockedUrl",
                        Message = "此URL已被阻止"
                    };
                }

                // 检查是否为钓鱼网站
                if (_phishingUrls.Contains(url))
                {
                    return new WebProtectionResult
                    {
                        Safe = false,
                        Url = url,
                        ThreatType = "Phishing",
                        Message = "此网站可能是钓鱼网站"
                    };
                }

                // 检查域名是否为恶意域名
                if (_maliciousDomains.Contains(domain))
                {
                    return new WebProtectionResult
                    {
                        Safe = false,
                        Url = url,
                        ThreatType = "MaliciousDomain",
                        Message = "此域名已被标记为恶意"
                    };
                }

                // 检查URL是否包含可疑关键词
                if (ContainsSuspiciousKeywords(url))
                {
                    return new WebProtectionResult
                    {
                        Safe = false,
                        Url = url,
                        ThreatType = "Suspicious",
                        Message = "此URL包含可疑关键词"
                    };
                }

                // 模拟实时检查
                bool isSafe = await CheckUrlRealTime(url);
                if (!isSafe)
                {
                    return new WebProtectionResult
                    {
                        Safe = false,
                        Url = url,
                        ThreatType = "RealTimeBlock",
                        Message = "实时检查发现此URL存在安全风险"
                    };
                }

                return new WebProtectionResult
                {
                    Safe = true,
                    Url = url,
                    ThreatType = "Safe",
                    Message = "此URL安全"
                };
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "WebProtectionError",
                    Message = "网页防护检查错误",
                    Details = $"URL: {url}, 错误: {ex.Message}"
                });

                return new WebProtectionResult
                {
                    Safe = true, // 默认安全，避免误报
                    Url = url,
                    ThreatType = "Error",
                    Message = "检查过程中发生错误"
                };
            }
        }

        private bool ContainsSuspiciousKeywords(string url)
        {
            string[] suspiciousKeywords = { "hack", "crack", "keygen", "serial", "malware", "virus", "trojan", "ransomware" };
            return suspiciousKeywords.Any(keyword => url.ToLower().Contains(keyword));
        }

        private async Task<bool> CheckUrlRealTime(string url)
        {
            // 模拟实时检查
            await Task.Delay(100);
            return true; // 默认安全
        }

        public void AddBlockedUrl(string url)
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

        public void RemoveBlockedUrl(string url)
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

        public List<string> GetBlockedUrls()
        {
            return _blockedUrls.ToList();
        }

        public List<string> GetPhishingUrls()
        {
            return _phishingUrls.ToList();
        }

        public List<string> GetMaliciousDomains()
        {
            return _maliciousDomains.ToList();
        }
    }
}