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

        public WebProtectionManager(DataManager dataManager, AntivirusEngine antivirusEngine)
            : this(dataManager)
        {
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
            // 阻止的URL列表初始为空，用户可通过 AddBlockedUrl 手动添加
            // 实时检查由 CheckUrlRealTime 使用 SignatureDatabaseUpdater.IsMaliciousUrl 完成
        }

        private void LoadPhishingUrls()
        {
            // 钓鱼网站URL列表由用户手动添加，初始为空
        }

        private void LoadMaliciousDomains()
        {
            // 恶意域名列表由用户手动添加，初始为空
            // 实时检查已委托给 CheckUrlRealTime 使用 SignatureDatabaseUpdater.IsMaliciousUrl
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
            // 实时检查URL是否在签名数据库中
            await Task.Delay(100);
            return !SignatureDatabaseUpdater.IsMaliciousUrl(url);
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

        // === 兼容 WPF 页面调用的方法 ===

        public List<string> GetBlockedWebsites() => GetBlockedUrls();

        public List<string> GetAllowedWebsites() => new List<string>();

        public void BlockWebsite(string url) => AddBlockedUrl(url);

        public void UnblockWebsite(string url) => RemoveBlockedUrl(url);

        private HashSet<string> _allowedWebsites = new HashSet<string>();

        public void AddAllowedWebsite(string url)
        {
            _allowedWebsites.Add(url);
        }

        public void RemoveAllowedWebsite(string url)
        {
            _allowedWebsites.Remove(url);
        }

        public void UpdateSettings(bool blockPhishing, bool blockMalware, bool blockAds,
            List<string> blacklist, List<string> whitelist, List<string> allowedSites)
        {
            _blockedUrls = new HashSet<string>(blacklist);
            _allowedWebsites = new HashSet<string>(allowedSites);
            foreach (var site in whitelist)
                _allowedWebsites.Add(site);
        }
    }
}