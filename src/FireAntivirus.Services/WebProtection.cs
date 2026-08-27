using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using FireAntivirus.Data;
using FireAntivirus.Engine;
using FireAntivirus.Common.Notification;

namespace FireAntivirus.Services
{
    /// <summary>
    /// 网页防护服务 - 通过Hosts文件和实时网络监控实现URL拦截
    /// </summary>
    public class WebProtection : IMonitor
    {
        private Thread _monitorThread;
        private bool _isRunning;
        private DataManager _dataManager;
        private AntivirusEngine _antivirusEngine;
        private List<string> _blockedWebsites;
        private List<string> _allowedWebsites;
        private List<string> _adDomains;
        private List<string> _phishingPatterns;
        private bool _enableWebsiteBlock = true;
        private bool _enableAdBlock = true;
        private bool _enablePhishingProtection = true;
        private CancellationTokenSource _cts;
        private Timer _dnsFlushTimer;
        
        // Hosts文件路径
        private static readonly string HostsFilePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            @"drivers\etc\hosts"
        );
        
        // 标记已添加到Hosts的条目
        private const string HostsMarker = "# FireAntivirus Block - ";
        
        // DNS刷新间隔（分钟）
        private const int DnsFlushIntervalMinutes = 30;

        public bool IsRunning => _isRunning;
        public bool EnableWebsiteBlock => _enableWebsiteBlock;
        public bool EnableAdBlock => _enableAdBlock;
        public int BlockedSitesCount => _blockedWebsites?.Count ?? 0;
        public int AdDomainsCount => _adDomains?.Count ?? 0;

        // Windows API for DNS cache
        [DllImport("dnsapi.dll", EntryPoint = "DnsFlushResolverCache")]
        private static extern bool DnsFlushResolverCache();

        public WebProtection(DataManager dataManager, AntivirusEngine antivirusEngine)
        {
            _dataManager = dataManager;
            _antivirusEngine = antivirusEngine;
            _blockedWebsites = new List<string>();
            _allowedWebsites = new List<string>();
            _adDomains = new List<string>();
            _phishingPatterns = new List<string>();
            LoadBlockedWebsites();
            LoadAdDomains();
            LoadPhishingPatterns();
            LoadAllowedWebsites();
        }

        public void Start()
        {
            if (_isRunning) return;
            
            _isRunning = true;
            _cts = new CancellationTokenSource();
            
            // 应用Hosts文件规则
            if (_enableWebsiteBlock || _enableAdBlock)
            {
                ApplyHostsFileRules();
            }
            
            // 启动浏览器进程监控线程
            _monitorThread = new Thread(() => MonitorBrowserProcesses(_cts.Token));
            _monitorThread.IsBackground = true;
            _monitorThread.Start();
            
            // 定期刷新DNS缓存
            _dnsFlushTimer = new Timer(_ => FlushDnsCache(), null, 
                TimeSpan.FromMinutes(DnsFlushIntervalMinutes), 
                TimeSpan.FromMinutes(DnsFlushIntervalMinutes));
            
            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "WebProtectionStarted",
                Message = "网页防护服务已启动",
                Details = $"网站拦截: {_enableWebsiteBlock}, 广告拦截: {_enableAdBlock}, 钓鱼防护: {_enablePhishingProtection}"
            });
        }

        public void Stop()
        {
            if (!_isRunning) return;
            
            _isRunning = false;
            _cts?.Cancel();
            _monitorThread?.Join(2000);
            _dnsFlushTimer?.Dispose();
            
            // 清理Hosts文件中的规则
            RemoveHostsFileRules();
            
            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "WebProtectionStopped",
                Message = "网页防护服务已停止"
            });
        }

        #region Hosts文件管理

        /// <summary>
        /// 应用Hosts文件规则 - 真正拦截恶意网站
        /// </summary>
        private void ApplyHostsFileRules()
        {
            try
            {
                // 检查是否有管理员权限
                if (!HasAdminPrivileges())
                {
                    NotificationService.Instance.ShowNotification(
                        "网页防护",
                        "需要管理员权限才能拦截恶意网站",
                        NotificationType.Warning
                    );
                    return;
                }

                var hostsContent = new StringBuilder();
                var existingLines = File.Exists(HostsFilePath) 
                    ? File.ReadAllLines(HostsFilePath).ToList() 
                    : new List<string>();

                // 过滤掉旧的FireAntivirus规则
                var filteredLines = existingLines
                    .Where(line => !line.Contains(HostsMarker))
                    .ToList();

                hostsContent.AppendLine(string.Join(Environment.NewLine, filteredLines));
                hostsContent.AppendLine();
                hostsContent.AppendLine("# === FireAntivirus Web Protection Rules ===");
                hostsContent.AppendLine($"# Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                hostsContent.AppendLine("# DO NOT MODIFY THESE LINES MANUALLY");

                // 添加网站拦截规则
                if (_enableWebsiteBlock)
                {
                    foreach (var site in _blockedWebsites)
                    {
                        var domain = CleanDomain(site);
                        if (!string.IsNullOrEmpty(domain) && !_allowedWebsites.Contains(domain))
                        {
                            hostsContent.AppendLine($"127.0.0.1    {domain}    {HostsMarker}{domain}");
                            hostsContent.AppendLine($"127.0.0.1    www.{domain}    {HostsMarker}{domain}");
                        }
                    }
                }

                // 添加广告域名拦截规则
                if (_enableAdBlock)
                {
                    foreach (var adDomain in _adDomains)
                    {
                        var domain = CleanDomain(adDomain);
                        if (!string.IsNullOrEmpty(domain) && !_allowedWebsites.Contains(domain))
                        {
                            hostsContent.AppendLine($"127.0.0.1    {domain}    {HostsMarker}ad-{domain}");
                            hostsContent.AppendLine($"127.0.0.1    www.{domain}    {HostsMarker}ad-{domain}");
                        }
                    }
                }

                hostsContent.AppendLine("# === End FireAntivirus Rules ===");
                hostsContent.AppendLine();

                // 写入Hosts文件
                File.WriteAllText(HostsFilePath, hostsContent.ToString(), Encoding.UTF8);
                
                // 刷新DNS缓存使规则立即生效
                FlushDnsCache();

                var blockedCount = _enableWebsiteBlock ? _blockedWebsites.Count : 0;
                var adCount = _enableAdBlock ? _adDomains.Count : 0;
                
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "HostsFileUpdated",
                    Message = "Hosts文件规则已应用",
                    Details = $"网站: {blockedCount}, 广告: {adCount}"
                });
            }
            catch (UnauthorizedAccessException)
            {
                NotificationService.Instance.ShowNotification(
                    "网页防护",
                    "无法修改Hosts文件，请以管理员身份运行",
                    NotificationType.Error
                );
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "HostsFileError",
                    Message = "更新Hosts文件失败",
                    Details = ex.Message
                });
            }
        }

        /// <summary>
        /// 移除Hosts文件规则
        /// </summary>
        private void RemoveHostsFileRules()
        {
            try
            {
                if (!File.Exists(HostsFilePath)) return;
                if (!HasAdminPrivileges()) return;

                var lines = File.ReadAllLines(HostsFilePath)
                    .Where(line => !line.Contains(HostsMarker))
                    .ToList();

                File.WriteAllLines(HostsFilePath, lines, Encoding.UTF8);
                FlushDnsCache();
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "WebProtection.cs 捕获异常", ex.Message); }
        }

        /// <summary>
        /// 添加单个网站到拦截列表并立即应用
        /// </summary>
        public bool BlockWebsite(string domain)
        {
            domain = CleanDomain(domain);
            if (string.IsNullOrEmpty(domain)) return false;
            if (_blockedWebsites.Contains(domain)) return true;
            if (_allowedWebsites.Contains(domain)) return false;

            _blockedWebsites.Add(domain);
            SaveBlockedWebsites();

            // 立即更新Hosts文件
            if (_enableWebsiteBlock && HasAdminPrivileges())
            {
                AddToHostsFile(domain, false);
            }

            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "WebsiteBlocked",
                Message = "网站已添加到拦截列表",
                Details = domain
            });

            return true;
        }

        /// <summary>
        /// 从拦截列表移除网站
        /// </summary>
        public bool UnblockWebsite(string domain)
        {
            domain = CleanDomain(domain);
            if (!_blockedWebsites.Contains(domain)) return false;

            _blockedWebsites.Remove(domain);
            SaveBlockedWebsites();

            // 更新Hosts文件
            if (HasAdminPrivileges())
            {
                RemoveFromHostsFile(domain);
            }

            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "WebsiteUnblocked",
                Message = "网站已从拦截列表移除",
                Details = domain
            });

            return true;
        }

        private void AddToHostsFile(string domain, bool isAdDomain)
        {
            try
            {
                if (!HasAdminPrivileges()) return;
                
                var prefix = isAdDomain ? "ad-" : "";
                var lines = new[]
                {
                    $"127.0.0.1    {domain}    {HostsMarker}{prefix}{domain}",
                    $"127.0.0.1    www.{domain}    {HostsMarker}{prefix}{domain}"
                };
                File.AppendAllLines(HostsFilePath, lines, Encoding.UTF8);
                FlushDnsCache();
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "WebProtection.cs 捕获异常", ex.Message); }
        }

        private void RemoveFromHostsFile(string domain)
        {
            try
            {
                if (!HasAdminPrivileges()) return;
                
                var lines = File.ReadAllLines(HostsFilePath)
                    .Where(line => !line.Contains(domain) || !line.Contains(HostsMarker))
                    .ToList();
                File.WriteAllLines(HostsFilePath, lines, Encoding.UTF8);
                FlushDnsCache();
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "WebProtection.cs 捕获异常", ex.Message); }
        }

        private void FlushDnsCache()
        {
            try
            {
                DnsFlushResolverCache();
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "WebProtection.cs 捕获异常", ex.Message); }
        }

        private bool HasAdminPrivileges()
        {
            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            var principal = new System.Security.Principal.WindowsPrincipal(identity);
            return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }

        private string CleanDomain(string url)
        {
            if (string.IsNullOrWhiteSpace(url)) return string.Empty;
            
            // 移除协议前缀
            var domain = url.ToLowerInvariant();
            domain = domain.Replace("https://", "").Replace("http://", "");
            domain = domain.Replace("www.", "");
            
            // 只保留域名部分
            var slashIndex = domain.IndexOf('/');
            if (slashIndex > 0)
                domain = domain.Substring(0, slashIndex);
            
            // 移除端口
            var colonIndex = domain.IndexOf(':');
            if (colonIndex > 0)
                domain = domain.Substring(0, colonIndex);
            
            return domain.Trim().TrimEnd('/');
        }

        #endregion

        #region 浏览器进程监控

        private void MonitorBrowserProcesses(CancellationToken token)
        {
            var browserNames = new[] { "chrome", "firefox", "msedge", "iexplore", "opera", "brave" };

            while (!token.IsCancellationRequested && _isRunning)
            {
                try
                {
                    var processes = Process.GetProcesses()
                        .Where(p => browserNames.Any(b => p.ProcessName.Contains(b, StringComparison.OrdinalIgnoreCase)))
                        .ToList();

                    foreach (var process in processes)
                    {
                        if (token.IsCancellationRequested) break;
                        CheckBrowserActivity(process);
                    }
                }
                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "WebProtection.cs 捕获异常", ex.Message); }

                Thread.Sleep(5000);
            }
        }

        private void CheckBrowserActivity(Process process)
        {
            try
            {
                var commandLine = GetProcessCommandLine(process.Id);
                if (string.IsNullOrEmpty(commandLine)) return;

                // 检查白名单
                foreach (var allowed in _allowedWebsites)
                {
                    if (commandLine.Contains(allowed, StringComparison.OrdinalIgnoreCase))
                        return;
                }

                // 检查钓鱼模式
                if (_enablePhishingProtection)
                {
                    foreach (var pattern in _phishingPatterns)
                    {
                        if (commandLine.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                        {
                            NotificationService.Instance.ShowNotification(
                                "钓鱼防护",
                                $"警告：正在访问可疑网站 - {pattern}",
                                NotificationType.Error
                            );

                            _dataManager.AddLog(new LogEntry
                            {
                                Id = Guid.NewGuid().ToString(),
                                Time = DateTime.Now,
                                Type = "PhishingDetected",
                                Message = "检测到钓鱼网站访问",
                                Details = $"模式: {pattern}, 进程: {process.ProcessName}"
                            });
                            break;
                        }
                    }
                }

                // 检查被阻止的网站（作为备份，主要依赖Hosts文件）
                if (_enableWebsiteBlock)
                {
                    foreach (var blockedSite in _blockedWebsites)
                    {
                        if (commandLine.Contains(blockedSite, StringComparison.OrdinalIgnoreCase))
                        {
                            _dataManager.AddLog(new LogEntry
                            {
                                Id = Guid.NewGuid().ToString(),
                                Time = DateTime.Now,
                                Type = "BlockedWebsiteAccess",
                                Message = "访问被阻止的网站",
                                Details = $"网站: {blockedSite}, 进程: {process.ProcessName}"
                            });
                            break;
                        }
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "WebProtection.cs 捕获异常", ex.Message); }
        }

        private string GetProcessCommandLine(int processId)
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {processId}");
                
                foreach (var obj in searcher.Get())
                {
                    return obj["CommandLine"] as string ?? string.Empty;
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "WebProtection.cs 捕获异常", ex.Message); }
            return string.Empty;
        }

        #endregion

        #region 数据加载与保存

        private void LoadBlockedWebsites()
        {
            try
            {
                var data = _dataManager.LoadWebProtectionData();
                if (data?.BlockedWebsites != null && data.BlockedWebsites.Count > 0)
                {
                    _blockedWebsites = data.BlockedWebsites;
                }
                else
                {
                    // 默认恶意网站列表
                    _blockedWebsites = new List<string>
                    {
                        "malware.com", "phishing-site.com", "virus-download.net",
                        "trojan-horse.org", "ransomware-site.com", "keylogger.net",
                        "spyware-central.com", "adware-payload.net", "botnet-c2.com",
                        "fake-update.com", "crack-download.org", "warez-site.net"
                    };
                }
            }
            catch
            {
                _blockedWebsites = new List<string>
                {
                    "malware.com", "phishing-site.com", "virus-download.net"
                };
            }
        }

        private void LoadAllowedWebsites()
        {
            try
            {
                var data = _dataManager.LoadWebProtectionData();
                if (data?.AllowedWebsites != null)
                {
                    _allowedWebsites = data.AllowedWebsites;
                }
                else
                {
                    _allowedWebsites = new List<string>();
                }
            }
            catch
            {
                _allowedWebsites = new List<string>();
            }
        }

        private void LoadAdDomains()
        {
            try
            {
                var data = _dataManager.LoadWebProtectionData();
                if (data?.AdDomains != null && data.AdDomains.Count > 0)
                {
                    _adDomains = data.AdDomains;
                }
                else
                {
                    // 默认广告域名
                    _adDomains = new List<string>
                    {
                        "doubleclick.net", "googlesyndication.com", "adnxs.com",
                        "rubiconproject.com", "openx.net", "pubmatic.com",
                        "exponential.com", "advertising.com", "adsrvr.org",
                        "ads.twitter.com", "analytics.google.com"
                    };
                }
            }
            catch
            {
                _adDomains = new List<string> { "doubleclick.net", "googlesyndication.com" };
            }
        }

        private void LoadPhishingPatterns()
        {
            try
            {
                var data = _dataManager.LoadWebProtectionData();
                if (data?.PhishingPatterns != null && data.PhishingPatterns.Count > 0)
                {
                    _phishingPatterns = data.PhishingPatterns;
                }
                else
                {
                    // 默认钓鱼网站模式
                    _phishingPatterns = new List<string>
                    {
                        "login-verify", "account-suspended", "password-expired",
                        "security-alert", "verify-now", "urgent-action",
                        "confirm-identity", "update-payment", "invoice-",
                        "doc-share", "secure-login", "banking-verify"
                    };
                }
            }
            catch
            {
                _phishingPatterns = new List<string> { "login-verify", "account-suspended" };
            }
        }

        private void SaveBlockedWebsites()
        {
            try
            {
                var data = new WebProtectionData
                {
                    BlockedWebsites = _blockedWebsites,
                    AllowedWebsites = _allowedWebsites,
                    AdDomains = _adDomains,
                    PhishingPatterns = _phishingPatterns
                };
                _dataManager.SaveWebProtectionData(data);
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "WebProtection.cs 捕获异常", ex.Message); }
        }

        #endregion

        #region 公共接口

        public void UpdateSettings(bool enableWebsiteBlock, bool enableAdBlock, 
            bool enablePhishingProtection, List<string> blockedWebsites = null,
            List<string> adDomains = null, List<string> allowedWebsites = null)
        {
            _enableWebsiteBlock = enableWebsiteBlock;
            _enableAdBlock = enableAdBlock;
            _enablePhishingProtection = enablePhishingProtection;

            if (blockedWebsites != null)
            {
                _blockedWebsites = blockedWebsites;
            }
            if (adDomains != null)
            {
                _adDomains = adDomains;
            }
            if (allowedWebsites != null)
            {
                _allowedWebsites = allowedWebsites;
            }

            SaveBlockedWebsites();

            // 重新应用Hosts规则
            if (_isRunning && HasAdminPrivileges())
            {
                ApplyHostsFileRules();
            }

            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "WebProtectionSettingsUpdated",
                Message = "网页防护设置已更新",
                Details = $"网站拦截: {enableWebsiteBlock}, 广告拦截: {enableAdBlock}, 钓鱼防护: {enablePhishingProtection}"
            });
        }

        public void UpdateSettings(bool enableWebsiteBlock, bool enableAdBlock, List<string> blockedWebsites, List<string> adDomains)
        {
            UpdateSettings(enableWebsiteBlock, enableAdBlock, _enablePhishingProtection, blockedWebsites, adDomains, null);
        }

        public List<string> GetBlockedWebsites() => new List<string>(_blockedWebsites);
        public List<string> GetAllowedWebsites() => new List<string>(_allowedWebsites);
        public List<string> GetAdDomains() => new List<string>(_adDomains);
        public List<string> GetPhishingPatterns() => new List<string>(_phishingPatterns);

        public void AddAllowedWebsite(string domain)
        {
            domain = CleanDomain(domain);
            if (string.IsNullOrEmpty(domain) || _allowedWebsites.Contains(domain)) return;
            
            _allowedWebsites.Add(domain);
            _blockedWebsites.Remove(domain);
            SaveBlockedWebsites();
            
            if (HasAdminPrivileges())
            {
                RemoveFromHostsFile(domain);
            }
        }

        public void RemoveAllowedWebsite(string domain)
        {
            domain = CleanDomain(domain);
            _allowedWebsites.Remove(domain);
            SaveBlockedWebsites();
        }

        public bool IsWebsiteBlocked(string domain)
        {
            domain = CleanDomain(domain);
            return _blockedWebsites.Contains(domain);
        }

        #endregion
    }
}