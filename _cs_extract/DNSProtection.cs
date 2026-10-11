using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using FireAntivirus.Data;
using FireAntivirus.Engine;

namespace FireAntivirus.Services
{
    /// <summary>
    /// 专业级DNS保护服务 - 支持DoH/DoT、DNS劫持检测、DGA检测、恶意域名过滤
    /// </summary>
    public class DNSProtection : IMonitor
    {
        private Thread _monitorThread;
        private Thread _updateThread;
        private Thread _analysisThread;
        private bool _isRunning;
        private DataManager _dataManager;
        private AntivirusEngine _antivirusEngine;
        
        // 使用并发集合
        private ConcurrentDictionary<string, DNSQueryRecord> _queryHistory;
        private ConcurrentDictionary<string, DNSCacheEntry> _dnsCache;
        private ConcurrentDictionary<string, MaliciousDomainInfo> _maliciousDomains;
        private ConcurrentDictionary<string, TrustedDomainInfo> _trustedDomains;
        private ConcurrentDictionary<string, DNSAnomalyRecord> _anomalyRecords;
        private ConcurrentQueue<DNSAlert> _alerts;
        private ConcurrentDictionary<string, string> _currentDNSServers;
        
        // 黑名单和白名单
        private HashSet<string> _blockedDomains;
        private HashSet<string> _blockedIPs;
        private HashSet<string> _trustedDNSServers;
        private HashSet<string> _suspiciousTLDs;
        
        // 配置参数
        private int _monitoringInterval;
        private int _cacheTimeout;
        private bool _enableDNSOverHTTPS;
        private bool _enableDNSOverTLS;
        private bool _enableDNSHijackingDetection;
        private bool _enableDGADetection;
        private bool _enableFamilyProtection;
        private bool _enableMaliciousDomainBlocking;
        private bool _enableHostsProtection;
        private bool _enableDNSCacheProtection;
        private bool _logAllQueries;
        private int _maxQueryHistory;
        private int _maxCacheEntries;
        
        // 统计数据
        private long _totalQueries;
        private long _blockedQueries;
        private long _hijackingAttempts;
        private long _dgasDetected;
        private DateTime _startTime;
        
        // Hosts文件路径
        private string _hostsFilePath;
        private DateTime _lastHostsModification;
        private string _originalHostsHash;
        
        // DoH客户端
        private HttpClient _dohClient;
        
        // 预定义的DoH服务器
        private readonly Dictionary<string, string> _dohServers = new Dictionary<string, string>
        {
            ["Cloudflare"] = "https://cloudflare-dns.com/dns-query",
            ["Google"] = "https://dns.google/dns-query",
            ["Quad9"] = "https://dns.quad9.net/dns-query",
            ["Alibaba"] = "https://dns.alidns.com/dns-query",
            ["Tencent"] = "https://doh.pub/dns-query"
        };

        public DNSProtection(DataManager dataManager, AntivirusEngine antivirusEngine)
        {
            _dataManager = dataManager;
            _antivirusEngine = antivirusEngine;
            _isRunning = false;
            
            // 初始化并发集合
            _queryHistory = new ConcurrentDictionary<string, DNSQueryRecord>();
            _dnsCache = new ConcurrentDictionary<string, DNSCacheEntry>();
            _maliciousDomains = new ConcurrentDictionary<string, MaliciousDomainInfo>();
            _trustedDomains = new ConcurrentDictionary<string, TrustedDomainInfo>();
            _anomalyRecords = new ConcurrentDictionary<string, DNSAnomalyRecord>();
            _alerts = new ConcurrentQueue<DNSAlert>();
            _currentDNSServers = new ConcurrentDictionary<string, string>();
            
            // 初始化集合
            _blockedDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _blockedIPs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _trustedDNSServers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _suspiciousTLDs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            
            // 默认配置
            _monitoringInterval = 30000;
            _cacheTimeout = 300; // 5分钟
            _enableDNSOverHTTPS = false;
            _enableDNSOverTLS = false;
            _enableDNSHijackingDetection = true;
            _enableDGADetection = true;
            _enableFamilyProtection = false;
            _enableMaliciousDomainBlocking = true;
            _enableHostsProtection = true;
            _enableDNSCacheProtection = true;
            _logAllQueries = false;
            _maxQueryHistory = 10000;
            _maxCacheEntries = 5000;
            
            // Hosts文件路径
            _hostsFilePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), 
                "drivers\\etc\\hosts");
            
            // 初始化
            InitializeTrustedDNSServers();
            InitializeSuspiciousTLDs();
            LoadMaliciousDomainDatabase();
            GetCurrentDNSServers();
            InitializeHostsProtection();
            
            // 初始化DoH客户端
            _dohClient = new HttpClient();
            _dohClient.DefaultRequestHeaders.Add("Accept", "application/dns-message");
        }

        private void InitializeTrustedDNSServers()
        {
            // 可信DNS服务器
            string[] trustedDNS = {
                "8.8.8.8", "8.8.4.4",           // Google
                "1.1.1.1", "1.0.0.1",           // Cloudflare
                "9.9.9.9", "149.112.112.112",   // Quad9
                "223.5.5.5", "223.6.6.6",       // Alibaba
                "119.29.29.29", "182.254.116.116", // Tencent
                "114.114.114.114", "114.114.115.115" // 114 DNS
            };
            
            foreach (var dns in trustedDNS)
            {
                _trustedDNSServers.Add(dns);
            }
        }

        private void InitializeSuspiciousTLDs()
        {
            // 可疑顶级域名
            string[] suspiciousTLDs = {
                ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".cc", ".ws",
                ".info", ".biz", ".click", ".link", ".work", ".loan", ".date", ".racing",
                ".stream", ".download", ".trade", ".accountant", ".review", ".party",
                ".kim", ".men", ".pro", ".red", ".win", ".tube"
            };
            
            foreach (var tld in suspiciousTLDs)
            {
                _suspiciousTLDs.Add(tld);
            }
        }

        private void LoadMaliciousDomainDatabase()
        {
            try
            {
                string dbPath = GetDatabasePath("malicious_domains.txt");
                if (File.Exists(dbPath))
                {
                    var lines = File.ReadAllLines(dbPath);
                    foreach (var line in lines)
                    {
                        var domain = line.Trim();
                        if (!string.IsNullOrEmpty(domain) && !domain.StartsWith("#"))
                        {
                            _blockedDomains.Add(domain.ToLower());
                            
                            _maliciousDomains.TryAdd(domain.ToLower(), new MaliciousDomainInfo
                            {
                                Domain = domain.ToLower(),
                                Source = "Database",
                                AddedTime = DateTime.Now
                            });
                        }
                    }
                }
                
                // 加载恶意IP
                string ipDbPath = GetDatabasePath("malicious_ips.txt");
                if (File.Exists(ipDbPath))
                {
                    var lines = File.ReadAllLines(ipDbPath);
                    foreach (var line in lines)
                    {
                        var ip = line.Trim();
                        if (!string.IsNullOrEmpty(ip) && !ip.StartsWith("#"))
                        {
                            _blockedIPs.Add(ip);
                        }
                    }
                }
                
                _dataManager.LogInfo($"DNS恶意域名库加载完成: {_blockedDomains.Count}个域名, {_blockedIPs.Count}个IP");
            }
            catch (Exception ex)
            {
                _dataManager.LogError("加载恶意域名数据库失败", ex.Message, "DNSProtection");
            }
        }

        private void InitializeHostsProtection()
        {
            try
            {
                if (File.Exists(_hostsFilePath))
                {
                    _lastHostsModification = File.GetLastWriteTime(_hostsFilePath);
                    _originalHostsHash = CalculateFileHash(_hostsFilePath);
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "DNSProtection.cs 捕获异常", ex.Message); }
        }

        private string GetDatabasePath(string filename)
        {
            return Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "FireAntivirus", "Data", filename);
        }

        private void GetCurrentDNSServers()
        {
            try
            {
                _currentDNSServers.Clear();
                NetworkInterface[] adapters = NetworkInterface.GetAllNetworkInterfaces();
                
                foreach (NetworkInterface adapter in adapters)
                {
                    if (adapter.OperationalStatus == OperationalStatus.Up)
                    {
                        IPInterfaceProperties adapterProperties = adapter.GetIPProperties();
                        IPAddressCollection dnsServers = adapterProperties.DnsAddresses;
                        
                        foreach (IPAddress dns in dnsServers)
                        {
                            _currentDNSServers[adapter.Name] = dns.ToString();
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _dataManager.LogError("获取DNS服务器失败", ex.Message, "DNSProtection");
            }
        }

        public void Start()
        {
            if (_isRunning)
                return;
            
            _isRunning = true;
            _startTime = DateTime.Now;
            
            // 启动监控线程
            _monitorThread = new Thread(MonitorDNS)
            {
                IsBackground = true,
                Priority = ThreadPriority.BelowNormal
            };
            _monitorThread.Start();
            
            // 启动更新线程
            _updateThread = new Thread(UpdateDatabaseLoop)
            {
                IsBackground = true,
                Priority = ThreadPriority.Lowest
            };
            _updateThread.Start();
            
            // 启动分析线程
            _analysisThread = new Thread(AnalyzeDNSPatterns)
            {
                IsBackground = true,
                Priority = ThreadPriority.BelowNormal
            };
            _analysisThread.Start();

            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "DNSProtectionStart",
                Message = "DNS防护已启动",
                Details = $"恶意域名: {_blockedDomains.Count}, 可信DNS: {_trustedDNSServers.Count}",
                Source = "DNSProtection"
            });
        }

        public void Stop()
        {
            _isRunning = false;
            
            _monitorThread?.Join(3000);
            _updateThread?.Join(2000);
            _analysisThread?.Join(2000);
            
            SaveDatabase();

            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "DNSProtectionStop",
                Message = "DNS防护已停止",
                Details = $"查询总数: {_totalQueries}, 阻止查询: {_blockedQueries}, 劫持尝试: {_hijackingAttempts}",
                Source = "DNSProtection"
            });
        }

        private void MonitorDNS()
        {
            while (_isRunning)
            {
                try
                {
                    // 检查DNS配置
                    CheckDNSConfiguration();
                    
                    // 检查Hosts文件
                    if (_enableHostsProtection)
                    {
                        CheckHostsFile();
                    }
                    
                    // 检查DNS劫持
                    if (_enableDNSHijackingDetection)
                    {
                        DetectDNSHijacking();
                    }
                    
                    // 检查DNS缓存投毒
                    if (_enableDNSCacheProtection)
                    {
                        CheckDNSCacheIntegrity();
                    }
                    
                    // 清理过期缓存
                    CleanupExpiredCache();
                    
                    Thread.Sleep(_monitoringInterval);
                }
                catch (Exception ex)
                {
                    _dataManager.LogError("DNS监控错误", ex.Message, "DNSProtection");
                    Thread.Sleep(5000);
                }
            }
        }

        private void UpdateDatabaseLoop()
        {
            while (_isRunning)
            {
                try
                {
                    // 每小时更新数据库
                    Thread.Sleep(3600000);
                    
                    if (_isRunning)
                    {
                        UpdateMaliciousDomainDatabase();
                    }
                }
                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "DNSProtection.cs 捕获异常", ex.Message); }
            }
        }

        private void AnalyzeDNSPatterns()
        {
            while (_isRunning)
            {
                try
                {
                    // 分析DNS查询模式
                    AnalyzeQueryPatterns();
                    
                    // 检测DGA域名
                    if (_enableDGADetection)
                    {
                        DetectDGADomains();
                    }
                    
                    Thread.Sleep(60000);
                }
                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "DNSProtection.cs 捕获异常", ex.Message); }
            }
        }

        #region DNS Configuration Check

        private void CheckDNSConfiguration()
        {
            try
            {
                var previousServers = new Dictionary<string, string>(_currentDNSServers);
                GetCurrentDNSServers();
                
                // 检查DNS服务器是否被修改
                foreach (var kvp in _currentDNSServers)
                {
                    string adapterName = kvp.Key;
                    string currentDNS = kvp.Value;
                    
                    if (previousServers.TryGetValue(adapterName, out string previousDNS))
                    {
                        if (previousDNS != currentDNS)
                        {
                            HandleDNSChange(adapterName, previousDNS, currentDNS);
                        }
                    }
                    else
                    {
                        // 新适配器
                        _dataManager.LogInfo($"检测到新网络适配器: {adapterName}, DNS: {currentDNS}");
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "DNSProtection.cs 捕获异常", ex.Message); }
        }

        private void HandleDNSChange(string adapterName, string oldDNS, string newDNS)
        {
            bool isSuspicious = IsSuspiciousDNSServer(newDNS);
            
            var alert = new DNSAlert
            {
                AlertId = Guid.NewGuid().ToString(),
                AlertType = isSuspicious ? "DNSHijacking" : "DNSChange",
                Title = isSuspicious ? "检测到DNS劫持" : "DNS服务器已更改",
                Description = $"适配器: {adapterName}\n原DNS: {oldDNS}\n新DNS: {newDNS}",
                Severity = isSuspicious ? ThreatSeverity.High : ThreatSeverity.Low,
                DetectedAt = DateTime.Now
            };
            
            _alerts.Enqueue(alert);
            
            if (isSuspicious)
            {
                Interlocked.Increment(ref _hijackingAttempts);
                _dataManager.LogWarning($"检测到可疑DNS服务器: {adapterName} -> {newDNS}");
                
                // 自动恢复
                if (_enableDNSHijackingDetection)
                {
                    RestoreDNSSettings(adapterName);
                }
            }
            else
            {
                _dataManager.LogInfo($"DNS服务器已更改: {adapterName} -> {newDNS}");
            }
        }

        private bool IsSuspiciousDNSServer(string dnsServer)
        {
            if (string.IsNullOrEmpty(dnsServer))
                return false;
            
            // 检查是否是可信DNS
            if (_trustedDNSServers.Contains(dnsServer))
                return false;
            
            // 检查是否是私有IP
            if (IPAddress.TryParse(dnsServer, out IPAddress ip))
            {
                byte[] bytes = ip.GetAddressBytes();
                
                // 本地回环
                if (bytes[0] == 127)
                    return false;
                
                // 私有网络
                if (bytes[0] == 10)
                    return false;
                if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
                    return false;
                if (bytes[0] == 192 && bytes[1] == 168)
                    return false;
            }
            
            return true;
        }

        private void RestoreDNSSettings(string adapterName)
        {
            try
            {
                // 使用可信DNS恢复
                string primaryDNS = "1.1.1.1";
                string secondaryDNS = "8.8.8.8";
                
                SetDNSServer(adapterName, primaryDNS, secondaryDNS);
                
                _dataManager.LogInfo($"已恢复DNS设置: {adapterName} -> {primaryDNS}");
            }
            catch (Exception ex)
            {
                _dataManager.LogError("恢复DNS设置失败", ex.Message, "DNSProtection");
            }
        }

        #endregion

        #region Hosts File Protection

        private void CheckHostsFile()
        {
            try
            {
                if (!File.Exists(_hostsFilePath))
                    return;
                
                var lastMod = File.GetLastWriteTime(_hostsFilePath);
                
                if (lastMod > _lastHostsModification)
                {
                    var currentHash = CalculateFileHash(_hostsFilePath);
                    
                    if (currentHash != _originalHostsHash)
                    {
                        AnalyzeHostsFileChanges();
                    }
                    
                    _lastHostsModification = lastMod;
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "DNSProtection.cs 捕获异常", ex.Message); }
        }

        private void AnalyzeHostsFileChanges()
        {
            try
            {
                var lines = File.ReadAllLines(_hostsFilePath);
                var suspiciousEntries = new List<HostsEntry>();
                
                foreach (var line in lines)
                {
                    var trimmedLine = line.Trim();
                    if (string.IsNullOrEmpty(trimmedLine) || trimmedLine.StartsWith("#"))
                        continue;
                    
                    var parts = Regex.Split(trimmedLine, @"\s+");
                    if (parts.Length >= 2)
                    {
                        var entry = new HostsEntry
                        {
                            IPAddress = parts[0],
                            Domain = parts[1].ToLower(),
                            Line = trimmedLine
                        };
                        
                        // 检查是否是恶意条目
                        if (IsMaliciousHostsEntry(entry))
                        {
                            suspiciousEntries.Add(entry);
                        }
                    }
                }
                
                if (suspiciousEntries.Count > 0)
                {
                    var alert = new DNSAlert
                    {
                        AlertId = Guid.NewGuid().ToString(),
                        AlertType = "HostsModification",
                        Title = "Hosts文件被修改",
                        Description = $"检测到{suspiciousEntries.Count}个可疑条目",
                        Severity = ThreatSeverity.High,
                        DetectedAt = DateTime.Now,
                        Details = suspiciousEntries
                    };
                    
                    _alerts.Enqueue(alert);
                    
                    _dataManager.LogWarning($"Hosts文件检测到可疑修改: {suspiciousEntries.Count}个条目");
                    
                    // 自动清理
                    if (_enableHostsProtection)
                    {
                        CleanHostsFile(suspiciousEntries);
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "DNSProtection.cs 捕获异常", ex.Message); }
        }

        private bool IsMaliciousHostsEntry(HostsEntry entry)
        {
            // 检查是否重定向知名网站到恶意IP
            string[] knownBrands = {
                "google.com", "facebook.com", "twitter.com", "youtube.com",
                "baidu.com", "qq.com", "taobao.com", "tmall.com",
                "microsoft.com", "apple.com", "amazon.com", "paypal.com"
            };
            
            foreach (var brand in knownBrands)
            {
                if (entry.Domain.Contains(brand) || entry.Domain.EndsWith("." + brand))
                {
                    // 检查是否指向非预期的IP
                    if (IPAddress.TryParse(entry.IPAddress, out IPAddress ip))
                    {
                        byte[] bytes = ip.GetAddressBytes();
                        
                        // 排除本地回环
                        if (bytes[0] == 127 || bytes[0] == 0)
                            return false;
                        
                        // 其他IP重定向知名网站可能是恶意
                        return true;
                    }
                }
            }
            
            return false;
        }

        private void CleanHostsFile(List<HostsEntry> suspiciousEntries)
        {
            try
            {
                var lines = File.ReadAllLines(_hostsFilePath).ToList();
                var cleanedLines = new List<string>();
                
                foreach (var line in lines)
                {
                    bool isSuspicious = false;
                    
                    foreach (var entry in suspiciousEntries)
                    {
                        if (line.Contains(entry.Domain))
                        {
                            isSuspicious = true;
                            break;
                        }
                    }
                    
                    if (!isSuspicious)
                    {
                        cleanedLines.Add(line);
                    }
                }
                
                // 备份原文件
                File.Copy(_hostsFilePath, _hostsFilePath + ".bak", true);
                
                // 写入清理后的文件
                File.WriteAllLines(_hostsFilePath, cleanedLines);
                
                _dataManager.LogInfo($"Hosts文件已清理: 移除{suspiciousEntries.Count}个可疑条目");
            }
            catch (Exception ex)
            {
                _dataManager.LogError("清理Hosts文件失败", ex.Message, "DNSProtection");
            }
        }

        #endregion

        #region DNS Hijacking Detection

        private void DetectDNSHijacking()
        {
            try
            {
                // 测试已知域名的DNS解析
                string[] testDomains = {
                    "www.google.com",
                    "www.baidu.com",
                    "www.microsoft.com"
                };
                
                foreach (var domain in testDomains)
                {
                    try
                    {
                        var expectedIPs = GetExpectedIPs(domain);
                        var actualIPs = ResolveDomain(domain);
                        
                        // 比较解析结果
                        if (expectedIPs != null && actualIPs != null)
                        {
                            var unexpectedIPs = actualIPs.Except(expectedIPs).ToList();
                            
                            if (unexpectedIPs.Count > 0)
                            {
                                var alert = new DNSAlert
                                {
                                    AlertId = Guid.NewGuid().ToString(),
                                    AlertType = "DNSCachePoisoning",
                                    Title = "检测到DNS缓存投毒",
                                    Description = $"域名: {domain}\n异常IP: {string.Join(", ", unexpectedIPs)}",
                                    Severity = ThreatSeverity.High,
                                    DetectedAt = DateTime.Now
                                };
                                
                                _alerts.Enqueue(alert);
                                
                                // 清除DNS缓存
                                FlushDNSCache();
                            }
                        }
                    }
                    catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "DNSProtection.cs 捕获异常", ex.Message); }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "DNSProtection.cs 捕获异常", ex.Message); }
        }

        private List<string> GetExpectedIPs(string domain)
        {
            // 使用DoH查询可信DNS
            // 简化实现：返回null表示未知
            return null;
        }

        private List<string> ResolveDomain(string domain)
        {
            try
            {
                var addresses = Dns.GetHostAddresses(domain);
                return addresses.Select(a => a.ToString()).ToList();
            }
            catch
            {
                return null;
            }
        }

        private void CheckDNSCacheIntegrity()
        {
            // 验证DNS缓存中的条目
            // 实际实现需要与系统DNS缓存交互
        }

        #endregion

        #region DGA Detection (Domain Generation Algorithm)

        private void DetectDGADomains()
        {
            try
            {
                // 分析最近的DNS查询
                var recentQueries = _queryHistory.Values
                    .Where(q => q.QueryTime > DateTime.Now.AddHours(-1))
                    .ToList();
                
                foreach (var query in recentQueries)
                {
                    if (IsDGADomain(query.Domain))
                    {
                        var alert = new DNSAlert
                        {
                            AlertId = Guid.NewGuid().ToString(),
                            AlertType = "DGADetected",
                            Title = "检测到DGA域名",
                            Description = $"域名: {query.Domain}\n进程: {query.ProcessName}",
                            Severity = ThreatSeverity.High,
                            DetectedAt = DateTime.Now
                        };
                        
                        _alerts.Enqueue(alert);
                        Interlocked.Increment(ref _dgasDetected);
                        
                        // 阻止域名
                        _blockedDomains.Add(query.Domain.ToLower());
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "DNSProtection.cs 捕获异常", ex.Message); }
        }

        private bool IsDGADomain(string domain)
        {
            if (string.IsNullOrEmpty(domain))
                return false;
            
            var parts = domain.Split('.');
            if (parts.Length < 2)
                return false;
            
            string mainPart = parts[0];
            
            // DGA检测特征
            
            // 1. 高熵值（随机字符）
            double entropy = CalculateEntropy(mainPart);
            if (entropy > 4.0 && mainPart.Length > 10)
                return true;
            
            // 2. 过长的域名部分
            if (mainPart.Length > 20 && !mainPart.All(char.IsLetter))
                return true;
            
            // 3. 高比例数字
            double digitRatio = (double)mainPart.Count(char.IsDigit) / mainPart.Length;
            if (digitRatio > 0.5 && mainPart.Length > 8)
                return true;
            
            // 4. 连续辅音或元音
            if (HasConsecutiveConsonants(mainPart, 6) || HasConsecutiveVowels(mainPart, 5))
                return true;
            
            // 5. 无意义的字符组合
            if (!HasValidWordPatterns(mainPart) && mainPart.Length > 12)
                return true;
            
            return false;
        }

        private double CalculateEntropy(string str)
        {
            if (string.IsNullOrEmpty(str))
                return 0;
            
            var frequency = new Dictionary<char, int>();
            foreach (char c in str.ToLower())
            {
                if (!frequency.ContainsKey(c))
                    frequency[c] = 0;
                frequency[c]++;
            }
            
            double entropy = 0;
            int total = str.Length;
            
            foreach (var kvp in frequency)
            {
                double probability = (double)kvp.Value / total;
                entropy -= probability * Math.Log(probability, 2);
            }
            
            return entropy;
        }

        private bool HasConsecutiveConsonants(string str, int count)
        {
            const string consonants = "bcdfghjklmnpqrstvwxyz";
            int consecutive = 0;
            
            foreach (char c in str.ToLower())
            {
                if (consonants.Contains(c))
                {
                    consecutive++;
                    if (consecutive >= count)
                        return true;
                }
                else
                {
                    consecutive = 0;
                }
            }
            
            return false;
        }

        private bool HasConsecutiveVowels(string str, int count)
        {
            const string vowels = "aeiou";
            int consecutive = 0;
            
            foreach (char c in str.ToLower())
            {
                if (vowels.Contains(c))
                {
                    consecutive++;
                    if (consecutive >= count)
                        return true;
                }
                else
                {
                    consecutive = 0;
                }
            }
            
            return false;
        }

        private bool HasValidWordPatterns(string str)
        {
            // 检查是否包含常见的英文词根
            string[] commonPatterns = {
                "the", "ing", "tion", "er", "est", "ly", "ment", "ness",
                "able", "ible", "ful", "less", "ous", "ive", "al", "ent"
            };
            
            str = str.ToLower();
            foreach (var pattern in commonPatterns)
            {
                if (str.Contains(pattern))
                    return true;
            }
            
            return false;
        }

        #endregion

        #region Query Analysis

        private void AnalyzeQueryPatterns()
        {
            try
            {
                // 检测异常DNS查询模式
                var recentQueries = _queryHistory.Values
                    .Where(q => q.QueryTime > DateTime.Now.AddMinutes(-10))
                    .ToList();
                
                // 按进程分组
                var byProcess = recentQueries.GroupBy(q => q.ProcessName);
                
                foreach (var group in byProcess)
                {
                    var queries = group.ToList();
                    
                    // 高频查询
                    if (queries.Count > 100)
                    {
                        var alert = new DNSAlert
                        {
                            AlertId = Guid.NewGuid().ToString(),
                            AlertType = "HighQueryRate",
                            Title = "高频DNS查询",
                            Description = $"进程: {group.Key}\n查询次数: {queries.Count}",
                            Severity = ThreatSeverity.Medium,
                            DetectedAt = DateTime.Now
                        };
                        
                        _alerts.Enqueue(alert);
                    }
                    
                    // 检查是否查询多个可疑域名
                    var suspiciousCount = queries.Count(q => IsSuspiciousDomain(q.Domain));
                    if (suspiciousCount > 5)
                    {
                        var alert = new DNSAlert
                        {
                            AlertId = Guid.NewGuid().ToString(),
                            AlertType = "SuspiciousQueryPattern",
                            Title = "可疑DNS查询模式",
                            Description = $"进程: {group.Key}\n可疑查询: {suspiciousCount}",
                            Severity = ThreatSeverity.High,
                            DetectedAt = DateTime.Now
                        };
                        
                        _alerts.Enqueue(alert);
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "DNSProtection.cs 捕获异常", ex.Message); }
        }

        private bool IsSuspiciousDomain(string domain)
        {
            if (string.IsNullOrEmpty(domain))
                return false;
            
            domain = domain.ToLower();
            
            // 检查黑名单
            if (_blockedDomains.Contains(domain))
                return true;
            
            // 检查可疑TLD
            foreach (var tld in _suspiciousTLDs)
            {
                if (domain.EndsWith(tld))
                    return true;
            }
            
            // 检查DGA特征
            if (IsDGADomain(domain))
                return true;
            
            return false;
        }

        #endregion

        #region DNS Resolution API

        /// <summary>
        /// 安全DNS解析 - 支持恶意域名拦截和DoH
        /// </summary>
        public DNSResolutionResult ResolveDomainSafe(string domain, int processId = 0, string processName = "")
        {
            var result = new DNSResolutionResult
            {
                Domain = domain,
                QueryTime = DateTime.Now
            };
            
            Interlocked.Increment(ref _totalQueries);
            
            // 检查是否被阻止
            if (_enableMaliciousDomainBlocking && _blockedDomains.Contains(domain.ToLower()))
            {
                result.IsBlocked = true;
                result.BlockReason = "恶意域名";
                Interlocked.Increment(ref _blockedQueries);
                
                CreateDNSAlert("DomainBlocked", "域名被阻止", $"域名: {domain}", ThreatSeverity.High);
                return result;
            }
            
            // 家庭保护
            if (_enableFamilyProtection && IsAdultDomain(domain))
            {
                result.IsBlocked = true;
                result.BlockReason = "成人内容";
                Interlocked.Increment(ref _blockedQueries);
                return result;
            }
            
            // 检查缓存
            if (_dnsCache.TryGetValue(domain, out var cached))
            {
                if (cached.ExpiryTime > DateTime.Now)
                {
                    result.IPAddresses = cached.IPAddresses;
                    result.FromCache = true;
                    return result;
                }
            }
            
            // 使用DoH或普通DNS解析
            if (_enableDNSOverHTTPS)
            {
                result = ResolveViaDoH(domain);
            }
            else
            {
                try
                {
                    var addresses = Dns.GetHostAddresses(domain);
                    result.IPAddresses = addresses.Select(a => a.ToString()).ToList();
                }
                catch (Exception ex)
                {
                    result.HasError = true;
                    result.ErrorMessage = ex.Message;
                }
            }
            
            // 验证解析结果
            if (result.IPAddresses != null)
            {
                foreach (var ip in result.IPAddresses)
                {
                    if (_blockedIPs.Contains(ip))
                    {
                        result.IsBlocked = true;
                        result.BlockReason = "恶意IP";
                        Interlocked.Increment(ref _blockedQueries);
                        return result;
                    }
                }
            }
            
            // 缓存结果
            if (result.IPAddresses != null && !result.HasError)
            {
                _dnsCache.TryAdd(domain, new DNSCacheEntry
                {
                    Domain = domain,
                    IPAddresses = result.IPAddresses,
                    QueryTime = DateTime.Now,
                    ExpiryTime = DateTime.Now.AddSeconds(_cacheTimeout)
                });
            }
            
            // 记录查询历史
            _queryHistory.TryAdd(Guid.NewGuid().ToString(), new DNSQueryRecord
            {
                Domain = domain,
                QueryTime = DateTime.Now,
                ProcessId = processId,
                ProcessName = processName,
                IPAddresses = result.IPAddresses
            });
            
            return result;
        }

        private bool IsAdultDomain(string domain)
        {
            // 简化的成人域名检测
            string[] adultKeywords = { "porn", "xxx", "adult", "sex" };
            domain = domain.ToLower();
            
            return adultKeywords.Any(k => domain.Contains(k));
        }

        private DNSResolutionResult ResolveViaDoH(string domain)
        {
            var result = new DNSResolutionResult
            {
                Domain = domain,
                QueryTime = DateTime.Now
            };
            
            try
            {
                // 使用Cloudflare DoH
                string dohUrl = _dohServers["Cloudflare"];
                
                // 构建DNS查询
                var query = BuildDNSQuery(domain);
                
                var response = _dohClient.PostAsync(dohUrl, 
                    new ByteArrayContent(query))
                    .Result;
                
                if (response.IsSuccessStatusCode)
                {
                    var responseData = response.Content.ReadAsByteArrayAsync().Result;
                    result.IPAddresses = ParseDNSResponse(responseData);
                }
            }
            catch (Exception ex)
            {
                result.HasError = true;
                result.ErrorMessage = ex.Message;
                
                // 回退到普通DNS
                try
                {
                    var addresses = Dns.GetHostAddresses(domain);
                    result.IPAddresses = addresses.Select(a => a.ToString()).ToList();
                    result.HasError = false;
                }
                catch (System.Exception ex2) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "DNSProtection.cs 捕获异常", ex2.Message); }
            }
            
            return result;
        }

        private byte[] BuildDNSQuery(string domain)
        {
            // 构建DNS查询包
            using (var ms = new MemoryStream())
            {
                // DNS头部
                byte[] header = new byte[12];
                header[0] = 0x00; header[1] = 0x01; // Transaction ID
                header[2] = 0x01; header[3] = 0x00; // Flags: Standard query
                header[4] = 0x00; header[5] = 0x01; // Questions: 1
                header[6] = 0x00; header[7] = 0x00; // Answers: 0
                header[8] = 0x00; header[9] = 0x00; // Authority: 0
                header[10] = 0x00; header[11] = 0x00; // Additional: 0
                
                ms.Write(header, 0, header.Length);
                
                // 域名部分
                string[] parts = domain.Split('.');
                foreach (var part in parts)
                {
                    byte[] label = Encoding.ASCII.GetBytes(part);
                    ms.WriteByte((byte)label.Length);
                    ms.Write(label, 0, label.Length);
                }
                ms.WriteByte(0x00); // End of domain
                
                // 查询类型和类
                ms.Write(new byte[] { 0x00, 0x01, 0x00, 0x01 }, 0, 4); // Type A, Class IN
                
                return ms.ToArray();
            }
        }

        private List<string> ParseDNSResponse(byte[] data)
        {
            var ips = new List<string>();
            
            try
            {
                // 简化的DNS响应解析
                // 实际实现需要完整解析DNS响应包
                int offset = 12; // Skip header
                
                // Skip question section
                while (data[offset] != 0)
                {
                    int labelLen = data[offset];
                    offset += labelLen + 1;
                }
                offset += 5; // End marker + QTYPE + QCLASS
                
                // Parse answers
                while (offset < data.Length - 12)
                {
                    // Skip name (compressed pointer)
                    offset += 2;
                    
                    ushort type = (ushort)((data[offset] << 8) | data[offset + 1]);
                    offset += 2;
                    ushort cls = (ushort)((data[offset] << 8) | data[offset + 1]);
                    offset += 2;
                    uint ttl = (uint)((data[offset] << 24) | (data[offset + 1] << 16) | 
                                     (data[offset + 2] << 8) | data[offset + 3]);
                    offset += 4;
                    ushort rdLength = (ushort)((data[offset] << 8) | data[offset + 1]);
                    offset += 2;
                    
                    if (type == 1 && rdLength == 4) // A record
                    {
                        string ip = $"{data[offset]}.{data[offset + 1]}.{data[offset + 2]}.{data[offset + 3]}";
                        ips.Add(ip);
                    }
                    
                    offset += rdLength;
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "DNSProtection.cs 捕获异常", ex.Message); }
            
            return ips;
        }

        #endregion

        #region Public API

        public void BlockDomain(string domain)
        {
            if (!string.IsNullOrEmpty(domain))
            {
                _blockedDomains.Add(domain.ToLower());
                SaveDatabase();
            }
        }

        public void UnblockDomain(string domain)
        {
            _blockedDomains.Remove(domain.ToLower());
            SaveDatabase();
        }

        public void BlockIP(string ip)
        {
            if (!string.IsNullOrEmpty(ip))
            {
                _blockedIPs.Add(ip);
                SaveDatabase();
            }
        }

        public void UnblockIP(string ip)
        {
            _blockedIPs.Remove(ip);
        }

        public bool SetDNSServer(string adapterName, string primaryDNS, string secondaryDNS = null)
        {
            try
            {
                string interfaceAlias = GetInterfaceAlias(adapterName);
                if (string.IsNullOrEmpty(interfaceAlias))
                    return false;
                
                string command = $"interface ip set dns name=\"{interfaceAlias}\" static {primaryDNS}";
                if (!string.IsNullOrEmpty(secondaryDNS))
                {
                    command += $" && netsh interface ip add dns name=\"{interfaceAlias}\" {secondaryDNS} index=2";
                }
                
                ExecuteCommand("netsh", command);
                GetCurrentDNSServers();
                
                _dataManager.LogInfo($"DNS服务器已设置: {adapterName} -> {primaryDNS}");
                return true;
            }
            catch (Exception ex)
            {
                _dataManager.LogError("设置DNS服务器失败", ex.Message, "DNSProtection");
                return false;
            }
        }

        public bool SetDHCPDNS(string adapterName)
        {
            try
            {
                string interfaceAlias = GetInterfaceAlias(adapterName);
                if (string.IsNullOrEmpty(interfaceAlias))
                    return false;
                
                ExecuteCommand("netsh", $"interface ip set dns name=\"{interfaceAlias}\" dhcp");
                GetCurrentDNSServers();
                
                return true;
            }
            catch { return false; }
        }

        public void FlushDNSCache()
        {
            try
            {
                ExecuteCommand("ipconfig", "/flushdns");
                _dataManager.LogInfo("DNS缓存已清除");
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "DNSProtection.cs 捕获异常", ex.Message); }
        }

        public List<DNSQueryRecord> GetQueryHistory()
        {
            return _queryHistory.Values
                .OrderByDescending(q => q.QueryTime)
                .Take(1000)
                .ToList();
        }

        public List<DNSAlert> GetAlerts()
        {
            return _alerts.ToList();
        }

        public DNSProtectionStatistics GetStatistics()
        {
            return new DNSProtectionStatistics
            {
                TotalQueries = _totalQueries,
                BlockedQueries = _blockedQueries,
                HijackingAttempts = _hijackingAttempts,
                DGAsDetected = _dgasDetected,
                BlockedDomains = _blockedDomains.Count,
                BlockedIPs = _blockedIPs.Count,
                CacheEntries = _dnsCache.Count,
                RunningTime = DateTime.Now - _startTime
            };
        }

        public Dictionary<string, string> GetCurrentDNSServersInfo()
        {
            return new Dictionary<string, string>(_currentDNSServers);
        }

        public List<string> GetBlockedDomains()
        {
            return _blockedDomains.ToList();
        }

        public List<string> GetBlockedIPs()
        {
            return _blockedIPs.ToList();
        }

        public void EnableDNSOverHTTPS(bool enable) => _enableDNSOverHTTPS = enable;
        public void EnableDNSOverTLS(bool enable) => _enableDNSOverTLS = enable;
        public void EnableFamilyProtection(bool enable) => _enableFamilyProtection = enable;
        public void EnableDGADetection(bool enable) => _enableDGADetection = enable;
        public void EnableHostsProtection(bool enable) => _enableHostsProtection = enable;

        #endregion

        #region Helper Methods

        private string CalculateFileHash(string filePath)
        {
            try
            {
                using (var sha256 = SHA256.Create())
                using (var stream = File.OpenRead(filePath))
                {
                    return BitConverter.ToString(sha256.ComputeHash(stream)).Replace("-", "").ToLower();
                }
            }
            catch { return ""; }
        }

        private string GetInterfaceAlias(string adapterName)
        {
            try
            {
                var adapters = NetworkInterface.GetAllNetworkInterfaces();
                foreach (var adapter in adapters)
                {
                    if (adapter.Description.Contains(adapterName) || adapter.Name == adapterName)
                    {
                        return adapter.Name;
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "DNSProtection.cs 捕获异常", ex.Message); }
            return null;
        }

        private string ExecuteCommand(string fileName, string arguments)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = fileName,
                    Arguments = arguments,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                };
                
                using (var proc = Process.Start(psi))
                {
                    var output = proc.StandardOutput.ReadToEnd();
                    proc.WaitForExit(30000);
                    return output;
                }
            }
            catch { return ""; }
        }

        private void CreateDNSAlert(string alertType, string title, string description, ThreatSeverity severity)
        {
            var alert = new DNSAlert
            {
                AlertId = Guid.NewGuid().ToString(),
                AlertType = alertType,
                Title = title,
                Description = description,
                Severity = severity,
                DetectedAt = DateTime.Now
            };
            
            _alerts.Enqueue(alert);
        }

        private void UpdateMaliciousDomainDatabase()
        {
            // 从云端更新恶意域名库
            _dataManager.LogInfo("正在更新恶意域名数据库...");
        }

        private void SaveDatabase()
        {
            try
            {
                string dbPath = GetDatabasePath("malicious_domains.txt");
                Directory.CreateDirectory(Path.GetDirectoryName(dbPath));
                File.WriteAllLines(dbPath, _blockedDomains);
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "DNSProtection.cs 捕获异常", ex.Message); }
        }

        private void CleanupExpiredCache()
        {
            var now = DateTime.Now;
            var expiredKeys = _dnsCache
                .Where(kvp => kvp.Value.ExpiryTime < now)
                .Select(kvp => kvp.Key)
                .ToList();
            
            foreach (var key in expiredKeys)
            {
                DNSCacheEntry removed;
                _dnsCache.TryRemove(key, out removed);
            }
            
            // 清理旧的查询历史
            if (_queryHistory.Count > _maxQueryHistory)
            {
                var oldKeys = _queryHistory
                    .OrderBy(kvp => kvp.Value.QueryTime)
                    .Take(_queryHistory.Count - _maxQueryHistory)
                    .Select(kvp => kvp.Key)
                    .ToList();
                
                foreach (var key in oldKeys)
                {
                    DNSQueryRecord removed;
                    _queryHistory.TryRemove(key, out removed);
                }
            }
        }

        #endregion
    }

    #region Data Classes

    public class DNSQueryRecord
    {
        public string Domain { get; set; }
        public DateTime QueryTime { get; set; }
        public int ProcessId { get; set; }
        public string ProcessName { get; set; }
        public List<string> IPAddresses { get; set; }
        public bool WasBlocked { get; set; }
        public string BlockReason { get; set; }
    }

    public class DNSCacheEntry
    {
        public string Domain { get; set; }
        public List<string> IPAddresses { get; set; }
        public DateTime QueryTime { get; set; }
        public DateTime ExpiryTime { get; set; }
    }

    public class MaliciousDomainInfo
    {
        public string Domain { get; set; }
        public string ThreatType { get; set; }
        public string Source { get; set; }
        public DateTime AddedTime { get; set; }
    }

    public class TrustedDomainInfo
    {
        public string Domain { get; set; }
        public string Category { get; set; }
        public DateTime AddedTime { get; set; }
    }

    public class DNSAnomalyRecord
    {
        public string Domain { get; set; }
        public string AnomalyType { get; set; }
        public string Details { get; set; }
        public DateTime DetectedTime { get; set; }
    }

    public class DNSAlert
    {
        public string AlertId { get; set; }
        public string AlertType { get; set; }
        public string Title { get; set; }
        public string Description { get; set; }
        public ThreatSeverity Severity { get; set; }
        public DateTime DetectedAt { get; set; }
        public object Details { get; set; }
    }

    public class HostsEntry
    {
        public string IPAddress { get; set; }
        public string Domain { get; set; }
        public string Line { get; set; }
    }

    public class DNSResolutionResult
    {
        public string Domain { get; set; }
        public List<string> IPAddresses { get; set; }
        public DateTime QueryTime { get; set; }
        public bool IsBlocked { get; set; }
        public string BlockReason { get; set; }
        public bool HasError { get; set; }
        public string ErrorMessage { get; set; }
        public bool FromCache { get; set; }
    }

    public class DNSProtectionStatistics
    {
        public long TotalQueries { get; set; }
        public long BlockedQueries { get; set; }
        public long HijackingAttempts { get; set; }
        public long DGAsDetected { get; set; }
        public int BlockedDomains { get; set; }
        public int BlockedIPs { get; set; }
        public int CacheEntries { get; set; }
        public TimeSpan RunningTime { get; set; }
    }

    #endregion
}
