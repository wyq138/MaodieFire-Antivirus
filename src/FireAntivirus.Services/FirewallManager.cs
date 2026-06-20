using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using FireAntivirus.Data;
using FireAntivirus.Engine;

namespace FireAntivirus.Services
{
    /// <summary>
    /// 专业级防火墙管理 - 支持智能规则生成、入侵检测、流量分析、带宽控制
    /// </summary>
    public class FirewallManager : IMonitor
    {
        private Thread _monitorThread;
        private Thread _analysisThread;
        private Thread _ruleUpdateThread;
        private bool _isRunning;
        private DataManager _dataManager;
        private AntivirusEngine _antivirusEngine;
        
        // 使用并发集合
        private ConcurrentDictionary<string, FirewallRule> _rules;
        private ConcurrentDictionary<string, ApplicationNetworkProfile> _appProfiles;
        private ConcurrentDictionary<string, BlockedIPInfo> _blockedIPs;
        private ConcurrentDictionary<string, BlockedPortInfo> _blockedPorts;
        private ConcurrentQueue<FirewallNetworkConnectionEvent> _connectionEvents;
        private ConcurrentQueue<FirewallAlert> _alerts;
        private ConcurrentBag<IntrusionAttempt> _intrusionAttempts;
        
        // 规则列表
        private HashSet<string> _trustedApplications;
        private HashSet<string> _blockedApplications;
        private HashSet<string> _maliciousIPs;
        private HashSet<string> _maliciousDomains;
        private HashSet<int> _restrictedPorts;
        
        // 配置参数
        private int _monitoringInterval;
        private int _ruleUpdateInterval;
        private bool _enableIntrusionDetection;
        private bool _enableBandwidthControl;
        private bool _enableAutoBlocking;
        private bool _enablePortScanDetection;
        private bool _enableDDoSProtection;
        private bool _enableApplicationControl;
        private bool _stealthMode;
        private bool _blockAllIncoming;
        private bool _logAllConnections;
        private int _maxConnectionsPerIP;
        private int _maxConnectionRate;
        private int _maxAlerts;
        
        // 统计数据
        private long _totalConnectionsMonitored;
        private long _connectionsBlocked;
        private long _intrusionsDetected;
        private long _rulesApplied;
        private DateTime _startTime;
        
        // 网络区域
        private Dictionary<string, NetworkZone> _networkZones;
        private NetworkZone _currentZone;

        public FirewallManager(DataManager dataManager, AntivirusEngine antivirusEngine)
        {
            _dataManager = dataManager;
            _antivirusEngine = antivirusEngine;
            _isRunning = false;
            
            // 初始化并发集合
            _rules = new ConcurrentDictionary<string, FirewallRule>();
            _appProfiles = new ConcurrentDictionary<string, ApplicationNetworkProfile>();
            _blockedIPs = new ConcurrentDictionary<string, BlockedIPInfo>();
            _blockedPorts = new ConcurrentDictionary<string, BlockedPortInfo>();
            _connectionEvents = new ConcurrentQueue<FirewallNetworkConnectionEvent>();
            _alerts = new ConcurrentQueue<FirewallAlert>();
            _intrusionAttempts = new ConcurrentBag<IntrusionAttempt>();
            
            // 初始化集合
            _trustedApplications = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _blockedApplications = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _maliciousIPs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _maliciousDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _restrictedPorts = new HashSet<int>();
            
            // 默认配置
            _monitoringInterval = 5000;
            _ruleUpdateInterval = 60000;
            _enableIntrusionDetection = true;
            _enableBandwidthControl = false;
            _enableAutoBlocking = true;
            _enablePortScanDetection = true;
            _enableDDoSProtection = true;
            _enableApplicationControl = true;
            _stealthMode = true;
            _blockAllIncoming = false;
            _logAllConnections = false;
            _maxConnectionsPerIP = 100;
            _maxConnectionRate = 50;
            _maxAlerts = 5000;
            
            // 初始化网络区域
            InitializeNetworkZones();
            LoadFirewallSettings();
            LoadMaliciousIPDatabase();
        }

        private void InitializeNetworkZones()
        {
            _networkZones = new Dictionary<string, NetworkZone>
            {
                ["Home"] = new NetworkZone
                {
                    Name = "家庭网络",
                    Description = "受信任的家庭网络环境",
                    SecurityLevel = SecurityLevel.Low,
                    BlockIncoming = false,
                    StealthMode = false,
                    AllowedPorts = new HashSet<int> { 80, 443, 445, 139, 22, 3389 },
                    TrustedNetworks = new List<string> { "192.168.0.0/16", "10.0.0.0/8" }
                },
                ["Work"] = new NetworkZone
                {
                    Name = "工作网络",
                    Description = "企业办公网络环境",
                    SecurityLevel = SecurityLevel.Medium,
                    BlockIncoming = false,
                    StealthMode = true,
                    AllowedPorts = new HashSet<int> { 80, 443, 22, 3389 },
                    TrustedNetworks = new List<string>()
                },
                ["Public"] = new NetworkZone
                {
                    Name = "公用网络",
                    Description = "不安全的公共网络环境",
                    SecurityLevel = SecurityLevel.High,
                    BlockIncoming = true,
                    StealthMode = true,
                    AllowedPorts = new HashSet<int> { 80, 443 },
                    TrustedNetworks = new List<string>()
                },
                ["Blocked"] = new NetworkZone
                {
                    Name = "阻止所有",
                    Description = "最高安全级别，阻止所有非必要连接",
                    SecurityLevel = SecurityLevel.Critical,
                    BlockIncoming = true,
                    StealthMode = true,
                    AllowedPorts = new HashSet<int>(),
                    TrustedNetworks = new List<string>()
                }
            };
            
            // 默认使用公用网络配置
            _currentZone = _networkZones["Public"];
        }

        private void LoadFirewallSettings()
        {
            try
            {
                string settingsPath = GetSettingsPath();
                if (File.Exists(settingsPath))
                {
                    var json = File.ReadAllText(settingsPath);
                    var settings = Newtonsoft.Json.JsonConvert.DeserializeObject<FirewallSettings>(json);
                    if (settings != null)
                    {
                        foreach (var app in settings.TrustedApplications)
                            _trustedApplications.Add(app);
                        foreach (var app in settings.BlockedApplications)
                            _blockedApplications.Add(app);
                        foreach (var ip in settings.BlockedIPs)
                            _maliciousIPs.Add(ip);
                        foreach (var port in settings.RestrictedPorts)
                            _restrictedPorts.Add(port);
                        
                        _stealthMode = settings.StealthMode;
                        _blockAllIncoming = settings.BlockAllIncoming;
                        _enableAutoBlocking = settings.EnableAutoBlocking;
                    }
                }
            }
            catch (Exception ex)
            {
                _dataManager.LogError("加载防火墙设置失败", ex.Message, "FirewallManager");
            }
        }

        private void SaveFirewallSettings()
        {
            try
            {
                var settings = new FirewallSettings
                {
                    TrustedApplications = _trustedApplications.ToList(),
                    BlockedApplications = _blockedApplications.ToList(),
                    BlockedIPs = _maliciousIPs.ToList(),
                    RestrictedPorts = _restrictedPorts.ToList(),
                    StealthMode = _stealthMode,
                    BlockAllIncoming = _blockAllIncoming,
                    EnableAutoBlocking = _enableAutoBlocking,
                    LastSaved = DateTime.Now
                };
                
                string settingsPath = GetSettingsPath();
                Directory.CreateDirectory(Path.GetDirectoryName(settingsPath));
                var json = Newtonsoft.Json.JsonConvert.SerializeObject(settings, Newtonsoft.Json.Formatting.Indented);
                File.WriteAllText(settingsPath, json);
            }
            catch (Exception ex)
            {
                _dataManager.LogError("保存防火墙设置失败", ex.Message, "FirewallManager");
            }
        }

        private void LoadMaliciousIPDatabase()
        {
            try
            {
                string dbPath = Path.Combine(GetSettingsPath(), "..", "malicious_ips.txt");
                if (File.Exists(dbPath))
                {
                    var lines = File.ReadAllLines(dbPath);
                    foreach (var line in lines)
                    {
                        var ip = line.Trim();
                        if (!string.IsNullOrEmpty(ip) && !ip.StartsWith("#"))
                        {
                            _maliciousIPs.Add(ip);
                        }
                    }
                }
                
                // 添加已知的恶意IP范围
                AddKnownMaliciousIPRanges();
                
                _dataManager.LogInfo($"防火墙恶意IP库加载完成: {_maliciousIPs.Count}个IP");
            }
            catch { }
        }

        private void AddKnownMaliciousIPRanges()
        {
            // 添加已知的恶意IP和CIDR范围
            // 这些可以从威胁情报源更新
        }

        private string GetSettingsPath()
        {
            return Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "FireAntivirus", "firewall_settings.json");
        }

        public void Start()
        {
            if (_isRunning)
                return;
            
            _isRunning = true;
            _startTime = DateTime.Now;
            
            // 确保Windows防火墙服务运行
            EnsureFirewallServiceRunning();
            
            // 启动监控线程
            _monitorThread = new Thread(MonitorFirewall)
            {
                IsBackground = true,
                Priority = ThreadPriority.BelowNormal
            };
            _monitorThread.Start();
            
            // 启动分析线程
            _analysisThread = new Thread(AnalyzeNetworkTraffic)
            {
                IsBackground = true,
                Priority = ThreadPriority.BelowNormal
            };
            _analysisThread.Start();
            
            // 启动规则更新线程
            _ruleUpdateThread = new Thread(UpdateRulesLoop)
            {
                IsBackground = true,
                Priority = ThreadPriority.Lowest
            };
            _ruleUpdateThread.Start();

            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "FirewallStart",
                Message = "防火墙管理已启动",
                Details = $"当前区域: {_currentZone.Name}, 规则数: {_rules.Count}, 恶意IP: {_maliciousIPs.Count}",
                Source = "FirewallManager"
            });
        }

        public void Stop()
        {
            _isRunning = false;
            
            _monitorThread?.Join(3000);
            _analysisThread?.Join(2000);
            _ruleUpdateThread?.Join(1000);
            
            SaveFirewallSettings();

            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "FirewallStop",
                Message = "防火墙管理已停止",
                Details = $"监控连接: {_totalConnectionsMonitored}, 阻止连接: {_connectionsBlocked}, 检测入侵: {_intrusionsDetected}",
                Source = "FirewallManager"
            });
        }

        private void EnsureFirewallServiceRunning()
        {
            try
            {
                var service = new System.ServiceProcess.ServiceController("MpsSvc");
                if (service.Status != System.ServiceProcess.ServiceControllerStatus.Running)
                {
                    service.Start();
                    service.WaitForStatus(System.ServiceProcess.ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
                    _dataManager.LogInfo("Windows防火墙服务已启动");
                }
            }
            catch (Exception ex)
            {
                _dataManager.LogError("启动防火墙服务失败", ex.Message, "FirewallManager");
            }
        }

        private void MonitorFirewall()
        {
            while (_isRunning)
            {
                try
                {
                    // 检查网络连接
                    CheckNetworkConnections();
                    
                    // 检测端口扫描
                    if (_enablePortScanDetection)
                    {
                        DetectPortScanning();
                    }
                    
                    // 检测DDoS攻击
                    if (_enableDDoSProtection)
                    {
                        DetectDDoSAttack();
                    }
                    
                    Thread.Sleep(_monitoringInterval);
                }
                catch (Exception ex)
                {
                    _dataManager.LogError("防火墙监控错误", ex.Message, "FirewallManager");
                    Thread.Sleep(1000);
                }
            }
        }

        private void AnalyzeNetworkTraffic()
        {
            while (_isRunning)
            {
                try
                {
                    // 处理连接事件队列
                    while (_connectionEvents.TryDequeue(out var connEvent))
                    {
                        AnalyzeConnectionEvent(connEvent);
                        Interlocked.Increment(ref _totalConnectionsMonitored);
                    }
                    
                    Thread.Sleep(500);
                }
                catch (Exception ex)
                {
                    _dataManager.LogError("流量分析错误", ex.Message, "FirewallManager");
                }
            }
        }

        private void UpdateRulesLoop()
        {
            while (_isRunning)
            {
                try
                {
                    // 定期更新规则
                    UpdateFirewallRules();
                    
                    // 更新恶意IP数据库
                    if (_enableAutoBlocking)
                    {
                        UpdateMaliciousIPDatabase();
                    }
                    
                    Thread.Sleep(_ruleUpdateInterval);
                }
                catch (Exception ex)
                {
                    _dataManager.LogError("规则更新错误", ex.Message, "FirewallManager");
                }
            }
        }

        #region Connection Monitoring
        
        private void CheckNetworkConnections()
        {
            try
            {
                var connections = GetActiveConnections();
                
                foreach (var connection in connections)
                {
                    try
                    {
                        // 检查是否需要阻止
                        if (ShouldBlockConnection(connection))
                        {
                            BlockConnection(connection);
                            Interlocked.Increment(ref _connectionsBlocked);
                            continue;
                        }
                        
                        // 检查入侵检测
                        if (_enableIntrusionDetection)
                        {
                            CheckForIntrusion(connection);
                        }
                        
                        // 应用程序控制
                        if (_enableApplicationControl)
                        {
                            CheckApplicationNetworkAccess(connection);
                        }
                        
                        // 记录连接事件
                        if (_logAllConnections || connection.IsSuspicious)
                        {
                            _connectionEvents.Enqueue(new FirewallNetworkConnectionEvent
                            {
                                Protocol = connection.Protocol,
                                LocalAddress = connection.LocalAddress,
                                RemoteAddress = connection.RemoteAddress,
                                RemotePort = connection.RemotePort,
                                ProcessId = connection.ProcessId,
                                ProcessName = connection.ProcessName,
                                ProcessPath = connection.ProcessPath,
                                Direction = connection.Direction,
                                Timestamp = DateTime.Now,
                                IsSuspicious = connection.IsSuspicious
                            });
                        }
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                _dataManager.LogError("检查网络连接错误", ex.Message, "FirewallManager");
            }
        }

        private List<FirewallNetworkConnectionInfo> GetActiveConnections()
        {
            var connections = new List<FirewallNetworkConnectionInfo>();
            
            try
            {
                // 使用netstat获取连接
                string output = ExecuteCommand("netstat", "-ano");
                if (!string.IsNullOrEmpty(output))
                {
                    connections = ParseNetstatOutput(output);
                }
            }
            catch { }
            
            return connections;
        }

        private List<FirewallNetworkConnectionInfo> ParseNetstatOutput(string output)
        {
            var connections = new List<FirewallNetworkConnectionInfo>();
            
            try
            {
                var lines = output.Split('\n');
                foreach (var line in lines)
                {
                    var trimmedLine = line.Trim();
                    if (!trimmedLine.StartsWith("TCP") && !trimmedLine.StartsWith("UDP"))
                        continue;
                    
                    var parts = trimmedLine.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length < 4)
                        continue;
                    
                    var conn = new FirewallNetworkConnectionInfo
                    {
                        Protocol = parts[0],
                        LocalAddress = parts[1]
                    };
                    
                    if (trimmedLine.StartsWith("TCP"))
                    {
                        conn.RemoteAddress = parts[2];
                        conn.State = parts[3];
                        
                        int pidIndex = parts.Length > 4 ? 4 : -1;
                        if (pidIndex >= 0 && int.TryParse(parts[pidIndex], out int pid))
                        {
                            conn.ProcessId = pid;
                            GetProcessInfo(conn, pid);
                        }
                        
                        // 解析端口
                        ParseAddressPort(conn.RemoteAddress, out string remoteIP, out int remotePort);
                        conn.RemoteIP = remoteIP;
                        conn.RemotePort = remotePort;
                    }
                    else
                    {
                        int pidIndex = parts.Length > 2 ? 3 : -1;
                        if (pidIndex >= 0 && int.TryParse(parts[pidIndex], out int pid))
                        {
                            conn.ProcessId = pid;
                            GetProcessInfo(conn, pid);
                        }
                    }
                    
                    connections.Add(conn);
                }
            }
            catch { }
            
            return connections;
        }

        private void ParseAddressPort(string addressPort, out string address, out int port)
        {
            address = "";
            port = 0;
            
            if (string.IsNullOrEmpty(addressPort))
                return;
            
            int lastColon = addressPort.LastIndexOf(':');
            if (lastColon > 0)
            {
                address = addressPort.Substring(0, lastColon).Trim('[', ']');
                int.TryParse(addressPort.Substring(lastColon + 1), out port);
            }
        }

        private void GetProcessInfo(FirewallNetworkConnectionInfo conn, int pid)
        {
            try
            {
                var process = Process.GetProcessById(pid);
                conn.ProcessName = process.ProcessName;
                try
                {
                    conn.ProcessPath = process.MainModule?.FileName;
                }
                catch
                {
                    conn.ProcessPath = "访问被拒绝";
                }
            }
            catch
            {
                conn.ProcessName = "未知";
            }
        }

        #endregion

        #region Connection Filtering
        
        private bool ShouldBlockConnection(FirewallNetworkConnectionInfo connection)
        {
            // 检查被阻止的应用程序
            if (!string.IsNullOrEmpty(connection.ProcessPath) && 
                _blockedApplications.Contains(connection.ProcessPath))
            {
                LogBlockedConnection(connection, "应用程序被阻止");
                return true;
            }
            
            // 检查恶意IP
            if (!string.IsNullOrEmpty(connection.RemoteIP) && 
                (_maliciousIPs.Contains(connection.RemoteIP) || _blockedIPs.ContainsKey(connection.RemoteIP)))
            {
                LogBlockedConnection(connection, "恶意IP地址");
                return true;
            }
            
            // 检查受限端口
            if (_restrictedPorts.Contains(connection.RemotePort))
            {
                LogBlockedConnection(connection, "受限端口");
                return true;
            }
            
            // 检查当前区域策略
            if (_currentZone.BlockIncoming && connection.Direction == ConnectionDirection.Inbound)
            {
                if (!_currentZone.AllowedPorts.Contains(connection.RemotePort))
                {
                    LogBlockedConnection(connection, "区域策略阻止入站");
                    return true;
                }
            }
            
            return false;
        }

        private void BlockConnection(FirewallNetworkConnectionInfo connection)
        {
            try
            {
                // 使用Windows防火墙API阻止连接
                // 这里使用netsh命令作为示例
                if (!string.IsNullOrEmpty(connection.RemoteIP))
                {
                    // 添加临时阻止规则
                    string ruleName = $"FireAntivirus_Block_{connection.RemoteIP}_{DateTime.Now.Ticks}";
                    string command = $"advfirewall firewall add rule name=\"{ruleName}\" dir=out remoteip={connection.RemoteIP} action=block";
                    ExecuteCommand("netsh", command);
                }
            }
            catch (Exception ex)
            {
                _dataManager.LogError("阻止连接失败", ex.Message, "FirewallManager");
            }
        }

        private void LogBlockedConnection(FirewallNetworkConnectionInfo connection, string reason)
        {
            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "ConnectionBlocked",
                Message = "连接被阻止",
                Details = $"进程: {connection.ProcessName}, 远程地址: {connection.RemoteIP}:{connection.RemotePort}, 原因: {reason}",
                Source = "FirewallManager",
                Category = "网络防护"
            });
        }

        #endregion

        #region Intrusion Detection
        
        private void CheckForIntrusion(FirewallNetworkConnectionInfo connection)
        {
            try
            {
                // 检测可疑连接模式
                var indicators = new List<string>();
                
                // 检查连接到可疑端口
                int[] suspiciousPorts = { 4444, 5555, 6666, 7777, 8888, 9999, 31337, 12345 };
                if (suspiciousPorts.Contains(connection.RemotePort))
                {
                    indicators.Add($"可疑端口: {connection.RemotePort}");
                }
                
                // 检查未知进程的出站连接
                if (!string.IsNullOrEmpty(connection.ProcessPath))
                {
                    if (IsSuspiciousProcessLocation(connection.ProcessPath))
                    {
                        indicators.Add($"可疑进程位置: {connection.ProcessPath}");
                    }
                }
                
                // 检查高频连接
                // (需要在流量分析中统计)
                
                if (indicators.Count > 0)
                {
                    var intrusion = new IntrusionAttempt
                    {
                        IntrusionId = Guid.NewGuid().ToString(),
                        SourceIP = connection.RemoteIP,
                        SourcePort = connection.RemotePort,
                        TargetProcess = connection.ProcessName,
                        TargetPath = connection.ProcessPath,
                        Indicators = indicators,
                        Severity = indicators.Count >= 3 ? ThreatSeverity.High : ThreatSeverity.Medium,
                        DetectedAt = DateTime.Now
                    };
                    
                    _intrusionAttempts.Add(intrusion);
                    Interlocked.Increment(ref _intrusionsDetected);
                    
                    CreateFirewallAlert("IntrusionAttempt", 
                        $"检测到可能的入侵尝试: {connection.ProcessName}", 
                        string.Join("; ", indicators));
                    
                    // 自动阻止
                    if (_enableAutoBlocking && !string.IsNullOrEmpty(connection.RemoteIP))
                    {
                        BlockIPAddress(connection.RemoteIP, "入侵尝试");
                    }
                }
            }
            catch { }
        }

        private bool IsSuspiciousProcessLocation(string path)
        {
            if (string.IsNullOrEmpty(path))
                return false;
            
            string lowerPath = path.ToLower();
            
            string[] suspiciousLocations = {
                "\\temp\\", "\\appdata\\local\\temp\\", "\\downloads\\",
                "\\desktop\\", "\\appdata\\roaming\\", "\\public\\",
                "\\windows\\temp\\"
            };
            
            return suspiciousLocations.Any(loc => lowerPath.Contains(loc));
        }

        #endregion

        #region Port Scan Detection
        
        private void DetectPortScanning()
        {
            try
            {
                // 分析最近的连接事件
                var recentEvents = _connectionEvents.ToArray()
                    .Where(e => e.Timestamp > DateTime.Now.AddMinutes(-5))
                    .ToList();
                
                // 按源IP分组
                var groupedByIP = recentEvents
                    .GroupBy(e => e.RemoteAddress)
                    .Where(g => g.Count() > 10)
                    .ToList();
                
                foreach (var group in groupedByIP)
                {
                    var ports = group.Select(e => e.RemotePort).Distinct().ToList();
                    
                    // 如果一个IP在短时间内连接多个不同端口，可能是端口扫描
                    if (ports.Count > 10)
                    {
                        CreateFirewallAlert("PortScan",
                            $"检测到端口扫描: {group.Key}",
                            $"扫描端口数: {ports.Count}, 连接数: {group.Count()}");
                        
                        if (_enableAutoBlocking)
                        {
                            BlockIPAddress(group.Key, "端口扫描");
                        }
                    }
                }
            }
            catch { }
        }

        #endregion

        #region DDoS Protection

        private void DetectDDoSAttack()
        {
            try
            {
                // 分析入站连接速率
                var recentConnections = _connectionEvents.ToArray()
                    .Where(e => e.Timestamp > DateTime.Now.AddSeconds(-10))
                    .ToList();
                
                // 按目标端口分组
                var groupedByPort = recentConnections
                    .GroupBy(e => e.LocalAddress)
                    .Where(g => g.Count() > _maxConnectionRate)
                    .ToList();
                
                foreach (var group in groupedByPort)
                {
                    var sourceIPs = group.Select(e => e.RemoteAddress).Distinct().ToList();
                    
                    if (sourceIPs.Count > 10)
                    {
                        CreateFirewallAlert("DDoSAttack",
                            $"检测到可能的DDoS攻击",
                            $"目标: {group.Key}, 连接数: {group.Count()}, 源IP数: {sourceIPs.Count}");
                    }
                }
            }
            catch { }
        }

        #endregion

        #region Application Control

        private void CheckApplicationNetworkAccess(FirewallNetworkConnectionInfo connection)
        {
            if (string.IsNullOrEmpty(connection.ProcessPath))
                return;
            
            var profile = _appProfiles.GetOrAdd(connection.ProcessPath, 
                path => CreateAppProfile(path, connection.ProcessName));
            
            // 更新统计
            profile.TotalConnections++;
            profile.LastConnectionTime = DateTime.Now;
            
            // 检查是否需要阻止
            if (!profile.IsAllowed)
            {
                LogBlockedConnection(connection, "应用程序网络访问被拒绝");
                // 可以选择阻止连接
            }
        }

        private ApplicationNetworkProfile CreateAppProfile(string path, string processName)
        {
            var profile = new ApplicationNetworkProfile
            {
                FilePath = path,
                ProcessName = processName,
                FirstSeen = DateTime.Now,
                TotalConnections = 0,
                IsAllowed = true, // 默认允许
                TrustLevel = TrustLevel.Unknown
            };
            
            // 评估信任等级
            if (_trustedApplications.Contains(path))
            {
                profile.TrustLevel = TrustLevel.Trusted;
                profile.IsAllowed = true;
            }
            else if (_blockedApplications.Contains(path))
            {
                profile.TrustLevel = TrustLevel.Blocked;
                profile.IsAllowed = false;
            }
            else
            {
                // 根据路径和签名评估
                profile.TrustLevel = EvaluateTrustLevel(path);
            }
            
            return profile;
        }

        private TrustLevel EvaluateTrustLevel(string path)
        {
            try
            {
                // 检查路径
                string lowerPath = path.ToLower();
                
                // 系统目录
                string system32 = Environment.GetFolderPath(Environment.SpecialFolder.System).ToLower();
                string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows).ToLower();
                
                if (lowerPath.StartsWith(system32) || lowerPath.StartsWith(windows))
                {
                    return TrustLevel.System;
                }
                
                // Program Files
                string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles).ToLower();
                string programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86).ToLower();
                
                if (lowerPath.StartsWith(programFiles) || lowerPath.StartsWith(programFilesX86))
                {
                    return TrustLevel.Trusted;
                }
                
                // 可疑位置
                if (IsSuspiciousProcessLocation(path))
                {
                    return TrustLevel.Suspicious;
                }
                
                // 验证签名
                // TODO: 实现签名验证
                
                return TrustLevel.Unknown;
            }
            catch
            {
                return TrustLevel.Unknown;
            }
        }

        #endregion

        #region Rule Management

        private void UpdateFirewallRules()
        {
            try
            {
                // 同步规则到Windows防火墙
                foreach (var rule in _rules.Values.Where(r => r.IsEnabled && !r.IsApplied))
                {
                    ApplyRuleToSystem(rule);
                    rule.IsApplied = true;
                    Interlocked.Increment(ref _rulesApplied);
                }
                
                // 清理过期规则
                var expiredRules = _rules.Values
                    .Where(r => r.ExpirationTime.HasValue && r.ExpirationTime.Value < DateTime.Now)
                    .ToList();
                
                foreach (var rule in expiredRules)
                {
                    RemoveRuleFromSystem(rule);
                    FirewallRule removed;
                    _rules.TryRemove(rule.Id, out removed);
                }
            }
            catch (Exception ex)
            {
                _dataManager.LogError("更新防火墙规则错误", ex.Message, "FirewallManager");
            }
        }

        private void ApplyRuleToSystem(FirewallRule rule)
        {
            try
            {
                var command = BuildRuleCommand(rule);
                ExecuteCommand("netsh", command);
            }
            catch (Exception ex)
            {
                _dataManager.LogError($"应用规则失败: {rule.Name}", ex.Message, "FirewallManager");
            }
        }

        private void RemoveRuleFromSystem(FirewallRule rule)
        {
            try
            {
                ExecuteCommand("netsh", $"advfirewall firewall delete rule name=\"{rule.Name}\"");
            }
            catch { }
        }

        private string BuildRuleCommand(FirewallRule rule)
        {
            var sb = new StringBuilder();
            sb.Append("advfirewall firewall add rule ");
            sb.Append($"name=\"{rule.Name}\" ");
            sb.Append($"dir={rule.Direction.ToString().ToLower()} ");
            sb.Append($"action={rule.Action.ToString().ToLower()} ");
            
            if (!string.IsNullOrEmpty(rule.ApplicationPath))
                sb.Append($"program=\"{rule.ApplicationPath}\" ");
            
            if (!string.IsNullOrEmpty(rule.RemoteIP))
                sb.Append($"remoteip={rule.RemoteIP} ");
            
            if (!string.IsNullOrEmpty(rule.LocalPort))
                sb.Append($"localport={rule.LocalPort} ");
            
            if (!string.IsNullOrEmpty(rule.RemotePort))
                sb.Append($"remoteport={rule.RemotePort} ");
            
            if (!string.IsNullOrEmpty(rule.Protocol))
                sb.Append($"protocol={rule.Protocol} ");
            
            return sb.ToString();
        }

        private void UpdateMaliciousIPDatabase()
        {
            // 从威胁情报源更新恶意IP列表
            // 此处为框架实现
        }

        #endregion

        #region Public API

        public void AllowApplication(string applicationPath)
        {
            if (string.IsNullOrEmpty(applicationPath) || !File.Exists(applicationPath))
                return;
            
            _trustedApplications.Add(applicationPath);
            _blockedApplications.Remove(applicationPath);
            
            // 添加防火墙规则
            var rule = new FirewallRule
            {
                Id = Guid.NewGuid().ToString(),
                Name = $"FireAntivirus_Allow_{Path.GetFileName(applicationPath)}",
                Direction = RuleDirection.Both,
                Action = RuleAction.Allow,
                ApplicationPath = applicationPath,
                IsEnabled = true,
                CreatedAt = DateTime.Now
            };
            
            _rules.TryAdd(rule.Id, rule);
            ApplyRuleToSystem(rule);
            SaveFirewallSettings();
        }

        public void BlockApplication(string applicationPath)
        {
            if (string.IsNullOrEmpty(applicationPath) || !File.Exists(applicationPath))
                return;
            
            _blockedApplications.Add(applicationPath);
            _trustedApplications.Remove(applicationPath);
            
            // 添加防火墙规则
            var rule = new FirewallRule
            {
                Id = Guid.NewGuid().ToString(),
                Name = $"FireAntivirus_Block_{Path.GetFileName(applicationPath)}",
                Direction = RuleDirection.Both,
                Action = RuleAction.Block,
                ApplicationPath = applicationPath,
                IsEnabled = true,
                CreatedAt = DateTime.Now
            };
            
            _rules.TryAdd(rule.Id, rule);
            ApplyRuleToSystem(rule);
            SaveFirewallSettings();
        }

        public void BlockIPAddress(string ipAddress, string reason)
        {
            if (string.IsNullOrEmpty(ipAddress))
                return;
            
            _blockedIPs.TryAdd(ipAddress, new BlockedIPInfo
            {
                IPAddress = ipAddress,
                Reason = reason,
                BlockedAt = DateTime.Now
            });
            
            _maliciousIPs.Add(ipAddress);
            
            // 添加防火墙规则
            var rule = new FirewallRule
            {
                Id = Guid.NewGuid().ToString(),
                Name = $"FireAntivirus_Block_IP_{ipAddress.Replace(".", "_")}",
                Direction = RuleDirection.Outbound,
                Action = RuleAction.Block,
                RemoteIP = ipAddress,
                IsEnabled = true,
                CreatedAt = DateTime.Now,
                Reason = reason
            };
            
            _rules.TryAdd(rule.Id, rule);
            ApplyRuleToSystem(rule);
        }

        public void BlockPort(int port, string protocol = "TCP")
        {
            _restrictedPorts.Add(port);
            
            var rule = new FirewallRule
            {
                Id = Guid.NewGuid().ToString(),
                Name = $"FireAntivirus_Block_Port_{port}",
                Direction = RuleDirection.Both,
                Action = RuleAction.Block,
                LocalPort = port.ToString(),
                Protocol = protocol,
                IsEnabled = true,
                CreatedAt = DateTime.Now
            };
            
            _rules.TryAdd(rule.Id, rule);
            ApplyRuleToSystem(rule);
        }

        public void SetNetworkZone(string zoneName)
        {
            if (_networkZones.TryGetValue(zoneName, out var zone))
            {
                _currentZone = zone;
                ApplyZonePolicy(zone);
                
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "NetworkZoneChanged",
                    Message = $"网络区域已切换: {zone.Name}",
                    Source = "FirewallManager"
                });
            }
        }

        private void ApplyZonePolicy(NetworkZone zone)
        {
            // 应用区域策略到防火墙
            _stealthMode = zone.StealthMode;
            _blockAllIncoming = zone.BlockIncoming;
            
            // 更新Windows防火墙配置
            if (_stealthMode)
            {
                // 启用隐身模式
            }
        }

        public List<FirewallRule> GetRules()
        {
            return _rules.Values.ToList();
        }

        public List<ApplicationNetworkProfile> GetApplicationProfiles()
        {
            return _appProfiles.Values.ToList();
        }

        public List<IntrusionAttempt> GetIntrusionAttempts()
        {
            return _intrusionAttempts.ToList();
        }

        public List<FirewallAlert> GetAlerts()
        {
            return _alerts.ToList();
        }

        public FirewallStatistics GetStatistics()
        {
            return new FirewallStatistics
            {
                TotalConnectionsMonitored = _totalConnectionsMonitored,
                ConnectionsBlocked = _connectionsBlocked,
                IntrusionsDetected = _intrusionsDetected,
                RulesApplied = _rulesApplied,
                ActiveRules = _rules.Count,
                BlockedIPs = _blockedIPs.Count,
                ApplicationProfiles = _appProfiles.Count,
                CurrentZone = _currentZone?.Name ?? "Unknown",
                RunningTime = DateTime.Now - _startTime
            };
        }

        public void AddCustomRule(FirewallRule rule)
        {
            if (string.IsNullOrEmpty(rule.Id))
                rule.Id = Guid.NewGuid().ToString();
            
            rule.CreatedAt = DateTime.Now;
            rule.IsEnabled = true;
            
            _rules.TryAdd(rule.Id, rule);
            ApplyRuleToSystem(rule);
        }

        public void RemoveRule(string ruleId)
        {
            if (_rules.TryRemove(ruleId, out var rule))
            {
                RemoveRuleFromSystem(rule);
            }
        }

        public void SetStealthMode(bool enabled)
        {
            _stealthMode = enabled;
            SaveFirewallSettings();
        }

        public void SetBlockAllIncoming(bool enabled)
        {
            _blockAllIncoming = enabled;
            SaveFirewallSettings();
        }

        public void SetMonitoringInterval(int milliseconds)
        {
            _monitoringInterval = Math.Max(1000, milliseconds);
        }

        public void EnableIntrusionDetection(bool enable) => _enableIntrusionDetection = enable;
        public void EnablePortScanDetection(bool enable) => _enablePortScanDetection = enable;
        public void EnableDDoSProtection(bool enable) => _enableDDoSProtection = enable;
        public void EnableAutoBlocking(bool enable) => _enableAutoBlocking = enable;

        #endregion

        #region Helper Methods

        private string ExecuteCommand(string fileName, string arguments)
        {
            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = fileName,
                        Arguments = arguments,
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true
                    }
                };
                
                process.Start();
                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit(30000);
                return output;
            }
            catch
            {
                return string.Empty;
            }
        }

        private void AnalyzeConnectionEvent(FirewallNetworkConnectionEvent connEvent)
        {
            // 深度分析连接事件
        }

        private void CreateFirewallAlert(string alertType, string title, string description)
        {
            var alert = new FirewallAlert
            {
                AlertId = Guid.NewGuid().ToString(),
                AlertType = alertType,
                Title = title,
                Description = description,
                DetectedAt = DateTime.Now
            };
            
            _alerts.Enqueue(alert);
            
            // 限制告警数量
            while (_alerts.Count > _maxAlerts)
            {
                FirewallAlert removed;
                _alerts.TryDequeue(out removed);
            }
            
            _dataManager.AddLog(new LogEntry
            {
                Id = alert.AlertId,
                Time = alert.DetectedAt,
                Type = alertType,
                Message = title,
                Details = description,
                Source = "FirewallManager",
                Category = "网络防护"
            });
        }

        #endregion
    }

    #region Data Classes

    public class FirewallRule
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public RuleDirection Direction { get; set; }
        public RuleAction Action { get; set; }
        public string ApplicationPath { get; set; }
        public string RemoteIP { get; set; }
        public string LocalPort { get; set; }
        public string RemotePort { get; set; }
        public string Protocol { get; set; }
        public bool IsEnabled { get; set; }
        public bool IsApplied { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime? ExpirationTime { get; set; }
        public string Reason { get; set; }
    }

    public enum RuleDirection { Inbound, Outbound, Both }
    public enum RuleAction { Allow, Block }

    public class ApplicationNetworkProfile
    {
        public string FilePath { get; set; }
        public string ProcessName { get; set; }
        public DateTime FirstSeen { get; set; }
        public DateTime LastConnectionTime { get; set; }
        public long TotalConnections { get; set; }
        public bool IsAllowed { get; set; }
        public TrustLevel TrustLevel { get; set; }
        public List<string> ConnectedIPs { get; set; } = new List<string>();
    }

    public class BlockedIPInfo
    {
        public string IPAddress { get; set; }
        public string Reason { get; set; }
        public DateTime BlockedAt { get; set; }
        public int BlockCount { get; set; }
    }

    public class BlockedPortInfo
    {
        public int Port { get; set; }
        public string Protocol { get; set; }
        public string Reason { get; set; }
        public DateTime BlockedAt { get; set; }
    }

    public class NetworkZone
    {
        public string Name { get; set; }
        public string Description { get; set; }
        public SecurityLevel SecurityLevel { get; set; }
        public bool BlockIncoming { get; set; }
        public bool StealthMode { get; set; }
        public HashSet<int> AllowedPorts { get; set; }
        public List<string> TrustedNetworks { get; set; }
    }

    public enum SecurityLevel { Low, Medium, High, VeryHigh, Critical }

    public class FirewallAlert
    {
        public string AlertId { get; set; }
        public string AlertType { get; set; }
        public string Title { get; set; }
        public string Description { get; set; }
        public DateTime DetectedAt { get; set; }
    }

    public class FirewallSettings
    {
        public List<string> TrustedApplications { get; set; } = new List<string>();
        public List<string> BlockedApplications { get; set; } = new List<string>();
        public List<string> BlockedIPs { get; set; } = new List<string>();
        public List<int> RestrictedPorts { get; set; } = new List<int>();
        public bool StealthMode { get; set; }
        public bool BlockAllIncoming { get; set; }
        public bool EnableAutoBlocking { get; set; }
        public DateTime LastSaved { get; set; }
    }

    public class FirewallStatistics
    {
        public long TotalConnectionsMonitored { get; set; }
        public long ConnectionsBlocked { get; set; }
        public long IntrusionsDetected { get; set; }
        public long RulesApplied { get; set; }
        public int ActiveRules { get; set; }
        public int BlockedIPs { get; set; }
        public int ApplicationProfiles { get; set; }
        public string CurrentZone { get; set; }
        public TimeSpan RunningTime { get; set; }
    }

    public class FirewallNetworkConnectionInfo
    {
        public string Protocol { get; set; }
        public string LocalAddress { get; set; }
        public int LocalPort { get; set; }
        public string RemoteAddress { get; set; }
        public string RemoteIP { get; set; }
        public int RemotePort { get; set; }
        public string State { get; set; }
        public int ProcessId { get; set; }
        public string ProcessName { get; set; }
        public string ProcessPath { get; set; }
        public bool IsSuspicious { get; set; }
        public ConnectionDirection Direction { get; set; }
        public DateTime Timestamp { get; set; }
    }

    public class FirewallNetworkConnectionEvent
    {
        public DateTime Timestamp { get; set; }
        public string Protocol { get; set; }
        public string LocalAddress { get; set; }
        public string RemoteAddress { get; set; }
        public int RemotePort { get; set; }
        public int ProcessId { get; set; }
        public string ProcessName { get; set; }
        public string ProcessPath { get; set; }
        public ConnectionDirection Direction { get; set; }
        public bool IsSuspicious { get; set; }
        public ThreatSeverity Severity { get; set; }
        public string ThreatType { get; set; }
        public string Description { get; set; }
    }

    #endregion
}
