// 抖音用户 耄耋杀毒软件 开发，严禁非法反编译
// 专业级网络流量分析引擎 - 对标Wireshark/Zeek分析能力
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace FireAntivirus.Services
{
    public class NetworkTrafficAnalyzerService : IDisposable
    {
        #region Windows API

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(
            byte[] pTcpTable, ref int dwSize, bool bOrder,
            int ulAf, int TableClass, int Reserved);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedUdpTable(
            byte[] pUdpTable, ref int dwSize, bool bOrder,
            int ulAf, int TableClass, int Reserved);

        [DllImport("ws2_32.dll", SetLastError = true)]
        private static extern int inet_pton(int AddressFamily, string AddressString, byte[] Address);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetTcpStatisticsEx(ref MIB_TCPSTATS Statistics, int Family);

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPSTATS
        {
            public uint RtoAlgorithm;
            public uint RtoMin;
            public uint RtoMax;
            public uint MaxConn;
            public uint ActiveOpens;
            public uint PassiveOpens;
            public uint AttemptFails;
            public uint EstabResets;
            public uint CurrEstab;
            public uint InSegs;
            public uint OutSegs;
            public uint RetransSegs;
            public uint InErrs;
            public uint OutRsts;
            public uint NumConns;
        }

        private const int AF_INET = 2;
        private const int AF_INET6 = 23;
        private const int TCP_TABLE_OWNER_PID_ALL = 5;
        private const int UDP_TABLE_OWNER_PID = 1;

        #endregion

        private Timer _monitorTimer;
        private bool _isMonitoring = false;
        private long _lastBytesReceived = 0;
        private long _lastBytesSent = 0;
        private DateTime _lastUpdateTime;
        private ConcurrentDictionary<string, NetworkConnectionInfo> _connections = new ConcurrentDictionary<string, NetworkConnectionInfo>();
        private ConcurrentQueue<NetworkTrafficRecord> _trafficHistory = new ConcurrentQueue<NetworkTrafficRecord>();
        private ConcurrentDictionary<string, ApplicationTrafficStats> _applicationStats = new ConcurrentDictionary<string, ApplicationTrafficStats>();
        private ConcurrentDictionary<string, TrafficThreatIndicator> _threatIndicators = new ConcurrentDictionary<string, TrafficThreatIndicator>();

        // 威胁情报缓存
        private HashSet<string> _maliciousIPs = new HashSet<string>();
        private HashSet<string> _maliciousDomains = new HashSet<string>();
        private Dictionary<string, ProtocolSignature> _protocolSignatures = new Dictionary<string, ProtocolSignature>();
        private Dictionary<int, KnownPortInfo> _knownPorts = new Dictionary<int, KnownPortInfo>();

        // 端口扫描检测
        private Dictionary<string, PortScanTracker> _portScanTrackers = new Dictionary<string, PortScanTracker>();
        private DateTime _lastPortScanClean = DateTime.Now;

        // C&C检测
        private Dictionary<string, CCConnectionTracker> _ccTrackers = new Dictionary<string, CCConnectionTracker>();

        // 配置
        private readonly string _cachePath;
        private readonly int _historyMaxCount = 3600; // 1小时数据
        private readonly int _monitorIntervalMs = 1000;

        public event EventHandler<NetworkTrafficEventArgs> TrafficUpdated;
        public event EventHandler<SuspiciousConnectionEventArgs> SuspiciousConnectionDetected;
        public event EventHandler<TrafficThreatDetectedEventArgs> ThreatDetected;
        public event EventHandler<PortScanDetectedEventArgs> PortScanDetected;

        public NetworkTrafficAnalyzerService()
        {
            _cachePath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "FireAntivirus", "NetworkCache");

            if (!Directory.Exists(_cachePath))
                Directory.CreateDirectory(_cachePath);

            InitializeThreatIntelligence();
            InitializeProtocolSignatures();
            InitializeKnownPorts();
        }

        #region 初始化

        private void InitializeThreatIntelligence()
        {
            // 已知恶意IP地址（示例数据，实际应用中应从威胁情报源加载）
            var maliciousIPRanges = new string[]
            {
                // 已知僵尸网络和恶意服务器
                // 实际部署时需要连接威胁情报服务
            };

            foreach (var ip in maliciousIPRanges)
            {
                _maliciousIPs.Add(ip);
            }

            // 已知恶意域名
            var maliciousDomainsList = new[]
            {
                // 示例恶意域名（实际使用时填充真实数据）
                "malware.test", "botnet.test", "c2server.test"
            };

            foreach (var domain in maliciousDomainsList)
            {
                _maliciousDomains.Add(domain.ToLowerInvariant());
            }
        }

        private void InitializeProtocolSignatures()
        {
            _protocolSignatures = new Dictionary<string, ProtocolSignature>
            {
                ["HTTP"] = new ProtocolSignature
                {
                    Ports = new[] { 80, 8080, 8000, 8888 },
                    Patterns = new[] { "GET ", "POST ", "HEAD ", "HTTP/1.", "HTTP/2." },
                    Category = "Web"
                },
                ["HTTPS"] = new ProtocolSignature
                {
                    Ports = new[] { 443, 8443 },
                    Patterns = new[] { "\x16\x03", "\x17\x03" }, // TLS handshake
                    Category = "Web"
                },
                ["FTP"] = new ProtocolSignature
                {
                    Ports = new[] { 21 },
                    Patterns = new[] { "220 ", "USER ", "PASS " },
                    Category = "FileTransfer"
                },
                ["SSH"] = new ProtocolSignature
                {
                    Ports = new[] { 22 },
                    Patterns = new[] { "SSH-" },
                    Category = "RemoteAccess"
                },
                ["SMTP"] = new ProtocolSignature
                {
                    Ports = new[] { 25, 587, 465 },
                    Patterns = new[] { "220 ", "EHLO ", "HELO ", "MAIL FROM:", "RCPT TO:" },
                    Category = "Email"
                },
                ["POP3"] = new ProtocolSignature
                {
                    Ports = new[] { 110, 995 },
                    Patterns = new[] { "+OK ", "-ERR " },
                    Category = "Email"
                },
                ["IMAP"] = new ProtocolSignature
                {
                    Ports = new[] { 143, 993 },
                    Patterns = new[] { "* OK ", "* BAD ", "* NO " },
                    Category = "Email"
                },
                ["DNS"] = new ProtocolSignature
                {
                    Ports = new[] { 53 },
                    Category = "Infrastructure"
                },
                ["RDP"] = new ProtocolSignature
                {
                    Ports = new[] { 3389 },
                    Category = "RemoteAccess"
                },
                ["SMB"] = new ProtocolSignature
                {
                    Ports = new[] { 445, 139 },
                    Category = "FileSharing"
                },
                ["VNC"] = new ProtocolSignature
                {
                    Ports = new[] { 5900, 5901, 5902 },
                    Patterns = new[] { "RFB " },
                    Category = "RemoteAccess"
                },
                ["IRC"] = new ProtocolSignature
                {
                    Ports = new[] { 6667, 6668, 6669 },
                    Patterns = new[] { "NICK ", "USER ", "JOIN ", "PRIVMSG " },
                    Category = "Chat",
                    RiskLevel = ProtocolRiskLevel.Suspicious // 常被恶意软件使用
                },
                ["TOR"] = new ProtocolSignature
                {
                    Ports = new[] { 9001, 9030, 9050, 9051 },
                    Category = "Anonymity",
                    RiskLevel = ProtocolRiskLevel.Monitor
                }
            };
        }

        private void InitializeKnownPorts()
        {
            _knownPorts = new Dictionary<int, KnownPortInfo>
            {
                // 常见服务端口
                [20] = new KnownPortInfo { Service = "FTP-DATA", Risk = PortRisk.Low },
                [21] = new KnownPortInfo { Service = "FTP", Risk = PortRisk.Medium },
                [22] = new KnownPortInfo { Service = "SSH", Risk = PortRisk.Low },
                [23] = new KnownPortInfo { Service = "Telnet", Risk = PortRisk.High },
                [25] = new KnownPortInfo { Service = "SMTP", Risk = PortRisk.Medium },
                [53] = new KnownPortInfo { Service = "DNS", Risk = PortRisk.Medium },
                [80] = new KnownPortInfo { Service = "HTTP", Risk = PortRisk.Low },
                [110] = new KnownPortInfo { Service = "POP3", Risk = PortRisk.Medium },
                [135] = new KnownPortInfo { Service = "RPC", Risk = PortRisk.High },
                [139] = new KnownPortInfo { Service = "NetBIOS", Risk = PortRisk.High },
                [143] = new KnownPortInfo { Service = "IMAP", Risk = PortRisk.Medium },
                [443] = new KnownPortInfo { Service = "HTTPS", Risk = PortRisk.Low },
                [445] = new KnownPortInfo { Service = "SMB", Risk = PortRisk.High },
                [465] = new KnownPortInfo { Service = "SMTPS", Risk = PortRisk.Medium },
                [587] = new KnownPortInfo { Service = "SMTP-TLS", Risk = PortRisk.Medium },
                [993] = new KnownPortInfo { Service = "IMAPS", Risk = PortRisk.Medium },
                [995] = new KnownPortInfo { Service = "POP3S", Risk = PortRisk.Medium },
                [1433] = new KnownPortInfo { Service = "MSSQL", Risk = PortRisk.High },
                [1434] = new KnownPortInfo { Service = "MSSQL-Monitor", Risk = PortRisk.High },
                [1521] = new KnownPortInfo { Service = "Oracle", Risk = PortRisk.High },
                [3306] = new KnownPortInfo { Service = "MySQL", Risk = PortRisk.High },
                [3389] = new KnownPortInfo { Service = "RDP", Risk = PortRisk.High },
                [5432] = new KnownPortInfo { Service = "PostgreSQL", Risk = PortRisk.High },
                [5900] = new KnownPortInfo { Service = "VNC", Risk = PortRisk.High },
                [5985] = new KnownPortInfo { Service = "WinRM-HTTP", Risk = PortRisk.Medium },
                [5986] = new KnownPortInfo { Service = "WinRM-HTTPS", Risk = PortRisk.Medium },
                [6379] = new KnownPortInfo { Service = "Redis", Risk = PortRisk.High },
                [8080] = new KnownPortInfo { Service = "HTTP-Alt", Risk = PortRisk.Low },
                [8443] = new KnownPortInfo { Service = "HTTPS-Alt", Risk = PortRisk.Low },
                [27017] = new KnownPortInfo { Service = "MongoDB", Risk = PortRisk.High },

                // 高风险端口（常被恶意软件使用）
                [4444] = new KnownPortInfo { Service = "Metasploit", Risk = PortRisk.Critical },
                [5555] = new KnownPortInfo { Service = "Backdoor", Risk = PortRisk.Critical },
                [6666] = new KnownPortInfo { Service = "Backdoor", Risk = PortRisk.Critical },
                [7777] = new KnownPortInfo { Service = "Backdoor", Risk = PortRisk.Critical },
                [8888] = new KnownPortInfo { Service = "Backdoor", Risk = PortRisk.High },
                [9999] = new KnownPortInfo { Service = "Backdoor", Risk = PortRisk.Critical },
                [31337] = new KnownPortInfo { Service = "Elite", Risk = PortRisk.Critical },
                [12345] = new KnownPortInfo { Service = "NetBus", Risk = PortRisk.Critical },
                [27374] = new KnownPortInfo { Service = "SubSeven", Risk = PortRisk.Critical },
                [1234] = new KnownPortInfo { Service = "Backdoor", Risk = PortRisk.Critical },
                [1337] = new KnownPortInfo { Service = "Backdoor", Risk = PortRisk.Critical }
            };
        }

        #endregion

        #region 公共方法

        public void StartMonitoring()
        {
            if (_isMonitoring) return;

            _isMonitoring = true;
            _lastUpdateTime = DateTime.Now;

            var stats = GetNetworkStatistics();
            _lastBytesReceived = stats.BytesReceived;
            _lastBytesSent = stats.BytesSent;

            _monitorTimer = new Timer(MonitorCallback, null, TimeSpan.Zero, TimeSpan.FromMilliseconds(_monitorIntervalMs));
        }

        public void StopMonitoring()
        {
            _isMonitoring = false;
            _monitorTimer?.Dispose();
            _monitorTimer = null;
        }

        public NetworkStatistics GetNetworkStatistics()
        {
            var stats = new NetworkStatistics();

            try
            {
                foreach (var networkInterface in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (networkInterface.OperationalStatus != OperationalStatus.Up)
                        continue;

                    if (networkInterface.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                        continue;

                    var interfaceStats = networkInterface.GetIPv4Statistics();
                    stats.BytesReceived += interfaceStats.BytesReceived;
                    stats.BytesSent += interfaceStats.BytesSent;
                    stats.PacketsReceived += interfaceStats.UnicastPacketsReceived;
                    stats.PacketsSent += interfaceStats.UnicastPacketsSent;
                }

                // TCP统计
                var tcpStats = new MIB_TCPSTATS();
                if (GetTcpStatisticsEx(ref tcpStats, AF_INET) == 0)
                {
                    stats.TCPActiveConnections = (int)tcpStats.CurrEstab;
                    stats.TCPFailedConnections = (int)(tcpStats.AttemptFails + tcpStats.EstabResets);
                    stats.TCPRetransmissions = (int)tcpStats.RetransSegs;
                }

                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_NetworkAdapter WHERE NetEnabled = true"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        stats.Adapters.Add(new NetworkAdapterStats
                        {
                            Name = obj["Name"]?.ToString() ?? "",
                            MACAddress = obj["MACAddress"]?.ToString() ?? "",
                            Speed = ParseSpeed(obj["Speed"]?.ToString())
                        });
                    }
                }
            }
            catch { }

            return stats;
        }

        public List<NetworkConnectionInfo> GetActiveConnections()
        {
            var connections = new List<NetworkConnectionInfo>();

            try
            {
                // 使用GetExtendedTcpTable获取带进程信息的TCP连接
                connections.AddRange(GetExtendedTcpConnections());
                connections.AddRange(GetExtendedUdpConnections());
            }
            catch
            {
                // 回退到.NET API
                connections.AddRange(GetTcpConnectionsFallback());
            }

            // 丰富连接信息
            foreach (var conn in connections)
            {
                EnrichConnectionInfo(conn);
            }

            return connections;
        }

        public NetworkTrafficAnalysis GetTrafficAnalysis()
        {
            var analysis = new NetworkTrafficAnalysis
            {
                GeneratedAt = DateTime.Now
            };

            // 协议分布
            var connections = GetActiveConnections();
            var protocolGroups = connections.GroupBy(c => c.IdentifiedProtocol);
            foreach (var group in protocolGroups)
            {
                analysis.ProtocolDistribution[group.Key ?? "Unknown"] = group.Count();
            }

            // 应用流量统计
            analysis.TopApplications = _applicationStats
                .OrderByDescending(kv => kv.Value.TotalBytes)
                .Take(10)
                .Select(kv => new ApplicationTrafficInfo
                {
                    ProcessName = kv.Key,
                    BytesSent = kv.Value.BytesSent,
                    BytesReceived = kv.Value.BytesReceived,
                    Connections = kv.Value.ConnectionCount,
                    Protocol = kv.Value.PrimaryProtocol
                })
                .ToList();

            // 目的地分析
            analysis.TopDestinations = connections
                .Where(c => !string.IsNullOrEmpty(c.RemoteAddress) && c.RemoteAddress != "*" && c.RemoteAddress != "0.0.0.0")
                .GroupBy(c => c.RemoteAddress)
                .OrderByDescending(g => g.Count())
                .Take(10)
                .Select(g => new DestinationInfo
                {
                    IPAddress = g.Key,
                    ConnectionCount = g.Count(),
                    Ports = g.Select(c => c.RemotePort).Distinct().ToList(),
                    RiskLevel = GetIPRiskLevel(g.Key)
                })
                .ToList();

            // 地理位置分析（简化实现）
            analysis.ExternalConnections = connections
                .Count(c => !IsPrivateIP(c.RemoteAddress));

            // 威胁统计
            analysis.ThreatStats = new ThreatStatistics
            {
                TotalThreats = _threatIndicators.Count,
                CriticalThreats = _threatIndicators.Values.Count(t => t.Severity == ThreatSeverity.Critical),
                HighThreats = _threatIndicators.Values.Count(t => t.Severity == ThreatSeverity.High),
                MediumThreats = _threatIndicators.Values.Count(t => t.Severity == ThreatSeverity.Medium),
                LowThreats = _threatIndicators.Values.Count(t => t.Severity == ThreatSeverity.Low)
            };

            return analysis;
        }

        public List<TrafficThreatIndicator> GetActiveThreats()
        {
            return _threatIndicators.Values.ToList();
        }

        public List<NetworkConnectionInfo> GetSuspiciousConnections()
        {
            var suspicious = new List<NetworkConnectionInfo>();

            foreach (var conn in GetActiveConnections())
            {
                var threatLevel = EvaluateConnectionThreat(conn);
                if (threatLevel > 0)
                {
                    conn.ThreatScore = threatLevel;
                    suspicious.Add(conn);
                }
            }

            return suspicious.OrderByDescending(c => c.ThreatScore).ToList();
        }

        public Dictionary<string, ApplicationTrafficStats> GetApplicationTrafficStats()
        {
            return new Dictionary<string, ApplicationTrafficStats>(_applicationStats);
        }

        public List<NetworkTrafficRecord> GetTrafficHistory()
        {
            return _trafficHistory.ToList();
        }

        public PortScanAnalysis AnalyzePortScans()
        {
            var analysis = new PortScanAnalysis
            {
                GeneratedAt = DateTime.Now
            };

            foreach (var tracker in _portScanTrackers.Values)
            {
                if (tracker.IsPortScan)
                {
                    analysis.DetectedScans.Add(new PortScanInfo
                    {
                        SourceIP = tracker.SourceIP,
                        TargetPorts = tracker.ScannedPorts.ToList(),
                        StartTime = tracker.FirstSeen,
                        Duration = DateTime.Now - tracker.FirstSeen,
                        ScanRate = tracker.ScanRate,
                        IsOngoing = (DateTime.Now - tracker.LastSeen).TotalSeconds < 60
                    });
                }
            }

            return analysis;
        }

        public List<CCDetectionResult> DetectCCCommunications()
        {
            var results = new List<CCDetectionResult>();

            foreach (var tracker in _ccTrackers.Values)
            {
                if (tracker.IsLikelyCC)
                {
                    results.Add(new CCDetectionResult
                    {
                        DestinationIP = tracker.DestinationIP,
                        DestinationPort = tracker.DestinationPort,
                        ProcessName = tracker.ProcessName,
                        Confidence = tracker.Confidence,
                        Indicators = tracker.Indicators.ToList(),
                        FirstSeen = tracker.FirstSeen,
                        LastSeen = tracker.LastSeen,
                        ConnectionCount = tracker.ConnectionCount,
                        TotalBytes = tracker.TotalBytes
                    });
                }
            }

            return results.OrderByDescending(r => r.Confidence).ToList();
        }

        public NetworkSpeedTestResult TestNetworkSpeed()
        {
            var result = new NetworkSpeedTestResult();

            try
            {
                // 测试多个目标的延迟
                var targets = new[] { "8.8.8.8", "1.1.1.1", "208.67.222.222" };
                var latencies = new List<long>();

                foreach (var target in targets)
                {
                    try
                    {
                        using (var ping = new Ping())
                        {
                            var reply = ping.Send(target, 2000);
                            if (reply.Status == IPStatus.Success)
                            {
                                latencies.Add(reply.RoundtripTime);
                            }
                        }
                    }
                    catch { }
                }

                result.Latency = latencies.Count > 0 ? (long)latencies.Average() : -1;
                result.PacketLoss = latencies.Count < targets.Length ? (targets.Length - latencies.Count) * 100 / targets.Length : 0;

                // DNS解析测试
                var dnsTargets = new[] { "google.com", "microsoft.com", "cloudflare.com" };
                var dnsTimes = new List<long>();

                foreach (var dnsTarget in dnsTargets)
                {
                    var watch = Stopwatch.StartNew();
                    try
                    {
                        Dns.GetHostAddresses(dnsTarget);
                        watch.Stop();
                        dnsTimes.Add(watch.ElapsedMilliseconds);
                    }
                    catch { }
                }

                result.DNSResolutionTime = dnsTimes.Count > 0 ? (long)dnsTimes.Average() : -1;

                // 带宽估算
                result.DownloadSpeed = GetAverageDownloadSpeed();
                result.UploadSpeed = GetAverageUploadSpeed();

                // 连接状态
                result.ActiveConnections = GetActiveConnections().Count;
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
            }

            return result;
        }

        public void BlockConnection(string remoteIP, int? port = null)
        {
            // 创建防火墙规则阻止连接
            try
            {
                var ruleName = $"FireAntivirus_Block_{remoteIP.Replace(".", "_")}";
                var args = port.HasValue
                    ? $"advfirewall firewall add rule name=\"{ruleName}\" dir=out remoteip={remoteIP} remoteport={port} action=block protocol=tcp"
                    : $"advfirewall firewall add rule name=\"{ruleName}\" dir=out remoteip={remoteIP} action=block";

                var process = Process.Start(new ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = args,
                    UseShellExecute = true,
                    Verb = "runas",
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                });
                process?.WaitForExit(10000);
            }
            catch { }
        }

        #endregion

        #region 私有方法 - 监控

        private void MonitorCallback(object state)
        {
            try
            {
                var stats = GetNetworkStatistics();
                var now = DateTime.Now;
                var elapsed = (now - _lastUpdateTime).TotalSeconds;

                var bytesReceivedDiff = stats.BytesReceived - _lastBytesReceived;
                var bytesSentDiff = stats.BytesSent - _lastBytesSent;

                var downloadSpeed = elapsed > 0 ? (long)(bytesReceivedDiff / elapsed) : 0;
                var uploadSpeed = elapsed > 0 ? (long)(bytesSentDiff / elapsed) : 0;

                _lastBytesReceived = stats.BytesReceived;
                _lastBytesSent = stats.BytesSent;
                _lastUpdateTime = now;

                // 记录历史
                if (_trafficHistory.Count >= _historyMaxCount)
                {
                    _trafficHistory.TryDequeue(out _);
                }

                _trafficHistory.Enqueue(new NetworkTrafficRecord
                {
                    Timestamp = now,
                    DownloadSpeed = downloadSpeed,
                    UploadSpeed = uploadSpeed,
                    DownloadedBytes = bytesReceivedDiff,
                    UploadedBytes = bytesSentDiff
                });

                // 更新连接
                UpdateConnections();

                // 检测威胁
                DetectThreats();

                // 检测端口扫描
                DetectPortScans();

                // 检测C&C通信
                DetectCCBehavior();

                // 清理过期数据
                CleanupExpiredData();

                TrafficUpdated?.Invoke(this, new NetworkTrafficEventArgs
                {
                    DownloadSpeed = downloadSpeed,
                    UploadSpeed = uploadSpeed,
                    TotalDownloaded = stats.BytesReceived,
                    TotalUploaded = stats.BytesSent,
                    ActiveConnections = _connections.Count,
                    TCPConnections = stats.TCPActiveConnections,
                    ThreatCount = _threatIndicators.Count
                });
            }
            catch { }
        }

        private void UpdateConnections()
        {
            var currentConnections = GetActiveConnections();
            var currentKeys = new HashSet<string>();

            foreach (var conn in currentConnections)
            {
                var key = $"{conn.Protocol}_{conn.LocalAddress}_{conn.LocalPort}_{conn.RemoteAddress}_{conn.RemotePort}_{conn.ProcessId}";
                currentKeys.Add(key);

                var existingConn = _connections.GetOrAdd(key, conn);
                existingConn.LastSeen = DateTime.Now;
                existingConn.BytesTransferred += conn.BytesTransferred;

                // 更新应用统计
                UpdateApplicationStats(conn);
            }

            // 移除已关闭的连接
            var keysToRemove = _connections.Keys.Where(k => !currentKeys.Contains(k)).ToList();
            foreach (var key in keysToRemove)
            {
                _connections.TryRemove(key, out _);
            }
        }

        private void UpdateApplicationStats(NetworkConnectionInfo conn)
        {
            if (string.IsNullOrEmpty(conn.ProcessName)) return;

            var stats = _applicationStats.GetOrAdd(conn.ProcessName, new ApplicationTrafficStats
            {
                ProcessId = conn.ProcessId,
                ProcessName = conn.ProcessName,
                FirstSeen = DateTime.Now
            });

            stats.LastSeen = DateTime.Now;
            stats.ConnectionCount++;
            stats.BytesSent += conn.BytesSent;
            stats.BytesReceived += conn.BytesReceived;

            if (!string.IsNullOrEmpty(conn.IdentifiedProtocol))
            {
                stats.PrimaryProtocol = conn.IdentifiedProtocol;
            }
        }

        #endregion

        #region 私有方法 - 威胁检测

        private void DetectThreats()
        {
            foreach (var conn in _connections.Values)
            {
                var threatLevel = EvaluateConnectionThreat(conn);

                if (threatLevel >= 50) // 高威胁阈值
                {
                    var threat = new TrafficThreatIndicator
                    {
                        Id = Guid.NewGuid().ToString(),
                        Timestamp = DateTime.Now,
                        Type = DetermineThreatType(conn),
                        Severity = threatLevel >= 80 ? ThreatSeverity.Critical :
                                   threatLevel >= 60 ? ThreatSeverity.High :
                                   ThreatSeverity.Medium,
                        Source = conn.LocalAddress,
                        Destination = conn.RemoteAddress,
                        ProcessName = conn.ProcessName,
                        Description = GenerateThreatDescription(conn),
                        Connection = conn
                    };

                    _threatIndicators[threat.Id] = threat;

                    ThreatDetected?.Invoke(this, new TrafficThreatDetectedEventArgs { Threat = threat });
                }
            }
        }

        private int EvaluateConnectionThreat(NetworkConnectionInfo conn)
        {
            int score = 0;

            // 检查端口风险
            if (_knownPorts.TryGetValue(conn.RemotePort, out var portInfo))
            {
                score += portInfo.Risk switch
                {
                    PortRisk.Critical => 60,
                    PortRisk.High => 40,
                    PortRisk.Medium => 20,
                    _ => 0
                };
            }

            // 检查恶意IP
            if (_maliciousIPs.Contains(conn.RemoteAddress))
            {
                score += 80;
            }

            // 检查可疑协议
            if (!string.IsNullOrEmpty(conn.IdentifiedProtocol))
            {
                if (_protocolSignatures.TryGetValue(conn.IdentifiedProtocol, out var sig))
                {
                    if (sig.RiskLevel == ProtocolRiskLevel.Suspicious)
                        score += 30;
                    else if (sig.RiskLevel == ProtocolRiskLevel.Monitor)
                        score += 10;
                }
            }

            // 检查未知进程的高风险连接
            if (conn.ProcessName == "Unknown" && conn.State == "Established")
            {
                score += 25;
            }

            // 检查非标准端口
            if (conn.RemotePort > 49152 && conn.State == "Established" && !IsPrivateIP(conn.RemoteAddress))
            {
                score += 15;
            }

            // 检查连接行为
            if (conn.BytesTransferred > 0 && conn.BytesSent > conn.BytesReceived * 10)
            {
                // 大量数据外传
                score += 30;
            }

            return Math.Min(score, 100);
        }

        private ThreatType DetermineThreatType(NetworkConnectionInfo conn)
        {
            if (_maliciousIPs.Contains(conn.RemoteAddress))
                return ThreatType.KnownMalicious;

            if (_knownPorts.TryGetValue(conn.RemotePort, out var portInfo) && portInfo.Risk >= PortRisk.Critical)
                return ThreatType.Backdoor;

            if (conn.IdentifiedProtocol == "IRC")
                return ThreatType.BotnetCommunication;

            if (conn.BytesSent > conn.BytesReceived * 10)
                return ThreatType.DataExfiltration;

            return ThreatType.SuspiciousActivity;
        }

        private string GenerateThreatDescription(NetworkConnectionInfo conn)
        {
            var sb = new StringBuilder();

            if (_maliciousIPs.Contains(conn.RemoteAddress))
            {
                sb.AppendLine($"连接到已知恶意IP地址: {conn.RemoteAddress}");
            }

            if (_knownPorts.TryGetValue(conn.RemotePort, out var portInfo) && portInfo.Risk >= PortRisk.High)
            {
                sb.AppendLine($"使用高风险端口: {conn.RemotePort} ({portInfo.Service})");
            }

            if (conn.IdentifiedProtocol == "IRC")
            {
                sb.AppendLine("检测到IRC协议通信，常被恶意软件用于C&C通信");
            }

            sb.AppendLine($"进程: {conn.ProcessName} (PID: {conn.ProcessId})");
            sb.AppendLine($"远程地址: {conn.RemoteAddress}:{conn.RemotePort}");

            return sb.ToString();
        }

        private void DetectPortScans()
        {
            var now = DateTime.Now;

            // 清理过期的端口扫描追踪器
            if ((now - _lastPortScanClean).TotalMinutes > 5)
            {
                var expiredKeys = _portScanTrackers
                    .Where(kv => (now - kv.Value.LastSeen).TotalMinutes > 10)
                    .Select(kv => kv.Key)
                    .ToList();

                foreach (var key in expiredKeys)
                {
                    _portScanTrackers.Remove(key);
                }

                _lastPortScanClean = now;
            }

            // 分析连接模式
            foreach (var conn in _connections.Values)
            {
                if (conn.LocalPort == 0 || conn.RemoteAddress == "*" || IsPrivateIP(conn.RemoteAddress))
                    continue;

                var key = conn.RemoteAddress;

                if (!_portScanTrackers.TryGetValue(key, out var tracker))
                {
                    tracker = new PortScanTracker
                    {
                        SourceIP = conn.RemoteAddress,
                        FirstSeen = now
                    };
                    _portScanTrackers[key] = tracker;
                }

                tracker.LastSeen = now;
                tracker.ScannedPorts.Add(conn.LocalPort);
                tracker.ConnectionCount++;

                // 计算扫描速率
                var duration = (now - tracker.FirstSeen).TotalSeconds;
                if (duration > 0)
                {
                    tracker.ScanRate = tracker.ScannedPorts.Count / duration;

                    // 判断是否为端口扫描
                    if (tracker.ScannedPorts.Count >= 10 && tracker.ScanRate > 0.5)
                    {
                        tracker.IsPortScan = true;

                        if (!tracker.Alerted)
                        {
                            tracker.Alerted = true;

                            PortScanDetected?.Invoke(this, new PortScanDetectedEventArgs
                            {
                                SourceIP = tracker.SourceIP,
                                TargetPorts = tracker.ScannedPorts.ToList(),
                                ScanRate = tracker.ScanRate,
                                StartTime = tracker.FirstSeen
                            });

                            // 添加威胁指示器
                            var threat = new TrafficThreatIndicator
                            {
                                Id = Guid.NewGuid().ToString(),
                                Timestamp = now,
                                Type = ThreatType.PortScan,
                                Severity = ThreatSeverity.High,
                                Source = tracker.SourceIP,
                                Description = $"检测到端口扫描攻击\n源IP: {tracker.SourceIP}\n扫描端口数: {tracker.ScannedPorts.Count}\n扫描速率: {tracker.ScanRate:F2} 端口/秒"
                            };

                            _threatIndicators[threat.Id] = threat;
                        }
                    }
                }
            }
        }

        private void DetectCCBehavior()
        {
            var now = DateTime.Now;

            foreach (var conn in _connections.Values)
            {
                if (conn.RemotePort == 0 || IsPrivateIP(conn.RemoteAddress))
                    continue;

                var key = $"{conn.RemoteAddress}:{conn.RemotePort}";

                if (!_ccTrackers.TryGetValue(key, out var tracker))
                {
                    tracker = new CCConnectionTracker
                    {
                        DestinationIP = conn.RemoteAddress,
                        DestinationPort = conn.RemotePort,
                        ProcessName = conn.ProcessName,
                        FirstSeen = now
                    };
                    _ccTrackers[key] = tracker;
                }

                tracker.LastSeen = now;
                tracker.ConnectionCount++;
                tracker.TotalBytes += conn.BytesTransferred;

                // 计算置信度
                CalculateCCConfidence(tracker, conn);
            }

            // 清理过期的C&C追踪器
            var expiredCCKeys = _ccTrackers
                .Where(kv => (now - kv.Value.LastSeen).TotalMinutes > 30)
                .Select(kv => kv.Key)
                .ToList();

            foreach (var key in expiredCCKeys)
            {
                _ccTrackers.Remove(key);
            }
        }

        private void CalculateCCConfidence(CCConnectionTracker tracker, NetworkConnectionInfo conn)
        {
            int confidence = 0;
            var indicators = new List<string>();

            // 检查连接模式

            // 周期性连接模式
            if (tracker.ConnectionCount > 5 && tracker.ConnectionCount < 50)
            {
                confidence += 20;
                indicators.Add("周期性连接模式");
            }

            // 小数据包心跳
            if (conn.BytesTransferred > 0 && conn.BytesTransferred < 1000)
            {
                confidence += 15;
                indicators.Add("小数据包传输");
            }

            // 非标准端口
            if (conn.RemotePort > 49152)
            {
                confidence += 10;
                indicators.Add("非标准端口");
            }

            // 可疑协议
            if (conn.IdentifiedProtocol == "IRC" || conn.IdentifiedProtocol == "TOR")
            {
                confidence += 25;
                indicators.Add($"可疑协议: {conn.IdentifiedProtocol}");
            }

            // 未知进程
            if (conn.ProcessName == "Unknown")
            {
                confidence += 15;
                indicators.Add("未知进程");
            }

            // 大量数据外传
            if (tracker.TotalBytes > 10 * 1024 * 1024 && conn.BytesSent > conn.BytesReceived * 5)
            {
                confidence += 20;
                indicators.Add("大量数据外传");
            }

            tracker.Indicators = indicators;
            tracker.Confidence = Math.Min(confidence, 100);
            tracker.IsLikelyCC = confidence >= 50;
        }

        #endregion

        #region 私有方法 - 连接获取

        private List<NetworkConnectionInfo> GetExtendedTcpConnections()
        {
            var connections = new List<NetworkConnectionInfo>();

            try
            {
                int size = 0;
                GetExtendedTcpTable(null, ref size, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

                var table = new byte[size];
                var result = GetExtendedTcpTable(table, ref size, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

                if (result == 0)
                {
                    var rowCount = BitConverter.ToInt32(table, 0);
                    var offset = 4;

                    for (int i = 0; i < rowCount; i++)
                    {
                        try
                        {
                            var state = table[offset];
                            var localAddr = new byte[4];
                            Array.Copy(table, offset + 4, localAddr, 0, 4);
                            var localPort = BitConverter.ToUInt16(table, offset + 8) % 65536;
                            Array.Reverse(localAddr);

                            var remoteAddr = new byte[4];
                            Array.Copy(table, offset + 10, remoteAddr, 0, 4);
                            var remotePort = BitConverter.ToUInt16(table, offset + 14) % 65536;
                            Array.Reverse(remoteAddr);

                            var pid = BitConverter.ToInt32(table, offset + 16);

                            var conn = new NetworkConnectionInfo
                            {
                                Protocol = "TCP",
                                LocalAddress = string.Join(".", localAddr),
                                LocalPort = localPort,
                                RemoteAddress = string.Join(".", remoteAddr),
                                RemotePort = remotePort,
                                State = GetTcpStateName(state),
                                ProcessId = pid,
                                ProcessName = GetProcessName(pid)
                            };

                            connections.Add(conn);
                        }
                        catch { }

                        offset += 20; // 每行20字节
                    }
                }
            }
            catch { }

            return connections;
        }

        private List<NetworkConnectionInfo> GetExtendedUdpConnections()
        {
            var connections = new List<NetworkConnectionInfo>();

            try
            {
                int size = 0;
                GetExtendedUdpTable(null, ref size, true, AF_INET, UDP_TABLE_OWNER_PID, 0);

                var table = new byte[size];
                var result = GetExtendedUdpTable(table, ref size, true, AF_INET, UDP_TABLE_OWNER_PID, 0);

                if (result == 0)
                {
                    var rowCount = BitConverter.ToInt32(table, 0);
                    var offset = 4;

                    for (int i = 0; i < rowCount; i++)
                    {
                        try
                        {
                            var localAddr = new byte[4];
                            Array.Copy(table, offset, localAddr, 0, 4);
                            var localPort = BitConverter.ToUInt16(table, offset + 4) % 65536;
                            Array.Reverse(localAddr);

                            var pid = BitConverter.ToInt32(table, offset + 6);

                            var conn = new NetworkConnectionInfo
                            {
                                Protocol = "UDP",
                                LocalAddress = string.Join(".", localAddr),
                                LocalPort = localPort,
                                RemoteAddress = "*",
                                RemotePort = 0,
                                State = "LISTENING",
                                ProcessId = pid,
                                ProcessName = GetProcessName(pid)
                            };

                            connections.Add(conn);
                        }
                        catch { }

                        offset += 10; // 每行10字节
                    }
                }
            }
            catch { }

            return connections;
        }

        private List<NetworkConnectionInfo> GetTcpConnectionsFallback()
        {
            var connections = new List<NetworkConnectionInfo>();

            try
            {
                var properties = IPGlobalProperties.GetIPGlobalProperties();
                var tcpConnections = properties.GetActiveTcpConnections();

                foreach (var conn in tcpConnections)
                {
                    connections.Add(new NetworkConnectionInfo
                    {
                        Protocol = "TCP",
                        LocalAddress = conn.LocalEndPoint.Address.ToString(),
                        LocalPort = conn.LocalEndPoint.Port,
                        RemoteAddress = conn.RemoteEndPoint.Address.ToString(),
                        RemotePort = conn.RemoteEndPoint.Port,
                        State = conn.State.ToString(),
                        ProcessName = "Unknown",
                        ProcessId = 0
                    });
                }
            }
            catch { }

            return connections;
        }

        #endregion

        #region 私有方法 - 辅助

        private void EnrichConnectionInfo(NetworkConnectionInfo conn)
        {
            // 识别协议
            conn.IdentifiedProtocol = IdentifyProtocol(conn);

            // 评估风险
            conn.RiskLevel = GetIPRiskLevel(conn.RemoteAddress);

            // 获取进程路径
            if (conn.ProcessId > 0)
            {
                conn.ProcessPath = GetProcessPath(conn.ProcessId);
            }
        }

        private string IdentifyProtocol(NetworkConnectionInfo conn)
        {
            // 先检查已知端口
            foreach (var sig in _protocolSignatures)
            {
                if (sig.Value.Ports != null && sig.Value.Ports.Contains(conn.RemotePort))
                {
                    return sig.Key;
                }
            }

            // 默认识别
            if (conn.RemotePort == 443 || conn.RemotePort == 8443)
                return "HTTPS";
            if (conn.RemotePort == 80 || conn.RemotePort == 8080)
                return "HTTP";

            return null;
        }

        private string GetProcessName(int pid)
        {
            if (pid <= 0) return "System";

            try
            {
                var process = Process.GetProcessById(pid);
                return process.ProcessName;
            }
            catch { }

            return "Unknown";
        }

        private string GetProcessPath(int pid)
        {
            try
            {
                var process = Process.GetProcessById(pid);
                return process.MainModule?.FileName ?? "";
            }
            catch { }

            return "";
        }

        private string GetTcpStateName(byte state)
        {
            return state switch
            {
                1 => "CLOSED",
                2 => "LISTEN",
                3 => "SYN_SENT",
                4 => "SYN_RECEIVED",
                5 => "ESTABLISHED",
                6 => "FIN_WAIT_1",
                7 => "FIN_WAIT_2",
                8 => "CLOSE_WAIT",
                9 => "CLOSING",
                10 => "LAST_ACK",
                11 => "TIME_WAIT",
                12 => "DELETE_TCB",
                _ => "UNKNOWN"
            };
        }

        private bool IsPrivateIP(string ip)
        {
            if (string.IsNullOrEmpty(ip) || ip == "*" || ip == "0.0.0.0" || ip == "127.0.0.1")
                return true;

            try
            {
                var address = IPAddress.Parse(ip);
                var bytes = address.GetAddressBytes();

                if (bytes.Length != 4) return false;

                // 10.0.0.0/8
                if (bytes[0] == 10) return true;

                // 172.16.0.0/12
                if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return true;

                // 192.168.0.0/16
                if (bytes[0] == 192 && bytes[1] == 168) return true;

                // 169.254.0.0/16 (Link-local)
                if (bytes[0] == 169 && bytes[1] == 254) return true;

                return false;
            }
            catch { return false; }
        }

        private RiskLevel GetIPRiskLevel(string ip)
        {
            if (string.IsNullOrEmpty(ip) || ip == "*" || ip == "0.0.0.0")
                return RiskLevel.Low;

            if (_maliciousIPs.Contains(ip))
                return RiskLevel.Critical;

            if (IsPrivateIP(ip))
                return RiskLevel.Low;

            // 外部IP默认中等风险
            return RiskLevel.Medium;
        }

        private long ParseSpeed(string speed)
        {
            if (string.IsNullOrEmpty(speed)) return 0;
            if (long.TryParse(speed, out long value)) return value / 8;
            return 0;
        }

        private long GetAverageDownloadSpeed()
        {
            var records = _trafficHistory.ToList();
            if (records.Count < 5) return 0;
            return (long)records.Skip(records.Count - 5).Average(r => r.DownloadSpeed);
        }

        private long GetAverageUploadSpeed()
        {
            var records = _trafficHistory.ToList();
            if (records.Count < 5) return 0;
            return (long)records.Skip(records.Count - 5).Average(r => r.UploadSpeed);
        }

        private void CleanupExpiredData()
        {
            var now = DateTime.Now;

            // 清理过期威胁指示器（超过1小时）
            var expiredThreats = _threatIndicators
                .Where(kv => (now - kv.Value.Timestamp).TotalHours > 1)
                .Select(kv => kv.Key)
                .ToList();

            foreach (var key in expiredThreats)
            {
                _threatIndicators.TryRemove(key, out _);
            }
        }

        #endregion

        public void Dispose()
        {
            StopMonitoring();
        }
    }

    #region 数据模型

    public enum PortRisk
    {
        Low,
        Medium,
        High,
        Critical
    }

    public enum ProtocolRiskLevel
    {
        Normal,
        Monitor,
        Suspicious
    }

    public class NetworkTrafficRecord
    {
        public DateTime Timestamp { get; set; }
        public long DownloadSpeed { get; set; }
        public long UploadSpeed { get; set; }
        public long DownloadedBytes { get; set; }
        public long UploadedBytes { get; set; }
    }

    public class NetworkTrafficEventArgs : EventArgs
    {
        public long DownloadSpeed { get; set; }
        public long UploadSpeed { get; set; }
        public long TotalDownloaded { get; set; }
        public long TotalUploaded { get; set; }
        public int ActiveConnections { get; set; }
        public int TCPConnections { get; set; }
        public int ThreatCount { get; set; }
    }

    public class SuspiciousConnectionEventArgs : EventArgs
    {
        public NetworkConnectionInfo Connection { get; set; }
        public string Reason { get; set; }
        public ThreatSeverity Severity { get; set; }
    }

    public class TrafficThreatDetectedEventArgs : EventArgs
    {
        public TrafficThreatIndicator Threat { get; set; }
    }

    public class PortScanDetectedEventArgs : EventArgs
    {
        public string SourceIP { get; set; }
        public List<int> TargetPorts { get; set; }
        public double ScanRate { get; set; }
        public DateTime StartTime { get; set; }
    }

    public class TrafficThreatIndicator
    {
        public string Id { get; set; }
        public DateTime Timestamp { get; set; }
        public ThreatType Type { get; set; }
        public ThreatSeverity Severity { get; set; }
        public string Source { get; set; }
        public string Destination { get; set; }
        public string ProcessName { get; set; }
        public string Description { get; set; }
        public NetworkConnectionInfo Connection { get; set; }
    }

    public class ProtocolSignature
    {
        public int[] Ports { get; set; }
        public string[] Patterns { get; set; }
        public string Category { get; set; }
        public ProtocolRiskLevel RiskLevel { get; set; } = ProtocolRiskLevel.Normal;
    }

    public class KnownPortInfo
    {
        public string Service { get; set; }
        public PortRisk Risk { get; set; }
    }

    public class ApplicationTrafficStats
    {
        public string ProcessName { get; set; }
        public int ProcessId { get; set; }
        public long BytesSent { get; set; }
        public long BytesReceived { get; set; }
        public long TotalBytes => BytesSent + BytesReceived;
        public int ConnectionCount { get; set; }
        public string PrimaryProtocol { get; set; }
        public DateTime FirstSeen { get; set; }
        public DateTime LastSeen { get; set; }
    }

    public class PortScanTracker
    {
        public string SourceIP { get; set; }
        public HashSet<int> ScannedPorts { get; set; } = new HashSet<int>();
        public DateTime FirstSeen { get; set; }
        public DateTime LastSeen { get; set; }
        public int ConnectionCount { get; set; }
        public double ScanRate { get; set; }
        public bool IsPortScan { get; set; }
        public bool Alerted { get; set; }
    }

    public class CCConnectionTracker
    {
        public string DestinationIP { get; set; }
        public int DestinationPort { get; set; }
        public string ProcessName { get; set; }
        public DateTime FirstSeen { get; set; }
        public DateTime LastSeen { get; set; }
        public int ConnectionCount { get; set; }
        public long TotalBytes { get; set; }
        public int Confidence { get; set; }
        public bool IsLikelyCC { get; set; }
        public List<string> Indicators { get; set; } = new List<string>();
    }

    public class NetworkTrafficAnalysis
    {
        public DateTime GeneratedAt { get; set; }
        public Dictionary<string, int> ProtocolDistribution { get; set; } = new Dictionary<string, int>();
        public List<ApplicationTrafficInfo> TopApplications { get; set; } = new List<ApplicationTrafficInfo>();
        public List<DestinationInfo> TopDestinations { get; set; } = new List<DestinationInfo>();
        public int ExternalConnections { get; set; }
        public ThreatStatistics ThreatStats { get; set; }
    }

    public class ApplicationTrafficInfo
    {
        public string ProcessName { get; set; }
        public long BytesSent { get; set; }
        public long BytesReceived { get; set; }
        public int Connections { get; set; }
        public string Protocol { get; set; }
    }

    public class DestinationInfo
    {
        public string IPAddress { get; set; }
        public int ConnectionCount { get; set; }
        public List<int> Ports { get; set; } = new List<int>();
        public RiskLevel RiskLevel { get; set; }
    }

    public class ThreatStatistics
    {
        public int TotalThreats { get; set; }
        public int CriticalThreats { get; set; }
        public int HighThreats { get; set; }
        public int MediumThreats { get; set; }
        public int LowThreats { get; set; }
    }

    public class PortScanAnalysis
    {
        public DateTime GeneratedAt { get; set; }
        public List<PortScanInfo> DetectedScans { get; set; } = new List<PortScanInfo>();
    }

    public class PortScanInfo
    {
        public string SourceIP { get; set; }
        public List<int> TargetPorts { get; set; }
        public DateTime StartTime { get; set; }
        public TimeSpan Duration { get; set; }
        public double ScanRate { get; set; }
        public bool IsOngoing { get; set; }
    }

    public class CCDetectionResult
    {
        public string DestinationIP { get; set; }
        public int DestinationPort { get; set; }
        public string ProcessName { get; set; }
        public int Confidence { get; set; }
        public List<string> Indicators { get; set; } = new List<string>();
        public DateTime FirstSeen { get; set; }
        public DateTime LastSeen { get; set; }
        public int ConnectionCount { get; set; }
        public long TotalBytes { get; set; }
    }

    public class NetworkSpeedTestResult
    {
        public long Latency { get; set; }
        public int PacketLoss { get; set; }
        public long DNSResolutionTime { get; set; }
        public long DownloadSpeed { get; set; }
        public long UploadSpeed { get; set; }
        public int ActiveConnections { get; set; }
        public string Error { get; set; }
    }

    #endregion
}
