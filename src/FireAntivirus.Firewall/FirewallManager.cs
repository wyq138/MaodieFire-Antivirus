// 耄耋软件工作室 开发，严禁非法反编译
// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using FireAntivirus.Common;

namespace FireAntivirus.Firewall
{
    #region Native P/Invoke (IP Helper API)

    /// <summary>
    /// Windows IP Helper API 的 P/Invoke 封装，用于枚举活动 TCP/UDP 连接及终止 TCP 连接
    /// </summary>
    internal static class NativeMethods
    {
        public const int AF_INET = 2;
        public const int AF_INET6 = 23;

        public const int TCP_TABLE_OWNER_PID_LISTENER = 3;
        public const int TCP_TABLE_OWNER_PID_CONNECTIONS = 4;
        public const int TCP_TABLE_OWNER_PID_ALL = 5;

        public const int UDP_TABLE_OWNER_PID = 2;

        public const int MIB_TCP_STATE_CLOSED = 1;
        public const int MIB_TCP_STATE_LISTEN = 2;
        public const int MIB_TCP_STATE_SYN_SENT = 3;
        public const int MIB_TCP_STATE_SYN_RCVD = 4;
        public const int MIB_TCP_STATE_ESTAB = 5;
        public const int MIB_TCP_STATE_FIN_WAIT1 = 6;
        public const int MIB_TCP_STATE_FIN_WAIT2 = 7;
        public const int MIB_TCP_STATE_CLOSE_WAIT = 8;
        public const int MIB_TCP_STATE_CLOSING = 9;
        public const int MIB_TCP_STATE_LAST_ACK = 10;
        public const int MIB_TCP_STATE_TIME_WAIT = 11;
        public const int MIB_TCP_STATE_DELETE_TCB = 12;

        public const uint NO_ERROR = 0;
        public const uint ERROR_INSUFFICIENT_BUFFER = 122;

        /// <summary>
        /// 获取包含 PID 信息的扩展 TCP 连接表
        /// </summary>
        [DllImport("iphlpapi.dll", SetLastError = true)]
        public static extern uint GetExtendedTcpTable(
            IntPtr pTcpTable,
            ref int pdwSize,
            bool bOrder,
            int ulAf,
            int TableClass,
            int Reserved);

        /// <summary>
        /// 获取包含 PID 信息的扩展 UDP 监听表
        /// </summary>
        [DllImport("iphlpapi.dll", SetLastError = true)]
        public static extern uint GetExtendedUdpTable(
            IntPtr pUdpTable,
            ref int pdwSize,
            bool bOrder,
            int ulAf,
            int TableClass,
            int Reserved);

        /// <summary>
        /// 设置 TCP 连接行的状态，可用于终止 TCP 连接（设置状态为 DELETE_TCB）
        /// </summary>
        [DllImport("iphlpapi.dll", SetLastError = true)]
        public static extern uint SetTcpEntry(ref MIB_TCPROW pTcpRow);

        /// <summary>
        /// 包含 PID 的 TCP 连接行
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_TCPROW_OWNER_PID
        {
            public uint dwState;
            public uint dwLocalAddr;
            public uint dwLocalPort;
            public uint dwRemoteAddr;
            public uint dwRemotePort;
            public uint dwOwningPid;
        }

        /// <summary>
        /// 包含 PID 的 TCP 连接表
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_TCPTABLE_OWNER_PID
        {
            public uint dwNumEntries;
            public MIB_TCPROW_OWNER_PID table;
        }

        /// <summary>
        /// 包含 PID 的 UDP 监听行
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_UDPROW_OWNER_PID
        {
            public uint dwLocalAddr;
            public uint dwLocalPort;
            public uint dwOwningPid;
        }

        /// <summary>
        /// 包含 PID 的 UDP 监听表
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_UDPTABLE_OWNER_PID
        {
            public uint dwNumEntries;
            public MIB_UDPROW_OWNER_PID table;
        }

        /// <summary>
        /// 用于 SetTcpEntry 的 TCP 连接行（不含 PID）
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_TCPROW
        {
            public uint dwState;
            public uint dwLocalAddr;
            public uint dwLocalPort;
            public uint dwRemoteAddr;
            public uint dwRemotePort;
        }
    }

    #endregion

    #region Enums

    /// <summary>
    /// 防火墙动作类型
    /// </summary>
    public enum FirewallAction
    {
        Allow,
        Block
    }

    /// <summary>
    /// 防火墙规则协议
    /// </summary>
    public enum FirewallProtocol
    {
        Any,
        TCP,
        UDP
    }

    /// <summary>
    /// 防火墙规则方向
    /// </summary>
    public enum FirewallDirection
    {
        Inbound,
        Outbound,
        Both
    }

    /// <summary>
    /// TCP 连接状态（对应 MIB_TCP_STATE）
    /// </summary>
    public enum TcpConnectionState
    {
        Closed = 1,
        Listen = 2,
        SynSent = 3,
        SynReceived = 4,
        Established = 5,
        FinWait1 = 6,
        FinWait2 = 7,
        CloseWait = 8,
        Closing = 9,
        LastAck = 10,
        TimeWait = 11,
        DeleteTcb = 12
    }

    #endregion

    #region Data Classes

    /// <summary>
    /// 防火墙规则定义
    /// </summary>
    public class FirewallRule
    {
        public string Name { get; set; }
        public string IpAddress { get; set; }
        public int Port { get; set; }
        public FirewallAction Action { get; set; }
        public string Description { get; set; }

        public FirewallProtocol Protocol { get; set; } = FirewallProtocol.Any;
        public FirewallDirection Direction { get; set; } = FirewallDirection.Inbound;
        public string ApplicationPath { get; set; }
        public bool IsSystemRule { get; set; }
        public DateTime CreatedTime { get; set; } = DateTime.Now;

        /// <summary>
        /// 检查规则是否匹配给定 IP 和端口
        /// </summary>
        public bool Matches(string ipAddress, int port)
        {
            bool ipMatch = string.IsNullOrEmpty(IpAddress) || IpAddress == "*" || IpAddress == ipAddress;
            bool portMatch = Port == 0 || Port == port;
            return ipMatch && portMatch;
        }

        /// <summary>
        /// 检查规则是否匹配连接信息
        /// </summary>
        public bool Matches(ConnectionInfo connection)
        {
            bool actionMatch = Action == FirewallAction.Block;
            bool ipMatch = string.IsNullOrEmpty(IpAddress) || IpAddress == "*" ||
                           IpAddress.Equals(connection.RemoteAddress, StringComparison.OrdinalIgnoreCase);
            bool portMatch = Port == 0 || Port == connection.RemotePort;
            bool protoMatch = Protocol == FirewallProtocol.Any ||
                              (Protocol == FirewallProtocol.TCP && connection.Protocol == "TCP") ||
                              (Protocol == FirewallProtocol.UDP && connection.Protocol == "UDP");
            return actionMatch && ipMatch && portMatch && protoMatch;
        }
    }

    /// <summary>
    /// 活动网络连接信息
    /// </summary>
    public class ConnectionInfo
    {
        public string Protocol { get; set; }
        public string LocalAddress { get; set; }
        public int LocalPort { get; set; }
        public string RemoteAddress { get; set; }
        public int RemotePort { get; set; }
        public TcpConnectionState State { get; set; }
        public int ProcessId { get; set; }
        public string ProcessName { get; set; }
        public DateTime DetectedTime { get; set; }

        /// <summary>原始本地地址（网络字节序），用于 SetTcpEntry</summary>
        internal uint RawLocalAddr { get; set; }
        /// <summary>原始本地端口（网络字节序），用于 SetTcpEntry</summary>
        internal uint RawLocalPort { get; set; }
        /// <summary>原始远程地址（网络字节序），用于 SetTcpEntry</summary>
        internal uint RawRemoteAddr { get; set; }
        /// <summary>原始远程端口（网络字节序），用于 SetTcpEntry</summary>
        internal uint RawRemotePort { get; set; }

        public long BytesSent { get; set; }
        public long BytesReceived { get; set; }

        public bool IsLoopback
        {
            get
            {
                return RemoteAddress == "127.0.0.1" || RemoteAddress == "::1" ||
                       LocalAddress == "127.0.0.1" || LocalAddress == "::1";
            }
        }

        public override string ToString()
        {
            return $"{Protocol} {LocalAddress}:{LocalPort} -> {RemoteAddress}:{RemotePort} [{State}] PID:{ProcessId} ({ProcessName})";
        }
    }

    /// <summary>
    /// DNS 缓存条目
    /// </summary>
    public class DnsCacheEntry
    {
        public string Domain { get; set; }
        public string IpAddress { get; set; }
        public string RecordType { get; set; }
        public int TimeToLive { get; set; }
        public bool IsMalicious { get; set; }
        public string ThreatReason { get; set; }
    }

    /// <summary>
    /// 网络统计信息
    /// </summary>
    public class NetworkStatistics
    {
        public long TotalBytesSent { get; set; }
        public long TotalBytesReceived { get; set; }
        public long TotalConnections { get; set; }
        public long BlockedConnections { get; set; }
        public long KilledConnections { get; set; }
        public long PortScansDetected { get; set; }
        public long DnsThreatsDetected { get; set; }
        public long RulesApplied { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime LastUpdate { get; set; }

        public TimeSpan Uptime => LastUpdate - StartTime;
    }

    /// <summary>
    /// 防火墙阻止事件参数
    /// </summary>
    public class FirewallBlockEventArgs : EventArgs
    {
        public string IpAddress { get; set; }
        public int Port { get; set; }
        public string RuleName { get; set; }
        public DateTime Timestamp { get; set; }
        public string Protocol { get; set; }
        public string ProcessName { get; set; }
        public int ProcessId { get; set; }
        public string LocalAddress { get; set; }
        public int LocalPort { get; set; }
        public string BlockReason { get; set; }
        public bool ConnectionKilled { get; set; }
    }

    /// <summary>
    /// 端口扫描检测事件参数
    /// </summary>
    public class PortScanEventArgs : EventArgs
    {
        public string ScannerIp { get; set; }
        public List<int> ScannedPorts { get; set; } = new List<int>();
        public int PortCount { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public TimeSpan Duration => EndTime - StartTime;
        public string Description { get; set; }
    }

    #endregion

    #region Port Scan Detector

    /// <summary>
    /// 端口扫描检测器 - 跟踪同一 IP 在时间窗口内对连续端口的连接尝试
    /// </summary>
    public class PortScanDetector
    {
        private readonly ConcurrentDictionary<string, List<PortScanAttempt>> _attemptsByIp;
        private readonly TimeSpan _timeWindow;
        private readonly int _threshold;
        private readonly int _sequentialThreshold;

        public event EventHandler<PortScanEventArgs> PortScanDetected;

        public PortScanDetector(TimeSpan? timeWindow = null, int threshold = 10, int sequentialThreshold = 5)
        {
            _attemptsByIp = new ConcurrentDictionary<string, List<PortScanAttempt>>();
            _timeWindow = timeWindow ?? TimeSpan.FromSeconds(30);
            _threshold = threshold;
            _sequentialThreshold = sequentialThreshold;
        }

        /// <summary>
        /// 记录一次连接尝试并检测是否为端口扫描
        /// </summary>
        public bool RecordAttempt(string remoteIp, int port)
        {
            if (string.IsNullOrEmpty(remoteIp) || remoteIp == "127.0.0.1" || remoteIp == "::1")
                return false;

            var attempt = new PortScanAttempt
            {
                RemoteIp = remoteIp,
                Port = port,
                Timestamp = DateTime.Now
            };

            var attempts = _attemptsByIp.GetOrAdd(remoteIp, _ => new List<PortScanAttempt>());

            lock (attempts)
            {
                attempts.Add(attempt);
                var cutoff = DateTime.Now - _timeWindow;
                attempts.RemoveAll(a => a.Timestamp < cutoff);

                if (attempts.Count >= _threshold)
                {
                    var ports = attempts.Select(a => a.Port).Distinct().ToList();
                    var sortedPorts = ports.OrderBy(p => p).ToList();
                    int sequentialCount = CountSequentialPorts(sortedPorts);

                    if (ports.Count >= _threshold || sequentialCount >= _sequentialThreshold)
                    {
                        var args = new PortScanEventArgs
                        {
                            ScannerIp = remoteIp,
                            ScannedPorts = sortedPorts,
                            PortCount = ports.Count,
                            StartTime = attempts.First().Timestamp,
                            EndTime = DateTime.Now,
                            Description = $"检测到端口扫描: {remoteIp} 在 {_timeWindow.TotalSeconds:F0} 秒内尝试连接 {ports.Count} 个不同端口" +
                                         (sequentialCount >= _sequentialThreshold ? $"，其中 {sequentialCount} 个为连续端口" : "")
                        };
                        PortScanDetected?.Invoke(this, args);
                        attempts.Clear();
                        return true;
                    }
                }
            }

            return false;
        }

        /// <summary>
        /// 计算连续端口数量
        /// </summary>
        private int CountSequentialPorts(List<int> sortedPorts)
        {
            if (sortedPorts.Count < 2)
                return sortedPorts.Count;

            int maxSequential = 1;
            int currentSequential = 1;

            for (int i = 1; i < sortedPorts.Count; i++)
            {
                if (sortedPorts[i] == sortedPorts[i - 1] + 1)
                {
                    currentSequential++;
                    maxSequential = Math.Max(maxSequential, currentSequential);
                }
                else
                {
                    currentSequential = 1;
                }
            }

            return maxSequential;
        }

        /// <summary>
        /// 清除所有记录
        /// </summary>
        public void Clear()
        {
            _attemptsByIp.Clear();
        }

        /// <summary>
        /// 清除指定 IP 的记录
        /// </summary>
        public void Clear(string remoteIp)
        {
            _attemptsByIp.TryRemove(remoteIp, out _);
        }

        /// <summary>
        /// 获取当前跟踪的所有 IP 及其尝试次数
        /// </summary>
        public Dictionary<string, int> GetTrackedIps()
        {
            var result = new Dictionary<string, int>();
            foreach (var kvp in _attemptsByIp)
            {
                lock (kvp.Value)
                {
                    result[kvp.Key] = kvp.Value.Count;
                }
            }
            return result;
        }

        private class PortScanAttempt
        {
            public string RemoteIp { get; set; }
            public int Port { get; set; }
            public DateTime Timestamp { get; set; }
        }
    }

    #endregion

    /// <summary>
    /// 防火墙管理器 - 集成 Windows 防火墙 API、实时连接监控、端口扫描检测、
    /// IP 信誉检查、应用网络控制、DNS 缓存监控、连接终止和规则持久化
    /// </summary>
    public class FirewallManager
    {
        private readonly object _lock = new object();
        private bool _isEnabled;
        private CancellationTokenSource _cancellationTokenSource;
        private readonly ConcurrentDictionary<string, FirewallRule> _rules;
        private readonly HashSet<string> _blockedIps;
        private readonly HashSet<string> _blockedApplications;
        private readonly HashSet<string> _maliciousDomains;
        private readonly PortScanDetector _portScanDetector;
        private NetworkStatistics _statistics;
        private readonly string _rulesFilePath;
        private readonly string _logTag = "FirewallManager";
        private DataManager _dataManager;
        private int _monitorInterval = 2000;
        private bool _autoBlockEnabled = true;
        private bool _portScanDetectionEnabled = true;
        private bool _dnsMonitoringEnabled = true;

        public event EventHandler<FirewallBlockEventArgs> Blocked;
        public event EventHandler<PortScanEventArgs> PortScanDetected;
        public event EventHandler<FirewallBlockEventArgs> SuspiciousConnection;
        public event EventHandler<FirewallBlockEventArgs> DnsThreatDetected;

        public bool IsEnabled => _isEnabled;
        public int RuleCount => _rules.Count;
        public int BlockedIpCount => _blockedIps.Count;
        public int BlockedApplicationCount => _blockedApplications.Count;
        public NetworkStatistics Statistics => _statistics;

        public FirewallManager()
        {
            _rules = new ConcurrentDictionary<string, FirewallRule>();
            _blockedIps = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _blockedApplications = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _maliciousDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _portScanDetector = new PortScanDetector();
            _portScanDetector.PortScanDetected += OnPortScanDetected;
            _statistics = new NetworkStatistics { StartTime = DateTime.Now, LastUpdate = DateTime.Now };

            _rulesFilePath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "FireAntivirus", "firewall_rules.json");

            InitializeDefaultRules();
            LoadRules();
            LoadBlocklist();
            LoadMaliciousDomains();
        }

        public FirewallManager(DataManager dataManager) : this()
        {
            _dataManager = dataManager;
        }

        #region Enable / Disable

        /// <summary>
        /// 启用防火墙监控
        /// </summary>
        public void Enable()
        {
            lock (_lock)
            {
                if (_isEnabled)
                    return;

                _isEnabled = true;
                _cancellationTokenSource = new CancellationTokenSource();

                EnsureFirewallServiceRunning();

                Task.Run(() => MonitorNetwork(_cancellationTokenSource.Token),
                         _cancellationTokenSource.Token);

                Log("防火墙已启用，开始监控网络连接");
            }
        }

        /// <summary>
        /// 禁用防火墙监控
        /// </summary>
        public void Disable()
        {
            lock (_lock)
            {
                if (!_isEnabled)
                    return;

                _cancellationTokenSource?.Cancel();
                _isEnabled = false;

                Log("防火墙已禁用，停止监控网络连接");
            }
        }

        #endregion

        #region Rule Management

        /// <summary>
        /// 添加防火墙规则
        /// </summary>
        public void AddRule(FirewallRule rule)
        {
            if (rule == null || string.IsNullOrEmpty(rule.Name))
                return;

            _rules[rule.Name] = rule;
            SaveRules();
            Log($"添加防火墙规则: {rule.Name}");
        }

        /// <summary>
        /// 删除防火墙规则
        /// </summary>
        public void RemoveRule(FirewallRule rule)
        {
            if (rule == null)
                return;

            _rules.TryRemove(rule.Name, out _);
            SaveRules();
            Log($"删除防火墙规则: {rule.Name}");
        }

        /// <summary>
        /// 删除指定名称的防火墙规则
        /// </summary>
        public bool RemoveRule(string ruleName)
        {
            bool removed = _rules.TryRemove(ruleName, out _);
            if (removed)
            {
                SaveRules();
                Log($"删除防火墙规则: {ruleName}");
            }
            return removed;
        }

        /// <summary>
        /// 清除所有防火墙规则
        /// </summary>
        public void ClearRules()
        {
            _rules.Clear();
            InitializeDefaultRules();
            SaveRules();
            Log("清除所有防火墙规则，恢复默认规则");
        }

        /// <summary>
        /// 获取所有防火墙规则
        /// </summary>
        public List<FirewallRule> GetRules()
        {
            return _rules.Values.ToList();
        }

        /// <summary>
        /// 检查连接是否应该被阻止
        /// </summary>
        public bool ShouldBlockConnection(string ipAddress, int port)
        {
            foreach (var rule in _rules.Values)
            {
                if (rule.Matches(ipAddress, port))
                {
                    return rule.Action == FirewallAction.Block;
                }
            }
            return false;
        }

        /// <summary>
        /// 初始化默认防火墙规则
        /// </summary>
        private void InitializeDefaultRules()
        {
            var defaults = new[]
            {
                new FirewallRule { Name = "Block Known Malicious IPs", IpAddress = "192.168.1.100", Port = 0, Action = FirewallAction.Block, Description = "阻止已知恶意IP", IsSystemRule = true },
                new FirewallRule { Name = "Allow Localhost", IpAddress = "127.0.0.1", Port = 0, Action = FirewallAction.Allow, Description = "允许本地回环", IsSystemRule = true },
                new FirewallRule { Name = "Block Common Malware Ports", IpAddress = "*", Port = 4444, Action = FirewallAction.Block, Protocol = FirewallProtocol.TCP, Description = "阻止恶意软件常用端口4444", IsSystemRule = true },
                new FirewallRule { Name = "Block Remote Desktop", IpAddress = "*", Port = 3389, Action = FirewallAction.Block, Protocol = FirewallProtocol.TCP, Description = "阻止远程桌面", IsSystemRule = true },
                new FirewallRule { Name = "Block SQL Server", IpAddress = "*", Port = 1433, Action = FirewallAction.Block, Protocol = FirewallProtocol.TCP, Description = "阻止SQL Server端口", IsSystemRule = true },
                new FirewallRule { Name = "Block Telnet", IpAddress = "*", Port = 23, Action = FirewallAction.Block, Protocol = FirewallProtocol.TCP, Description = "阻止Telnet端口", IsSystemRule = true },
                new FirewallRule { Name = "Block Back Orifice", IpAddress = "*", Port = 31337, Action = FirewallAction.Block, Protocol = FirewallProtocol.UDP, Description = "阻止Back Orifice后门端口", IsSystemRule = true }
            };

            foreach (var rule in defaults)
            {
                _rules[rule.Name] = rule;
            }
        }

        #endregion

        #region Windows Firewall API Integration (netsh.exe)

        /// <summary>
        /// 通过 netsh.exe 创建 Windows 防火墙规则
        /// </summary>
        public bool CreateWindowsFirewallRule(string name, string direction, string action,
            string protocol = null, string localPort = null, string remoteIp = null,
            string program = null, string description = null)
        {
            var sb = new StringBuilder();
            sb.Append($"advfirewall firewall add rule name=\"{name}\"");
            sb.Append($" dir={direction}");
            sb.Append($" action={action}");

            if (!string.IsNullOrEmpty(protocol))
                sb.Append($" protocol={protocol}");
            if (!string.IsNullOrEmpty(localPort))
                sb.Append($" localport={localPort}");
            if (!string.IsNullOrEmpty(remoteIp))
                sb.Append($" remoteip={remoteIp}");
            if (!string.IsNullOrEmpty(program))
                sb.Append($" program=\"{program}\"");
            if (!string.IsNullOrEmpty(description))
                sb.Append($" description=\"{description}\"");

            string output = RunNetsh(sb.ToString());
            bool success = output.Contains("OK") || output.Contains("确定");

            if (success)
                Log($"创建Windows防火墙规则成功: {name}");
            else
                Log($"创建Windows防火墙规则失败: {name} - {output}");

            return success;
        }

        /// <summary>
        /// 通过 netsh.exe 删除 Windows 防火墙规则
        /// </summary>
        public bool DeleteWindowsFirewallRule(string name)
        {
            string output = RunNetsh($"advfirewall firewall delete rule name=\"{name}\"");
            bool success = output.Contains("OK") || output.Contains("删除") || output.Contains("deleted");

            if (success)
                Log($"删除Windows防火墙规则成功: {name}");
            else
                Log($"删除Windows防火墙规则失败: {name} - {output}");

            return success;
        }

        /// <summary>
        /// 阻止指定 IP 地址的所有入站连接
        /// </summary>
        public bool BlockIp(string ipAddress)
        {
            if (string.IsNullOrEmpty(ipAddress))
                return false;

            _blockedIps.Add(ipAddress);

            string ruleName = $"FireAntivirus_Block_IP_{ipAddress.Replace('.', '_')}";
            bool success = CreateWindowsFirewallRule(
                ruleName, "in", "block", remoteIp: ipAddress,
                description: $"FireAntivirus blocked IP: {ipAddress}");

            if (success)
            {
                Interlocked.Increment(ref _statistics.RulesApplied);
                Log($"阻止IP地址: {ipAddress}");
            }

            return success;
        }

        /// <summary>
        /// 允许指定 IP 地址的连接（移除阻止规则）
        /// </summary>
        public bool AllowIp(string ipAddress)
        {
            if (string.IsNullOrEmpty(ipAddress))
                return false;

            _blockedIps.Remove(ipAddress);

            string ruleName = $"FireAntivirus_Block_IP_{ipAddress.Replace('.', '_')}";
            bool success = DeleteWindowsFirewallRule(ruleName);

            if (success)
                Log($"允许IP地址: {ipAddress}");

            return success;
        }

        /// <summary>
        /// 阻止指定端口
        /// </summary>
        public bool BlockPort(int port, FirewallProtocol protocol = FirewallProtocol.TCP)
        {
            string protoStr = protocol == FirewallProtocol.UDP ? "UDP" : "TCP";
            string ruleName = $"FireAntivirus_Block_Port_{protoStr}_{port}";

            bool success = CreateWindowsFirewallRule(
                ruleName, "in", "block", protocol: protoStr, localPort: port.ToString(),
                description: $"FireAntivirus blocked port: {protoStr}/{port}");

            if (success)
            {
                var rule = new FirewallRule
                {
                    Name = ruleName,
                    IpAddress = "*",
                    Port = port,
                    Action = FirewallAction.Block,
                    Protocol = protocol,
                    Direction = FirewallDirection.Inbound,
                    Description = $"阻止端口 {protoStr}/{port}",
                    IsSystemRule = false
                };
                _rules[ruleName] = rule;
                SaveRules();
                Log($"阻止端口: {protoStr}/{port}");
            }

            return success;
        }

        /// <summary>
        /// 阻止指定应用程序访问网络
        /// </summary>
        public bool BlockApplication(string applicationPath)
        {
            if (string.IsNullOrEmpty(applicationPath) || !File.Exists(applicationPath))
            {
                Log($"应用程序路径无效: {applicationPath}");
                return false;
            }

            _blockedApplications.Add(applicationPath);

            string fileName = Path.GetFileNameWithoutExtension(applicationPath);
            string ruleName = $"FireAntivirus_Block_App_{fileName}";

            bool success = CreateWindowsFirewallRule(
                ruleName, "out", "block", program: applicationPath,
                description: $"FireAntivirus blocked application: {applicationPath}");

            if (success)
            {
                // 同时阻止入站
                CreateWindowsFirewallRule(
                    ruleName + "_In", "in", "block", program: applicationPath,
                    description: $"FireAntivirus blocked application (inbound): {applicationPath}");

                Log($"阻止应用程序访问网络: {applicationPath}");
            }

            return success;
        }

        /// <summary>
        /// 允许指定应用程序访问网络
        /// </summary>
        public bool UnblockApplication(string applicationPath)
        {
            if (string.IsNullOrEmpty(applicationPath))
                return false;

            _blockedApplications.Remove(applicationPath);

            string fileName = Path.GetFileNameWithoutExtension(applicationPath);
            string ruleName = $"FireAntivirus_Block_App_{fileName}";

            DeleteWindowsFirewallRule(ruleName);
            DeleteWindowsFirewallRule(ruleName + "_In");

            Log($"允许应用程序访问网络: {applicationPath}");
            return true;
        }

        /// <summary>
        /// 检查应用程序是否被阻止
        /// </summary>
        public bool IsApplicationBlocked(string applicationPath)
        {
            return _blockedApplications.Contains(applicationPath);
        }

        /// <summary>
        /// 获取所有通过 netsh 创建的 Windows 防火墙规则
        /// </summary>
        public List<string> GetWindowsFirewallRules()
        {
            var rules = new List<string>();
            string output = RunNetsh("advfirewall firewall show rule name=all");

            var lines = output.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
            foreach (var line in lines)
            {
                if (line.StartsWith("规则名称", StringComparison.OrdinalIgnoreCase) ||
                    line.StartsWith("Rule Name", StringComparison.OrdinalIgnoreCase))
                {
                    var parts = line.Split(new[] { ':' }, 2);
                    if (parts.Length >= 2)
                        rules.Add(parts[1].Trim());
                }
            }

            return rules;
        }

        /// <summary>
        /// 启用 Windows 防火墙（所有网络配置文件）
        /// </summary>
        public bool EnableWindowsFirewall()
        {
            string output = RunNetsh("advfirewall set allprofiles state on");
            bool success = output.Contains("OK") || output.Contains("确定");
            Log(success ? "Windows防火墙已启用" : "启用Windows防火墙失败");
            return success;
        }

        /// <summary>
        /// 禁用 Windows 防火墙（所有网络配置文件）
        /// </summary>
        public bool DisableWindowsFirewall()
        {
            string output = RunNetsh("advfirewall set allprofiles state off");
            bool success = output.Contains("OK") || output.Contains("确定");
            Log(success ? "Windows防火墙已禁用" : "禁用Windows防火墙失败");
            return success;
        }

        #endregion

        #region Connection Monitoring (P/Invoke)

        /// <summary>
        /// 获取所有活动 TCP 连接（通过 GetExtendedTcpTable）
        /// </summary>
        public List<ConnectionInfo> GetActiveTcpConnections()
        {
            var connections = new List<ConnectionInfo>();

            int size = 0;
            uint result = NativeMethods.GetExtendedTcpTable(
                IntPtr.Zero, ref size, false,
                NativeMethods.AF_INET,
                NativeMethods.TCP_TABLE_OWNER_PID_ALL, 0);

            if (result != NativeMethods.ERROR_INSUFFICIENT_BUFFER && result != NativeMethods.NO_ERROR)
                return connections;

            if (size == 0)
                return connections;

            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                result = NativeMethods.GetExtendedTcpTable(
                    buffer, ref size, false,
                    NativeMethods.AF_INET,
                    NativeMethods.TCP_TABLE_OWNER_PID_ALL, 0);

                if (result != NativeMethods.NO_ERROR)
                    return connections;

                int numEntries = Marshal.ReadInt32(buffer);
                int rowSize = Marshal.SizeOf<NativeMethods.MIB_TCPROW_OWNER_PID>();

                for (int i = 0; i < numEntries; i++)
                {
                    IntPtr rowPtr = (IntPtr)(buffer.ToInt64() + 4 + (i * rowSize));
                    var row = Marshal.PtrToStructure<NativeMethods.MIB_TCPROW_OWNER_PID>(rowPtr);

                    var conn = new ConnectionInfo
                    {
                        Protocol = "TCP",
                        LocalAddress = GetIpAddress(row.dwLocalAddr),
                        LocalPort = GetPort(row.dwLocalPort),
                        RemoteAddress = GetIpAddress(row.dwRemoteAddr),
                        RemotePort = GetPort(row.dwRemotePort),
                        State = (TcpConnectionState)row.dwState,
                        ProcessId = (int)row.dwOwningPid,
                        DetectedTime = DateTime.Now,
                        RawLocalAddr = row.dwLocalAddr,
                        RawLocalPort = row.dwLocalPort,
                        RawRemoteAddr = row.dwRemoteAddr,
                        RawRemotePort = row.dwRemotePort
                    };

                    conn.ProcessName = GetProcessName(conn.ProcessId);
                    connections.Add(conn);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }

            return connections;
        }

        /// <summary>
        /// 获取所有活动 UDP 连接（通过 GetExtendedUdpTable）
        /// </summary>
        public List<ConnectionInfo> GetActiveUdpConnections()
        {
            var connections = new List<ConnectionInfo>();

            int size = 0;
            uint result = NativeMethods.GetExtendedUdpTable(
                IntPtr.Zero, ref size, false,
                NativeMethods.AF_INET,
                NativeMethods.UDP_TABLE_OWNER_PID, 0);

            if (result != NativeMethods.ERROR_INSUFFICIENT_BUFFER && result != NativeMethods.NO_ERROR)
                return connections;

            if (size == 0)
                return connections;

            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                result = NativeMethods.GetExtendedUdpTable(
                    buffer, ref size, false,
                    NativeMethods.AF_INET,
                    NativeMethods.UDP_TABLE_OWNER_PID, 0);

                if (result != NativeMethods.NO_ERROR)
                    return connections;

                int numEntries = Marshal.ReadInt32(buffer);
                int rowSize = Marshal.SizeOf<NativeMethods.MIB_UDPROW_OWNER_PID>();

                for (int i = 0; i < numEntries; i++)
                {
                    IntPtr rowPtr = (IntPtr)(buffer.ToInt64() + 4 + (i * rowSize));
                    var row = Marshal.PtrToStructure<NativeMethods.MIB_UDPROW_OWNER_PID>(rowPtr);

                    var conn = new ConnectionInfo
                    {
                        Protocol = "UDP",
                        LocalAddress = GetIpAddress(row.dwLocalAddr),
                        LocalPort = GetPort(row.dwLocalPort),
                        RemoteAddress = "*",
                        RemotePort = 0,
                        State = TcpConnectionState.Listen,
                        ProcessId = (int)row.dwOwningPid,
                        DetectedTime = DateTime.Now,
                        RawLocalAddr = row.dwLocalAddr,
                        RawLocalPort = row.dwLocalPort
                    };

                    conn.ProcessName = GetProcessName(conn.ProcessId);
                    connections.Add(conn);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }

            return connections;
        }

        /// <summary>
        /// 获取所有活动网络连接（TCP + UDP）
        /// </summary>
        public List<ConnectionInfo> GetAllActiveConnections()
        {
            var connections = new List<ConnectionInfo>();
            connections.AddRange(GetActiveTcpConnections());
            connections.AddRange(GetActiveUdpConnections());

            UpdateNetworkStatistics(connections.Count);

            return connections;
        }

        /// <summary>
        /// 网络连接监控循环 - 周期性扫描活动连接并检查阻止规则
        /// </summary>
        private async Task MonitorNetwork(CancellationToken cancellationToken)
        {
            Log("网络连接监控循环已启动");

            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    var connections = GetAllActiveConnections();
                    ScanConnections(connections);

                    if (_dnsMonitoringEnabled)
                    {
                        CheckDnsCache();
                    }

                    _statistics.LastUpdate = DateTime.Now;

                    await Task.Delay(_monitorInterval, cancellationToken);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    Log($"监控网络连接时出错: {ex.Message}");
                    try
                    {
                        await Task.Delay(5000, cancellationToken);
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                }
            }

            Log("网络连接监控循环已停止");
        }

        /// <summary>
        /// 扫描活动连接，检查阻止规则并执行相应动作
        /// </summary>
        public void ScanConnections(List<ConnectionInfo> connections)
        {
            foreach (var conn in connections)
            {
                if (conn.IsLoopback)
                    continue;

                if (conn.State == TcpConnectionState.Established ||
                    conn.State == TcpConnectionState.SynSent ||
                    conn.State == TcpConnectionState.SynReceived)
                {
                    bool shouldBlock = false;
                    string blockReason = null;
                    string ruleName = null;

                    if (IsIpBlocked(conn.RemoteAddress))
                    {
                        shouldBlock = true;
                        blockReason = "IP在黑名单中";
                        ruleName = "IP Blocklist";
                    }

                    if (!shouldBlock)
                    {
                        foreach (var rule in _rules.Values)
                        {
                            if (rule.Matches(conn))
                            {
                                shouldBlock = true;
                                blockReason = $"匹配规则: {rule.Name}";
                                ruleName = rule.Name;
                                break;
                            }
                        }
                    }

                    if (!shouldBlock && _portScanDetectionEnabled && conn.Protocol == "TCP")
                    {
                        bool scanDetected = _portScanDetector.RecordAttempt(
                            conn.RemoteAddress, conn.RemotePort);

                        if (scanDetected)
                        {
                            shouldBlock = _autoBlockEnabled;
                            blockReason = "检测到端口扫描行为";
                            ruleName = "PortScanDetection";
                        }
                    }

                    if (shouldBlock)
                    {
                        var args = new FirewallBlockEventArgs
                        {
                            IpAddress = conn.RemoteAddress,
                            Port = conn.RemotePort,
                            RuleName = ruleName,
                            Timestamp = DateTime.Now,
                            Protocol = conn.Protocol,
                            ProcessName = conn.ProcessName,
                            ProcessId = conn.ProcessId,
                            LocalAddress = conn.LocalAddress,
                            LocalPort = conn.LocalPort,
                            BlockReason = blockReason
                        };

                        if (_autoBlockEnabled && conn.Protocol == "TCP")
                        {
                            args.ConnectionKilled = KillConnection(conn);
                            if (args.ConnectionKilled)
                            {
                                Interlocked.Increment(ref _statistics.KilledConnections);
                            }
                        }

                        Interlocked.Increment(ref _statistics.BlockedConnections);
                        OnBlocked(args);

                        Log($"阻止连接: {conn} 原因: {blockReason}" +
                            (args.ConnectionKilled ? " (已终止)" : ""));
                    }
                    else
                    {
                        if (!string.IsNullOrEmpty(conn.RemoteAddress) && conn.RemoteAddress != "*")
                        {
                            var suspicious = CheckSuspiciousConnection(conn);
                            if (suspicious != null)
                            {
                                SuspiciousConnection?.Invoke(this, suspicious);
                            }
                        }
                    }
                }
            }
        }

        /// <summary>
        /// 检查可疑连接（非阻止但值得关注的连接）
        /// </summary>
        private FirewallBlockEventArgs CheckSuspiciousConnection(ConnectionInfo conn)
        {
            var suspiciousPorts = new HashSet<int> { 4444, 5555, 6666, 7777, 8888, 9999, 31337, 40404, 1234, 444 };
            var highRiskPorts = new HashSet<int> { 23, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 6379 };

            if (suspiciousPorts.Contains(conn.RemotePort))
            {
                return new FirewallBlockEventArgs
                {
                    IpAddress = conn.RemoteAddress,
                    Port = conn.RemotePort,
                    RuleName = "SuspiciousPort",
                    Timestamp = DateTime.Now,
                    Protocol = conn.Protocol,
                    ProcessName = conn.ProcessName,
                    ProcessId = conn.ProcessId,
                    BlockReason = $"连接到可疑端口 {conn.RemotePort}"
                };
            }

            if (highRiskPorts.Contains(conn.RemotePort) && !IsPrivateIp(conn.RemoteAddress))
            {
                return new FirewallBlockEventArgs
                {
                    IpAddress = conn.RemoteAddress,
                    Port = conn.RemotePort,
                    RuleName = "HighRiskPort",
                    Timestamp = DateTime.Now,
                    Protocol = conn.Protocol,
                    ProcessName = conn.ProcessName,
                    ProcessId = conn.ProcessId,
                    BlockReason = $"连接到公网高危端口 {conn.RemotePort}"
                };
            }

            return null;
        }

        #endregion

        #region Connection Kill (SetTcpEntry)

        /// <summary>
        /// 终止指定的 TCP 连接（通过 SetTcpEntry 设置状态为 DELETE_TCB）
        /// </summary>
        public bool KillConnection(ConnectionInfo connection)
        {
            if (connection == null || connection.Protocol != "TCP")
                return false;

            if (connection.State != TcpConnectionState.Established &&
                connection.State != TcpConnectionState.SynSent &&
                connection.State != TcpConnectionState.SynReceived)
                return false;

            try
            {
                var row = new NativeMethods.MIB_TCPROW
                {
                    dwState = (uint)NativeMethods.MIB_TCP_STATE_DELETE_TCB,
                    dwLocalAddr = connection.RawLocalAddr,
                    dwLocalPort = connection.RawLocalPort,
                    dwRemoteAddr = connection.RawRemoteAddr,
                    dwRemotePort = connection.RawRemotePort
                };

                uint result = NativeMethods.SetTcpEntry(ref row);

                if (result == NativeMethods.NO_ERROR)
                {
                    Log($"终止TCP连接成功: {connection}");
                    return true;
                }
                else
                {
                    Log($"终止TCP连接失败: {connection} 错误码: {result}");
                    return false;
                }
            }
            catch (Exception ex)
            {
                Log($"终止TCP连接异常: {connection} {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// 终止所有连接到指定远程 IP 的 TCP 连接
        /// </summary>
        public int KillConnectionsByIp(string remoteIp)
        {
            int killed = 0;
            var connections = GetActiveTcpConnections();

            foreach (var conn in connections)
            {
                if (conn.RemoteAddress.Equals(remoteIp, StringComparison.OrdinalIgnoreCase))
                {
                    if (KillConnection(conn))
                        killed++;
                }
            }

            Log($"终止IP {remoteIp} 的 {killed} 个TCP连接");
            return killed;
        }

        /// <summary>
        /// 终止指定进程的所有 TCP 连接
        /// </summary>
        public int KillConnectionsByPid(int processId)
        {
            int killed = 0;
            var connections = GetActiveTcpConnections();

            foreach (var conn in connections)
            {
                if (conn.ProcessId == processId)
                {
                    if (KillConnection(conn))
                        killed++;
                }
            }

            Log($"终止进程PID {processId} 的 {killed} 个TCP连接");
            return killed;
        }

        #endregion

        #region IP Reputation / Blocklist

        /// <summary>
        /// 添加 IP 到黑名单
        /// </summary>
        public void AddBlockedIp(string ipAddress)
        {
            if (!string.IsNullOrEmpty(ipAddress))
            {
                _blockedIps.Add(ipAddress);
                Log($"添加IP到黑名单: {ipAddress}");
            }
        }

        /// <summary>
        /// 从黑名单移除 IP
        /// </summary>
        public void RemoveBlockedIp(string ipAddress)
        {
            if (_blockedIps.Remove(ipAddress))
                Log($"从黑名单移除IP: {ipAddress}");
        }

        /// <summary>
        /// 检查 IP 是否在黑名单中
        /// </summary>
        public bool IsIpBlocked(string ipAddress)
        {
            if (string.IsNullOrEmpty(ipAddress))
                return false;
            return _blockedIps.Contains(ipAddress);
        }

        /// <summary>
        /// 获取所有被阻止的 IP
        /// </summary>
        public List<string> GetBlockedIps()
        {
            return _blockedIps.ToList();
        }

        /// <summary>
        /// 加载 IP 黑名单文件
        /// </summary>
        public void LoadBlocklist()
        {
            string blocklistPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "FireAntivirus", "ip_blocklist.txt");

            try
            {
                if (File.Exists(blocklistPath))
                {
                    var lines = File.ReadAllLines(blocklistPath);
                    foreach (var line in lines)
                    {
                        var ip = line.Trim();
                        if (!string.IsNullOrEmpty(ip) && !ip.StartsWith("#"))
                        {
                            _blockedIps.Add(ip);
                        }
                    }
                    Log($"加载IP黑名单完成: {_blockedIps.Count} 个IP");
                }
            }
            catch (Exception ex)
            {
                Log($"加载IP黑名单失败: {ex.Message}");
            }
        }

        /// <summary>
        /// 保存 IP 黑名单到文件
        /// </summary>
        public void SaveBlocklist()
        {
            try
            {
                string dir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "FireAntivirus");
                Directory.CreateDirectory(dir);
                string path = Path.Combine(dir, "ip_blocklist.txt");

                var lines = _blockedIps.Select(ip => ip).ToList();
                lines.Insert(0, "# FireAntivirus IP Blocklist");
                File.WriteAllLines(path, lines);
                Log($"保存IP黑名单: {_blockedIps.Count} 个IP");
            }
            catch (Exception ex)
            {
                Log($"保存IP黑名单失败: {ex.Message}");
            }
        }

        /// <summary>
        /// 加载已知恶意域名列表
        /// </summary>
        private void LoadMaliciousDomains()
        {
            var knownMaliciousDomains = new[]
            {
                "malicious-c2-server.com",
                "botnet-cc.example.net",
                "phishing-site.xyz",
                "malware-download.cc",
                "trojan-c2.ddns.net",
                "ransomware-c2.top",
                "keylogger-exfil.net",
                "cryptominer-pool.mooo.com"
            };

            foreach (var domain in knownMaliciousDomains)
            {
                _maliciousDomains.Add(domain);
            }

            Log($"加载恶意域名库: {_maliciousDomains.Count} 个域名");
        }

        /// <summary>
        /// 添加恶意域名
        /// </summary>
        public void AddMaliciousDomain(string domain)
        {
            if (!string.IsNullOrEmpty(domain))
                _maliciousDomains.Add(domain.ToLowerInvariant());
        }

        /// <summary>
        /// 检查域名是否为已知恶意域名
        /// </summary>
        public bool IsMaliciousDomain(string domain)
        {
            if (string.IsNullOrEmpty(domain))
                return false;
            return _maliciousDomains.Contains(domain.ToLowerInvariant());
        }

        #endregion

        #region DNS Cache Monitoring

        /// <summary>
        /// 获取 DNS 解析缓存（通过 ipconfig /displaydns）
        /// </summary>
        public List<DnsCacheEntry> GetDnsCache()
        {
            var entries = new List<DnsCacheEntry>();

            try
            {
                string output = RunProcess("ipconfig.exe", "/displaydns");

                if (string.IsNullOrEmpty(output))
                    return entries;

                var lines = output.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);
                DnsCacheEntry current = null;

                foreach (var line in lines)
                {
                    var trimmed = line.Trim();

                    if (trimmed.StartsWith("记录名称", StringComparison.OrdinalIgnoreCase) ||
                        trimmed.StartsWith("Record Name", StringComparison.OrdinalIgnoreCase))
                    {
                        if (current != null)
                            entries.Add(current);

                        current = new DnsCacheEntry();
                        var parts = trimmed.Split(new[] { ':' }, 2);
                        if (parts.Length >= 2)
                            current.Domain = parts[1].Trim();
                    }
                    else if (current != null)
                    {
                        if (trimmed.StartsWith("记录类型", StringComparison.OrdinalIgnoreCase) ||
                            trimmed.StartsWith("Record Type", StringComparison.OrdinalIgnoreCase))
                        {
                            var parts = trimmed.Split(new[] { ':' }, 2);
                            if (parts.Length >= 2)
                                current.RecordType = parts[1].Trim();
                        }
                        else if (trimmed.Contains("A (Host) Record") ||
                                 trimmed.Contains("A 记录") ||
                                 (trimmed.StartsWith("A (Host)", StringComparison.OrdinalIgnoreCase)))
                        {
                            var match = Regex.Match(trimmed, @"[:：]\s*([\d.]+)");
                            if (match.Success)
                                current.IpAddress = match.Groups[1].Value;
                        }
                        else if (trimmed.StartsWith("TTL", StringComparison.OrdinalIgnoreCase) ||
                                 trimmed.StartsWith("生存时间", StringComparison.OrdinalIgnoreCase))
                        {
                            var match = Regex.Match(trimmed, @"(\d+)");
                            if (match.Success && int.TryParse(match.Groups[1].Value, out int ttl))
                                current.TimeToLive = ttl;
                        }
                    }
                }

                if (current != null)
                    entries.Add(current);

                foreach (var entry in entries)
                {
                    if (IsMaliciousDomain(entry.Domain))
                    {
                        entry.IsMalicious = true;
                        entry.ThreatReason = "域名匹配已知恶意域名库";
                    }
                }
            }
            catch (Exception ex)
            {
                Log($"获取DNS缓存失败: {ex.Message}");
            }

            return entries;
        }

        /// <summary>
        /// 检查 DNS 缓存中是否存在恶意域名
        /// </summary>
        public void CheckDnsCache()
        {
            try
            {
                var entries = GetDnsCache();
                var maliciousEntries = entries.Where(e => e.IsMalicious).ToList();

                foreach (var entry in maliciousEntries)
                {
                    var args = new FirewallBlockEventArgs
                    {
                        IpAddress = entry.IpAddress,
                        Port = 53,
                        RuleName = "DnsThreatDetection",
                        Timestamp = DateTime.Now,
                        Protocol = "DNS",
                        BlockReason = $"DNS缓存中发现恶意域名: {entry.Domain}"
                    };

                    Interlocked.Increment(ref _statistics.DnsThreatsDetected);
                    DnsThreatDetected?.Invoke(this, args);

                    Log($"DNS威胁检测: 域名={entry.Domain} IP={entry.IpAddress}");

                    if (_autoBlockEnabled && !string.IsNullOrEmpty(entry.IpAddress))
                    {
                        BlockIp(entry.IpAddress);
                    }
                }
            }
            catch (Exception ex)
            {
                Log($"检查DNS缓存失败: {ex.Message}");
            }
        }

        /// <summary>
        /// 清除 DNS 解析缓存（通过 ipconfig /flushdns）
        /// </summary>
        public bool FlushDnsCache()
        {
            try
            {
                string output = RunProcess("ipconfig.exe", "/flushdns");
                bool success = output.Contains("成功") || output.Contains("successfully");
                Log(success ? "DNS缓存已清除" : "清除DNS缓存失败");
                return success;
            }
            catch (Exception ex)
            {
                Log($"清除DNS缓存异常: {ex.Message}");
                return false;
            }
        }

        #endregion

        #region Network Statistics

        /// <summary>
        /// 获取网络接口统计数据（字节发送/接收）
        /// </summary>
        public Dictionary<string, (long BytesSent, long BytesReceived)> GetNetworkInterfaceStatistics()
        {
            var result = new Dictionary<string, (long, long)>();

            try
            {
                var interfaces = NetworkInterface.GetAllNetworkInterfaces();

                foreach (var nic in interfaces)
                {
                    if (nic.OperationalStatus != OperationalStatus.Up)
                        continue;

                    try
                    {
                        var ipv4Stats = nic.GetIPv4Statistics();
                        long sent = ipv4Stats.BytesSent;
                        long received = ipv4Stats.BytesReceived;

                        result[nic.Name] = (sent, received);

                        _statistics.TotalBytesSent = Math.Max(_statistics.TotalBytesSent, sent);
                        _statistics.TotalBytesReceived = Math.Max(_statistics.TotalBytesReceived, received);
                    }
                    catch
                    {
                        // 某些接口可能不支持统计
                    }
                }
            }
            catch (Exception ex)
            {
                Log($"获取网络接口统计失败: {ex.Message}");
            }

            return result;
        }

        /// <summary>
        /// 更新网络统计数据
        /// </summary>
        private void UpdateNetworkStatistics(int connectionCount)
        {
            Interlocked.Exchange(ref _statistics.TotalConnections, connectionCount);

            try
            {
                GetNetworkInterfaceStatistics();
            }
            catch
            {
                // 忽略统计更新错误
            }
        }

        /// <summary>
        /// 获取防火墙统计摘要
        /// </summary>
        public string GetStatisticsReport()
        {
            var sb = new StringBuilder();
            sb.AppendLine("===== 防火墙统计报告 =====");
            sb.AppendLine($"运行时间: {_statistics.Uptime:hh\\:mm\\:ss}");
            sb.AppendLine($"当前活动连接: {_statistics.TotalConnections}");
            sb.AppendLine($"阻止连接总数: {_statistics.BlockedConnections}");
            sb.AppendLine($"终止连接总数: {_statistics.KilledConnections}");
            sb.AppendLine($"检测到端口扫描: {_statistics.PortScansDetected}");
            sb.AppendLine($"检测到DNS威胁: {_statistics.DnsThreatsDetected}");
            sb.AppendLine($"应用规则次数: {_statistics.RulesApplied}");
            sb.AppendLine($"当前规则数: {_rules.Count}");
            sb.AppendLine($"黑名单IP数: {_blockedIps.Count}");
            sb.AppendLine($"阻止应用数: {_blockedApplications.Count}");
            sb.AppendLine($"总发送字节: {_statistics.TotalBytesSent:N0}");
            sb.AppendLine($"总接收字节: {_statistics.TotalBytesReceived:N0}");
            sb.AppendLine("=========================");
            return sb.ToString();
        }

        #endregion

        #region Rule Persistence (JSON)

        /// <summary>
        /// 保存自定义防火墙规则到 JSON 文件
        /// </summary>
        public void SaveRules()
        {
            try
            {
                string dir = Path.GetDirectoryName(_rulesFilePath);
                Directory.CreateDirectory(dir);

                var rulesToSave = _rules.Values
                    .Where(r => !r.IsSystemRule)
                    .Select(r => new
                    {
                        r.Name,
                        r.IpAddress,
                        r.Port,
                        Action = r.Action.ToString(),
                        r.Description,
                        Protocol = r.Protocol.ToString(),
                        Direction = r.Direction.ToString(),
                        r.ApplicationPath,
                        r.CreatedTime
                    }).ToList();

                var blocklist = _blockedIps.ToList();
                var blockedApps = _blockedApplications.ToList();

                var data = new
                {
                    Rules = rulesToSave,
                    BlockedIps = blocklist,
                    BlockedApplications = blockedApps,
                    MaliciousDomains = _maliciousDomains.ToList(),
                    LastSaved = DateTime.Now
                };

                var options = new JsonSerializerOptions { WriteIndented = true };
                string json = JsonSerializer.Serialize(data, options);
                File.WriteAllText(_rulesFilePath, json);
            }
            catch (Exception ex)
            {
                Log($"保存防火墙规则失败: {ex.Message}");
            }
        }

        /// <summary>
        /// 从 JSON 文件加载自定义防火墙规则
        /// </summary>
        public void LoadRules()
        {
            try
            {
                if (!File.Exists(_rulesFilePath))
                    return;

                string json = File.ReadAllText(_rulesFilePath);
                using var doc = JsonDocument.Parse(json);

                if (doc.RootElement.TryGetProperty("Rules", out var rulesElement))
                {
                    foreach (var item in rulesElement.EnumerateArray())
                    {
                        var rule = new FirewallRule
                        {
                            Name = item.GetProperty("Name").GetString(),
                            IpAddress = item.GetProperty("IpAddress").GetString(),
                            Port = item.GetProperty("Port").GetInt32(),
                            Description = item.TryGetProperty("Description", out var desc) ? desc.GetString() : "",
                            ApplicationPath = item.TryGetProperty("ApplicationPath", out var app) ? app.GetString() : null,
                            CreatedTime = item.TryGetProperty("CreatedTime", out var ct) ? ct.GetDateTime() : DateTime.Now
                        };

                        if (item.TryGetProperty("Action", out var action) &&
                            Enum.TryParse<FirewallAction>(action.GetString(), out var act))
                            rule.Action = act;

                        if (item.TryGetProperty("Protocol", out var proto) &&
                            Enum.TryParse<FirewallProtocol>(proto.GetString(), out var p))
                            rule.Protocol = p;

                        if (item.TryGetProperty("Direction", out var dir) &&
                            Enum.TryParse<FirewallDirection>(dir.GetString(), out var d))
                            rule.Direction = d;

                        if (!string.IsNullOrEmpty(rule.Name))
                            _rules[rule.Name] = rule;
                    }
                }

                if (doc.RootElement.TryGetProperty("BlockedIps", out var ipsElement))
                {
                    foreach (var ip in ipsElement.EnumerateArray())
                    {
                        var ipStr = ip.GetString();
                        if (!string.IsNullOrEmpty(ipStr))
                            _blockedIps.Add(ipStr);
                    }
                }

                if (doc.RootElement.TryGetProperty("BlockedApplications", out var appsElement))
                {
                    foreach (var app in appsElement.EnumerateArray())
                    {
                        var appStr = app.GetString();
                        if (!string.IsNullOrEmpty(appStr))
                            _blockedApplications.Add(appStr);
                    }
                }

                Log($"加载防火墙规则完成: {_rules.Count} 条规则");
            }
            catch (Exception ex)
            {
                Log($"加载防火墙规则失败: {ex.Message}");
            }
        }

        #endregion

        #region Firewall Service Management

        /// <summary>
        /// 确保 Windows 防火墙服务正在运行
        /// </summary>
        private void EnsureFirewallServiceRunning()
        {
            try
            {
                foreach (var proc in Process.GetProcessesByName("mpssvc"))
                {
                    proc.Dispose();
                    // 服务正在运行
                    return;
                }

                // 尝试通过 sc 命令启动防火墙服务
                RunProcess("sc.exe", "start mpssvc");
                Log("Windows防火墙服务已启动");
            }
            catch (Exception ex)
            {
                Log($"确保防火墙服务运行时出错: {ex.Message}");
            }
        }

        #endregion

        #region Helper Methods

        /// <summary>
        /// 将网络字节序的 uint 转换为 IP 地址字符串
        /// </summary>
        private static string GetIpAddress(uint addr)
        {
            try
            {
                byte[] bytes = BitConverter.GetBytes(addr);
                return new IPAddress(bytes).ToString();
            }
            catch
            {
                return "0.0.0.0";
            }
        }

        /// <summary>
        /// 将网络字节序的端口字段转换为端口号
        /// </summary>
        private static int GetPort(uint port)
        {
            return (int)(((port & 0xFF) << 8) | ((port >> 8) & 0xFF));
        }

        /// <summary>
        /// 获取进程名称
        /// </summary>
        private static string GetProcessName(int pid)
        {
            if (pid == 0)
                return "System Idle";
            if (pid == 4)
                return "System";

            try
            {
                using var proc = Process.GetProcessById(pid);
                return proc.ProcessName;
            }
            catch
            {
                return "Unknown";
            }
        }

        /// <summary>
        /// 检查 IP 是否为私有地址
        /// </summary>
        private static bool IsPrivateIp(string ipAddress)
        {
            if (string.IsNullOrEmpty(ipAddress))
                return false;

            if (!IPAddress.TryParse(ipAddress, out var ip))
                return false;

            if (ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                return false;

            var bytes = ip.GetAddressBytes();
            if (bytes[0] == 10) return true;
            if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return true;
            if (bytes[0] == 192 && bytes[1] == 168) return true;
            if (bytes[0] == 127) return true;

            return false;
        }

        /// <summary>
        /// 执行 netsh 命令并返回输出
        /// </summary>
        private string RunNetsh(string arguments)
        {
            return RunProcess("netsh.exe", arguments);
        }

        /// <summary>
        /// 执行外部进程并返回标准输出
        /// </summary>
        private string RunProcess(string fileName, string arguments)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = fileName,
                    Arguments = arguments,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                    StandardOutputEncoding = Encoding.GetEncoding("gb2312")
                };

                using var process = Process.Start(psi);
                if (process == null)
                    return string.Empty;

                string output = process.StandardOutput.ReadToEnd();
                string error = process.StandardError.ReadToEnd();
                process.WaitForExit(15000);

                return string.IsNullOrEmpty(error) ? output : output + "\n" + error;
            }
            catch (Exception ex)
            {
                Log($"执行命令失败: {fileName} {arguments} - {ex.Message}");
                return string.Empty;
            }
        }

        /// <summary>
        /// 记录日志
        /// </summary>
        private void Log(string message)
        {
            LogHelper.Log(LogHelper.LogLevel.Info, $"[{_logTag}] {message}");

            if (_dataManager != null)
            {
                try
                {
                    _dataManager.LogInfo($"[{_logTag}] {message}", "", "FirewallManager");
                }
                catch
                {
                    // 忽略 DataManager 日志错误
                }
            }
        }

        /// <summary>
        /// 触发阻止事件
        /// </summary>
        protected virtual void OnBlocked(FirewallBlockEventArgs e)
        {
            Blocked?.Invoke(this, e);
        }

        /// <summary>
        /// 端口扫描检测事件处理
        /// </summary>
        private void OnPortScanDetected(object sender, PortScanEventArgs e)
        {
            Interlocked.Increment(ref _statistics.PortScansDetected);
            PortScanDetected?.Invoke(this, e);

            Log($"端口扫描检测: {e.Description}");

            if (_autoBlockEnabled && !IsIpBlocked(e.ScannerIp))
            {
                AddBlockedIp(e.ScannerIp);
                if (_autoBlockEnabled)
                {
                    BlockIp(e.ScannerIp);
                }
                KillConnectionsByIp(e.ScannerIp);
            }
        }

        #endregion
    }
}
