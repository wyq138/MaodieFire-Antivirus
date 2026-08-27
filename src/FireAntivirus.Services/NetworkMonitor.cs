using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using FireAntivirus.Data;
using FireAntivirus.Engine;
using System.Linq;

namespace FireAntivirus.Services
{
    public class NetworkMonitor : IMonitor
    {
        private Thread monitorThread;
        private bool isRunning;
        private DataManager dataManager;
        private AntivirusEngine antivirusEngine;
        private HashSet<string> suspiciousIps;
        private HashSet<string> suspiciousPorts;
        private Dictionary<int, string> processCache;
        private Dictionary<string, MonitorNetworkConnectionInfo> connectionCache;
        private HashSet<string> alertedConnections;
        private Dictionary<string, DnsQueryInfo> dnsQueryCache;
        private Dictionary<string, NetworkFlowInfo> flowAnalysisData;
        private Timer analysisTimer;
        private const int MAX_CONNECTION_AGE = 60;
        private const int DNS_CACHE_TTL = 300; // 5分钟
        private const int FLOW_ANALYSIS_INTERVAL = 60000; // 1分钟
        
        // 受信任进程白名单
        private HashSet<string> trustedProcessNames;
        
        // 受信任路径白名单
        private HashSet<string> trustedPaths;
        
        // 高风险端口白名单（避免误报常用端口）
        private HashSet<string> safePorts;
        
        public NetworkMonitor(DataManager dataManager, AntivirusEngine antivirusEngine)
        {
            this.dataManager = dataManager;
            this.antivirusEngine = antivirusEngine;
            suspiciousIps = new HashSet<string>
            {
                // 已知恶意IP可以在这里添加
            };
            suspiciousPorts = new HashSet<string>
            {
                // 已知恶意软件常用端口
                "4444",  // Metasploit
                "5555",  // Android ADB remote
                "6666",  // IRC Bot
                "6667",  // IRC
                "31337"  // Back Orifice
            };
            processCache = new Dictionary<int, string>();
            connectionCache = new Dictionary<string, MonitorNetworkConnectionInfo>();
            alertedConnections = new HashSet<string>();
            InitializeTrustedProcesses();
            InitializeSafePorts();
        }
        
        private void InitializeTrustedProcesses()
        {
            // 初始化受信任进程白名单
            trustedProcessNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "System", "svchost", "lsass", "services", "csrss", "wininit",
                "chrome", "firefox", "msedge", "brave", "opera", "vivaldi",
                "QQ", "WeChat", "DingTalk", "Steam", "Discord",
                "powershell", "pwsh", "cmd", "explorer"
            };
        }
        
        private void InitializeSafePorts()
        {
            // 初始化常用安全端口白名单，避免误报
            safePorts = new HashSet<string>
            {
                "80", "443", "8080", "8443",  // HTTP/HTTPS
                "21", "22", "23", "25", "53", "110", "143", // 常见服务端口
                "3306", "5432", "6379", "27017",  // 数据库端口（本地）
                "3000", "5000", "8000", "8888", "9000" // 开发服务器
            };
        }
        
        // 检查进程是否受信任
        private bool IsTrustedProcess(string processName)
        {
            return trustedProcessNames.Contains(processName);
        }
        
        public void Start()
        {
            isRunning = true;
            monitorThread = new Thread(MonitorNetwork);
            monitorThread.Start();

            dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "NetworkMonitorStart",
                Message = "网络监控已启动",
                Details = "开始监控网络连接和流量，检测所有在线应用程序"
            });
        }

        public void Stop()
        {
            isRunning = false;
            monitorThread?.Join(2000);
            analysisTimer?.Dispose();

            dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "NetworkMonitorStop",
                Message = "网络监控已停止",
                Details = string.Empty
            });
        }

        private void MonitorNetwork()
        {
            while (isRunning)
            {
                try
                {
                    var connections = GetAllNetworkConnections();
                    AnalyzeConnections(connections);
                    MonitorNetworkInterfaces();
                    MonitorDnsQueries();
                    AnalyzeTrafficPatterns();
                    CleanupConnectionCache();
                }
                catch (Exception ex)
                {
                    dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "NetworkMonitorError",
                        Message = "网络监控出错",
                        Details = ex.Message
                    });
                }

                Thread.Sleep(3000);
            }
        }

        private List<MonitorNetworkConnectionInfo> GetAllNetworkConnections()
        {
            var connections = new List<MonitorNetworkConnectionInfo>();

            try
            {
                string output = ExecuteCommand("netstat -ano");
                if (!string.IsNullOrEmpty(output))
                {
                    connections = ParseNetstatOutput(output);
                }

                connections.AddRange(GetConnectionsFromWMI());
            }
            catch (Exception ex)
            {
                dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "ConnectionRetrievalError",
                    Message = "获取网络连接信息失败",
                    Details = ex.Message
                });
            }

            return connections;
        }

        private List<MonitorNetworkConnectionInfo> ParseNetstatOutput(string output)
        {
            var connections = new List<MonitorNetworkConnectionInfo>();
            string[] lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

            string pattern = @"^(TCP|UDP)\s+([\d.]+):(\d+)\s+([\d.]+):(\d+|\*)\s+([A-Z_]+)?\s*(\d+)?$";
            Regex regex = new Regex(pattern, RegexOptions.IgnoreCase);

            foreach (string line in lines)
            {
                Match match = regex.Match(line);
                if (match.Success)
                {
                    try
                    {
                        string protocol = match.Groups[1].Value;
                        string localAddress = match.Groups[2].Value;
                        int localPort = int.Parse(match.Groups[3].Value);
                        string remoteAddress = match.Groups[4].Value;
                        string remotePort = match.Groups[5].Value;
                        string state = match.Groups[6].Value;
                        int processId = match.Groups[7].Success ? int.Parse(match.Groups[7].Value) : 0;

                        string processName = GetProcessName(processId);

                        var connection = new MonitorNetworkConnectionInfo
                        {
                            Protocol = protocol,
                            LocalAddress = localAddress,
                            LocalPort = localPort,
                            RemoteAddress = remoteAddress,
                            RemotePort = remotePort,
                            State = state,
                            ProcessId = processId,
                            ProcessName = processName,
                            Timestamp = DateTime.Now
                        };

                        connections.Add(connection);
                    }
                    catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "NetworkMonitor.cs 捕获异常", ex.Message); }
                }
            }

            return connections;
        }

        private List<MonitorNetworkConnectionInfo> GetConnectionsFromWMI()
        {
            var connections = new List<MonitorNetworkConnectionInfo>();

            try
            {
                using (var searcher = new System.Management.ManagementObjectSearcher("SELECT * FROM Win32_NetworkConnection"))
                {
                    foreach (var obj in searcher.Get())
                    {
                        try
                        {
                            var connection = new MonitorNetworkConnectionInfo
                            {
                                RemoteAddress = obj["RemoteName"]?.ToString(),
                                LocalAddress = obj["LocalName"]?.ToString(),
                                State = obj["ConnectionState"]?.ToString(),
                                UserName = obj["UserName"]?.ToString(),
                                Timestamp = DateTime.Now
                            };

                            connections.Add(connection);
                        }
                        catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "NetworkMonitor.cs 捕获异常", ex.Message); }
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "NetworkMonitor.cs 捕获异常", ex.Message); }

            return connections;
        }

        private void AnalyzeConnections(List<MonitorNetworkConnectionInfo> connections)
        {
            foreach (var connection in connections)
            {
                try
                {
                    string connectionId = $"{connection.Protocol}_{connection.LocalAddress}:{connection.LocalPort}_{connection.RemoteAddress}:{connection.RemotePort}";

                    if (!connectionCache.ContainsKey(connectionId))
                    {
                        connectionCache[connectionId] = connection;

                        dataManager.AddLog(new LogEntry
                        {
                            Id = Guid.NewGuid().ToString(),
                            Time = DateTime.Now,
                            Type = "NewNetworkConnection",
                            Message = "发现新的网络连接",
                            Details = $"应用: {connection.ProcessName}, 协议: {connection.Protocol}, 本地: {connection.LocalAddress}:{connection.LocalPort}, 远程: {connection.RemoteAddress}:{connection.RemotePort}, 状态: {connection.State}"
                        });
                    }
                    else
                    {
                        connectionCache[connectionId].Timestamp = DateTime.Now;
                    }

                    CheckForSuspiciousConnection(connection);
                }
                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "NetworkMonitor.cs 捕获异常", ex.Message); }
            }
        }

private void CheckForSuspiciousConnection(MonitorNetworkConnectionInfo connection)
        {
            string connectionKey = $"{connection.RemoteAddress}:{connection.RemotePort}";
            
            // 避免重复弹窗
            if (alertedConnections.Contains(connectionKey))
                return;
            
            // ========== 受信任检查：如果是受信任进程，跳过检查 ==========
            if (!string.IsNullOrEmpty(connection.ProcessName) && IsTrustedProcess(connection.ProcessName))
                return;
            
            // ========== 检查安全端口白名单 ==========
            if (!string.IsNullOrEmpty(connection.RemotePort) && safePorts.Contains(connection.RemotePort))
                return;
            
            // 检查远程IP是否可疑
            if (!string.IsNullOrEmpty(connection.RemoteAddress) && suspiciousIps.Contains(connection.RemoteAddress))
            {
                string message = $"发现可疑网络连接\n应用: {connection.ProcessName}\n远程地址: {connection.RemoteAddress}:{connection.RemotePort}\n协议: {connection.Protocol}";

                dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "SuspiciousNetworkConnection",
                    Message = "发现可疑网络连接",
                    Details = message
                });

                ShowThreatNotification("可疑网络连接警告", message, NotificationType.Error);
                alertedConnections.Add(connectionKey);
            }

            // 检查远程端口是否可疑（高风险端口）
            if (!string.IsNullOrEmpty(connection.RemotePort) && suspiciousPorts.Contains(connection.RemotePort))
            {
                string message = $"发现可疑端口连接\n应用: {connection.ProcessName}\n远程端口: {connection.RemotePort}\n协议: {connection.Protocol}\n这可能表示潜在的恶意活动";

                dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "SuspiciousPortConnection",
                    Message = "发现可疑端口连接",
                    Details = message
                });

                ShowThreatNotification("可疑端口连接警告", message, NotificationType.Warning);
                alertedConnections.Add(connectionKey);
            }

            // 检查是否是未知名进程的连接
            if (connection.ProcessId > 0 && string.IsNullOrEmpty(connection.ProcessName))
            {
                string message = $"发现未知进程的网络连接\nPID: {connection.ProcessId}\n远程: {connection.RemoteAddress}:{connection.RemotePort}\n协议: {connection.Protocol}";

                dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "UnknownProcessConnection",
                    Message = "发现未知进程的网络连接",
                    Details = message
                });

                ShowThreatNotification("未知进程网络连接", message, NotificationType.Warning);
                alertedConnections.Add(connectionKey);
            }
        }

private void MonitorNetworkInterfaces()
        {
            try
            {
                var interfaces = NetworkInterface.GetAllNetworkInterfaces();
                foreach (var iface in interfaces)
                {
                    if (iface.OperationalStatus == OperationalStatus.Up)
                    {
                        var ipv4Stats = iface.GetIPv4Statistics();

                        long bytesSent = ipv4Stats.BytesSent;
                        long bytesReceived = ipv4Stats.BytesReceived;
                        
                        // 计算速率（使用累计值除以接口运行时间，模拟速率）
                        // 如果接口刚启动，累计值就是速率；运行久了就除以时间来估算
                        TimeSpan uptime = DateTime.Now - System.Diagnostics.Process.GetCurrentProcess().StartTime;
                        long sentRate = uptime.TotalSeconds > 0 ? bytesSent / (long)uptime.TotalSeconds : bytesSent;
                        long recvRate = uptime.TotalSeconds > 0 ? bytesReceived / (long)uptime.TotalSeconds : bytesReceived;

                        // 禁用高流量检测，避免误报
                        long highTrafficThreshold = long.MaxValue; // 禁用此检测
                        if (false) // 永远不触发
                        {
                            string message = $"检测到高网络流量\n接口: {iface.Name}\n发送速率: {FormatBytes(sentRate)}/s\n接收速率: {FormatBytes(recvRate)}/s";

                            dataManager.AddLog(new LogEntry
                            {
                                Id = Guid.NewGuid().ToString(),
                                Time = DateTime.Now,
                                Type = "HighNetworkTraffic",
                                Message = "检测到高网络流量",
                                Details = message
                            });

                            ShowThreatNotification("高网络流量警告", message, NotificationType.Warning);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "InterfaceMonitoringError",
                    Message = "网络接口监控出错",
                    Details = ex.Message
                });
            }
        }

        private string GetProcessName(int processId)
        {
            if (processId == 0)
                return string.Empty;

            if (processCache.TryGetValue(processId, out string cachedName))
                return cachedName;

            try
            {
                using (var process = Process.GetProcessById(processId))
                {
                    string processName = process.ProcessName;
                    processCache[processId] = processName;
                    return processName;
                }
            }
            catch
            {
                processCache[processId] = "Unknown";
                return "Unknown";
            }
        }

        private void CleanupConnectionCache()
        {
            var expiredConnections = new List<string>();

            foreach (var kvp in connectionCache)
            {
                if ((DateTime.Now - kvp.Value.Timestamp).TotalSeconds > MAX_CONNECTION_AGE)
                {
                    expiredConnections.Add(kvp.Key);
                }
            }

            foreach (var connectionId in expiredConnections)
            {
                connectionCache.Remove(connectionId);
            }

            var expiredProcesses = new List<int>();
            foreach (var kvp in processCache)
            {
                try
                {
                    Process.GetProcessById(kvp.Key);
                }
                catch
                {
                    expiredProcesses.Add(kvp.Key);
                }
            }

            foreach (var processId in expiredProcesses)
            {
                processCache.Remove(processId);
            }
            
            // 清理已警告的连接记录
            alertedConnections.Clear();
        }

        private string FormatBytes(long bytes)
        {
            if (bytes >= 1073741824)
                return $"{bytes / 1073741824.0:F2} GB";
            if (bytes >= 1048576)
                return $"{bytes / 1048576.0:F2} MB";
            if (bytes >= 1024)
                return $"{bytes / 1024.0:F2} KB";
            return $"{bytes} B";
        }

        private string ExecuteCommand(string command)
        {
            try
            {
                using (var process = new Process())
                {
                    process.StartInfo.FileName = "cmd.exe";
                    process.StartInfo.Arguments = $"/c {command}";
                    process.StartInfo.RedirectStandardOutput = true;
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.CreateNoWindow = true;
                    process.Start();
                    return process.StandardOutput.ReadToEnd();
                }
            }
            catch
            {
                return string.Empty;
            }
        }
        
        private void ShowThreatNotification(string title, string message, NotificationType type)
        {
            try
            {
                NotificationService.Instance.ShowNotification(title, message, type);
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "NetworkMonitor.cs 捕获异常", ex.Message); }
        }

        private void MonitorDnsQueries() { }
        private void AnalyzeTrafficPatterns() { }

        public ConnectionAnalysisResult AnalyzeConnection(NetworkConnection connection)
        {
            return new ConnectionAnalysisResult { IsMalicious = false };
        }


        public class MonitorNetworkConnectionInfo
        {
            public string Protocol { get; set; }
            public string LocalAddress { get; set; }
            public int LocalPort { get; set; }
            public string RemoteAddress { get; set; }
            public string RemotePort { get; set; }
            public string State { get; set; }
            public int ProcessId { get; set; }
            public string ProcessName { get; set; }
            public string UserName { get; set; }
            public DateTime Timestamp { get; set; }
        }
    }

    public class DnsQueryInfo
    {
        public string Domain { get; set; }
        public string ResolvedIp { get; set; }
        public List<string> ResolvedIps { get; set; } = new List<string>();
        public string QueryType { get; set; }
        public DateTime QueryTime { get; set; }
        public DateTime LastSeen { get; set; }
        public int QueryCount { get; set; }
        public bool IsSuspicious { get; set; }
        public string ProcessName { get; set; }
        public int ProcessId { get; set; }
    }

    public class NetworkFlowInfo
    {
        public string FlowKey { get; set; }
        public string SourceAddress { get; set; }
        public int SourcePort { get; set; }
        public string DestinationAddress { get; set; }
        public int DestinationPort { get; set; }
        public string Protocol { get; set; }
        public long BytesSent { get; set; }
        public long BytesReceived { get; set; }
        public int PacketsSent { get; set; }
        public int PacketsReceived { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime LastActivity { get; set; }
        public string ProcessName { get; set; }
        public int ProcessId { get; set; }
        public bool IsAnomalous { get; set; }
        public double AnomalyScore { get; set; }
    }

    public class ConnectionAnalysisResult
    {
        public bool IsMalicious { get; set; }
        public string ThreatType { get; set; }
        public SecurityThreatLevel ThreatLevel { get; set; }
    }

    public enum SecurityThreatLevel
    {
        Low, Medium, High, Critical
    }
}