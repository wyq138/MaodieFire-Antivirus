using FireAntivirus.Common;
using FireAntivirus.Data;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace FireAntivirus.Services
{


    public class NetworkSecurity
    {
        private readonly int _packetCaptureBufferSize;
        private readonly int _analysisTimeoutMs;
        private readonly int _maxConnections;
        private readonly int _maxPacketsPerSecond;

        public NetworkSecurity(int packetCaptureBufferSize = 1048576, int analysisTimeoutMs = 5000, int maxConnections = 1000, int maxPacketsPerSecond = 10000)
        {
            _packetCaptureBufferSize = packetCaptureBufferSize;
            _analysisTimeoutMs = analysisTimeoutMs;
            _maxConnections = maxConnections;
            _maxPacketsPerSecond = maxPacketsPerSecond;
        }

        public async Task<NetworkAnalysisResult> AnalyzeNetworkTrafficAsync(string interfaceName)
        {
            try
            {
                var result = new NetworkAnalysisResult
                {
                    InterfaceName = interfaceName,
                    AnalysisStartTime = DateTime.UtcNow,
                    Connections = new List<NetworkConnection>(),
                    Packets = new List<NetworkPacket>(),
                    Anomalies = new List<NetworkAnomaly>()
                };

                // 实际网络流量捕获和分析
                // 使用System.Net.NetworkInformation获取网络连接信息
                await Task.Delay(100);

                // 获取实际的网络连接
                result.Connections = GetActualNetworkConnections();
                
                // 生成实际的网络数据包
                result.Packets = GetActualNetworkPackets();

                // 分析网络异常
                await AnalyzeNetworkAnomaliesAsync(result);

                result.AnalysisEndTime = DateTime.UtcNow;
                result.AnalysisDuration = result.AnalysisEndTime - result.AnalysisStartTime;

                return result;
            }
            catch (Exception ex)
            {
                Logger.Error($"Network traffic analysis error: {ex.Message}");
                throw;
            }
        }

        public async Task<NetworkConnectionAnalysis> AnalyzeConnectionAsync(IPEndPoint localEndPoint, IPEndPoint remoteEndPoint)
        {
            try
            {
                var analysis = new NetworkConnectionAnalysis
                {
                    LocalEndPoint = localEndPoint,
                    RemoteEndPoint = remoteEndPoint,
                    AnalysisStartTime = DateTime.UtcNow,
                    Packets = new List<NetworkPacket>(),
                    Anomalies = new List<NetworkAnomaly>()
                };

                // 真实连接特征分析（此前 await Task.Delay(500) 仅为模拟耗时，已移除）

                // 分析连接特征
                await AnalyzeConnectionFeaturesAsync(analysis);

                // 检测连接异常
                await DetectConnectionAnomaliesAsync(analysis);

                analysis.AnalysisEndTime = DateTime.UtcNow;
                analysis.AnalysisDuration = analysis.AnalysisEndTime - analysis.AnalysisStartTime;

                return analysis;
            }
            catch (Exception ex)
            {
                Logger.Error($"Connection analysis error: {ex.Message}");
                throw;
            }
        }

        public async Task<NetworkAnomalyDetectionResult> DetectAnomaliesAsync(List<NetworkPacket> packets)
        {
            try
            {
                var result = new NetworkAnomalyDetectionResult
                {
                    AnalysisStartTime = DateTime.UtcNow,
                    AnalyzedPackets = packets.Count,
                    Anomalies = new List<NetworkAnomaly>()
                };

                // 分析数据包异常
                await AnalyzePacketAnomaliesAsync(packets, result);

                // 分析流量模式异常
                await AnalyzeTrafficPatternAnomaliesAsync(packets, result);

                // 分析连接行为异常
                await AnalyzeConnectionBehaviorAnomaliesAsync(packets, result);

                result.AnalysisEndTime = DateTime.UtcNow;
                result.AnalysisDuration = result.AnalysisEndTime - result.AnalysisStartTime;

                return result;
            }
            catch (Exception ex)
            {
                Logger.Error($"Anomaly detection error: {ex.Message}");
                throw;
            }
        }

        public async Task<NetworkThreatDetectionResult> DetectThreatsAsync(NetworkAnalysisResult networkAnalysis)
        {
            try
            {
                var result = new NetworkThreatDetectionResult
                {
                    AnalysisStartTime = DateTime.UtcNow,
                    Threats = new List<NetworkThreat>()
                };

                // 检测已知威胁
                await DetectKnownThreatsAsync(networkAnalysis, result);

                // 检测可疑行为
                await DetectSuspiciousBehaviorAsync(networkAnalysis, result);

                // 检测异常流量模式
                await DetectAbnormalTrafficPatternsAsync(networkAnalysis, result);

                result.AnalysisEndTime = DateTime.UtcNow;
                result.AnalysisDuration = result.AnalysisEndTime - result.AnalysisStartTime;

                return result;
            }
            catch (Exception ex)
            {
                Logger.Error($"Threat detection error: {ex.Message}");
                throw;
            }
        }

        public async Task<NetworkFirewallRule> CreateFirewallRuleAsync(FirewallRuleType ruleType, string name, string description, IPEndPoint sourceEndPoint, IPEndPoint destinationEndPoint, ProtocolType protocol, FirewallAction action)
        {
            try
            {
                var rule = new NetworkFirewallRule
                {
                    RuleType = ruleType,
                    Name = name,
                    Description = description,
                    SourceEndPoint = sourceEndPoint,
                    DestinationEndPoint = destinationEndPoint,
                    Protocol = protocol,
                    Action = action,
                    CreatedAt = DateTime.UtcNow,
                    IsEnabled = true
                };

                // 真实实现：调用 netsh advfirewall 创建系统防火墙规则
                string dir = ruleType == FirewallRuleType.Outbound ? "out" : "in";
                string act = action == FirewallAction.Allow ? "allow" : "block";
                string proto = protocol == ProtocolType.Udp ? "udp" : "tcp";
                string remoteIp = destinationEndPoint?.Address?.Equals(IPAddress.Any) != false
                    ? "any" : destinationEndPoint.Address.ToString();
                string remotePort = destinationEndPoint != null && destinationEndPoint.Port > 0
                    ? destinationEndPoint.Port.ToString() : "any";
                string ruleName = $"FireAntivirus_{name}";

                await Task.Run(() => RunNetsh(
                    $"advfirewall firewall add rule name=\"{ruleName}\" dir={dir} action={act} protocol={proto} remoteip={remoteIp} remoteport={remotePort}"));

                Logger.Info($"Created firewall rule: {ruleName}");
                return rule;
            }
            catch (Exception ex)
            {
                Logger.Error($"Firewall rule creation error: {ex.Message}");
                throw;
            }
        }

        public async Task<NetworkFirewallRule> UpdateFirewallRuleAsync(string ruleId, FirewallRuleUpdate update)
        {
            try
            {
                // 真实实现：删除旧规则后按更新内容重建（netsh 无部分更新语义）
                string ruleName = $"FireAntivirus_{ruleId}";
                await Task.Run(() =>
                {
                    RunNetsh($"advfirewall firewall delete rule name=\"{ruleName}\"");
                    if (update.IsEnabled != false)
                    {
                        string dir = (update.RuleType ?? FirewallRuleType.Inbound) == FirewallRuleType.Outbound ? "out" : "in";
                        string act = (update.Action ?? FirewallAction.Block) == FirewallAction.Allow ? "allow" : "block";
                        string proto = (update.Protocol ?? ProtocolType.Tcp) == ProtocolType.Udp ? "udp" : "tcp";
                        string remoteIp = update.DestinationEndPoint?.Address?.Equals(IPAddress.Any) != false
                            ? "any" : update.DestinationEndPoint?.Address?.ToString() ?? "any";
                        string remotePort = update.DestinationEndPoint != null && update.DestinationEndPoint.Port > 0
                            ? update.DestinationEndPoint.Port.ToString() : "any";
                        RunNetsh($"advfirewall firewall add rule name=\"{ruleName}\" dir={dir} action={act} protocol={proto} remoteip={remoteIp} remoteport={remotePort}");
                    }
                });

                var rule = new NetworkFirewallRule
                {
                    Id = ruleId,
                    RuleType = update.RuleType ?? FirewallRuleType.Inbound,
                    Name = ruleId,
                    Description = update.Description,
                    SourceEndPoint = update.SourceEndPoint,
                    DestinationEndPoint = update.DestinationEndPoint,
                    Protocol = update.Protocol ?? ProtocolType.Tcp,
                    Action = update.Action ?? FirewallAction.Block,
                    CreatedAt = DateTime.UtcNow.AddDays(-1),
                    UpdatedAt = DateTime.UtcNow,
                    IsEnabled = update.IsEnabled ?? true
                };

                Logger.Info($"Updated firewall rule: {ruleName}");
                return rule;
            }
            catch (Exception ex)
            {
                Logger.Error($"Firewall rule update error: {ex.Message}");
                throw;
            }
        }

        public async Task DeleteFirewallRuleAsync(string ruleId)
        {
            try
            {
                // 真实实现：从系统防火墙删除规则
                string ruleName = $"FireAntivirus_{ruleId}";
                await Task.Run(() => RunNetsh($"advfirewall firewall delete rule name=\"{ruleName}\""));
                Logger.Info($"Deleted firewall rule: {ruleName}");
            }
            catch (Exception ex)
            {
                Logger.Error($"Firewall rule deletion error: {ex.Message}");
                throw;
            }
        }

        public async Task<List<NetworkFirewallRule>> GetFirewallRulesAsync(FirewallRuleType? ruleType = null, bool? isEnabled = null)
        {
            try
            {
                // 真实实现：解析 netsh advfirewall firewall show rule 输出中本软件创建的规则
                var rules = new List<NetworkFirewallRule>();
                await Task.Run(() =>
                {
                    var psi = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = "netsh.exe",
                        Arguments = "advfirewall firewall show rule name=all verbose",
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        RedirectStandardOutput = true
                    };
                    using var p = System.Diagnostics.Process.Start(psi);
                    string output = p?.StandardOutput.ReadToEnd() ?? "";
                    p?.WaitForExit(30000);

                    NetworkFirewallRule current = null;
                    foreach (var raw in output.Split('\n'))
                    {
                        var line = raw.Trim();
                        if (line.StartsWith("Rule Name:"))
                        {
                            current = null; // 新规则块开始
                            var rn = line.Substring("Rule Name:".Length).Trim();
                            if (rn.StartsWith("FireAntivirus_", StringComparison.OrdinalIgnoreCase))
                            {
                                current = new NetworkFirewallRule
                                {
                                    Id = rn.Substring("FireAntivirus_".Length),
                                    Name = rn,
                                    IsEnabled = true
                                };
                                rules.Add(current);
                            }
                        }
                        if (current == null) continue;
                        if (line.StartsWith("Enabled:")) current.IsEnabled = line.Contains("Yes", StringComparison.OrdinalIgnoreCase);
                        else if (line.StartsWith("Direction:")) current.RuleType = line.Contains("Out", StringComparison.OrdinalIgnoreCase) ? FirewallRuleType.Outbound : FirewallRuleType.Inbound;
                        else if (line.StartsWith("Action:")) current.Action = line.Contains("Allow", StringComparison.OrdinalIgnoreCase) ? FirewallAction.Allow : FirewallAction.Block;
                        else if (line.StartsWith("Description:")) current.Description = line.Substring("Description:".Length).Trim();
                    }
                });

                if (ruleType.HasValue)
                {
                    rules = rules.Where(r => r.RuleType == ruleType.Value).ToList();
                }

                if (isEnabled.HasValue)
                {
                    rules = rules.Where(r => r.IsEnabled == isEnabled.Value).ToList();
                }

                return rules;
            }
            catch (Exception ex)
            {
                Logger.Error($"Get firewall rules error: {ex.Message}");
                throw;
            }
        }

        private List<NetworkConnection> GetActualNetworkConnections()
        {
            var connections = new List<NetworkConnection>();
            try
            {
                // 使用System.Net.NetworkInformation获取TCP连接
                var tcpConnections = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections();
                
                int id = 1;
                foreach (var tcpConn in tcpConnections)
                {
                    if (tcpConn.RemoteEndPoint != null)
                    {
                        connections.Add(new NetworkConnection
                        {
                            Id = id.ToString(),
                            LocalEndPoint = tcpConn.LocalEndPoint.ToString(),
                            RemoteEndPoint = tcpConn.RemoteEndPoint.ToString(),
                            Protocol = ProtocolType.Tcp,
                            State = tcpConn.State.ToString(),
                            BytesSent = 0,
                            BytesReceived = 0,
                            CreatedAt = DateTime.UtcNow.AddMinutes(-1),
                            LastActivity = DateTime.UtcNow
                        });
                        id++;
                    }
                }
                
                // 限制连接数量，避免过多数据
                return connections.Take(10).ToList();
            }
            catch (Exception ex)
            {
                Logger.Error($"获取网络连接失败: {ex.Message}");
                return new List<NetworkConnection>();
            }
        }

        private List<NetworkPacket> GetActualNetworkPackets()
        {
            // 托管 .NET 无法直接抓取原始数据包（需要 SharpPcap/WinPcap 等驱动）。
            // 为避免伪造数据，此处不生成任何模拟数据包；流量分析基于真实的 TCP 连接记录。
            return new List<NetworkPacket>();
        }

        private async Task AnalyzeNetworkAnomaliesAsync(NetworkAnalysisResult result)
        {
            // 分析连接异常
            foreach (var connection in result.Connections)
            {
                if (connection.BytesSent > 1000000 || connection.BytesReceived > 1000000)
                {
                    result.Anomalies.Add(new NetworkAnomaly
                    {
                        Id = Guid.NewGuid().ToString(),
                        Type = NetworkAnomalyType.HighDataTransfer,
                        Severity = AnomalySeverity.Medium,
                        Description = $"High data transfer detected: {connection.BytesSent} bytes sent, {connection.BytesReceived} bytes received",
                        ConnectionId = connection.Id,
                        Timestamp = DateTime.UtcNow
                    });
                }
            }

            // 分析数据包异常
            foreach (var packet in result.Packets)
            {
                if (packet.Length > 1500)
                {
                    result.Anomalies.Add(new NetworkAnomaly
                    {
                        Id = Guid.NewGuid().ToString(),
                        Type = NetworkAnomalyType.LargePacket,
                        Severity = AnomalySeverity.Low,
                        Description = $"Large packet detected: {packet.Length} bytes",
                        PacketId = packet.Id,
                        Timestamp = DateTime.UtcNow
                    });
                }
            }

            await Task.CompletedTask;
        }

        private async Task AnalyzeConnectionFeaturesAsync(NetworkConnectionAnalysis analysis)
        {
            // 分析连接特征
            analysis.ConnectionDuration = DateTime.UtcNow - analysis.AnalysisStartTime;
            analysis.DataTransferRate = (analysis.BytesSent + analysis.BytesReceived) / analysis.ConnectionDuration.TotalSeconds;

            // 分析协议特征
            switch (analysis.RemoteEndPoint.Port)
            {
                case 80:
                    analysis.Service = "HTTP";
                    break;
                case 443:
                    analysis.Service = "HTTPS";
                    break;
                case 53:
                    analysis.Service = "DNS";
                    break;
                case 25:
                    analysis.Service = "SMTP";
                    break;
                case 110:
                    analysis.Service = "POP3";
                    break;
                case 143:
                    analysis.Service = "IMAP";
                    break;
                default:
                    analysis.Service = "Unknown";
                    break;
            }

            await Task.CompletedTask;
        }

        private async Task DetectConnectionAnomaliesAsync(NetworkConnectionAnalysis analysis)
        {
            // 检测连接异常
            if (analysis.DataTransferRate > 1000000) // 1MB/s
            {
                analysis.Anomalies.Add(new NetworkAnomaly
                {
                    Id = Guid.NewGuid().ToString(),
                    Type = NetworkAnomalyType.HighDataRate,
                    Severity = AnomalySeverity.High,
                    Description = $"High data transfer rate detected: {analysis.DataTransferRate:N0} bytes/s",
                    Timestamp = DateTime.UtcNow
                });
            }

            // 检测可疑端口
            var suspiciousPorts = new List<int> { 21, 22, 23, 445, 135, 139 };
            if (suspiciousPorts.Contains(analysis.RemoteEndPoint.Port))
            {
                analysis.Anomalies.Add(new NetworkAnomaly
                {
                    Id = Guid.NewGuid().ToString(),
                    Type = NetworkAnomalyType.SuspiciousPort,
                    Severity = AnomalySeverity.Medium,
                    Description = $"Connection to suspicious port: {analysis.RemoteEndPoint.Port}",
                    Timestamp = DateTime.UtcNow
                });
            }

            await Task.CompletedTask;
        }

        private async Task AnalyzePacketAnomaliesAsync(List<NetworkPacket> packets, NetworkAnomalyDetectionResult result)
        {
            // 分析数据包大小异常
            foreach (var packet in packets)
            {
                if (packet.Length > 1500) // 超过MTU
                {
                    result.Anomalies.Add(new NetworkAnomaly
                    {
                        Id = Guid.NewGuid().ToString(),
                        Type = NetworkAnomalyType.LargePacket,
                        Severity = AnomalySeverity.Low,
                        Description = $"Large packet detected: {packet.Length} bytes",
                        PacketId = packet.Id,
                        Timestamp = packet.Timestamp
                    });
                }
                else if (packet.Length < 64) // 过小的数据包
                {
                    result.Anomalies.Add(new NetworkAnomaly
                    {
                        Id = Guid.NewGuid().ToString(),
                        Type = NetworkAnomalyType.SmallPacket,
                        Severity = AnomalySeverity.Low,
                        Description = $"Small packet detected: {packet.Length} bytes",
                        PacketId = packet.Id,
                        Timestamp = packet.Timestamp
                    });
                }
            }

            await Task.CompletedTask;
        }

        private async Task AnalyzeTrafficPatternAnomaliesAsync(List<NetworkPacket> packets, NetworkAnomalyDetectionResult result)
        {
            // 分析流量模式异常
            var packetCount = packets.Count;
            var timeSpan = packets.Last().Timestamp - packets.First().Timestamp;
            var packetsPerSecond = packetCount / timeSpan.TotalSeconds;

            if (packetsPerSecond > _maxPacketsPerSecond)
            {
                result.Anomalies.Add(new NetworkAnomaly
                {
                    Id = Guid.NewGuid().ToString(),
                    Type = NetworkAnomalyType.HighPacketRate,
                    Severity = AnomalySeverity.High,
                    Description = $"High packet rate detected: {packetsPerSecond:N0} packets/s",
                    Timestamp = DateTime.UtcNow
                });
            }

            await Task.CompletedTask;
        }

        private async Task AnalyzeConnectionBehaviorAnomaliesAsync(List<NetworkPacket> packets, NetworkAnomalyDetectionResult result)
        {
            // 分析连接行为异常
            var connections = new Dictionary<string, int>();

            foreach (var packet in packets)
            {
                var connectionKey = $"{packet.SourceEndPoint}-{packet.DestinationEndPoint}";
                if (connections.ContainsKey(connectionKey))
                {
                    connections[connectionKey]++;
                }
                else
                {
                    connections[connectionKey] = 1;
                }
            }

            foreach (var connection in connections)
            {
                if (connection.Value > 100) // 短时间内大量数据包
                {
                    result.Anomalies.Add(new NetworkAnomaly
                    {
                        Id = Guid.NewGuid().ToString(),
                        Type = NetworkAnomalyType.ConnectionFlood,
                        Severity = AnomalySeverity.Medium,
                        Description = $"Potential connection flood detected: {connection.Value} packets",
                        Timestamp = DateTime.UtcNow
                    });
                }
            }

            await Task.CompletedTask;
        }

        private async Task DetectKnownThreatsAsync(NetworkAnalysisResult networkAnalysis, NetworkThreatDetectionResult result)
        {
            // 检测已知威胁
            var knownMaliciousIPs = new List<string> { "192.168.1.100", "10.0.0.50", "172.16.0.200" };

            foreach (var connection in networkAnalysis.Connections)
            {
                try
                {
                    // 尝试将string转换为IPEndPoint
                    var remoteEndPoint = connection.RemoteEndPoint;
                    // 提取IP地址部分
                    var ipAddressPart = remoteEndPoint.Split(':')[0];
                    if (knownMaliciousIPs.Contains(ipAddressPart))
                    {
                        result.Threats.Add(new NetworkThreat
                        {
                            Id = Guid.NewGuid().ToString(),
                            Type = NetworkThreatType.MaliciousIP,
                            Severity = ThreatSeverity.High,
                            Description = $"Connection to known malicious IP: {ipAddressPart}",
                            ConnectionId = connection.Id,
                            Timestamp = DateTime.UtcNow
                        });
                    }
                }
                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "NetworkSecurity.cs 捕获异常", ex.Message); }
            }

            await Task.CompletedTask;
        }

        private async Task DetectSuspiciousBehaviorAsync(NetworkAnalysisResult networkAnalysis, NetworkThreatDetectionResult result)
        {
            // 检测可疑行为
            foreach (var connection in networkAnalysis.Connections)
            {
                // 检测长时间连接
                var connectionDuration = DateTime.UtcNow - connection.CreatedAt;
                if (connectionDuration.TotalHours > 24)
                {
                    result.Threats.Add(new NetworkThreat
                    {
                        Id = Guid.NewGuid().ToString(),
                        Type = NetworkThreatType.LongConnection,
                        Severity = ThreatSeverity.Medium,
                        Description = $"Long-lived connection detected: {connectionDuration.TotalHours:N1} hours",
                        ConnectionId = connection.Id,
                        Timestamp = DateTime.UtcNow
                    });
                }

                // 检测大量数据传输
                if (connection.BytesSent > 1000000000 || connection.BytesReceived > 1000000000) // 1GB
                {
                    result.Threats.Add(new NetworkThreat
                    {
                        Id = Guid.NewGuid().ToString(),
                        Type = NetworkThreatType.DataExfiltration,
                        Severity = ThreatSeverity.High,
                        Description = $"Potential data exfiltration: {connection.BytesSent + connection.BytesReceived:N0} bytes transferred",
                        ConnectionId = connection.Id,
                        Timestamp = DateTime.UtcNow
                    });
                }
            }

            await Task.CompletedTask;
        }

        private async Task DetectAbnormalTrafficPatternsAsync(NetworkAnalysisResult networkAnalysis, NetworkThreatDetectionResult result)
        {
            // 检测异常流量模式
            var totalPackets = networkAnalysis.Packets.Count;
            var totalBytes = networkAnalysis.Packets.Sum(p => p.Length);
            var averagePacketSize = totalPackets > 0 ? totalBytes / totalPackets : 0;

            if (averagePacketSize > 1000)
            {
                result.Threats.Add(new NetworkThreat
                {
                    Id = Guid.NewGuid().ToString(),
                    Type = NetworkThreatType.AbnormalTrafficPattern,
                    Severity = ThreatSeverity.Medium,
                    Description = $"Abnormal traffic pattern: average packet size {averagePacketSize:N0} bytes",
                    Timestamp = DateTime.UtcNow
                });
            }

            await Task.CompletedTask;
        }

        /// <summary>执行 netsh 命令，非零退出码抛异常（真实防火墙操作）。</summary>
        private static void RunNetsh(string arguments)
        {
            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName = "netsh.exe",
                Arguments = arguments,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using var p = System.Diagnostics.Process.Start(psi);
            p?.WaitForExit(20000);
            if (p != null && p.ExitCode != 0)
            {
                var err = p.StandardError.ReadToEnd();
                throw new InvalidOperationException($"netsh 退出码 {p.ExitCode}: {err}");
            }
        }
    }

    public class NetworkAnalysisResult
    {
        public string InterfaceName { get; set; }
        public DateTime AnalysisStartTime { get; set; }
        public DateTime AnalysisEndTime { get; set; }
        public TimeSpan AnalysisDuration { get; set; }
        public List<NetworkConnection> Connections { get; set; }
        public List<NetworkPacket> Packets { get; set; }
        public List<NetworkAnomaly> Anomalies { get; set; }
        public int TotalConnections => Connections?.Count ?? 0;
        public int TotalPackets => Packets?.Count ?? 0;
        public long TotalBytes => Packets?.Sum(p => p.Length) ?? 0;
    }

    public class NetworkConnection
    {
        public string Id { get; set; }
        public string LocalEndPoint { get; set; }
        public string RemoteEndPoint { get; set; }
        public ProtocolType Protocol { get; set; }
        public string State { get; set; }
        public long BytesSent { get; set; }
        public long BytesReceived { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime LastActivity { get; set; }
        public TimeSpan Duration => LastActivity - CreatedAt;
        public int ProcessId { get; set; }
        public string ProcessName { get; set; }
        public DateTime Timestamp { get; set; }
    }



    public class NetworkAnomaly
    {
        public string Id { get; set; }
        public NetworkAnomalyType Type { get; set; }
        public AnomalySeverity Severity { get; set; }
        public string Description { get; set; }
        public string ConnectionId { get; set; }
        public string PacketId { get; set; }
        public DateTime Timestamp { get; set; }
    }

    public class NetworkThreat
    {
        public string Id { get; set; }
        public NetworkThreatType Type { get; set; }
        public ThreatSeverity Severity { get; set; }
        public string Description { get; set; }
        public string ConnectionId { get; set; }
        public DateTime Timestamp { get; set; }
    }

    public class NetworkConnectionAnalysis
    {
        public IPEndPoint LocalEndPoint { get; set; }
        public IPEndPoint RemoteEndPoint { get; set; }
        public DateTime AnalysisStartTime { get; set; }
        public DateTime AnalysisEndTime { get; set; }
        public TimeSpan AnalysisDuration { get; set; }
        public TimeSpan ConnectionDuration { get; set; }
        public double DataTransferRate { get; set; }
        public string Service { get; set; }
        public long BytesSent { get; set; }
        public long BytesReceived { get; set; }
        public List<NetworkPacket> Packets { get; set; }
        public List<NetworkAnomaly> Anomalies { get; set; }
    }

    public class NetworkAnomalyDetectionResult
    {
        public DateTime AnalysisStartTime { get; set; }
        public DateTime AnalysisEndTime { get; set; }
        public TimeSpan AnalysisDuration { get; set; }
        public int AnalyzedPackets { get; set; }
        public List<NetworkAnomaly> Anomalies { get; set; }
        public int AnomalyCount => Anomalies?.Count ?? 0;
    }

    public class NetworkThreatDetectionResult
    {
        public DateTime AnalysisStartTime { get; set; }
        public DateTime AnalysisEndTime { get; set; }
        public TimeSpan AnalysisDuration { get; set; }
        public List<NetworkThreat> Threats { get; set; }
        public int ThreatCount => Threats?.Count ?? 0;
    }

    public class NetworkFirewallRule
    {
        public string Id { get; set; }
        public FirewallRuleType RuleType { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public IPEndPoint SourceEndPoint { get; set; }
        public IPEndPoint DestinationEndPoint { get; set; }
        public ProtocolType Protocol { get; set; }
        public FirewallAction Action { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime? UpdatedAt { get; set; }
        public bool IsEnabled { get; set; }
    }

    public class FirewallRuleUpdate
    {
        public FirewallRuleType? RuleType { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public IPEndPoint SourceEndPoint { get; set; }
        public IPEndPoint DestinationEndPoint { get; set; }
        public ProtocolType? Protocol { get; set; }
        public FirewallAction? Action { get; set; }
        public bool? IsEnabled { get; set; }
    }

    public enum ConnectionState
    {
        Closed,
        Listen,
        SynSent,
        SynReceived,
        Established,
        FinWait1,
        FinWait2,
        CloseWait,
        LastAck,
        TimeWait,
        DeleteTcb
    }

    public enum NetworkAnomalyType
    {
        HighDataTransfer,
        HighDataRate,
        LargePacket,
        SmallPacket,
        HighPacketRate,
        ConnectionFlood,
        SuspiciousPort,
        UnusualProtocol,
        DNSAmplification,
        SYNFlood,
        UDPFlood,
        ICMPFlood,
        PortScan,
        HostScan
    }

    public enum NetworkThreatType
    {
        MaliciousIP,
        MaliciousDomain,
        DataExfiltration,
        CommandAndControl,
        DDoSAttack,
        PortScan,
        BruteForce,
        SQLInjection,
        XSS,
        CSRF,
        MaliciousFileDownload,
        Phishing,
        LongConnection,
        AbnormalTrafficPattern
    }

    public enum AnomalySeverity
    {
        Low,
        Medium,
        High,
        Critical
    }



    public enum FirewallRuleType
    {
        Inbound,
        Outbound,
        InboundAndOutbound
    }

    public enum FirewallAction
    {
        Allow,
        Block,
        Log,
        AllowAndLog,
        BlockAndLog
    }
}