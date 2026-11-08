using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Text;
using System.Threading.Tasks;
using FireAntivirus.Common;
using FireAntivirus.Data;

namespace FireAntivirus.NetworkTrafficAnalyzer
{
    public class NetworkTrafficAnalyzerManager
    {
        private DataManager _dataManager;
        private List<NetworkConnection> _connections;
        private List<NetworkAlert> _alerts;
        private bool _isEnabled;

        // 真实可疑 IP 黑名单（从配置文件加载）
        private HashSet<string> _suspiciousIPs;

        // 网卡流量累计基线，用于计算报告期内的真实流量增量
        private long _baselineBytesSent;
        private long _baselineBytesReceived;
        private DateTime _baselineTime = DateTime.MinValue;

        public NetworkTrafficAnalyzerManager(DataManager dataManager)
        {
            _dataManager = dataManager;
            _connections = new List<NetworkConnection>();
            _alerts = new List<NetworkAlert>();
            _isEnabled = true;
            InitializeAnalyzer();
        }

        private void InitializeAnalyzer()
        {
            // 真实初始化：加载 IP 黑名单配置并记录流量统计基线
            _suspiciousIPs = LoadBlockedIPList();
            RecordTrafficBaseline();
        }

        private HashSet<string> LoadBlockedIPList()
        {
            // 从配置目录加载黑名单（每行一个 IP，# 开头为注释）
            var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                var path = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "FireAntivirus", "blocked_ips.txt");

                if (File.Exists(path))
                {
                    foreach (var line in File.ReadLines(path))
                    {
                        var trimmed = line.Trim();
                        if (trimmed.Length > 0 && !trimmed.StartsWith("#"))
                            result.Add(trimmed);
                    }
                }
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error,
                    "加载 IP 黑名单失败: " + ex.Message);
            }

            return result;
        }

        private void RecordTrafficBaseline()
        {
            try
            {
                _baselineBytesSent = 0;
                _baselineBytesReceived = 0;

                foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (nic.OperationalStatus != OperationalStatus.Up ||
                        nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;

                    var stats = nic.GetIPStatistics();
                    _baselineBytesSent += stats.BytesSent;
                    _baselineBytesReceived += stats.BytesReceived;
                }

                _baselineTime = DateTime.Now;
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error,
                    "记录流量基线失败: " + ex.Message);
            }
        }

        public void StartMonitoring()
        {
            _isEnabled = true;
            RecordTrafficBaseline();
            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "NetworkTrafficMonitoringStarted",
                Message = "网络流量监控已启动"
            });
        }

        public void StopMonitoring()
        {
            _isEnabled = false;
            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "NetworkTrafficMonitoringStopped",
                Message = "网络流量监控已停止"
            });
        }

        public bool IsEnabled()
        {
            return _isEnabled;
        }

        public List<NetworkConnection> GetCurrentConnections()
        {
            if (!_isEnabled)
            {
                return new List<NetworkConnection>();
            }

            _connections.Clear();

            try
            {
                // 优先通过 netstat -ano 获取真实连接表（可关联进程名）
                _connections = GetConnectionsViaNetstat();
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error,
                    "通过 netstat 枚举连接失败: " + ex.Message);
            }

            if (_connections.Count == 0)
            {
                // netstat 不可用时回退到 IPGlobalProperties（无进程名信息）
                try
                {
                    var props = IPGlobalProperties.GetIPGlobalProperties();

                    foreach (var c in props.GetActiveTcpConnections())
                    {
                        _connections.Add(new NetworkConnection
                        {
                            Id = Guid.NewGuid().ToString(),
                            ProcessName = "-",
                            LocalAddress = c.LocalEndPoint.Address.ToString(),
                            LocalPort = c.LocalEndPoint.Port,
                            RemoteAddress = c.RemoteEndPoint.Address.ToString(),
                            RemotePort = c.RemoteEndPoint.Port,
                            Protocol = "TCP",
                            State = c.State.ToString(),
                            BytesSent = 0,
                            BytesReceived = 0,
                            StartTime = DateTime.Now
                        });
                    }

                    foreach (var e in props.GetActiveUdpListeners())
                    {
                        _connections.Add(new NetworkConnection
                        {
                            Id = Guid.NewGuid().ToString(),
                            ProcessName = "-",
                            LocalAddress = e.Address.ToString(),
                            LocalPort = e.Port,
                            RemoteAddress = "-",
                            RemotePort = 0,
                            Protocol = "UDP",
                            State = "LISTEN",
                            BytesSent = 0,
                            BytesReceived = 0,
                            StartTime = DateTime.Now
                        });
                    }
                }
                catch (Exception ex)
                {
                    FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error,
                        "枚举网络连接失败: " + ex.Message);
                }
            }

            return _connections;
        }

        private List<NetworkConnection> GetConnectionsViaNetstat()
        {
            var results = new List<NetworkConnection>();

            var psi = new ProcessStartInfo
            {
                FileName = "netstat.exe",
                Arguments = "-ano",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            if (process == null) return results;

            var output = process.StandardOutput.ReadToEnd();
            process.WaitForExit(30000);

            // PID -> 进程名映射
            var pidNames = new Dictionary<int, string>();
            foreach (var proc in Process.GetProcesses())
            {
                try { pidNames[proc.Id] = proc.ProcessName; } catch { }
            }

            foreach (var line in output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
            {
                var tokens = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                if (tokens.Length < 4) continue;

                var proto = tokens[0].ToUpperInvariant();
                if (proto != "TCP" && proto != "UDP") continue;

                try
                {
                    bool isTcp = proto == "TCP";

                    // TCP 行: Proto Local Foreign State PID；UDP 行: Proto Local Foreign PID
                    string state = isTcp && tokens.Length >= 5 ? tokens[3] : (isTcp ? "UNKNOWN" : "LISTEN");
                    var pidText = tokens[tokens.Length - 1];
                    if (!int.TryParse(pidText, out var pid)) continue;

                    var localParts = tokens[1].Split(':');
                    var remoteParts = tokens[2].Split(':');

                    var localPort = int.Parse(localParts[localParts.Length - 1]);
                    var remotePort = remoteParts.Length > 1 && int.TryParse(remoteParts[remoteParts.Length - 1], out var rp) ? rp : 0;

                    var localAddr = string.Join(":", localParts, 0, localParts.Length - 1);
                    var remoteAddr = remoteParts.Length > 1 ? string.Join(":", remoteParts, 0, remoteParts.Length - 1) : "-";

                    pidNames.TryGetValue(pid, out var processName);

                    results.Add(new NetworkConnection
                    {
                        Id = Guid.NewGuid().ToString(),
                        ProcessName = string.IsNullOrEmpty(processName) ? $"PID:{pid}" : processName,
                        LocalAddress = localAddr,
                        LocalPort = localPort,
                        RemoteAddress = remoteAddr,
                        RemotePort = remotePort,
                        Protocol = proto,
                        State = state,
                        BytesSent = 0,
                        BytesReceived = 0,
                        StartTime = DateTime.Now
                    });
                }
                catch
                {
                    // 跳过解析失败的行（如 IPv6 特殊格式）
                }
            }

            return results;
        }

        public List<NetworkAlert> GetAlerts()
        {
            return _alerts;
        }

        public NetworkTrafficReport GenerateReport(TimeSpan timeSpan)
        {
            // 基于真实系统数据生成报告：网卡流量统计 + 当前连接聚合
            var report = new NetworkTrafficReport
            {
                StartTime = DateTime.Now - timeSpan,
                EndTime = DateTime.Now,
                TopProcesses = new List<ProcessNetworkUsage>(),
                TopDestinations = new List<DestinationNetworkUsage>(),
                Alerts = _alerts.Where(a => a.Timestamp >= DateTime.Now - timeSpan).ToList()
            };

            try
            {
                // 1. 真实网卡字节统计（基线之后的增量；基线不在报告期内时报告累计值）
                long totalSent = 0, totalReceived = 0;
                foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (nic.OperationalStatus != OperationalStatus.Up ||
                        nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;

                    var stats = nic.GetIPStatistics();
                    totalSent += stats.BytesSent;
                    totalReceived += stats.BytesReceived;
                }

                if (_baselineTime != DateTime.MinValue && _baselineTime >= report.StartTime)
                {
                    report.TotalBytesSent = Math.Max(0, totalSent - _baselineBytesSent);
                    report.TotalBytesReceived = Math.Max(0, totalReceived - _baselineBytesReceived);
                }
                else
                {
                    report.TotalBytesSent = totalSent;
                    report.TotalBytesReceived = totalReceived;
                }

                // 2. 真实连接统计：按进程与目标地址聚合
                var connections = GetCurrentConnections();
                report.TotalConnections = connections.Count;

                report.TopProcesses = connections
                    .Where(c => !string.IsNullOrEmpty(c.ProcessName) && c.ProcessName != "-")
                    .GroupBy(c => c.ProcessName)
                    .Select(g => new ProcessNetworkUsage
                    {
                        ProcessName = g.Key,
                        ConnectionCount = g.Count(),
                        BytesSent = 0,
                        BytesReceived = 0
                    })
                    .OrderByDescending(p => p.ConnectionCount)
                    .Take(10)
                    .ToList();

                report.TopDestinations = connections
                    .Where(c => c.RemoteAddress != "-" && c.RemoteAddress != "0.0.0.0" && c.RemoteAddress != "*")
                    .GroupBy(c => c.RemoteAddress)
                    .Select(g => new DestinationNetworkUsage
                    {
                        Address = g.Key,
                        ConnectionCount = g.Count(),
                        BytesSent = 0,
                        BytesReceived = 0
                    })
                    .OrderByDescending(d => d.ConnectionCount)
                    .Take(10)
                    .ToList();
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error,
                    "生成网络流量报告失败: " + ex.Message);
            }

            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "NetworkTrafficReportGenerated",
                Message = "网络流量报告已生成",
                Details = $"时间范围: {timeSpan.TotalHours}小时, 总流量: {report.TotalBytesSent + report.TotalBytesReceived}字节"
            });

            return report;
        }

        public void AnalyzeTraffic()
        {
            if (!_isEnabled)
            {
                return;
            }

            // 分析真实网络连接，检测异常流量与可疑目标
            var connections = GetCurrentConnections();
            foreach (var connection in connections)
            {
                // 检查异常流量
                if (connection.BytesSent > 1000000 || connection.BytesReceived > 5000000)
                {
                    var alert = new NetworkAlert
                    {
                        Id = Guid.NewGuid().ToString(),
                        AlertType = "HighTraffic",
                        Severity = AlertSeverity.Medium,
                        Message = "检测到异常网络流量",
                        Details = $"进程: {connection.ProcessName}, 目标: {connection.RemoteAddress}:{connection.RemotePort}, 发送: {connection.BytesSent}字节, 接收: {connection.BytesReceived}字节",
                        Timestamp = DateTime.Now
                    };
                    _alerts.Add(alert);
                    _dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "NetworkAlert",
                        Message = "网络流量警报",
                        Details = alert.Details
                    });
                }

                // 检查可疑IP地址
                if (IsSuspiciousIP(connection.RemoteAddress))
                {
                    var alert = new NetworkAlert
                    {
                        Id = Guid.NewGuid().ToString(),
                        AlertType = "SuspiciousIP",
                        Severity = AlertSeverity.High,
                        Message = "检测到可疑IP地址",
                        Details = $"进程: {connection.ProcessName}, IP: {connection.RemoteAddress}",
                        Timestamp = DateTime.Now
                    };
                    _alerts.Add(alert);
                    _dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "NetworkAlert",
                        Message = "网络流量警报",
                        Details = alert.Details
                    });
                }
            }
        }

        private bool IsSuspiciousIP(string ipAddress)
        {
            // 真实可疑 IP 判定：配置黑名单 + 异常地址特征（不把普通内网地址误报为可疑）
            if (string.IsNullOrEmpty(ipAddress) || ipAddress == "-" || ipAddress == "0.0.0.0" || ipAddress == "::" || ipAddress == "*")
                return false;

            if (_suspiciousIPs.Contains(ipAddress)) return true;

            return System.Net.IPAddress.TryParse(ipAddress, out var addr) && IsAbnormalAddress(addr);
        }

        private static bool IsAbnormalAddress(System.Net.IPAddress address)
        {
            var bytes = address.GetAddressBytes();
            if (bytes.Length != 4) return false;

            // 远程端点不应出现：组播/保留段(>=224)、0.x、127.x 回环、受限广播
            if (bytes[0] >= 224) return true;
            if (bytes[0] == 0 || bytes[0] == 127) return true;
            if (bytes[0] == 255 && bytes[1] == 255 && bytes[2] == 255 && bytes[3] == 255) return true;

            return false;
        }

        public void BlockIP(string ipAddress)
        {
            // 真实阻止：创建 Windows 防火墙出站阻止规则（需管理员权限）
            var ruleName = $"FireAntivirus_Block_{ipAddress}";
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "netsh.exe",
                    Arguments = $"advfirewall firewall add rule name=\"{ruleName}\" dir=out action=block remoteip={ipAddress}",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                using var process = Process.Start(psi);
                var output = process?.StandardOutput.ReadToEnd();
                process?.WaitForExit(30000);

                bool success = process?.ExitCode == 0;
                if (success)
                {
                    _suspiciousIPs.Add(ipAddress);
                }

                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "IPBlocked",
                    Message = success ? "IP地址已被阻止（已创建防火墙规则）" : "IP阻止操作未成功（可能需要管理员权限）",
                    Details = $"IP: {ipAddress}, 规则: {ruleName}, 输出: {(output ?? "").Trim()}"
                });
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "IPBlocked",
                    Message = "IP阻止操作执行失败",
                    Details = $"IP: {ipAddress}, 错误: {ex.Message}"
                });
            }
        }

        public void AllowIP(string ipAddress)
        {
            // 真实解除阻止：删除对应的防火墙阻止规则
            var ruleName = $"FireAntivirus_Block_{ipAddress}";
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "netsh.exe",
                    Arguments = $"advfirewall firewall delete rule name=\"{ruleName}\"",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                using var process = Process.Start(psi);
                var output = process?.StandardOutput.ReadToEnd();
                process?.WaitForExit(30000);

                bool success = process?.ExitCode == 0;
                if (success)
                {
                    _suspiciousIPs.Remove(ipAddress);
                }

                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "IPAllowed",
                    Message = success ? "IP地址已解除阻止（已删除防火墙规则）" : "解除阻止操作未成功（可能需要管理员权限）",
                    Details = $"IP: {ipAddress}, 规则: {ruleName}, 输出: {(output ?? "").Trim()}"
                });
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "IPAllowed",
                    Message = "解除阻止操作执行失败",
                    Details = $"IP: {ipAddress}, 错误: {ex.Message}"
                });
            }
        }

        public void ClearAlerts()
        {
            _alerts.Clear();
            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "AlertsCleared",
                Message = "网络流量警报已清除"
            });
        }
    }
}