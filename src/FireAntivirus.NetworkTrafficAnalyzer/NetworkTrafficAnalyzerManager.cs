using System;
using System.Collections.Generic;
using System.Linq;
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
            // 初始化网络流量分析器
        }

        public void StartMonitoring()
        {
            _isEnabled = true;
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
            // 模拟获取当前网络连接
            if (!_isEnabled)
            {
                return new List<NetworkConnection>();
            }

            // 模拟生成一些网络连接
            _connections.Clear();
            _connections.Add(new NetworkConnection
            {
                Id = Guid.NewGuid().ToString(),
                ProcessName = "chrome.exe",
                LocalAddress = "127.0.0.1",
                LocalPort = 54321,
                RemoteAddress = "216.58.217.46",
                RemotePort = 443,
                Protocol = "TCP",
                State = "ESTABLISHED",
                BytesSent = 10240,
                BytesReceived = 51200,
                StartTime = DateTime.Now.AddMinutes(-5)
            });

            _connections.Add(new NetworkConnection
            {
                Id = Guid.NewGuid().ToString(),
                ProcessName = "firefox.exe",
                LocalAddress = "127.0.0.1",
                LocalPort = 54322,
                RemoteAddress = "151.101.1.69",
                RemotePort = 443,
                Protocol = "TCP",
                State = "ESTABLISHED",
                BytesSent = 5120,
                BytesReceived = 25600,
                StartTime = DateTime.Now.AddMinutes(-3)
            });

            _connections.Add(new NetworkConnection
            {
                Id = Guid.NewGuid().ToString(),
                ProcessName = "svchost.exe",
                LocalAddress = "127.0.0.1",
                LocalPort = 54323,
                RemoteAddress = "104.16.132.229",
                RemotePort = 443,
                Protocol = "TCP",
                State = "ESTABLISHED",
                BytesSent = 2048,
                BytesReceived = 10240,
                StartTime = DateTime.Now.AddMinutes(-10)
            });

            return _connections;
        }

        public List<NetworkAlert> GetAlerts()
        {
            return _alerts;
        }

        public NetworkTrafficReport GenerateReport(TimeSpan timeSpan)
        {
            var report = new NetworkTrafficReport
            {
                StartTime = DateTime.Now - timeSpan,
                EndTime = DateTime.Now,
                TotalBytesSent = 1024000, // 1MB
                TotalBytesReceived = 5120000, // 5MB
                TotalConnections = 20,
                TopProcesses = new List<ProcessNetworkUsage>(),
                TopDestinations = new List<DestinationNetworkUsage>(),
                Alerts = _alerts.Where(a => a.Timestamp >= DateTime.Now - timeSpan).ToList()
            };

            // 模拟生成报告数据
            report.TopProcesses.Add(new ProcessNetworkUsage
            {
                ProcessName = "chrome.exe",
                BytesSent = 512000,
                BytesReceived = 2560000,
                ConnectionCount = 10
            });

            report.TopProcesses.Add(new ProcessNetworkUsage
            {
                ProcessName = "firefox.exe",
                BytesSent = 256000,
                BytesReceived = 1280000,
                ConnectionCount = 5
            });

            report.TopProcesses.Add(new ProcessNetworkUsage
            {
                ProcessName = "svchost.exe",
                BytesSent = 128000,
                BytesReceived = 640000,
                ConnectionCount = 3
            });

            report.TopDestinations.Add(new DestinationNetworkUsage
            {
                Address = "216.58.217.46",
                BytesSent = 256000,
                BytesReceived = 1280000,
                ConnectionCount = 8
            });

            report.TopDestinations.Add(new DestinationNetworkUsage
            {
                Address = "151.101.1.69",
                BytesSent = 128000,
                BytesReceived = 640000,
                ConnectionCount = 5
            });

            report.TopDestinations.Add(new DestinationNetworkUsage
            {
                Address = "104.16.132.229",
                BytesSent = 64000,
                BytesReceived = 320000,
                ConnectionCount = 3
            });

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

            // 模拟分析网络流量
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
            // 模拟检查可疑IP地址
            string[] suspiciousIPs = { "192.168.1.100", "10.0.0.50", "172.16.0.200" };
            return suspiciousIPs.Contains(ipAddress);
        }

        public void BlockIP(string ipAddress)
        {
            // 模拟阻止IP地址
            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "IPBlocked",
                Message = "IP地址已被阻止",
                Details = $"IP: {ipAddress}"
            });
        }

        public void AllowIP(string ipAddress)
        {
            // 模拟允许IP地址
            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "IPAllowed",
                Message = "IP地址已被允许",
                Details = $"IP: {ipAddress}"
            });
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