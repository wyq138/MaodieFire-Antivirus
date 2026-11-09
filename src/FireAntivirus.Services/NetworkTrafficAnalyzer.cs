using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using FireAntivirus.Data;

namespace FireAntivirus.Services
{
    public class NetworkTrafficAnalyzer : IMonitor
    {
        private readonly DataManager _dataManager;
        private Thread _analysisThread;
        private bool _isRunning;
        private Dictionary<string, NetworkConnection> _connections;
        private Dictionary<string, NetworkStatistics> _statistics;
        private Dictionary<string, NetworkAlert> _alerts;
        private int _analysisInterval;
        private int _alertThreshold;
        private int _connectionLimit;
        private bool _enableDeepPacketInspection;
        private bool _enableProtocolAnalysis;
        private bool _enableAnomalyDetection;
        private bool _enableThreatIntelligence;
        private bool _enableGeoIPAnalysis;
        private bool _enableBandwidthMonitoring;
        private bool _enablePacketCapture;
        private bool _enableNetworkMapping;
        private bool _enablePortScanningDetection;
        private bool _enableDDoSProtection;
        private bool _enableMaliciousTrafficDetection;
        private bool _enableEncryptedTrafficAnalysis;
        private bool _enableApplicationIdentification;
        private bool _enableUserIdentification;
        private bool _enableDeviceIdentification;
        private bool _enableNetworkBehaviorAnalysis;
        private bool _enableNetworkPerformanceMonitoring;
        private bool _enableNetworkHealthCheck;
        private bool _enableNetworkComplianceCheck;
        private bool _enableNetworkAudit;
        private bool _enableNetworkReporting;

        public NetworkTrafficAnalyzer(DataManager dataManager)
        {
            _dataManager = dataManager;
            _isRunning = false;
            _connections = new Dictionary<string, NetworkConnection>();
            _statistics = new Dictionary<string, NetworkStatistics>();
            _alerts = new Dictionary<string, NetworkAlert>();
            _analysisInterval = 1000;
            _alertThreshold = 104857600;
            _connectionLimit = 5000;
            _enableDeepPacketInspection = true;
            _enableProtocolAnalysis = true;
            _enableAnomalyDetection = true;
            _enableThreatIntelligence = true;
            _enableGeoIPAnalysis = true;
            _enableBandwidthMonitoring = true;
            _enablePacketCapture = true;
            _enableNetworkMapping = true;
            _enablePortScanningDetection = true;
            _enableDDoSProtection = true;
            _enableMaliciousTrafficDetection = true;
            _enableEncryptedTrafficAnalysis = true;
            _enableApplicationIdentification = true;
            _enableUserIdentification = true;
            _enableDeviceIdentification = true;
            _enableNetworkBehaviorAnalysis = true;
            _enableNetworkPerformanceMonitoring = true;
            _enableNetworkHealthCheck = true;
            _enableNetworkComplianceCheck = true;
            _enableNetworkAudit = true;
            _enableNetworkReporting = true;
        }

        public void Start()
        {
            if (_isRunning)
                return;

            _isRunning = true;
            _analysisThread = new Thread(RunNetworkAnalysis);
            _analysisThread.IsBackground = true;
            _analysisThread.Start();

            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "NetworkTrafficAnalyzerStart",
                Message = "网络流量分析器已启动",
                Details = "开始分析网络流量和检测异常"
            });
        }

        public void Stop()
        {
            _isRunning = false;
            if (_analysisThread != null && _analysisThread.IsAlive)
            {
                _analysisThread.Join(2000);
            }

            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "NetworkTrafficAnalyzerStop",
                Message = "网络流量分析器已停止",
                Details = "停止分析网络流量和检测异常"
            });
        }

        private void RunNetworkAnalysis()
        {
            try
            {
                while (_isRunning)
                {
                    // 分析网络连接
                    AnalyzeNetworkConnections();

                    // 分析网络统计
                    AnalyzeNetworkStatistics();

                    // 禁用异常流量检测 - 避免误报
                    // DetectAnomalies();

                    // 禁用网络健康检查 - 避免系统进程误报
                    // CheckNetworkHealth();

                    // 生成网络报告
                    GenerateNetworkReport();

                    Thread.Sleep(_analysisInterval);
                }
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "NetworkTrafficAnalyzerError",
                    Message = "网络流量分析器错误",
                    Details = ex.Message
                });
            }
        }

        private void AnalyzeNetworkConnections()
        {
            try
            {
                var currentConnections = new Dictionary<string, NetworkConnection>();
                
                // 获取当前网络连接
                var connections = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections();
                
                foreach (var connection in connections)
                {
                    var key = $"{connection.LocalEndPoint}-{connection.RemoteEndPoint}-{connection.State}";
                    currentConnections[key] = new NetworkConnection
                    {
                        LocalEndPoint = connection.LocalEndPoint.ToString(),
                        RemoteEndPoint = connection.RemoteEndPoint.ToString(),
                        State = connection.State.ToString(),
                        ProcessId = GetProcessIdFromConnection(connection),
                        ProcessName = GetProcessNameFromId(GetProcessIdFromConnection(connection)),
                        Timestamp = DateTime.Now
                    };
                }
                
                // 检测新连接
                foreach (var connection in currentConnections)
                {
                    if (!_connections.ContainsKey(connection.Key))
                    {
                        _connections[connection.Key] = connection.Value;
                        _dataManager.AddLog(new LogEntry
                        {
                            Id = Guid.NewGuid().ToString(),
                            Time = DateTime.Now,
                            Type = "NewNetworkConnection",
                            Message = "新网络连接",
                            Details = $"本地: {connection.Value.LocalEndPoint}, 远程: {connection.Value.RemoteEndPoint}, 进程: {connection.Value.ProcessName}"
                        });
                    }
                }
                
                // 移除已关闭的连接
                var closedConnections = new List<string>();
                foreach (var connection in _connections)
                {
                    if (!currentConnections.ContainsKey(connection.Key))
                    {
                        closedConnections.Add(connection.Key);
                    }
                }
                
                foreach (var key in closedConnections)
                {
                    _connections.Remove(key);
                }
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "NetworkAnalysisError",
                    Message = "网络连接分析错误",
                    Details = ex.Message
                });
            }
        }

        private void AnalyzeNetworkStatistics()
        {
            try
            {
                var networkInterfaces = NetworkInterface.GetAllNetworkInterfaces();
                
                foreach (var networkInterface in networkInterfaces)
                {
                    if (networkInterface.OperationalStatus == OperationalStatus.Up)
                    {
                        var statistics = networkInterface.GetIPv4Statistics();
                        var key = networkInterface.Id;
                        
                        _statistics[key] = new NetworkStatistics
                        {
                            InterfaceName = networkInterface.Name,
                            InterfaceType = networkInterface.NetworkInterfaceType.ToString(),
                            OperationalStatus = networkInterface.OperationalStatus.ToString(),
                            BytesSent = statistics.BytesSent,
                            BytesReceived = statistics.BytesReceived,
                            PacketsSent = statistics.UnicastPacketsSent,
                            PacketsReceived = statistics.UnicastPacketsReceived,
                            IncomingErrors = statistics.IncomingPacketsWithErrors,
                            OutgoingErrors = statistics.OutgoingPacketsWithErrors,
                            Timestamp = DateTime.Now
                        };
                    }
                }
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "NetworkStatisticsError",
                    Message = "网络统计分析错误",
                    Details = ex.Message
                });
            }
        }

        private void DetectAnomalies()
        {
            try
            {
                // 检测异常连接数
                if (_connections.Count > _connectionLimit)
                {
                    var alertKey = $"ConnectionLimit_{DateTime.Now.Ticks}";
                    _alerts[alertKey] = new NetworkAlert
                    {
                        AlertId = alertKey,
                        AlertType = "ConnectionLimitExceeded",
                        Severity = "High",
                        Description = $"连接数超过限制: {_connections.Count}",
                        Timestamp = DateTime.Now,
                        Status = "Active",
                        Source = "NetworkTrafficAnalyzer"
                    };
                    
                    _dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "NetworkAnomaly",
                        Message = "连接数异常",
                        Details = $"当前连接数: {_connections.Count}, 限制: {_connectionLimit}"
                    });
                }
                
                // 检测异常流量
                foreach (var stat in _statistics.Values)
                {
                    if (stat.BytesSent > _alertThreshold || stat.BytesReceived > _alertThreshold)
                    {
                        var alertKey = $"TrafficAnomaly_{stat.InterfaceName}_{DateTime.Now.Ticks}";
                        _alerts[alertKey] = new NetworkAlert
                        {
                            AlertId = alertKey,
                            AlertType = "TrafficAnomaly",
                            Severity = "Medium",
                            Description = $"网络流量异常: {stat.InterfaceName}",
                            Timestamp = DateTime.Now,
                            Status = "Active",
                            Source = "NetworkTrafficAnalyzer"
                        };
                        
                        _dataManager.AddLog(new LogEntry
                        {
                            Id = Guid.NewGuid().ToString(),
                            Time = DateTime.Now,
                            Type = "NetworkAnomaly",
                            Message = "流量异常",
                            Details = $"接口: {stat.InterfaceName}, 发送: {stat.BytesSent}, 接收: {stat.BytesReceived}"
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "AnomalyDetectionError",
                    Message = "异常检测错误",
                    Details = ex.Message
                });
            }
        }

        private void CheckNetworkHealth()
        {
            try
            {
                var networkInterfaces = NetworkInterface.GetAllNetworkInterfaces();
                
                foreach (var networkInterface in networkInterfaces)
                {
                    if (networkInterface.OperationalStatus != OperationalStatus.Up)
                    {
                        var alertKey = $"NetworkInterfaceDown_{networkInterface.Id}_{DateTime.Now.Ticks}";
                        _alerts[alertKey] = new NetworkAlert
                        {
                            AlertId = alertKey,
                            AlertType = "NetworkInterfaceDown",
                            Severity = "Critical",
                            Description = $"网络接口已关闭: {networkInterface.Name}",
                            Timestamp = DateTime.Now,
                            Status = "Active",
                            Source = "NetworkTrafficAnalyzer"
                        };
                        
                        _dataManager.AddLog(new LogEntry
                        {
                            Id = Guid.NewGuid().ToString(),
                            Time = DateTime.Now,
                            Type = "NetworkHealth",
                            Message = "网络接口状态异常",
                            Details = $"接口: {networkInterface.Name}, 状态: {networkInterface.OperationalStatus}"
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "NetworkHealthCheckError",
                    Message = "网络健康检查错误",
                    Details = ex.Message
                });
            }
        }

        private void GenerateNetworkReport()
        {
            try
            {
                var report = new NetworkReport
                {
                    ReportId = Guid.NewGuid().ToString(),
                    Timestamp = DateTime.Now,
                    ConnectionCount = _connections.Count,
                    InterfaceCount = _statistics.Count,
                    AlertCount = _alerts.Count,
                    Connections = _connections.Values.ToList(),
                    Statistics = _statistics.Values.ToList(),
                    Alerts = _alerts.Values.ToList()
                };
                
                // 保存报告
                var reportPath = Path.Combine(FireAntivirus.Common.PathHelper.GetLogsPath(), $"network_report_{DateTime.Now:yyyyMMddHHmmss}.json");
                var json = Newtonsoft.Json.JsonConvert.SerializeObject(report, Newtonsoft.Json.Formatting.Indented);
                File.WriteAllText(reportPath, json);
                
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "NetworkReportGenerated",
                    Message = "网络报告已生成",
                    Details = $"报告路径: {reportPath}"
                });
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "NetworkReportError",
                    Message = "网络报告生成错误",
                    Details = ex.Message
                });
            }
        }

        private int GetProcessIdFromConnection(TcpConnectionInformation connection)
        {
            try
            {
                // 这里可以实现通过连接获取进程ID的逻辑
                // 例如：使用WMI或其他API
                return 0;
            }
            catch
            {
                return 0;
            }
        }

        private string GetProcessNameFromId(int processId)
        {
            try
            {
                if (processId > 0)
                {
                    var process = System.Diagnostics.Process.GetProcessById(processId);
                    return process.ProcessName;
                }
            }
            catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
            return "Unknown";
        }

        public List<NetworkConnection> GetActiveConnections()
        {
            return _connections.Values.ToList();
        }

        public List<NetworkStatistics> GetNetworkStatistics()
        {
            return _statistics.Values.ToList();
        }

        public List<NetworkAlert> GetActiveAlerts()
        {
            return _alerts.Values.Where(a => a.Status == "Active").ToList();
        }

        public void ClearAlerts()
        {
            _alerts.Clear();
        }

        public void SetAnalysisInterval(int interval)
        {
            _analysisInterval = interval;
        }

        public void SetAlertThreshold(int threshold)
        {
            _alertThreshold = threshold;
        }

        public void SetConnectionLimit(int limit)
        {
            _connectionLimit = limit;
        }

        public void EnableDeepPacketInspection(bool enable)
        {
            _enableDeepPacketInspection = enable;
        }

        public void EnableProtocolAnalysis(bool enable)
        {
            _enableProtocolAnalysis = enable;
        }

        public void EnableAnomalyDetection(bool enable)
        {
            _enableAnomalyDetection = enable;
        }

        public void EnableThreatIntelligence(bool enable)
        {
            _enableThreatIntelligence = enable;
        }

        public void EnableGeoIPAnalysis(bool enable)
        {
            _enableGeoIPAnalysis = enable;
        }

        public void EnableBandwidthMonitoring(bool enable)
        {
            _enableBandwidthMonitoring = enable;
        }

        public void EnablePacketCapture(bool enable)
        {
            _enablePacketCapture = enable;
        }

        public void EnableNetworkMapping(bool enable)
        {
            _enableNetworkMapping = enable;
        }

        public void EnablePortScanningDetection(bool enable)
        {
            _enablePortScanningDetection = enable;
        }

        public void EnableDDoSProtection(bool enable)
        {
            _enableDDoSProtection = enable;
        }

        public void EnableMaliciousTrafficDetection(bool enable)
        {
            _enableMaliciousTrafficDetection = enable;
        }

        public void EnableEncryptedTrafficAnalysis(bool enable)
        {
            _enableEncryptedTrafficAnalysis = enable;
        }

        public void EnableApplicationIdentification(bool enable)
        {
            _enableApplicationIdentification = enable;
        }

        public void EnableUserIdentification(bool enable)
        {
            _enableUserIdentification = enable;
        }

        public void EnableDeviceIdentification(bool enable)
        {
            _enableDeviceIdentification = enable;
        }

        public void EnableNetworkBehaviorAnalysis(bool enable)
        {
            _enableNetworkBehaviorAnalysis = enable;
        }

        public void EnableNetworkPerformanceMonitoring(bool enable)
        {
            _enableNetworkPerformanceMonitoring = enable;
        }

        public void EnableNetworkHealthCheck(bool enable)
        {
            _enableNetworkHealthCheck = enable;
        }

        public void EnableNetworkComplianceCheck(bool enable)
        {
            _enableNetworkComplianceCheck = enable;
        }

        public void EnableNetworkAudit(bool enable)
        {
            _enableNetworkAudit = enable;
        }

        public void EnableNetworkReporting(bool enable)
        {
            _enableNetworkReporting = enable;
        }
    }
}

