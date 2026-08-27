// 耄耋软件工作室 开发，严禁非法反编译
// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace FireAntivirus.NetworkSecurity
{
    public class NetworkSecurityManager
    {
        private CancellationTokenSource _cancellationTokenSource;
        private Task _monitoringTask;
        private Dictionary<IPEndPoint, ConnectionInfo> _connections;
        private Dictionary<IPAddress, int> _ipRequestCount;
        private List<IPAddress> _blockedIPs;
        private List<IPAddress> _suspiciousIPs;
        private List<int> _suspiciousPorts;

        public event EventHandler<NetworkThreatDetectedEventArgs> NetworkThreatDetected;
        public event EventHandler<NetworkConnectionEventArgs> NetworkConnectionEstablished;
        public event EventHandler<NetworkConnectionEventArgs> NetworkConnectionClosed;
        public event EventHandler<NetworkTrafficEventArgs> NetworkTrafficDetected;



        public async Task StartMonitoring()
        {
            if (_monitoringTask != null && !_monitoringTask.IsCompleted)
            {
                return;
            }

            _cancellationTokenSource = new CancellationTokenSource();
            var token = _cancellationTokenSource.Token;

            _monitoringTask = Task.Run(async () => {
                while (!token.IsCancellationRequested)
                {
                    try
                    {
                        // 监控网络连接
                        MonitorNetworkConnections();

                        // 监控网络流量
                        await MonitorNetworkTraffic();

                        // 检测DDoS攻击
                        DetectDDoSAttacks();

                        // 检测端口扫描
                        DetectPortScanning();

                        // 检查可疑IP
                        CheckSuspiciousIPs();

                        // 等待一段时间再进行下一次检查
                        await Task.Delay(1000, token);
                    }
                    catch (Exception ex)
                    {
                        // 记录错误但继续运行
                        Console.WriteLine($"网络安全监控错误: {ex.Message}");
                    }
                }
            }, token);
        }

        public void StopMonitoring()
        {
            if (_cancellationTokenSource != null)
            {
                _cancellationTokenSource.Cancel();
                _cancellationTokenSource.Dispose();
            }

            if (_monitoringTask != null)
            {
                try
                {
                    _monitoringTask.Wait(2000);
                }
                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "NetworkSecurityManager.cs 捕获异常", ex.Message); }
            }

            _connections.Clear();
            _ipRequestCount.Clear();
        }

        private void MonitorNetworkConnections()
        {
            var ipGlobalProperties = IPGlobalProperties.GetIPGlobalProperties();
            var tcpConnections = ipGlobalProperties.GetActiveTcpConnections();

            // 检测新连接
            foreach (var connection in tcpConnections)
            {
                if (connection.State == TcpState.Established)
                {
                    var endPoint = connection.RemoteEndPoint;
                    if (endPoint != null && !_connections.ContainsKey(endPoint))
                    {
                        var connectionInfo = new ConnectionInfo
                        {
                            RemoteEndPoint = endPoint,
                            LocalEndPoint = connection.LocalEndPoint,
                            EstablishTime = DateTime.Now,
                            State = connection.State
                        };

                        _connections[endPoint] = connectionInfo;

                        OnNetworkConnectionEstablished(new NetworkConnectionEventArgs
                        {
                            RemoteEndPoint = endPoint,
                            LocalEndPoint = connection.LocalEndPoint,
                            EstablishTime = DateTime.Now
                        });

                        // 检查连接是否可疑
                        CheckSuspiciousConnection(connectionInfo);
                    }
                }
            }

            // 检测已关闭的连接
            var endedConnections = new List<IPEndPoint>();
            foreach (var kvp in _connections)
            {
                bool stillActive = false;
                foreach (var connection in tcpConnections)
                {
                    if (connection.RemoteEndPoint != null && connection.RemoteEndPoint.Equals(kvp.Key))
                    {
                        stillActive = true;
                        break;
                    }
                }

                if (!stillActive)
                {
                    endedConnections.Add(kvp.Key);
                }
            }

            foreach (var endPoint in endedConnections)
            {
                var connectionInfo = _connections[endPoint];
                _connections.Remove(endPoint);

                OnNetworkConnectionClosed(new NetworkConnectionEventArgs
                {
                    RemoteEndPoint = endPoint,
                    LocalEndPoint = connectionInfo.LocalEndPoint,
                    EstablishTime = connectionInfo.EstablishTime
                });
            }
        }

        private List<NetworkInterface> _networkInterfaces;

        public NetworkSecurityManager()
        {
            _connections = new Dictionary<IPEndPoint, ConnectionInfo>();
            _ipRequestCount = new Dictionary<IPAddress, int>();
            _blockedIPs = new List<IPAddress>();
            _suspiciousIPs = LoadSuspiciousIPs();
            _suspiciousPorts = LoadSuspiciousPorts();
            _networkInterfaces = NetworkInterface.GetAllNetworkInterfaces().ToList();
        }

        private async Task MonitorNetworkTraffic()
        {
            // 监控网络流量
            foreach (var networkInterface in _networkInterfaces)
            {
                if (networkInterface.OperationalStatus == OperationalStatus.Up)
                {
                    var statistics = networkInterface.GetIPv4Statistics();
                    OnNetworkTrafficDetected(new NetworkTrafficEventArgs
                    {
                        SourceIP = IPAddress.Any,
                        DestinationIP = IPAddress.Any,
                        BytesSent = statistics.BytesSent,
                        BytesReceived = statistics.BytesReceived,
                        Timestamp = DateTime.Now
                    });
                }
            }
            await Task.CompletedTask;
        }

        public void UpdateNetworkInterfaces()
        {
            _networkInterfaces = NetworkInterface.GetAllNetworkInterfaces().ToList();
        }

        public List<NetworkInterface> GetNetworkInterfaces()
        {
            return new List<NetworkInterface>(_networkInterfaces);
        }

        private void DetectDDoSAttacks()
        {
            // 检测DDoS攻击
            var now = DateTime.Now;
            var ipsToRemove = new List<IPAddress>();

            foreach (var kvp in _ipRequestCount)
            {
                // 如果IP在短时间内请求过多，可能是DDoS攻击
                if (kvp.Value > 100) // 100个请求/秒
                {
                    OnNetworkThreatDetected(new NetworkThreatDetectedEventArgs
                    {
                        ThreatType = "DDoS攻击",
                        SourceIP = kvp.Key,
                        SourcePort = 0,
                        DestinationIP = IPAddress.Any,
                        DestinationPort = 0,
                        DetectionTime = now
                    });

                    // 阻止该IP
                    BlockIP(kvp.Key);
                    ipsToRemove.Add(kvp.Key);
                }
            }

            foreach (var ip in ipsToRemove)
            {
                _ipRequestCount.Remove(ip);
            }

            // 清空过期的请求计数
            _ipRequestCount.Clear();
        }

        private void DetectPortScanning()
        {
            // 检测端口扫描
            var portCounts = new Dictionary<IPAddress, HashSet<int>>();

            foreach (var connectionInfo in _connections.Values)
            {
                var remoteIP = connectionInfo.RemoteEndPoint.Address;
                var localPort = connectionInfo.LocalEndPoint.Port;

                if (!portCounts.ContainsKey(remoteIP))
                {
                    portCounts[remoteIP] = new HashSet<int>();
                }

                portCounts[remoteIP].Add(localPort);
            }

            foreach (var kvp in portCounts)
            {
                // 如果一个IP尝试连接多个端口，可能是端口扫描
                if (kvp.Value.Count > 10)
                {
                    OnNetworkThreatDetected(new NetworkThreatDetectedEventArgs
                    {
                        ThreatType = "端口扫描",
                        SourceIP = kvp.Key,
                        SourcePort = 0,
                        DestinationIP = IPAddress.Any,
                        DestinationPort = 0,
                        DetectionTime = DateTime.Now
                    });

                    // 阻止该IP
                    BlockIP(kvp.Key);
                }
            }
        }

        private void CheckSuspiciousIPs()
        {
            // 检查可疑IP
            foreach (var connectionInfo in _connections.Values)
            {
                var remoteIP = connectionInfo.RemoteEndPoint.Address;
                if (_suspiciousIPs.Contains(remoteIP))
                {
                    OnNetworkThreatDetected(new NetworkThreatDetectedEventArgs
                    {
                        ThreatType = "可疑IP",
                        SourceIP = remoteIP,
                        SourcePort = connectionInfo.RemoteEndPoint.Port,
                        DestinationIP = connectionInfo.LocalEndPoint.Address,
                        DestinationPort = connectionInfo.LocalEndPoint.Port,
                        DetectionTime = DateTime.Now
                    });
                }
            }
        }

        private void CheckSuspiciousConnection(ConnectionInfo connectionInfo)
        {
            var remoteIP = connectionInfo.RemoteEndPoint.Address;
            var remotePort = connectionInfo.RemoteEndPoint.Port;

            // 检查可疑端口
            if (_suspiciousPorts.Contains(remotePort))
            {
                OnNetworkThreatDetected(new NetworkThreatDetectedEventArgs
                {
                    ThreatType = "可疑端口",
                    SourceIP = remoteIP,
                    SourcePort = remotePort,
                    DestinationIP = connectionInfo.LocalEndPoint.Address,
                    DestinationPort = connectionInfo.LocalEndPoint.Port,
                    DetectionTime = DateTime.Now
                });
            }

            // 检查连接到内网IP
            if (IsPrivateIP(remoteIP))
            {
                OnNetworkThreatDetected(new NetworkThreatDetectedEventArgs
                {
                    ThreatType = "内网连接",
                    SourceIP = remoteIP,
                    SourcePort = remotePort,
                    DestinationIP = connectionInfo.LocalEndPoint.Address,
                    DestinationPort = connectionInfo.LocalEndPoint.Port,
                    DetectionTime = DateTime.Now
                });
            }
        }

        public void BlockIP(IPAddress ipAddress)
        {
            if (!_blockedIPs.Contains(ipAddress))
            {
                _blockedIPs.Add(ipAddress);
                // 这里可以添加实际的IP阻止逻辑
                Console.WriteLine($"已阻止IP: {ipAddress}");
            }
        }

        public void UnblockIP(IPAddress ipAddress)
        {
            if (_blockedIPs.Contains(ipAddress))
            {
                _blockedIPs.Remove(ipAddress);
                Console.WriteLine($"已解除阻止IP: {ipAddress}");
            }
        }

        public List<IPAddress> GetBlockedIPs()
        {
            return new List<IPAddress>(_blockedIPs);
        }

        public List<ConnectionInfo> GetActiveConnections()
        {
            return new List<ConnectionInfo>(_connections.Values);
        }

        private bool IsPrivateIP(IPAddress ipAddress)
        {
            // 检查是否为内网IP
            byte[] bytes = ipAddress.GetAddressBytes();
            return (
                (bytes[0] == 10) ||
                (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
                (bytes[0] == 192 && bytes[1] == 168)
            );
        }

        private List<IPAddress> LoadSuspiciousIPs()
        {
            // 加载可疑IP列表
            return new List<IPAddress>
            {
                // 这里可以添加可疑IP地址
                IPAddress.Parse("1.1.1.1"), // 示例IP
                IPAddress.Parse("8.8.8.8")  // 示例IP
            };
        }

        private List<int> LoadSuspiciousPorts()
        {
            // 加载可疑端口列表
            return new List<int>
            {
                21,  // FTP
                22,  // SSH
                23,  // Telnet
                25,  // SMTP
                445, // SMB
                1433, // SQL Server
                3389, // RDP
                4444, // Metasploit
                5555, // Android ADB
                6667, // IRC
                8080, // Proxy
                8888, // Proxy
                1337, // Backdoor
                31337 // Backdoor
            };
        }

        protected virtual void OnNetworkThreatDetected(NetworkThreatDetectedEventArgs e)
        {
            NetworkThreatDetected?.Invoke(this, e);
        }

        protected virtual void OnNetworkConnectionEstablished(NetworkConnectionEventArgs e)
        {
            NetworkConnectionEstablished?.Invoke(this, e);
        }

        protected virtual void OnNetworkConnectionClosed(NetworkConnectionEventArgs e)
        {
            NetworkConnectionClosed?.Invoke(this, e);
        }

        protected virtual void OnNetworkTrafficDetected(NetworkTrafficEventArgs e)
        {
            NetworkTrafficDetected?.Invoke(this, e);
        }
    }

    public class ConnectionInfo
    {
        public IPEndPoint RemoteEndPoint { get; set; }
        public IPEndPoint LocalEndPoint { get; set; }
        public DateTime EstablishTime { get; set; }
        public TcpState State { get; set; }
    }

    public class NetworkThreatDetectedEventArgs : EventArgs
    {
        public string ThreatType { get; set; }
        public IPAddress SourceIP { get; set; }
        public int SourcePort { get; set; }
        public IPAddress DestinationIP { get; set; }
        public int DestinationPort { get; set; }
        public DateTime DetectionTime { get; set; }
    }

    public class NetworkConnectionEventArgs : EventArgs
    {
        public IPEndPoint RemoteEndPoint { get; set; }
        public IPEndPoint LocalEndPoint { get; set; }
        public DateTime EstablishTime { get; set; }
    }

    public class NetworkTrafficEventArgs : EventArgs
    {
        public IPAddress SourceIP { get; set; }
        public IPAddress DestinationIP { get; set; }
        public long BytesSent { get; set; }
        public long BytesReceived { get; set; }
        public DateTime Timestamp { get; set; }
    }
}