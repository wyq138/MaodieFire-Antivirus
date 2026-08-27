// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;

namespace FireAntivirus.Engine.Analyzers.Protection
{
    /// <summary>
    /// 网络流量分析器 - 分析网络连接和流量
    /// </summary>
    public class NetworkTrafficAnalyzer
    {
        private readonly HashSet<string> _suspiciousIPs;
        private readonly HashSet<int> _suspiciousPorts;
        private readonly Dictionary<string, int> _connectionHistory;

        public NetworkTrafficAnalyzer()
        {
            _suspiciousIPs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _suspiciousPorts = new HashSet<int>();
            _connectionHistory = new Dictionary<string, int>();
            InitializeSuspiciousIndicators();
        }

        private void InitializeSuspiciousIndicators()
        {
            // 常见后门端口
            _suspiciousPorts.UnionWith(new[] {
                4444, 5555, 6666, 7777, 8888, 9999,
                31337, 12345, 54321, 1337,
                6667, 6668, 6669,  // IRC
                1080, 8080,  // 代理
            });
        }

        public NetworkTrafficResult Analyze()
        {
            var result = new NetworkTrafficResult
            {
                Connections = new List<NetworkConnectionInfo>(),
                SuspiciousConnections = new List<NetworkConnectionInfo>(),
                Warnings = new List<string>()
            };

            try
            {
                // 获取所有TCP连接
                var tcpConnections = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections();
                foreach (var conn in tcpConnections)
                {
                    var info = new NetworkConnectionInfo
                    {
                        Protocol = "TCP",
                        LocalEndPoint = conn.LocalEndPoint.ToString(),
                        RemoteEndPoint = conn.RemoteEndPoint?.ToString() ?? "N/A",
                        State = conn.State.ToString(),
                        ProcessId = 0
                    };

                    // 尝试获取进程信息
                    try
                    {
                        var process = GetProcessByPort(conn.LocalEndPoint.Port);
                        if (process != null)
                        {
                            info.ProcessId = process.Id;
                            info.ProcessName = process.ProcessName;
                            info.ProcessPath = GetProcessPath(process);
                        }
                    }
                    catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "NetworkTrafficAnalyzer.cs 捕获异常", ex.Message); }

                    result.Connections.Add(info);

                    // 检查是否可疑
                    if (IsSuspiciousConnection(info))
                    {
                        info.IsSuspicious = true;
                        result.SuspiciousConnections.Add(info);
                    }
                }

                // 获取所有UDP监听
                var udpListeners = IPGlobalProperties.GetIPGlobalProperties().GetActiveUdpListeners();
                foreach (var listener in udpListeners)
                {
                    var info = new NetworkConnectionInfo
                    {
                        Protocol = "UDP",
                        LocalEndPoint = listener.ToString(),
                        RemoteEndPoint = "N/A",
                        State = "Listening",
                        ProcessId = 0
                    };

                    try
                    {
                        var process = GetProcessByPort(listener.Port);
                        if (process != null)
                        {
                            info.ProcessId = process.Id;
                            info.ProcessName = process.ProcessName;
                        }
                    }
                    catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "NetworkTrafficAnalyzer.cs 捕获异常", ex.Message); }

                    result.Connections.Add(info);
                }

                result.TotalConnections = result.Connections.Count;
                result.SuspiciousCount = result.SuspiciousConnections.Count;

                if (result.SuspiciousCount > 0)
                {
                    result.Warnings.Add($"发现 {result.SuspiciousCount} 个可疑网络连接");
                }
            }
            catch (Exception ex)
            {
                result.Warnings.Add($"网络分析错误: {ex.Message}");
            }

            return result;
        }

        private Process GetProcessByPort(int port)
        {
            try
            {
                // 使用netstat获取端口对应的进程
                var psi = new ProcessStartInfo
                {
                    FileName = "netstat",
                    Arguments = "-ano",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                };

                using var process = Process.Start(psi);
                if (process == null) return null;

                var output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                foreach (var line in output.Split('\n'))
                {
                    if (line.Contains($":{port} "))
                    {
                        var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length >= 5 && int.TryParse(parts.Last(), out var pid))
                        {
                            return Process.GetProcessById(pid);
                        }
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "NetworkTrafficAnalyzer.cs 捕获异常", ex.Message); }

            return null;
        }

        private string GetProcessPath(Process process)
        {
            try
            {
                return process.MainModule?.FileName ?? "";
            }
            catch
            {
                return "";
            }
        }

        private bool IsSuspiciousConnection(NetworkConnectionInfo conn)
        {
            // 检查可疑端口
            if (!string.IsNullOrEmpty(conn.LocalEndPoint))
            {
                var portPart = conn.LocalEndPoint.Split(':').Last();
                if (int.TryParse(portPart, out var port) && _suspiciousPorts.Contains(port))
                {
                    return true;
                }
            }

            if (!string.IsNullOrEmpty(conn.RemoteEndPoint) && conn.RemoteEndPoint != "N/A")
            {
                var portPart = conn.RemoteEndPoint.Split(':').Last();
                if (int.TryParse(portPart, out var port) && _suspiciousPorts.Contains(port))
                {
                    return true;
                }
            }

            // 检查可疑IP
            if (!string.IsNullOrEmpty(conn.RemoteEndPoint) && conn.RemoteEndPoint != "N/A")
            {
                var ipPart = conn.RemoteEndPoint.Split(':').First();
                if (_suspiciousIPs.Contains(ipPart))
                {
                    return true;
                }
            }

            // 检查可疑进程名
            var suspiciousProcessNames = new[] { "cmd", "powershell", "wscript", "cscript", "mshta" };
            if (!string.IsNullOrEmpty(conn.ProcessName))
            {
                foreach (var name in suspiciousProcessNames)
                {
                    if (conn.ProcessName.Contains(name, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        public void AddSuspiciousIP(string ip)
        {
            _suspiciousIPs.Add(ip);
        }

        public void AddSuspiciousPort(int port)
        {
            _suspiciousPorts.Add(port);
        }
    }

    public class NetworkTrafficResult
    {
        public List<NetworkConnectionInfo> Connections { get; set; }
        public List<NetworkConnectionInfo> SuspiciousConnections { get; set; }
        public List<string> Warnings { get; set; }
        public int TotalConnections { get; set; }
        public int SuspiciousCount { get; set; }
        public long BytesSent { get; set; }
        public long BytesReceived { get; set; }
    }

    public class NetworkConnectionInfo
    {
        public string Protocol { get; set; }
        public string LocalEndPoint { get; set; }
        public string RemoteEndPoint { get; set; }
        public string State { get; set; }
        public int ProcessId { get; set; }
        public string ProcessName { get; set; }
        public string ProcessPath { get; set; }
        public bool IsSuspicious { get; set; }
        public string ThreatReason { get; set; }
    }
}