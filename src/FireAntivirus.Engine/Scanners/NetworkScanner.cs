using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using FireAntivirus.Common;
using FireAntivirus.Data;
using FireAntivirus.Engine;

namespace FireAntivirus.Engine.Scanners
{
    public class NetworkScanner
    {
        private DataManager dataManager;
        private Dictionary<string, List<string>> networkCache;
        private Dictionary<string, List<string>> networkPatterns;
        private Dictionary<string, List<string>> maliciousNetworkSignatures;
        private Dictionary<string, List<string>> suspiciousNetworkSignatures;
        private Dictionary<string, List<string>> benignNetworkSignatures;
        private int maxDegreeOfParallelism;
        private int batchSize;

        public NetworkScanner(int maxThreads = 4, int batchSize = 10)
        {
            dataManager = new DataManager();
            networkCache = new Dictionary<string, List<string>>();
            maxDegreeOfParallelism = Math.Max(1, Math.Min(Environment.ProcessorCount, maxThreads));
            this.batchSize = Math.Max(1, batchSize);
            InitializeNetworkPatterns();
            InitializeNetworkSignatures();
        }

        public int MaxDegreeOfParallelism
        {
            get { return maxDegreeOfParallelism; }
            set { maxDegreeOfParallelism = Math.Max(1, Math.Min(Environment.ProcessorCount, value)); }
        }

        public int BatchSize
        {
            get { return batchSize; }
            set { batchSize = Math.Max(1, value); }
        }

        private void InitializeNetworkPatterns()
        {
            networkPatterns = new Dictionary<string, List<string>>
            {
                { "Protocols", new List<string> { "TCP", "UDP", "ICMP", "ARP", "DNS", "HTTP", "HTTPS", "FTP" } },
                { "Ports", new List<string> { "80", "443", "8080", "8443", "3389", "22", "21", "23", "1433", "3306" } },
                { "Addresses", new List<string> { "127.0.0.1", "192.168.0.0", "10.0.0.0", "172.16.0.0", "::1", "fe80::" } },
                { "States", new List<string> { "LISTENING", "ESTABLISHED", "TIME_WAIT", "CLOSE_WAIT", "SYN_SENT", "SYN_RECEIVED" } }
            };
        }

        private void InitializeNetworkSignatures()
        {
            maliciousNetworkSignatures = new Dictionary<string, List<string>>
            {
                { "C2", new List<string> {
                    "185.234.xx.xx", "91.243.xx.xx", "103.245.xx.xx", "141.101.xx.xx",
                    "209.141.xx.xx", "199.244.xx.xx", "173.239.xx.xx", "104.20.xx.xx"
                }},
                { "Malware", new List<string> {
                    "bot", "c2", "command and control", "exfil", "payload", "ransom", "keylog", "steal"
                }},
                { "Ports", new List<string> {
                    "4444", "5555", "6666", "7777", "8888", "9999", "31337", "40404"
                }},
                { "Protocols", new List<string> {
                    "DNS", "HTTP", "HTTPS", "TCP", "UDP"
                }}
            };

            suspiciousNetworkSignatures = new Dictionary<string, List<string>>
            {
                { "IPs", new List<string> {
                    "192.168.0.0", "10.0.0.0", "172.16.0.0", "100.64.0.0"
                }},
                { "Ports", new List<string> {
                    "80", "443", "8080", "8443", "3389", "22", "21", "23"
                }},
                { "Protocols", new List<string> {
                    "HTTP", "HTTPS", "FTP", "SSH", "RDP"
                }},
                { "States", new List<string> {
                    "ESTABLISHED", "LISTENING", "TIME_WAIT"
                }}
            };

            benignNetworkSignatures = new Dictionary<string, List<string>>
            {
                { "IPs", new List<string> {
                    "127.0.0.1", "::1", "fe80::", "192.168.1.1"
                }},
                { "Ports", new List<string> {
                    "80", "443", "8080", "8443", "53", "25", "110", "143"
                }},
                { "Protocols", new List<string> {
                    "HTTP", "HTTPS", "DNS", "SMTP", "POP3", "IMAP"
                }},
                { "States", new List<string> {
                    "LISTENING", "ESTABLISHED", "TIME_WAIT"
                }}
            };
        }

        public List<ScanResult> ScanNetworkConnections()
        {
            var results = new List<ScanResult>();
            
            try
            {
                // 并行获取网络信息，提高扫描效率
                var options = new ParallelOptions { MaxDegreeOfParallelism = maxDegreeOfParallelism };
                List<string> connections = null;
                List<string> adapters = null;
                List<string> routes = null;
                Dictionary<string, object> statistics = null;
                
                Parallel.Invoke(options,
                    () => { connections = GetNetworkConnections(); },
                    () => { adapters = GetNetworkAdapters(); },
                    () => { routes = GetNetworkRoutes(); },
                    () => { statistics = GetNetworkStatistics(); }
                );

                double networkScore = CalculateNetworkScore(connections ?? new List<string>(), adapters ?? new List<string>(), routes ?? new List<string>(), statistics ?? new Dictionary<string, object>());
                var result = CreateNetworkScanResult("Network Connections", networkScore);
                results.Add(result);

                if (result.IsInfected)
                {
                    dataManager.LogThreat("网络扫描检测到恶意连接", $"评分: {networkScore:P}", "NetworkScanner");
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError("网络扫描失败", ex.Message, "NetworkScanner");
            }

            return results;
        }

        public List<ScanResult> ScanAllProcessesNetwork()
        {
            var results = new List<ScanResult>();
            
            try
            {
                var processes = Process.GetProcesses();
                var threadSafeResults = new System.Collections.Concurrent.ConcurrentBag<ScanResult>();
                var options = new ParallelOptions { MaxDegreeOfParallelism = maxDegreeOfParallelism };
                
                Parallel.ForEach(processes, options, process =>
                {
                    try
                    {
                        var processResults = ScanSpecificProcess(process.Id);
                        foreach (var result in processResults)
                        {
                            threadSafeResults.Add(result);
                        }
                    }
                    catch
                    {
                        // 忽略无法访问的进程
                    }
                });
                
                results.AddRange(threadSafeResults);
            }
            catch (Exception ex)
            {
                dataManager.LogError("扫描所有进程网络失败", ex.Message, "NetworkScanner");
            }

            return results;
        }

        public List<ScanResult> ScanProcessesNetworkInBatches()
        {
            var results = new List<ScanResult>();
            
            try
            {
                var processes = Process.GetProcesses();
                var processBatches = processes.Batch(batchSize);
                
                foreach (var batch in processBatches)
                {
                    var batchResults = new System.Collections.Concurrent.ConcurrentBag<ScanResult>();
                    var options = new ParallelOptions { MaxDegreeOfParallelism = maxDegreeOfParallelism };
                    
                    Parallel.ForEach(batch, options, process =>
                    {
                        try
                        {
                            var processResults = ScanSpecificProcess(process.Id);
                            foreach (var result in processResults)
                            {
                                batchResults.Add(result);
                            }
                        }
                        catch
                        {
                            // 忽略无法访问的进程
                        }
                    });
                    
                    results.AddRange(batchResults);
                    
                    // 每批次扫描后短暂休息，减少系统负载
                    Thread.Sleep(50);
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError("批量扫描进程网络失败", ex.Message, "NetworkScanner");
            }

            return results;
        }



        public List<ScanResult> ScanSpecificProcess(int processId)
        {
            var results = new List<ScanResult>();
            
            try
            {
                var process = Process.GetProcessById(processId);
                var connections = GetProcessNetworkConnections(processId);
                double processNetworkScore = CalculateProcessNetworkScore(connections);
                var result = CreateProcessNetworkScanResult(process, processNetworkScore);
                results.Add(result);

                if (result.IsInfected)
                {
                    dataManager.LogThreat($"网络扫描检测到恶意进程连接: {process.ProcessName} (PID: {processId})", $"评分: {processNetworkScore:P}", "NetworkScanner");
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"进程网络扫描失败: PID {processId}", ex.Message, "NetworkScanner");
            }

            return results;
        }

        private List<string> GetNetworkConnections()
        {
            var connections = new List<string>();
            
            if (networkCache.TryGetValue("Connections", out List<string> cachedConnections))
            {
                return cachedConnections;
            }

            try
            {
                var tcpConnections = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections();
                var udpListeners = IPGlobalProperties.GetIPGlobalProperties().GetActiveUdpListeners();

                foreach (var connection in tcpConnections)
                {
                    connections.Add($"TCP: {connection.LocalEndPoint} -> {connection.RemoteEndPoint} ({connection.State})");
                }

                foreach (var listener in udpListeners)
                {
                    connections.Add($"UDP: {listener}");
                }

                networkCache["Connections"] = connections;
            }
            catch
            {
                connections.Clear();
            }

            return connections;
        }

        private List<string> GetNetworkAdapters()
        {
            var adapters = new List<string>();
            
            if (networkCache.TryGetValue("Adapters", out List<string> cachedAdapters))
            {
                return cachedAdapters;
            }

            try
            {
                var networkInterfaces = NetworkInterface.GetAllNetworkInterfaces();
                foreach (var adapter in networkInterfaces)
                {
                    adapters.Add($"{adapter.Name}: {adapter.Description} ({adapter.OperationalStatus}) - {string.Join(", ", adapter.GetIPProperties().UnicastAddresses.Select(a => a.Address))}");
                }

                networkCache["Adapters"] = adapters;
            }
            catch
            {
                adapters.Clear();
            }

            return adapters;
        }

        private List<string> GetNetworkRoutes()
        {
            var routes = new List<string>();
            
            if (networkCache.TryGetValue("Routes", out List<string> cachedRoutes))
            {
                return cachedRoutes;
            }

            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_IP4RouteTable"))
                {
                    foreach (var route in searcher.Get())
                    {
                        routes.Add($"{route["Destination"]} -> {route["NextHop"]} (Metric: {route["Metric1"]})");
                    }
                }

                networkCache["Routes"] = routes;
            }
            catch
            {
                routes.Clear();
            }

            return routes;
        }

        private Dictionary<string, object> GetNetworkStatistics()
        {
            var statistics = new Dictionary<string, object>();
            
            if (networkCache.TryGetValue("Statistics", out List<string> cachedStatistics))
            {
                foreach (var stat in cachedStatistics)
                {
                    var parts = stat.Split(':');
                    if (parts.Length == 2)
                    {
                        statistics[parts[0].Trim()] = parts[1].Trim();
                    }
                }
                return statistics;
            }

            try
            {
                var adapters = NetworkInterface.GetAllNetworkInterfaces();
                foreach (var adapter in adapters)
                {
                    var ipStats = adapter.GetIPv4Statistics();
                    statistics[$"{adapter.Name}_BytesSent"] = ipStats.BytesSent;
                    statistics[$"{adapter.Name}_BytesReceived"] = ipStats.BytesReceived;
                    statistics[$"{adapter.Name}_PacketsSent"] = ipStats.UnicastPacketsSent;
                    statistics[$"{adapter.Name}_PacketsReceived"] = ipStats.UnicastPacketsReceived;
                    statistics[$"{adapter.Name}_IncomingPacketsDiscarded"] = ipStats.IncomingPacketsDiscarded;
                    statistics[$"{adapter.Name}_OutgoingPacketsDiscarded"] = ipStats.OutgoingPacketsDiscarded;
                    statistics[$"{adapter.Name}_IncomingPacketsWithErrors"] = ipStats.IncomingPacketsWithErrors;
                    statistics[$"{adapter.Name}_OutgoingPacketsWithErrors"] = ipStats.OutgoingPacketsWithErrors;
                }

                var cachedStats = statistics.Select(kv => $"{kv.Key}: {kv.Value}").ToList();
                networkCache["Statistics"] = cachedStats;
            }
            catch
            {
                statistics.Clear();
            }

            return statistics;
        }

        private List<string> GetProcessNetworkConnections(int processId)
        {
            var connections = new List<string>();
            
            try
            {
                using (var searcher = new ManagementObjectSearcher($"SELECT * FROM Win32_PerfRawData_Tcpip_NetworkInterface"))
                {
                    foreach (var connection in searcher.Get())
                    {
                        connections.Add($"{connection["Name"]}: {connection["BytesTotalPersec"]}");
                    }
                }
            }
            catch
            {
                connections.Clear();
            }

            return connections;
        }

        private double CalculateNetworkScore(List<string> connections, List<string> adapters, List<string> routes, Dictionary<string, object> statistics)
        {
            double score = 0.0;

            try
            {
                score += AnalyzeMaliciousNetworkSignatures(connections);
                score += AnalyzeSuspiciousNetworkSignatures(connections);
                score += AnalyzeNetworkPatterns(connections);
                score += AnalyzeBenignNetworkSignatures(connections);
            }
            catch
            {
                score = 0.0;
            }

            return Math.Max(0.0, Math.Min(score, 1.0));
        }

        private double CalculateProcessNetworkScore(List<string> connections)
        {
            double score = 0.0;

            try
            {
                score += AnalyzeMaliciousNetworkSignatures(connections);
                score += AnalyzeSuspiciousNetworkSignatures(connections);
                score += AnalyzeBenignNetworkSignatures(connections);
            }
            catch
            {
                score = 0.0;
            }

            return Math.Max(0.0, Math.Min(score, 1.0));
        }

        private double AnalyzeMaliciousNetworkSignatures(List<string> connections)
        {
            double score = 0.0;

            foreach (var connection in connections)
            {
                foreach (var signatureCategory in maliciousNetworkSignatures)
                {
                    foreach (var signature in signatureCategory.Value)
                    {
                        if (connection.Contains(signature, StringComparison.OrdinalIgnoreCase))
                        {
                            score += 0.1;
                        }
                    }
                }
            }

            return score;
        }

        private double AnalyzeSuspiciousNetworkSignatures(List<string> connections)
        {
            double score = 0.0;

            foreach (var connection in connections)
            {
                foreach (var signatureCategory in suspiciousNetworkSignatures)
                {
                    foreach (var signature in signatureCategory.Value)
                    {
                        if (connection.Contains(signature, StringComparison.OrdinalIgnoreCase))
                        {
                            score += 0.05;
                        }
                    }
                }
            }

            return score;
        }

        private double AnalyzeBenignNetworkSignatures(List<string> connections)
        {
            double score = 0.0;

            foreach (var connection in connections)
            {
                foreach (var signatureCategory in benignNetworkSignatures)
                {
                    foreach (var signature in signatureCategory.Value)
                    {
                        if (connection.Contains(signature, StringComparison.OrdinalIgnoreCase))
                        {
                            score -= 0.03;
                        }
                    }
                }
            }

            return score;
        }

        private double AnalyzeNetworkPatterns(List<string> connections)
        {
            double score = 0.0;

            foreach (var connection in connections)
            {
                foreach (var patternCategory in networkPatterns)
                {
                    foreach (var pattern in patternCategory.Value)
                    {
                        if (connection.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                        {
                            score += 0.01;
                        }
                    }
                }
            }

            return score;
        }

        private ScanResult CreateNetworkScanResult(string target, double networkScore)
        {
            var result = new ScanResult
            {
                FilePath = target,
                IsInfected = networkScore > 0.85,
                Confidence = networkScore,
                DetectionTime = DateTime.Now,
                DetectionMethod = "Network"
            };

            if (result.IsInfected)
            {
                if (networkScore > 0.95)
                {
                    result.ThreatName = "网络扫描检测到恶意连接";
                    result.ThreatType = "Malware";
                    result.Severity = "High";
                }
                else
                {
                    result.ThreatName = "网络扫描检测到可疑连接";
                    result.ThreatType = "Suspicious";
                    result.Severity = "Medium";
                }

                result.AdditionalInfo = $"网络评分: {networkScore:P}";
            }

            return result;
        }

        private ScanResult CreateProcessNetworkScanResult(Process process, double networkScore)
        {
            var result = new ScanResult
            {
                FilePath = process.MainModule?.FileName ?? process.ProcessName,
                IsInfected = networkScore > 0.85,
                Confidence = networkScore,
                DetectionTime = DateTime.Now,
                DetectionMethod = "Network"
            };

            if (result.IsInfected)
            {
                if (networkScore > 0.95)
                {
                    result.ThreatName = "网络扫描检测到恶意进程连接";
                    result.ThreatType = "Malware";
                    result.Severity = "High";
                }
                else
                {
                    result.ThreatName = "网络扫描检测到可疑进程连接";
                    result.ThreatType = "Suspicious";
                    result.Severity = "Medium";
                }

                result.AdditionalInfo = $"网络评分: {networkScore:P}, 进程ID: {process.Id}, 进程名: {process.ProcessName}";
            }

            return result;
        }

        public void ClearCache()
        {
            networkCache.Clear();
        }

        public int GetCacheSize()
        {
            return networkCache.Count;
        }
    }
}
