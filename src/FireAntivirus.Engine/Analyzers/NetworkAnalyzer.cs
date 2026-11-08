using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using FireAntivirus.Common;
using FireAntivirus.Data;

namespace FireAntivirus.Engine.Analyzers
{
    public class NetworkAnalyzer
    {
        private DataManager dataManager;
        private Dictionary<string, List<string>> networkCache;
        private Dictionary<string, List<string>> networkPatterns;
        private Dictionary<string, List<string>> maliciousNetworkSignatures;
        private Dictionary<string, List<string>> suspiciousNetworkSignatures;
        private Dictionary<string, List<string>> benignNetworkSignatures;

        public NetworkAnalyzer()
        {
            dataManager = DataManager.SharedInstance;
            networkCache = new Dictionary<string, List<string>>();
            InitializeNetworkPatterns();
            InitializeNetworkSignatures();
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

        public List<ScanResult> AnalyzeNetwork()
        {
            var results = new List<ScanResult>();
            
            try
            {
                var connections = GetNetworkConnections();
                var adapters = GetNetworkAdapters();
                var routes = GetNetworkRoutes();
                var statistics = GetNetworkStatistics();

                double networkScore = CalculateNetworkScore(connections, adapters, routes, statistics);
                var result = CreateNetworkScanResult("Network", networkScore);
                results.Add(result);

                if (result.IsInfected)
                {
                    dataManager.LogThreat("网络分析检测到恶意活动", $"评分: {networkScore:P}", "NetworkAnalyzer");
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError("网络分析失败", ex.Message, "NetworkAnalyzer");
            }

            return results;
        }

        public List<ScanResult> AnalyzeSpecificConnection(string connection)
        {
            var results = new List<ScanResult>();
            
            try
            {
                double connectionScore = CalculateConnectionScore(connection);
                var result = CreateConnectionScanResult(connection, connectionScore);
                results.Add(result);

                if (result.IsInfected)
                {
                    dataManager.LogThreat($"网络分析检测到恶意连接: {connection}", $"评分: {connectionScore:P}", "NetworkAnalyzer");
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"连接分析失败: {connection}", ex.Message, "NetworkAnalyzer");
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
                using (var searcher = new System.Management.ManagementObjectSearcher("SELECT * FROM Win32_IP4RouteTable"))
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

        private double CalculateConnectionScore(string connection)
        {
            double score = 0.0;

            try
            {
                score += AnalyzeMaliciousNetworkSignatures(new List<string> { connection });
                score += AnalyzeSuspiciousNetworkSignatures(new List<string> { connection });
                score += AnalyzeNetworkPatterns(new List<string> { connection });
                score += AnalyzeBenignNetworkSignatures(new List<string> { connection });
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
                    result.ThreatName = "网络分析检测到恶意活动";
                    result.ThreatType = "Malware";
                    result.Severity = "High";
                }
                else
                {
                    result.ThreatName = "网络分析检测到可疑活动";
                    result.ThreatType = "Suspicious";
                    result.Severity = "Medium";
                }

                result.AdditionalInfo = $"网络评分: {networkScore:P}";
            }

            return result;
        }

        private ScanResult CreateConnectionScanResult(string connection, double connectionScore)
        {
            var result = new ScanResult
            {
                FilePath = connection,
                IsInfected = connectionScore > 0.85,
                Confidence = connectionScore,
                DetectionTime = DateTime.Now,
                DetectionMethod = "Network"
            };

            if (result.IsInfected)
            {
                if (connectionScore > 0.95)
                {
                    result.ThreatName = "网络分析检测到恶意连接";
                    result.ThreatType = "Malware";
                    result.Severity = "High";
                }
                else
                {
                    result.ThreatName = "网络分析检测到可疑连接";
                    result.ThreatType = "Suspicious";
                    result.Severity = "Medium";
                }

                result.AdditionalInfo = $"连接评分: {connectionScore:P}";
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
