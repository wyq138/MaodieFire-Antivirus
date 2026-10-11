using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading;
using System.Linq;
using System.Text.RegularExpressions;
using FireAntivirus.Data;
using FireAntivirus.Engine;

namespace FireAntivirus.Services
{
    public class ARPProtection : IMonitor
    {
        private Thread monitorThread;
        private bool isRunning;
        private DataManager dataManager;
        private AntivirusEngine antivirusEngine;
        private Dictionary<string, ARPEntry> arpCache;
        private Dictionary<string, ARPEntry> trustedARPEntries;
        private HashSet<string> localNetworkIPs;
        private string localIPAddress;
        private string localMACAddress;
        private string gatewayIP;
        private string gatewayMAC;
        private int checkInterval;
        private bool enableARPSpoofingDetection;
        private bool enableGatewayProtection;
        private bool autoBlockSpoofing;

        public ARPProtection(DataManager dataManager, AntivirusEngine antivirusEngine)
        {
            this.dataManager = dataManager;
            this.antivirusEngine = antivirusEngine;
            this.arpCache = new Dictionary<string, ARPEntry>();
            this.trustedARPEntries = new Dictionary<string, ARPEntry>();
            this.localNetworkIPs = new HashSet<string>();
            this.checkInterval = 30000;
            this.enableARPSpoofingDetection = true;
            this.enableGatewayProtection = true;
            this.autoBlockSpoofing = false;
            InitializeNetworkInfo();
            LoadTrustedARPEntries();
        }

        private void InitializeNetworkInfo()
        {
            try
            {
                NetworkInterface[] adapters = NetworkInterface.GetAllNetworkInterfaces();
                foreach (NetworkInterface adapter in adapters)
                {
                    if (adapter.OperationalStatus == OperationalStatus.Up &&
                        adapter.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                    {
                        IPInterfaceProperties adapterProperties = adapter.GetIPProperties();
                        IPv4InterfaceProperties ipv4Properties = adapterProperties.GetIPv4Properties();

                        foreach (UnicastIPAddressInformation ip in adapterProperties.UnicastAddresses)
                        {
                            if (ip.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                            {
                                localIPAddress = ip.Address.ToString();
                                localMACAddress = adapter.GetPhysicalAddress().ToString();
                                break;
                            }
                        }

                        foreach (GatewayIPAddressInformation gateway in adapterProperties.GatewayAddresses)
                        {
                            if (gateway.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                            {
                                gatewayIP = gateway.Address.ToString();
                                break;
                            }
                        }

                        if (!string.IsNullOrEmpty(localIPAddress) && !string.IsNullOrEmpty(gatewayIP))
                        {
                            break;
                        }
                    }
                }

                if (!string.IsNullOrEmpty(localIPAddress))
                {
                    DiscoverLocalNetwork();
                }

                if (!string.IsNullOrEmpty(gatewayIP))
                {
                    gatewayMAC = GetMACAddress(gatewayIP);
                }
            }
            catch (Exception ex)
            {
                LogError("初始化网络信息失败: " + ex.Message);
            }
        }

        private void DiscoverLocalNetwork()
        {
            try
            {
                string[] parts = localIPAddress.Split('.');
                if (parts.Length == 4)
                {
                    string networkPrefix = $"{parts[0]}.{parts[1]}.{parts[2]}";

                    for (int i = 1; i <= 254; i++)
                    {
                        string ip = $"{networkPrefix}.{i}";
                        if (ip != localIPAddress)
                        {
                            Ping ping = new Ping();
                            try
                            {
                                PingReply reply = ping.Send(ip, 100);
                                if (reply.Status == IPStatus.Success)
                                {
                                    localNetworkIPs.Add(ip);
                                }
                            }
                            catch
                            {
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                LogError("发现本地网络失败: " + ex.Message);
            }
        }

        private void LoadTrustedARPEntries()
        {
            try
            {
                string entriesPath = Path.Combine(dataManager.GetDataDirectory(), "trusted_arp_entries.json");
                if (System.IO.File.Exists(entriesPath))
                {
                    string json = System.IO.File.ReadAllText(entriesPath);
                    var entries = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, ARPEntry>>(json);
                    if (entries != null)
                    {
                        trustedARPEntries = entries;
                    }
                }
            }
            catch (Exception ex)
            {
                LogError("加载可信ARP条目失败: " + ex.Message);
            }
        }

        private void SaveTrustedARPEntries()
        {
            try
            {
                string entriesPath = Path.Combine(dataManager.GetDataDirectory(), "trusted_arp_entries.json");
                string json = System.Text.Json.JsonSerializer.Serialize(trustedARPEntries, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
                System.IO.File.WriteAllText(entriesPath, json);
            }
            catch (Exception ex)
            {
                LogError("保存可信ARP条目失败: " + ex.Message);
            }
        }

        public void Start()
        {
            if (isRunning) return;
            isRunning = true;
            monitorThread = new Thread(MonitorLoop);
            monitorThread.IsBackground = true;
            monitorThread.Start();
            LogInfo("ARP防护已启动");
        }

        public void Stop()
        {
            isRunning = false;
            if (monitorThread != null && monitorThread.IsAlive)
            {
                monitorThread.Join(5000);
            }
            LogInfo("ARP防护已停止");
        }

        private void MonitorLoop()
        {
            while (isRunning)
            {
                try
                {
                    UpdateARPCache();
                    if (enableARPSpoofingDetection)
                    {
                        CheckARPSpoofing();
                    }
                    if (enableGatewayProtection)
                    {
                        CheckGatewayARP();
                    }
                    Thread.Sleep(checkInterval);
                }
                catch (Exception ex)
                {
                    LogError("ARP防护监控异常: " + ex.Message);
                    Thread.Sleep(5000);
                }
            }
        }

        public void UpdateARPCache()
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = "arp",
                    Arguments = "-a",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using (Process process = Process.Start(psi))
                {
                    string output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();

                    ParseARPOutput(output);
                }
            }
            catch (Exception ex)
            {
                LogError("更新ARP缓存失败: " + ex.Message);
            }
        }

        private void ParseARPOutput(string output)
        {
            try
            {
                Dictionary<string, ARPEntry> newCache = new Dictionary<string, ARPEntry>();
                string[] lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

                foreach (string line in lines)
                {
                    Match match = Regex.Match(line.Trim(), @"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fA-F-]{17})\s+(\w+)");
                    if (match.Success)
                    {
                        string ip = match.Groups[1].Value;
                        string mac = match.Groups[2].Value;
                        string type = match.Groups[3].Value;

                        ARPEntry entry = new ARPEntry
                        {
                            IPAddress = ip,
                            MACAddress = mac,
                            Type = type,
                            LastSeen = DateTime.Now
                        };

                        newCache[ip] = entry;
                    }
                }

                arpCache = newCache;
            }
            catch (Exception ex)
            {
                LogError("解析ARP输出失败: " + ex.Message);
            }
        }

        public void CheckARPSpoofing()
        {
            try
            {
                foreach (var kvp in arpCache)
                {
                    string ip = kvp.Key;
                    ARPEntry currentEntry = kvp.Value;

                    if (trustedARPEntries.ContainsKey(ip))
                    {
                        ARPEntry trustedEntry = trustedARPEntries[ip];
                        if (currentEntry.MACAddress != trustedEntry.MACAddress)
                        {
                            HandleARPSpoofing(ip, trustedEntry.MACAddress, currentEntry.MACAddress);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                LogError("检查ARP欺骗失败: " + ex.Message);
            }
        }

        private void HandleARPSpoofing(string ip, string originalMAC, string newMAC)
        {
            string message = $"检测到ARP欺骗: {ip}\n" +
                            $"原始MAC: {originalMAC}\n" +
                            $"当前MAC: {newMAC}";

            LogWarning(message);

            ARPThreatDetection detection = new ARPThreatDetection
            {
                Id = Guid.NewGuid().ToString(),
                FilePath = ip,
                ThreatType = "ARPSpoofing",
                ThreatName = "ARP欺骗攻击",
                Confidence = 0.95,
                DetectionTime = DateTime.Now,
                DetectionMethod = "ARP缓存监控",
                ActionTaken = autoBlockSpoofing ? "自动阻止" : "无",
                AdditionalInfo = message
            };
            dataManager.LogThreat($"检测到ARP欺骗: {detection.FilePath}", $"威胁类型: {detection.ThreatType}, 详细信息: {detection.AdditionalInfo}");

            if (autoBlockSpoofing)
            {
                BlockARPSpoofing(ip);
            }
        }

        public void CheckGatewayARP()
        {
            try
            {
                if (string.IsNullOrEmpty(gatewayIP) || string.IsNullOrEmpty(gatewayMAC)) return;

                if (arpCache.ContainsKey(gatewayIP))
                {
                    ARPEntry currentEntry = arpCache[gatewayIP];
                    if (currentEntry.MACAddress != gatewayMAC)
                    {
                        string message = $"检测到网关ARP欺骗: {gatewayIP}\n" +
                                        $"原始MAC: {gatewayMAC}\n" +
                                        $"当前MAC: {currentEntry.MACAddress}";

                        LogWarning(message);

                        ARPThreatDetection detection = new ARPThreatDetection
                        {
                            Id = Guid.NewGuid().ToString(),
                            FilePath = gatewayIP,
                            ThreatType = "GatewayARPSpoofing",
                            ThreatName = "网关ARP欺骗攻击",
                            Confidence = 0.99,
                            DetectionTime = DateTime.Now,
                            DetectionMethod = "ARP缓存监控",
                            ActionTaken = autoBlockSpoofing ? "自动恢复网关ARP" : "无",
                            AdditionalInfo = message
                        };
                        dataManager.LogThreat($"检测到ARP欺骗: {detection.FilePath}", $"威胁类型: {detection.ThreatType}, 详细信息: {detection.AdditionalInfo}");

                        if (autoBlockSpoofing)
                        {
                            RestoreGatewayARP();
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                LogError("检查网关ARP失败: " + ex.Message);
            }
        }

        private string GetMACAddress(string ipAddress)
        {
            try
            {
                UpdateARPCache();
                if (arpCache.ContainsKey(ipAddress))
                {
                    return arpCache[ipAddress].MACAddress;
                }
                return null;
            }
            catch
            {
                return null;
            }
        }

        public bool AddTrustedARPEntry(string ip, string mac)
        {
            try
            {
                ARPEntry entry = new ARPEntry
                {
                    IPAddress = ip,
                    MACAddress = mac,
                    Type = "static",
                    LastSeen = DateTime.Now
                };

                trustedARPEntries[ip] = entry;
                SaveTrustedARPEntries();
                LogInfo($"添加可信ARP条目: {ip} -> {mac}");
                return true;
            }
            catch (Exception ex)
            {
                LogError($"添加可信ARP条目异常: " + ex.Message);
                return false;
            }
        }

        public bool RemoveTrustedARPEntry(string ip)
        {
            try
            {
                if (trustedARPEntries.Remove(ip))
                {
                    SaveTrustedARPEntries();
                    LogInfo($"移除可信ARP条目: {ip}");
                    return true;
                }
                return false;
            }
            catch (Exception ex)
            {
                LogError($"移除可信ARP条目异常: " + ex.Message);
                return false;
            }
        }

        public bool BlockARPSpoofing(string ipAddress)
        {
            try
            {
                if (trustedARPEntries.ContainsKey(ipAddress))
                {
                    ARPEntry trustedEntry = trustedARPEntries[ipAddress];
                    string command = $"arp -s {ipAddress} {trustedEntry.MACAddress}";

                    ProcessStartInfo psi = new ProcessStartInfo
                    {
                        FileName = "cmd.exe",
                        Arguments = $"/c {command}",
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        Verb = "runas"
                    };

                    Process process = Process.Start(psi);
                    process.WaitForExit();

                    if (process.ExitCode == 0)
                    {
                        LogInfo($"ARP欺骗阻止成功: {ipAddress}");
                        return true;
                    }
                    else
                    {
                        LogError($"ARP欺骗阻止失败: {ipAddress}, 退出代码: {process.ExitCode}");
                        return false;
                    }
                }
                return false;
            }
            catch (Exception ex)
            {
                LogError($"阻止ARP欺骗异常: " + ex.Message);
                return false;
            }
        }

        public bool RestoreGatewayARP()
        {
            try
            {
                if (!string.IsNullOrEmpty(gatewayIP) && !string.IsNullOrEmpty(gatewayMAC))
                {
                    string command = $"arp -s {gatewayIP} {gatewayMAC}";

                    ProcessStartInfo psi = new ProcessStartInfo
                    {
                        FileName = "cmd.exe",
                        Arguments = $"/c {command}",
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        Verb = "runas"
                    };

                    Process process = Process.Start(psi);
                    process.WaitForExit();

                    if (process.ExitCode == 0)
                    {
                        LogInfo($"网关ARP恢复成功: {gatewayIP}");
                        return true;
                    }
                    else
                    {
                        LogError($"网关ARP恢复失败: {gatewayIP}, 退出代码: {process.ExitCode}");
                        return false;
                    }
                }
                return false;
            }
            catch (Exception ex)
            {
                LogError($"恢复网关ARP异常: " + ex.Message);
                return false;
            }
        }

        public void FlushARPCache()
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = "arp",
                    Arguments = "-d *",
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                Process process = Process.Start(psi);
                process.WaitForExit();

                if (process.ExitCode == 0)
                {
                    LogInfo("ARP缓存清除成功");
                    UpdateARPCache();
                }
                else
                {
                    LogError($"ARP缓存清除失败, 退出代码: {process.ExitCode}");
                }
            }
            catch (Exception ex)
            {
                LogError("清除ARP缓存异常: " + ex.Message);
            }
        }

        public Dictionary<string, ARPEntry> GetARPCache()
        {
            return new Dictionary<string, ARPEntry>(arpCache);
        }

        public Dictionary<string, ARPEntry> GetTrustedARPEntries()
        {
            return new Dictionary<string, ARPEntry>(trustedARPEntries);
        }

        public string GetLocalIPAddress()
        {
            return localIPAddress;
        }

        public string GetLocalMACAddress()
        {
            return localMACAddress;
        }

        public string GetGatewayIP()
        {
            return gatewayIP;
        }

        public string GetGatewayMAC()
        {
            return gatewayMAC;
        }

        public void SetCheckInterval(int milliseconds)
        {
            checkInterval = milliseconds;
        }

        public void SetARPSpoofingDetection(bool enabled)
        {
            enableARPSpoofingDetection = enabled;
        }

        public void SetGatewayProtection(bool enabled)
        {
            enableGatewayProtection = enabled;
        }

        public void SetAutoBlockSpoofing(bool enabled)
        {
            autoBlockSpoofing = enabled;
        }

        private void LogInfo(string message)
        {
            dataManager.LogInfo("[ARP防护] " + message);
        }

        private void LogWarning(string message)
        {
            dataManager.LogWarning("[ARP防护] " + message);
        }

        private void LogError(string message)
        {
            dataManager.LogError("[ARP防护] " + message);
        }
    }

    public class ARPEntry
    {
        public string IPAddress { get; set; }
        public string MACAddress { get; set; }
        public string Type { get; set; }
        public DateTime LastSeen { get; set; }
    }

    public class ARPThreatDetection
    {
        public string Id { get; set; }
        public string FilePath { get; set; }
        public string ThreatType { get; set; }
        public string ThreatName { get; set; }
        public double Confidence { get; set; }
        public DateTime DetectionTime { get; set; }
        public string DetectionMethod { get; set; }
        public string ActionTaken { get; set; }
        public string AdditionalInfo { get; set; }
    }
}
