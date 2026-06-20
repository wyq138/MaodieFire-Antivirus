// 抖音用户 耄耋杀毒软件 开发，严禁非法反编译
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text.RegularExpressions;

namespace FireAntivirus.Engine.Analyzers.Protection
{
    /// <summary>
    /// WiFi防护分析器 - 分析WiFi网络安全
    /// </summary>
    public class WifiProtectionAnalyzer
    {
        private readonly HashSet<string> _suspiciousSSIDs;
        private readonly HashSet<string> _knownSafeNetworks;
        private readonly List<WiFiNetwork> _scanHistory;

        public WifiProtectionAnalyzer()
        {
            _suspiciousSSIDs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _knownSafeNetworks = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _scanHistory = new List<WiFiNetwork>();
            InitializeSuspiciousPatterns();
        }

        private void InitializeSuspiciousPatterns()
        {
            // 可疑SSID模式
            _suspiciousSSIDs.UnionWith(new[]
            {
                "Free WiFi", "Free Internet", "Public WiFi",
                "FREE_WIFI", "Airport WiFi", "Hotel Guest",
                "Starbucks", "McDonalds", "Library"
            });
        }

        public WifiProtectionResult Analyze()
        {
            var result = new WifiProtectionResult
            {
                Networks = new List<WiFiNetwork>(),
                SuspiciousNetworks = new List<WiFiNetwork>(),
                Warnings = new List<string>()
            };

            try
            {
                // 使用netsh扫描WiFi网络
                var networks = ScanWiFiNetworks();
                result.Networks = networks;

                // 分析每个网络
                foreach (var network in networks)
                {
                    if (IsSuspiciousNetwork(network))
                    {
                        network.IsSuspicious = true;
                        result.SuspiciousNetworks.Add(network);
                    }
                }

                result.TotalNetworks = result.Networks.Count;
                result.SuspiciousCount = result.SuspiciousNetworks.Count;

                if (result.SuspiciousCount > 0)
                {
                    result.Warnings.Add($"发现 {result.SuspiciousCount} 个可疑WiFi网络");
                }
            }
            catch (Exception ex)
            {
                result.Warnings.Add($"WiFi分析错误: {ex.Message}");
            }

            return result;
        }

        private List<WiFiNetwork> ScanWiFiNetworks()
        {
            var networks = new List<WiFiNetwork>();

            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = "wlan show networks mode=bssid",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                };

                using var process = Process.Start(psi);
                if (process == null) return networks;

                var output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                networks = ParseWiFiOutput(output);
            }
            catch { }

            return networks;
        }

        private List<WiFiNetwork> ParseWiFiOutput(string output)
        {
            var networks = new List<WiFiNetwork>();
            WiFiNetwork currentNetwork = null;

            foreach (var line in output.Split('\n'))
            {
                var trimmed = line.Trim();

                if (trimmed.StartsWith("SSID"))
                {
                    if (currentNetwork != null)
                        networks.Add(currentNetwork);

                    var ssidMatch = Regex.Match(trimmed, @"SSID\s+\d+\s*:\s*(.+)");
                    if (ssidMatch.Success)
                    {
                        currentNetwork = new WiFiNetwork
                        {
                            SSID = ssidMatch.Groups[1].Value.Trim()
                        };
                    }
                }
                else if (currentNetwork != null)
                {
                    if (trimmed.StartsWith("网络类型") || trimmed.StartsWith("Network type"))
                    {
                        currentNetwork.NetworkType = trimmed.Split(':').Last().Trim();
                    }
                    else if (trimmed.StartsWith("身份验证") || trimmed.StartsWith("Authentication"))
                    {
                        currentNetwork.Authentication = trimmed.Split(':').Last().Trim();
                        currentNetwork.IsOpen = currentNetwork.Authentication.Contains("Open") ||
                                                 currentNetwork.Authentication.Contains("开放");
                    }
                    else if (trimmed.StartsWith("加密") || trimmed.StartsWith("Encryption"))
                    {
                        currentNetwork.Encryption = trimmed.Split(':').Last().Trim();
                    }
                    else if (trimmed.StartsWith("信号") || trimmed.StartsWith("Signal"))
                    {
                        var signalStr = trimmed.Split(':').Last().Trim();
                        currentNetwork.SignalStrength = ParseSignalStrength(signalStr);
                    }
                    else if (trimmed.StartsWith("BSSID"))
                    {
                        var macMatch = Regex.Match(trimmed, @"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}");
                        if (macMatch.Success)
                        {
                            currentNetwork.BSSID = macMatch.Value;
                        }
                    }
                    else if (trimmed.Contains("频道") || trimmed.Contains("Channel"))
                    {
                        var channelMatch = Regex.Match(trimmed, @"\d+");
                        if (channelMatch.Success)
                        {
                            currentNetwork.Channel = int.Parse(channelMatch.Value);
                        }
                    }
                }
            }

            if (currentNetwork != null)
                networks.Add(currentNetwork);

            return networks;
        }

        private int ParseSignalStrength(string signal)
        {
            // 格式通常是 "XX%"
            var match = Regex.Match(signal, @"\d+");
            return match.Success ? int.Parse(match.Value) : 0;
        }

        private bool IsSuspiciousNetwork(WiFiNetwork network)
        {
            // 开放网络
            if (network.IsOpen)
            {
                network.SuspicionReason = "开放网络，无加密";
                return true;
            }

            // 可疑SSID
            foreach (var suspicious in _suspiciousSSIDs)
            {
                if (network.SSID.Contains(suspicious, StringComparison.OrdinalIgnoreCase))
                {
                    network.SuspicionReason = "可疑SSID名称";
                    return true;
                }
            }

            // 弱加密
            if (network.Encryption?.Contains("WEP") == true)
            {
                network.SuspicionReason = "使用WEP加密（不安全）";
                return true;
            }

            // 信号过强可能是钓鱼AP
            if (network.SignalStrength > 95)
            {
                network.SuspicionReason = "信号异常强，可能是钓鱼AP";
                return true;
            }

            // SSID模仿已知网络
            if (IsMimickingKnownNetwork(network.SSID))
            {
                network.SuspicionReason = "模仿已知网络";
                return true;
            }

            return false;
        }

        private bool IsMimickingKnownNetwork(string ssid)
        {
            // 检查是否是已知安全网络的变体
            foreach (var known in _knownSafeNetworks)
            {
                if (ssid.Length == known.Length + 1 || ssid.Length == known.Length - 1)
                {
                    // 可能是拼写错误或变体
                    var diff = ssid.Zip(known, (a, b) => a != b).Count(x => x);
                    if (diff <= 2)
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        public void AddKnownSafeNetwork(string ssid)
        {
            _knownSafeNetworks.Add(ssid);
        }

        public void AddSuspiciousSSID(string ssid)
        {
            _suspiciousSSIDs.Add(ssid);
        }

        public WiFiConnectionResult ConnectToSafe(string ssid, string password)
        {
            var result = new WiFiConnectionResult { SSID = ssid };

            try
            {
                // 创建配置文件并连接
                var profileXml = $@"<?xml version=""1.0""?>
<WLANProfile xmlns=""http://www.microsoft.com/networking/WLAN/profile/v1"">
    <name>{ssid}</name>
    <SSIDConfig>
        <SSID>
            <name>{ssid}</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>auto</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>WPA2PSK</authentication>
                <encryption>AES</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
            <sharedKey>
                <keyType>passPhrase</keyType>
                <protected>false</protected>
                <keyMaterial>{password}</keyMaterial>
            </sharedKey>
        </security>
    </MSM>
</WLANProfile>";

                // 保存配置文件
                var tempPath = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"{ssid}.xml");
                System.IO.File.WriteAllText(tempPath, profileXml);

                // 添加配置
                var addProfile = new ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = $"wlan add profile filename=\"{tempPath}\"",
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var addProcess = Process.Start(addProfile);
                addProcess?.WaitForExit();

                // 连接
                var connect = new ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = $"wlan connect name=\"{ssid}\"",
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var connectProcess = Process.Start(connect);
                connectProcess?.WaitForExit();

                result.Success = true;
                System.IO.File.Delete(tempPath);
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
            }

            return result;
        }
    }

    public class WifiProtectionResult
    {
        public List<WiFiNetwork> Networks { get; set; }
        public List<WiFiNetwork> SuspiciousNetworks { get; set; }
        public List<string> Warnings { get; set; }
        public int TotalNetworks { get; set; }
        public int SuspiciousCount { get; set; }
    }

    public class WiFiNetwork
    {
        public string SSID { get; set; }
        public string BSSID { get; set; }
        public string NetworkType { get; set; }
        public string Authentication { get; set; }
        public string Encryption { get; set; }
        public int SignalStrength { get; set; }
        public int Channel { get; set; }
        public bool IsOpen { get; set; }
        public bool IsSuspicious { get; set; }
        public string SuspicionReason { get; set; }
    }

    public class WiFiConnectionResult
    {
        public string SSID { get; set; }
        public bool Success { get; set; }
        public string Error { get; set; }
    }
}
