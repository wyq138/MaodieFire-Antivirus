// 抖音用户 耄耋杀毒软件 开发，严禁非法反编译
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;

namespace FireAntivirus.Engine.Analyzers.Protection
{
    /// <summary>
    /// 蓝牙防护分析器 - 分析蓝牙设备安全
    /// </summary>
    public class BluetoothProtectionAnalyzer
    {
        private readonly HashSet<string> _authorizedDevices;
        private readonly HashSet<string> _blockedDevices;
        private readonly Dictionary<string, BluetoothDeviceInfo> _deviceHistory;

        public BluetoothProtectionAnalyzer()
        {
            _authorizedDevices = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _blockedDevices = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _deviceHistory = new Dictionary<string, BluetoothDeviceInfo>();
        }

        public BluetoothProtectionResult Analyze()
        {
            var result = new BluetoothProtectionResult
            {
                Devices = new List<BluetoothDeviceInfo>(),
                SuspiciousDevices = new List<BluetoothDeviceInfo>(),
                Warnings = new List<string>()
            };

            try
            {
                // 检查蓝牙服务状态
                CheckBluetoothService(result);

                // 获取已配对设备
                var pairedDevices = GetPairedDevices();
                result.Devices.AddRange(pairedDevices);

                // 分析每个设备
                foreach (var device in result.Devices)
                {
                    if (IsSuspiciousDevice(device))
                    {
                        device.IsSuspicious = true;
                        result.SuspiciousDevices.Add(device);
                    }
                }

                // 检查蓝牙安全设置
                CheckBluetoothSecuritySettings(result);

                result.TotalDevices = result.Devices.Count;
                result.SuspiciousCount = result.SuspiciousDevices.Count;

                if (result.IsBluetoothOn && result.IsDiscoverable)
                {
                    result.Warnings.Add("蓝牙可被发现，建议关闭");
                }

                if (result.SuspiciousCount > 0)
                {
                    result.Warnings.Add($"发现 {result.SuspiciousCount} 个可疑蓝牙设备");
                }
            }
            catch (Exception ex)
            {
                result.Warnings.Add($"蓝牙分析错误: {ex.Message}");
            }

            return result;
        }

        private void CheckBluetoothService(BluetoothProtectionResult result)
        {
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Service WHERE Name='bthserv'");
                foreach (ManagementObject obj in searcher.Get())
                {
                    result.IsBluetoothOn = obj["State"]?.ToString() == "Running";
                    break;
                }
            }
            catch { }
        }

        private List<BluetoothDeviceInfo> GetPairedDevices()
        {
            var devices = new List<BluetoothDeviceInfo>();

            try
            {
                // 使用PowerShell获取蓝牙设备
                var psi = new ProcessStartInfo
                {
                    FileName = "powershell",
                    Arguments = "-Command \"Get-PnpDevice | Where-Object {$_.Class -eq 'Bluetooth'}\"",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                };

                using var process = Process.Start(psi);
                if (process == null) return devices;

                var output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                // 解析输出
                devices = ParseBluetoothDevices(output);
            }
            catch { }

            return devices;
        }

        private List<BluetoothDeviceInfo> ParseBluetoothDevices(string output)
        {
            var devices = new List<BluetoothDeviceInfo>();

            try
            {
                var lines = output.Split('\n');
                BluetoothDeviceInfo currentDevice = null;

                foreach (var line in lines)
                {
                    var trimmed = line.Trim();
                    
                    if (!string.IsNullOrEmpty(trimmed) && !trimmed.StartsWith("Status") && !trimmed.StartsWith("---"))
                    {
                        var parts = trimmed.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length >= 3)
                        {
                            currentDevice = new BluetoothDeviceInfo
                            {
                                Status = parts[0],
                                Class = parts[1],
                                Name = string.Join(" ", parts.Skip(2))
                            };
                            devices.Add(currentDevice);
                        }
                    }
                }
            }
            catch { }

            return devices;
        }

        private bool IsSuspiciousDevice(BluetoothDeviceInfo device)
        {
            // 检查未知设备
            if (device.Status == "Unknown")
            {
                device.SuspicionReason = "未知设备状态";
                return true;
            }

            // 检查可疑设备名称
            var suspiciousNames = new[] { "hack", "exploit", "attack", "malware" };
            foreach (var name in suspiciousNames)
            {
                if (device.Name.Contains(name, StringComparison.OrdinalIgnoreCase))
                {
                    device.SuspicionReason = "可疑设备名称";
                    return true;
                }
            }

            // 检查是否在黑名单
            if (_blockedDevices.Contains(device.Name))
            {
                device.SuspicionReason = "设备在黑名单中";
                return true;
            }

            return false;
        }

        private void CheckBluetoothSecuritySettings(BluetoothProtectionResult result)
        {
            try
            {
                // 检查蓝牙发现设置
                var psi = new ProcessStartInfo
                {
                    FileName = "powershell",
                    Arguments = "-Command \"Get-NetFirewallRule | Where-Object {$_.DisplayName -like '*Bluetooth*'}\"",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                };

                using var process = Process.Start(psi);
                if (process != null)
                {
                    var output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();

                    result.FirewallRulesCount = output.Split('\n').Count(l => l.Contains("Bluetooth"));
                }

                // 检查注册表中的蓝牙设置
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\bthserv\Parameters");
                if (key != null)
                {
                    var discovery = key.GetValue("BluetoothServiceDisplayName");
                    result.HasValidConfiguration = discovery != null;
                }
            }
            catch { }
        }

        public void AuthorizeDevice(string deviceName)
        {
            _authorizedDevices.Add(deviceName);
            _blockedDevices.Remove(deviceName);
        }

        public void BlockDevice(string deviceName)
        {
            _blockedDevices.Add(deviceName);
            _authorizedDevices.Remove(deviceName);
        }

        public bool IsAuthorized(string deviceName)
        {
            return _authorizedDevices.Contains(deviceName);
        }

        public bool IsBlocked(string deviceName)
        {
            return _blockedDevices.Contains(deviceName);
        }

        public void DisableBluetoothDiscovery()
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "powershell",
                    Arguments = "-Command \"Set-NetFirewallRule -DisplayName '*Bluetooth*' -Enabled False\"",
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var process = Process.Start(psi);
                process?.WaitForExit();
            }
            catch { }
        }
    }

    public class BluetoothProtectionResult
    {
        public List<BluetoothDeviceInfo> Devices { get; set; }
        public List<BluetoothDeviceInfo> SuspiciousDevices { get; set; }
        public List<string> Warnings { get; set; }
        public bool IsBluetoothOn { get; set; }
        public bool IsDiscoverable { get; set; }
        public bool HasValidConfiguration { get; set; }
        public int TotalDevices { get; set; }
        public int SuspiciousCount { get; set; }
        public int FirewallRulesCount { get; set; }
    }

    public class BluetoothDeviceInfo
    {
        public string Name { get; set; }
        public string Address { get; set; }
        public string Status { get; set; }
        public string Class { get; set; }
        public bool IsPaired { get; set; }
        public bool IsConnected { get; set; }
        public bool IsSuspicious { get; set; }
        public string SuspicionReason { get; set; }
        public DateTime LastSeen { get; set; }
    }
}
