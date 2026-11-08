using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;

namespace FireAntivirus.Engine.Analyzers.Protection
{
    /// <summary>
    /// USB防护分析器 - 分析USB设备安全
    /// </summary>
    public class USBProtectionAnalyzer
    {
        private readonly HashSet<string> _authorizedDevices;
        private readonly HashSet<string> _blockedDevices;
        private readonly Dictionary<string, USBDeviceInfo> _deviceHistory;

        public USBProtectionAnalyzer()
        {
            _authorizedDevices = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _blockedDevices = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _deviceHistory = new Dictionary<string, USBDeviceInfo>();
        }

        public USBProtectionResult Analyze()
        {
            var result = new USBProtectionResult
            {
                Devices = new List<USBDeviceInfo>(),
                SuspiciousDevices = new List<USBDeviceInfo>(),
                Warnings = new List<string>()
            };

            try
            {
                // 获取所有USB设备
                using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_USBHub");
                foreach (ManagementObject obj in searcher.Get())
                {
                    var device = new USBDeviceInfo
                    {
                        DeviceID = obj["DeviceID"]?.ToString() ?? "",
                        Description = obj["Description"]?.ToString() ?? "",
                        Manufacturer = obj["Manufacturer"]?.ToString() ?? "Unknown",
                        Status = obj["Status"]?.ToString() ?? "Unknown"
                    };

                    // 获取更多信息
                    GetAdditionalDeviceInfo(device);

                    result.Devices.Add(device);

                    // 检查是否可疑
                    if (IsSuspiciousDevice(device))
                    {
                        device.IsSuspicious = true;
                        result.SuspiciousDevices.Add(device);
                    }
                }

                // 获取可移动存储设备
                using var diskSearcher = new ManagementObjectSearcher("SELECT * FROM Win32_LogicalDisk WHERE DriveType = 2");
                foreach (ManagementObject obj in diskSearcher.Get())
                {
                    var drive = new USBStorageInfo
                    {
                        DriveLetter = obj["DeviceID"]?.ToString() ?? "",
                        VolumeName = obj["VolumeName"]?.ToString() ?? "Removable Disk",
                        SizeGB = Convert.ToUInt64(obj["Size"] ?? 0) / (1024 * 1024 * 1024),
                        FreeSpaceGB = Convert.ToUInt64(obj["FreeSpace"] ?? 0) / (1024 * 1024 * 1024),
                        FileSystem = obj["FileSystem"]?.ToString() ?? ""
                    };

                    result.StorageDevices.Add(drive);

                    // 扫描U盘中的自动运行文件
                    if (Directory.Exists(drive.DriveLetter))
                    {
                        CheckAutoRunFiles(drive.DriveLetter, result);
                    }
                }

                result.TotalDevices = result.Devices.Count;
                result.StorageCount = result.StorageDevices.Count;
                result.SuspiciousCount = result.SuspiciousDevices.Count;

                if (result.SuspiciousCount > 0)
                {
                    result.Warnings.Add($"发现 {result.SuspiciousCount} 个可疑USB设备");
                }
            }
            catch (Exception ex)
            {
                result.Warnings.Add($"USB设备分析错误: {ex.Message}");
            }

            return result;
        }

        private void GetAdditionalDeviceInfo(USBDeviceInfo device)
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    $"ASSOCIATORS OF {{Win32_USBHub.DeviceID='{device.DeviceID.Replace("\\", "\\\\")}'}} WHERE ResultClass=Win32_PnPEntity");
                
                foreach (ManagementObject obj in searcher.Get())
                {
                    if (obj["ClassGuid"] != null)
                    {
                        device.ClassGuid = obj["ClassGuid"].ToString();
                    }
                    if (obj["Service"] != null)
                    {
                        device.Service = obj["Service"].ToString();
                    }
                    break;
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "USBProtectionAnalyzer.cs 捕获异常", ex.Message); }
        }

        private bool IsSuspiciousDevice(USBDeviceInfo device)
        {
            // 检查是否在黑名单
            if (_blockedDevices.Contains(device.DeviceID))
            {
                device.SuspicionReason = "设备在黑名单中";
                return true;
            }

            // 检查可疑描述
            var suspiciousDescriptions = new[] { "rubber ducky", "badusb", "hid", "keyboard" };
            foreach (var desc in suspiciousDescriptions)
            {
                if (device.Description.Contains(desc, StringComparison.OrdinalIgnoreCase))
                {
                    device.SuspicionReason = "可疑设备类型";
                    return true;
                }
            }

            // 检查未知厂商
            if (string.IsNullOrEmpty(device.Manufacturer) || 
                device.Manufacturer.Equals("Unknown", StringComparison.OrdinalIgnoreCase))
            {
                // 未知厂商可能是可疑的，但不一定是威胁
                device.SuspicionReason = "未知厂商";
            }

            return false;
        }

        private void CheckAutoRunFiles(string driveLetter, USBProtectionResult result)
        {
            try
            {
                // 检查autorun.inf
                var autorunPath = Path.Combine(driveLetter, "autorun.inf");
                if (File.Exists(autorunPath))
                {
                    result.SuspiciousFiles.Add(new USBSuspiciousFile
                    {
                        Path = autorunPath,
                        Type = "自动运行文件",
                        Risk = "高"
                    });
                    result.Warnings.Add($"发现自动运行文件: {autorunPath}");
                }

                // 检查可疑可执行文件
                var suspiciousExtensions = new[] { ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js" };
                foreach (var ext in suspiciousExtensions)
                {
                    var files = Directory.GetFiles(driveLetter, $"*{ext}", SearchOption.TopDirectoryOnly);
                    foreach (var file in files)
                    {
                        var fileName = Path.GetFileName(file).ToLower();
                        if (IsSuspiciousFileName(fileName))
                        {
                            result.SuspiciousFiles.Add(new USBSuspiciousFile
                            {
                                Path = file,
                                Type = "可疑可执行文件",
                                Risk = "中"
                            });
                        }
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "USBProtectionAnalyzer.cs 捕获异常", ex.Message); }
        }

        private bool IsSuspiciousFileName(string fileName)
        {
            var suspiciousNames = new[]
            {
                "autorun", "setup", "install", "launcher", "start",
                "password", "hack", "crack", "keygen", "patch"
            };

            foreach (var name in suspiciousNames)
            {
                if (fileName.Contains(name))
                {
                    return true;
                }
            }

            return false;
        }

        public void AuthorizeDevice(string deviceId)
        {
            _authorizedDevices.Add(deviceId);
            _blockedDevices.Remove(deviceId);
        }

        public void BlockDevice(string deviceId)
        {
            _blockedDevices.Add(deviceId);
            _authorizedDevices.Remove(deviceId);
        }

        public bool IsAuthorized(string deviceId)
        {
            return _authorizedDevices.Contains(deviceId);
        }

        public bool IsBlocked(string deviceId)
        {
            return _blockedDevices.Contains(deviceId);
        }
    }

    public class USBProtectionResult
    {
        public List<USBDeviceInfo> Devices { get; set; }
        public List<USBDeviceInfo> SuspiciousDevices { get; set; }
        public List<USBStorageInfo> StorageDevices { get; set; } = new List<USBStorageInfo>();
        public List<USBSuspiciousFile> SuspiciousFiles { get; set; } = new List<USBSuspiciousFile>();
        public List<string> Warnings { get; set; }
        public int TotalDevices { get; set; }
        public int StorageCount { get; set; }
        public int SuspiciousCount { get; set; }
    }

    public class USBDeviceInfo
    {
        public string DeviceID { get; set; }
        public string Description { get; set; }
        public string Manufacturer { get; set; }
        public string Status { get; set; }
        public string ClassGuid { get; set; }
        public string Service { get; set; }
        public bool IsSuspicious { get; set; }
        public string SuspicionReason { get; set; }
    }

    public class USBStorageInfo
    {
        public string DriveLetter { get; set; }
        public string VolumeName { get; set; }
        public ulong SizeGB { get; set; }
        public ulong FreeSpaceGB { get; set; }
        public string FileSystem { get; set; }
    }

    public class USBSuspiciousFile
    {
        public string Path { get; set; }
        public string Type { get; set; }
        public string Risk { get; set; }
    }
}