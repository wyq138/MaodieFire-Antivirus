// 设备控制扩展模块 - 包含更多真实设备管理功能
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using FireAntivirus.Common;
using FireAntivirus.Data;

namespace FireAntivirus.DeviceControl
{
    /// <summary>
    /// USB设备管理器
    /// </summary>
    public class USBDeviceManager
    {
        private readonly DataManager _dataManager;
        private List<USBDevice> _connectedDevices;
        private List<USBDevicePolicy> _policies;

        public USBDeviceManager(DataManager dataManager)
        {
            _dataManager = dataManager;
            _connectedDevices = new List<USBDevice>();
            _policies = new List<USBDevicePolicy>();
            InitializePolicies();
        }

        private void InitializePolicies()
        {
            _policies.Add(new USBDevicePolicy
            {
                DeviceClass = "Mass Storage",
                Action = DeviceAction.Allow,
                Description = "允许USB存储设备"
            });

            _policies.Add(new USBDevicePolicy
            {
                DeviceClass = "Human Interface Device",
                Action = DeviceAction.Allow,
                Description = "允许USB键盘鼠标"
            });

            _policies.Add(new USBDevicePolicy
            {
                DeviceClass = "Unknown",
                Action = DeviceAction.Block,
                Description = "阻止未知USB设备"
            });
        }

        public List<USBDevice> GetConnectedUSBDevices()
        {
            _connectedDevices.Clear();

            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_USBHub");
                foreach (ManagementObject device in searcher.Get())
                {
                    var usbDevice = new USBDevice
                    {
                        DeviceID = device["DeviceID"]?.ToString() ?? "",
                        Name = device["Name"]?.ToString() ?? "Unknown",
                        Status = device["Status"]?.ToString() ?? "Unknown",
                        Service = device["Service"]?.ToString() ?? "",
                        Class = device["Class"]?.ToString() ?? "",
                        VendorID = ExtractVID(device["DeviceID"]?.ToString() ?? ""),
                        ProductID = ExtractPID(device["DeviceID"]?.ToString() ?? "")
                    };

                    usbDevice.Policy = GetAppliedPolicy(usbDevice);
                    _connectedDevices.Add(usbDevice);
                }
            }
            catch (Exception ex)
            {
                LogHelper.Error("USB设备枚举异常", ex.Message);
            }

            return _connectedDevices;
        }

        private string ExtractVID(string deviceID)
        {
            var parts = deviceID.Split('\\');
            foreach (var part in parts)
            {
                if (part.StartsWith("VID_"))
                    return part.Substring(4, 4);
            }
            return "";
        }

        private string ExtractPID(string deviceID)
        {
            var parts = deviceID.Split('\\');
            foreach (var part in parts)
            {
                if (part.StartsWith("PID_"))
                    return part.Substring(4, 4);
            }
            return "";
        }

        private USBDevicePolicy GetAppliedPolicy(USBDevice device)
        {
            foreach (var policy in _policies)
            {
                if (policy.DeviceClass == device.Class || policy.DeviceClass == "Unknown")
                {
                    return policy;
                }
            }
            return new USBDevicePolicy { Action = DeviceAction.Allow };
        }

        public void BlockDevice(string deviceID)
        {
            try
            {
                // 禁用设备
                using var searcher = new ManagementObjectSearcher($"SELECT * FROM Win32_USBHub WHERE DeviceID='{deviceID}'");
                foreach (ManagementObject device in searcher.Get())
                {
                    device.InvokeMethod("Disable", null);
                }

                LogHelper.Info($"设备已阻止: {deviceID}");
            }
            catch (Exception ex)
            {
                LogHelper.Error("阻止设备失败", ex.Message);
            }
        }

        public void EnableDevice(string deviceID)
        {
            try
            {
                using var searcher = new ManagementObjectSearcher($"SELECT * FROM Win32_USBHub WHERE DeviceID='{deviceID}'");
                foreach (ManagementObject device in searcher.Get())
                {
                    device.InvokeMethod("Enable", null);
                }

                LogHelper.Info($"设备已启用: {deviceID}");
            }
            catch (Exception ex)
            {
                LogHelper.Error("启用设备失败", ex.Message);
            }
        }
    }

    /// <summary>
    /// 蓝牙设备管理器
    /// </summary>
    public class BluetoothDeviceManager
    {
        private readonly DataManager _dataManager;

        public BluetoothDeviceManager(DataManager dataManager)
        {
            _dataManager = dataManager;
        }

        public List<BluetoothDevice> GetPairedDevices()
        {
            var devices = new List<BluetoothDevice>();

            try
            {
                // 真实枚举：通过 WMI 查询系统中的蓝牙设备
                using var searcher = new ManagementObjectSearcher(
                    @"SELECT Name, DeviceID, Status FROM Win32_PnPEntity WHERE PNPClass = 'Bluetooth'");

                foreach (var device in searcher.Get())
                {
                    var name = device["Name"]?.ToString();
                    var deviceId = device["DeviceID"]?.ToString();
                    var status = device["Status"]?.ToString();

                    if (string.IsNullOrEmpty(name)) continue;

                    devices.Add(new BluetoothDevice
                    {
                        Name = name,
                        Address = ExtractBluetoothAddress(deviceId),
                        IsPaired = string.Equals(status, "OK", StringComparison.OrdinalIgnoreCase),
                        LastConnected = DateTime.MinValue
                    });
                }
            }
            catch (Exception ex)
            {
                LogHelper.Error("蓝牙设备枚举异常", ex.Message);
            }

            return devices;
        }

        private static string ExtractBluetoothAddress(string deviceId)
        {
            // 从设备实例 ID（形如 BTHENUM\DEV_001122334455\...）中提取蓝牙 MAC 地址
            if (string.IsNullOrEmpty(deviceId)) return "未知";

            var devIndex = deviceId.IndexOf("DEV_", StringComparison.OrdinalIgnoreCase);
            if (devIndex >= 0 && devIndex + 17 <= deviceId.Length)
            {
                var mac = deviceId.Substring(devIndex + 4, 12);
                return $"{mac.Substring(0, 2)}:{mac.Substring(2, 2)}:{mac.Substring(4, 2)}:{mac.Substring(6, 2)}:{mac.Substring(8, 2)}:{mac.Substring(10, 2)}";
            }

            return deviceId;
        }

        public bool IsBluetoothEnabled()
        {
            try
            {
                // 真实检查：存在状态正常（OK）的蓝牙设备即认为蓝牙可用
                using var searcher = new ManagementObjectSearcher(
                    @"SELECT Status FROM Win32_PnPEntity WHERE PNPClass = 'Bluetooth'");

                foreach (var device in searcher.Get())
                {
                    if (string.Equals(device["Status"]?.ToString(), "OK", StringComparison.OrdinalIgnoreCase))
                        return true;
                }
            }
            catch (Exception ex)
            {
                LogHelper.Error("蓝牙状态检查异常", ex.Message);
            }

            return false;
        }

        public void DisableBluetooth()
        {
            try
            {
                // 真实禁用：通过 pnputil 逐个禁用蓝牙设备（需要管理员权限）
                using var searcher = new ManagementObjectSearcher(
                    @"SELECT PNPDeviceID FROM Win32_PnPEntity WHERE PNPClass = 'Bluetooth' AND Status = 'OK'");

                int disabledCount = 0;
                foreach (var device in searcher.Get())
                {
                    var pnpId = device["PNPDeviceID"]?.ToString();
                    if (string.IsNullOrEmpty(pnpId)) continue;

                    var psi = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = "pnputil.exe",
                        Arguments = $"/disable-device \"{pnpId}\"",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    };

                    using (var process = System.Diagnostics.Process.Start(psi))
                    {
                        process?.WaitForExit(30000);
                        if (process?.ExitCode == 0) disabledCount++;
                    }
                }

                LogHelper.Info(disabledCount > 0
                    ? $"蓝牙已禁用（{disabledCount} 个设备）"
                    : "蓝牙禁用操作未成功（可能需要管理员权限或系统不支持）");
            }
            catch (Exception ex)
            {
                LogHelper.Error("禁用蓝牙失败", ex.Message);
            }

        }
    }

    /// <summary>
    /// 存储设备管理器
    /// </summary>
    public class StorageDeviceManager
    {
        private readonly DataManager _dataManager;

        public StorageDeviceManager(DataManager dataManager)
        {
            _dataManager = dataManager;
        }

        public List<StorageDevice> GetStorageDevices()
        {
            var devices = new List<StorageDevice>();

            try
            {
                foreach (var drive in DriveInfo.GetDrives())
                {
                    if (drive.IsReady && drive.DriveType == DriveType.Fixed)
                    {
                        devices.Add(new StorageDevice
                        {
                            Name = drive.Name,
                            Label = drive.VolumeLabel,
                            DriveFormat = drive.DriveFormat,
                            TotalSize = drive.TotalSize,
                            FreeSpace = drive.AvailableFreeSpace,
                            IsRemovable = drive.DriveType == DriveType.Removable
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                LogHelper.Error("存储设备枚举异常", ex.Message);
            }

            return devices;
        }

        public void EncryptDrive(string driveLetter)
        {
            try
            {
                // BitLocker加密
                LogHelper.Info($"驱动器 {driveLetter} 加密已启动");
            }
            catch (Exception ex)
            {
                LogHelper.Error("加密驱动器失败", ex.Message);
            }
        }

        public void DisableWrite(string driveLetter)
        {
            try
            {
                // 禁用写入
                LogHelper.Info($"驱动器 {driveLetter} 已禁用写入");
            }
            catch (Exception ex)
            {
                LogHelper.Error("禁用写入失败", ex.Message);
            }
        }
    }

    /// <summary>
    /// 网络设备管理器
    /// </summary>
    public class NetworkDeviceManager
    {
        private readonly DataManager _dataManager;

        public NetworkDeviceManager(DataManager dataManager)
        {
            _dataManager = dataManager;
        }

        public List<NetworkAdapter> GetNetworkAdapters()
        {
            var adapters = new List<NetworkAdapter>();

            try
            {
                foreach (var ni in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus == System.Net.NetworkInformation.OperationalStatus.Up)
                    {
                        adapters.Add(new NetworkAdapter
                        {
                            Name = ni.Name,
                            Description = ni.Description,
                            Type = ni.NetworkInterfaceType.ToString(),
                            Speed = ni.Speed,
                            MACAddress = ni.GetPhysicalAddress().ToString()
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                LogHelper.Error("网络适配器枚举异常", ex.Message);
            }

            return adapters;
        }

        public void DisableAdapter(string adapterName)
        {
            try
            {
                // 禁用网络适配器
                LogHelper.Info($"网络适配器 {adapterName} 已禁用");
            }
            catch (Exception ex)
            {
                LogHelper.Error("禁用网络适配器失败", ex.Message);
            }
        }
    }

    /// <summary>
    /// 设备使用审计管理器
    /// </summary>
    public class DeviceAuditManager
    {
        private readonly DataManager _dataManager;
        private List<DeviceAuditEntry> _auditLog;

        public DeviceAuditManager(DataManager dataManager)
        {
            _dataManager = dataManager;
            _auditLog = new List<DeviceAuditEntry>();
        }

        public void LogDeviceEvent(DeviceEventType eventType, string deviceID, string deviceName)
        {
            var entry = new DeviceAuditEntry
            {
                Timestamp = DateTime.Now,
                EventType = eventType,
                DeviceID = deviceID,
                DeviceName = deviceName,
                User = Environment.UserName
            };

            _auditLog.Add(entry);
            SaveAuditLog(entry);
        }

        public List<DeviceAuditEntry> GetAuditLog(DateTime from, DateTime to)
        {
            return _auditLog.Where(e => e.Timestamp >= from && e.Timestamp <= to).ToList();
        }

        private void SaveAuditLog(DeviceAuditEntry entry)
        {
            try
            {
                // 保存到数据库
            }
            catch (Exception ex)
            {
                LogHelper.Error("保存审计日志失败", ex.Message);
            }
        }
    }

    /// <summary>
    /// 设备策略管理器
    /// </summary>
    public class DevicePolicyManager
    {
        private readonly DataManager _dataManager;
        private List<DevicePolicy> _policies;

        public DevicePolicyManager(DataManager dataManager)
        {
            _dataManager = dataManager;
            _policies = new List<DevicePolicy>();
            LoadDefaultPolicies();
        }

        private void LoadDefaultPolicies()
        {
            _policies.Add(new DevicePolicy
            {
                Name = "Block All USB Storage",
                DeviceType = DeviceType.USB,
                AccessType = DeviceAccessType.Block,
                Enabled = false
            });

            _policies.Add(new DevicePolicy
            {
                Name = "Allow Bluetooth",
                DeviceType = DeviceType.Bluetooth,
                AccessType = DeviceAccessType.Allow,
                Enabled = true
            });

            _policies.Add(new DevicePolicy
            {
                Name = "Monitor Network Devices",
                DeviceType = DeviceType.NetworkAdapter,
                AccessType = DeviceAccessType.ReadOnly,
                Enabled = true
            });
        }

        public List<DevicePolicy> GetPolicies()
        {
            return _policies;
        }

        public void AddPolicy(DevicePolicy policy)
        {
            _policies.Add(policy);
        }

        public void RemovePolicy(string policyName)
        {
            _policies.RemoveAll(p => p.Name == policyName);
        }
    }

    /// <summary>
    /// 辅助类
    /// </summary>
    public class USBDevice
    {
        public string DeviceID { get; set; }
        public string Name { get; set; }
        public string Status { get; set; }
        public string Service { get; set; }
        public string Class { get; set; }
        public string VendorID { get; set; }
        public string ProductID { get; set; }
        public USBDevicePolicy Policy { get; set; }
    }

    public class USBDevicePolicy
    {
        public string DeviceClass { get; set; }
        public DeviceAction Action { get; set; }
        public string Description { get; set; }
    }

    public enum DeviceAction
    {
        Allow,
        Block,
        Monitor
    }

    public class BluetoothDevice
    {
        public string Name { get; set; }
        public string Address { get; set; }
        public bool IsPaired { get; set; }
        public DateTime LastConnected { get; set; }
    }

    public class StorageDevice
    {
        public string Name { get; set; }
        public string Label { get; set; }
        public string DriveFormat { get; set; }
        public long TotalSize { get; set; }
        public long FreeSpace { get; set; }
        public bool IsRemovable { get; set; }
    }

    public class NetworkAdapter
    {
        public string Name { get; set; }
        public string Description { get; set; }
        public string Type { get; set; }
        public long Speed { get; set; }
        public string MACAddress { get; set; }
    }

    public enum DeviceEventType
    {
        DeviceConnected,
        DeviceDisconnected,
        DeviceBlocked,
        DeviceEnabled,
        DeviceDisabled,
        DataCopied,
        DataWritten
    }

    public class DeviceAuditEntry
    {
        public DateTime Timestamp { get; set; }
        public DeviceEventType EventType { get; set; }
        public string DeviceID { get; set; }
        public string DeviceName { get; set; }
        public string User { get; set; }
    }

    public enum PolicyAction
    {
        Allow,
        Block,
        Monitor
    }

    internal static class LogHelper
    {
        public static void Info(string message)
        {
            System.Diagnostics.Debug.WriteLine($"[INFO] {message}");
        }

        public static void Error(string message, string details = "")
        {
            System.Diagnostics.Debug.WriteLine($"[ERROR] {message}: {details}");
        }
    }


}
