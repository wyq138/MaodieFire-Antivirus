using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Threading;
using FireAntivirus.Data;
using FireAntivirus.Common.Notification;
using Microsoft.Win32;

namespace FireAntivirus.Services
{
    /// <summary>
    /// 设备控制服务 - 通过注册表和系统策略实现设备阻止
    /// </summary>
    public class DeviceControlService : IMonitor
    {
        private Thread _monitorThread;
        private ManagementEventWatcher? _usbWatcher;
        private ManagementEventWatcher? _deviceRemovalWatcher;
        private bool _isRunning;
        private DataManager _dataManager;
        private List<DeviceInfo> _connectedDevices;
        private List<string> _blockedDeviceIds;
        private List<string> _trustedDeviceIds;
        private bool _enableDeviceControl = true;
        private bool _blockUSB = false;
        private bool _blockBluetooth = false;
        private bool _blockCDROM = false;

        public bool IsRunning => _isRunning;
        public bool BlockUSB => _blockUSB;
        public bool BlockBluetooth => _blockBluetooth;
        public int ConnectedDevicesCount => _connectedDevices.Count;
        public int BlockedDevicesCount => _blockedDeviceIds.Count;
        public int TrustedDevicesCount => _trustedDeviceIds.Count;

        // 注册表路径
        private const string UsbStorageRegistryPath = @"SYSTEM\CurrentControlSet\Services\USBSTOR";
        private const string UsbRegistryPath = @"SYSTEM\CurrentControlSet\Enum\USB";
        private const string BluetoothRegistryPath = @"SYSTEM\CurrentControlSet\Services\bthserv";
        private const string CdRomRegistryPath = @"SYSTEM\CurrentControlSet\Services\cdrom";

        // 设备安装策略路径
        private const string DeviceInstallPolicyPath = @"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions";

        public DeviceControlService(DataManager dataManager)
        {
            _dataManager = dataManager;
            _connectedDevices = new List<DeviceInfo>();
            _blockedDeviceIds = new List<string>();
            _trustedDeviceIds = new List<string>();
            LoadSettings();
        }

        public void Start()
        {
            if (_isRunning) return;
            
            _isRunning = true;
            
            // 应用设备阻止策略
            if (_blockUSB)
                ApplyUsbBlockPolicy();
            if (_blockBluetooth)
                ApplyBluetoothBlockPolicy();
            
            // 启动设备监控
            StartWmiWatcher();
            
            // 启动轮询监控线程
            _monitorThread = new Thread(MonitorDevices);
            _monitorThread.IsBackground = true;
            _monitorThread.Start();

            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "DeviceControlStart",
                Message = "设备控制服务已启动",
                Details = $"USB阻止: {_blockUSB}, 蓝牙阻止: {_blockBluetooth}"
            });
        }

        public void Stop()
        {
            if (!_isRunning) return;
            
            _isRunning = false;
            
            // 停止WMI监控
            StopWmiWatcher();
            
            _monitorThread?.Join(2000);
            
            // 恢复设备访问（如果需要）
            // RestoreDeviceAccess();

            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "DeviceControlStop",
                Message = "设备控制服务已停止"
            });
        }

        #region 设备阻止策略

        /// <summary>
        /// 应用USB存储设备阻止策略
        /// </summary>
        public bool ApplyUsbBlockPolicy()
        {
            try
            {
                if (!HasAdminPrivileges())
                {
                    NotificationService.Instance.ShowNotification(
                        "设备控制",
                        "需要管理员权限才能阻止USB设备",
                        NotificationType.Warning
                    );
                    return false;
                }

                // 方法1：禁用USBSTOR服务
                using (var key = Registry.LocalMachine.OpenSubKey(UsbStorageRegistryPath, true))
                {
                    if (key != null)
                    {
                        key.SetValue("Start", 4, RegistryValueKind.DWord); // 4 = Disabled
                    }
                }

                // 方法2：设置设备安装限制策略
                using (var key = Registry.LocalMachine.CreateSubKey(DeviceInstallPolicyPath))
                {
                    if (key != null)
                    {
                        key.SetValue("DenyRemovableDevices", 1, RegistryValueKind.DWord);
                        key.SetValue("DenyUnspecifiedDevices", 0, RegistryValueKind.DWord);
                    }
                }

                FlushPolicyChanges();

                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "UsbBlockApplied",
                    Message = "USB设备阻止策略已应用",
                    Details = "已禁用USBSTOR服务"
                });

                return true;
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "UsbBlockError",
                    Message = "应用USB阻止策略失败",
                    Details = ex.Message
                });
                return false;
            }
        }

        /// <summary>
        /// 解除USB存储设备阻止
        /// </summary>
        public bool RemoveUsbBlockPolicy()
        {
            try
            {
                if (!HasAdminPrivileges()) return false;

                // 恢复USBSTOR服务
                using (var key = Registry.LocalMachine.OpenSubKey(UsbStorageRegistryPath, true))
                {
                    if (key != null)
                    {
                        key.SetValue("Start", 3, RegistryValueKind.DWord); // 3 = Manual
                    }
                }

                // 移除设备安装限制
                using (var key = Registry.LocalMachine.OpenSubKey(DeviceInstallPolicyPath, true))
                {
                    if (key != null)
                    {
                        key.DeleteValue("DenyRemovableDevices", false);
                    }
                }

                FlushPolicyChanges();

                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "UsbBlockRemoved",
                    Message = "USB设备阻止策略已移除"
                });

                return true;
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "UsbUnblockError",
                    Message = "移除USB阻止策略失败",
                    Details = ex.Message
                });
                return false;
            }
        }

        /// <summary>
        /// 应用蓝牙设备阻止策略
        /// </summary>
        public bool ApplyBluetoothBlockPolicy()
        {
            try
            {
                if (!HasAdminPrivileges())
                {
                    NotificationService.Instance.ShowNotification(
                        "设备控制",
                        "需要管理员权限才能阻止蓝牙设备",
                        NotificationType.Warning
                    );
                    return false;
                }

                // 禁用蓝牙支持服务
                using (var key = Registry.LocalMachine.OpenSubKey(BluetoothRegistryPath, true))
                {
                    if (key != null)
                    {
                        key.SetValue("Start", 4, RegistryValueKind.DWord);
                    }
                }

                FlushPolicyChanges();

                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "BluetoothBlockApplied",
                    Message = "蓝牙设备阻止策略已应用"
                });

                return true;
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "BluetoothBlockError",
                    Message = "应用蓝牙阻止策略失败",
                    Details = ex.Message
                });
                return false;
            }
        }

        /// <summary>
        /// 解除蓝牙设备阻止
        /// </summary>
        public bool RemoveBluetoothBlockPolicy()
        {
            try
            {
                if (!HasAdminPrivileges()) return false;

                using (var key = Registry.LocalMachine.OpenSubKey(BluetoothRegistryPath, true))
                {
                    if (key != null)
                    {
                        key.SetValue("Start", 2, RegistryValueKind.DWord); // 2 = Automatic
                    }
                }

                FlushPolicyChanges();

                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "BluetoothBlockRemoved",
                    Message = "蓝牙设备阻止策略已移除"
                });

                return true;
            }
            catch { return false; }
        }

        /// <summary>
        /// 阻止特定设备（基于设备ID）
        /// </summary>
        public bool BlockSpecificDevice(string deviceId)
        {
            if (string.IsNullOrEmpty(deviceId)) return false;
            if (_trustedDeviceIds.Contains(deviceId))
            {
                NotificationService.Instance.ShowNotification(
                    "设备控制",
                    "无法阻止信任列表中的设备",
                    NotificationType.Warning
                );
                return false;
            }

            if (!_blockedDeviceIds.Contains(deviceId))
            {
                _blockedDeviceIds.Add(deviceId);
                SaveSettings();

                // 如果设备当前已连接，尝试断开
                var device = _connectedDevices.FirstOrDefault(d => d.DeviceId == deviceId);
                if (device != null)
                {
                    EjectDevice(device);
                }

                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "DeviceBlocked",
                    Message = "设备已添加到阻止列表",
                    Details = deviceId
                });
            }

            return true;
        }

        /// <summary>
        /// 解除特定设备阻止
        /// </summary>
        public bool UnblockSpecificDevice(string deviceId)
        {
            if (_blockedDeviceIds.Remove(deviceId))
            {
                SaveSettings();

                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "DeviceUnblocked",
                    Message = "设备已从阻止列表移除",
                    Details = deviceId
                });

                return true;
            }
            return false;
        }

        /// <summary>
        /// 添加设备到信任列表
        /// </summary>
        public bool TrustDevice(string deviceId)
        {
            if (string.IsNullOrEmpty(deviceId)) return false;
            
            // 从阻止列表移除
            _blockedDeviceIds.Remove(deviceId);
            
            if (!_trustedDeviceIds.Contains(deviceId))
            {
                _trustedDeviceIds.Add(deviceId);
                SaveSettings();

                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "DeviceTrusted",
                    Message = "设备已添加到信任列表",
                    Details = deviceId
                });
            }

            return true;
        }

        /// <summary>
        /// 移除设备信任
        /// </summary>
        public bool UntrustDevice(string deviceId)
        {
            if (_trustedDeviceIds.Remove(deviceId))
            {
                SaveSettings();

                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "DeviceUntrusted",
                    Message = "设备已从信任列表移除",
                    Details = deviceId
                });

                return true;
            }
            return false;
        }

        /// <summary>
        /// 弹出设备
        /// </summary>
        public bool EjectDevice(DeviceInfo device)
        {
            try
            {
                // 使用Windows API弹出设备
                // 这里使用简单的进程方式
                var processInfo = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-Command \"$drive = Get-WmiObject Win32_Volume | Where-Object {{$_.Label -eq '{device.Name}'}}; if($drive) {{ $drive.Dismount($false, $false) }}\"",
                    CreateNoWindow = true,
                    UseShellExecute = false
                };
                
                Process.Start(processInfo)?.WaitForExit(5000);

                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "DeviceEjected",
                    Message = "设备已弹出",
                    Details = device.Name
                });

                return true;
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "DeviceEjectError",
                    Message = "弹出设备失败",
                    Details = ex.Message
                });
                return false;
            }
        }

        private void FlushPolicyChanges()
        {
            try
            {
                // 刷新组策略
                var processInfo = new ProcessStartInfo
                {
                    FileName = "gpupdate.exe",
                    Arguments = "/force",
                    CreateNoWindow = true,
                    UseShellExecute = false
                };
                Process.Start(processInfo)?.WaitForExit(10000);
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "DeviceControlService.cs 捕获异常", ex.Message); }
        }

        private bool HasAdminPrivileges()
        {
            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            var principal = new System.Security.Principal.WindowsPrincipal(identity);
            return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }

        #endregion

        #region 设备监控

        private void StartWmiWatcher()
        {
            try
            {
                // 监控USB设备插入
                var usbInsertQuery = new WqlEventQuery(
                    "SELECT * FROM __InstanceCreationEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_USBControllerDevice'");
                _usbWatcher = new ManagementEventWatcher(usbInsertQuery);
                _usbWatcher.EventArrived += OnUsbDeviceInserted;
                _usbWatcher.Start();

                // 监控设备移除
                var removalQuery = new WqlEventQuery(
                    "SELECT * FROM __InstanceDeletionEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_USBControllerDevice'");
                _deviceRemovalWatcher = new ManagementEventWatcher(removalQuery);
                _deviceRemovalWatcher.EventArrived += OnDeviceRemoved;
                _deviceRemovalWatcher.Start();
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "WmiWatcherError",
                    Message = "WMI监控启动失败",
                    Details = ex.Message
                });
            }
        }

        private void StopWmiWatcher()
        {
            try
            {
                _usbWatcher?.Stop();
                _usbWatcher?.Dispose();
                _deviceRemovalWatcher?.Stop();
                _deviceRemovalWatcher?.Dispose();
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "DeviceControlService.cs 捕获异常", ex.Message); }
        }

        private void OnUsbDeviceInserted(object sender, EventArrivedEventArgs e)
        {
            try
            {
                var targetInstance = (ManagementBaseObject)e.NewEvent["TargetInstance"];
                var dependent = targetInstance["Dependent"]?.ToString();
                
                if (!string.IsNullOrEmpty(dependent))
                {
                    var device = new ManagementObject(dependent);
                    var deviceInfo = new DeviceInfo
                    {
                        DeviceId = device["DeviceID"]?.ToString() ?? "",
                        Name = device["Name"]?.ToString() ?? "USB设备",
                        Type = "USB",
                        Status = "Connected",
                        LastSeen = DateTime.Now
                    };

                    HandleNewDevice(deviceInfo);
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "DeviceControlService.cs 捕获异常", ex.Message); }
        }

        private void OnDeviceRemoved(object sender, EventArrivedEventArgs e)
        {
            try
            {
                var targetInstance = (ManagementBaseObject)e.NewEvent["TargetInstance"];
                var dependent = targetInstance["Dependent"]?.ToString();
                
                if (!string.IsNullOrEmpty(dependent))
                {
                    var device = new ManagementObject(dependent);
                    var deviceId = device["DeviceID"]?.ToString() ?? "";
                    
                    var knownDevice = _connectedDevices.FirstOrDefault(d => d.DeviceId == deviceId);
                    if (knownDevice != null)
                    {
                        HandleDeviceDisconnected(knownDevice);
                        lock (_connectedDevices)
                        {
                            _connectedDevices.Remove(knownDevice);
                        }
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "DeviceControlService.cs 捕获异常", ex.Message); }
        }

        private void MonitorDevices()
        {
            while (_isRunning)
            {
                try
                {
                    CheckConnectedDevices();
                }
                catch (Exception ex)
                {
                    _dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "DeviceControlError",
                        Message = "设备控制服务错误",
                        Details = ex.Message
                    });
                }

                Thread.Sleep(10000);
            }
        }

        private void CheckConnectedDevices()
        {
            if (!_enableDeviceControl) return;

            var currentDevices = GetConnectedDevices();

            // 检查新设备
            foreach (var device in currentDevices)
            {
                if (!_connectedDevices.Exists(d => d.DeviceId == device.DeviceId))
                {
                    HandleNewDevice(device);
                }
            }

            // 检查移除的设备
            foreach (var device in _connectedDevices.ToList())
            {
                if (!currentDevices.Exists(d => d.DeviceId == device.DeviceId))
                {
                    HandleDeviceDisconnected(device);
                }
            }

            lock (_connectedDevices)
            {
                _connectedDevices = currentDevices;
            }
        }

        private List<DeviceInfo> GetConnectedDevices()
        {
            var devices = new List<DeviceInfo>();

            try
            {
                // 获取USB存储设备
                using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_LogicalDisk WHERE DriveType = 2");
                foreach (ManagementObject disk in searcher.Get())
                {
                    devices.Add(new DeviceInfo
                    {
                        DeviceId = disk["DeviceID"]?.ToString() ?? "",
                        Name = disk["VolumeName"]?.ToString() ?? "USB存储设备",
                        Type = "USB Storage",
                        Status = "Connected",
                        LastSeen = DateTime.Now
                    });
                }

                // 获取USB控制器设备
                using var usbSearcher = new ManagementObjectSearcher("SELECT * FROM Win32_USBControllerDevice");
                foreach (ManagementObject usbDevice in usbSearcher.Get())
                {
                    try
                    {
                        var dependent = usbDevice["Dependent"]?.ToString();
                        if (!string.IsNullOrEmpty(dependent))
                        {
                            var device = new ManagementObject(dependent);
                            var deviceId = device["DeviceID"]?.ToString() ?? "";
                            var deviceName = device["Name"]?.ToString() ?? "USB设备";
                            
                            // 过滤掉根集线器
                            if (!deviceName.Contains("Root Hub", StringComparison.OrdinalIgnoreCase))
                            {
                                devices.Add(new DeviceInfo
                                {
                                    DeviceId = deviceId,
                                    Name = deviceName,
                                    Type = "USB",
                                    Status = "Connected",
                                    LastSeen = DateTime.Now
                                });
                            }
                        }
                    }
                    catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "DeviceControlService.cs 捕获异常", ex.Message); }
                }

                // 获取蓝牙设备
                using var btSearcher = new ManagementObjectSearcher("SELECT * FROM Win32_PnPEntity WHERE DeviceID LIKE '%BLUETOOTH%'");
                foreach (ManagementObject btDevice in btSearcher.Get())
                {
                    devices.Add(new DeviceInfo
                    {
                        DeviceId = btDevice["DeviceID"]?.ToString() ?? "",
                        Name = btDevice["Name"]?.ToString() ?? "蓝牙设备",
                        Type = "Bluetooth",
                        Status = "Connected",
                        LastSeen = DateTime.Now
                    });
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "DeviceControlService.cs 捕获异常", ex.Message); }

            return devices;
        }

        private void HandleNewDevice(DeviceInfo device)
        {
            // 检查是否在阻止列表中
            if (_blockedDeviceIds.Contains(device.DeviceId))
            {
                BlockDevice(device);
                return;
            }

            // 检查信任列表
            if (_trustedDeviceIds.Contains(device.DeviceId))
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "TrustedDeviceConnected",
                    Message = "信任设备已连接",
                    Details = $"设备: {device.Name}"
                });
                return;
            }

            // 检查全局阻止策略
            if (device.Type.StartsWith("USB") && _blockUSB)
            {
                BlockDevice(device);
                return;
            }

            if (device.Type == "Bluetooth" && _blockBluetooth)
            {
                BlockDevice(device);
                return;
            }

            // 正常设备连接通知
            NotificationService.Instance.ShowNotification(
                "设备连接",
                $"新设备已连接: {device.Name} ({device.Type})",
                NotificationType.Info
            );

            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "DeviceConnected",
                Message = "设备已连接",
                Details = $"设备: {device.Name}, 类型: {device.Type}, ID: {device.DeviceId}"
            });
        }

        private void HandleDeviceDisconnected(DeviceInfo device)
        {
            NotificationService.Instance.ShowNotification(
                "设备断开",
                $"设备已断开: {device.Name}",
                NotificationType.Info
            );

            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "DeviceDisconnected",
                Message = "设备已断开连接",
                Details = $"设备: {device.Name}, 类型: {device.Type}"
            });
        }

        private void BlockDevice(DeviceInfo device)
        {
            NotificationService.Instance.ShowNotification(
                "设备被阻止",
                $"设备 {device.Name} 已被阻止连接",
                NotificationType.Warning
            );

            // 尝试弹出设备
            EjectDevice(device);

            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "DeviceBlocked",
                Message = "设备已被阻止",
                Details = $"设备: {device.Name}, 类型: {device.Type}, ID: {device.DeviceId}"
            });
        }

        #endregion

        #region 设置管理

        private void LoadSettings()
        {
            try
            {
                var data = _dataManager.LoadDeviceControlData();
                if (data != null)
                {
                    _blockedDeviceIds = data.BlockedDeviceIds ?? new List<string>();
                    _trustedDeviceIds = data.TrustedDeviceIds ?? new List<string>();
                    _blockUSB = data.BlockUSB;
                    _blockBluetooth = data.BlockBluetooth;
                    _blockCDROM = data.BlockCDROM;
                }
            }
            catch
            {
                _blockedDeviceIds = new List<string>();
                _trustedDeviceIds = new List<string>();
            }
        }

        private void SaveSettings()
        {
            try
            {
                var data = new DeviceControlData
                {
                    BlockedDeviceIds = _blockedDeviceIds,
                    TrustedDeviceIds = _trustedDeviceIds,
                    BlockUSB = _blockUSB,
                    BlockBluetooth = _blockBluetooth,
                    BlockCDROM = _blockCDROM
                };
                _dataManager.SaveDeviceControlData(data);
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "DeviceControlService.cs 捕获异常", ex.Message); }
        }

        #endregion

        #region 公共接口

        public List<DeviceInfo> GetDevices()
        {
            lock (_connectedDevices)
            {
                return new List<DeviceInfo>(_connectedDevices);
            }
        }

        public List<string> GetBlockedDeviceIds() => new List<string>(_blockedDeviceIds);
        public List<string> GetTrustedDeviceIds() => new List<string>(_trustedDeviceIds);

        public bool IsDeviceBlocked(string deviceId) => _blockedDeviceIds.Contains(deviceId);
        public bool IsDeviceTrusted(string deviceId) => _trustedDeviceIds.Contains(deviceId);

        public void UpdateSettings(bool enableDeviceControl, bool blockUSB, bool blockBluetooth)
        {
            var usbChanged = _blockUSB != blockUSB;
            var btChanged = _blockBluetooth != blockBluetooth;

            _enableDeviceControl = enableDeviceControl;
            _blockUSB = blockUSB;
            _blockBluetooth = blockBluetooth;

            SaveSettings();

            // 应用或移除阻止策略
            if (_isRunning)
            {
                if (usbChanged)
                {
                    if (blockUSB)
                        ApplyUsbBlockPolicy();
                    else
                        RemoveUsbBlockPolicy();
                }

                if (btChanged)
                {
                    if (blockBluetooth)
                        ApplyBluetoothBlockPolicy();
                    else
                        RemoveBluetoothBlockPolicy();
                }
            }

            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "DeviceControlSettingsUpdated",
                Message = "设备控制设置已更新",
                Details = $"USB阻止: {blockUSB}, 蓝牙阻止: {blockBluetooth}"
            });
        }

        public void SetBlockUSB(bool block)
        {
            UpdateSettings(_enableDeviceControl, block, _blockBluetooth);
        }

        public void SetBlockBluetooth(bool block)
        {
            UpdateSettings(_enableDeviceControl, _blockUSB, block);
        }

        #endregion
    }

    public class DeviceInfo
    {
        public string DeviceId { get; set; } = "";
        public string Name { get; set; } = "";
        public string Type { get; set; } = "";
        public string Status { get; set; } = "";
        public string IPAddress { get; set; } = "";
        public string OSVersion { get; set; } = "";
        public DateTime LastSeen { get; set; }
        public string GroupId { get; set; } = "";
        public bool IsBlocked { get; set; }
        public bool IsTrusted { get; set; }
    }
}
