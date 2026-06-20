// 抖音用户 耄耋杀毒软件 开发，严禁非法反编译
// 抖音用户 耄耋杀毒软件 开发，严禁非法反编译
using System;
using System.Collections.Generic;
using System.IO;
using System.Management;
using System.Threading;
using System.Threading.Tasks;

namespace FireAntivirus.MobileSecurity
{
    public class MobileSecurityManager
    {
        private CancellationTokenSource _cancellationTokenSource;
        private Task _monitoringTask;
        private Dictionary<string, MobileDeviceInfo> _connectedDevices;
        private ManagementEventWatcher _usbWatcher;
        private ManagementEventWatcher _bluetoothWatcher;

        public event EventHandler<MobileDeviceDetectedEventArgs> MobileDeviceDetected;
        public event EventHandler<MobileDeviceRemovedEventArgs> MobileDeviceRemoved;
        public event EventHandler<MobileDeviceFileTransferEventArgs> MobileDeviceFileTransfer;
        public event EventHandler<MobileDeviceThreatDetectedEventArgs> MobileDeviceThreatDetected;

        public MobileSecurityManager()
        {
            _connectedDevices = new Dictionary<string, MobileDeviceInfo>();
            _fileWatchers = new Dictionary<string, FileSystemWatcher>();
        }

        public async Task StartMonitoring()
        {
            if (_monitoringTask != null && !_monitoringTask.IsCompleted)
            {
                return;
            }

            _cancellationTokenSource = new CancellationTokenSource();
            var token = _cancellationTokenSource.Token;

            // 启动USB设备监控
            StartUsbMonitoring();

            // 启动蓝牙设备监控
            StartBluetoothMonitoring();

            // 启动文件传输监控
            _monitoringTask = Task.Run(async () => {
                while (!token.IsCancellationRequested)
                {
                    try
                    {
                        // 监控已连接设备的文件传输
                        await MonitorFileTransfers();

                        // 检查设备安全性
                        await CheckDeviceSecurity();

                        // 等待一段时间再进行下一次检查
                        await Task.Delay(2000, token);
                    }
                    catch (Exception ex)
                    {
                        // 记录错误但继续运行
                        Console.WriteLine($"移动设备监控错误: {ex.Message}");
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
                catch { }
            }

            // 停止USB监控
            _usbWatcher?.Stop();
            _usbWatcher?.Dispose();

            // 停止蓝牙监控
            _bluetoothWatcher?.Stop();
            _bluetoothWatcher?.Dispose();

            _connectedDevices.Clear();
        }

        private void StartUsbMonitoring()
        {
            try
            {
                // 监控USB设备连接
                var query = new WqlEventQuery("SELECT * FROM Win32_DeviceChangeEvent WHERE EventType = 2");
                _usbWatcher = new ManagementEventWatcher(query);
                _usbWatcher.EventArrived += (sender, e) => {
                    try
                    {
                        DetectUsbDevices();
                    }
                    catch { }
                };
                _usbWatcher.Start();
            }
            catch { }
        }

        private void StartBluetoothMonitoring()
        {
            try
            {
                // 监控蓝牙设备连接
                var query = new WqlEventQuery("SELECT * FROM MSFT_WmiProvider_ExecMethodAsyncEvent_Post WHERE ProviderName = 'Bluetooth'" );
                _bluetoothWatcher = new ManagementEventWatcher(query);
                _bluetoothWatcher.EventArrived += (sender, e) => {
                    try
                    {
                        DetectBluetoothDevices();
                    }
                    catch { }
                };
                _bluetoothWatcher.Start();
            }
            catch { }
        }

        private void DetectUsbDevices()
        {
            try
            {
                var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_USBHub");
                var devices = searcher.Get();

                foreach (var device in devices)
                {
                    string deviceId = device["DeviceID"]?.ToString();
                    string deviceName = device["Name"]?.ToString();

                    if (!string.IsNullOrEmpty(deviceId) && !_connectedDevices.ContainsKey(deviceId))
                    {
                        var deviceInfo = new MobileDeviceInfo
                        {
                            DeviceId = deviceId,
                            DeviceName = deviceName,
                            DeviceType = "USB",
                            ConnectionType = "USB",
                            ConnectedTime = DateTime.Now
                        };

                        _connectedDevices[deviceId] = deviceInfo;

                        OnMobileDeviceDetected(new MobileDeviceDetectedEventArgs
                        {
                            DeviceName = deviceName,
                            DeviceType = "USB",
                            ConnectionType = "USB",
                            DetectionTime = DateTime.Now
                        });
                    }
                }

                // 检测已移除的设备
                var deviceIds = new List<string>(_connectedDevices.Keys);
                foreach (var deviceId in deviceIds)
                {
                    bool stillConnected = false;
                    foreach (var device in devices)
                    {
                        if (device["DeviceID"]?.ToString() == deviceId)
                        {
                            stillConnected = true;
                            break;
                        }
                    }

                    if (!stillConnected)
                    {
                        var deviceInfo = _connectedDevices[deviceId];
                        _connectedDevices.Remove(deviceId);

                        OnMobileDeviceRemoved(new MobileDeviceRemovedEventArgs
                        {
                            DeviceName = deviceInfo.DeviceName,
                            DeviceType = deviceInfo.DeviceType,
                            DisconnectedTime = DateTime.Now
                        });
                    }
                }
            }
            catch { }
        }

        private void DetectBluetoothDevices()
        {
            try
            {
                var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_PnPEntity WHERE Name LIKE '%Bluetooth%'");
                var devices = searcher.Get();

                foreach (var device in devices)
                {
                    string deviceId = device["DeviceID"]?.ToString();
                    string deviceName = device["Name"]?.ToString();

                    if (!string.IsNullOrEmpty(deviceId) && !_connectedDevices.ContainsKey(deviceId))
                    {
                        var deviceInfo = new MobileDeviceInfo
                        {
                            DeviceId = deviceId,
                            DeviceName = deviceName,
                            DeviceType = "Bluetooth",
                            ConnectionType = "Bluetooth",
                            ConnectedTime = DateTime.Now
                        };

                        _connectedDevices[deviceId] = deviceInfo;

                        OnMobileDeviceDetected(new MobileDeviceDetectedEventArgs
                        {
                            DeviceName = deviceName,
                            DeviceType = "Bluetooth",
                            ConnectionType = "Bluetooth",
                            DetectionTime = DateTime.Now
                        });
                    }
                }
            }
            catch { }
        }

        private async Task MonitorFileTransfers()
        {
            // 监控移动设备的文件传输
            string[] commonMobileDevicePaths = {
                "F:\\", "G:\\", "H:\\", "I:\\", "J:\\" // 常见的移动设备盘符
            };

            foreach (var path in commonMobileDevicePaths)
            {
                try
                {
                    if (Directory.Exists(path))
                    {
                        // 监控文件复制/移动操作
                        await MonitorDirectoryChanges(path);
                    }
                }
                catch { }
            }
        }

        private Dictionary<string, FileSystemWatcher> _fileWatchers;



        private async Task MonitorDirectoryChanges(string path)
        {
            // 使用FileSystemWatcher来监控文件变化
            if (!_fileWatchers.ContainsKey(path))
            {
                var watcher = new FileSystemWatcher(path);
                watcher.IncludeSubdirectories = true;
                watcher.NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.DirectoryName;
                watcher.Changed += OnFileChanged;
                watcher.Created += OnFileCreated;
                watcher.Deleted += OnFileDeleted;
                watcher.Renamed += OnFileRenamed;
                watcher.EnableRaisingEvents = true;
                _fileWatchers[path] = watcher;
            }
            await Task.CompletedTask;
        }

        private void OnFileChanged(object sender, FileSystemEventArgs e)
        {
            OnMobileDeviceFileTransfer(new MobileDeviceFileTransferEventArgs
            {
                DeviceName = GetDeviceNameFromPath(e.FullPath),
                FilePath = e.FullPath,
                TransferType = "修改",
                TransferTime = DateTime.Now
            });
        }

        private void OnFileCreated(object sender, FileSystemEventArgs e)
        {
            OnMobileDeviceFileTransfer(new MobileDeviceFileTransferEventArgs
            {
                DeviceName = GetDeviceNameFromPath(e.FullPath),
                FilePath = e.FullPath,
                TransferType = "创建",
                TransferTime = DateTime.Now
            });
        }

        private void OnFileDeleted(object sender, FileSystemEventArgs e)
        {
            OnMobileDeviceFileTransfer(new MobileDeviceFileTransferEventArgs
            {
                DeviceName = GetDeviceNameFromPath(e.FullPath),
                FilePath = e.FullPath,
                TransferType = "删除",
                TransferTime = DateTime.Now
            });
        }

        private void OnFileRenamed(object sender, RenamedEventArgs e)
        {
            OnMobileDeviceFileTransfer(new MobileDeviceFileTransferEventArgs
            {
                DeviceName = GetDeviceNameFromPath(e.FullPath),
                FilePath = e.FullPath,
                TransferType = "重命名",
                TransferTime = DateTime.Now
            });
        }

        private string GetDeviceNameFromPath(string path)
        {
            // 从路径中获取设备名称
            string driveLetter = Path.GetPathRoot(path);
            foreach (var device in _connectedDevices.Values)
            {
                // 这里可以根据实际情况映射设备名称
                if (device.ConnectionType == "USB")
                {
                    return device.DeviceName;
                }
            }
            return "未知设备";
        }

        public void Dispose()
        {
            StopMonitoring();
            foreach (var watcher in _fileWatchers.Values)
            {
                watcher.Dispose();
            }
            _fileWatchers.Clear();
        }

        private async Task CheckDeviceSecurity()
        {
            // 检查移动设备的安全性
            foreach (var deviceInfo in _connectedDevices.Values)
            {
                try
                {
                    // 检查设备是否有可疑文件
                    await CheckForSuspiciousFiles(deviceInfo);

                    // 检查设备是否有病毒特征
                    await CheckForVirusSignatures(deviceInfo);
                }
                catch { }
            }
        }

        private async Task CheckForSuspiciousFiles(MobileDeviceInfo deviceInfo)
        {
            // 检查移动设备上的可疑文件
            string[] commonMobileDevicePaths = {
                "F:\\", "G:\\", "H:\\", "I:\\", "J:\\" // 常见的移动设备盘符
            };

            foreach (var path in commonMobileDevicePaths)
            {
                try
                {
                    if (Directory.Exists(path))
                    {
                        // 检查可疑文件类型
                        string[] suspiciousExtensions = {".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js"};
                        foreach (var ext in suspiciousExtensions)
                        {
                            var files = Directory.GetFiles(path, "*" + ext, SearchOption.AllDirectories);
                            foreach (var file in files)
                            {
                                OnMobileDeviceThreatDetected(new MobileDeviceThreatDetectedEventArgs
                                {
                                    DeviceName = deviceInfo.DeviceName,
                                    ThreatType = "可疑文件",
                                    ThreatDetails = $"发现可疑文件: {file}",
                                    DetectionTime = DateTime.Now
                                });
                            }
                        }
                    }
                }
                catch { }
            }
        }

        private async Task CheckForVirusSignatures(MobileDeviceInfo deviceInfo)
        {
            // 检查移动设备上的病毒特征
            // 这里可以实现更复杂的病毒特征检测逻辑
            await Task.CompletedTask;
        }

        public List<MobileDeviceInfo> GetConnectedDevices()
        {
            return new List<MobileDeviceInfo>(_connectedDevices.Values);
        }

        public async Task ScanDevice(string deviceId)
        {
            if (_connectedDevices.TryGetValue(deviceId, out var deviceInfo))
            {
                // 扫描设备
                await Task.Run(() => {
                    // 扫描逻辑
                    Console.WriteLine($"正在扫描设备: {deviceInfo.DeviceName}");
                });
            }
        }

        protected virtual void OnMobileDeviceDetected(MobileDeviceDetectedEventArgs e)
        {
            MobileDeviceDetected?.Invoke(this, e);
        }

        protected virtual void OnMobileDeviceRemoved(MobileDeviceRemovedEventArgs e)
        {
            MobileDeviceRemoved?.Invoke(this, e);
        }

        protected virtual void OnMobileDeviceFileTransfer(MobileDeviceFileTransferEventArgs e)
        {
            MobileDeviceFileTransfer?.Invoke(this, e);
        }

        protected virtual void OnMobileDeviceThreatDetected(MobileDeviceThreatDetectedEventArgs e)
        {
            MobileDeviceThreatDetected?.Invoke(this, e);
        }
    }

    public class MobileDeviceInfo
    {
        public string DeviceId { get; set; }
        public string DeviceName { get; set; }
        public string DeviceType { get; set; }
        public string ConnectionType { get; set; }
        public DateTime ConnectedTime { get; set; }
    }

    public class MobileDeviceDetectedEventArgs : EventArgs
    {
        public string DeviceName { get; set; }
        public string DeviceType { get; set; }
        public string ConnectionType { get; set; }
        public DateTime DetectionTime { get; set; }
    }

    public class MobileDeviceRemovedEventArgs : EventArgs
    {
        public string DeviceName { get; set; }
        public string DeviceType { get; set; }
        public DateTime DisconnectedTime { get; set; }
    }

    public class MobileDeviceFileTransferEventArgs : EventArgs
    {
        public string DeviceName { get; set; }
        public string FilePath { get; set; }
        public string TransferType { get; set; } // 上传/下载
        public DateTime TransferTime { get; set; }
    }

    public class MobileDeviceThreatDetectedEventArgs : EventArgs
    {
        public string DeviceName { get; set; }
        public string ThreatType { get; set; }
        public string ThreatDetails { get; set; }
        public DateTime DetectionTime { get; set; }
    }
}
