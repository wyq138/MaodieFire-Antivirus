using System;
using System.IO;
using System.Management;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using FireAntivirus.Data;
using FireAntivirus.Engine;
using FireAntivirus.Common;

namespace FireAntivirus.Services
{
    public class USBMonitor : IMonitor
    {
        private Thread _monitorThread;
        private bool _isRunning;
        private readonly DataManager _dataManager;
        private readonly AntivirusEngine _antivirusEngine;
        private ManagementEventWatcher _insertWatcher;
        private ManagementEventWatcher _removeWatcher;
        private HashSet<string> _scannedDrives;
        private HashSet<string> _alertedDrives;
        private DeviceControlService _deviceControlService;
        
        // USB阻止设置
        private bool _blockUSB = false;
        private bool _enableDeviceControl = true;

        public USBMonitor(DataManager dataManager, AntivirusEngine antivirusEngine) : this(dataManager, antivirusEngine, null)
        {
        }

        public USBMonitor(DataManager dataManager, AntivirusEngine antivirusEngine, DeviceControlService deviceControlService)
        {
            _dataManager = dataManager;
            _antivirusEngine = antivirusEngine;
            _deviceControlService = deviceControlService;
            _scannedDrives = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _alertedDrives = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        }

        public void SetDeviceControlService(DeviceControlService service)
        {
            _deviceControlService = service;
        }

        /// <summary>
        /// 设置USB阻止选项
        /// </summary>
        public void UpdateBlockSettings(bool blockUSB, bool enableDeviceControl)
        {
            _blockUSB = blockUSB;
            _enableDeviceControl = enableDeviceControl;
        }

        public void Start()
        {
            if (_isRunning)
                return;

            _isRunning = true;
            _monitorThread = new Thread(MonitorUSB);
            _monitorThread.IsBackground = true;
            _monitorThread.Start();

            _dataManager.LogActivity("USBMonitor started");
        }

        public void Stop()
        {
            _isRunning = false;
            if (_monitorThread != null && _monitorThread.IsAlive)
            {
                _monitorThread.Join(2000);
            }

            CleanupWatchers();
            _dataManager.LogActivity("USBMonitor stopped");
        }

        private void MonitorUSB()
        {
            try
            {
                SetupWatchers();

                while (_isRunning)
                {
                    Thread.Sleep(1000);
                }
            }
            catch (Exception ex)
            {
                _dataManager.LogError($"USBMonitor error: {ex.Message}");
            }
            finally
            {
                CleanupWatchers();
            }
        }

        private void SetupWatchers()
        {
            try
            {
                string insertQuery = "SELECT * FROM __InstanceCreationEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_LogicalDisk' AND TargetInstance.DriveType = 2";
                string removeQuery = "SELECT * FROM __InstanceDeletionEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_LogicalDisk' AND TargetInstance.DriveType = 2";

                _insertWatcher = new ManagementEventWatcher(new WqlEventQuery(insertQuery));
                _insertWatcher.EventArrived += new EventArrivedEventHandler(USBInserted);
                _insertWatcher.Start();

                _removeWatcher = new ManagementEventWatcher(new WqlEventQuery(removeQuery));
                _removeWatcher.EventArrived += new EventArrivedEventHandler(USBRemoved);
                _removeWatcher.Start();
            }
            catch (Exception ex)
            {
                _dataManager.LogError($"Error setting up USB watchers: {ex.Message}");
            }
        }

        private void CleanupWatchers()
        {
            if (_insertWatcher != null)
            {
                _insertWatcher.Stop();
                _insertWatcher.Dispose();
                _insertWatcher = null;
            }

            if (_removeWatcher != null)
            {
                _removeWatcher.Stop();
                _removeWatcher.Dispose();
                _removeWatcher = null;
            }
        }

        private void USBInserted(object sender, EventArrivedEventArgs e)
        {
            try
            {
                ManagementBaseObject targetInstance = (ManagementBaseObject)e.NewEvent["TargetInstance"];
                string driveLetter = targetInstance["DeviceID"].ToString();
                string volumeName = targetInstance["VolumeName"]?.ToString() ?? "可移动磁盘";
                string fileSystem = targetInstance["FileSystem"]?.ToString() ?? "Unknown";
                long size = 0;
                try { size = Convert.ToInt64(targetInstance["Size"]); } catch { }
                double sizeGB = Math.Round(size / (1024.0 * 1024 * 1024), 2);

                _dataManager.LogActivity($"USB设备插入: {driveLetter} - {volumeName} ({sizeGB} GB)");

                // 首先检查是否需要阻止USB设备（实时阻止）
                if (_enableDeviceControl && _blockUSB)
                {
                    // 立即阻止并弹出USB设备
                    ShowUSBBlockedNotification(driveLetter, volumeName);
                    ForceEjectUSB(driveLetter);
                    return; // 不继续扫描
                }

                // 获取USB设备详细信息
                string deviceInfo = GetUSBDeviceInfo(driveLetter);

                // 弹窗提示U盘已插入
                ShowUSBInsertedNotification(driveLetter, volumeName, sizeGB, deviceInfo);

                // 异步扫描USB设备
                Task.Run(() => ScanUSBDevice(driveLetter, volumeName));
            }
            catch (Exception ex)
            {
                _dataManager.LogError($"Error handling USB insertion: {ex.Message}");
            }
        }

        /// <summary>
        /// 强制弹出USB设备
        /// </summary>
        private void ForceEjectUSB(string driveLetter)
        {
            try
            {
                // 先尝试使用Windows API弹出
                bool ejected = NativeMethods.EjectDrive(driveLetter);
                
                if (!ejected)
                {
                    // 备用方案：使用mountvol命令
                    var process = new System.Diagnostics.Process();
                    process.StartInfo.FileName = "mountvol";
                    process.StartInfo.Arguments = $"{driveLetter} /p";
                    process.StartInfo.CreateNoWindow = true;
                    process.StartInfo.UseShellExecute = false;
                    process.Start();
                    process.WaitForExit(5000);
                }
                
                _dataManager.LogActivity($"USB设备已强制弹出: {driveLetter}");
            }
            catch (Exception ex)
            {
                _dataManager.LogError($"强制弹出USB失败: {ex.Message}");
            }
        }

        private void ShowUSBBlockedNotification(string driveLetter, string volumeName)
        {
            try
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "USBDeviceBlocked",
                    Message = "USB设备已被阻止",
                    Details = $"盘符: {driveLetter}\n名称: {volumeName}\n原因: USB设备阻止功能已启用",
                    Source = "USBMonitor",
                    Category = "设备控制"
                });

                NotificationService.Instance.ShowNotification(
                    "USB设备已被阻止",
                    $"检测到USB设备但已被阻止连接\n\n" +
                    $"盘符: {driveLetter}\n" +
                    $"名称: {volumeName}\n\n" +
                    $"设备已被强制弹出。\n" +
                    $"如需允许USB设备，请在设置中关闭\"阻止USB设备\"选项。",
                    NotificationType.Warning
                );
            }
            catch { }
        }

        private void USBRemoved(object sender, EventArrivedEventArgs e)
        {
            try
            {
                ManagementBaseObject targetInstance = (ManagementBaseObject)e.NewEvent["TargetInstance"];
                string driveLetter = targetInstance["DeviceID"].ToString();

                _dataManager.LogActivity($"USB设备已移除: {driveLetter}");

                // 从已扫描列表中移除
                lock (_scannedDrives)
                {
                    _scannedDrives.Remove(driveLetter);
                    _alertedDrives.Remove(driveLetter);
                }

                // 弹窗提示U盘已移除
                ShowUSBRemovedNotification(driveLetter);
            }
            catch (Exception ex)
            {
                _dataManager.LogError($"Error handling USB removal: {ex.Message}");
            }
        }

        private string GetUSBDeviceInfo(string driveLetter)
        {
            try
            {
                // 获取USB设备物理信息
                using (var searcher = new ManagementObjectSearcher(
                    $"SELECT * FROM Win32_DiskDrive WHERE InterfaceType = 'USB'"))
                {
                    foreach (ManagementObject disk in searcher.Get())
                    {
                        string model = disk["Model"]?.ToString() ?? "";
                        string manufacturer = disk["Manufacturer"]?.ToString() ?? "";
                        string serial = disk["SerialNumber"]?.ToString() ?? "";

                        return $"型号: {model}\n制造商: {manufacturer}\n序列号: {serial}";
                    }
                }
            }
            catch { }

            return "";
        }

        private void ShowUSBInsertedNotification(string driveLetter, string volumeName, double sizeGB, string deviceInfo)
        {
            try
            {
                // 记录日志
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "USBDeviceInserted",
                    Message = "USB设备已插入",
                    Details = $"盘符: {driveLetter}\n名称: {volumeName}\n大小: {sizeGB} GB\n{deviceInfo}",
                    Source = "USBMonitor",
                    Category = "设备监控"
                });

                // 显示弹窗通知
                string title = "USB设备已插入";
                string message = $"检测到新的USB设备\n\n" +
                               $"盘符: {driveLetter}\n" +
                               $"名称: {volumeName}\n" +
                               $"大小: {sizeGB} GB\n" +
                               $"{deviceInfo}\n\n" +
                               $"正在扫描设备...";

                NotificationService.Instance.ShowNotification(title, message, NotificationType.Info);
            }
            catch { }
        }

        private void ShowUSBRemovedNotification(string driveLetter)
        {
            try
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "USBDeviceRemoved",
                    Message = "USB设备已移除",
                    Details = $"盘符: {driveLetter}",
                    Source = "USBMonitor",
                    Category = "设备监控"
                });

                NotificationService.Instance.ShowNotification(
                    "USB设备已移除",
                    $"USB设备 {driveLetter} 已安全移除",
                    NotificationType.Info
                );
            }
            catch { }
        }

        private void ScanUSBDevice(string driveLetter, string volumeName)
        {
            try
            {
                // 防止重复扫描
                lock (_scannedDrives)
                {
                    if (_scannedDrives.Contains(driveLetter))
                        return;
                    _scannedDrives.Add(driveLetter);
                }

                if (!Directory.Exists(driveLetter))
                    return;

                _dataManager.LogActivity($"开始扫描USB设备: {driveLetter}");

                // 先检查autorun文件
                CheckAutoRunFiles(driveLetter);

                // 检查可疑的快捷方式
                CheckSuspiciousShortcuts(driveLetter);

                // 获取文件统计
                var scanStats = new USBScanStats
                {
                    DriveLetter = driveLetter,
                    StartTime = DateTime.Now
                };

                // 扫描目录
                ScanDirectory(driveLetter, scanStats);

                scanStats.EndTime = DateTime.Now;

                // 显示扫描结果
                ShowScanResultNotification(driveLetter, volumeName, scanStats);
            }
            catch (Exception ex)
            {
                _dataManager.LogError($"Error scanning USB device: {ex.Message}");
            }
        }

        private void ScanDirectory(string directoryPath, USBScanStats stats)
        {
            try
            {
                // 扫描文件
                string[] files = Directory.GetFiles(directoryPath);
                foreach (string file in files)
                {
                    if (!_isRunning) return;
                    
                    stats.TotalFiles++;
                    ScanFile(file, stats);
                }

                // 递归扫描子目录
                string[] directories = Directory.GetDirectories(directoryPath);
                foreach (string directory in directories)
                {
                    if (!_isRunning) return;
                    
                    stats.TotalFolders++;
                    ScanDirectory(directory, stats);
                }
            }
            catch (UnauthorizedAccessException)
            {
                // 跳过无权限目录
            }
            catch (Exception ex)
            {
                _dataManager.LogError($"Error scanning directory {directoryPath}: {ex.Message}");
            }
        }

        private void ScanFile(string filePath, USBScanStats stats)
        {
            try
            {
                // 跳过超大文件 (>100MB)
                var fileInfo = new FileInfo(filePath);
                if (fileInfo.Length > 100 * 1024 * 1024)
                {
                    stats.SkippedFiles++;
                    return;
                }

                // 使用杀毒引擎扫描文件
                var result = _antivirusEngine.ScanFile(filePath);
                
                if (result.IsMalicious)
                {
                    stats.InfectedFiles++;
                    stats.Threats.Add(new ThreatInfo
                    {
                        FilePath = filePath,
                        ThreatName = result.ThreatName,
                        ThreatType = result.ThreatType,
                        Severity = result.Severity
                    });

                    _dataManager.LogThreat($"USB设备检测到恶意文件: {filePath} - {result.ThreatName}");
                    
                    // 触发威胁通知
                    ShowThreatNotification(filePath, result);
                }
                else if (result.IsInfected)
                {
                    stats.SuspiciousFiles++;
                }
                else
                {
                    stats.CleanFiles++;
                }
            }
            catch (Exception ex)
            {
                _dataManager.LogError($"Error scanning file {filePath}: {ex.Message}");
                stats.ErrorFiles++;
            }
        }

        private void ShowThreatNotification(string filePath, ScanResult result)
        {
            try
            {
                string severity = result.Severity ?? "Medium";
                NotificationType notifType = severity.Equals("Critical", StringComparison.OrdinalIgnoreCase) 
                    ? NotificationType.Error 
                    : severity.Equals("High", StringComparison.OrdinalIgnoreCase)
                        ? NotificationType.Error 
                        : NotificationType.Warning;

                NotificationService.Instance.ShowNotification(
                    "USB设备威胁检测",
                    $"检测到恶意文件!\n\n" +
                    $"位置: {filePath}\n" +
                    $"威胁: {result.ThreatName}\n" +
                    $"类型: {result.ThreatType}\n" +
                    $"严重性: {severity}\n\n" +
                    $"建议立即删除该文件!",
                    notifType
                );
            }
            catch { }
        }

        private void ShowScanResultNotification(string driveLetter, string volumeName, USBScanStats stats)
        {
            try
            {
                var duration = stats.EndTime - stats.StartTime;
                
                string message = $"USB设备扫描完成\n\n" +
                               $"设备: {driveLetter} ({volumeName})\n" +
                               $"扫描文件: {stats.TotalFiles} 个\n" +
                               $"扫描文件夹: {stats.TotalFolders} 个\n" +
                               $"跳过文件: {stats.SkippedFiles} 个\n" +
                               $"发现威胁: {stats.InfectedFiles} 个\n" +
                               $"可疑文件: {stats.SuspiciousFiles} 个\n" +
                               $"扫描耗时: {duration.TotalSeconds:F1} 秒";

                NotificationType notifType = stats.InfectedFiles > 0 
                    ? NotificationType.Error 
                    : NotificationType.Info;

                string title = stats.InfectedFiles > 0 
                    ? "USB设备扫描完成 - 发现威胁!" 
                    : "USB设备扫描完成 - 安全";

                NotificationService.Instance.ShowNotification(title, message, notifType);

                // 记录扫描结果日志
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = stats.InfectedFiles > 0 ? "USBScanThreat" : "USBScanClean",
                    Message = stats.InfectedFiles > 0 ? "USB设备扫描完成，发现威胁" : "USB设备扫描完成，设备安全",
                    Details = message,
                    Source = "USBMonitor",
                    Category = "设备监控"
                });
            }
            catch { }
        }

        // 检查USB设备是否包含自动运行文件
        private void CheckAutoRunFiles(string driveLetter)
        {
            try
            {
                string[] autoRunFiles = new[] { "autorun.inf", "autorun.exe", "autorun.bat", 
                                                "setup.exe", "install.exe", "startup.exe" };
                foreach (string fileName in autoRunFiles)
                {
                    string filePath = Path.Combine(driveLetter, fileName);
                    if (File.Exists(filePath))
                    {
                        _dataManager.LogActivity($"USB设备发现自动运行文件: {filePath}");
                        
                        // 检查autorun.inf内容
                        if (fileName.Equals("autorun.inf", StringComparison.OrdinalIgnoreCase))
                        {
                            CheckAutoRunContent(filePath);
                        }
                        
                        // 扫描文件
                        var result = _antivirusEngine.ScanFile(filePath);
                        if (result.IsMalicious)
                        {
                            NotificationService.Instance.ShowNotification(
                                "检测到可疑自动运行文件",
                                $"USB设备包含可疑的自动运行文件:\n{filePath}\n\n建议删除该文件!",
                                NotificationType.Warning
                            );
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _dataManager.LogError($"Error checking auto-run files: {ex.Message}");
            }
        }

        private void CheckAutoRunContent(string autorunPath)
        {
            try
            {
                string content = File.ReadAllText(autorunPath).ToLower();
                
                // 检查可疑的autorun命令
                string[] suspiciousPatterns = { 
                    "shellexecute=", "open=", "action=", 
                    "icon=", "label=", "useautoplay"
                };

                foreach (var pattern in suspiciousPatterns)
                {
                    if (content.Contains(pattern))
                    {
                        _dataManager.LogActivity($"autorun.inf包含可疑命令: {pattern}");
                    }
                }
            }
            catch { }
        }

        // 检查可疑的快捷方式
        private void CheckSuspiciousShortcuts(string driveLetter)
        {
            try
            {
                string[] lnkFiles = Directory.GetFiles(driveLetter, "*.lnk", SearchOption.TopDirectoryOnly);
                foreach (var lnkFile in lnkFiles)
                {
                    // 快捷方式可能是恶意软件伪装
                    _dataManager.LogActivity($"检测到USB快捷方式: {lnkFile}");
                }
            }
            catch { }
        }

        // 扫描统计类
        private class USBScanStats
        {
            public string DriveLetter { get; set; }
            public DateTime StartTime { get; set; }
            public DateTime EndTime { get; set; }
            public int TotalFiles { get; set; }
            public int TotalFolders { get; set; }
            public int CleanFiles { get; set; }
            public int InfectedFiles { get; set; }
            public int SuspiciousFiles { get; set; }
            public int SkippedFiles { get; set; }
            public int ErrorFiles { get; set; }
            public List<ThreatInfo> Threats { get; set; } = new List<ThreatInfo>();
        }

        private class ThreatInfo
        {
            public string FilePath { get; set; }
            public string ThreatName { get; set; }
            public string ThreatType { get; set; }
            public string Severity { get; set; }
        }
    }

    /// <summary>
    /// Windows API用于USB设备弹出
    /// </summary>
    internal static class NativeMethods
    {
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool DeviceIoControl(
            IntPtr hDevice,
            uint dwIoControlCode,
            IntPtr lpInBuffer,
            uint nInBufferSize,
            IntPtr lpOutBuffer,
            uint nOutBufferSize,
            out uint lpBytesReturned,
            IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern IntPtr CreateFile(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        private const uint GENERIC_READ = 0x80000000;
        private const uint FILE_SHARE_READ = 0x00000001;
        private const uint FILE_SHARE_WRITE = 0x00000002;
        private const uint OPEN_EXISTING = 3;
        private const uint IOCTL_STORAGE_EJECT_MEDIA = 0x2D4808;

        /// <summary>
        /// 弹出指定驱动器
        /// </summary>
        public static bool EjectDrive(string driveLetter)
        {
            try
            {
                // 移除冒号（如 "E:" -> "E"）
                string drive = driveLetter.TrimEnd(':');
                
                // 打开设备
                string devicePath = $"\\\\.\\{drive}:";
                IntPtr handle = CreateFile(
                    devicePath,
                    GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    IntPtr.Zero,
                    OPEN_EXISTING,
                    0,
                    IntPtr.Zero);

                if (handle == new IntPtr(-1))
                {
                    return false;
                }

                try
                {
                    // 发送弹出命令
                    uint bytesReturned;
                    bool result = DeviceIoControl(
                        handle,
                        IOCTL_STORAGE_EJECT_MEDIA,
                        IntPtr.Zero,
                        0,
                        IntPtr.Zero,
                        0,
                        out bytesReturned,
                        IntPtr.Zero);

                    return result;
                }
                finally
                {
                    CloseHandle(handle);
                }
            }
            catch
            {
                return false;
            }
        }
    }
}
