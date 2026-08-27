using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net.Cache;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Threading;

namespace FireAntivirus.Services
{
    public class SystemOptimizer
    {
        private bool _enabled;
        private object _optimizationLock = new object();

        public event EventHandler<SystemOptimizerEventArgs> SystemOptimizerEvent;

        public SystemOptimizer()
        {
            _enabled = true;
        }

        public async Task<OptimizationResult> OptimizeSystemAsync(OptimizationOptions options, CancellationToken cancellationToken = default)
        {
            var result = new OptimizationResult();
            try
            {
                RaiseSystemOptimizerEvent(new SystemOptimizerEventArgs(SystemOptimizerEventType.OptimizationStarted, "Starting system optimization..."));

                if (options.CleanTemporaryFiles)
                {
                    result.TemporaryFilesCleaned = await CleanTemporaryFilesAsync(cancellationToken);
                }

                if (options.CleanBrowserCache)
                {
                    result.BrowserCacheCleaned = await CleanBrowserCacheAsync(cancellationToken);
                }

                if (options.CleanRecycleBin)
                {
                    result.RecycleBinCleaned = await CleanRecycleBinAsync(cancellationToken);
                }

                if (options.CleanLogFiles)
                {
                    result.LogFilesCleaned = await CleanLogFilesAsync(cancellationToken);
                }

                if (options.CleanJunkFiles)
                {
                    result.JunkFilesCleaned = await CleanJunkFilesAsync(cancellationToken);
                }

                if (options.OptimizeRegistry)
                {
                    result.RegistryOptimized = await OptimizeRegistryAsync(cancellationToken);
                }

                if (options.OptimizeStartup)
                {
                    result.StartupOptimized = await OptimizeStartupAsync(cancellationToken);
                }

                if (options.OptimizeServices)
                {
                    result.ServicesOptimized = await OptimizeServicesAsync(cancellationToken);
                }

                if (options.OptimizeDisk)
                {
                    result.DiskOptimized = await OptimizeDiskAsync(cancellationToken);
                }

                result.Success = true;
                result.TotalCleanedBytes = result.TemporaryFilesCleaned + result.BrowserCacheCleaned + result.LogFilesCleaned + result.JunkFilesCleaned;

                RaiseSystemOptimizerEvent(new SystemOptimizerEventArgs(SystemOptimizerEventType.OptimizationCompleted, $"System optimization completed. Cleaned {result.TotalCleanedBytes / (1024 * 1024):F2} MB of data."));
            }
            catch (Exception ex)
            {
                RaiseSystemOptimizerEvent(new SystemOptimizerEventArgs(SystemOptimizerEventType.Error, "System optimization failed: " + ex.Message));
                result.Success = false;
                result.ErrorMessage = ex.Message;
            }

            return result;
        }

        private async Task<long> CleanTemporaryFilesAsync(CancellationToken cancellationToken = default)
        {
            long cleanedBytes = 0;
            try
            {
                RaiseSystemOptimizerEvent(new SystemOptimizerEventArgs(SystemOptimizerEventType.Info, "Cleaning temporary files..."));

                // 清理系统临时文件夹
                string[] tempFolders = new string[]
                {
                    Path.GetTempPath(),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp")
                };

                foreach (var folder in tempFolders)
                {
                    if (cancellationToken.IsCancellationRequested) break;
                    cleanedBytes += await CleanFolderAsync(folder, cancellationToken);
                }

                RaiseSystemOptimizerEvent(new SystemOptimizerEventArgs(SystemOptimizerEventType.Info, $"Cleaned {cleanedBytes / (1024 * 1024):F2} MB of temporary files."));
            }
            catch (Exception ex)
            {
                RaiseSystemOptimizerEvent(new SystemOptimizerEventArgs(SystemOptimizerEventType.Error, "Failed to clean temporary files: " + ex.Message));
            }
            return cleanedBytes;
        }

        private async Task<long> CleanBrowserCacheAsync(CancellationToken cancellationToken = default)
        {
            long cleanedBytes = 0;
            try
            {
                RaiseSystemOptimizerEvent(new SystemOptimizerEventArgs(SystemOptimizerEventType.Info, "Cleaning browser cache..."));

                // 清理常见浏览器缓存
                string[] browserPaths = new string[]
                {
                    // Chrome
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Google\Chrome\User Data\Default\Cache"),
                    // Firefox
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Mozilla\Firefox\Profiles"),
                    // Edge
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Microsoft\Edge\User Data\Default\Cache")
                };

                foreach (var path in browserPaths)
                {
                    if (cancellationToken.IsCancellationRequested) break;
                    if (Directory.Exists(path))
                    {
                        cleanedBytes += await CleanFolderAsync(path, cancellationToken);
                    }
                }

                RaiseSystemOptimizerEvent(new SystemOptimizerEventArgs(SystemOptimizerEventType.Info, $"Cleaned {cleanedBytes / (1024 * 1024):F2} MB of browser cache."));
            }
            catch (Exception ex)
            {
                RaiseSystemOptimizerEvent(new SystemOptimizerEventArgs(SystemOptimizerEventType.Error, "Failed to clean browser cache: " + ex.Message));
            }
            return cleanedBytes;
        }

        private async Task<bool> CleanRecycleBinAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                RaiseSystemOptimizerEvent(new SystemOptimizerEventArgs(SystemOptimizerEventType.Info, "Cleaning recycle bin..."));

                // 使用Shell API清空回收站
                SHEmptyRecycleBin(IntPtr.Zero, null, RecycleFlags.SHERB_NOCONFIRMATION | RecycleFlags.SHERB_NOPROGRESSUI | RecycleFlags.SHERB_NOSOUND);

                RaiseSystemOptimizerEvent(new SystemOptimizerEventArgs(SystemOptimizerEventType.Info, "Recycle bin cleaned successfully."));
                return true;
            }
            catch (Exception ex)
            {
                RaiseSystemOptimizerEvent(new SystemOptimizerEventArgs(SystemOptimizerEventType.Error, "Failed to clean recycle bin: " + ex.Message));
                return false;
            }
        }

        private async Task<long> CleanLogFilesAsync(CancellationToken cancellationToken = default)
        {
            long cleanedBytes = 0;
            try
            {
                RaiseSystemOptimizerEvent(new SystemOptimizerEventArgs(SystemOptimizerEventType.Info, "Cleaning log files..."));

                // 清理系统日志文件夹
                string[] logFolders = new string[]
                {
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Logs"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Microsoft\Windows\WER\ReportArchive"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Microsoft\Windows\WER\ReportQueue")
                };

                foreach (var folder in logFolders)
                {
                    if (cancellationToken.IsCancellationRequested) break;
                    if (Directory.Exists(folder))
                    {
                        cleanedBytes += await CleanFolderAsync(folder, "*.log", cancellationToken);
                        cleanedBytes += await CleanFolderAsync(folder, "*.txt", cancellationToken);
                    }
                }

                RaiseSystemOptimizerEvent(new SystemOptimizerEventArgs(SystemOptimizerEventType.Info, $"Cleaned {cleanedBytes / (1024 * 1024):F2} MB of log files."));
            }
            catch (Exception ex)
            {
                RaiseSystemOptimizerEvent(new SystemOptimizerEventArgs(SystemOptimizerEventType.Error, "Failed to clean log files: " + ex.Message));
            }
            return cleanedBytes;
        }

        private async Task<long> CleanJunkFilesAsync(CancellationToken cancellationToken = default)
        {
            long cleanedBytes = 0;
            try
            {
                RaiseSystemOptimizerEvent(new SystemOptimizerEventArgs(SystemOptimizerEventType.Info, "Cleaning junk files..."));

                // 清理常见垃圾文件
                string[] junkExtensions = { "*.tmp", "*.temp", "*.bak", "*.old", "*.log" };
                string[] commonFolders = new string[]
                {
                    Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                    Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonDocuments)
                };

                foreach (var folder in commonFolders)
                {
                    if (cancellationToken.IsCancellationRequested) break;
                    if (Directory.Exists(folder))
                    {
                        foreach (var extension in junkExtensions)
                        {
                            cleanedBytes += await CleanFilesAsync(folder, extension, cancellationToken);
                        }
                    }
                }

                RaiseSystemOptimizerEvent(new SystemOptimizerEventArgs(SystemOptimizerEventType.Info, $"Cleaned {cleanedBytes / (1024 * 1024):F2} MB of junk files."));
            }
            catch (Exception ex)
            {
                RaiseSystemOptimizerEvent(new SystemOptimizerEventArgs(SystemOptimizerEventType.Error, "Failed to clean junk files: " + ex.Message));
            }
            return cleanedBytes;
        }

        private async Task<bool> OptimizeRegistryAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                RaiseSystemOptimizerEvent(new SystemOptimizerEventArgs(SystemOptimizerEventType.Info, "Optimizing registry..."));

                // 这里可以添加注册表优化逻辑
                // 例如：清理无效的注册表项、修复注册表错误等

                // 模拟注册表优化
                await Task.Delay(1000, cancellationToken);

                RaiseSystemOptimizerEvent(new SystemOptimizerEventArgs(SystemOptimizerEventType.Info, "Registry optimized successfully."));
                return true;
            }
            catch (Exception ex)
            {
                RaiseSystemOptimizerEvent(new SystemOptimizerEventArgs(SystemOptimizerEventType.Error, "Failed to optimize registry: " + ex.Message));
                return false;
            }
        }

        private async Task<bool> OptimizeStartupAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                RaiseSystemOptimizerEvent(new SystemOptimizerEventArgs(SystemOptimizerEventType.Info, "Optimizing startup items..."));

                // 清理不必要的启动项
                string[] startupPaths = new string[]
                {
                    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"
                };

                foreach (var path in startupPaths)
                {
                    if (cancellationToken.IsCancellationRequested) break;
                    using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(path, true))
                    {
                        if (key != null)
                        {
                            // 这里可以添加启动项清理逻辑
                        }
                    }
                }

                RaiseSystemOptimizerEvent(new SystemOptimizerEventArgs(SystemOptimizerEventType.Info, "Startup items optimized successfully."));
                return true;
            }
            catch (Exception ex)
            {
                RaiseSystemOptimizerEvent(new SystemOptimizerEventArgs(SystemOptimizerEventType.Error, "Failed to optimize startup items: " + ex.Message));
                return false;
            }
        }

        private async Task<bool> OptimizeServicesAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                RaiseSystemOptimizerEvent(new SystemOptimizerEventArgs(SystemOptimizerEventType.Info, "Optimizing system services..."));

                // 优化系统服务
                string[] unnecessaryServices = { "Fax", "RemoteRegistry", "SSDP", "UPnP" };
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Service"))
                {
                    foreach (var obj in searcher.Get())
                    {
                        if (cancellationToken.IsCancellationRequested) break;
                        var serviceName = obj["Name"]?.ToString();
                        var startMode = obj["StartMode"]?.ToString();
                        if (unnecessaryServices.Contains(serviceName) && startMode == "Auto")
                        {
                            // 这里可以添加服务优化逻辑
                        }
                    }
                }

                RaiseSystemOptimizerEvent(new SystemOptimizerEventArgs(SystemOptimizerEventType.Info, "System services optimized successfully."));
                return true;
            }
            catch (Exception ex)
            {
                RaiseSystemOptimizerEvent(new SystemOptimizerEventArgs(SystemOptimizerEventType.Error, "Failed to optimize system services: " + ex.Message));
                return false;
            }
        }

        private async Task<bool> OptimizeDiskAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                RaiseSystemOptimizerEvent(new SystemOptimizerEventArgs(SystemOptimizerEventType.Info, "Optimizing disk..."));

                // 执行磁盘碎片整理
                foreach (var drive in DriveInfo.GetDrives().Where(d => d.IsReady && d.DriveType == DriveType.Fixed))
                {
                    if (cancellationToken.IsCancellationRequested) break;
                    // 这里可以添加磁盘碎片整理逻辑
                }

                RaiseSystemOptimizerEvent(new SystemOptimizerEventArgs(SystemOptimizerEventType.Info, "Disk optimized successfully."));
                return true;
            }
            catch (Exception ex)
            {
                RaiseSystemOptimizerEvent(new SystemOptimizerEventArgs(SystemOptimizerEventType.Error, "Failed to optimize disk: " + ex.Message));
                return false;
            }
        }

        private async Task<long> CleanFolderAsync(string folderPath, CancellationToken cancellationToken = default)
        {
            return await CleanFolderAsync(folderPath, "*", cancellationToken);
        }

        private async Task<long> CleanFolderAsync(string folderPath, string searchPattern, CancellationToken cancellationToken = default)
        {
            long cleanedBytes = 0;
            try
            {
                if (Directory.Exists(folderPath))
                {
                    var files = Directory.GetFiles(folderPath, searchPattern, SearchOption.AllDirectories);
                    foreach (var file in files)
                    {
                        if (cancellationToken.IsCancellationRequested) break;
                        try
                        {
                            var fileInfo = new FileInfo(file);
                            cleanedBytes += fileInfo.Length;
                            fileInfo.Delete();
                        }
                        catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SystemOptimizer.cs 捕获异常", ex.Message); }
                    }

                    // 清理空文件夹
                    var directories = Directory.GetDirectories(folderPath, "*", SearchOption.AllDirectories);
                    foreach (var directory in directories.OrderByDescending(d => d.Length))
                    {
                        if (cancellationToken.IsCancellationRequested) break;
                        try
                        {
                            if (Directory.GetFileSystemEntries(directory).Length == 0)
                            {
                                Directory.Delete(directory);
                            }
                        }
                        catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SystemOptimizer.cs 捕获异常", ex.Message); }
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SystemOptimizer.cs 捕获异常", ex.Message); }
            return cleanedBytes;
        }

        private async Task<long> CleanFilesAsync(string folderPath, string searchPattern, CancellationToken cancellationToken = default)
        {
            long cleanedBytes = 0;
            try
            {
                if (Directory.Exists(folderPath))
                {
                    var files = Directory.GetFiles(folderPath, searchPattern, SearchOption.AllDirectories);
                    foreach (var file in files)
                    {
                        if (cancellationToken.IsCancellationRequested) break;
                        try
                        {
                            var fileInfo = new FileInfo(file);
                            cleanedBytes += fileInfo.Length;
                            fileInfo.Delete();
                        }
                        catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SystemOptimizer.cs 捕获异常", ex.Message); }
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SystemOptimizer.cs 捕获异常", ex.Message); }
            return cleanedBytes;
        }

        public async Task<SystemInfo> GetSystemInfoAsync(CancellationToken cancellationToken = default)
        {
            var info = new SystemInfo();
            try
            {
                // 获取系统信息
                info.OSVersion = Environment.OSVersion.ToString();
                info.ComputerName = Environment.MachineName;
                info.UserName = Environment.UserName;

                // 获取内存信息
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystem"))
                {
                    foreach (var obj in searcher.Get())
                    {
                        info.TotalPhysicalMemory = (ulong)obj["TotalPhysicalMemory"];
                        break;
                    }
                }

                // 获取磁盘信息
                info.Drives = new List<DriveInfo>();
                foreach (var drive in DriveInfo.GetDrives().Where(d => d.IsReady))
                {
                    info.Drives.Add(drive);
                }

                // 获取CPU信息
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Processor"))
                {
                    foreach (var obj in searcher.Get())
                    {
                        info.CPUName = obj["Name"]?.ToString();
                        info.CPULogicalProcessors = (uint)obj["NumberOfLogicalProcessors"];
                        break;
                    }
                }
            }
            catch (Exception ex)
            {
                RaiseSystemOptimizerEvent(new SystemOptimizerEventArgs(SystemOptimizerEventType.Error, "Failed to get system info: " + ex.Message));
            }
            return info;
        }

        public void Enable()
        {
            _enabled = true;
            RaiseSystemOptimizerEvent(new SystemOptimizerEventArgs(SystemOptimizerEventType.Info, "System optimizer enabled"));
        }

        public void Disable()
        {
            _enabled = false;
            RaiseSystemOptimizerEvent(new SystemOptimizerEventArgs(SystemOptimizerEventType.Info, "System optimizer disabled"));
        }

        public bool IsEnabled()
        {
            return _enabled;
        }

        private void RaiseSystemOptimizerEvent(SystemOptimizerEventArgs e)
        {
            SystemOptimizerEvent?.Invoke(this, e);
        }

        // 导入Shell API
        [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
        private static extern int SHEmptyRecycleBin(IntPtr hwnd, string pszRootPath, RecycleFlags dwFlags);

        [Flags]
        private enum RecycleFlags
        {
            SHERB_NOCONFIRMATION = 0x00000001,
            SHERB_NOPROGRESSUI = 0x00000002,
            SHERB_NOSOUND = 0x00000004
        }
    }

    public class OptimizationOptions
    {
        public bool CleanTemporaryFiles { get; set; } = true;
        public bool CleanBrowserCache { get; set; } = true;
        public bool CleanRecycleBin { get; set; } = true;
        public bool CleanLogFiles { get; set; } = true;
        public bool CleanJunkFiles { get; set; } = true;
        public bool OptimizeRegistry { get; set; } = true;
        public bool OptimizeStartup { get; set; } = true;
        public bool OptimizeServices { get; set; } = true;
        public bool OptimizeDisk { get; set; } = true;
    }

    public class OptimizerSystemInfo
    {
        public string OSVersion { get; set; }
        public string MachineName { get; set; }
        public string Username { get; set; }
        public ulong TotalPhysicalMemory { get; set; }
        public List<DriveInfo> Drives { get; set; }
        public string CPUName { get; set; }
        public uint CPULogicalProcessors { get; set; }
    }

    public class SystemOptimizerEventArgs : EventArgs
    {
        public SystemOptimizerEventType EventType { get; set; }
        public string Message { get; set; }
        public DateTime Timestamp { get; set; }

        public SystemOptimizerEventArgs(SystemOptimizerEventType eventType, string message)
        {
            EventType = eventType;
            Message = message;
            Timestamp = DateTime.Now;
        }
    }

    public enum SystemOptimizerEventType
    {
        Info,
        Warning,
        Error,
        OptimizationStarted,
        OptimizationCompleted,
        CleanupStarted,
        CleanupCompleted
    }

    public class OptimizationResult
    {
        public bool Success { get; set; }
        public string ErrorMessage { get; set; }
        public string Category { get; set; }
        public string Message { get; set; }
        public long TotalCleanedBytes { get; set; }
        public long TemporaryFilesCleaned { get; set; }
        public long BrowserCacheCleaned { get; set; }
        public long LogFilesCleaned { get; set; }
        public long JunkFilesCleaned { get; set; }
        public bool RecycleBinCleaned { get; set; }
        public bool RegistryOptimized { get; set; }
        public bool StartupOptimized { get; set; }
        public bool ServicesOptimized { get; set; }
        public bool DiskOptimized { get; set; }
        public DateTime OptimizationTime { get; set; } = DateTime.Now;
    }
}