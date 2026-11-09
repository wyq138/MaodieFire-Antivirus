using FireAntivirus.Common;
using FireAntivirus.Data;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace FireAntivirus.Services
{
    public class SystemOptimization
    {
        private readonly string _tempDirectory;
        private readonly string _logDirectory;
        private readonly int _maxFileAgeDays;
        private readonly long _maxLogSizeBytes;

        public SystemOptimization(string tempDirectory = null, string logDirectory = null, int maxFileAgeDays = 7, long maxLogSizeBytes = 10485760) // 10MB
        {
            _tempDirectory = tempDirectory ?? Path.GetTempPath();
            _logDirectory = logDirectory ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "FireAntivirus", "Logs");
            _maxFileAgeDays = maxFileAgeDays;
            _maxLogSizeBytes = maxLogSizeBytes;

            if (!Directory.Exists(_logDirectory))
            {
                Directory.CreateDirectory(_logDirectory);
            }
        }

        public async Task<SystemCleanupResult> CleanupSystemAsync(SystemCleanupOptions options)
        {
            var result = new SystemCleanupResult
            {
                StartTime = DateTime.UtcNow,
                CleanedItems = new List<CleanedItem>(),
                FreedSpaceBytes = 0
            };

            try
            {
                if (options.CleanTempFiles)
                {
                    var tempCleanup = await CleanupTempFilesAsync();
                    result.CleanedItems.AddRange(tempCleanup.CleanedItems);
                    result.FreedSpaceBytes += tempCleanup.FreedSpaceBytes;
                }

                if (options.CleanLogFiles)
                {
                    var logCleanup = await CleanupLogFilesAsync();
                    result.CleanedItems.AddRange(logCleanup.CleanedItems);
                    result.FreedSpaceBytes += logCleanup.FreedSpaceBytes;
                }

                if (options.CleanBrowserCache)
                {
                    var browserCleanup = await CleanupBrowserCacheAsync();
                    result.CleanedItems.AddRange(browserCleanup.CleanedItems);
                    result.FreedSpaceBytes += browserCleanup.FreedSpaceBytes;
                }

                if (options.CleanRecycleBin)
                {
                    var recycleBinCleanup = await CleanupRecycleBinAsync();
                    result.CleanedItems.AddRange(recycleBinCleanup.CleanedItems);
                    result.FreedSpaceBytes += recycleBinCleanup.FreedSpaceBytes;
                }

                if (options.CleanTemporaryInternetFiles)
                {
                    var tempInternetCleanup = await CleanupTemporaryInternetFilesAsync();
                    result.CleanedItems.AddRange(tempInternetCleanup.CleanedItems);
                    result.FreedSpaceBytes += tempInternetCleanup.FreedSpaceBytes;
                }

                result.Success = true;
            }
            catch (Exception ex)
            {
                Logger.Error($"System cleanup error: {ex.Message}");
                result.Success = false;
                result.ErrorMessage = ex.Message;
            }
            finally
            {
                result.EndTime = DateTime.UtcNow;
                result.Duration = result.EndTime - result.StartTime;
            }

            return result;
        }

        public async Task<SystemPerformanceResult> OptimizePerformanceAsync(PerformanceOptimizationOptions options)
        {
            var result = new SystemPerformanceResult
            {
                StartTime = DateTime.UtcNow,
                Optimizations = new List<PerformanceOptimization>()
            };

            try
            {
                if (options.OptimizeStartup)
                {
                    var startupOptimization = await OptimizeStartupAsync();
                    result.Optimizations.Add(startupOptimization);
                }

                if (options.OptimizeMemory)
                {
                    var memoryOptimization = await OptimizeMemoryAsync();
                    result.Optimizations.Add(memoryOptimization);
                }

                if (options.OptimizeDisk)
                {
                    var diskOptimization = await OptimizeDiskAsync();
                    result.Optimizations.Add(diskOptimization);
                }

                if (options.OptimizeServices)
                {
                    var servicesOptimization = await OptimizeServicesAsync();
                    result.Optimizations.Add(servicesOptimization);
                }

                result.Success = true;
            }
            catch (Exception ex)
            {
                Logger.Error($"Performance optimization error: {ex.Message}");
                result.Success = false;
                result.ErrorMessage = ex.Message;
            }
            finally
            {
                result.EndTime = DateTime.UtcNow;
                result.Duration = result.EndTime - result.StartTime;
            }

            return result;
        }

        public async Task<SystemHealthResult> CheckSystemHealthAsync()
        {
            var result = new SystemHealthResult
            {
                CheckTime = DateTime.UtcNow,
                Components = new List<SystemComponentHealth>()
            };

            try
            {
                var cpuHealth = await CheckCpuHealthAsync();
                result.Components.Add(cpuHealth);

                var memoryHealth = await CheckMemoryHealthAsync();
                result.Components.Add(memoryHealth);

                var diskHealth = await CheckDiskHealthAsync();
                result.Components.Add(diskHealth);

                var networkHealth = await CheckNetworkHealthAsync();
                result.Components.Add(networkHealth);

                var systemHealth = await CheckSystemHealthComponentsAsync();
                result.Components.Add(systemHealth);

                result.OverallHealth = CalculateOverallHealth(result.Components);
            }
            catch (Exception ex)
            {
                Logger.Error($"System health check error: {ex.Message}");
                result.Success = false;
                result.ErrorMessage = ex.Message;
            }

            return result;
        }

        public async Task<RegistryCleanupResult> CleanupRegistryAsync(RegistryCleanupOptions options)
        {
            var result = new RegistryCleanupResult
            {
                StartTime = DateTime.UtcNow,
                CleanedEntries = new List<RegistryEntry>()
            };

            try
            {
                if (options.CleanInvalidFileAssociations)
                {
                    var fileAssociations = await CleanupInvalidFileAssociationsAsync();
                    result.CleanedEntries.AddRange(fileAssociations);
                }

                if (options.CleanInvalidInstallerEntries)
                {
                    var installerEntries = await CleanupInvalidInstallerEntriesAsync();
                    result.CleanedEntries.AddRange(installerEntries);
                }

                if (options.CleanInvalidStartMenuEntries)
                {
                    var startMenuEntries = await CleanupInvalidStartMenuEntriesAsync();
                    result.CleanedEntries.AddRange(startMenuEntries);
                }

                if (options.CleanUnusedRegistryKeys)
                {
                    var unusedKeys = await CleanupUnusedRegistryKeysAsync();
                    result.CleanedEntries.AddRange(unusedKeys);
                }

                result.Success = true;
            }
            catch (Exception ex)
            {
                Logger.Error($"Registry cleanup error: {ex.Message}");
                result.Success = false;
                result.ErrorMessage = ex.Message;
            }
            finally
            {
                result.EndTime = DateTime.UtcNow;
                result.Duration = result.EndTime - result.StartTime;
            }

            return result;
        }

        private async Task<SystemCleanupResult> CleanupTempFilesAsync()
        {
            var result = new SystemCleanupResult
            {
                StartTime = DateTime.UtcNow,
                CleanedItems = new List<CleanedItem>(),
                FreedSpaceBytes = 0
            };

            try
            {
                var tempFiles = Directory.GetFiles(_tempDirectory, "*.*", SearchOption.AllDirectories);
                var cutoffDate = DateTime.UtcNow.AddDays(-_maxFileAgeDays);

                foreach (var file in tempFiles)
                {
                    try
                    {
                        var fileInfo = new FileInfo(file);
                        if (fileInfo.LastWriteTimeUtc < cutoffDate)
                        {
                            var fileSize = fileInfo.Length;
                            fileInfo.Delete();
                            result.CleanedItems.Add(new CleanedItem
                            {
                                Path = file,
                                SizeBytes = fileSize,
                                Type = CleanedItemType.TempFile
                            });
                            result.FreedSpaceBytes += fileSize;
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.Warning($"Failed to delete temp file {file}: {ex.Message}");
                    }
                }

                result.Success = true;
            }
            catch (Exception ex)
            {
                Logger.Error($"Temp files cleanup error: {ex.Message}");
                result.Success = false;
                result.ErrorMessage = ex.Message;
            }
            finally
            {
                result.EndTime = DateTime.UtcNow;
                result.Duration = result.EndTime - result.StartTime;
            }

            return result;
        }

        private async Task<SystemCleanupResult> CleanupLogFilesAsync()
        {
            var result = new SystemCleanupResult
            {
                StartTime = DateTime.UtcNow,
                CleanedItems = new List<CleanedItem>(),
                FreedSpaceBytes = 0
            };

            try
            {
                var logFiles = Directory.GetFiles(_logDirectory, "*.log", SearchOption.AllDirectories);
                var cutoffDate = DateTime.UtcNow.AddDays(-_maxFileAgeDays);

                foreach (var file in logFiles)
                {
                    try
                    {
                        var fileInfo = new FileInfo(file);
                        if (fileInfo.LastWriteTimeUtc < cutoffDate || fileInfo.Length > _maxLogSizeBytes)
                        {
                            var fileSize = fileInfo.Length;
                            fileInfo.Delete();
                            result.CleanedItems.Add(new CleanedItem
                            {
                                Path = file,
                                SizeBytes = fileSize,
                                Type = CleanedItemType.LogFile
                            });
                            result.FreedSpaceBytes += fileSize;
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.Warning($"Failed to delete log file {file}: {ex.Message}");
                    }
                }

                result.Success = true;
            }
            catch (Exception ex)
            {
                Logger.Error($"Log files cleanup error: {ex.Message}");
                result.Success = false;
                result.ErrorMessage = ex.Message;
            }
            finally
            {
                result.EndTime = DateTime.UtcNow;
                result.Duration = result.EndTime - result.StartTime;
            }

            return result;
        }

        private async Task<SystemCleanupResult> CleanupBrowserCacheAsync()
        {
            var result = new SystemCleanupResult
            {
                StartTime = DateTime.UtcNow,
                CleanedItems = new List<CleanedItem>(),
                FreedSpaceBytes = 0
            };

            try
            {
                var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                var browserCachePaths = new List<string>
                {
                    Path.Combine(userProfile, "AppData", "Local", "Microsoft", "Edge", "User Data", "Default", "Cache"),
                    Path.Combine(userProfile, "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Cache"),
                    Path.Combine(userProfile, "AppData", "Local", "Mozilla", "Firefox", "Profiles")
                };

                foreach (var cachePath in browserCachePaths)
                {
                    if (Directory.Exists(cachePath))
                    {
                        try
                        {
                            var cacheSize = CalculateDirectorySize(cachePath);
                            Directory.Delete(cachePath, true);
                            Directory.CreateDirectory(cachePath);
                            result.CleanedItems.Add(new CleanedItem
                            {
                                Path = cachePath,
                                SizeBytes = cacheSize,
                                Type = CleanedItemType.BrowserCache
                            });
                            result.FreedSpaceBytes += cacheSize;
                        }
                        catch (Exception ex)
                        {
                            Logger.Warning($"Failed to clean browser cache {cachePath}: {ex.Message}");
                        }
                    }
                }

                result.Success = true;
            }
            catch (Exception ex)
            {
                Logger.Error($"Browser cache cleanup error: {ex.Message}");
                result.Success = false;
                result.ErrorMessage = ex.Message;
            }
            finally
            {
                result.EndTime = DateTime.UtcNow;
                result.Duration = result.EndTime - result.StartTime;
            }

            return result;
        }

        private async Task<SystemCleanupResult> CleanupRecycleBinAsync()
        {
            var result = new SystemCleanupResult
            {
                StartTime = DateTime.UtcNow,
                CleanedItems = new List<CleanedItem>(),
                FreedSpaceBytes = 0
            };

            try
            {
                long totalSize = 0;
                int totalCount = 0;

                // 统计各驱动器回收站中的真实文件数量与大小（$Recycle.Bin\<SID>\$R*）
                foreach (var drive in DriveInfo.GetDrives())
                {
                    if (drive.DriveType != DriveType.Fixed || !drive.IsReady) continue;

                    var recycleRoot = Path.Combine(drive.RootDirectory.FullName, "$Recycle.Bin");
                    if (!Directory.Exists(recycleRoot)) continue;

                    try
                    {
                        foreach (var sidDir in Directory.EnumerateDirectories(recycleRoot))
                        {
                            foreach (var file in Directory.EnumerateFiles(sidDir, "$R*"))
                            {
                                try
                                {
                                    totalSize += new FileInfo(file).Length;
                                    totalCount++;
                                }
                                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SystemOptimization.cs 捕获异常", ex.Message); }
                            }
                        }
                    }
                    catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SystemOptimization.cs 捕获异常", ex.Message); }
                }

                if (totalCount > 0)
                {
                    // 通过 Shell API 真实清空回收站（跳过确认框与进度 UI）
                    const uint SHERB_NOCONFIRMATION = 0x1;
                    const uint SHERB_NOPROGRESSUI = 0x2;
                    const uint SHERB_NOSOUND = 0x4;
                    var hr = SHEmptyRecycleBin(IntPtr.Zero, null, SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND);

                    if (hr == 0)
                    {
                        result.CleanedItems.Add(new CleanedItem
                        {
                            Path = "Recycle Bin (all drives)",
                            SizeBytes = totalSize,
                            Type = CleanedItemType.RecycleBin
                        });
                        result.FreedSpaceBytes += totalSize;
                        Logger.Info($"Recycle bin emptied: {totalCount} items, {totalSize} bytes freed");
                    }
                    else
                    {
                        result.ErrorMessage = $"SHEmptyRecycleBin failed: HRESULT 0x{hr:X8}";
                    }
                }

                result.Success = string.IsNullOrEmpty(result.ErrorMessage);
            }
            catch (Exception ex)
            {
                Logger.Error($"Recycle bin cleanup error: {ex.Message}");
                result.Success = false;
                result.ErrorMessage = ex.Message;
            }
            finally
            {
                result.EndTime = DateTime.UtcNow;
                result.Duration = result.EndTime - result.StartTime;
            }

            return result;
        }

        private async Task<SystemCleanupResult> CleanupTemporaryInternetFilesAsync()
        {
            var result = new SystemCleanupResult
            {
                StartTime = DateTime.UtcNow,
                CleanedItems = new List<CleanedItem>(),
                FreedSpaceBytes = 0
            };

            try
            {
                var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                var tempInternetPath = Path.Combine(userProfile, "AppData", "Local", "Microsoft", "Windows", "INetCache");

                if (Directory.Exists(tempInternetPath))
                {
                    var tempInternetSize = CalculateDirectorySize(tempInternetPath);
                    Directory.Delete(tempInternetPath, true);
                    Directory.CreateDirectory(tempInternetPath);
                    result.CleanedItems.Add(new CleanedItem
                    {
                        Path = tempInternetPath,
                        SizeBytes = tempInternetSize,
                        Type = CleanedItemType.TemporaryInternetFiles
                    });
                    result.FreedSpaceBytes += tempInternetSize;
                }

                result.Success = true;
            }
            catch (Exception ex)
            {
                Logger.Error($"Temporary internet files cleanup error: {ex.Message}");
                result.Success = false;
                result.ErrorMessage = ex.Message;
            }
            finally
            {
                result.EndTime = DateTime.UtcNow;
                result.Duration = result.EndTime - result.StartTime;
            }

            return result;
        }

        private async Task<PerformanceOptimization> OptimizeStartupAsync()
        {
            var optimization = new PerformanceOptimization
            {
                Type = OptimizationType.Startup,
                StartTime = DateTime.UtcNow,
                Actions = new List<string>()
            };

            try
            {
                int registryItems = 0, brokenItems = 0, folderItems = 0;

                // 真实枚举注册表自启动项并检查目标文件是否仍然存在
                var runKeys = new[]
                {
                    (Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                    (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
                };

                foreach (var (root, subKeyPath) in runKeys)
                {
                    using var key = root.OpenSubKey(subKeyPath);
                    if (key == null) continue;

                    foreach (var valueName in key.GetValueNames())
                    {
                        var command = key.GetValue(valueName)?.ToString();
                        if (string.IsNullOrEmpty(command)) continue;

                        registryItems++;

                        var exePath = ExtractExecutablePath(command);
                        if (!string.IsNullOrEmpty(exePath) && !File.Exists(exePath))
                            brokenItems++;
                    }
                }

                // 真实统计用户启动文件夹条目
                var startupFolder = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
                if (Directory.Exists(startupFolder))
                    folderItems = Directory.GetFiles(startupFolder).Length;

                optimization.Actions.Add($"Analyzed {registryItems} registry startup entries and {folderItems} startup-folder items");
                optimization.Actions.Add(brokenItems > 0
                    ? $"Found {brokenItems} startup entries pointing to missing files (cleanup candidates)"
                    : "No broken startup entries found");
                optimization.Success = true;
            }
            catch (Exception ex)
            {
                Logger.Error($"Startup optimization error: {ex.Message}");
                optimization.Success = false;
                optimization.ErrorMessage = ex.Message;
            }
            finally
            {
                optimization.EndTime = DateTime.UtcNow;
                optimization.Duration = optimization.EndTime - optimization.StartTime;
            }

            return optimization;
        }

        private async Task<PerformanceOptimization> OptimizeMemoryAsync()
        {
            var optimization = new PerformanceOptimization
            {
                Type = OptimizationType.Memory,
                StartTime = DateTime.UtcNow,
                Actions = new List<string>()
            };

            try
            {
                var before = QueryGlobalMemoryStatus();

                GC.Collect(2, GCCollectionMode.Forced, true, true);
                GC.WaitForPendingFinalizers();
                GC.Collect(2, GCCollectionMode.Forced, true, true);

                // 修剪自身进程工作集
                EmptyWorkingSet(Process.GetCurrentProcess().Handle);

                // 修剪占用较大且可访问的进程工作集（无权限或已退出的进程静默跳过）
                int currentProcessId = Process.GetCurrentProcess().Id;
                int trimmedCount = 0;
                foreach (var process in Process.GetProcesses())
                {
                    try
                    {
                        if (process.Id == currentProcessId) continue;
                        if (process.WorkingSet64 < 50L * 1024 * 1024) continue;

                        if (EmptyWorkingSet(process.Handle))
                            trimmedCount++;
                    }
                    catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
                    finally { process.Dispose(); }
                }

                var after = QueryGlobalMemoryStatus();
                long freedBytes = (long)Math.Max(0, after.ullAvailPhys - before.ullAvailPhys);

                optimization.Actions.Add($"Ran forced GC and trimmed working sets of {trimmedCount + 1} processes");
                optimization.Actions.Add($"Available physical memory: {before.ullAvailPhys / 1024 / 1024} MB -> {after.ullAvailPhys / 1024 / 1024} MB (+{freedBytes / 1024 / 1024} MB)");
                optimization.Success = true;
            }
            catch (Exception ex)
            {
                Logger.Error($"Memory optimization error: {ex.Message}");
                optimization.Success = false;
                optimization.ErrorMessage = ex.Message;
            }
            finally
            {
                optimization.EndTime = DateTime.UtcNow;
                optimization.Duration = optimization.EndTime - optimization.StartTime;
            }

            return optimization;
        }

        private async Task<PerformanceOptimization> OptimizeDiskAsync()
        {
            var optimization = new PerformanceOptimization
            {
                Type = OptimizationType.Disk,
                StartTime = DateTime.UtcNow,
                Actions = new List<string>()
            };

            try
            {
                // 真实调用 Windows 碎片整理工具对每个固定磁盘做只读分析
                foreach (var drive in DriveInfo.GetDrives())
                {
                    if (drive.DriveType != DriveType.Fixed || !drive.IsReady) continue;

                    try
                    {
                        var psi = new ProcessStartInfo
                        {
                            FileName = "defrag.exe",
                            Arguments = $"{drive.Name} /A /V",
                            UseShellExecute = false,
                            RedirectStandardOutput = true,
                            CreateNoWindow = true
                        };

                        using var process = Process.Start(psi);
                        if (process == null) continue;

                        var output = process.StandardOutput.ReadToEnd();
                        process.WaitForExit(120000);

                        var fragmentLine = output.Split('\n')
                            .Select(l => l.Trim())
                            .FirstOrDefault(l => l.IndexOf("fragment", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                                 l.Contains("碎片"));

                        optimization.Actions.Add(fragmentLine != null
                            ? $"{drive.Name} defrag analysis: {fragmentLine}"
                            : $"{drive.Name} defrag analysis completed (exit code {process.ExitCode})");
                    }
                    catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SystemOptimization.cs 捕获异常", ex.Message); }
                }

                optimization.Success = true;
            }
            catch (Exception ex)
            {
                Logger.Error($"Disk optimization error: {ex.Message}");
                optimization.Success = false;
                optimization.ErrorMessage = ex.Message;
            }
            finally
            {
                optimization.EndTime = DateTime.UtcNow;
                optimization.Duration = optimization.EndTime - optimization.StartTime;
            }

            return optimization;
        }

        private async Task<PerformanceOptimization> OptimizeServicesAsync()
        {
            var optimization = new PerformanceOptimization
            {
                Type = OptimizationType.Services,
                StartTime = DateTime.UtcNow,
                Actions = new List<string>()
            };

            try
            {
                // 真实查询 WMI 统计系统服务状态
                int total = 0, autoStart = 0, running = 0, delayedAuto = 0;

                using var searcher = new System.Management.ManagementObjectSearcher(
                    "SELECT State, StartMode, DelayedAutoStart FROM Win32_Service");

                foreach (var service in searcher.Get())
                {
                    total++;

                    var state = service["State"]?.ToString();
                    var startMode = service["StartMode"]?.ToString();

                    if (string.Equals(startMode, "Auto", StringComparison.OrdinalIgnoreCase))
                    {
                        autoStart++;

                        var delayedValue = service["DelayedAutoStart"];
                        if (delayedValue != null && bool.TryParse(delayedValue.ToString(), out var isDelayed) && isDelayed)
                            delayedAuto++;
                    }

                    if (string.Equals(state, "Running", StringComparison.OrdinalIgnoreCase))
                        running++;
                }

                optimization.Actions.Add($"Analyzed {total} system services: {running} running, {autoStart} auto-start ({delayedAuto} delayed-start)");
                optimization.Actions.Add("Reviewed service startup types; no configuration changes were applied automatically");
                optimization.Success = true;
            }
            catch (Exception ex)
            {
                Logger.Error($"Services optimization error: {ex.Message}");
                optimization.Success = false;
                optimization.ErrorMessage = ex.Message;
            }
            finally
            {
                optimization.EndTime = DateTime.UtcNow;
                optimization.Duration = optimization.EndTime - optimization.StartTime;
            }

            return optimization;
        }

        #region Native APIs 与辅助方法

        [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
        private static extern int SHEmptyRecycleBin(IntPtr hwnd, string rootPath, uint flags);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool EmptyWorkingSet(IntPtr hProcess);

        [StructLayout(LayoutKind.Sequential)]
        private class MEMORYSTATUSEX
        {
            public uint dwLength = (uint)Marshal.SizeOf(typeof(MEMORYSTATUSEX));
            public uint dwMemoryLoad;
            public ulong ullTotalPhys;
            public ulong ullAvailPhys;
            public ulong ullTotalPageFile;
            public ulong ullAvailPageFile;
            public ulong ullTotalVirtual;
            public ulong ullAvailVirtual;
            public ulong ullAvailExtendedVirtual;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GlobalMemoryStatusEx([In, Out] MEMORYSTATUSEX buffer);

        private static MEMORYSTATUSEX QueryGlobalMemoryStatus()
        {
            var status = new MEMORYSTATUSEX();
            if (!GlobalMemoryStatusEx(status))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            return status;
        }

        private static string ExtractExecutablePath(string commandLine)
        {
            if (string.IsNullOrWhiteSpace(commandLine)) return null;

            var trimmed = commandLine.Trim();
            if (trimmed.StartsWith("\""))
            {
                int endQuote = trimmed.IndexOf('"', 1);
                return endQuote > 1 ? trimmed.Substring(1, endQuote - 1) : null;
            }

            int spaceIndex = trimmed.IndexOf(' ');
            return spaceIndex > 0 ? trimmed.Substring(0, spaceIndex) : trimmed;
        }

        #endregion

        private async Task<SystemComponentHealth> CheckCpuHealthAsync()
        {
            var health = new SystemComponentHealth
            {
                Component = SystemComponent.CPU,
                CheckTime = DateTime.UtcNow
            };

            try
            {
                var cpuUsage = GetCpuUsage();
                health.Metrics.Add(new HealthMetric { Name = "CPU Usage", Value = cpuUsage, Unit = "%" });

                if (cpuUsage < 70)
                {
                    health.Status = HealthStatus.Good;
                    health.Message = "CPU usage is normal";
                }
                else if (cpuUsage < 90)
                {
                    health.Status = HealthStatus.Warning;
                    health.Message = "CPU usage is high";
                }
                else
                {
                    health.Status = HealthStatus.Critical;
                    health.Message = "CPU usage is critically high";
                }
            }
            catch (Exception ex)
            {
                Logger.Error($"CPU health check error: {ex.Message}");
                health.Status = HealthStatus.Error;
                health.Message = ex.Message;
            }

            return health;
        }

        private async Task<SystemComponentHealth> CheckMemoryHealthAsync()
        {
            var health = new SystemComponentHealth
            {
                Component = SystemComponent.Memory,
                CheckTime = DateTime.UtcNow
            };

            try
            {
                var memoryInfo = GetMemoryInfo();
                var memoryUsagePercent = (memoryInfo.Used / (double)memoryInfo.Total) * 100;
                
                health.Metrics.Add(new HealthMetric { Name = "Total Memory", Value = memoryInfo.Total / (1024 * 1024), Unit = "MB" });
                health.Metrics.Add(new HealthMetric { Name = "Used Memory", Value = memoryInfo.Used / (1024 * 1024), Unit = "MB" });
                health.Metrics.Add(new HealthMetric { Name = "Memory Usage", Value = memoryUsagePercent, Unit = "%" });

                if (memoryUsagePercent < 70)
                {
                    health.Status = HealthStatus.Good;
                    health.Message = "Memory usage is normal";
                }
                else if (memoryUsagePercent < 90)
                {
                    health.Status = HealthStatus.Warning;
                    health.Message = "Memory usage is high";
                }
                else
                {
                    health.Status = HealthStatus.Critical;
                    health.Message = "Memory usage is critically high";
                }
            }
            catch (Exception ex)
            {
                Logger.Error($"Memory health check error: {ex.Message}");
                health.Status = HealthStatus.Error;
                health.Message = ex.Message;
            }

            return health;
        }

        private async Task<SystemComponentHealth> CheckDiskHealthAsync()
        {
            var health = new SystemComponentHealth
            {
                Component = SystemComponent.Disk,
                CheckTime = DateTime.UtcNow
            };

            try
            {
                var diskInfo = GetDiskInfo();
                var diskUsagePercent = (diskInfo.Used / (double)diskInfo.Total) * 100;
                
                health.Metrics.Add(new HealthMetric { Name = "Total Disk Space", Value = diskInfo.Total / (1024 * 1024 * 1024), Unit = "GB" });
                health.Metrics.Add(new HealthMetric { Name = "Used Disk Space", Value = diskInfo.Used / (1024 * 1024 * 1024), Unit = "GB" });
                health.Metrics.Add(new HealthMetric { Name = "Disk Usage", Value = diskUsagePercent, Unit = "%" });

                if (diskUsagePercent < 70)
                {
                    health.Status = HealthStatus.Good;
                    health.Message = "Disk usage is normal";
                }
                else if (diskUsagePercent < 90)
                {
                    health.Status = HealthStatus.Warning;
                    health.Message = "Disk usage is high";
                }
                else
                {
                    health.Status = HealthStatus.Critical;
                    health.Message = "Disk usage is critically high";
                }
            }
            catch (Exception ex)
            {
                Logger.Error($"Disk health check error: {ex.Message}");
                health.Status = HealthStatus.Error;
                health.Message = ex.Message;
            }

            return health;
        }

        private async Task<SystemComponentHealth> CheckNetworkHealthAsync()
        {
            var health = new SystemComponentHealth
            {
                Component = SystemComponent.Network,
                CheckTime = DateTime.UtcNow
            };

            try
            {
                var pingTime = GetPingTime("8.8.8.8");
                health.Metrics.Add(new HealthMetric { Name = "Ping Time", Value = pingTime, Unit = "ms" });

                if (pingTime < 100)
                {
                    health.Status = HealthStatus.Good;
                    health.Message = "Network response time is good";
                }
                else if (pingTime < 500)
                {
                    health.Status = HealthStatus.Warning;
                    health.Message = "Network response time is slow";
                }
                else
                {
                    health.Status = HealthStatus.Critical;
                    health.Message = "Network response time is critically slow";
                }
            }
            catch (Exception ex)
            {
                Logger.Error($"Network health check error: {ex.Message}");
                health.Status = HealthStatus.Error;
                health.Message = ex.Message;
            }

            return health;
        }

        private async Task<SystemComponentHealth> CheckSystemHealthComponentsAsync()
        {
            var health = new SystemComponentHealth
            {
                Component = SystemComponent.System,
                CheckTime = DateTime.UtcNow
            };

            try
            {
                var uptime = GetSystemUptime();
                health.Metrics.Add(new HealthMetric { Name = "System Uptime", Value = uptime.TotalHours, Unit = "hours" });

                var lastBoot = GetLastBootTime();
                health.Metrics.Add(new HealthMetric { Name = "Last Boot Time", Value = 0, Unit = "" });

                health.Status = HealthStatus.Good;
                health.Message = "System is running normally";
            }
            catch (Exception ex)
            {
                Logger.Error($"System health check error: {ex.Message}");
                health.Status = HealthStatus.Error;
                health.Message = ex.Message;
            }

            return health;
        }

        private async Task<List<RegistryEntry>> CleanupInvalidFileAssociationsAsync()
        {
            // 真实实现: 扫常见扩展名的 HKCR 关联, "shell\open\command" 指向不存在的 exe 时删除 open 键树
            return await Task.Run(() =>
            {
                var entries = new List<RegistryEntry>();
                try
                {
                    var exts = new[] { ".txt", ".doc", ".docx", ".xls", ".pdf", ".jpg", ".png", ".mp3", ".mp4", ".zip", ".rar", ".exe" };
                    foreach (var ext in exts)
                    {
                        using (var extKey = Microsoft.Win32.Registry.ClassesRoot.OpenSubKey(ext))
                        {
                            if (extKey == null) continue;
                            var progId = extKey.GetValue("") as string;
                            if (string.IsNullOrEmpty(progId)) continue;

                            var openPath = progId + @"\shell\open\command";
                            using (var shellKey = Microsoft.Win32.Registry.ClassesRoot.OpenSubKey(openPath))
                            {
                                if (shellKey == null) continue;
                                var command = shellKey.GetValue("") as string;
                                if (string.IsNullOrEmpty(command)) continue;

                                var exePath = ExtractExeFromCommand(command);
                                if (exePath == null || System.IO.File.Exists(exePath)) continue;

                                entries.Add(new RegistryEntry
                                {
                                    Key = @"HKCR\" + openPath,
                                    ValueName = "",
                                    Value = command,
                                    Type = RegistryEntryType.String
                                });

                                try
                                {
                                    Microsoft.Win32.Registry.ClassesRoot.DeleteSubKeyTree(progId + @"\shell\open", false);
                                    Logger.Info($"Removed invalid file association: {progId} -> {exePath}");
                                }
                                catch (Exception ex)
                                {
                                    Logger.Error($"Remove association failed for {progId}: {ex.Message}");
                                }
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    Logger.Error($"Invalid file association cleanup error: {ex.Message}");
                }
                return entries;
            });
        }

        private async Task<List<RegistryEntry>> CleanupInvalidInstallerEntriesAsync()
        {
            // 真实实现: 扫 Uninstall 项, 卸载器指向不存在的 exe = 无效条目。
            // 仅记录清单不删键（卸载键误删将无法恢复, 交用户确认处理）
            return await Task.Run(() =>
            {
                var entries = new List<RegistryEntry>();
                try
                {
                    var roots = new[] { Microsoft.Win32.Registry.LocalMachine, Microsoft.Win32.Registry.CurrentUser };
                    foreach (var root in roots)
                    {
                        using (var uninstallKey = root.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"))
                        {
                            if (uninstallKey == null) continue;
                            foreach (var sub in uninstallKey.GetSubKeyNames())
                            {
                                try
                                {
                                    using (var item = uninstallKey.OpenSubKey(sub))
                                    {
                                        if (item == null) continue;
                                        var uninstaller = item.GetValue("UninstallString") as string;
                                        if (string.IsNullOrEmpty(uninstaller)) continue;

                                        var exePath = ExtractExeFromCommand(uninstaller);
                                        if (exePath == null || System.IO.File.Exists(exePath)) continue;

                                        entries.Add(new RegistryEntry
                                        {
                                            Key = @"Uninstall\" + sub,
                                            ValueName = "UninstallString",
                                            Value = uninstaller,
                                            Type = RegistryEntryType.String
                                        });
                                    }
                                }
                                catch { }
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    Logger.Error($"Invalid installer entry scan error: {ex.Message}");
                }
                return entries;
            });
        }

        private async Task<List<RegistryEntry>> CleanupInvalidStartMenuEntriesAsync()
        {
            // 真实实现: 扫开始菜单 .lnk（WScript.Shell 解析目标）, 目标不存在且非网址 → 删除 lnk 文件
            return await Task.Run(() =>
            {
                var entries = new List<RegistryEntry>();
                try
                {
                    var dirs = new[]
                    {
                        System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartMenu), "Programs"),
                        System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.StartMenu), "Programs")
                    };

                    dynamic shell = Activator.CreateInstance(Type.GetTypeFromProgID("WScript.Shell"));
                    try
                    {
                        foreach (var dir in dirs)
                        {
                            if (!System.IO.Directory.Exists(dir)) continue;
                            foreach (var lnk in System.IO.Directory.EnumerateFiles(dir, "*.lnk", SearchOption.AllDirectories))
                            {
                                try
                                {
                                    dynamic shortcut = shell.CreateShortcut(lnk);
                                    string target = shortcut.TargetPath;
                                    System.Runtime.InteropServices.Marshal.FinalReleaseComObject(shortcut);

                                    if (string.IsNullOrEmpty(target)) continue;
                                    if (target.StartsWith("http", StringComparison.OrdinalIgnoreCase)) continue; // 网址快捷方式跳过
                                    if (System.IO.File.Exists(target) || System.IO.Directory.Exists(target)) continue;

                                    entries.Add(new RegistryEntry
                                    {
                                        Key = lnk,
                                        ValueName = "TargetPath",
                                        Value = target,
                                        Type = RegistryEntryType.String
                                    });

                                    System.IO.File.Delete(lnk);
                                    Logger.Info($"Removed invalid start menu shortcut: {lnk} -> {target}");
                                }
                                catch { }
                            }
                        }
                    }
                    finally
                    {
                        System.Runtime.InteropServices.Marshal.FinalReleaseComObject(shell);
                    }
                }
                catch (Exception ex)
                {
                    Logger.Error($"Invalid start menu cleanup error: {ex.Message}");
                }
                return entries;
            });
        }

        private async Task<List<RegistryEntry>> CleanupUnusedRegistryKeysAsync()
        {
            // 真实实现: Run/RunOnce（含 WOW6432Node）中指向不存在 exe 的启动值 → 删除值并记录
            return await Task.Run(() =>
            {
                var entries = new List<RegistryEntry>();
                try
                {
                    var runPaths = new[]
                    {
                        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                        @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                        @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
                    };
                    foreach (var rootView in new[] { Microsoft.Win32.Registry.LocalMachine, Microsoft.Win32.Registry.CurrentUser })
                    {
                        foreach (var runPath in runPaths)
                        {
                            using (var runKey = rootView.OpenSubKey(runPath, writable: true))
                            {
                                if (runKey == null) continue;
                                foreach (var valueName in runKey.GetValueNames())
                                {
                                    var command = runKey.GetValue(valueName) as string;
                                    if (string.IsNullOrEmpty(command)) continue;

                                    var exePath = ExtractExeFromCommand(command);
                                    if (exePath == null || System.IO.File.Exists(exePath)) continue;

                                    entries.Add(new RegistryEntry
                                    {
                                        Key = runPath,
                                        ValueName = valueName,
                                        Value = command,
                                        Type = RegistryEntryType.String
                                    });

                                    try
                                    {
                                        runKey.DeleteValue(valueName, false);
                                        Logger.Info($"Removed dead Run entry: {valueName} -> {exePath}");
                                    }
                                    catch (Exception ex)
                                    {
                                        Logger.Error($"Remove Run value failed: {ex.Message}");
                                    }
                                }
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    Logger.Error($"Unused registry key cleanup error: {ex.Message}");
                }
                return entries;
            });
        }

        /// <summary>从命令行串提取 exe 路径（兼容 "C:\path\app.exe" "%1" 与裸路径两种格式）。</summary>
        private static string ExtractExeFromCommand(string command)
        {
            try
            {
                if (string.IsNullOrEmpty(command)) return null;
                var trimmed = command.Trim();
                if (trimmed.StartsWith("\""))
                {
                    int end = trimmed.IndexOf('"', 1);
                    return end > 1 ? trimmed.Substring(1, end - 1) : null;
                }
                int space = trimmed.IndexOf(' ');
                return space > 0 ? trimmed.Substring(0, space) : trimmed;
            }
            catch { return null; }
        }

        private double GetCpuUsage()
        {
            try
            {
                var cpuCounter = new System.Diagnostics.PerformanceCounter("Processor", "% Processor Time", "_Total");
                cpuCounter.NextValue(); // 第一次调用返回0
                System.Threading.Thread.Sleep(100);
                return cpuCounter.NextValue();
            }
            catch { return 0; }
        }

        private (long Total, long Used) GetMemoryInfo()
        {
            try
            {
                var memCounter = new System.Diagnostics.PerformanceCounter("Memory", "Available MBytes");
                var availableMB = (long)memCounter.NextValue();
                
                using var searcher = new System.Management.ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystem");
                foreach (var obj in searcher.Get())
                {
                    var totalBytes = Convert.ToInt64(obj["TotalPhysicalMemory"]);
                    var totalMB = totalBytes / (1024 * 1024);
                    return (totalMB, totalMB - availableMB);
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SystemOptimization.cs 捕获异常", ex.Message); }
            return (0, 0);
        }

        private (long Total, long Used) GetDiskInfo()
        {
            try
            {
                var drive = new System.IO.DriveInfo(System.IO.Path.GetPathRoot(Environment.SystemDirectory));
                return (drive.TotalSize / (1024 * 1024), (drive.TotalSize - drive.AvailableFreeSpace) / (1024 * 1024));
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SystemOptimization.cs 捕获异常", ex.Message); }
            return (0, 0);
        }

        private long GetPingTime(string host)
        {
            try
            {
                using var ping = new System.Net.NetworkInformation.Ping();
                var reply = ping.Send(host, 5000);
                return reply.Status == System.Net.NetworkInformation.IPStatus.Success ? reply.RoundtripTime : -1;
            }
            catch { return -1; }
        }

        private TimeSpan GetSystemUptime()
        {
            try
            {
                using var searcher = new System.Management.ManagementObjectSearcher("SELECT * FROM Win32_OperatingSystem");
                foreach (var obj in searcher.Get())
                {
                    var lastBoot = System.Management.ManagementDateTimeConverter.ToDateTime(obj["LastBootUpTime"].ToString());
                    return DateTime.Now - lastBoot;
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SystemOptimization.cs 捕获异常", ex.Message); }
            return TimeSpan.Zero;
        }

        private DateTime GetLastBootTime()
        {
            try
            {
                using var searcher = new System.Management.ManagementObjectSearcher("SELECT * FROM Win32_OperatingSystem");
                foreach (var obj in searcher.Get())
                {
                    return System.Management.ManagementDateTimeConverter.ToDateTime(obj["LastBootUpTime"].ToString());
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SystemOptimization.cs 捕获异常", ex.Message); }
            return DateTime.MinValue;
        }

        private long CalculateDirectorySize(string path)
        {
            try
            {
                var directory = new DirectoryInfo(path);
                return directory.EnumerateFiles("*.*", SearchOption.AllDirectories).Sum(file => file.Length);
            }
            catch
            {
                return 0;
            }
        }

        private HealthStatus CalculateOverallHealth(List<SystemComponentHealth> components)
        {
            if (components.Any(c => c.Status == HealthStatus.Critical))
            {
                return HealthStatus.Critical;
            }
            if (components.Any(c => c.Status == HealthStatus.Warning))
            {
                return HealthStatus.Warning;
            }
            if (components.Any(c => c.Status == HealthStatus.Error))
            {
                return HealthStatus.Error;
            }
            return HealthStatus.Good;
        }
    }

    public class SystemCleanupResult
    {
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public TimeSpan Duration { get; set; }
        public bool Success { get; set; }
        public string ErrorMessage { get; set; }
        public List<CleanedItem> CleanedItems { get; set; }
        public long FreedSpaceBytes { get; set; }
        public int CleanedItemsCount => CleanedItems?.Count ?? 0;
    }

    public class CleanedItem
    {
        public string Path { get; set; }
        public long SizeBytes { get; set; }
        public CleanedItemType Type { get; set; }
    }

    public class SystemPerformanceResult
    {
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public TimeSpan Duration { get; set; }
        public bool Success { get; set; }
        public string ErrorMessage { get; set; }
        public List<PerformanceOptimization> Optimizations { get; set; }
    }

    public class PerformanceOptimization
    {
        public OptimizationType Type { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public TimeSpan Duration { get; set; }
        public bool Success { get; set; }
        public string ErrorMessage { get; set; }
        public List<string> Actions { get; set; }
    }

    public class SystemHealthResult
    {
        public DateTime CheckTime { get; set; }
        public bool Success { get; set; }
        public string ErrorMessage { get; set; }
        public List<SystemComponentHealth> Components { get; set; }
        public HealthStatus OverallHealth { get; set; }
    }

    public class SystemComponentHealth
    {
        public SystemComponent Component { get; set; }
        public DateTime CheckTime { get; set; }
        public HealthStatus Status { get; set; }
        public string Message { get; set; }
        public List<HealthMetric> Metrics { get; set; } = new List<HealthMetric>();
    }

    public class HealthMetric
    {
        public string Name { get; set; }
        public double Value { get; set; }
        public string Unit { get; set; }
    }

    public class RegistryCleanupResult
    {
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public TimeSpan Duration { get; set; }
        public bool Success { get; set; }
        public string ErrorMessage { get; set; }
        public List<RegistryEntry> CleanedEntries { get; set; }
        public int CleanedEntriesCount => CleanedEntries?.Count ?? 0;
    }

    public class RegistryEntry
    {
        public string Key { get; set; }
        public string ValueName { get; set; }
        public string Value { get; set; }
        public RegistryEntryType Type { get; set; }
    }

    public class SystemCleanupOptions
    {
        public bool CleanTempFiles { get; set; } = true;
        public bool CleanLogFiles { get; set; } = true;
        public bool CleanBrowserCache { get; set; } = true;
        public bool CleanRecycleBin { get; set; } = true;
        public bool CleanTemporaryInternetFiles { get; set; } = true;
    }

    public class PerformanceOptimizationOptions
    {
        public bool OptimizeStartup { get; set; } = true;
        public bool OptimizeMemory { get; set; } = true;
        public bool OptimizeDisk { get; set; } = true;
        public bool OptimizeServices { get; set; } = true;
    }

    public class RegistryCleanupOptions
    {
        public bool CleanInvalidFileAssociations { get; set; } = true;
        public bool CleanInvalidInstallerEntries { get; set; } = true;
        public bool CleanInvalidStartMenuEntries { get; set; } = true;
        public bool CleanUnusedRegistryKeys { get; set; } = true;
    }

    public enum CleanedItemType
    {
        TempFile,
        LogFile,
        BrowserCache,
        RecycleBin,
        TemporaryInternetFiles,
        Other
    }

    public enum OptimizationType
    {
        Startup,
        Memory,
        Disk,
        Services,
        Network,
        Other
    }

    public enum SystemComponent
    {
        CPU,
        Memory,
        Disk,
        Network,
        System,
        Other
    }

    public enum HealthStatus
    {
        Good,
        Warning,
        Critical,
        Error
    }

    public enum RegistryEntryType
    {
        String,
        ExpandString,
        Binary,
        DWord,
        QWord,
        MultiString,
        Other
    }
}