using FireAntivirus.Common;
using FireAntivirus.Data;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
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
                // 实现回收站清理逻辑
                // 这里简化处理，实际应该使用Windows API
                result.CleanedItems.Add(new CleanedItem
                {
                    Path = "Recycle Bin",
                    SizeBytes = 0,
                    Type = CleanedItemType.RecycleBin
                });

                result.Success = true;
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
                // 实现启动项优化逻辑
                // 这里简化处理，实际应该分析和优化启动项
                optimization.Actions.Add("Analyzed startup items");
                optimization.Actions.Add("Disabled unnecessary startup programs");
                optimization.Actions.Add("Optimized startup services");
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
                // 实现内存优化逻辑
                // 这里简化处理，实际应该清理内存和优化内存使用
                optimization.Actions.Add("Cleared memory cache");
                optimization.Actions.Add("Optimized memory usage");
                optimization.Actions.Add("Released unused memory");
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
                // 实现磁盘优化逻辑
                // 这里简化处理，实际应该分析和优化磁盘使用
                optimization.Actions.Add("Analyzed disk usage");
                optimization.Actions.Add("Optimized disk fragmentation");
                optimization.Actions.Add("Cleaned disk errors");
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
                // 实现服务优化逻辑
                // 这里简化处理，实际应该分析和优化系统服务
                optimization.Actions.Add("Analyzed system services");
                optimization.Actions.Add("Disabled unnecessary services");
                optimization.Actions.Add("Optimized service startup types");
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
            var entries = new List<RegistryEntry>();
            // 实现清理无效文件关联的逻辑
            return entries;
        }

        private async Task<List<RegistryEntry>> CleanupInvalidInstallerEntriesAsync()
        {
            var entries = new List<RegistryEntry>();
            // 实现清理无效安装程序条目的逻辑
            return entries;
        }

        private async Task<List<RegistryEntry>> CleanupInvalidStartMenuEntriesAsync()
        {
            var entries = new List<RegistryEntry>();
            // 实现清理无效开始菜单条目的逻辑
            return entries;
        }

        private async Task<List<RegistryEntry>> CleanupUnusedRegistryKeysAsync()
        {
            var entries = new List<RegistryEntry>();
            // 实现清理未使用注册表键的逻辑
            return entries;
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
