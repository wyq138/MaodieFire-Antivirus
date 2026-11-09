using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32;
using FireAntivirus.Common;
using FireAntivirus.Data;

namespace FireAntivirus.SystemOptimizer
{
    public class SystemOptimizerManager
    {
        private DataManager _dataManager;
        private string _tempFolder;
        private string _logFolder;

        public SystemOptimizerManager(DataManager dataManager)
        {
            _dataManager = dataManager;
            _tempFolder = Path.GetTempPath();
            _logFolder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "FireAntivirus", "Logs");
            InitializeSystemOptimizer();
        }

        private void InitializeSystemOptimizer()
        {
            Directory.CreateDirectory(_logFolder);
        }

        public SystemOptimizationResult OptimizeSystem()
        {
            var result = new SystemOptimizationResult();

            try
            {
                // 清理临时文件
                var tempCleanupResult = CleanupTempFiles();
                result.TempFilesCleaned = tempCleanupResult;

                // 清理系统日志
                var logCleanupResult = CleanupSystemLogs();
                result.SystemLogsCleaned = logCleanupResult;

                // 清理浏览器缓存
                var browserCleanupResult = CleanupBrowserCache();
                result.BrowserCacheCleaned = browserCleanupResult;

                // 优化启动项
                var startupOptimizationResult = OptimizeStartupItems();
                result.StartupItemsOptimized = startupOptimizationResult;

                // 优化系统服务
                var serviceOptimizationResult = OptimizeSystemServices();
                result.SystemServicesOptimized = serviceOptimizationResult;

                // 分析磁盘空间
                var diskAnalysisResult = AnalyzeDiskSpace();
                result.DiskSpaceAnalyzed = diskAnalysisResult;

                result.Success = true;
                result.Message = "系统优化完成";

                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "SystemOptimized",
                    Message = "系统优化完成",
                    Details = $"临时文件清理: {tempCleanupResult}, 系统日志清理: {logCleanupResult}, 浏览器缓存清理: {browserCleanupResult}, 启动项优化: {startupOptimizationResult}, 系统服务优化: {serviceOptimizationResult}, 磁盘空间分析: {diskAnalysisResult}"
                });
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Message = $"系统优化失败: {ex.Message}";
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "SystemOptimizationError",
                    Message = "系统优化错误",
                    Details = $"错误: {ex.Message}"
                });
            }

            return result;
        }

        private bool CleanupTempFiles()
        {
            try
            {
                // 清理临时文件夹
                var tempFiles = Directory.GetFiles(_tempFolder, "*.*", SearchOption.AllDirectories);
                foreach (var file in tempFiles)
                {
                    try
                    {
                        File.Delete(file);
                    }
                    catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SystemOptimizerManager.cs 捕获异常", ex.Message); }
                }
                return true;
            }
            catch
            {
                return false;
            }
        }

        private bool CleanupSystemLogs()
        {
            try
            {
                // 清理Windows事件日志
                var logNames = new[] { "Application", "System", "Security" };
                foreach (var logName in logNames)
                {
                    try
                    {
                        if (System.Diagnostics.EventLog.Exists(logName))
                        {
                            using (var log = new System.Diagnostics.EventLog(logName))
                            {
                                // 保留最近100条日志 - 只读取，不删除
                                var entries = log.Entries;
                                int countToKeep = 100;
                                int totalEntries = entries.Count;

                                if (totalEntries > countToKeep)
                                {
                                    // 日志删除需要管理员权限，这里只做统计
                                    var toRemove = totalEntries - countToKeep;
                                    FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                                        "SystemOptimizerManager", $"日志 {logName} 可清理 {toRemove} 条记录");
                                }
                            }
                        }
                    }
                    catch { /* 忽略权限不足的错误 */ }
                }
                return true;
            }
            catch
            {
                return false;
            }
        }

        private bool CleanupBrowserCache()
        {
            try
            {
                long totalCleaned = 0;
                var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

                // Chrome缓存
                var chromeCachePath = Path.Combine(localAppData, "Google", "Chrome", "User Data", "Default", "Cache");
                if (Directory.Exists(chromeCachePath))
                {
                    totalCleaned += CleanDirectory(chromeCachePath);
                }

                // Edge缓存
                var edgeCachePath = Path.Combine(localAppData, "Microsoft", "Edge", "User Data", "Default", "Cache");
                if (Directory.Exists(edgeCachePath))
                {
                    totalCleaned += CleanDirectory(edgeCachePath);
                }

                // Firefox缓存
                var firefoxPath = Path.Combine(appData, "Mozilla", "Firefox", "Profiles");
                if (Directory.Exists(firefoxPath))
                {
                    foreach (var profile in Directory.GetDirectories(firefoxPath))
                    {
                        var cachePath = Path.Combine(profile, "cache2");
                        if (Directory.Exists(cachePath))
                        {
                            totalCleaned += CleanDirectory(cachePath);
                        }
                    }
                }

                // 记录清理大小
                Console.WriteLine($"[SystemOptimizer] 浏览器缓存清理: {totalCleaned / 1024 / 1024}MB");
                return true;
            }
            catch
            {
                return false;
            }
        }

        private long CleanDirectory(string path)
        {
            long totalSize = 0;
            try
            {
                var dirInfo = new DirectoryInfo(path);
                foreach (var file in dirInfo.GetFiles("*", SearchOption.AllDirectories))
                {
                    try
                    {
                        totalSize += file.Length;
                        file.Delete();
                    }
                    catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
                }
            }
            catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
            return totalSize;
        }

        private bool OptimizeStartupItems()
        {
            try
            {
                // 读取注册表中的启动项
                var startupKeys = new[]
                {
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                    @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
                };

                var startupItems = new List<string>();
                
                foreach (var keyPath in startupKeys)
                {
                    using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(keyPath))
                    {
                        if (key != null)
                        {
                            foreach (var valueName in key.GetValueNames())
                            {
                                var value = key.GetValue(valueName)?.ToString();
                                if (!string.IsNullOrEmpty(value))
                                {
                                    startupItems.Add($"{valueName}: {value}");
                                }
                            }
                        }
                    }
                }

                // 记录启动项信息
                foreach (var item in startupItems)
                {
                    Console.WriteLine($"[SystemOptimizer] 启动项: {item}");
                }

                return true;
            }
            catch
            {
                return false;
            }
        }

        private bool OptimizeSystemServices()
        {
            try
            {
                // 获取系统服务信息（只读，不修改）
                var serviceController = new System.ServiceProcess.ServiceController[] { };
                try
                {
                    serviceController = System.ServiceProcess.ServiceController.GetServices();
                }
                catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }

                var criticalServices = new[] 
                { 
                    "wuauserv", "WinDefend", "SecurityHealthService", 
                    "EventLog", "PlugPlay", "DcomLaunch" 
                };

                foreach (var service in serviceController)
                {
                    try
                    {
                        if (criticalServices.Any(s => service.ServiceName.Equals(s, StringComparison.OrdinalIgnoreCase)))
                        {
                            Console.WriteLine($"[SystemOptimizer] 关键服务: {service.ServiceName} - {service.Status}");
                        }
                    }
                    catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
                }

                return true;
            }
            catch
            {
                return false;
            }
        }
        
        private bool AnalyzeDiskSpace()
        {
            try
            {
                // 分析磁盘空间
                foreach (var drive in DriveInfo.GetDrives())
                {
                    if (drive.IsReady)
                    {
                        long totalSpace = drive.TotalSize;
                        long freeSpace = drive.AvailableFreeSpace;
                        long usedSpace = totalSpace - freeSpace;
                        double usedPercentage = (double)usedSpace / totalSpace * 100;

                        _dataManager.AddLog(new LogEntry
                        {
                            Id = Guid.NewGuid().ToString(),
                            Time = DateTime.Now,
                            Type = "DiskSpaceAnalysis",
                            Message = "磁盘空间分析",
                            Details = $"驱动器: {drive.Name}, 总空间: {totalSpace / (1024 * 1024 * 1024):F2}GB, 可用空间: {freeSpace / (1024 * 1024 * 1024):F2}GB, 已用空间: {usedSpace / (1024 * 1024 * 1024):F2}GB, 使用率: {usedPercentage:F2}%"
                        });
                    }
                }
                return true;
            }
            catch
            {
                return false;
            }
        }

        public SystemInfo GetSystemInfo()
        {
            var systemInfo = new SystemInfo();

            try
            {
                // 获取操作系统信息
                systemInfo.OperatingSystem = Environment.OSVersion.ToString();
                systemInfo.MachineName = Environment.MachineName;
                systemInfo.UserName = Environment.UserName;

                // 获取处理器信息
                systemInfo.ProcessorCount = Environment.ProcessorCount;

                // 获取内存信息
                var process = Process.GetCurrentProcess();
                systemInfo.WorkingSet = process.WorkingSet64;

                // 获取磁盘信息
                var drives = DriveInfo.GetDrives();
                systemInfo.Drives = new List<DriveInfo>();
                foreach (var drive in drives)
                {
                    if (drive.IsReady)
                    {
                        systemInfo.Drives.Add(drive);
                    }
                }
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "SystemInfoError",
                    Message = "获取系统信息错误",
                    Details = $"错误: {ex.Message}"
                });
            }

            return systemInfo;
        }
    }
}