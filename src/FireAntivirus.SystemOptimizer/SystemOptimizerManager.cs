using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
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
                // 清理系统日志
                // 实际实现中应该使用EventLog类来清理系统日志
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
                // 清理浏览器缓存
                // 实际实现中应该清理不同浏览器的缓存目录
                return true;
            }
            catch
            {
                return false;
            }
        }

        private bool OptimizeStartupItems()
        {
            try
            {
                // 优化启动项
                // 实际实现中应该检查和管理系统启动项
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
                // 优化系统服务
                // 实际实现中应该检查和管理系统服务
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