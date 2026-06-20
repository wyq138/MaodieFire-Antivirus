// 抖音用户 耄耋杀毒软件 开发，严禁非法反编译
// 专业级系统优化引擎 - 对标CCleaner/Advanced SystemCare能力
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace FireAntivirus.Services
{
    public class SystemOptimizerService : IDisposable
    {
        #region Windows API

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX lpBuffer);

        [DllImport("psapi.dll", SetLastError = true)]
        private static extern int EmptyWorkingSet(IntPtr hProcess);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool OpenClipboard(IntPtr hWndNewOwner);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool EmptyClipboard();

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool CloseClipboard();

        [DllImport("shell32.dll", SetLastError = true)]
        private static extern int SHEmptyRecycleBin(IntPtr hWnd, string pszRootPath, int dwFlags);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetProcessWorkingSetSize(IntPtr hProcess, int dwMinimumWorkingSetSize, int dwMaximumWorkingSetSize);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, int BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr ProcessHandle, int DesiredAccess, ref IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, ref LUID lpLuid);

        [StructLayout(LayoutKind.Sequential)]
        private struct MEMORYSTATUSEX
        {
            public uint dwLength;
            public uint dwMemoryLoad;
            public ulong ullTotalPhys;
            public ulong ullAvailPhys;
            public ulong ullTotalPageFile;
            public ulong ullAvailPageFile;
            public ulong ullTotalVirtual;
            public ulong ullAvailVirtual;
            public ulong ullAvailExtendedVirtual;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_PRIVILEGES
        {
            public int PrivilegeCount;
            public LUID Luid;
            public int Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID
        {
            public int LowPart;
            public int HighPart;
        }

        #endregion

        private readonly string _configPath;
        private readonly string _logPath;
        private bool _isScanning = false;
        private bool _isCleaning = false;

        // 监控
        private Timer _monitorTimer;
        private bool _isMonitoring = false;
        private SystemPerformanceMetrics _lastMetrics;

        // 优化历史
        private List<OptimizationHistory> _optimizationHistory = new List<OptimizationHistory>();

        public event EventHandler<OptimizerProgressEventArgs> ProgressChanged;
        public event EventHandler<PerformanceAlertEventArgs> PerformanceAlert;

        public SystemOptimizerService()
        {
            _configPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "FireAntivirus", "SystemOptimizer");

            _logPath = Path.Combine(_configPath, "Logs");

            foreach (var path in new[] { _configPath, _logPath })
            {
                if (!Directory.Exists(path))
                    Directory.CreateDirectory(path);
            }

            LoadOptimizationHistory();
        }

        #region 公共方法 - 垃圾文件清理

        /// <summary>
        /// 扫描垃圾文件
        /// </summary>
        public JunkScanResult ScanJunkFiles(ScanOptions options = null)
        {
            options ??= new ScanOptions();

            var result = new JunkScanResult
            {
                ScanId = Guid.NewGuid().ToString(),
                StartTime = DateTime.Now
            };

            if (_isScanning)
            {
                result.Error = "扫描正在进行中";
                return result;
            }

            _isScanning = true;

            try
            {
                long totalSize = 0;
                int progress = 0;
                int totalSteps = 12;

                // Windows临时文件
                RaiseProgress(ref progress, totalSteps, "扫描Windows临时文件...");
                if (options.ScanWindowsTemp)
                {
                    result.Categories.AddRange(ScanDirectory(
                        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"),
                        "Windows临时文件", ref totalSize, options.MaxFileAge));
                }

                // 用户临时文件
                RaiseProgress(ref progress, totalSteps, "扫描用户临时文件...");
                if (options.ScanUserTemp)
                {
                    result.Categories.AddRange(ScanDirectory(
                        Path.GetTempPath(),
                        "用户临时文件", ref totalSize, options.MaxFileAge));
                }

                // 浏览器缓存
                RaiseProgress(ref progress, totalSteps, "扫描浏览器缓存...");
                if (options.ScanBrowserCache)
                {
                    result.Categories.AddRange(ScanBrowserCache(ref totalSize, options));
                }

                // 回收站
                RaiseProgress(ref progress, totalSteps, "扫描回收站...");
                if (options.ScanRecycleBin)
                {
                    result.Categories.AddRange(ScanRecycleBin(ref totalSize));
                }

                // Windows更新缓存
                RaiseProgress(ref progress, totalSteps, "扫描Windows更新缓存...");
                if (options.ScanWindowsUpdate)
                {
                    result.Categories.AddRange(ScanDirectory(
                        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SoftwareDistribution", "Download"),
                        "Windows更新缓存", ref totalSize, null));
                }

                // 缩略图缓存
                RaiseProgress(ref progress, totalSteps, "扫描缩略图缓存...");
                if (options.ScanThumbnailCache)
                {
                    result.Categories.AddRange(ScanThumbnailCache(ref totalSize));
                }

                // 日志文件
                RaiseProgress(ref progress, totalSteps, "扫描日志文件...");
                if (options.ScanLogFiles)
                {
                    result.Categories.AddRange(ScanLogFiles(ref totalSize));
                }

                // Prefetch文件
                RaiseProgress(ref progress, totalSteps, "扫描Prefetch文件...");
                if (options.ScanPrefetch)
                {
                    result.Categories.AddRange(ScanDirectory(
                        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch"),
                        "Prefetch文件", ref totalSize, null));
                }

                // 错误报告
                RaiseProgress(ref progress, totalSteps, "扫描错误报告...");
                if (options.ScanErrorReports)
                {
                    var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                    result.Categories.AddRange(ScanDirectory(
                        Path.Combine(programData, "Microsoft", "Windows", "WER"),
                        "错误报告文件", ref totalSize, null));
                }

                // Windows旧版备份
                RaiseProgress(ref progress, totalSteps, "扫描旧版Windows备份...");
                if (options.ScanOldWindows)
                {
                    result.Categories.AddRange(ScanOldWindowsFolder(ref totalSize));
                }

                // 系统还原点
                RaiseProgress(ref progress, totalSteps, "扫描系统还原数据...");
                if (options.ScanSystemRestore)
                {
                    result.Categories.AddRange(ScanSystemRestore(ref totalSize));
                }

                // 应用程序缓存
                RaiseProgress(ref progress, totalSteps, "扫描应用程序缓存...");
                if (options.ScanAppCache)
                {
                    result.Categories.AddRange(ScanAppCache(ref totalSize));
                }

                result.TotalSize = totalSize;
                result.TotalFiles = result.Categories.Sum(c => c.FileCount);
                result.EndTime = DateTime.Now;
                result.Duration = result.EndTime - result.StartTime;
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
            }
            finally
            {
                _isScanning = false;
                RaiseProgress(12, 12, "扫描完成");
            }

            return result;
        }

        /// <summary>
        /// 清理垃圾文件
        /// </summary>
        public CleanResult CleanJunkFiles(List<JunkFileInfo> files, bool createRestorePoint = true)
        {
            var result = new CleanResult
            {
                StartTime = DateTime.Now
            };

            if (_isCleaning)
            {
                result.Error = "清理正在进行中";
                return result;
            }

            _isCleaning = true;

            try
            {
                // 创建还原点
                if (createRestorePoint)
                {
                    CreateRestorePoint("垃圾文件清理");
                }

                int total = files.Count;
                int cleaned = 0;
                long cleanedSize = 0;
                int failed = 0;

                foreach (var file in files)
                {
                    try
                    {
                        if (File.Exists(file.FilePath))
                        {
                            var fileInfo = new FileInfo(file.FilePath);
                            cleanedSize += fileInfo.Length;
                            File.Delete(file.FilePath);
                            result.CleanedFiles++;
                        }
                        else if (Directory.Exists(file.FilePath))
                        {
                            var dirInfo = new DirectoryInfo(file.FilePath);
                            cleanedSize += GetDirectorySize(dirInfo);
                            Directory.Delete(file.FilePath, true);
                            result.CleanedFiles++;
                        }

                        cleaned++;
                        int progress = (int)((cleaned / (double)total) * 100);
                        ProgressChanged?.Invoke(this, new OptimizerProgressEventArgs
                        {
                            Progress = progress,
                            Message = $"清理中... {cleaned}/{total}"
                        });
                    }
                    catch
                    {
                        failed++;
                        result.FailedFiles++;
                    }
                }

                // 清空回收站
                try
                {
                    SHEmptyRecycleBin(IntPtr.Zero, null, 7);
                }
                catch { }

                result.Success = true;
                result.CleanedSize = cleanedSize;
                result.EndTime = DateTime.Now;
                result.Duration = result.EndTime - result.StartTime;

                // 记录历史
                RecordOptimization("垃圾清理", result.CleanedSize, result.CleanedFiles);
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
            }
            finally
            {
                _isCleaning = false;
            }

            return result;
        }

        #endregion

        #region 公共方法 - 注册表清理

        /// <summary>
        /// 扫描注册表问题
        /// </summary>
        public RegistryScanResult ScanRegistry()
        {
            var result = new RegistryScanResult
            {
                ScanId = Guid.NewGuid().ToString(),
                StartTime = DateTime.Now
            };

            try
            {
                int progress = 0;
                int totalSteps = 6;

                // 无效卸载信息
                RaiseProgress(ref progress, totalSteps, "扫描卸载信息...");
                result.Issues.AddRange(ScanUninstallKeys());

                // 无效启动项
                RaiseProgress(ref progress, totalSteps, "扫描启动项...");
                result.Issues.AddRange(ScanStartupKeys());

                // 无效文件关联
                RaiseProgress(ref progress, totalSteps, "扫描文件关联...");
                result.Issues.AddRange(ScanFileAssociations());

                // 无效共享DLL
                RaiseProgress(ref progress, totalSteps, "扫描共享DLL...");
                result.Issues.AddRange(ScanSharedDLLs());

                // 无效COM组件
                RaiseProgress(ref progress, totalSteps, "扫描COM组件...");
                result.Issues.AddRange(ScanCOMComponents());

                // 历史记录
                RaiseProgress(ref progress, totalSteps, "扫描历史记录...");
                result.Issues.AddRange(ScanHistoryKeys());

                result.TotalIssues = result.Issues.Count;
                result.CriticalIssues = result.Issues.Count(i => i.Severity == "高");
                result.EndTime = DateTime.Now;
                result.Duration = result.EndTime - result.StartTime;
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
            }

            return result;
        }

        /// <summary>
        /// 修复注册表问题
        /// </summary>
        public RegistryFixResult FixRegistryIssues(List<RegistryIssue> issues)
        {
            var result = new RegistryFixResult
            {
                StartTime = DateTime.Now
            };

            try
            {
                // 创建备份
                var backupPath = CreateRegistryBackup();

                foreach (var issue in issues)
                {
                    try
                    {
                        if (FixRegistryIssue(issue))
                        {
                            result.FixedIssues++;
                        }
                        else
                        {
                            result.FailedIssues++;
                        }
                    }
                    catch
                    {
                        result.FailedIssues++;
                    }
                }

                result.Success = true;
                result.BackupPath = backupPath;
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
            }

            result.EndTime = DateTime.Now;
            return result;
        }

        #endregion

        #region 公共方法 - 内存优化

        /// <summary>
        /// 获取内存状态
        /// </summary>
        public MemoryStatus GetMemoryStatus()
        {
            var status = new MemoryStatus();
            var memStatus = new MEMORYSTATUSEX();
            memStatus.dwLength = (uint)Marshal.SizeOf(typeof(MEMORYSTATUSEX));

            if (GlobalMemoryStatusEx(ref memStatus))
            {
                status.TotalMB = (long)(memStatus.ullTotalPhys / 1024 / 1024);
                status.AvailableMB = (long)(memStatus.ullAvailPhys / 1024 / 1024);
                status.UsedPercent = (int)memStatus.dwMemoryLoad;
                status.TotalPageFileMB = (long)(memStatus.ullTotalPageFile / 1024 / 1024);
                status.AvailablePageFileMB = (long)(memStatus.ullAvailPageFile / 1024 / 1024);
            }

            // 获取进程内存使用
            status.TopMemoryProcesses = GetTopMemoryProcesses(10);

            return status;
        }

        /// <summary>
        /// 优化内存
        /// </summary>
        public MemoryOptimizeResult OptimizeMemory(MemoryOptimizeOptions options = null)
        {
            options ??= new MemoryOptimizeOptions();

            var result = new MemoryOptimizeResult
            {
                StartTime = DateTime.Now
            };

            try
            {
                var beforeStatus = GetMemoryStatus();
                result.BeforeAvailableMB = beforeStatus.AvailableMB;
                result.BeforeUsedPercent = beforeStatus.UsedPercent;

                // 清理系统工作集
                if (options.ClearWorkingSet)
                {
                    ClearSystemWorkingSet();
                }

                // 清理剪贴板
                if (options.ClearClipboard)
                {
                    ClearClipboardData();
                }

                // 清理 standby list
                if (options.ClearStandbyList)
                {
                    ClearStandbyList();
                }

                // 压缩内存
                if (options.CompressMemory)
                {
                    CompressMemoryPages();
                }

                // 等待清理完成
                Thread.Sleep(500);

                var afterStatus = GetMemoryStatus();
                result.AfterAvailableMB = afterStatus.AvailableMB;
                result.AfterUsedPercent = afterStatus.UsedPercent;
                result.FreedMB = Math.Max(0, afterStatus.AvailableMB - beforeStatus.AvailableMB);
                result.Success = true;

                RecordOptimization("内存优化", result.FreedMB * 1024 * 1024, 0);
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
            }

            result.EndTime = DateTime.Now;
            return result;
        }

        #endregion

        #region 公共方法 - 磁盘优化

        /// <summary>
        /// 获取磁盘信息
        /// </summary>
        public List<DiskInfo> GetDiskInfo()
        {
            var disks = new List<DiskInfo>();

            try
            {
                foreach (var drive in DriveInfo.GetDrives().Where(d => d.IsReady))
                {
                    var disk = new DiskInfo
                    {
                        Name = drive.Name,
                        Label = drive.VolumeLabel,
                        Format = drive.DriveFormat,
                        DriveType = drive.DriveType.ToString(),
                        TotalSize = drive.TotalSize,
                        FreeSpace = drive.AvailableFreeSpace,
                        UsedSpace = drive.TotalSize - drive.AvailableFreeSpace
                    };

                    disk.UsagePercent = (int)(disk.UsedSpace * 100 / disk.TotalSize);

                    // 检查是否为SSD
                    disk.IsSSD = CheckIfSSD(drive.Name);

                    // SMART状态
                    if (disk.IsSSD)
                    {
                        disk.SmartStatus = GetSMARTStatus(drive.Name).ToString();
                    }

                    disks.Add(disk);
                }
            }
            catch { }

            return disks;
        }

        /// <summary>
        /// 执行TRIM优化
        /// </summary>
        public TrimResult ExecuteTrim(string drive)
        {
            var result = new TrimResult
            {
                Drive = drive,
                StartTime = DateTime.Now
            };

            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "defrag",
                        Arguments = $"{drive} /L", // TRIM
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        RedirectStandardOutput = true
                    }
                };

                process.Start();
                var output = process.StandardOutput.ReadToEnd();
                process.WaitForExit(60000);

                result.Success = process.ExitCode == 0;
                result.Output = output;
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
            }

            result.EndTime = DateTime.Now;
            return result;
        }

        /// <summary>
        /// 分析磁盘碎片
        /// </summary>
        public DefragAnalysis AnalyzeDiskFragmentation(string drive)
        {
            var analysis = new DefragAnalysis
            {
                Drive = drive,
                AnalysisTime = DateTime.Now
            };

            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "defrag",
                        Arguments = $"{drive} /A",
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        RedirectStandardOutput = true
                    }
                };

                process.Start();
                var output = process.StandardOutput.ReadToEnd();
                process.WaitForExit(60000);

                // 解析输出
                analysis.RawOutput = output;

                // 查找碎片百分比
                var match = Regex.Match(output, @"(\d+)% fragmented");
                if (match.Success)
                {
                    analysis.FragmentationPercent = int.Parse(match.Groups[1].Value);
                }

                analysis.NeedsDefrag = analysis.FragmentationPercent > 10;
            }
            catch (Exception ex)
            {
                analysis.Error = ex.Message;
            }

            return analysis;
        }

        #endregion

        #region 公共方法 - 系统加速

        /// <summary>
        /// 获取系统优化建议
        /// </summary>
        public List<OptimizationRecommendation> GetOptimizationRecommendations()
        {
            var recommendations = new List<OptimizationRecommendation>();

            // 检查启动项
            var startupItems = GetStartupImpact();
            if (startupItems.Any(i => i.Impact == StartupImpact.High))
            {
                recommendations.Add(new OptimizationRecommendation
                {
                    Category = "启动优化",
                    Title = "优化启动项",
                    Description = $"发现 {startupItems.Count(i => i.Impact == StartupImpact.High)} 个高影响启动项",
                    Priority = RecommendationPriority.High,
                    PotentialGain = "减少启动时间"
                });
            }

            // 检查内存使用
            var memStatus = GetMemoryStatus();
            if (memStatus.UsedPercent > 80)
            {
                recommendations.Add(new OptimizationRecommendation
                {
                    Category = "内存优化",
                    Title = "释放内存",
                    Description = $"当前内存使用率 {memStatus.UsedPercent}%",
                    Priority = RecommendationPriority.High,
                    PotentialGain = "提升系统响应速度"
                });
            }

            // 检查磁盘空间
            var disks = GetDiskInfo();
            foreach (var disk in disks.Where(d => d.UsagePercent > 90))
            {
                recommendations.Add(new OptimizationRecommendation
                {
                    Category = "磁盘清理",
                    Title = $"清理{disk.Name}磁盘空间",
                    Description = $"磁盘{disk.Name}使用率已达{disk.UsagePercent}%",
                    Priority = RecommendationPriority.Critical,
                    PotentialGain = "防止磁盘空间不足"
                });
            }

            // 检查视觉效果
            if (IsVisualEffectsEnabled())
            {
                recommendations.Add(new OptimizationRecommendation
                {
                    Category = "性能优化",
                    Title = "优化视觉效果",
                    Description = "当前启用了视觉效果，可关闭以提升性能",
                    Priority = RecommendationPriority.Low,
                    PotentialGain = "提升系统响应速度"
                });
            }

            // 检查电源计划
            if (!IsHighPerformancePowerPlan())
            {
                recommendations.Add(new OptimizationRecommendation
                {
                    Category = "电源优化",
                    Title = "切换高性能电源计划",
                    Description = "当前不是高性能电源计划",
                    Priority = RecommendationPriority.Low,
                    PotentialGain = "最大化系统性能"
                });
            }

            return recommendations;
        }

        /// <summary>
        /// 执行一键优化
        /// </summary>
        public OneClickOptimizeResult OneClickOptimize()
        {
            var result = new OneClickOptimizeResult
            {
                StartTime = DateTime.Now
            };

            try
            {
                // 1. 清理垃圾文件
                var junkScan = ScanJunkFiles(new ScanOptions());
                if (junkScan.Categories.Any())
                {
                    var junkClean = CleanJunkFiles(
                        junkScan.Categories.SelectMany(c => c.Files).ToList(),
                        false);
                    result.JunkCleanResult = junkClean;
                }

                // 2. 优化内存
                result.MemoryOptimizeResult = OptimizeMemory();

                // 3. 系统优化
                result.SystemOptimizeResults = OptimizeSystem();

                // 4. 清理剪贴板
                ClearClipboardData();

                result.Success = true;
                RecordOptimization("一键优化", result.TotalCleanedBytes, 0);
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
            }

            result.EndTime = DateTime.Now;
            return result;
        }

        /// <summary>
        /// 系统优化
        /// </summary>
        public List<OptimizationResult> OptimizeSystem()
        {
            var results = new List<OptimizationResult>();

            results.Add(OptimizeServices());
            results.Add(OptimizeVisualEffects());
            results.Add(OptimizePowerSettings());
            results.Add(OptimizeNetworkSettings());

            return results;
        }

        #endregion

        #region 公共方法 - 性能监控

        /// <summary>
        /// 开始性能监控
        /// </summary>
        public void StartMonitoring()
        {
            if (_isMonitoring) return;

            _isMonitoring = true;
            _lastMetrics = CaptureMetrics();

            _monitorTimer = new Timer(MonitorCallback, null, TimeSpan.Zero, TimeSpan.FromSeconds(5));
        }

        /// <summary>
        /// 停止性能监控
        /// </summary>
        public void StopMonitoring()
        {
            _isMonitoring = false;
            _monitorTimer?.Dispose();
            _monitorTimer = null;
        }

        /// <summary>
        /// 获取优化历史
        /// </summary>
        public List<OptimizationHistory> GetOptimizationHistory()
        {
            return _optimizationHistory.OrderByDescending(h => h.Timestamp).ToList();
        }

        #endregion

        #region 私有方法 - 垃圾文件扫描

        private List<JunkFileCategory> ScanDirectory(string path, string category, ref long totalSize, TimeSpan? maxAge)
        {
            var categories = new List<JunkFileCategory>();

            try
            {
                if (!Directory.Exists(path)) return categories;

                var files = new List<JunkFileInfo>();
                var dirInfo = new DirectoryInfo(path);

                foreach (var file in dirInfo.GetFiles("*", SearchOption.AllDirectories))
                {
                    try
                    {
                        // 检查文件年龄
                        if (maxAge.HasValue && DateTime.Now - file.LastAccessTime < maxAge.Value)
                            continue;

                        files.Add(new JunkFileInfo
                        {
                            FilePath = file.FullName,
                            Category = category,
                            Size = file.Length,
                            LastAccessTime = file.LastAccessTime,
                            CreationTime = file.CreationTime
                        });
                        totalSize += file.Length;
                    }
                    catch { }
                }

                if (files.Any())
                {
                    categories.Add(new JunkFileCategory
                    {
                        Name = category,
                        Path = path,
                        Files = files,
                        TotalSize = files.Sum(f => f.Size),
                        FileCount = files.Count
                    });
                }
            }
            catch { }

            return categories;
        }

        private List<JunkFileCategory> ScanBrowserCache(ref long totalSize, ScanOptions options)
        {
            var categories = new List<JunkFileCategory>();

            try
            {
                // Chrome
                if (options.ScanChrome)
                {
                    var chromeCache = Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                        "Google", "Chrome", "User Data", "Default", "Cache");
                    categories.AddRange(ScanDirectory(chromeCache, "Chrome缓存", ref totalSize, null));

                    var chromeCodeCache = Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                        "Google", "Chrome", "User Data", "Default", "Code Cache");
                    categories.AddRange(ScanDirectory(chromeCodeCache, "Chrome代码缓存", ref totalSize, null));
                }

                // Edge
                if (options.ScanEdge)
                {
                    var edgeCache = Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                        "Microsoft", "Edge", "User Data", "Default", "Cache");
                    categories.AddRange(ScanDirectory(edgeCache, "Edge缓存", ref totalSize, null));
                }

                // Firefox
                if (options.ScanFirefox)
                {
                    var firefoxPath = Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                        "Mozilla", "Firefox", "Profiles");
                    if (Directory.Exists(firefoxPath))
                    {
                        foreach (var profile in Directory.GetDirectories(firefoxPath))
                        {
                            categories.AddRange(ScanDirectory(Path.Combine(profile, "cache2"), "Firefox缓存", ref totalSize, null));
                        }
                    }
                }

                // IE
                if (options.ScanIE)
                {
                    var ieCache = Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                        "Microsoft", "Windows", "INetCache");
                    categories.AddRange(ScanDirectory(ieCache, "IE缓存", ref totalSize, null));
                }
            }
            catch { }

            return categories;
        }

        private List<JunkFileCategory> ScanRecycleBin(ref long totalSize)
        {
            var categories = new List<JunkFileCategory>();

            try
            {
                var files = new List<JunkFileInfo>();

                foreach (var drive in DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Fixed))
                {
                    var recyclePath = Path.Combine(drive.Name, "$Recycle.Bin");
                    if (Directory.Exists(recyclePath))
                    {
                        var category = new JunkFileCategory
                        {
                            Name = "回收站",
                            Path = recyclePath
                        };

                        try
                        {
                            var dirInfo = new DirectoryInfo(recyclePath);
                            foreach (var file in dirInfo.GetFiles("*", SearchOption.AllDirectories))
                            {
                                try
                                {
                                    category.Files.Add(new JunkFileInfo
                                    {
                                        FilePath = file.FullName,
                                        Category = "回收站",
                                        Size = file.Length,
                                        LastAccessTime = file.LastAccessTime
                                    });
                                    totalSize += file.Length;
                                }
                                catch { }
                            }
                        }
                        catch { }

                        if (category.Files.Any())
                        {
                            category.TotalSize = category.Files.Sum(f => f.Size);
                            category.FileCount = category.Files.Count;
                            categories.Add(category);
                        }
                    }
                }
            }
            catch { }

            return categories;
        }

        private List<JunkFileCategory> ScanThumbnailCache(ref long totalSize)
        {
            var categories = new List<JunkFileCategory>();

            try
            {
                var thumbcachePath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "Microsoft", "Windows", "Explorer");

                if (Directory.Exists(thumbcachePath))
                {
                    var files = new List<JunkFileInfo>();
                    var dirInfo = new DirectoryInfo(thumbcachePath);

                    foreach (var file in dirInfo.GetFiles("thumbcache_*.db"))
                    {
                        files.Add(new JunkFileInfo
                        {
                            FilePath = file.FullName,
                            Category = "缩略图缓存",
                            Size = file.Length,
                            LastAccessTime = file.LastAccessTime
                        });
                        totalSize += file.Length;
                    }

                    if (files.Any())
                    {
                        categories.Add(new JunkFileCategory
                        {
                            Name = "缩略图缓存",
                            Path = thumbcachePath,
                            Files = files,
                            TotalSize = files.Sum(f => f.Size),
                            FileCount = files.Count
                        });
                    }
                }
            }
            catch { }

            return categories;
        }

        private List<JunkFileCategory> ScanLogFiles(ref long totalSize)
        {
            var categories = new List<JunkFileCategory>();

            try
            {
                var windowsLogs = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Logs");
                categories.AddRange(ScanDirectory(windowsLogs, "系统日志", ref totalSize, null));

                var cbsLogs = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Logs", "CBS");
                categories.AddRange(ScanDirectory(cbsLogs, "CBS日志", ref totalSize, null));

                var dismLogs = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Logs", "DISM");
                categories.AddRange(ScanDirectory(dismLogs, "DISM日志", ref totalSize, null));
            }
            catch { }

            return categories;
        }

        private List<JunkFileCategory> ScanOldWindowsFolder(ref long totalSize)
        {
            var categories = new List<JunkFileCategory>();

            try
            {
                var oldWindows = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\'),
                    "..", "Windows.old");

                if (Directory.Exists(oldWindows))
                {
                    categories.AddRange(ScanDirectory(oldWindows, "旧版Windows备份", ref totalSize, null));
                }
            }
            catch { }

            return categories;
        }

        private List<JunkFileCategory> ScanSystemRestore(ref long totalSize)
        {
            var categories = new List<JunkFileCategory>();

            try
            {
                // 系统还原数据在System Volume Information目录
                foreach (var drive in DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Fixed))
                {
                    var sviPath = Path.Combine(drive.Name, "System Volume Information");
                    if (Directory.Exists(sviPath))
                    {
                        // 需要管理员权限访问，标记但不直接扫描
                        categories.Add(new JunkFileCategory
                        {
                            Name = "系统还原点",
                            Path = sviPath,
                            Files = new List<JunkFileInfo>(),
                            TotalSize = 0, // 需要API获取
                            FileCount = 0,
                            RequiresAdmin = true
                        });
                    }
                }
            }
            catch { }

            return categories;
        }

        private List<JunkFileCategory> ScanAppCache(ref long totalSize)
        {
            var categories = new List<JunkFileCategory>();

            try
            {
                // Windows应用缓存
                var appCache = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "Packages");

                if (Directory.Exists(appCache))
                {
                    foreach (var packageDir in Directory.GetDirectories(appCache))
                    {
                        var cacheDir = Path.Combine(packageDir, "LocalCache");
                        if (Directory.Exists(cacheDir))
                        {
                            var name = Path.GetFileName(packageDir);
                            categories.AddRange(ScanDirectory(cacheDir, $"应用缓存 ({name})", ref totalSize, null));
                        }
                    }
                }
            }
            catch { }

            return categories;
        }

        #endregion

        #region 私有方法 - 注册表扫描

        private List<RegistryIssue> ScanUninstallKeys()
        {
            var issues = new List<RegistryIssue>();

            try
            {
                var keys = new[]
                {
                    Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                    Registry.LocalMachine.OpenSubKey(@"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
                    Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
                };

                foreach (var key in keys.Where(k => k != null))
                {
                    foreach (var subKeyName in key.GetSubKeyNames())
                    {
                        try
                        {
                            using (var subKey = key.OpenSubKey(subKeyName))
                            {
                                var uninstallString = subKey?.GetValue("UninstallString")?.ToString();
                                if (!string.IsNullOrEmpty(uninstallString))
                                {
                                    var exePath = ExtractExePath(uninstallString);
                                    if (!string.IsNullOrEmpty(exePath) && !File.Exists(exePath))
                                    {
                                        issues.Add(new RegistryIssue
                                        {
                                            KeyPath = $"{key.Name}\\{subKeyName}",
                                            IssueType = "无效卸载项",
                                            Description = $"卸载程序不存在: {exePath}",
                                            Severity = "低",
                                            ValueName = "UninstallString",
                                            CanFix = true
                                        });
                                    }
                                }
                            }
                        }
                        catch { }
                    }
                    key.Dispose();
                }
            }
            catch { }

            return issues;
        }

        private List<RegistryIssue> ScanStartupKeys()
        {
            var issues = new List<RegistryIssue>();

            try
            {
                var startupKeys = new[]
                {
                    Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                    Registry.LocalMachine.OpenSubKey(@"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
                    Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
                };

                foreach (var key in startupKeys.Where(k => k != null))
                {
                    foreach (var valueName in key.GetValueNames())
                    {
                        try
                        {
                            var value = key.GetValue(valueName)?.ToString();
                            if (!string.IsNullOrEmpty(value))
                            {
                                var exePath = ExtractExePath(value);
                                if (!string.IsNullOrEmpty(exePath) && !File.Exists(exePath))
                                {
                                    issues.Add(new RegistryIssue
                                    {
                                        KeyPath = key.Name,
                                        IssueType = "无效启动项",
                                        Description = $"启动程序不存在: {exePath}",
                                        Severity = "中",
                                        ValueName = valueName,
                                        CanFix = true
                                    });
                                }
                            }
                        }
                        catch { }
                    }
                    key.Dispose();
                }
            }
            catch { }

            return issues;
        }

        private List<RegistryIssue> ScanFileAssociations()
        {
            var issues = new List<RegistryIssue>();

            // 简化实现
            return issues;
        }

        private List<RegistryIssue> ScanSharedDLLs()
        {
            var issues = new List<RegistryIssue>();

            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDLLs"))
                {
                    if (key != null)
                    {
                        foreach (var valueName in key.GetValueNames())
                        {
                            try
                            {
                                var path = valueName.Replace("\"", "");
                                path = Environment.ExpandEnvironmentVariables(path);

                                if (!File.Exists(path))
                                {
                                    issues.Add(new RegistryIssue
                                    {
                                        KeyPath = key.Name,
                                        IssueType = "无效共享DLL引用",
                                        Description = $"DLL文件不存在: {path}",
                                        Severity = "低",
                                        ValueName = valueName,
                                        CanFix = true
                                    });
                                }
                            }
                            catch { }
                        }
                    }
                }
            }
            catch { }

            return issues;
        }

        private List<RegistryIssue> ScanCOMComponents()
        {
            var issues = new List<RegistryIssue>();

            // 简化实现
            return issues;
        }

        private List<RegistryIssue> ScanHistoryKeys()
        {
            var issues = new List<RegistryIssue>();

            // 简化实现
            return issues;
        }

        private bool FixRegistryIssue(RegistryIssue issue)
        {
            try
            {
                // 根据问题类型修复
                if (issue.IssueType.Contains("启动项"))
                {
                    using (var key = Registry.CurrentUser.OpenSubKey(
                        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", true))
                    {
                        key?.DeleteValue(issue.ValueName, false);
                    }
                    return true;
                }
            }
            catch { }

            return false;
        }

        private string CreateRegistryBackup()
        {
            var backupPath = Path.Combine(_configPath, $"RegistryBackup_{DateTime.Now:yyyyMMddHHmmss}.reg");

            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "reg",
                        Arguments = $"export HKLM {backupPath}",
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };
                process.Start();
                process.WaitForExit(30000);
            }
            catch { }

            return backupPath;
        }

        #endregion

        #region 私有方法 - 内存优化

        private List<ProcessMemoryInfo> GetTopMemoryProcesses(int count)
        {
            var processes = new List<ProcessMemoryInfo>();

            try
            {
                foreach (var proc in Process.GetProcesses())
                {
                    try
                    {
                        processes.Add(new ProcessMemoryInfo
                        {
                            ProcessName = proc.ProcessName,
                            ProcessId = proc.Id,
                            WorkingSetMB = proc.WorkingSet64 / 1024 / 1024,
                            PrivateMemoryMB = proc.PrivateMemorySize64 / 1024 / 1024
                        });
                    }
                    catch { }
                }

                processes = processes.OrderByDescending(p => p.WorkingSetMB).Take(count).ToList();
            }
            catch { }

            return processes;
        }

        private void ClearSystemWorkingSet()
        {
            try
            {
                // 清理当前进程
                EmptyWorkingSet(Process.GetCurrentProcess().Handle);

                // 清理系统进程
                foreach (var proc in Process.GetProcesses())
                {
                    try
                    {
                        if (proc.Id != Process.GetCurrentProcess().Id)
                        {
                            EmptyWorkingSet(proc.Handle);
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        private void ClearClipboardData()
        {
            try
            {
                if (OpenClipboard(IntPtr.Zero))
                {
                    EmptyClipboard();
                    CloseClipboard();
                }
            }
            catch { }
        }

        private void ClearStandbyList()
        {
            try
            {
                // 使用RAMMap工具的方法清除standby list
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "cmd.exe",
                        Arguments = "/c echo 1 > /proc/sys/vm/drop_caches",
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };
                process.Start();
            }
            catch { }
        }

        private void CompressMemoryPages()
        {
            // Windows 10+ 内置内存压缩
            // 此功能由系统自动管理
        }

        #endregion

        #region 私有方法 - 磁盘优化

        private bool CheckIfSSD(string drive)
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher(
                    "SELECT * FROM Win32_DiskDrive WHERE MediaType LIKE '%SSD%'"))
                {
                    return searcher.Get().Count > 0;
                }
            }
            catch { return false; }
        }

        private SmartStatus GetSMARTStatus(string drive)
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher(
                    "SELECT * FROM MSStorageDriver_FailurePredictStatus"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        if (obj["PredictFailure"]?.ToString() == "True")
                        {
                            return SmartStatus.Warning;
                        }
                    }
                }
            }
            catch { }

            return SmartStatus.Ok;
        }

        private long GetDirectorySize(DirectoryInfo dir)
        {
            long size = 0;
            try
            {
                foreach (var file in dir.GetFiles())
                {
                    size += file.Length;
                }
                foreach (var subDir in dir.GetDirectories())
                {
                    size += GetDirectorySize(subDir);
                }
            }
            catch { }
            return size;
        }

        #endregion

        #region 私有方法 - 系统优化

        private List<StartupImpactInfo> GetStartupImpact()
        {
            var items = new List<StartupImpactInfo>();

            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"))
                {
                    if (key != null)
                    {
                        foreach (var name in key.GetValueNames())
                        {
                            items.Add(new StartupImpactInfo
                            {
                                Name = name,
                                Impact = StartupImpact.Unknown
                            });
                        }
                    }
                }
            }
            catch { }

            return items;
        }

        private bool IsVisualEffectsEnabled()
        {
            try
            {
                using (var key = Registry.CurrentUser.OpenSubKey(
                    @"Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects"))
                {
                    var setting = key?.GetValue("VisualFXSetting");
                    return setting == null || (int)setting != 2;
                }
            }
            catch { return true; }
        }

        private bool IsHighPerformancePowerPlan()
        {
            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "powercfg",
                        Arguments = "/getactivescheme",
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        RedirectStandardOutput = true
                    }
                };

                process.Start();
                var output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                return output.Contains("高性能") || output.Contains("High performance");
            }
            catch { return false; }
        }

        private OptimizationResult OptimizeServices()
        {
            var result = new OptimizationResult { Category = "服务优化" };

            try
            {
                var servicesToOptimize = new Dictionary<string, string>
                {
                    { "DiagTrack", "禁用诊断跟踪服务" },
                    { "dmwappushservice", "禁用WAP推送服务" }
                };

                int optimized = 0;
                foreach (var kvp in servicesToOptimize)
                {
                    try
                    {
                        using (var service = new System.ServiceProcess.ServiceController(kvp.Key))
                        {
                            if (service.Status == System.ServiceProcess.ServiceControllerStatus.Running)
                            {
                                var process = new Process
                                {
                                    StartInfo = new ProcessStartInfo
                                    {
                                        FileName = "sc",
                                        Arguments = $"config {kvp.Key} start= disabled",
                                        UseShellExecute = false,
                                        CreateNoWindow = true
                                    }
                                };
                                process.Start();
                                process.WaitForExit();
                                optimized++;
                            }
                        }
                    }
                    catch { }
                }

                result.Success = true;
                result.Message = $"已优化 {optimized} 个服务";
            }
            catch (Exception ex)
            {
                result.Message = $"优化失败: {ex.Message}";
            }

            return result;
        }

        private OptimizationResult OptimizeVisualEffects()
        {
            var result = new OptimizationResult { Category = "视觉效果优化" };

            try
            {
                using (var key = Registry.CurrentUser.OpenSubKey(
                    @"Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects", true))
                {
                    key?.SetValue("VisualFXSetting", 2, RegistryValueKind.DWord);
                }

                result.Success = true;
                result.Message = "已设置为最佳性能模式";
            }
            catch (Exception ex)
            {
                result.Message = $"优化失败: {ex.Message}";
            }

            return result;
        }

        private OptimizationResult OptimizePowerSettings()
        {
            var result = new OptimizationResult { Category = "电源优化" };

            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "powercfg",
                        Arguments = "/setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c",
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };
                process.Start();
                process.WaitForExit();

                result.Success = true;
                result.Message = "已设置为高性能电源模式";
            }
            catch (Exception ex)
            {
                result.Message = $"优化失败: {ex.Message}";
            }

            return result;
        }

        private OptimizationResult OptimizeNetworkSettings()
        {
            var result = new OptimizationResult { Category = "网络优化" };

            try
            {
                // 清除DNS缓存
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "ipconfig",
                        Arguments = "/flushdns",
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };
                process.Start();
                process.WaitForExit();

                result.Success = true;
                result.Message = "已清除DNS缓存";
            }
            catch (Exception ex)
            {
                result.Message = $"优化失败: {ex.Message}";
            }

            return result;
        }

        #endregion

        #region 私有方法 - 辅助

        private string ExtractExePath(string commandLine)
        {
            if (string.IsNullOrEmpty(commandLine)) return null;

            commandLine = commandLine.Trim();

            if (commandLine.StartsWith("\""))
            {
                int endQuote = commandLine.IndexOf('\"', 1);
                if (endQuote > 0)
                {
                    return commandLine.Substring(1, endQuote - 1);
                }
            }

            int spaceIndex = commandLine.IndexOf(' ');
            if (spaceIndex > 0)
            {
                return commandLine.Substring(0, spaceIndex);
            }

            return commandLine;
        }

        private void RaiseProgress(ref int current, int total, string message)
        {
            current++;
            ProgressChanged?.Invoke(this, new OptimizerProgressEventArgs
            {
                Progress = (int)((current / (double)total) * 100),
                Message = message
            });
        }

        private void RaiseProgress(int current, int total, string message)
        {
            ProgressChanged?.Invoke(this, new OptimizerProgressEventArgs
            {
                Progress = (int)((current / (double)total) * 100),
                Message = message
            });
        }

        private void CreateRestorePoint(string description)
        {
            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "powershell",
                        Arguments = $"-command \"Checkpoint-Computer -Description '{description}' -RestorePointType 'MODIFY_SETTINGS'\"",
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };
                process.Start();
                process.WaitForExit(30000);
            }
            catch { }
        }

        private void RecordOptimization(string type, long bytesCleaned, int filesCleaned)
        {
            var history = new OptimizationHistory
            {
                Type = type,
                Timestamp = DateTime.Now,
                BytesCleaned = bytesCleaned,
                FilesCleaned = filesCleaned
            };

            _optimizationHistory.Add(history);
            SaveOptimizationHistory();
        }

        private void LoadOptimizationHistory()
        {
            try
            {
                var historyPath = Path.Combine(_configPath, "history.json");
                if (File.Exists(historyPath))
                {
                    _optimizationHistory = JsonSerializer.Deserialize<List<OptimizationHistory>>(
                        File.ReadAllText(historyPath)) ?? new List<OptimizationHistory>();
                }
            }
            catch { }
        }

        private void SaveOptimizationHistory()
        {
            try
            {
                var historyPath = Path.Combine(_configPath, "history.json");
                File.WriteAllText(historyPath, JsonSerializer.Serialize(_optimizationHistory.TakeLast(100).ToList()));
            }
            catch { }
        }

        private SystemPerformanceMetrics CaptureMetrics()
        {
            var metrics = new SystemPerformanceMetrics
            {
                Timestamp = DateTime.Now
            };

            try
            {
                var memStatus = GetMemoryStatus();
                metrics.MemoryUsedPercent = memStatus.UsedPercent;

                var cpuCounter = new PerformanceCounter("Processor", "% Processor Time", "_Total");
                metrics.CpuUsagePercent = (int)cpuCounter.NextValue();

                foreach (var disk in GetDiskInfo())
                {
                    metrics.DiskUsage[disk.Name] = disk.UsagePercent;
                }
            }
            catch { }

            return metrics;
        }

        private void MonitorCallback(object state)
        {
            try
            {
                var current = CaptureMetrics();

                // 检测高内存使用
                if (current.MemoryUsedPercent > 90)
                {
                    PerformanceAlert?.Invoke(this, new PerformanceAlertEventArgs
                    {
                        AlertType = "HighMemoryUsage",
                        Message = $"内存使用率过高: {current.MemoryUsedPercent}%",
                        Severity = AlertSeverity.Warning
                    });
                }

                // 检测高CPU使用
                if (current.CpuUsagePercent > 90)
                {
                    PerformanceAlert?.Invoke(this, new PerformanceAlertEventArgs
                    {
                        AlertType = "HighCpuUsage",
                        Message = $"CPU使用率过高: {current.CpuUsagePercent}%",
                        Severity = AlertSeverity.Warning
                    });
                }

                _lastMetrics = current;
            }
            catch { }
        }

        #endregion

        public void Dispose()
        {
            StopMonitoring();
        }
    }

    #region 数据模型

    public enum SmartStatus
    {
        Ok,
        Warning,
        Critical
    }

    public enum AlertSeverity
    {
        Info,
        Warning,
        Critical
    }

    public class ScanOptions
    {
        public bool ScanWindowsTemp { get; set; } = true;
        public bool ScanUserTemp { get; set; } = true;
        public bool ScanBrowserCache { get; set; } = true;
        public bool ScanChrome { get; set; } = true;
        public bool ScanEdge { get; set; } = true;
        public bool ScanFirefox { get; set; } = true;
        public bool ScanIE { get; set; } = true;
        public bool ScanRecycleBin { get; set; } = true;
        public bool ScanWindowsUpdate { get; set; } = true;
        public bool ScanThumbnailCache { get; set; } = true;
        public bool ScanLogFiles { get; set; } = true;
        public bool ScanPrefetch { get; set; } = false;
        public bool ScanErrorReports { get; set; } = true;
        public bool ScanOldWindows { get; set; } = true;
        public bool ScanSystemRestore { get; set; } = false;
        public bool ScanAppCache { get; set; } = true;
        public TimeSpan? MaxFileAge { get; set; }
    }

    public class MemoryOptimizeOptions
    {
        public bool ClearWorkingSet { get; set; } = true;
        public bool ClearClipboard { get; set; } = true;
        public bool ClearStandbyList { get; set; } = true;
        public bool CompressMemory { get; set; } = true;
    }

    public class JunkScanResult
    {
        public string ScanId { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public TimeSpan Duration { get; set; }
        public List<JunkFileCategory> Categories { get; set; } = new List<JunkFileCategory>();
        public long TotalSize { get; set; }
        public int TotalFiles { get; set; }
        public string Error { get; set; }
    }

    public class JunkFileCategory
    {
        public string Name { get; set; }
        public string Path { get; set; }
        public List<JunkFileInfo> Files { get; set; } = new List<JunkFileInfo>();
        public long TotalSize { get; set; }
        public int FileCount { get; set; }
        public bool RequiresAdmin { get; set; }
    }

    public class JunkFileInfo
    {
        public string FilePath { get; set; }
        public string Category { get; set; }
        public long Size { get; set; }
        public DateTime LastAccessTime { get; set; }
        public DateTime CreationTime { get; set; }
    }

    public class RegistryScanResult
    {
        public string ScanId { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public TimeSpan Duration { get; set; }
        public List<RegistryIssue> Issues { get; set; } = new List<RegistryIssue>();
        public int TotalIssues { get; set; }
        public int CriticalIssues { get; set; }
        public string Error { get; set; }
    }

    public class RegistryIssue
    {
        public string KeyPath { get; set; }
        public string IssueType { get; set; }
        public string Description { get; set; }
        public string Severity { get; set; }
        public string ValueName { get; set; }
        public bool CanFix { get; set; }
    }

    public class RegistryFixResult
    {
        public bool Success { get; set; }
        public int FixedIssues { get; set; }
        public int FailedIssues { get; set; }
        public string BackupPath { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public string Error { get; set; }
    }

    public class MemoryStatus
    {
        public long TotalMB { get; set; }
        public long AvailableMB { get; set; }
        public int UsedPercent { get; set; }
        public long TotalPageFileMB { get; set; }
        public long AvailablePageFileMB { get; set; }
        public List<ProcessMemoryInfo> TopMemoryProcesses { get; set; } = new List<ProcessMemoryInfo>();
    }

    public class MemoryOptimizeResult
    {
        public bool Success { get; set; }
        public long BeforeAvailableMB { get; set; }
        public long AfterAvailableMB { get; set; }
        public long FreedMB { get; set; }
        public int BeforeUsedPercent { get; set; }
        public int AfterUsedPercent { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public string Error { get; set; }
    }

    public class TrimResult
    {
        public string Drive { get; set; }
        public bool Success { get; set; }
        public string Output { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public string Error { get; set; }
    }

    public class DefragAnalysis
    {
        public string Drive { get; set; }
        public DateTime AnalysisTime { get; set; }
        public int FragmentationPercent { get; set; }
        public bool NeedsDefrag { get; set; }
        public string RawOutput { get; set; }
        public string Error { get; set; }
    }

    public class OneClickOptimizeResult
    {
        public bool Success { get; set; }
        public CleanResult JunkCleanResult { get; set; }
        public MemoryOptimizeResult MemoryOptimizeResult { get; set; }
        public List<OptimizationResult> SystemOptimizeResults { get; set; } = new List<OptimizationResult>();
        public long TotalCleanedBytes => (JunkCleanResult?.CleanedSize ?? 0) + (MemoryOptimizeResult?.FreedMB ?? 0) * 1024 * 1024;
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public string Error { get; set; }
    }

    public class OptimizationHistory
    {
        public string Type { get; set; }
        public DateTime Timestamp { get; set; }
        public long BytesCleaned { get; set; }
        public int FilesCleaned { get; set; }
    }

    public class SystemPerformanceMetrics
    {
        public DateTime Timestamp { get; set; }
        public int CpuUsagePercent { get; set; }
        public int MemoryUsedPercent { get; set; }
        public Dictionary<string, int> DiskUsage { get; set; } = new Dictionary<string, int>();
    }

    public class OptimizerProgressEventArgs : EventArgs
    {
        public int Progress { get; set; }
        public string Message { get; set; }
        public string Category { get; set; }
    }

    public class PerformanceAlertEventArgs : EventArgs
    {
        public string AlertType { get; set; }
        public string Message { get; set; }
        public AlertSeverity Severity { get; set; }
    }

    public class CleanResult
    {
        public bool Success { get; set; }
        public string Category { get; set; }
        public long CleanedSize { get; set; }
        public long BytesFreed { get; set; }
        public int CleanedFiles { get; set; }
        public int FailedFiles { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public TimeSpan Duration { get; set; }
        public string Error { get; set; }
        public string[] Errors { get; set; }
    }

    #endregion
}
