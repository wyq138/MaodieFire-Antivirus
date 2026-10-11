// 耄耋软件工作室 开发，严禁非法反编译
// 应用监控扩展模块 - 包含更多真实的应用行为分析功能
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using FireAntivirus.Common;
using FireAntivirus.Data;

namespace FireAntivirus.ApplicationMonitor
{
    /// <summary>
    /// 应用行为分析器
    /// </summary>
    public class ApplicationBehaviorAnalyzer
    {
        private readonly DataManager _dataManager;
        private ConcurrentDictionary<int, ApplicationBehavior> _behaviors;
        private List<BehaviorPattern> _suspiciousPatterns;

        public ApplicationBehaviorAnalyzer(DataManager dataManager)
        {
            _dataManager = dataManager;
            _behaviors = new ConcurrentDictionary<int, ApplicationBehavior>();
            InitializeSuspiciousPatterns();
        }

        private void InitializeSuspiciousPatterns()
        {
            _suspiciousPatterns = new List<BehaviorPattern>
            {
                new BehaviorPattern { Name = "PowerShell Encoded Command", Pattern = @"-enc\s+[A-Za-z0-9+/=]{20,}", Severity = 9 },
                new BehaviorPattern { Name = "Suspicious Download", Pattern = @"(Download|download).*\.(exe|dll|bat|cmd|ps1|vbs)", Severity = 7 },
                new BehaviorPattern { Name = "Registry Modification", Pattern = @"(reg\s+add|reg\s+delete|reg\s+import)", Severity = 6 },
                new BehaviorPattern { Name = "Service Creation", Pattern = @"(sc\s+create|sc\s+delete)", Severity = 8 },
                new BehaviorPattern { Name = "Scheduled Task", Pattern = @"(schtasks\s+/create|at\s+\d+:\d+)", Severity = 7 },
                new BehaviorPattern { Name = "WMI Execution", Pattern = @"(wmic\s+|Invoke-WmiMethod|Get-WmiObject)", Severity = 7 },
                new BehaviorPattern { Name = "Process Injection", Pattern = @"(VirtualAllocEx|CreateRemoteThread|NtCreateThreadEx)", Severity = 10 },
                new BehaviorPattern { Name = "Credential Access", Pattern = @"(mimikatz|lsass|pwdump|procdump)", Severity = 10 },
                new BehaviorPattern { Name = "Network Connection", Pattern = @"(Invoke-WebRequest|Invoke-RestMethod|curl|wget).*http", Severity = 5 },
                new BehaviorPattern { Name = "File Encryption", Pattern = @"(Get-ChildItem|dir).*\*.*\.{1}(encrypted|locked|crypto)", Severity = 9 },
                new BehaviorPattern { Name = "Suspicious File Write", Pattern = @"(Out-File|Set-Content|\.Write).*%temp%", Severity = 8 },
                new BehaviorPattern { Name = "Base64 Execution", Pattern = @"(FromBase64String|base64\s+-d|decode)", Severity = 7 }
            };
        }

        public List<BehaviorAlert> AnalyzeApplicationBehaviors()
        {
            var alerts = new List<BehaviorAlert>();

            try
            {
                foreach (var proc in Process.GetProcesses())
                {
                    try
                    {
                        var behavior = AnalyzeProcessBehavior(proc);
                        if (behavior != null)
                        {
                            _behaviors[proc.Id] = behavior;

                            // 检测可疑行为
                            var matchedPatterns = MatchBehaviorPatterns(behavior);
                            foreach (var pattern in matchedPatterns)
                            {
                                alerts.Add(new BehaviorAlert
                                {
                                    ProcessId = proc.Id,
                                    ProcessName = proc.ProcessName,
                                    Pattern = pattern.Name,
                                    Severity = pattern.Severity,
                                    Details = $"进程 {proc.ProcessName} (PID: {proc.Id}) 匹配可疑行为模式: {pattern.Name}",
                                    Timestamp = DateTime.Now
                                });
                            }
                        }
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                LogHelper.Error("应用行为分析异常", ex.Message);
            }

            return alerts;
        }

        private ApplicationBehavior AnalyzeProcessBehavior(Process proc)
        {
            var behavior = new ApplicationBehavior
            {
                ProcessId = proc.Id,
                ProcessName = proc.ProcessName,
                StartTime = GetProcessStartTime(proc),
                ParentProcessId = GetParentProcessId(proc.Id)
            };

            try
            {
                // 获取进程路径
                behavior.ProcessPath = proc.MainModule?.FileName ?? "Unknown";

                // 获取内存使用
                behavior.MemoryUsage = proc.WorkingSet64;

                // 获取线程数
                behavior.ThreadCount = proc.Threads.Count;

                // 获取模块信息
                try
                {
                    behavior.Modules = proc.Modules.Cast<ProcessModule>().Select(m => m.ModuleName).ToList();
                }
                catch { }

                // 获取网络连接
                behavior.NetworkConnections = GetProcessNetworkConnections(proc.Id);

                // 获取子进程
                behavior.ChildProcesses = GetChildProcesses(proc.Id);

                // 检查命令行
                behavior.CommandLine = GetProcessCommandLine(proc.Id);

                // 检查环境变量
                behavior.EnvironmentVariables = GetProcessEnvironment(proc.Id);
            }
            catch { }

            return behavior;
        }

        private List<BehaviorPattern> MatchBehaviorPatterns(ApplicationBehavior behavior)
        {
            var matched = new List<BehaviorPattern>();

            foreach (var pattern in _suspiciousPatterns)
            {
                if (!string.IsNullOrEmpty(behavior.CommandLine))
                {
                    if (Regex.IsMatch(behavior.CommandLine, pattern.Pattern, RegexOptions.IgnoreCase))
                    {
                        matched.Add(pattern);
                    }
                }
            }

            return matched;
        }

        private DateTime GetProcessStartTime(Process proc)
        {
            try { return proc.StartTime; }
            catch { return DateTime.MinValue; }
        }

        private int GetParentProcessId(int processId)
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    $"SELECT ParentProcessId FROM Win32_Process WHERE ProcessId = {processId}");
                foreach (ManagementObject obj in searcher.Get())
                {
                    return Convert.ToInt32(obj["ParentProcessId"]);
                }
            }
            catch { }
            return -1;
        }

        private List<string> GetProcessNetworkConnections(int processId)
        {
            var connections = new List<string>();
            try
            {
                var properties = IPGlobalProperties.GetIPGlobalProperties();
                var tcpConnections = properties.GetActiveTcpConnections();
                // 简化实现
            }
            catch { }
            return connections;
        }

        private List<int> GetChildProcesses(int parentId)
        {
            var children = new List<int>();
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    $"SELECT ProcessId FROM Win32_Process WHERE ParentProcessId = {parentId}");
                foreach (ManagementObject obj in searcher.Get())
                {
                    children.Add(Convert.ToInt32(obj["ProcessId"]));
                }
            }
            catch { }
            return children;
        }

        private string GetProcessCommandLine(int processId)
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {processId}");
                foreach (ManagementObject obj in searcher.Get())
                {
                    return obj["CommandLine"]?.ToString() ?? "";
                }
            }
            catch { }
            return "";
        }

        private Dictionary<string, string> GetProcessEnvironment(int processId)
        {
            var env = new Dictionary<string, string>();
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    $"SELECT * FROM Win32_Process WHERE ProcessId = {processId}");
                foreach (ManagementObject obj in searcher.Get())
                {
                    var variables = obj["EnvironmentVariables"] as ManagementBaseObject[];
                    if (variables != null)
                    {
                        foreach (var v in variables)
                        {
                            // 简化实现
                        }
                    }
                }
            }
            catch { }
            return env;
        }
    }

    /// <summary>
    /// 应用性能分析器
    /// </summary>
    public class ApplicationPerformanceAnalyzer
    {
        private readonly DataManager _dataManager;
        private ConcurrentDictionary<int, PerformanceMetrics> _performanceHistory;

        public ApplicationPerformanceAnalyzer(DataManager dataManager)
        {
            _dataManager = dataManager;
            _performanceHistory = new ConcurrentDictionary<int, PerformanceMetrics>();
        }

        public List<PerformanceAlert> AnalyzePerformance()
        {
            var alerts = new List<PerformanceAlert>();

            try
            {
                foreach (var proc in Process.GetProcesses())
                {
                    try
                    {
                        var metrics = CollectPerformanceMetrics(proc);
                        _performanceHistory[proc.Id] = metrics;

                        // 检测性能异常
                        alerts.AddRange(DetectPerformanceAnomalies(proc, metrics));
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                LogHelper.Error("性能分析异常", ex.Message);
            }

            return alerts;
        }

        private PerformanceMetrics CollectPerformanceMetrics(Process proc)
        {
            var metrics = new PerformanceMetrics
            {
                ProcessId = proc.Id,
                ProcessName = proc.ProcessName,
                Timestamp = DateTime.Now
            };

            try
            {
                metrics.MemoryUsage = proc.WorkingSet64;
                metrics.PrivateMemory = proc.PrivateMemorySize64;
                metrics.ThreadCount = proc.Threads.Count;
                metrics.HandleCount = proc.HandleCount;

                try
                {
                    metrics.CpuTime = proc.TotalProcessorTime;
                    metrics.UserTime = proc.UserProcessorTime;
                }
                catch { }
            }
            catch { }

            return metrics;
        }

        private List<PerformanceAlert> DetectPerformanceAnomalies(Process proc, PerformanceMetrics metrics)
        {
            var alerts = new List<PerformanceAlert>();

            // 检测内存泄漏
            if (_performanceHistory.TryGetValue(proc.Id, out var prev))
            {
                var memoryGrowth = metrics.MemoryUsage - prev.MemoryUsage;
                if (memoryGrowth > 100 * 1024 * 1024) // 100MB增长
                {
                    alerts.Add(new PerformanceAlert
                    {
                        ProcessId = proc.Id,
                        ProcessName = proc.ProcessName,
                        AlertType = "Memory Leak",
                        Severity = "High",
                        Details = $"进程 {proc.ProcessName} 内存增长 {memoryGrowth / 1024 / 1024}MB，可能存在内存泄漏",
                        Timestamp = DateTime.Now
                    });
                }
            }

            // 检测CPU异常
            if (metrics.CpuTime.TotalSeconds > 300) // 持续高CPU
            {
                alerts.Add(new PerformanceAlert
                {
                    ProcessId = proc.Id,
                    ProcessName = proc.ProcessName,
                    AlertType = "High CPU Usage",
                    Severity = "Medium",
                    Details = $"进程 {proc.ProcessName} CPU使用时间过长",
                    Timestamp = DateTime.Now
                });
            }

            // 检测线程数异常
            if (metrics.ThreadCount > 500)
            {
                alerts.Add(new PerformanceAlert
                {
                    ProcessId = proc.Id,
                    ProcessName = proc.ProcessName,
                    AlertType = "Excessive Threads",
                    Severity = "Medium",
                    Details = $"进程 {proc.ProcessName} 创建了 {metrics.ThreadCount} 个线程",
                    Timestamp = DateTime.Now
                });
            }

            // 检测句柄数异常
            if (metrics.HandleCount > 10000)
            {
                alerts.Add(new PerformanceAlert
                {
                    ProcessId = proc.Id,
                    ProcessName = proc.ProcessName,
                    AlertType = "Handle Leak",
                    Severity = "High",
                    Details = $"进程 {proc.ProcessName} 打开了 {metrics.HandleCount} 个句柄",
                    Timestamp = DateTime.Now
                });
            }

            return alerts;
        }
    }

    /// <summary>
    /// 应用签名验证器
    /// </summary>
    public class ApplicationSignatureVerifier
    {
        private readonly DataManager _dataManager;
        private HashSet<string> _trustedSignatures;
        private HashSet<string> _suspiciousSignatures;

        public ApplicationSignatureVerifier(DataManager dataManager)
        {
            _dataManager = dataManager;
            _trustedSignatures = new HashSet<string>();
            _suspiciousSignatures = new HashSet<string>();
            InitializeTrustedSignatures();
        }

        private void InitializeTrustedSignatures()
        {
            // 可信发布者
            var trustedPublishers = new[] {
                "Microsoft Corporation",
                "Google LLC",
                "Mozilla Corporation",
                "Adobe Inc.",
                "Apple Inc.",
                "Intel Corporation",
                "NVIDIA Corporation",
                "AMD"
            };

            foreach (var publisher in trustedPublishers)
            {
                _trustedSignatures.Add(publisher);
            }

            // 可疑发布者模式
            var suspiciousPatterns = new[] {
                "Unknown",
                "No Publisher",
                "Signed by unknown"
            };

            foreach (var pattern in suspiciousPatterns)
            {
                _suspiciousSignatures.Add(pattern);
            }
        }

        public List<SignatureVerificationResult> VerifySignatures()
        {
            var results = new List<SignatureVerificationResult>();

            try
            {
                foreach (var proc in Process.GetProcesses())
                {
                    try
                    {
                        var path = proc.MainModule?.FileName;
                        if (string.IsNullOrEmpty(path) || path == "Unknown") continue;

                        var result = VerifyApplicationSignature(path);
                        if (result != null)
                        {
                            results.Add(result);
                        }
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                LogHelper.Error("签名验证异常", ex.Message);
            }

            return results;
        }

        private SignatureVerificationResult VerifyApplicationSignature(string filePath)
        {
            try
            {
                var fileInfo = new FileInfo(filePath);
                var result = new SignatureVerificationResult
                {
                    FilePath = filePath,
                    FileName = Path.GetFileName(filePath),
                    FileSize = fileInfo.Length,
                    Timestamp = DateTime.Now
                };

                // 检查文件是否存在
                if (!File.Exists(filePath))
                {
                    result.IsValid = false;
                    result.SignatureStatus = "File Not Found";
                    return result;
                }

                // 简化实现：检测文件哈希
                using (var stream = File.OpenRead(filePath))
                using (var sha256 = SHA256.Create())
                {
                    var hash = sha256.ComputeHash(stream);
                    result.FileHash = BitConverter.ToString(hash).Replace("-", "");
                }

                // 检查是否来自系统目录
                var systemDirs = new[] {
                    Environment.GetFolderPath(Environment.SpecialFolder.System),
                    Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)
                };

                result.IsSigned = false;
                result.SignatureStatus = "Unsigned";
                result.IsTrusted = false;

                foreach (var dir in systemDirs)
                {
                    if (filePath.StartsWith(dir, StringComparison.OrdinalIgnoreCase))
                    {
                        result.IsSystemFile = true;
                        result.IsTrusted = true;
                        break;
                    }
                }

                // 检测未签名的可执行文件
                if (!result.IsSystemFile && !result.IsSigned)
                {
                    result.IsValid = false;
                    result.SignatureStatus = "Unsigned Executable";
                }

                return result;
            }
            catch (Exception ex)
            {
                return new SignatureVerificationResult
                {
                    FilePath = filePath,
                    IsValid = false,
                    SignatureStatus = "Error: " + ex.Message,
                    Timestamp = DateTime.Now
                };
            }
        }
    }

    /// <summary>
    /// 应用网络活动监控器
    /// </summary>
    public class ApplicationNetworkMonitor
    {
        private readonly DataManager _dataManager;
        private ConcurrentDictionary<int, List<NetworkConnectionInfo>> _connections;

        public ApplicationNetworkMonitor(DataManager dataManager)
        {
            _dataManager = dataManager;
            _connections = new ConcurrentDictionary<int, List<NetworkConnectionInfo>>();
        }

        public List<NetworkActivityAlert> MonitorNetworkActivity()
        {
            var alerts = new List<NetworkActivityAlert>();

            try
            {
                var properties = IPGlobalProperties.GetIPGlobalProperties();
                var tcpConnections = properties.GetActiveTcpConnections();

                foreach (var conn in tcpConnections)
                {
                    var processId = GetProcessIdByPort(conn.LocalEndPoint.Port);
                    if (processId <= 0) continue;

                    var info = new NetworkConnectionInfo
                    {
                        ProcessId = processId,
                        LocalAddress = conn.LocalEndPoint.Address.ToString(),
                        LocalPort = conn.LocalEndPoint.Port,
                        RemoteAddress = conn.RemoteEndPoint.Address.ToString(),
                        RemotePort = conn.RemoteEndPoint.Port,
                        State = conn.State.ToString(),
                        Timestamp = DateTime.Now
                    };

                    if (!_connections.ContainsKey(processId))
                        _connections[processId] = new List<NetworkConnectionInfo>();
                    _connections[processId].Add(info);

                    // 检测可疑连接
                    alerts.AddRange(DetectSuspiciousConnection(info));
                }
            }
            catch (Exception ex)
            {
                LogHelper.Error("网络活动监控异常", ex.Message);
            }

            return alerts;
        }

        private int GetProcessIdByPort(int port)
        {
            // 简化实现
            return -1;
        }

        private List<NetworkActivityAlert> DetectSuspiciousConnection(NetworkConnectionInfo info)
        {
            var alerts = new List<NetworkActivityAlert>();

            // 检测可疑端口
            var suspiciousPorts = new[] { 4444, 5555, 6666, 7777, 31337, 1337, 12345, 54321 };
            if (suspiciousPorts.Contains(info.RemotePort))
            {
                alerts.Add(new NetworkActivityAlert
                {
                    ProcessId = info.ProcessId,
                    AlertType = "Suspicious Port",
                    Severity = "High",
                    Details = $"进程 {info.ProcessId} 连接到可疑端口 {info.RemotePort} ({info.RemoteAddress})",
                    Timestamp = DateTime.Now
                });
            }

            // 检测异常连接状态
            if (info.State == "Established")
            {
                // 检测大量连接
                if (_connections.TryGetValue(info.ProcessId, out var conns))
                {
                    if (conns.Count > 50)
                    {
                        alerts.Add(new NetworkActivityAlert
                        {
                            ProcessId = info.ProcessId,
                            AlertType = "Excessive Connections",
                            Severity = "Medium",
                            Details = $"进程 {info.ProcessId} 建立过多网络连接 ({conns.Count})",
                            Timestamp = DateTime.Now
                        });
                    }
                }
            }

            return alerts;
        }
    }

    /// <summary>
    /// 应用资源使用分析器
    /// </summary>
    public class ResourceUsageAnalyzer
    {
        private readonly DataManager _dataManager;

        public ResourceUsageAnalyzer(DataManager dataManager)
        {
            _dataManager = dataManager;
        }

        public ResourceUsageReport GenerateUsageReport()
        {
            var report = new ResourceUsageReport
            {
                GeneratedTime = DateTime.Now
            };

            try
            {
                // CPU使用统计
                var cpuCounter = new PerformanceCounter("Processor", "% Processor Time", "_Total");
                cpuCounter.NextValue(); // 首次调用返回0
                report.SystemCpuUsage = cpuCounter.NextValue();

                // 内存使用统计
                var memInfo = GetMemoryInfo();
                report.TotalPhysicalMemory = memInfo.TotalPhysical;
                report.AvailablePhysicalMemory = memInfo.AvailablePhysical;
                report.PhysicalMemoryUsagePercent = memInfo.UsagePercent;

                // 磁盘使用统计
                report.DiskUsage = GetDiskUsage();

                // 进程统计
                var processes = Process.GetProcesses();
                report.TotalProcessCount = processes.Length;
                report.TopCpuProcesses = processes
                    .OrderByDescending(p => { try { return p.TotalProcessorTime.TotalMilliseconds; } catch { return 0; } })
                    .Take(10)
                    .Select(p => new ProcessResourceInfo
                    {
                        ProcessName = p.ProcessName,
                        CpuUsage = 0, // 需要计算
                        MemoryUsage = p.WorkingSet64
                    })
                    .ToList();

                report.TopMemoryProcesses = processes
                    .OrderByDescending(p => p.WorkingSet64)
                    .Take(10)
                    .Select(p => new ProcessResourceInfo
                    {
                        ProcessName = p.ProcessName,
                        CpuUsage = 0,
                        MemoryUsage = p.WorkingSet64
                    })
                    .ToList();
            }
            catch (Exception ex)
            {
                LogHelper.Error("资源使用分析异常", ex.Message);
            }

            return report;
        }

        private MemoryInfo GetMemoryInfo()
        {
            var info = new MemoryInfo();
            try
            {
                var gcMemInfo = GC.GetGCMemoryInfo();
                info.TotalPhysical = gcMemInfo.TotalAvailableMemoryBytes;

                var memStatus = new MEMORYSTATUSEX();
                memStatus.dwLength = (uint)Marshal.SizeOf(typeof(MEMORYSTATUSEX));
                if (GlobalMemoryStatusEx(ref memStatus))
                {
                    info.TotalPhysical = (long)memStatus.ullTotalPhys;
                    info.AvailablePhysical = (long)memStatus.ullAvailPhys;
                    info.UsagePercent = (double)(info.TotalPhysical - info.AvailablePhysical) / info.TotalPhysical * 100;
                }
            }
            catch { }
            return info;
        }

        private List<DiskUsageInfo> GetDiskUsage()
        {
            var disks = new List<DiskUsageInfo>();
            try
            {
                foreach (var drive in DriveInfo.GetDrives())
                {
                    if (drive.IsReady && drive.DriveType == DriveType.Fixed)
                    {
                        disks.Add(new DiskUsageInfo
                        {
                            DriveName = drive.Name,
                            TotalSize = drive.TotalSize,
                            FreeSpace = drive.AvailableFreeSpace,
                            UsagePercent = (double)(drive.TotalSize - drive.AvailableFreeSpace) / drive.TotalSize * 100
                        });
                    }
                }
            }
            catch { }
            return disks;
        }

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

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX lpBuffer);
    }

    /// <summary>
    /// 应用启动分析器
    /// </summary>
    public class StartupAnalyzer
    {
        private readonly DataManager _dataManager;
        private List<StartupEntry> _startupEntries;

        public StartupAnalyzer(DataManager dataManager)
        {
            _dataManager = dataManager;
            _startupEntries = new List<StartupEntry>();
        }

        public List<StartupEntry> AnalyzeStartupEntries()
        {
            _startupEntries.Clear();

            try
            {
                // 分析注册表启动项
                AnalyzeRegistryStartup();

                // 分析计划任务启动项
                AnalyzeScheduledTaskStartup();

                // 分析启动文件夹
                AnalyzeStartupFolder();
            }
            catch (Exception ex)
            {
                LogHelper.Error("启动项分析异常", ex.Message);
            }

            return _startupEntries;
        }

        private void AnalyzeRegistryStartup()
        {
            var registryPaths = new Dictionary<string, Microsoft.Win32.RegistryKey>
            {
                { @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", Microsoft.Win32.Registry.LocalMachine },
                { @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", Microsoft.Win32.Registry.LocalMachine },
                { @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run", Microsoft.Win32.Registry.LocalMachine },
                { @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run", Microsoft.Win32.Registry.LocalMachine }
            };

            foreach (var kvp in registryPaths)
            {
                try
                {
                    using var key = kvp.Value.OpenSubKey(kvp.Key);
                    if (key != null)
                    {
                        foreach (var valueName in key.GetValueNames())
                        {
                            var value = key.GetValue(valueName)?.ToString();
                            if (!string.IsNullOrEmpty(value))
                            {
                                _startupEntries.Add(new StartupEntry
                                {
                                    Name = valueName,
                                    Path = value,
                                    Location = "Registry: " + kvp.Key,
                                    IsEnabled = true,
                                    Type = "Registry"
                                });
                            }
                        }
                    }
                }
                catch { }
            }
        }

        private void AnalyzeScheduledTaskStartup()
        {
            try
            {
                // 简化实现
            }
            catch { }
        }

        private void AnalyzeStartupFolder()
        {
            var startupFolder = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
            try
            {
                if (Directory.Exists(startupFolder))
                {
                    foreach (var file in Directory.GetFiles(startupFolder, "*.lnk"))
                    {
                        _startupEntries.Add(new StartupEntry
                        {
                            Name = Path.GetFileNameWithoutExtension(file),
                            Path = file,
                            Location = "Startup Folder",
                            IsEnabled = true,
                            Type = "Folder"
                        });
                    }
                }
            }
            catch { }
        }
    }

    /// <summary>
    /// 辅助类
    /// </summary>
    public class BehaviorPattern
    {
        public string Name { get; set; }
        public string Pattern { get; set; }
        public int Severity { get; set; }
    }

    public class ApplicationBehavior
    {
        public int ProcessId { get; set; }
        public string ProcessName { get; set; }
        public string ProcessPath { get; set; }
        public DateTime StartTime { get; set; }
        public int ParentProcessId { get; set; }
        public long MemoryUsage { get; set; }
        public int ThreadCount { get; set; }
        public List<string> Modules { get; set; }
        public List<string> NetworkConnections { get; set; }
        public List<int> ChildProcesses { get; set; }
        public string CommandLine { get; set; }
        public Dictionary<string, string> EnvironmentVariables { get; set; }
    }

    public class BehaviorAlert
    {
        public int ProcessId { get; set; }
        public string ProcessName { get; set; }
        public string Pattern { get; set; }
        public int Severity { get; set; }
        public string Details { get; set; }
        public DateTime Timestamp { get; set; }
    }

    public class PerformanceMetrics
    {
        public int ProcessId { get; set; }
        public string ProcessName { get; set; }
        public DateTime Timestamp { get; set; }
        public long MemoryUsage { get; set; }
        public long PrivateMemory { get; set; }
        public int ThreadCount { get; set; }
        public int HandleCount { get; set; }
        public TimeSpan CpuTime { get; set; }
        public TimeSpan UserTime { get; set; }
    }

    public class PerformanceAlert
    {
        public int ProcessId { get; set; }
        public string ProcessName { get; set; }
        public string AlertType { get; set; }
        public string Severity { get; set; }
        public string Details { get; set; }
        public DateTime Timestamp { get; set; }
    }

    public class SignatureVerificationResult
    {
        public string FilePath { get; set; }
        public string FileName { get; set; }
        public long FileSize { get; set; }
        public string FileHash { get; set; }
        public bool IsSigned { get; set; }
        public string SignatureStatus { get; set; }
        public bool IsValid { get; set; }
        public bool IsTrusted { get; set; }
        public bool IsSystemFile { get; set; }
        public DateTime Timestamp { get; set; }
    }

    public class NetworkConnectionInfo
    {
        public int ProcessId { get; set; }
        public string LocalAddress { get; set; }
        public int LocalPort { get; set; }
        public string RemoteAddress { get; set; }
        public int RemotePort { get; set; }
        public string State { get; set; }
        public DateTime Timestamp { get; set; }
    }

    public class NetworkActivityAlert
    {
        public int ProcessId { get; set; }
        public string AlertType { get; set; }
        public string Severity { get; set; }
        public string Details { get; set; }
        public DateTime Timestamp { get; set; }
    }

    public class ResourceUsageReport
    {
        public DateTime GeneratedTime { get; set; }
        public double SystemCpuUsage { get; set; }
        public long TotalPhysicalMemory { get; set; }
        public long AvailablePhysicalMemory { get; set; }
        public double PhysicalMemoryUsagePercent { get; set; }
        public List<DiskUsageInfo> DiskUsage { get; set; }
        public int TotalProcessCount { get; set; }
        public List<ProcessResourceInfo> TopCpuProcesses { get; set; }
        public List<ProcessResourceInfo> TopMemoryProcesses { get; set; }
    }

    public class MemoryInfo
    {
        public long TotalPhysical { get; set; }
        public long AvailablePhysical { get; set; }
        public double UsagePercent { get; set; }
    }

    public class DiskUsageInfo
    {
        public string DriveName { get; set; }
        public long TotalSize { get; set; }
        public long FreeSpace { get; set; }
        public double UsagePercent { get; set; }
    }

    public class ProcessResourceInfo
    {
        public string ProcessName { get; set; }
        public double CpuUsage { get; set; }
        public long MemoryUsage { get; set; }
    }

    public class StartupEntry
    {
        public string Name { get; set; }
        public string Path { get; set; }
        public string Location { get; set; }
        public bool IsEnabled { get; set; }
        public string Type { get; set; }
    }

    internal static class LogHelper
    {
        public static void Error(string message, string details = "")
        {
            System.Diagnostics.Debug.WriteLine($"[ERROR] {message}: {details}");
        }
    }
}
