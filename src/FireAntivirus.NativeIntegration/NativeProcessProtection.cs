using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace FireAntivirus.NativeIntegration
{
    /// <summary>
    /// 进程保护模块的C#封装
    /// </summary>
    public class NativeProcessProtection : IDisposable
    {
        #region 私有字段
        private readonly NativeSecurityCoreWrapper _core;
        private Timer _scanTimer;
        private bool _isMonitoring;
        private readonly object _lockObject = new object();
        private readonly List<int> _protectedProcessIds = new List<int>();
        private readonly HashSet<string> _blockedProcessNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private bool _disposed;
        #endregion

        #region 事件
        public event EventHandler<ProcessThreatEventArgs> ThreatDetected;
        public event EventHandler<ProcessEventArgs> ProcessBlocked;
        public event EventHandler<ProcessEventArgs> ProcessTerminated;
        #endregion

        #region 构造函数
        public NativeProcessProtection(NativeSecurityCoreWrapper core)
        {
            _core = core ?? throw new ArgumentNullException(nameof(core));
            InitializeBlockedProcesses();
        }

        ~NativeProcessProtection()
        {
            Dispose(false);
        }
        #endregion

        #region 公共属性
        public bool IsEnabled
        {
            get => _core.ProcessProtectionEnabled;
            set => _core.ProcessProtectionEnabled = value;
        }

        public bool IsMonitoring
        {
            get => _isMonitoring;
        }

        public IReadOnlyList<int> ProtectedProcessIds
        {
            get
            {
                lock (_protectedProcessIds)
                {
                    return _protectedProcessIds.ToList().AsReadOnly();
                }
            }
        }

        public IReadOnlyList<string> BlockedProcessNames
        {
            get
            {
                lock (_blockedProcessNames)
                {
                    return _blockedProcessNames.ToList().AsReadOnly();
                }
            }
        }
        #endregion

        #region 公共方法

        /// <summary>
        /// 开始进程监控
        /// </summary>
        public void StartMonitoring(int intervalSeconds = 5)
        {
            lock (_lockObject)
            {
                if (_isMonitoring)
                    return;

                _isMonitoring = true;
                _scanTimer = new Timer(ScanProcesses, null,
                    TimeSpan.Zero,
                    TimeSpan.FromSeconds(intervalSeconds));
            }
        }

        /// <summary>
        /// 停止进程监控
        /// </summary>
        public void StopMonitoring()
        {
            lock (_lockObject)
            {
                if (!_isMonitoring)
                    return;

                _scanTimer?.Dispose();
                _scanTimer = null;
                _isMonitoring = false;
            }
        }

        /// <summary>
        /// 添加要保护的进程ID
        /// </summary>
        public void AddProtectedProcess(int processId)
        {
            lock (_protectedProcessIds)
            {
                if (!_protectedProcessIds.Contains(processId))
                {
                    _protectedProcessIds.Add(processId);
                }
            }
        }

        /// <summary>
        /// 移除受保护的进程ID
        /// </summary>
        public void RemoveProtectedProcess(int processId)
        {
            lock (_protectedProcessIds)
            {
                _protectedProcessIds.Remove(processId);
            }
        }

        /// <summary>
        /// 添加要阻止的进程名称
        /// </summary>
        public void AddBlockedProcess(string processName)
        {
            if (string.IsNullOrWhiteSpace(processName))
                return;

            lock (_blockedProcessNames)
            {
                _blockedProcessNames.Add(processName);
            }
        }

        /// <summary>
        /// 移除被阻止的进程名称
        /// </summary>
        public void RemoveBlockedProcess(string processName)
        {
            if (string.IsNullOrWhiteSpace(processName))
                return;

            lock (_blockedProcessNames)
            {
                _blockedProcessNames.Remove(processName);
            }
        }

        /// <summary>
        /// 扫描所有进程
        /// </summary>
        public List<ProcessInfo> ScanAllProcesses()
        {
            var result = new List<ProcessInfo>();

            try
            {
                var processes = Process.GetProcesses();
                foreach (var process in processes)
                {
                    try
                    {
                        var info = new ProcessInfo
                        {
                            Id = process.Id,
                            Name = process.ProcessName,
                            Path = GetProcessPath(process),
                            StartTime = GetProcessStartTime(process),
                            Threads = process.Threads.Count,
                            Handles = process.HandleCount,
                            MemoryUsageMB = process.WorkingSet64 / (1024 * 1024)
                        };

                        // 检查是否为恶意进程
                        info.IsMalicious = CheckIfProcessIsMalicious(info);

                        // 检查是否为受保护进程
                        lock (_protectedProcessIds)
                        {
                            info.IsProtected = _protectedProcessIds.Contains(process.Id);
                        }

                        // 检查是否应该被阻止
                        info.ShouldBeBlocked = ShouldBlockProcess(info.Name);

                        if (info.IsMalicious || info.ShouldBeBlocked)
                        {
                            result.Add(info);
                        }
                    }
                    catch
                    {
                        // 忽略无法访问的进程
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"扫描进程失败: {ex.Message}");
            }

            return result;
        }

        /// <summary>
        /// 终止指定进程
        /// </summary>
        public bool TerminateProcess(int processId)
        {
            try
            {
                var process = Process.GetProcessById(processId);
                process.Kill();
                ProcessTerminated?.Invoke(this, new ProcessEventArgs
                {
                    ProcessId = processId,
                    ProcessName = process.ProcessName
                });
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"终止进程失败: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// 获取进程信息
        /// </summary>
        public ProcessInfo GetProcessInfo(int processId)
        {
            try
            {
                var process = Process.GetProcessById(processId);
                return new ProcessInfo
                {
                    Id = process.Id,
                    Name = process.ProcessName,
                    Path = GetProcessPath(process),
                    StartTime = GetProcessStartTime(process),
                    Threads = process.Threads.Count,
                    Handles = process.HandleCount,
                    MemoryUsageMB = process.WorkingSet64 / (1024 * 1024),
                    IsMalicious = CheckIfProcessIsMalicious(new ProcessInfo
                    {
                        Id = process.Id,
                        Name = process.ProcessName,
                        Path = GetProcessPath(process)
                    })
                };
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// 扫描指定进程
        /// </summary>
        public async Task<ProcessScanResult> ScanProcessAsync(int processId)
        {
            return await Task.Run(() =>
            {
                var result = new ProcessScanResult
                {
                    ProcessId = processId,
                    ScanTime = DateTime.Now
                };

                try
                {
                    var process = Process.GetProcessById(processId);
                    result.ProcessName = process.ProcessName;
                    result.ProcessPath = GetProcessPath(process);

                    // 检查进程路径
                    if (string.IsNullOrEmpty(result.ProcessPath))
                    {
                        result.IsSuspicious = true;
                        result.SuspiciousReasons.Add("无法获取进程路径");
                    }

                    // 检查进程名称
                    if (IsSuspiciousProcessName(result.ProcessName))
                    {
                        result.IsSuspicious = true;
                        result.SuspiciousReasons.Add("进程名称可疑");
                    }

                    // 检查文件是否存在
                    if (!string.IsNullOrEmpty(result.ProcessPath) &&
                        !System.IO.File.Exists(result.ProcessPath))
                    {
                        result.IsSuspicious = true;
                        result.SuspiciousReasons.Add("进程文件不存在");
                    }

                    // 检查内存使用
                    var memoryMB = process.WorkingSet64 / (1024 * 1024);
                    if (memoryMB > 500) // 异常高内存使用
                    {
                        result.IsSuspicious = true;
                        result.SuspiciousReasons.Add($"内存使用异常高: {memoryMB}MB");
                    }

                    // 检查子进程
                    try
                    {
                        var children = GetChildProcesses(processId);
                        result.ChildProcessCount = children.Count;

                        foreach (var child in children)
                        {
                            result.ChildProcesses.Add(new ProcessInfo
                            {
                                Id = child.Id,
                                Name = child.ProcessName,
                                Path = GetProcessPath(child)
                            });
                        }
                    }
                    catch
                    {
                        // 无法获取子进程
                    }

                    // 检查网络连接
                    result.HasNetworkConnections = HasNetworkConnections(processId);
                }
                catch (Exception ex)
                {
                    result.Error = ex.Message;
                }

                return result;
            });
        }

        #endregion

        #region 私有方法
        private void InitializeBlockedProcesses()
        {
            // 添加默认阻止的恶意进程名称
            AddBlockedProcess("mimikatz");
            AddBlockedProcess("mimikatz.exe");
            AddBlockedProcess("procdump");
            AddBlockedProcess("procdump.exe");
            AddBlockedProcess("lsass");
            AddBlockedProcess("lsass.exe");
            AddBlockedProcess("pwdump");
            AddBlockedProcess("pwdump.exe");
            AddBlockedProcess("fgdump");
            AddBlockedProcess("fgdump.exe");
            AddBlockedProcess("hashdump");
            AddBlockedProcess("wce");
            AddBlockedProcess("wce.exe");
            AddBlockedProcess("gsecdump");
            AddBlockedProcess("gsecdump.exe");
            AddBlockedProcess("cachedump");
            AddBlockedProcess("lsasecrets");
            AddBlockedProcess("pstgdump");
            AddBlockedProcess("creddump");
        }

        private void ScanProcesses(object state)
        {
            if (!_isMonitoring)
                return;

            try
            {
                var threats = ScanAllProcesses();
                foreach (var threat in threats.Where(t => t.IsMalicious || t.ShouldBeBlocked))
                {
                    ThreatDetected?.Invoke(this, new ProcessThreatEventArgs
                    {
                        ProcessInfo = threat,
                        ThreatType = threat.ShouldBeBlocked ? "BlockedProcess" : "MaliciousProcess"
                    });

                    // 如果应该被阻止，则终止进程
                    if (threat.ShouldBeBlocked)
                    {
                        TerminateProcess(threat.Id);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"扫描进程失败: {ex.Message}");
            }
        }

        private string GetProcessPath(Process process)
        {
            try
            {
                return process.MainModule?.FileName;
            }
            catch
            {
                return string.Empty;
            }
        }

        private DateTime? GetProcessStartTime(Process process)
        {
            try
            {
                return process.StartTime;
            }
            catch
            {
                return null;
            }
        }

        private bool CheckIfProcessIsMalicious(ProcessInfo info)
        {
            // 检查是否为阻止列表中的进程
            if (ShouldBlockProcess(info.Name))
                return true;

            // 检查可疑进程名称
            if (IsSuspiciousProcessName(info.Name))
                return true;

            // 检查可疑路径
            if (!string.IsNullOrEmpty(info.Path))
            {
                var suspiciousPaths = new[]
                {
                    @"\temp\",
                    @"\tmp\",
                    @"\appdata\local\temp",
                    @"\downloads\"
                };

                var lowerPath = info.Path.ToLower();
                if (suspiciousPaths.Any(p => lowerPath.Contains(p)))
                {
                    return true;
                }
            }

            return false;
        }

        private bool ShouldBlockProcess(string processName)
        {
            if (string.IsNullOrEmpty(processName))
                return false;

            lock (_blockedProcessNames)
            {
                return _blockedProcessNames.Contains(processName);
            }
        }

        private bool IsSuspiciousProcessName(string processName)
        {
            if (string.IsNullOrEmpty(processName))
                return false;

            var lowerName = processName.ToLower();

            // 常见的恶意进程名称模式
            var suspiciousPatterns = new[]
            {
                "injector",
                "hack",
                "crack",
                "keygen",
                "loader",
                "stealer",
                "grabber",
                "logger",
                "miner",
                "cryptominer",
                "bot",
                "rat",
                "backdoor",
                "trojan",
                "virus",
                "worm",
                "ransom"
            };

            return suspiciousPatterns.Any(p => lowerName.Contains(p));
        }

        private List<Process> GetChildProcesses(int parentId)
        {
            var children = new List<Process>();

            try
            {
                var allProcesses = Process.GetProcesses();
                foreach (var process in allProcesses)
                {
                    try
                    {
                        if (process.Parent().Id == parentId)
                        {
                            children.Add(process);
                        }
                    }
                    catch
                    {
                        // 忽略
                    }
                }
            }
            catch
            {
                // 忽略
            }

            return children;
        }

        // netstat 查询结果缓存（15秒），避免高频调用
        private static Dictionary<int, bool> _networkConnectionCache;
        private static DateTime _networkCacheTime = DateTime.MinValue;
        private static readonly object _networkCacheLock = new object();

        private bool HasNetworkConnections(int processId)
        {
            // 真实检测：通过 netstat -ano 查询该 PID 是否持有网络连接（带 15 秒缓存）
            lock (_networkCacheLock)
            {
                if (_networkConnectionCache == null || (DateTime.Now - _networkCacheTime).TotalSeconds > 15)
                {
                    _networkConnectionCache = BuildNetworkConnectionCache();
                    _networkCacheTime = DateTime.Now;
                }

                return _networkConnectionCache.TryGetValue(processId, out var hasConnection) && hasConnection;
            }
        }

        private static Dictionary<int, bool> BuildNetworkConnectionCache()
        {
            var result = new Dictionary<int, bool>();

            try
            {
                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "netstat.exe",
                    Arguments = "-ano",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                };

                using var process = System.Diagnostics.Process.Start(psi);
                if (process == null) return result;

                var output = process.StandardOutput.ReadToEnd();
                process.WaitForExit(30000);

                foreach (var line in output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    var tokens = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    if (tokens.Length < 4) continue;

                    var proto = tokens[0].ToUpperInvariant();
                    if (proto != "TCP" && proto != "UDP") continue;

                    // 最后一列为 PID
                    if (int.TryParse(tokens[tokens.Length - 1], out var pid) && pid > 0)
                        result[pid] = true;
                }
            }
            catch
            {
                // 查询失败时返回空缓存（视为无连接）
            }

            return result;
        }
        #endregion

        #region IDisposable
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                StopMonitoring();
            }

            _disposed = true;
        }
        #endregion
    }

    #region 支持的类
    public class ProcessInfo
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string Path { get; set; }
        public DateTime? StartTime { get; set; }
        public int Threads { get; set; }
        public int Handles { get; set; }
        public long MemoryUsageMB { get; set; }
        public bool IsMalicious { get; set; }
        public bool IsProtected { get; set; }
        public bool ShouldBeBlocked { get; set; }
    }

    public class ProcessScanResult
    {
        public int ProcessId { get; set; }
        public string ProcessName { get; set; }
        public string ProcessPath { get; set; }
        public DateTime ScanTime { get; set; }
        public bool IsSuspicious { get; set; }
        public List<string> SuspiciousReasons { get; set; } = new List<string>();
        public int ChildProcessCount { get; set; }
        public List<ProcessInfo> ChildProcesses { get; set; } = new List<ProcessInfo>();
        public bool HasNetworkConnections { get; set; }
        public string Error { get; set; }
    }

    public class ProcessEventArgs : EventArgs
    {
        public int ProcessId { get; set; }
        public string ProcessName { get; set; }
    }

    public class ProcessThreatEventArgs : EventArgs
    {
        public ProcessInfo ProcessInfo { get; set; }
        public string ThreatType { get; set; }
    }

    // 扩展方法：获取父进程
    public static class ProcessExtensions
    {
        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, ref PROCESS_BASIC_INFORMATION processInformation, uint processInformationLength, out uint returnLength);

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebBaseAddress;
            public IntPtr Reserved2;
            public IntPtr Reserved3;
            public IntPtr UniqueProcessId;
            public IntPtr ParentProcessId;
        }

        public static Process Parent(this Process process)
        {
            try
            {
                var pbi = new PROCESS_BASIC_INFORMATION();
                int status = NtQueryInformationProcess(process.Handle, 0, ref pbi, (uint)Marshal.SizeOf(pbi), out _);

                if (status >= 0)
                {
                    return Process.GetProcessById(pbi.ParentProcessId.ToInt32());
                }
            }
            catch
            {
                // 忽略
            }

            return null;
        }
    }
    #endregion
}
