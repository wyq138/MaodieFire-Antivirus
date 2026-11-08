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
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using FireAntivirus.Common;
using FireAntivirus.Data;

namespace FireAntivirus.Sandbox
{
    /// <summary>
    /// 沙箱管理器：在 Windows Job Object 内隔离执行可疑程序，并实时监控其文件、
    /// 注册表、网络与进程行为，最终产出行为分析报告与风险评估分数。
    /// 所有子进程在 Job 关闭时被一并终止，确保安全清理。
    /// </summary>
    public class SandboxManager : IDisposable
    {
        #region 字段与常量

        private readonly DataManager _dataManager;
        private readonly string _sandboxRoot;
        private readonly List<SandboxSession> _activeSessions;
        private readonly object _sessionsLock = new object();
        private bool _disposed;

        /// <summary>默认最大执行时间（毫秒），超时强制终止。</summary>
        public const int DefaultTimeoutMs = 60_000;

        // ===== 风险评分权重 =====
        private const int ScoreRegistryAutorun = 30;
        private const int ScoreFileInSystemDir = 25;
        private const int ScoreNetworkBadIp = 20;
        private const int ScoreChildProcess = 15;
        private const int ScoreMassEncryption = 40;
        private const int ScoreProcessInjection = 30;

        /// <summary>勒索软件加密扩展名集合（命中即判为加密行为）。</summary>
        private static readonly HashSet<string> RansomwareExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".locked", ".encrypted", ".enc", ".crypto", ".crypt", ".crypted",
            ".locky", ".cryptolocker", ".cerber", ".wcry", ".wannacry",
            ".zepto", ".odin", ".aesir", ".thor", ".harma", ".ryk", ".ryansom",
            ".revilton", ".rkdol", ".mole", ".krab", ".gandcrab", ".salsa",
            ".moka", ".stop", ".nppp", ".msop", ".grov", ".mban", ".vhd", ".lalo"
        };

        /// <summary>已知恶意/可疑 IP 样本（演示用威胁情报，实际应来自威胁情报库）。</summary>
        private static readonly HashSet<string> KnownBadIps = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "185.220.101.1", "185.220.101.2", "185.220.101.3",
            "104.244.74.211", "193.169.245.53", "91.219.236.166",
            "23.94.28.123", "45.155.205.83", "194.165.16.78",
            "51.158.144.218", "62.233.50.113", "179.43.175.15"
        };

        /// <summary>注入/逃逸类可疑子进程命令行特征。</summary>
        private static readonly string[] InjectionPatterns =
        {
            "rundll32", "regsvr32", "certutil", "mshta", "wscript", "cscript",
            "powershell -enc", "powershell -e ", "-executionpolicy bypass",
            "iex(", "invoke-", "downloadstring", "frombase64string",
            "cmd /c ", "cmd /k ", "reg add", "reg import", "schtasks /create",
            "net user ", "net localgroup", "vssadmin delete", "wbadmin delete",
            "bcdedit /set", "wevtutil cl", "icacls", "takeown"
        };

        #endregion

        #region 构造与初始化

        public SandboxManager(DataManager dataManager)
        {
            _dataManager = dataManager ?? throw new ArgumentNullException(nameof(dataManager));
            _sandboxRoot = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "FireAntivirus", "Sandbox");
            _activeSessions = new List<SandboxSession>();
            InitializeSandboxEnvironment();
        }

        private void InitializeSandboxEnvironment()
        {
            Directory.CreateDirectory(_sandboxRoot);
            Log("SandboxEnvironmentInitialized", "沙箱环境已初始化", $"根目录: {_sandboxRoot}");
        }

        #endregion

        #region 公共 API

        /// <summary>
        /// 创建一个新的沙箱会话并准备其隔离工作目录。
        /// </summary>
        public SandboxSession CreateSandboxSession()
        {
            string sessionId = Guid.NewGuid().ToString("N");
            string sessionPath = Path.Combine(_sandboxRoot, sessionId);
            Directory.CreateDirectory(sessionPath);

            // 额外创建工作子目录，便于集中观察沙箱内落盘行为
            Directory.CreateDirectory(Path.Combine(sessionPath, "Work"));
            Directory.CreateDirectory(Path.Combine(sessionPath, "Reports"));

            var session = new SandboxSession
            {
                SessionId = sessionId,
                SessionPath = sessionPath,
                CreatedTime = DateTime.Now,
                Status = SandboxStatus.Ready
            };

            lock (_sessionsLock)
            {
                _activeSessions.Add(session);
            }

            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "SandboxSessionCreated",
                Message = "沙箱会话已创建",
                Details = $"会话ID: {sessionId}, 路径: {sessionPath}",
                Severity = "Info",
                Source = "Sandbox",
                Category = "Sandbox"
            });

            return session;
        }

        /// <summary>
        /// 在沙箱（Job Object）内隔离执行指定可执行文件，并全程监控其行为。
        /// 该方法阻塞直到执行结束、超时或出错。
        /// </summary>
        public bool RunInSandbox(string filePath, SandboxSession session)
        {
            return RunInSandbox(filePath, session, DefaultTimeoutMs, null);
        }

        /// <summary>
        /// 在沙箱（Job Object）内隔离执行指定可执行文件，并全程监控其行为。
        /// </summary>
        /// <param name="filePath">被分析的可执行文件路径。</param>
        /// <param name="session">对应的沙箱会话。</param>
        /// <param name="timeoutMs">最大执行时间，超时强制终止。</param>
        /// <param name="arguments">传递给被分析程序的命令行参数。</param>
        public bool RunInSandbox(string filePath, SandboxSession session, int timeoutMs, string arguments)
        {
            if (session == null) throw new ArgumentNullException(nameof(session));
            if (!File.Exists(filePath))
            {
                session.Status = SandboxStatus.Failed;
                session.ErrorMessage = "被分析文件不存在";
                Log("SandboxFileMissing", "沙箱执行失败：文件不存在", $"文件: {filePath}");
                return false;
            }

            session.Status = SandboxStatus.Initializing;
            session.AnalyzedFilePath = filePath;
            session.StartTime = DateTime.Now;

            // 预计算文件哈希用于报告归档
            try
            {
                session.FileHash = FileHelper.GetFileHash(filePath);
            }
            catch (Exception hex)
            {
                session.FileHash = "N/A";
                Log("SandboxHashError", "计算文件哈希失败", hex.Message);
            }

            // 1) 创建 Job Object（KillOnJobClose）实现进程隔离
            IntPtr jobHandle = CreateAndConfigureJobObject(session);
            if (jobHandle == IntPtr.Zero)
            {
                session.Status = SandboxStatus.Failed;
                session.ErrorMessage = "无法创建 Job Object，沙箱隔离初始化失败";
                Log("SandboxJobFailed", "Job Object 创建失败", "CreateJobObject 返回空句柄");
                return false;
            }

            // 2) 启动各路监控（文件/注册表/网络/进程树）
            var monitorCancellation = new CancellationTokenSource();
            var monitors = StartAllMonitors(session, monitorCancellation.Token);

            Process process = null;
            bool success = false;
            try
            {
                session.Status = SandboxStatus.Running;

                var startInfo = new ProcessStartInfo
                {
                    FileName = filePath,
                    Arguments = arguments ?? string.Empty,
                    WorkingDirectory = session.SessionPath,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                };

                var sw = Stopwatch.StartNew();
                process = Process.Start(startInfo);
                if (process == null)
                {
                    session.Status = SandboxStatus.Failed;
                    session.ErrorMessage = "Process.Start 返回空";
                    return false;
                }

                session.MainProcessId = process.Id;
                session.CommandLine = $"\"{filePath}\" {arguments ?? string.Empty}".Trim();

                // 将主进程加入 Job，使其及所有子进程受 Job 约束
                if (!AssignProcessToJobObject(jobHandle, process.Handle))
                {
                    int err = Marshal.GetLastWin32Error();
                    Log("SandboxJobAssignWarning", "主进程加入 Job 失败（仍继续监控）",
                        $"PID={process.Id}, Win32Error={err}");
                }
                else
                {
                    Log("SandboxProcessAssigned", "主进程已加入 Job Object",
                        $"PID={process.Id}, 会话={session.SessionId}");
                }

                // 将主进程 PID 登记到进程树跟踪集合
                monitors.ProcessTree?.RegisterMainProcess(process.Id);

                // 捕获标准输出/错误（API 调用追踪的一部分）
                var stdoutBuilder = new StringBuilder();
                var stderrBuilder = new StringBuilder();
                process.OutputDataReceived += (s, e) => { if (e.Data != null) stdoutBuilder.AppendLine(e.Data); };
                process.ErrorDataReceived += (s, e) => { if (e.Data != null) stderrBuilder.AppendLine(e.Data); };
                process.BeginOutputReadLine();
                process.BeginErrorReadLine();

                // 等待退出或超时
                bool exited = process.WaitForExit(timeoutMs);
                if (!exited)
                {
                    session.Status = SandboxStatus.Timeout;
                    Log("SandboxTimeout", "沙箱执行超时，强制终止进程树",
                        $"PID={process.Id}, 超时={timeoutMs}ms");
                    try
                    {
                        // 终止整个 Job（连带所有子进程）
                        TerminateJobObject(jobHandle, 1);
                        process.WaitForExit(3000);
                    }
                    catch (Exception tex)
                    {
                        Log("SandboxTerminateError", "终止超时进程失败", tex.Message);
                    }
                }

                sw.Stop();
                session.ExecutionDurationMs = sw.ElapsedMilliseconds;

                // 给监控一点时间捕获最后的事件
                monitorCancellation.Cancel();
                monitors.Stop(2000);

                try
                {
                    if (process.HasExited)
                        session.ExitCode = process.ExitCode;
                }
                catch { /* ignore */ }

                session.StandardOutput = stdoutBuilder.ToString();
                session.StandardError = stderrBuilder.ToString();

                session.Status = exited ? SandboxStatus.Analyzing : SandboxStatus.Timeout;

                // 3) 生成行为分析报告与风险评估
                session.Status = exited ? SandboxStatus.Completed : SandboxStatus.Timeout;
                session.CompletedTime = DateTime.Now;

                CalculateRiskScore(session);
                GenerateAnalysisReport(session);

                success = true;

                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "SandboxProgramExecuted",
                    Message = exited ? "程序已在沙箱中执行完毕" : "程序在沙箱中超时终止",
                    Details = $"文件: {filePath}, PID: {session.MainProcessId}, " +
                              $"退出码: {session.ExitCode}, 用时: {session.ExecutionDurationMs}ms, " +
                              $"风险分: {session.RiskScore}({session.RiskLevel})",
                    Severity = session.RiskScore >= 60 ? "Warning" : "Info",
                    Source = "Sandbox",
                    Category = "Sandbox"
                });
            }
            catch (Exception ex)
            {
                session.Status = SandboxStatus.Failed;
                session.ErrorMessage = ex.Message;
                session.CompletedTime = DateTime.Now;

                monitorCancellation.Cancel();
                monitors.Stop(2000);

                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "SandboxExecutionError",
                    Message = "沙箱执行错误",
                    Details = $"文件: {filePath}, 错误: {ex.Message}",
                    Severity = "Error",
                    Source = "Sandbox",
                    Category = "Sandbox"
                });
            }
            finally
            {
                // 安全清理：关闭 Job（KillOnJobClose 会连带终止残留子进程）
                if (jobHandle != IntPtr.Zero)
                {
                    try { TerminateJobObject(jobHandle, 1); } catch { /* ignore */ }
                    CloseHandle(jobHandle);
                }
                process?.Dispose();
            }

            return success;
        }

        /// <summary>异步在沙箱中执行（便于上层非阻塞调用）。</summary>
        public Task<bool> RunInSandboxAsync(string filePath, SandboxSession session, int timeoutMs = DefaultTimeoutMs, string arguments = null)
        {
            return Task.Run(() => RunInSandbox(filePath, session, timeoutMs, arguments));
        }

        /// <summary>
        /// 关闭沙箱会话：终止其中所有进程并清理会话目录。
        /// </summary>
        public void CloseSandboxSession(SandboxSession session)
        {
            if (session == null) return;

            try
            {
                // 再次确保进程已退出（双保险）
                if (session.MainProcessId > 0)
                {
                    SafeKillProcessTree(session.MainProcessId);
                }

                // 清理沙箱目录
                SafeDeleteDirectory(session.SessionPath);

                lock (_sessionsLock)
                {
                    _activeSessions.Remove(session);
                }

                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "SandboxSessionClosed",
                    Message = "沙箱会话已关闭并清理",
                    Details = $"会话ID: {session.SessionId}",
                    Severity = "Info",
                    Source = "Sandbox",
                    Category = "Sandbox"
                });
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "SandboxCleanupError",
                    Message = "沙箱清理错误",
                    Details = $"会话ID: {session.SessionId}, 错误: {ex.Message}",
                    Severity = "Error",
                    Source = "Sandbox",
                    Category = "Sandbox"
                });
            }
        }

        /// <summary>获取当前活动的沙箱会话列表副本。</summary>
        public List<SandboxSession> GetActiveSessions()
        {
            lock (_sessionsLock)
            {
                return new List<SandboxSession>(_activeSessions);
            }
        }

        /// <summary>获取最近一次会话的文本报告内容。</summary>
        public string GetAnalysisReport(SandboxSession session)
        {
            return session?.AnalysisReport ?? string.Empty;
        }

        #endregion

        #region Job Object 隔离（P/Invoke）

        private const int JobObjectExtendedLimitInformation = 9;
        private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000;
        private const uint JOB_OBJECT_LIMIT_BREAKAWAY_OK = 0x0080;

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateJobObject(IntPtr lpJobAttributes, string lpName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetInformationJobObject(
            IntPtr hJob, int infoType, ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION info, int length);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateJobObject(IntPtr hJob, uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [StructLayout(LayoutKind.Sequential)]
        private struct IO_COUNTERS
        {
            public ulong ReadOperationCount;
            public ulong WriteOperationCount;
            public ulong OtherOperationCount;
            public ulong ReadTransferCount;
            public ulong WriteTransferCount;
            public ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
        {
            public long PerProcessUserTimeLimit;
            public long PerJobUserTimeLimit;
            public uint LimitFlags;
            public UIntPtr MinimumWorkingSetSize;
            public UIntPtr MaximumWorkingSetSize;
            public uint ActiveProcessLimit;
            public UIntPtr Affinity;
            public uint PriorityClass;
            public uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        {
            public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
            public IO_COUNTERS IoInfo;
            public UIntPtr ProcessMemoryLimit;
            public UIntPtr JobMemoryLimit;
            public UIntPtr PeakProcessMemoryUsed;
            public UIntPtr PeakJobMemoryUsed;
        }

        /// <summary>
        /// 创建 Job Object 并设置 KillOnJobClose：当 Job 句柄关闭时，
        /// 其内所有进程（含子进程）被自动终止，实现进程级隔离与安全清理。
        /// </summary>
        private IntPtr CreateAndConfigureJobObject(SandboxSession session)
        {
            IntPtr handle = CreateJobObject(IntPtr.Zero, null);
            if (handle == IntPtr.Zero)
            {
                return IntPtr.Zero;
            }

            var limits = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION
            {
                BasicLimitInformation = new JOBOBJECT_BASIC_LIMIT_INFORMATION
                {
                    LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                    // 限制活动进程数，避免沙箱内进程爆炸
                    ActiveProcessLimit = 256
                }
            };

            int size = Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
            if (!SetInformationJobObject(handle, JobObjectExtendedLimitInformation, ref limits, size))
            {
                int err = Marshal.GetLastWin32Error();
                CloseHandle(handle);
                Log("SandboxJobConfigFailed", "Job Object 配置失败",
                    $"Win32Error={err}, 会话={session.SessionId}");
                return IntPtr.Zero;
            }

            Log("SandboxJobConfigured", "Job Object 已配置 KillOnJobClose",
                $"句柄={handle}, 会话={session.SessionId}");
            return handle;
        }

        #endregion

        #region 监控集合启动/停止

        /// <summary>保存一次执行的全部监控器句柄，便于统一停止。</summary>
        private class MonitorSet
        {
            public FileSystemMonitor FileMonitor;
            public RegistryMonitor RegistryMonitor;
            public NetworkMonitor NetworkMonitor;
            public ProcessTreeTracker ProcessTree;
            public ManagementEventWatcher ProcessStartWatcher;

            public void Stop(int timeoutMs)
            {
                try { FileMonitor?.Stop(); } catch { /* ignore */ }
                try { RegistryMonitor?.Stop(); } catch { /* ignore */ }
                try { NetworkMonitor?.Stop(); } catch { /* ignore */ }
                try { ProcessTree?.Stop(); } catch { /* ignore */ }
                try
                {
                    if (ProcessStartWatcher != null)
                    {
                        ProcessStartWatcher.Stop();
                        ProcessStartWatcher.Dispose();
                    }
                }
                catch { /* ignore */ }
            }
        }

        private MonitorSet StartAllMonitors(SandboxSession session, CancellationToken token)
        {
            var set = new MonitorSet();

            // 文件系统监控
            set.FileMonitor = new FileSystemMonitor(session, this, token);
            set.FileMonitor.Start();

            // 注册表监控
            set.RegistryMonitor = new RegistryMonitor(session, this, token);
            set.RegistryMonitor.Start();

            // 网络活动监控
            set.NetworkMonitor = new NetworkMonitor(session, this, token);
            set.NetworkMonitor.Start();

            // 进程树跟踪
            set.ProcessTree = new ProcessTreeTracker(session, this, token);
            set.ProcessTree.Start();

            // API/进程创建事件追踪（ETW 经由 WMI 内核事件）
            set.ProcessStartWatcher = StartProcessCreationWatcher(session, set.ProcessTree);

            return set;
        }

        #endregion

        #region 文件系统监控

        /// <summary>
        /// 使用 FileSystemWatcher 监控沙箱会话目录与系统临时目录的文件变更，
        /// 记录所有创建/修改/删除/重命名事件。
        /// </summary>
        private class FileSystemMonitor
        {
            private readonly SandboxSession _session;
            private readonly SandboxManager _owner;
            private readonly CancellationToken _token;
            private readonly List<FileSystemWatcher> _watchers = new List<FileSystemWatcher>();
            private readonly object _fileLock = new object();

            public FileSystemMonitor(SandboxSession session, SandboxManager owner, CancellationToken token)
            {
                _session = session;
                _owner = owner;
                _token = token;
            }

            public void Start()
            {
                var watchPaths = new List<string>
                {
                    _session.SessionPath,
                    Path.GetTempPath(),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp")
                };

                foreach (var path in watchPaths.Where(Directory.Exists).Distinct(StringComparer.OrdinalIgnoreCase))
                {
                    try
                    {
                        var watcher = new FileSystemWatcher(path)
                        {
                            IncludeSubdirectories = true,
                            NotifyFilter = NotifyFilters.FileName | NotifyFilters.DirectoryName |
                                           NotifyFilters.LastWrite | NotifyFilters.Size |
                                           NotifyFilters.CreationTime | NotifyFilters.Attributes
                        };

                        watcher.Created += (s, e) => OnChange(e.FullPath, "Created");
                        watcher.Changed += (s, e) => OnChange(e.FullPath, "Modified");
                        watcher.Deleted += (s, e) => OnChange(e.FullPath, "Deleted");
                        watcher.Renamed += (s, e) =>
                        {
                            OnChange(e.OldFullPath, "RenamedFrom");
                            OnChange(e.FullPath, "RenamedTo");
                        };

                        watcher.EnableRaisingEvents = true;
                        _watchers.Add(watcher);
                    }
                    catch (Exception ex)
                    {
                        _owner.Log("SandboxFsWatchError", "文件监控器初始化失败",
                            $"路径: {path}, 错误: {ex.Message}");
                    }
                }
            }

            private void OnChange(string fullPath, string changeType)
            {
                if (_token.IsCancellationRequested) return;

                try
                {
                    var record = new FileChangeRecord
                    {
                        FilePath = fullPath,
                        ChangeType = changeType,
                        Timestamp = DateTime.Now
                    };

                    var ext = Path.GetExtension(fullPath);
                    record.FileExtension = ext;
                    record.IsRansomwareIndicator = RansomwareExtensions.Contains(ext);

                    try
                    {
                        if (File.Exists(fullPath))
                        {
                            record.FileSize = new FileInfo(fullPath).Length;
                        }
                    }
                    catch { /* ignore size errors */ }

                    record.IsSystemDirectory = IsInSystemDirectory(fullPath);

                    lock (_fileLock)
                    {
                        _session.FileChanges.Add(record);
                    }

                    // 勒索软件指标即时告警
                    if (record.IsRansomwareIndicator && (changeType == "Created" || changeType == "RenamedTo"))
                    {
                        _owner.Log("SandboxRansomwareIndicator", "检测到勒索软件加密文件指标",
                            $"文件: {fullPath}, 类型: {changeType}");
                    }
                }
                catch { /* swallow monitor errors */ }
            }

            private bool IsInSystemDirectory(string path)
            {
                try
                {
                    string p = path.ToLowerInvariant();
                    string sys = Environment.GetFolderPath(Environment.SpecialFolder.System).ToLowerInvariant();
                    string win = Environment.GetFolderPath(Environment.SpecialFolder.Windows).ToLowerInvariant();
                    string pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles).ToLowerInvariant();
                    string pfx86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86).ToLowerInvariant();

                    return p.StartsWith(sys + "\\") || p.StartsWith(win + "\\") ||
                           p.StartsWith(pf + "\\") || p.StartsWith(pfx86 + "\\");
                }
                catch
                {
                    return false;
                }
            }

            public void Stop()
            {
                foreach (var w in _watchers)
                {
                    try
                    {
                        w.EnableRaisingEvents = false;
                        w.Dispose();
                    }
                    catch { /* ignore */ }
                }
                _watchers.Clear();
            }
        }

        #endregion

        #region 注册表监控（RegNotifyChangeKeyValue）

        private static readonly IntPtr HKEY_CLASSES_ROOT = new IntPtr(unchecked((int)0x80000000));
        private static readonly IntPtr HKEY_CURRENT_USER = new IntPtr(unchecked((int)0x80000001));
        private static readonly IntPtr HKEY_LOCAL_MACHINE = new IntPtr(unchecked((int)0x80000002));
        private static readonly IntPtr HKEY_USERS = new IntPtr(unchecked((int)0x80000003));
        private static readonly IntPtr HKEY_CURRENT_CONFIG = new IntPtr(unchecked((int)0x80000005));

        private const int KEY_NOTIFY = 0x0010;
        private const int KEY_READ = 0x20019;

        private const int REG_NOTIFY_CHANGE_NAME = 0x00000001;
        private const int REG_NOTIFY_CHANGE_ATTRIBUTES = 0x00000002;
        private const int REG_NOTIFY_CHANGE_LAST_SET = 0x00000004;
        private const int REG_NOTIFY_CHANGE_SECURITY = 0x00000008;
        private const int REG_NOTIFY_ALL = REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_ATTRIBUTES |
                                           REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_CHANGE_SECURITY;

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int RegOpenKeyEx(IntPtr hKey, string lpSubKey, int ulOptions, int samDesired, out IntPtr phkResult);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern int RegNotifyChangeKeyValue(IntPtr hKey, bool bWatchSubtree, int dwNotifyFilter, IntPtr hEvent, bool fAsynchronous);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern int RegCloseKey(IntPtr hKey);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateEvent(IntPtr lpEventAttributes, bool bManualReset, bool bInitialState, string lpName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ResetEvent(IntPtr hEvent);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern int WaitForMultipleObjects(int nCount, IntPtr[] lpHandles, bool bWaitAll, int dwMilliseconds);

        private const int WAIT_TIMEOUT = 0x102;

        /// <summary>
        /// 监控的关键注册表位置（自启动/持久化相关，命中即计入风险）。
        /// </summary>
        private static readonly (IntPtr Hive, string SubKey, string Name)[] MonitoredRegistryKeys =
        {
            (HKEY_LOCAL_MACHINE, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM Run"),
            (HKEY_LOCAL_MACHINE, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce"),
            (HKEY_CURRENT_USER, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"),
            (HKEY_CURRENT_USER, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce"),
            (HKEY_LOCAL_MACHINE, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "Winlogon"),
            (HKEY_LOCAL_MACHINE, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders", "Shell Folders"),
            (HKEY_CURRENT_USER, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders", "Shell Folders CU"),
            (HKEY_LOCAL_MACHINE, @"SYSTEM\CurrentControlSet\Services", "Services"),
            (HKEY_LOCAL_MACHINE, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "Uninstall"),
            (HKEY_CURRENT_USER, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects", "BHO"),
            (HKEY_LOCAL_MACHINE, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", "IFEO"),
            (HKEY_CURRENT_USER, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings", "Internet Settings")
        };

        /// <summary>
        /// 使用 RegNotifyChangeKeyValue 异步监控多个关键注册表项的变更。
        /// </summary>
        private class RegistryMonitor
        {
            private readonly SandboxSession _session;
            private readonly SandboxManager _owner;
            private readonly CancellationToken _token;
            private Thread _thread;
            private volatile bool _running;
            private readonly List<IntPtr> _keyHandles = new List<IntPtr>();
            private readonly List<IntPtr> _eventHandles = new List<IntPtr>();
            private readonly List<(string HiveName, string SubKey)> _labels = new List<(string, string)>();

            public RegistryMonitor(SandboxSession session, SandboxManager owner, CancellationToken token)
            {
                _session = session;
                _owner = owner;
                _token = token;
            }

            public void Start()
            {
                _running = true;
                _thread = new Thread(MonitorLoop) { IsBackground = true, Name = $"RegMon-{_session.SessionId}" };
                _thread.Start();
            }

            private void MonitorLoop()
            {
                // 打开所有受监控键并注册变更通知
                for (int i = 0; i < MonitoredRegistryKeys.Length; i++)
                {
                    var (hive, subKey, name) = MonitoredRegistryKeys[i];
                    try
                    {
                        IntPtr keyHandle;
                        int rc = RegOpenKeyEx(hive, subKey, 0, KEY_NOTIFY, out keyHandle);
                        if (rc != 0 || keyHandle == IntPtr.Zero)
                            continue;

                        IntPtr evt = CreateEvent(IntPtr.Zero, true, false, null);
                        if (evt == IntPtr.Zero)
                        {
                            RegCloseKey(keyHandle);
                            continue;
                        }

                        // 异步注册变更通知：当键或其子树发生变更时，事件被置位
                        rc = RegNotifyChangeKeyValue(keyHandle, true, REG_NOTIFY_ALL, evt, true);
                        if (rc != 0)
                        {
                            CloseHandle(evt);
                            RegCloseKey(keyHandle);
                            continue;
                        }

                        string hiveName = HiveToString(hive);
                        _keyHandles.Add(keyHandle);
                        _eventHandles.Add(evt);
                        _labels.Add((hiveName, subKey));
                    }
                    catch (Exception ex)
                    {
                        _owner.Log("SandboxRegWatchInitError", "注册表监控初始化异常",
                            $"键: {name}, 错误: {ex.Message}");
                    }
                }

                if (_eventHandles.Count == 0)
                {
                    return;
                }

                // 轮询等待任意事件触发
                while (_running && !_token.IsCancellationRequested)
                {
                    IntPtr[] handles = _eventHandles.ToArray();
                    int wait = WaitForMultipleObjects(handles.Length, handles, false, 1000);

                    if (wait == WAIT_TIMEOUT || wait < 0 || wait >= handles.Length)
                        continue;

                    // wait 是触发事件的索引
                    var (hiveName, subKey) = _labels[wait];
                    RecordChange(hiveName, subKey);

                    // 重置事件并重新挂接通知
                    ResetEvent(_eventHandles[wait]);
                    try
                    {
                        RegNotifyChangeKeyValue(_keyHandles[wait], true, REG_NOTIFY_ALL, _eventHandles[wait], true);
                    }
                    catch { /* ignore re-arm errors */ }
                }
            }

            private void RecordChange(string hiveName, string subKey)
            {
                try
                {
                    bool isAutorun = subKey.IndexOf("Run", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                     subKey.IndexOf("Winlogon", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                     subKey.IndexOf("Image File Execution Options", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                     subKey.IndexOf("Services", StringComparison.OrdinalIgnoreCase) >= 0;

                    var record = new RegistryChangeRecord
                    {
                        Hive = hiveName,
                        KeyPath = subKey,
                        ChangeType = "ValueChanged",
                        Timestamp = DateTime.Now,
                        IsAutorunLocation = isAutorun
                    };

                    lock (_session)
                    {
                        _session.RegistryChanges.Add(record);
                    }

                    _owner.Log("SandboxRegistryChange", "检测到注册表变更",
                        $"{hiveName}\\{subKey} (持久化位置={isAutorun})");
                }
                catch { /* ignore */ }
            }

            private static string HiveToString(IntPtr hive)
            {
                if (hive == HKEY_LOCAL_MACHINE) return "HKEY_LOCAL_MACHINE";
                if (hive == HKEY_CURRENT_USER) return "HKEY_CURRENT_USER";
                if (hive == HKEY_CLASSES_ROOT) return "HKEY_CLASSES_ROOT";
                if (hive == HKEY_USERS) return "HKEY_USERS";
                if (hive == HKEY_CURRENT_CONFIG) return "HKEY_CURRENT_CONFIG";
                return hive.ToString();
            }

            public void Stop()
            {
                _running = false;
                try { if (_thread != null && _thread.IsAlive) _thread.Join(2000); } catch { /* ignore */ }

                foreach (var evt in _eventHandles)
                {
                    try { CloseHandle(evt); } catch { /* ignore */ }
                }
                foreach (var key in _keyHandles)
                {
                    try { RegCloseKey(key); } catch { /* ignore */ }
                }
                _eventHandles.Clear();
                _keyHandles.Clear();
            }
        }

        #endregion

        #region 网络活动监控（GetExtendedTcpTable）

        private const int AF_INET = 2;
        private const int AF_INET6 = 23;
        private const int TCP_TABLE_OWNER_PID_ALL = 5;

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern int GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize, bool bOrder, int ulAf, int tableClass, int reserved);

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPROW_OWNER_PID
        {
            public uint dwState;
            public uint dwLocalAddr;
            public uint dwLocalPort;
            public uint dwRemoteAddr;
            public uint dwRemotePort;
            public uint dwOwningPid;
        }

        private static readonly string[] TcpStateNames =
        {
            "Unknown", "Closed", "Listening", "SynSent", "SynReceived",
            "Established", "FinWait1", "FinWait2", "CloseWait", "Closing",
            "LastAck", "TimeWait", "DeleteTcb"
        };

        /// <summary>
        /// 轮询 GetExtendedTcpTable，捕获沙箱进程发起的对外 TCP 连接。
        /// </summary>
        private class NetworkMonitor
        {
            private readonly SandboxSession _session;
            private readonly SandboxManager _owner;
            private readonly CancellationToken _token;
            private Thread _thread;
            private volatile bool _running;
            private readonly HashSet<string> _seenConnections = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            public NetworkMonitor(SandboxSession session, SandboxManager owner, CancellationToken token)
            {
                _session = session;
                _owner = owner;
                _token = token;
            }

            public void Start()
            {
                _running = true;
                _thread = new Thread(MonitorLoop) { IsBackground = true, Name = $"NetMon-{_session.SessionId}" };
                _thread.Start();
            }

            private void MonitorLoop()
            {
                while (_running && !_token.IsCancellationRequested)
                {
                    try
                    {
                        var rows = GetTcpTableOwnerPid();
                        foreach (var row in rows)
                        {
                            // 仅关注属于本沙箱进程树的连接
                            if (!IsInSandboxProcessTree(row.dwOwningPid))
                                continue;

                            string remote = IpToString(row.dwRemoteAddr);
                            int remotePort = PortFromDword(row.dwRemotePort);
                            string local = IpToString(row.dwLocalAddr);
                            int localPort = PortFromDword(row.dwLocalPort);

                            string key = $"{local}:{localPort}->{remote}:{remotePort}";
                            if (_seenConnections.Contains(key))
                                continue;
                            _seenConnections.Add(key);

                            bool suspicious = false;
                            string reason = null;

                            if (KnownBadIps.Contains(remote))
                            {
                                suspicious = true;
                                reason = "已知恶意IP";
                            }
                            else if (IsPrivateAddress(remote) && remote != "127.0.0.1")
                            {
                                suspicious = true;
                                reason = "内网横向移动疑似IP";
                            }
                            else if (row.dwRemotePort != 0 && remotePort > 0 &&
                                     remotePort != 80 && remotePort != 443 &&
                                     remotePort != 53 && remotePort != 123)
                            {
                                suspicious = true;
                                reason = $"非标准端口({remotePort})";
                            }

                            string state = row.dwState < TcpStateNames.Length
                                ? TcpStateNames[row.dwState]
                                : row.dwState.ToString();

                            var record = new NetworkConnectionRecord
                            {
                                LocalAddress = local,
                                LocalPort = localPort,
                                RemoteAddress = remote,
                                RemotePort = remotePort,
                                State = state,
                                ProcessId = (int)row.dwOwningPid,
                                ProcessName = SafeGetProcessName((int)row.dwOwningPid),
                                Timestamp = DateTime.Now,
                                IsSuspicious = suspicious,
                                SuspicionReason = reason
                            };

                            lock (_session)
                            {
                                _session.NetworkConnections.Add(record);
                            }

                            if (suspicious)
                            {
                                _owner.Log("SandboxNetworkSuspicious", "检测到可疑网络连接",
                                    $"{local}:{localPort} -> {remote}:{remotePort} ({reason}), PID={row.dwOwningPid}");
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _owner.Log("SandboxNetMonitorError", "网络监控异常", ex.Message);
                    }

                    // 1 秒轮询间隔
                    try { Thread.Sleep(1000); } catch { break; }
                }
            }

            private bool IsInSandboxProcessTree(uint pid)
            {
                // 主进程或其任何子进程
                if (_session.MainProcessId > 0 && pid == _session.MainProcessId)
                    return true;
                foreach (var child in _session.ChildProcesses)
                {
                    if (child.ProcessId == (int)pid)
                        return true;
                }
                return false;
            }

            /// <summary>调用 GetExtendedTcpTable 获取全部 TCP 行（含 PID）。</summary>
            private List<MIB_TCPROW_OWNER_PID> GetTcpTableOwnerPid()
            {
                var result = new List<MIB_TCPROW_OWNER_PID>();
                int size = 0;
                // 第一次调用获取所需缓冲区大小
                GetExtendedTcpTable(IntPtr.Zero, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

                if (size <= 0) return result;

                IntPtr buffer = Marshal.AllocHGlobal(size);
                try
                {
                    int rc = GetExtendedTcpTable(buffer, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
                    if (rc != 0) return result;

                    // 头 4 字节为条目数
                    int count = Marshal.ReadInt32(buffer);
                    int rowSize = Marshal.SizeOf(typeof(MIB_TCPROW_OWNER_PID));
                    IntPtr rowPtr = IntPtr.Add(buffer, 4);

                    for (int i = 0; i < count; i++)
                    {
                        var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(IntPtr.Add(rowPtr, i * rowSize));
                        result.Add(row);
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
                return result;
            }

            private static string IpToString(uint addr)
            {
                // DWORD 以网络字节序存储：高位为第一段
                return string.Format("{0}.{1}.{2}.{3}",
                    (addr >> 24) & 0xFF,
                    (addr >> 16) & 0xFF,
                    (addr >> 8) & 0xFF,
                    addr & 0xFF);
            }

            private static int PortFromDword(uint port)
            {
                // 端口以网络字节序存于低 16 位，需主机序转换
                return (int)(((port >> 8) & 0xFF) | ((port & 0xFF) << 8));
            }

            private static bool IsPrivateAddress(string ip)
            {
                if (!IPAddress.TryParse(ip, out var addr)) return false;
                try
                {
                    if (IPAddress.IsLoopback(addr)) return true;
                    // 私有网段判断
                    var bytes = addr.GetAddressBytes();
                    if (bytes[0] == 10) return true;
                    if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return true;
                    if (bytes[0] == 192 && bytes[1] == 168) return true;
                    if (bytes[0] == 169 && bytes[1] == 254) return true; // 链路本地
                    if (bytes[0] == 0) return true;
                    return false;
                }
                catch { return false; }
            }

            private static string SafeGetProcessName(int pid)
            {
                try
                {
                    using (var p = Process.GetProcessById(pid))
                        return p.ProcessName;
                }
                catch { return "Unknown"; }
            }

            public void Stop()
            {
                _running = false;
                try { if (_thread != null && _thread.IsAlive) _thread.Join(2000); } catch { /* ignore */ }
            }
        }

        #endregion

        #region 进程树跟踪（WMI Win32_ProcessStartTrace）

        /// <summary>
        /// 使用 ETW 经由 WMI 的 Win32_ProcessStartTrace 捕获系统进程创建事件，
        /// 过滤出沙箱进程衍生的子进程并构建进程树。同时跟踪这些子进程的退出。
        /// </summary>
        private class ProcessTreeTracker
        {
            private readonly SandboxSession _session;
            private readonly SandboxManager _owner;
            private readonly CancellationToken _token;
            private Thread _pollThread;
            private volatile bool _running;
            private readonly Dictionary<int, ProcessNode> _nodes = new Dictionary<int, ProcessNode>();
            private readonly object _treeLock = new object();

            public ProcessTreeTracker(SandboxSession session, SandboxManager owner, CancellationToken token)
            {
                _session = session;
                _owner = owner;
                _token = token;
            }

            public void RegisterMainProcess(int pid)
            {
                lock (_treeLock)
                {
                    if (_nodes.ContainsKey(pid)) return;
                    var node = new ProcessNode
                    {
                        ProcessId = pid,
                        ParentProcessId = 0,
                        ProcessName = SafeGetProcessName(pid),
                        ExecutablePath = _session.AnalyzedFilePath,
                        CommandLine = _session.CommandLine,
                        StartTime = DateTime.Now
                    };
                    _nodes[pid] = node;
                }
            }

            public void Start()
            {
                _running = true;
                // 兜底轮询线程：当 WMI 事件不可用时，仍能通过扫描发现子进程
                _pollThread = new Thread(PollLoop) { IsBackground = true, Name = $"ProcTree-{_session.SessionId}" };
                _pollThread.Start();
            }

            /// <summary>WMI 事件到达时调用：登记新发现的子进程。</summary>
            public void OnProcessStarted(int pid, int parentPid, string name, string commandLine, string execPath)
            {
                lock (_treeLock)
                {
                    if (_nodes.ContainsKey(pid)) return;

                    bool parentInTree = _nodes.ContainsKey(parentPid);
                    if (!parentInTree && parentPid != _session.MainProcessId)
                        return; // 不属于本沙箱进程树

                    var node = new ProcessNode
                    {
                        ProcessId = pid,
                        ParentProcessId = parentPid,
                        ProcessName = name,
                        CommandLine = commandLine,
                        ExecutablePath = execPath,
                        StartTime = DateTime.Now
                    };
                    _nodes[pid] = node;

                    // 挂到父节点下
                    if (_nodes.TryGetValue(parentPid, out var parent))
                    {
                        parent.Children.Add(node);
                    }

                    _session.ChildProcesses.Add(node);

                    // 检测注入/逃逸指标
                    if (IsInjectionIndicator(name, commandLine, execPath))
                    {
                        node.IsInjectionIndicator = true;
                        _owner.Log("SandboxInjectionIndicator", "检测到进程注入/逃逸指标",
                            $"进程: {name}, PID={pid}, 命令行: {commandLine}");
                    }
                    else
                    {
                        _owner.Log("SandboxChildProcess", "沙箱衍生子进程",
                            $"进程: {name}, PID={pid}, 父PID={parentPid}, 命令行: {commandLine}");
                    }
                }
            }

            private void PollLoop()
            {
                var known = new HashSet<int>();
                if (_session.MainProcessId > 0)
                    known.Add(_session.MainProcessId);

                while (_running && !_token.IsCancellationRequested)
                {
                    try
                    {
                        // 枚举所有进程，发现其父在本树中的新进程（兜底机制）
                        var all = Process.GetProcesses();
                        foreach (var p in all)
                        {
                            try
                            {
                                if (known.Contains(p.Id)) continue;
                                int ppid;
                                try { ppid = GetParentProcessId(p.Id); }
                                catch { continue; }

                                if (known.Contains(ppid))
                                {
                                    string name = p.ProcessName;
                                    string cmd = SafeGetCommandLine(p.Id);
                                    string exe = SafeGetExecutablePath(p);
                                    OnProcessStarted(p.Id, ppid, name, cmd, exe);
                                    known.Add(p.Id);
                                }
                            }
                            catch { /* ignore */ }
                            finally { try { p.Dispose(); } catch { /* ignore */ } }
                        }

                        // 更新已退出进程的退出码
                        UpdateExitedProcesses();
                    }
                    catch (Exception ex)
                    {
                        _owner.Log("SandboxProcTreeError", "进程树轮询异常", ex.Message);
                    }

                    try { Thread.Sleep(500); } catch { break; }
                }
            }

            private void UpdateExitedProcesses()
            {
                lock (_treeLock)
                {
                    foreach (var node in _nodes.Values)
                    {
                        if (node.EndTime.HasValue) continue;
                        try
                        {
                            using (var p = Process.GetProcessById(node.ProcessId)) { /* still running */ }
                        }
                        catch
                        {
                            // 进程已退出
                            node.EndTime = DateTime.Now;
                        }
                    }
                }
            }

            private static bool IsInjectionIndicator(string name, string commandLine, string execPath)
            {
                if (string.IsNullOrEmpty(name)) return false;
                string lowerName = name.ToLowerInvariant();
                string lowerCmd = (commandLine ?? string.Empty).ToLowerInvariant();
                string lowerPath = (execPath ?? string.Empty).ToLowerInvariant();

                // 可疑进程承载器从临时目录启动
                if ((lowerName == "rundll32" || lowerName == "regsvr32" || lowerName == "certutil" ||
                     lowerName == "mshta" || lowerName == "wscript" || lowerName == "cscript") &&
                    (lowerPath.Contains("\\temp\\") || lowerPath.Contains("\\appdata\\local\\temp")))
                {
                    return true;
                }

                foreach (var pattern in InjectionPatterns)
                {
                    if (lowerCmd.Contains(pattern))
                        return true;
                }
                return false;
            }

            public void Stop()
            {
                _running = false;
                try { if (_pollThread != null && _pollThread.IsAlive) _pollThread.Join(2000); } catch { /* ignore */ }
            }

            [DllImport("kernel32.dll", SetLastError = true)]
            private static extern IntPtr OpenProcess(int access, bool inherit, int pid);

            [DllImport("kernel32.dll", SetLastError = true)]
            private static extern bool CloseHandle(IntPtr h);

            [DllImport("ntdll.dll", SetLastError = true)]
            private static extern int NtQueryInformationProcess(
                IntPtr h, int cls, ref PROCESS_BASIC_INFORMATION pbi, int size, out int ret);

            [StructLayout(LayoutKind.Sequential)]
            private struct PROCESS_BASIC_INFORMATION
            {
                public IntPtr Reserved1;
                public IntPtr PebBaseAddress;
                public IntPtr Reserved2_0;
                public IntPtr Reserved2_1;
                public IntPtr UniqueProcessId;
                public IntPtr Reserved3;
            }

            private const int ProcessBasicInformation = 0;
            private const int PROCESS_QUERY_INFORMATION = 0x0400;

            private static int GetParentProcessId(int pid)
            {
                IntPtr h = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid);
                if (h == IntPtr.Zero) return -1;
                try
                {
                    var pbi = new PROCESS_BASIC_INFORMATION();
                    int ret;
                    int status = NtQueryInformationProcess(h, ProcessBasicInformation, ref pbi,
                        Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION)), out ret);
                    if (status != 0) return -1;
                    // InheritedFromUniqueProcessId 即为父 PID
                    return pbi.Reserved3 == IntPtr.Zero ? -1 : unchecked((int)pbi.Reserved3.ToInt64());
                }
                finally { CloseHandle(h); }
            }

            private static string SafeGetCommandLine(int pid)
            {
                try
                {
                    using (var searcher = new ManagementObjectSearcher(
                        $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {pid}"))
                    {
                        foreach (var obj in searcher.Get())
                        {
                            return obj["CommandLine"]?.ToString() ?? string.Empty;
                        }
                    }
                }
                catch { /* ignore */ }
                return string.Empty;
            }

            private static string SafeGetExecutablePath(Process p)
            {
                try { return p.MainModule?.FileName ?? string.Empty; }
                catch { return string.Empty; }
            }

            private static string SafeGetProcessName(int pid)
            {
                try { using (var p = Process.GetProcessById(pid)) return p.ProcessName; }
                catch { return "Unknown"; }
            }
        }

        /// <summary>
        /// 启动 WMI 进程创建事件监听（ETW 内核提供者），实时捕获进程创建并取得命令行。
        /// </summary>
        private ManagementEventWatcher StartProcessCreationWatcher(SandboxSession session, ProcessTreeTracker tracker)
        {
            try
            {
                var query = new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace");
                var watcher = new ManagementEventWatcher(query);
                watcher.EventArrived += (sender, e) =>
                {
                    try
                    {
                        int pid = Convert.ToInt32(e.NewEvent.Properties["ProcessID"]?.Value ?? 0);
                        int parentPid = Convert.ToInt32(e.NewEvent.Properties["ParentProcessID"]?.Value ?? 0);
                        string name = e.NewEvent.Properties["ProcessName"]?.Value?.ToString() ?? "Unknown";

                        if (pid == 0) return;

                        // 取命令行：Win32_ProcessStartTrace 不含 CommandLine，需查询 Win32_Process
                        string cmdLine = QueryProcessCommandLine(pid);
                        string execPath = string.Empty;
                        try
                        {
                            using (var p = Process.GetProcessById(pid))
                                execPath = p.MainModule?.FileName ?? string.Empty;
                        }
                        catch { /* ignore */ }

                        tracker.OnProcessStarted(pid, parentPid, name, cmdLine, execPath);

                        // API 调用追踪：记录命令行参数
                        _dataManager.AddLog(new LogEntry
                        {
                            Id = Guid.NewGuid().ToString(),
                            Time = DateTime.Now,
                            Type = "SandboxProcessCreation",
                            Message = "捕获到进程创建事件",
                            Details = $"进程: {name}, PID={pid}, 父PID={parentPid}, 命令行: {cmdLine}",
                            Severity = "Info",
                            Source = "Sandbox",
                            Category = "Sandbox"
                        });
                    }
                    catch (Exception ex)
                    {
                        Log("SandboxProcEventError", "处理进程创建事件异常", ex.Message);
                    }
                };
                watcher.Start();
                Log("SandboxProcWatcherStarted", "ETW/WMI 进程创建监听已启动", $"会话={session.SessionId}");
                return watcher;
            }
            catch (Exception ex)
            {
                Log("SandboxProcWatcherFailed", "WMI 进程创建监听启动失败，使用轮询兜底", ex.Message);
                return null;
            }
        }

        /// <summary>查询指定 PID 的命令行。</summary>
        private static string QueryProcessCommandLine(int pid)
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher(
                    $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {pid}"))
                {
                    foreach (var obj in searcher.Get())
                    {
                        return obj["CommandLine"]?.ToString() ?? string.Empty;
                    }
                }
            }
            catch { /* ignore */ }
            return string.Empty;
        }

        #endregion

        #region 风险评分

        /// <summary>
        /// 基于观察到的行为计算风险分数与等级。
        /// </summary>
        private void CalculateRiskScore(SandboxSession session)
        {
            int score = 0;
            var factors = new List<string>();

            // 1) 自启动位置注册表修改 (+30)
            int autorunRegChanges = session.RegistryChanges.Count(r => r.IsAutorunLocation);
            if (autorunRegChanges > 0)
            {
                score += ScoreRegistryAutorun;
                factors.Add($"自启动位置注册表修改 ({autorunRegChanges} 处) +{ScoreRegistryAutorun}");
            }

            // 2) 系统目录文件创建 (+25)
            bool systemFileWrite = session.FileChanges.Any(f => f.IsSystemDirectory &&
                (f.ChangeType == "Created" || f.ChangeType == "Modified" || f.ChangeType == "RenamedTo"));
            if (systemFileWrite)
            {
                score += ScoreFileInSystemDir;
                factors.Add($"系统目录文件修改 +{ScoreFileInSystemDir}");
            }

            // 3) 连接已知恶意 IP (+20)
            bool badIpConnection = session.NetworkConnections.Any(n => KnownBadIps.Contains(n.RemoteAddress));
            if (badIpConnection)
            {
                score += ScoreNetworkBadIp;
                factors.Add($"连接已知恶意 IP +{ScoreNetworkBadIp}");
            }

            // 4) 衍生子进程 (+15)
            if (session.ChildProcesses.Count > 0)
            {
                score += ScoreChildProcess;
                factors.Add($"衍生子进程 ({session.ChildProcesses.Count} 个) +{ScoreChildProcess}");
            }

            // 5) 大规模文件加密模式 (+40)
            int encryptedFiles = session.FileChanges.Count(f => f.IsRansomwareIndicator);
            int massModifications = session.FileChanges
                .Where(f => f.ChangeType == "Modified" || f.ChangeType == "RenamedTo")
                .GroupBy(f =>
                {
                    try { return Path.GetDirectoryName(f.FilePath); }
                    catch { return f.FilePath; }
                })
                .Max(g => g.Count());

            if (encryptedFiles >= 3 || massModifications >= 20)
            {
                score += ScoreMassEncryption;
                factors.Add($"大规模文件加密/篡改 (加密文件={encryptedFiles}, 单目录最多={massModifications}) +{ScoreMassEncryption}");
            }

            // 6) 进程注入指标 (+30)
            bool injection = session.ChildProcesses.Any(p => p.IsInjectionIndicator);
            if (injection)
            {
                score += ScoreProcessInjection;
                factors.Add($"进程注入/逃逸指标 +{ScoreProcessInjection}");
            }

            // 额外加权：可疑网络连接数量（每个 +5，上限 +30）
            int suspiciousNet = session.NetworkConnections.Count(n => n.IsSuspicious);
            if (suspiciousNet > 0)
            {
                int add = Math.Min(suspiciousNet * 5, 30);
                score += add;
                factors.Add($"可疑网络连接 ({suspiciousNet} 个) +{add}");
            }

            session.RiskScore = score;
            session.RiskLevel = ScoreToLevel(score);
            session.RiskFactors = factors;

            Log("SandboxRiskScored", "风险评估完成",
                $"总分={score}, 等级={session.RiskLevel}, 因素数={factors.Count}");
        }

        private static RiskLevel ScoreToLevel(int score)
        {
            if (score >= 100) return RiskLevel.Critical;
            if (score >= 70) return RiskLevel.High;
            if (score >= 40) return RiskLevel.Medium;
            if (score >= 15) return RiskLevel.Low;
            return RiskLevel.Clean;
        }

        #endregion

        #region 行为分析报告

        /// <summary>
        /// 生成综合行为分析报告，写入会话目录与 session.AnalysisReport / ReportPath。
        /// </summary>
        private void GenerateAnalysisReport(SandboxSession session)
        {
            var sb = new StringBuilder();

            sb.AppendLine("============================================================");
            sb.AppendLine("            耄耋安全沙箱 - 行为分析报告");
            sb.AppendLine("============================================================");
            sb.AppendLine();
            sb.AppendLine("【一、基本信息】");
            sb.AppendLine($"  会话 ID      : {session.SessionId}");
            sb.AppendLine($"  被分析文件   : {session.AnalyzedFilePath}");
            sb.AppendLine($"  文件哈希     : {session.FileHash}");
            sb.AppendLine($"  命令行       : {session.CommandLine}");
            sb.AppendLine($"  主进程 PID   : {session.MainProcessId}");
            sb.AppendLine($"  启动时间     : {session.StartTime:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"  完成时间     : {session.CompletedTime:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"  执行时长     : {session.ExecutionDurationMs} ms");
            sb.AppendLine($"  退出码       : {session.ExitCode}");
            sb.AppendLine($"  最终状态     : {session.Status}");
            if (!string.IsNullOrEmpty(session.ErrorMessage))
                sb.AppendLine($"  错误信息     : {session.ErrorMessage}");
            sb.AppendLine();

            sb.AppendLine("【二、风险评估】");
            sb.AppendLine($"  风险分数     : {session.RiskScore}");
            sb.AppendLine($"  风险等级     : {session.RiskLevel}");
            if (session.RiskFactors.Count > 0)
            {
                sb.AppendLine("  风险因素:");
                foreach (var f in session.RiskFactors)
                    sb.AppendLine($"    - {f}");
            }
            else
            {
                sb.AppendLine("  风险因素: 无");
            }
            sb.AppendLine();

            sb.AppendLine("【三、文件系统行为】");
            sb.AppendLine($"  文件变更事件总数: {session.FileChanges.Count}");
            var byType = session.FileChanges.GroupBy(f => f.ChangeType)
                .Select(g => $"{g.Key}({g.Count()})");
            sb.AppendLine($"  分类: {string.Join(", ", byType)}");
            if (session.FileChanges.Count > 0)
            {
                sb.AppendLine("  变更明细 (最多 50 条):");
                int idx = 0;
                foreach (var f in session.FileChanges.Take(50))
                {
                    string flag = f.IsRansomwareIndicator ? " [勒索]" : (f.IsSystemDirectory ? " [系统目录]" : "");
                    sb.AppendLine($"    [{f.Timestamp:HH:mm:ss}] {f.ChangeType}: {f.FilePath}{flag}");
                }
                if (session.FileChanges.Count > 50)
                    sb.AppendLine($"    ... 另有 {session.FileChanges.Count - 50} 条未显示");
            }
            sb.AppendLine();

            sb.AppendLine("【四、注册表行为】");
            sb.AppendLine($"  注册表变更事件总数: {session.RegistryChanges.Count}");
            if (session.RegistryChanges.Count > 0)
            {
                sb.AppendLine("  变更明细:");
                foreach (var r in session.RegistryChanges)
                {
                    string flag = r.IsAutorunLocation ? " [自启动]" : "";
                    sb.AppendLine($"    [{r.Timestamp:HH:mm:ss}] {r.Hive}\\{r.KeyPath}{flag}");
                }
            }
            sb.AppendLine();

            sb.AppendLine("【五、网络行为】");
            sb.AppendLine($"  网络连接总数: {session.NetworkConnections.Count}");
            int suspicious = session.NetworkConnections.Count(n => n.IsSuspicious);
            sb.AppendLine($"  其中可疑连接: {suspicious}");
            if (session.NetworkConnections.Count > 0)
            {
                sb.AppendLine("  连接明细:");
                foreach (var n in session.NetworkConnections)
                {
                    string flag = n.IsSuspicious ? $" [可疑:{n.SuspicionReason}]" : "";
                    sb.AppendLine($"    [{n.Timestamp:HH:mm:ss}] {n.LocalAddress}:{n.LocalPort} -> " +
                                  $"{n.RemoteAddress}:{n.RemotePort} ({n.State}) PID={n.ProcessId}({n.ProcessName}){flag}");
                }
            }
            sb.AppendLine();

            sb.AppendLine("【六、进程树】");
            sb.AppendLine($"  衍生子进程总数: {session.ChildProcesses.Count}");
            int injectionCount = session.ChildProcesses.Count(p => p.IsInjectionIndicator);
            if (injectionCount > 0)
                sb.AppendLine($"  含注入/逃逸指标进程: {injectionCount}");
            foreach (var c in session.ChildProcesses)
            {
                string flag = c.IsInjectionIndicator ? " [注入]" : "";
                sb.AppendLine($"    PID={c.ProcessId} (父PID={c.ParentProcessId}) {c.ProcessName}{flag}");
                if (!string.IsNullOrEmpty(c.CommandLine))
                    sb.AppendLine($"      命令行: {c.CommandLine}");
            }
            sb.AppendLine();

            sb.AppendLine("【七、标准输出 / 标准错误 (节选)】");
            sb.AppendLine("  --- stdout ---");
            sb.AppendLine(Truncate(session.StandardOutput, 2000));
            sb.AppendLine("  --- stderr ---");
            sb.AppendLine(Truncate(session.StandardError, 2000));
            sb.AppendLine();

            sb.AppendLine("【八、总结】");
            sb.Append(GenerateSummary(session));
            sb.AppendLine();
            sb.AppendLine("============================================================");

            string report = sb.ToString();
            session.AnalysisReport = report;

            try
            {
                string reportFile = Path.Combine(session.SessionPath, "Reports",
                    $"analysis_{session.SessionId}.txt");
                Directory.CreateDirectory(Path.GetDirectoryName(reportFile));
                File.WriteAllText(reportFile, report, Encoding.UTF8);
                session.ReportPath = reportFile;
            }
            catch (Exception ex)
            {
                Log("SandboxReportSaveError", "报告写入文件失败", ex.Message);
            }
        }

        private static string GenerateSummary(SandboxSession session)
        {
            var parts = new List<string>();

            if (session.Status == SandboxStatus.Timeout)
                parts.Add("程序执行超时被强制终止");

            if (session.RiskLevel == RiskLevel.Critical)
                parts.Add("行为高度可疑，判定为高危");
            else if (session.RiskLevel == RiskLevel.High)
                parts.Add("行为可疑，判定为高风险");
            else if (session.RiskLevel == RiskLevel.Medium)
                parts.Add("存在部分风险行为，建议进一步人工分析");
            else if (session.RiskLevel == RiskLevel.Low)
                parts.Add("行为轻微可疑，风险较低");
            else
                parts.Add("未观察到明显恶意行为");

            if (session.RegistryChanges.Any(r => r.IsAutorunLocation))
                parts.Add("尝试持久化（自启动）");
            if (session.FileChanges.Any(f => f.IsRansomwareIndicator))
                parts.Add("存在勒索软件加密特征");
            if (session.NetworkConnections.Any(n => KnownBadIps.Contains(n.RemoteAddress)))
                parts.Add("尝试连接已知恶意基础设施");
            if (session.ChildProcesses.Any(p => p.IsInjectionIndicator))
                parts.Add("存在进程注入/逃逸行为");

            return string.Join("；", parts) + "。";
        }

        private static string Truncate(string s, int max)
        {
            if (string.IsNullOrEmpty(s)) return "(无)";
            return s.Length <= max ? s : s.Substring(0, max) + $"... (共 {s.Length} 字符)";
        }

        #endregion

        #region 安全清理辅助

        /// <summary>安全删除目录（忽略错误）。</summary>
        private static void SafeDeleteDirectory(string path)
        {
            try
            {
                if (Directory.Exists(path))
                {
                    // 先清除只读属性
                    foreach (var f in Directory.GetFiles(path, "*", SearchOption.AllDirectories))
                    {
                        try { File.SetAttributes(f, FileAttributes.Normal); } catch { /* ignore */ }
                    }
                    Directory.Delete(path, true);
                }
            }
            catch { /* ignore */ }
        }

        /// <summary>安全终止一个进程树（通过 TrustedProcessGuard 保护系统进程）。</summary>
        private void SafeKillProcessTree(int rootPid)
        {
            try
            {
                // 先尝试枚举子进程并终止（注意不误杀受保护进程）
                foreach (var p in Process.GetProcesses())
                {
                    try
                    {
                        if (p.Id == rootPid) continue;
                        // 简单启发：无法精确取父 PID 时跳过
                    }
                    catch { /* ignore */ }
                    finally { try { p.Dispose(); } catch { /* ignore */ } }
                }

                if (!TrustedProcessGuard.CanTerminate(rootPid))
                {
                    Log("SandboxKillSkipped", "终止被跳过（受保护进程）", $"PID={rootPid}");
                    return;
                }
                try
                {
                    using (var p = Process.GetProcessById(rootPid))
                    {
                        p.Kill(entireProcessTree: true);
                    }
                }
                catch { /* 进程可能已退出 */ }
            }
            catch (Exception ex)
            {
                Log("SandboxKillError", "终止进程树异常", $"PID={rootPid}, {ex.Message}");
            }
        }

        #endregion

        #region 日志辅助

        private void Log(string type, string message, string details)
        {
            try
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = type,
                    Message = message,
                    Details = details ?? string.Empty,
                    Severity = "Info",
                    Source = "Sandbox",
                    Category = "Sandbox"
                });
            }
            catch { /* 防止日志失败影响主流程 */ }
        }

        #endregion

        #region IDisposable

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;

            lock (_sessionsLock)
            {
                foreach (var session in _activeSessions.ToList())
                {
                    try { CloseSandboxSession(session); } catch { /* ignore */ }
                }
            }
        }

        #endregion
    }
}
