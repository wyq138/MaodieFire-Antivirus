// 抖音用户 耄耋杀毒软件 开发，严禁非法反编译
// 抖音用户 耄耋杀毒软件 开发，严禁非法反编译
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace FireAntivirus.BehaviorAnalysis
{
    public class BehaviorAnalyzer
    {
        private CancellationTokenSource _cancellationTokenSource;
        private Task _analysisTask;
        private Dictionary<int, ProcessInfo> _monitoredProcesses;
        private List<BehaviorRule> _behaviorRules;

        public event EventHandler<BehaviorDetectedEventArgs> BehaviorDetected;



        public async Task StartAnalysis()
        {
            if (_analysisTask != null && !_analysisTask.IsCompleted)
            {
                return;
            }

            _cancellationTokenSource = new CancellationTokenSource();
            var token = _cancellationTokenSource.Token;

            _analysisTask = Task.Run(async () => {
                while (!token.IsCancellationRequested)
                {
                    try
                    {
                        // 监控进程创建
                        MonitorProcessCreation();

                        // 监控进程行为
                        await MonitorProcessBehavior();

                        // 监控网络行为
                        MonitorNetworkBehavior();

                        // 监控文件系统行为
                        MonitorFileSystemBehavior();

                        // 监控注册表行为
                        MonitorRegistryBehavior();

                        // 等待一段时间再进行下一次检查
                        await Task.Delay(1000, token);
                    }
                    catch (Exception ex)
                    {
                        // 记录错误但继续运行
                        Console.WriteLine($"行为分析错误: {ex.Message}");
                    }
                }
            }, token);
        }

        public void StopAnalysis()
        {
            if (_cancellationTokenSource != null)
            {
                _cancellationTokenSource.Cancel();
                _cancellationTokenSource.Dispose();
            }

            if (_analysisTask != null)
            {
                try
                {
                    _analysisTask.Wait(2000);
                }
                catch { }
            }

            _monitoredProcesses.Clear();
        }

        private void MonitorProcessCreation()
        {
            var currentProcesses = Process.GetProcesses();
            var currentProcessIds = currentProcesses.Select(p => p.Id).ToHashSet();
            var existingProcessIds = _monitoredProcesses.Keys.ToHashSet();

            // 检测新进程
            var newProcesses = currentProcesses.Where(p => !existingProcessIds.Contains(p.Id));
            foreach (var process in newProcesses)
            {
                try
                {
                    var processInfo = new ProcessInfo
                    {
                        ProcessId = process.Id,
                        ProcessName = process.ProcessName,
                        StartTime = DateTime.Now,
                        FilePath = GetProcessFilePath(process)
                    };

                    _monitoredProcesses[process.Id] = processInfo;

                    // 检查进程是否可疑
                    CheckSuspiciousProcess(processInfo);
                }
                catch { }
            }

            // 移除已结束的进程
            var endedProcesses = existingProcessIds.Where(id => !currentProcessIds.Contains(id));
            foreach (var processId in endedProcesses)
            {
                _monitoredProcesses.Remove(processId);
            }
        }

        private async Task MonitorProcessBehavior()
        {
            foreach (var processInfo in _monitoredProcesses.Values.ToList())
            {
                try
                {
                    var process = Process.GetProcessById(processInfo.ProcessId);

                    // 检查进程内存使用
                    CheckMemoryUsage(process, processInfo);

                    // 检查进程CPU使用
                    CheckCpuUsage(process, processInfo);

                    // 检查进程线程数
                    CheckThreadCount(process, processInfo);

                    // 检查进程模块
                    CheckProcessModules(process, processInfo);
                }
                catch { }
            }
        }

        private void MonitorNetworkBehavior()
        {
            var ipGlobalProperties = IPGlobalProperties.GetIPGlobalProperties();
            var tcpConnections = ipGlobalProperties.GetActiveTcpConnections();

            foreach (var connection in tcpConnections)
            {
                if (connection.State == TcpState.Established)
                {
                    try
                    {
                        // 检查可疑的网络连接
                        CheckSuspiciousNetworkConnection(connection);
                    }
                    catch { }
                }
            }
        }

        private void MonitorFileSystemBehavior()
        {
            // 只监控 Temp 目录和 Startup 目录，避免对 System32、ProgramFiles 等大型系统目录
            // 进行 FileSystemWatcher 监控（会产生海量文件变更事件造成 I/O 噪音和资源泄漏）
            string[] criticalDirectories = {
                Path.GetTempPath(),
                Environment.GetFolderPath(Environment.SpecialFolder.Startup)
            };

            foreach (var directory in criticalDirectories)
            {
                try
                {
                    if (Directory.Exists(directory))
                    {
                        CheckDirectoryChanges(directory);
                    }
                }
                catch { }
            }
        }

        private void MonitorRegistryBehavior()
        {
            // 监控关键注册表项
            string[] criticalRegistryKeys = {
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks",
                "SYSTEM\\CurrentControlSet\\Services"
            };

            foreach (var keyPath in criticalRegistryKeys)
            {
                try
                {
                    using (var key = Registry.LocalMachine.OpenSubKey(keyPath))
                    {
                        if (key != null)
                        {
                            CheckRegistryChanges(key, keyPath);
                        }
                    }
                }
                catch { }
            }
        }

        private void CheckSuspiciousProcess(ProcessInfo processInfo)
        {
            // 检查进程路径是否可疑
            if (string.IsNullOrEmpty(processInfo.FilePath))
            {
                OnBehaviorDetected(new BehaviorDetectedEventArgs
                {
                    ProcessName = processInfo.ProcessName,
                    BehaviorType = "可疑进程",
                    Details = "进程路径为空",
                    Timestamp = DateTime.Now
                });
                return;
            }

            // 检查进程是否位于临时目录
            string tempPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + "\\Temp";
            if (processInfo.FilePath.StartsWith(tempPath, StringComparison.OrdinalIgnoreCase))
            {
                OnBehaviorDetected(new BehaviorDetectedEventArgs
                {
                    ProcessName = processInfo.ProcessName,
                    BehaviorType = "可疑进程",
                    Details = "进程位于临时目录",
                    Timestamp = DateTime.Now
                });
                return;
            }

            // 检查进程名称是否可疑
            // 注意: cmd.exe 和 powershell.exe 是 Windows 核心系统工具，绝大多数情况是合法使用。
            // 只有当它们位于临时目录时（已在上方检查）才标记为可疑，此处不再无条件标记。
            string[] suspiciousProcessNames = { "wscript.exe", "cscript.exe" };
            if (suspiciousProcessNames.Contains(processInfo.ProcessName.ToLower()))
            {
                OnBehaviorDetected(new BehaviorDetectedEventArgs
                {
                    ProcessName = processInfo.ProcessName,
                    BehaviorType = "可疑进程",
                    Details = "使用了可能的命令执行工具",
                    Timestamp = DateTime.Now
                });
            }
        }

        private void CheckMemoryUsage(Process process, ProcessInfo processInfo)
        {
            try
            {
                var memoryUsage = process.WorkingSet64 / 1024 / 1024; // MB
                if (memoryUsage > 2000) // 超过2GB（现代浏览器等程序超过500MB是常态）
                {
                    OnBehaviorDetected(new BehaviorDetectedEventArgs
                    {
                        ProcessName = processInfo.ProcessName,
                        BehaviorType = "内存异常",
                        Details = $"内存使用过高: {memoryUsage}MB",
                        Timestamp = DateTime.Now
                    });
                }
            }
            catch { }
        }

        private void CheckCpuUsage(Process process, ProcessInfo processInfo)
        {
            try
            {
                // 注意：这种方法不是很准确，只是示例
                var cpuUsage = process.TotalProcessorTime.TotalMilliseconds;
                if (cpuUsage > 10000) // 超过10秒的CPU时间
                {
                    OnBehaviorDetected(new BehaviorDetectedEventArgs
                    {
                        ProcessName = processInfo.ProcessName,
                        BehaviorType = "CPU异常",
                        Details = $"CPU使用过高",
                        Timestamp = DateTime.Now
                    });
                }
            }
            catch { }
        }

        private void CheckThreadCount(Process process, ProcessInfo processInfo)
        {
            try
            {
                if (process.Threads.Count > 300)
                {
                    OnBehaviorDetected(new BehaviorDetectedEventArgs
                    {
                        ProcessName = processInfo.ProcessName,
                        BehaviorType = "线程异常",
                        Details = $"线程数量过多: {process.Threads.Count}",
                        Timestamp = DateTime.Now
                    });
                }
            }
            catch { }
        }

        private void CheckProcessModules(Process process, ProcessInfo processInfo)
        {
            try
            {
                foreach (ProcessModule module in process.Modules)
                {
                    if (module.FileName.Contains("inject"))
                    {
                        OnBehaviorDetected(new BehaviorDetectedEventArgs
                        {
                            ProcessName = processInfo.ProcessName,
                            BehaviorType = "模块注入",
                            Details = $"发现可疑模块: {module.FileName}",
                            Timestamp = DateTime.Now
                        });
                        break;
                    }
                }
            }
            catch { }
        }

        private void CheckSuspiciousNetworkConnection(TcpConnectionInformation connection)
        {
            // 检查连接到可疑端口
            int[] suspiciousPorts = { 4444, 1337, 31337, 6667, 23 };
            if (suspiciousPorts.Contains(connection.RemoteEndPoint.Port))
            {
                OnBehaviorDetected(new BehaviorDetectedEventArgs
                {
                    ProcessName = "网络连接",
                    BehaviorType = "可疑网络连接",
                    Details = $"连接到可疑端口: {connection.RemoteEndPoint}",
                    Timestamp = DateTime.Now
                });
            }
        }

        private Dictionary<string, FileSystemWatcher> _directoryWatchers;

        public BehaviorAnalyzer()
        {
            _monitoredProcesses = new Dictionary<int, ProcessInfo>();
            _behaviorRules = LoadBehaviorRules();
            _directoryWatchers = new Dictionary<string, FileSystemWatcher>();
            InitializeDirectoryWatchers();
        }

        private void InitializeDirectoryWatchers()
        {
            // 只监控 Temp 目录和 Startup 目录，避免对 System32、ProgramFiles 等大型系统目录
            // 进行 FileSystemWatcher 监控（会产生海量文件变更事件）
            string[] criticalDirectories = {
                Path.GetTempPath(),
                Environment.GetFolderPath(Environment.SpecialFolder.Startup)
            };

            foreach (var directory in criticalDirectories)
            {
                if (Directory.Exists(directory))
                {
                    var watcher = new FileSystemWatcher(directory);
                    watcher.IncludeSubdirectories = true;
                    watcher.NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.DirectoryName;
                    // 增大 InternalBufferSize 以防止缓冲区溢出导致的事件丢失和崩溃
                    watcher.InternalBufferSize = 64 * 1024; // 64KB，默认 8KB
                    watcher.Changed += OnDirectoryChanged;
                    watcher.Created += OnDirectoryChanged;
                    watcher.Deleted += OnDirectoryChanged;
                    watcher.Renamed += OnDirectoryRenamed;
                    watcher.EnableRaisingEvents = true;
                    _directoryWatchers[directory] = watcher;
                }
            }
        }

        private void OnDirectoryChanged(object sender, FileSystemEventArgs e)
        {
            OnBehaviorDetected(new BehaviorDetectedEventArgs
            {
                ProcessName = "文件系统",
                BehaviorType = "文件系统更改",
                Details = $"{e.ChangeType}: {e.FullPath}",
                Timestamp = DateTime.Now
            });
        }

        private void OnDirectoryRenamed(object sender, RenamedEventArgs e)
        {
            OnBehaviorDetected(new BehaviorDetectedEventArgs
            {
                ProcessName = "文件系统",
                BehaviorType = "文件重命名",
                Details = $"从 {e.OldFullPath} 重命名为 {e.FullPath}",
                Timestamp = DateTime.Now
            });
        }

        private void CheckDirectoryChanges(string directory)
        {
            // 已经使用FileSystemWatcher实现了目录监控
        }

        private void CheckRegistryChanges(RegistryKey key, string keyPath)
        {
            // 检查注册表项的变化
            var values = key.GetValueNames();
            foreach (var value in values)
            {
                var valueData = key.GetValue(value);
                // 检查可疑的注册表值
                // 加括号修正 operator 优先级，防止 valueData 为 null 时 NullReferenceException
                if (valueData != null && (valueData.ToString().Contains("cmd.exe") || valueData.ToString().Contains("powershell.exe")))
                {
                    OnBehaviorDetected(new BehaviorDetectedEventArgs
                    {
                        ProcessName = "注册表",
                        BehaviorType = "可疑注册表项",
                        Details = $"在 {keyPath} 中发现可疑值: {value} = {valueData}",
                        Timestamp = DateTime.Now
                    });
                }
            }
        }

        private string GetProcessFilePath(Process process)
        {
            try
            {
                return process.MainModule.FileName;
            }
            catch
            {
                return string.Empty;
            }
        }

        private List<BehaviorRule> LoadBehaviorRules()
        {
            // 加载行为规则
            return new List<BehaviorRule>
            {
                new BehaviorRule { Id = 1, Name = "可疑进程创建", Pattern = "temp\\.*\\exe", Severity = 8 },
                new BehaviorRule { Id = 2, Name = "内存注入", Pattern = "inject", Severity = 10 },
                new BehaviorRule { Id = 3, Name = "可疑网络连接", Pattern = "4444|1337|31337", Severity = 9 },
                new BehaviorRule { Id = 4, Name = "注册表自启动", Pattern = "Run\\\\.*", Severity = 7 },
                new BehaviorRule { Id = 5, Name = "系统文件修改", Pattern = "System32\\\\.*", Severity = 9 }
            };
        }

        protected virtual void OnBehaviorDetected(BehaviorDetectedEventArgs e)
        {
            BehaviorDetected?.Invoke(this, e);
        }

        public void Dispose()
        {
            StopAnalysis();
            foreach (var watcher in _directoryWatchers.Values)
            {
                try
                {
                    watcher.EnableRaisingEvents = false;
                    watcher.Dispose();
                }
                catch
                {
                    // 确保异常时也能释放其他 watcher
                }
            }
            _directoryWatchers.Clear();
        }
    }

    public class ProcessInfo
    {
        public int ProcessId { get; set; }
        public string ProcessName { get; set; }
        public DateTime StartTime { get; set; }
        public string FilePath { get; set; }
        public long MemoryUsage { get; set; }
        public int ThreadCount { get; set; }
    }

    public class BehaviorRule
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string Pattern { get; set; }
        public int Severity { get; set; }
    }

    public class BehaviorDetectedEventArgs : EventArgs
    {
        public string ProcessName { get; set; }
        public string BehaviorType { get; set; }
        public string Details { get; set; }
        public DateTime Timestamp { get; set; }
    }
}
