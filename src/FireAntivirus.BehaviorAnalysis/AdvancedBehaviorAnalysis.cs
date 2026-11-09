// 行为分析扩展模块 - 包含更多真实行为检测功能
using System;
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

namespace FireAntivirus.BehaviorAnalysis
{
    /// <summary>
    /// 高级行为监控器
    /// </summary>
    public class AdvancedBehaviorMonitor
    {
        private readonly DataManager _dataManager;
        private CancellationTokenSource _cancellationTokenSource;
        private Task _monitorTask;

        public AdvancedBehaviorMonitor(DataManager dataManager)
        {
            _dataManager = dataManager;
            _cancellationTokenSource = new CancellationTokenSource();
        }

        public void StartMonitoring()
        {
            if (_monitorTask != null && !_monitorTask.IsCompleted) return;

            _monitorTask = Task.Run(async () =>
            {
                while (!_cancellationTokenSource.Token.IsCancellationRequested)
                {
                    try
                    {
                        MonitorProcessCreation();
                        MonitorFileSystemActivity();
                        MonitorNetworkActivity();
                        MonitorRegistryActivity();
                        MonitorMemoryActivity();
                        await Task.Delay(1000, _cancellationTokenSource.Token);
                    }
                    catch (OperationCanceledException) { break; }
                    catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
                }
            });
        }

        public void StopMonitoring()
        {
            _cancellationTokenSource.Cancel();
        }

        private void MonitorProcessCreation()
        {
            // 检测可疑进程创建
            var suspiciousParents = new[] { "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe" };
            var suspiciousChildren = new[] { "net.exe", "net1.exe", "reg.exe", "attrib.exe", "cacls.exe" };

            try
            {
                foreach (var proc in Process.GetProcesses())
                {
                    try
                    {
                        var parentPid = GetParentProcessId(proc.Id);
                        if (parentPid <= 0) continue;

                        var parent = Process.GetProcessById(parentPid);
                        if (parent == null) continue;

                        var parentName = parent.ProcessName.ToLower();
                        var childName = proc.ProcessName.ToLower();

                        // 检测可疑进程链
                        if (suspiciousParents.Contains(parentName) && suspiciousChildren.Contains(childName))
                        {
                            FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                                $"可疑进程创建: {parentName} -> {childName}");
                        }

                        // 检测从临时目录启动的进程
                        var path = proc.MainModule?.FileName;
                        if (!string.IsNullOrEmpty(path) && path.StartsWith(Path.GetTempPath(), StringComparison.OrdinalIgnoreCase))
                        {
                            FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                                $"从临时目录启动的进程: {path}");
                        }
                    }
                    catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
                }
            }
            catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
        }

        private void MonitorFileSystemActivity()
        {
            // 监控敏感目录的文件操作
            var sensitivePaths = new[] {
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)
            };

            try
            {
                foreach (var path in sensitivePaths)
                {
                    if (Directory.Exists(path))
                    {
                        // 检查最近修改的可执行文件
                        var recentFiles = Directory.GetFiles(path, "*.exe", SearchOption.TopDirectoryOnly)
                            .Where(f => File.GetLastWriteTime(f) > DateTime.Now.AddHours(-1));

                        foreach (var file in recentFiles)
                        {
                            // 检查文件哈希
                            var hash = ComputeFileHash(file);
                            FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info,
                                $"系统目录文件修改: {file}, Hash: {hash}");
                        }
                    }
                }
            }
            catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
        }

        private void MonitorNetworkActivity()
        {
            try
            {
                var properties = IPGlobalProperties.GetIPGlobalProperties();
                var connections = properties.GetActiveTcpConnections();

                foreach (var conn in connections)
                {
                    // 检测可疑端口
                    var suspiciousPorts = new[] { 4444, 5555, 6666, 31337, 1337, 12345, 54321 };
                    if (suspiciousPorts.Contains(conn.RemoteEndPoint.Port))
                    {
                        FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                            $"可疑网络连接: {conn.RemoteEndPoint}");
                    }
                }
            }
            catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
        }

        private void MonitorRegistryActivity()
        {
            // 检测注册表启动项
            var autoRunPaths = new[] {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
            };

            try
            {
                foreach (var path in autoRunPaths)
                {
                    using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(path);
                    if (key != null)
                    {
                        foreach (var valueName in key.GetValueNames())
                        {
                            var value = key.GetValue(valueName)?.ToString();
                            if (!string.IsNullOrEmpty(value))
                            {
                                // 检查启动项的合法性
                                if (value.Contains(Path.GetTempPath()) || value.Contains("download"))
                                {
                                    FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                                        $"可疑启动项: {valueName} = {value}");
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
        }

        private void MonitorMemoryActivity()
        {
            // 检测可疑内存分配
            try
            {
                foreach (var proc in Process.GetProcesses())
                {
                    try
                    {
                        // 检测内存异常
                        if (proc.WorkingSet64 > 500 * 1024 * 1024) // > 500MB
                        {
                            // 进一步检查是否是可疑进程
                            var suspiciousProcs = new[] { "notepad.exe", "calc.exe", "cmd.exe" };
                            if (suspiciousProcs.Contains(proc.ProcessName, StringComparer.OrdinalIgnoreCase))
                            {
                                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                                    $"可疑高内存进程: {proc.ProcessName} 使用 {proc.WorkingSet64 / 1024 / 1024}MB");
                            }
                        }
                    }
                    catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
                }
            }
            catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
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
            catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
            return -1;
        }

        private string ComputeFileHash(string filePath)
        {
            try
            {
                using var stream = File.OpenRead(filePath);
                using var sha256 = SHA256.Create();
                var hash = sha256.ComputeHash(stream);
                return BitConverter.ToString(hash).Replace("-", "").Substring(0, 16);
            }
            catch
            {
                return "ERROR";
            }
        }
    }

    /// <summary>
    /// 异常行为检测器
    /// </summary>
    public class AnomalyDetector
    {
        private readonly DataManager _dataManager;
        private Dictionary<string, List<DateTime>> _behaviorHistory;

        public AnomalyDetector(DataManager dataManager)
        {
            _dataManager = dataManager;
            _behaviorHistory = new Dictionary<string, List<DateTime>>();
        }

        public List<AnomalyResult> DetectAnomalies()
        {
            var results = new List<AnomalyResult>();

            results.AddRange(DetectProcessAnomalies());
            results.AddRange(DetectNetworkAnomalies());
            results.AddRange(DetectFileSystemAnomalies());
            results.AddRange(DetectRegistryAnomalies());

            return results;
        }

        private List<AnomalyResult> DetectProcessAnomalies()
        {
            var results = new List<AnomalyResult>();

            try
            {
                var processCount = Process.GetProcesses().Length;
                if (processCount > 300)
                {
                    results.Add(new AnomalyResult
                    {
                        Type = "Process Count",
                        Severity = "High",
                        Description = $"进程数量异常: {processCount}",
                        Timestamp = DateTime.Now
                    });
                }

                // 检测快速重启的进程
                var procPath = @"C:\Windows\System32";
                if (Directory.Exists(procPath))
                {
                    var criticalProcs = new[] { "explorer.exe", "svchost.exe", "csrss.exe", "winlogon.exe" };
                    foreach (var procName in criticalProcs)
                    {
                        var procs = Process.GetProcessesByName(procName);
                        if (procs.Length == 0)
                        {
                            results.Add(new AnomalyResult
                            {
                                Type = "Critical Process",
                                Severity = "Critical",
                                Description = $"关键进程缺失: {procName}",
                                Timestamp = DateTime.Now
                            });
                        }
                    }
                }
            }
            catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }

            return results;
        }

        private List<AnomalyResult> DetectNetworkAnomalies()
        {
            var results = new List<AnomalyResult>();

            try
            {
                var properties = IPGlobalProperties.GetIPGlobalProperties();
                var tcpConnections = properties.GetActiveTcpConnections();

                if (tcpConnections.Length > 1000)
                {
                    results.Add(new AnomalyResult
                    {
                        Type = "Network Connections",
                        Severity = "Medium",
                        Description = $"网络连接数异常: {tcpConnections.Length}",
                        Timestamp = DateTime.Now
                    });
                }

                // 检测同一IP的大量连接
                var ipCounts = tcpConnections.GroupBy(c => c.RemoteEndPoint.Address.ToString())
                    .Where(g => g.Count() > 50);

                foreach (var group in ipCounts)
                {
                    results.Add(new AnomalyResult
                    {
                        Type = "DDoS Pattern",
                        Severity = "High",
                        Description = $"检测到可疑连接模式: {group.Key} 有 {group.Count()} 个连接",
                        Timestamp = DateTime.Now
                    });
                }
            }
            catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }

            return results;
        }

        private List<AnomalyResult> DetectFileSystemAnomalies()
        {
            var results = new List<AnomalyResult>();

            try
            {
                // 检测系统目录的可执行文件创建
                var systemDir = Environment.GetFolderPath(Environment.SpecialFolder.System);
                var recentExes = Directory.GetFiles(systemDir, "*.exe", SearchOption.TopDirectoryOnly)
                    .Where(f => File.GetCreationTime(f) > DateTime.Now.AddHours(-1));

                if (recentExes.Count() > 5)
                {
                    results.Add(new AnomalyResult
                    {
                        Type = "System File Creation",
                        Severity = "High",
                        Description = $"系统目录最近创建了 {recentExes.Count()} 个可执行文件",
                        Timestamp = DateTime.Now
                    });
                }
            }
            catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }

            return results;
        }

        private List<AnomalyResult> DetectRegistryAnomalies()
        {
            var results = new List<AnomalyResult>();

            try
            {
                // 检测注册表启动项变化
                var runKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(runKey);
                if (key != null)
                {
                    var count = key.GetValueNames().Length;
                    if (count > 20)
                    {
                        results.Add(new AnomalyResult
                        {
                            Type = "Registry Startup Items",
                            Severity = "Medium",
                            Description = $"注册表启动项过多: {count}个",
                            Timestamp = DateTime.Now
                        });
                    }
                }
            }
            catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }

            return results;
        }
    }

    /// <summary>
    /// 行为规则引擎
    /// </summary>
    public class BehaviorRuleEngine
    {
        private readonly DataManager _dataManager;
        private List<BehaviorRule> _rules;

        public BehaviorRuleEngine(DataManager dataManager)
        {
            _dataManager = dataManager;
            InitializeRules();
        }

        private void InitializeRules()
        {
            _rules = new List<BehaviorRule>
            {
                new BehaviorRule { Name = "Suspicious Process Creation", Pattern = @"(cmd|powershell)\.exe.*(net|reg|attrib)", Severity = 8 },
                new BehaviorRule { Name = "PowerShell Encoded Command", Pattern = @"-enc\s+[A-Za-z0-9+/=]{20,}", Severity = 9 },
                new BehaviorRule { Name = "Temporary File Execution", Pattern = @"%temp%.*\.exe", Severity = 7 },
                new BehaviorRule { Name = "Suspicious Network Port", Pattern = @":(4444|5555|6666|31337|1337)\s", Severity = 8 },
                new BehaviorRule { Name = "Registry Modification", Pattern = @"reg\s+(add|delete|import)", Severity = 6 },
                new BehaviorRule { Name = "Service Creation", Pattern = @"sc\s+create", Severity = 8 },
                new BehaviorRule { Name = "Scheduled Task", Pattern = @"schtasks\s+/create", Severity = 7 },
                new BehaviorRule { Name = "WMI Execution", Pattern = @"wmic\s+(process|service)", Severity = 7 },
                new BehaviorRule { Name = "DLL Injection", Pattern = @"(CreateRemoteThread|VirtualAllocEx).*dll", Severity = 9 },
                new BehaviorRule { Name = "Credential Access", Pattern = @"(mimikatz|lsass|pwdump)", Severity = 10 },
                new BehaviorRule { Name = "Lateral Movement", Pattern = @"(psexec|wmi|winrm).*\\", Severity = 9 },
                new BehaviorRule { Name = "Data Exfiltration", Pattern = @"(ftp|http).*upload", Severity = 8 },
                new BehaviorRule { Name = "Persistence Mechanism", Pattern = @"(runonce|autostart|scheduler).*(malware|backdoor)", Severity = 10 },
                new BehaviorRule { Name = "Process Hollowing", Pattern = @"(NtUnmapViewOfSection|SetThreadContext).*(suspended)", Severity = 10 },
                new BehaviorRule { Name = "AMSI Bypass", Pattern = @"(amsi|am_si).*(bypass|patch|disable)", Severity = 9 }
            };
        }

        public List<RuleMatchResult> EvaluateBehavior(string behavior)
        {
            var results = new List<RuleMatchResult>();

            foreach (var rule in _rules)
            {
                if (Regex.IsMatch(behavior, rule.Pattern, RegexOptions.IgnoreCase))
                {
                    results.Add(new RuleMatchResult
                    {
                        RuleName = rule.Name,
                        MatchedPattern = rule.Pattern,
                        Severity = rule.Severity,
                        Details = $"行为 '{behavior}' 匹配规则 '{rule.Name}'"
                    });
                }
            }

            return results;
        }
    }

    /// <summary>
    /// 行为白名单管理器
    /// </summary>
    public class WhitelistManager
    {
        private HashSet<string> _processWhitelist;
        private HashSet<string> _pathWhitelist;
        private HashSet<string> _hashWhitelist;

        public WhitelistManager()
        {
            _processWhitelist = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _pathWhitelist = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _hashWhitelist = new HashSet<string>();
            InitializeWhitelists();
        }

        private void InitializeWhitelists()
        {
            // Windows系统进程白名单
            var systemProcesses = new[] {
                "System", "Registry", "smss.exe", "csrss.exe", "wininit.exe",
                "services.exe", "lsass.exe", "svchost.exe", "winlogon.exe",
                "dwm.exe", "explorer.exe", "taskhostw.exe", "RuntimeBroker.exe",
                "SearchIndexer.exe", "SecurityHealthService.exe", "MsMpEng.exe",
                "conhost.exe", "fontdrvhost.exe", "sihost.exe", "dllhost.exe"
            };

            foreach (var proc in systemProcesses)
            {
                _processWhitelist.Add(proc);
            }

            // Windows系统路径白名单
            var systemPaths = new[] {
                @"C:\Windows\System32",
                @"C:\Windows\SysWOW64",
                @"C:\Windows\WinSxS",
                @"C:\Program Files",
                @"C:\Program Files (x86)"
            };

            foreach (var path in systemPaths)
            {
                _pathWhitelist.Add(path);
            }

            // 常见安全软件进程白名单
            var securityProcesses = new[] {
                "MsMpEng.exe", "NisSrv.exe", "SgrmBroker.exe",
                "SecurityHealthService.exe", "MpDefenderCoreService.exe",
                "avp.exe", "ksafe.exe", "360sd.exe", "QQPCTray.exe"
            };

            foreach (var proc in securityProcesses)
            {
                _processWhitelist.Add(proc);
            }
        }

        public bool IsProcessWhitelisted(string processName)
        {
            return _processWhitelist.Contains(processName);
        }

        public bool IsPathWhitelisted(string filePath)
        {
            return _pathWhitelist.Any(p => filePath.StartsWith(p, StringComparison.OrdinalIgnoreCase));
        }

        public bool IsHashWhitelisted(string hash)
        {
            return _hashWhitelist.Contains(hash);
        }

        public void AddToWhitelist(WhitelistType type, string value)
        {
            switch (type)
            {
                case WhitelistType.Process:
                    _processWhitelist.Add(value);
                    break;
                case WhitelistType.Path:
                    _pathWhitelist.Add(value);
                    break;
                case WhitelistType.Hash:
                    _hashWhitelist.Add(value);
                    break;
            }
        }

        public void RemoveFromWhitelist(WhitelistType type, string value)
        {
            switch (type)
            {
                case WhitelistType.Process:
                    _processWhitelist.Remove(value);
                    break;
                case WhitelistType.Path:
                    _pathWhitelist.Remove(value);
                    break;
                case WhitelistType.Hash:
                    _hashWhitelist.Remove(value);
                    break;
            }
        }
    }

    /// <summary>
    /// 行为分析报告生成器
    /// </summary>
    public class BehaviorReportGenerator
    {
        private readonly DataManager _dataManager;

        public BehaviorReportGenerator(DataManager dataManager)
        {
            _dataManager = dataManager;
        }

        public BehaviorReport GenerateReport()
        {
            var report = new BehaviorReport
            {
                GeneratedTime = DateTime.Now,
                ProcessCount = Process.GetProcesses().Length,
                NetworkConnections = GetNetworkConnectionCount(),
                RunningServices = GetRunningServiceCount()
            };

            // 收集进程行为
            report.ProcessBehaviors = CollectProcessBehaviors();

            // 收集网络行为
            report.NetworkBehaviors = CollectNetworkBehaviors();

            // 收集文件操作行为
            report.FileBehaviors = CollectFileBehaviors();

            // 评估整体风险
            report.RiskLevel = EvaluateRiskLevel(report);

            return report;
        }

        private int GetNetworkConnectionCount()
        {
            try
            {
                var properties = IPGlobalProperties.GetIPGlobalProperties();
                return properties.GetActiveTcpConnections().Length;
            }
            catch { return 0; }
        }

        private int GetRunningServiceCount()
        {
            try
            {
                return System.ServiceProcess.ServiceController.GetServices().Length;
            }
            catch { return 0; }
        }

        private List<ProcessBehavior> CollectProcessBehaviors()
        {
            var behaviors = new List<ProcessBehavior>();
            try
            {
                foreach (var proc in Process.GetProcesses())
                {
                    try
                    {
                        behaviors.Add(new ProcessBehavior
                        {
                            ProcessName = proc.ProcessName,
                            PID = proc.Id,
                            MemoryUsage = proc.WorkingSet64,
                            ThreadCount = proc.Threads.Count,
                            StartTime = GetProcessStartTime(proc)
                        });
                    }
                    catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
                }
            }
            catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
            return behaviors;
        }

        private DateTime GetProcessStartTime(Process proc)
        {
            try
            {
                return proc.StartTime;
            }
            catch
            {
                return DateTime.MinValue;
            }
        }

        private List<NetworkBehavior> CollectNetworkBehaviors()
        {
            var behaviors = new List<NetworkBehavior>();
            try
            {
                var properties = IPGlobalProperties.GetIPGlobalProperties();
                var connections = properties.GetActiveTcpConnections();

                foreach (var conn in connections)
                {
                    behaviors.Add(new NetworkBehavior
                    {
                        LocalEndpoint = conn.LocalEndPoint.ToString(),
                        RemoteEndpoint = conn.RemoteEndPoint.ToString(),
                        State = conn.State.ToString()
                    });
                }
            }
            catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
            return behaviors;
        }

        private List<FileBehavior> CollectFileBehaviors()
        {
            var behaviors = new List<FileBehavior>();

            // 检测临时目录中的可执行文件
            try
            {
                var tempPath = Path.GetTempPath();
                var exeFiles = Directory.GetFiles(tempPath, "*.exe", SearchOption.AllDirectories);

                foreach (var file in exeFiles)
                {
                    behaviors.Add(new FileBehavior
                    {
                        FilePath = file,
                        Operation = "Create",
                        Timestamp = File.GetCreationTime(file)
                    });
                }
            }
            catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }

            return behaviors;
        }

        private string EvaluateRiskLevel(BehaviorReport report)
        {
            var riskScore = 0;

            if (report.ProcessCount > 200) riskScore += 2;
            if (report.NetworkConnections > 500) riskScore += 3;
            if (report.FileBehaviors.Count > 10) riskScore += 2;

            if (riskScore >= 7) return "High";
            if (riskScore >= 4) return "Medium";
            return "Low";
        }
    }

    /// <summary>
    /// 辅助类
    /// </summary>
    public class RuleMatchResult
    {
        public string RuleName { get; set; }
        public string MatchedPattern { get; set; }
        public int Severity { get; set; }
        public string Details { get; set; }
    }

    public class AnomalyResult
    {
        public string Type { get; set; }
        public string Severity { get; set; }
        public string Description { get; set; }
        public DateTime Timestamp { get; set; }
    }

    public enum WhitelistType
    {
        Process,
        Path,
        Hash
    }

    public class BehaviorReport
    {
        public DateTime GeneratedTime { get; set; }
        public int ProcessCount { get; set; }
        public int NetworkConnections { get; set; }
        public int RunningServices { get; set; }
        public string RiskLevel { get; set; }
        public List<ProcessBehavior> ProcessBehaviors { get; set; }
        public List<NetworkBehavior> NetworkBehaviors { get; set; }
        public List<FileBehavior> FileBehaviors { get; set; }
    }

    public class ProcessBehavior
    {
        public string ProcessName { get; set; }
        public int PID { get; set; }
        public long MemoryUsage { get; set; }
        public int ThreadCount { get; set; }
        public DateTime StartTime { get; set; }
    }

    public class NetworkBehavior
    {
        public string LocalEndpoint { get; set; }
        public string RemoteEndpoint { get; set; }
        public string State { get; set; }
    }

    public class FileBehavior
    {
        public string FilePath { get; set; }
        public string Operation { get; set; }
        public DateTime Timestamp { get; set; }
    }


}
