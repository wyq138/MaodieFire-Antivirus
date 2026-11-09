using FireAntivirus.Common;
using FireAntivirus.Data;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace FireAntivirus.Services
{
    public class BehaviorAnalysis
    {
        // 系统服务白名单 - 这些进程不会被标记为可疑
        private static readonly HashSet<string> SystemServiceWhitelist = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            // Windows核心进程
            "svchost.exe", "services.exe", "lsass.exe", "csrss.exe",
            "wininit.exe", "winlogon.exe", "smss.exe", "dwm.exe",
            "explorer.exe", "runtimebroker.exe", "searchindexer.exe",
            "spoolsv.exe", "system", "system idle process",
            // Windows服务
            "wuauserv.exe", "bits.exe", "eventlog.exe", "dns.exe",
            "dhcp.exe", "lanmanserver.exe", "lanmanworkstation.exe",
            // 安全软件相关
            "msmpeng.exe", "nissrv.exe", "securityhealthservice.exe",
            // 常见系统工具（单独运行通常无害）
            "notepad.exe", "calc.exe", "mspaint.exe", "wordpad.exe",
            // 开发工具（减少误报）
            "devenv.exe", "code.exe", "idea64.exe", "dotnet.exe",
            "msbuild.exe", "nuget.exe"
        };

        // 受信任的路径前缀
        private static readonly string[] TrustedPaths = new string[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            Environment.SystemDirectory,
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + "\\Microsoft",
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86) + "\\Windows Kits"
        };

        // 提高检测阈值，减少误报
        private const double SuspiciousThreshold = 0.8; // 原来是0.5

        private readonly string _logDirectory;
        private int _maxLogSize;
        private int _analysisInterval;
        private readonly int _maxProcesses;
        private readonly int _maxNetworkConnections;
        private readonly int _maxFileOperations;
        private bool _enableRealTimeMonitoring;
        private bool _enableNetworkMonitoring;
        private bool _enableFileMonitoring;
        private bool _enableRegistryMonitoring;
        private bool _enableProcessMonitoring;
        private readonly object _lockObject = new object();
        private readonly Dictionary<int, ProcessInfo> _processes = new Dictionary<int, ProcessInfo>();
        private readonly Dictionary<string, BehaviorNetworkConnectionInfo> _networkConnections = new Dictionary<string, BehaviorNetworkConnectionInfo>();
        private readonly Dictionary<string, FileOperationInfo> _fileOperations = new Dictionary<string, FileOperationInfo>();
        private readonly Dictionary<string, RegistryOperationInfo> _registryOperations = new Dictionary<string, RegistryOperationInfo>();
        private CancellationTokenSource _cancellationTokenSource;
        private Task _monitoringTask;

        public event EventHandler<BehaviorAnalysisEventArgs> BehaviorAnalysisEvent;

        public BehaviorAnalysis(string logDirectory = null, int analysisInterval = 1000, int maxLogSize = 10485760)
        {
            _logDirectory = logDirectory ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "FireAntivirus", "BehaviorLogs");
            _analysisInterval = analysisInterval;
            _maxLogSize = maxLogSize;
            _maxProcesses = 1000;
            _maxNetworkConnections = 500;
            _maxFileOperations = 2000;
            _enableRealTimeMonitoring = true;
            _enableNetworkMonitoring = true;
            _enableFileMonitoring = true;
            _enableRegistryMonitoring = true;
            _enableProcessMonitoring = true;

            InitializeDirectories();
        }

        private void InitializeDirectories()
        {
            if (!Directory.Exists(_logDirectory))
            {
                Directory.CreateDirectory(_logDirectory);
            }
        }

        public void StartMonitoring()
        {
            if (_monitoringTask != null && !_monitoringTask.IsCompleted)
            {
                return;
            }

            _cancellationTokenSource = new CancellationTokenSource();
            _monitoringTask = Task.Run(async () => await MonitorAsync(_cancellationTokenSource.Token), _cancellationTokenSource.Token);
            RaiseBehaviorAnalysisEvent(new BehaviorAnalysisEventArgs(BehaviorAnalysisEventType.Info, "Behavior monitoring started"));
        }

        public void StopMonitoring()
        {
            if (_cancellationTokenSource != null)
            {
                _cancellationTokenSource.Cancel();
                _cancellationTokenSource = null;
            }

            if (_monitoringTask != null)
            {
                _monitoringTask.Wait(1000);
                _monitoringTask = null;
            }

            RaiseBehaviorAnalysisEvent(new BehaviorAnalysisEventArgs(BehaviorAnalysisEventType.Info, "Behavior monitoring stopped"));
        }

        private async Task MonitorAsync(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    if (_enableProcessMonitoring)
                    {
                        await MonitorProcessesAsync();
                    }

                    if (_enableNetworkMonitoring)
                    {
                        await MonitorNetworkConnectionsAsync();
                    }

                    if (_enableFileMonitoring)
                    {
                        await MonitorFileOperationsAsync();
                    }

                    if (_enableRegistryMonitoring)
                    {
                        await MonitorRegistryOperationsAsync();
                    }

                    await Task.Delay(_analysisInterval, cancellationToken);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    Logger.Error($"Behavior monitoring error: {ex.Message}");
                    RaiseBehaviorAnalysisEvent(new BehaviorAnalysisEventArgs(BehaviorAnalysisEventType.Error, $"Monitoring error: {ex.Message}"));
                }
            }
        }

        private async Task MonitorProcessesAsync()
        {
            try
            {
                var currentProcesses = Process.GetProcesses();
                var newProcesses = new List<ProcessInfo>();
                var terminatedProcesses = new List<ProcessInfo>();

                lock (_lockObject)
                {
                    // 检测新进程
                    foreach (var process in currentProcesses)
                    {
                        if (!_processes.ContainsKey(process.Id))
                        {
                            var processInfo = CreateProcessInfo(process);
                            _processes[process.Id] = processInfo;
                            newProcesses.Add(processInfo);
                        }
                        else
                        {
                            // 更新现有进程信息
                            UpdateProcessInfo(_processes[process.Id], process);
                        }
                    }

                    // 检测终止的进程
                    var processIdsToRemove = new List<int>();
                    foreach (var kvp in _processes)
                    {
                        if (!currentProcesses.Any(p => p.Id == kvp.Key))
                        {
                            terminatedProcesses.Add(kvp.Value);
                            processIdsToRemove.Add(kvp.Key);
                        }
                    }

                    foreach (var processId in processIdsToRemove)
                    {
                        _processes.Remove(processId);
                    }

                    // 限制进程数量
                    if (_processes.Count > _maxProcesses)
                    {
                        var oldestProcesses = _processes.OrderBy(p => p.Value.StartTime).Take(_processes.Count - _maxProcesses).ToList();
                        foreach (var process in oldestProcesses)
                        {
                            _processes.Remove(process.Key);
                        }
                    }
                }

                // 分析新进程
                foreach (var processInfo in newProcesses)
                {
                    await AnalyzeProcessAsync(processInfo);
                }

                // 记录终止的进程
                foreach (var processInfo in terminatedProcesses)
                {
                    LogProcessTermination(processInfo);
                }
            }
            catch (Exception ex)
            {
                Logger.Error($"Process monitoring error: {ex.Message}");
            }
        }

        private async Task MonitorNetworkConnectionsAsync()
        {
            try
            {
                var connections = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections();
                var newConnections = new List<BehaviorNetworkConnectionInfo>();
                var closedConnections = new List<BehaviorNetworkConnectionInfo>();

                lock (_lockObject)
                {
                    // 检测新连接
                    foreach (var connection in connections)
                    {
                        var connectionKey = $"{connection.LocalEndPoint}-{connection.RemoteEndPoint}";
                        if (!_networkConnections.ContainsKey(connectionKey))
                        {
                            var connectionInfo = CreateBehaviorNetworkConnectionInfo(connection);
                            _networkConnections[connectionKey] = connectionInfo;
                            newConnections.Add(connectionInfo);
                        }
                        else
                        {
                            // 更新现有连接信息
                            UpdateBehaviorNetworkConnectionInfo(_networkConnections[connectionKey], connection);
                        }
                    }

                    // 检测关闭的连接
                    var connectionKeysToRemove = new List<string>();
                    foreach (var kvp in _networkConnections)
                    {
                        if (!connections.Any(c => $"{c.LocalEndPoint}-{c.RemoteEndPoint}" == kvp.Key))
                        {
                            closedConnections.Add(kvp.Value);
                            connectionKeysToRemove.Add(kvp.Key);
                        }
                    }

                    foreach (var connectionKey in connectionKeysToRemove)
                    {
                        _networkConnections.Remove(connectionKey);
                    }

                    // 限制连接数量
                    if (_networkConnections.Count > _maxNetworkConnections)
                    {
                        var oldestConnections = _networkConnections.OrderBy(c => c.Value.StartTime).Take(_networkConnections.Count - _maxNetworkConnections).ToList();
                        foreach (var connection in oldestConnections)
                        {
                            _networkConnections.Remove(connection.Key);
                        }
                    }
                }

                // 分析新连接
                foreach (var connectionInfo in newConnections)
                {
                    await AnalyzeNetworkConnectionAsync(connectionInfo);
                }

                // 记录关闭的连接
                foreach (var connectionInfo in closedConnections)
                {
                    LogNetworkConnectionClose(connectionInfo);
                }
            }
            catch (Exception ex)
            {
                Logger.Error($"Network monitoring error: {ex.Message}");
            }
        }

        private async Task MonitorFileOperationsAsync()
        {
            try
            {
                // 这里实现文件操作监控
                // 实际应用中应该使用文件系统过滤器驱动或Windows API钩子
                await Task.CompletedTask;
            }
            catch (Exception ex)
            {
                Logger.Error($"File monitoring error: {ex.Message}");
            }
        }

        private async Task MonitorRegistryOperationsAsync()
        {
            try
            {
                // 这里实现注册表操作监控
                // 实际应用中应该使用Windows API钩子或WMI事件
                await Task.CompletedTask;
            }
            catch (Exception ex)
            {
                Logger.Error($"Registry monitoring error: {ex.Message}");
            }
        }

        private async Task AnalyzeProcessAsync(ProcessInfo processInfo)
        {
            try
            {
                // 首先检查白名单 - 白名单进程直接跳过分析
                if (SystemServiceWhitelist.Contains(processInfo.ProcessName))
                {
                    return; // 白名单进程，不进行可疑分析
                }

                var analysisResult = new BehaviorAnalysisResult
                {
                    AnalysisType = AnalysisType.Process,
                    Target = processInfo.ProcessName,
                    Score = 0.0,
                    Details = new List<string>(),
                    Timestamp = DateTime.UtcNow
                };

                // 检查进程路径
                if (string.IsNullOrEmpty(processInfo.FilePath))
                {
                    // 某些系统进程没有路径，但这不一定是可疑的
                    // 只记录，不加分
                    analysisResult.Details.Add("Process path not available (may be system process)");
                }
                else
                {
                    // 检查是否在受信任路径
                    bool isTrustedPath = TrustedPaths.Any(path => 
                        !string.IsNullOrEmpty(path) && 
                        processInfo.FilePath.StartsWith(path, StringComparison.OrdinalIgnoreCase));

                    if (isTrustedPath)
                    {
                        // 受信任路径的进程，降低基础分数
                        analysisResult.Details.Add("Process in trusted path");
                    }
                    else
                    {
                        // 非受信任路径才加分
                        analysisResult.Score += 0.1;
                        analysisResult.Details.Add("Process not in trusted directory");
                    }

                    // 检查文件是否存在
                    if (!File.Exists(processInfo.FilePath))
                    {
                        analysisResult.Score += 0.2; // 降低权重
                        analysisResult.Details.Add("Process file not found");
                    }
                }

                // 检查进程名称 - 只有在非受信任路径时才检查
                var suspiciousProcessNames = new List<string> { "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe" };
                if (suspiciousProcessNames.Contains(processInfo.ProcessName.ToLower()))
                {
                    // 只有当有可疑命令行参数时才加分
                    if (!string.IsNullOrEmpty(processInfo.CommandLine))
                    {
                        var suspiciousCommands = new List<string> { "-EncodedCommand", "-ExecutionPolicy Bypass", "-WindowStyle Hidden", "Bypass" };
                        bool hasSuspiciousCommand = suspiciousCommands.Any(cmd => 
                            processInfo.CommandLine.Contains(cmd, StringComparison.OrdinalIgnoreCase));
                        
                        if (hasSuspiciousCommand)
                        {
                            analysisResult.Score += 0.3;
                            analysisResult.Details.Add("Suspicious command line parameter detected");
                        }
                    }
                }

                // 检查命令行参数（更精确的检测）
                if (!string.IsNullOrEmpty(processInfo.CommandLine))
                {
                    // 只检测真正危险的命令行参数组合
                    var dangerousCommands = new List<string> { 
                        "-EncodedCommand", "-ExecutionPolicy Bypass", "-WindowStyle Hidden",
                        "IEX", "DownloadString", "DownloadFile", "Invoke-Expression",
                        "FromBase64String", "Net.WebClient" 
                    };
                    int suspiciousCount = 0;
                    foreach (var command in dangerousCommands)
                    {
                        if (processInfo.CommandLine.Contains(command, StringComparison.OrdinalIgnoreCase))
                        {
                            suspiciousCount++;
                        }
                    }
                    if (suspiciousCount >= 2) // 至少两个可疑参数才标记
                    {
                        analysisResult.Score += 0.4;
                        analysisResult.Details.Add("Multiple suspicious command line parameters detected");
                    }
                }

                // 检查父进程 - 放宽条件
                if (processInfo.ParentProcessId > 0)
                {
                    try
                    {
                        var parentProcess = Process.GetProcessById(processInfo.ParentProcessId);
                        if (parentProcess != null)
                        {
                            // 只有explorer.exe作为powershell/cmd的父进程才略微可疑
                            if (parentProcess.ProcessName.ToLower() == "explorer.exe")
                            {
                                if (suspiciousProcessNames.Contains(processInfo.ProcessName.ToLower()))
                                {
                                    analysisResult.Score += 0.05; // 大幅降低权重
                                    analysisResult.Details.Add("Script launched from explorer");
                                }
                            }
                        }
                    }
                    catch
                    {
                        // 父进程可能已结束，这很正常
                    }
                }

                // 使用更高的阈值判断
                if (analysisResult.Score >= SuspiciousThreshold)
                {
                    analysisResult.IsSuspicious = true;
                    RaiseBehaviorAnalysisEvent(new BehaviorAnalysisEventArgs(BehaviorAnalysisEventType.Warning, 
                        $"Suspicious process detected: {processInfo.ProcessName} (score: {analysisResult.Score:F2})"));
                }

                // 记录分析结果
                LogAnalysisResult(analysisResult);
            }
            catch (Exception ex)
            {
                Logger.Error($"Process analysis error: {ex.Message}");
            }
        }

        private async Task AnalyzeNetworkConnectionAsync(BehaviorNetworkConnectionInfo connectionInfo)
        {
            try
            {
                var analysisResult = new BehaviorAnalysisResult
                {
                    AnalysisType = AnalysisType.Network,
                    Target = connectionInfo.RemoteEndPoint.ToString(),
                    Score = 0.0,
                    Details = new List<string>(),
                    Timestamp = DateTime.UtcNow
                };

                // 检查远程IP地址
                var ipAddress = connectionInfo.RemoteEndPoint.Address.ToString();
                if (ipAddress == "127.0.0.1" || ipAddress.StartsWith("192.168.") || ipAddress.StartsWith("10.") || ipAddress.StartsWith("172.16."))
                {
                    // 本地网络，风险较低
                }
                else
                {
                    // 真实威胁情报判定（Feodo C2 IP 库/abuse.ch 实时库）：
                    // 此前用 {"8.8.8.8","8.8.4.4"} 当可疑 IP = 假数据且把 Google 公共 DNS 误判为恶意
                    bool knownBadIp = false;
                    try { knownBadIp = FireAntivirus.Engine.SignatureDatabaseUpdater.IsMaliciousIp(ipAddress); }
                    catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }

                    if (knownBadIp)
                    {
                        analysisResult.Score += 0.3;
                        analysisResult.Details.Add("命中威胁情报恶意 IP（Feodo/abuse.ch 实时库）");
                    }
                }

                // 检查端口
                var port = connectionInfo.RemoteEndPoint.Port;
                var suspiciousPorts = new List<int> { 21, 22, 23, 25, 445, 1433, 3306, 3389, 5432, 8080 };
                if (suspiciousPorts.Contains(port))
                {
                    analysisResult.Score += 0.2;
                    analysisResult.Details.Add($"Suspicious port: {port}");
                }

                // 检查连接状态
                if (connectionInfo.State == TcpState.Established)
                {
                    analysisResult.Score += 0.1;
                    analysisResult.Details.Add("Established connection");
                }

                // 使用更高的阈值判断（网络连接）
                if (analysisResult.Score >= SuspiciousThreshold)
                {
                    analysisResult.IsSuspicious = true;
                    RaiseBehaviorAnalysisEvent(new BehaviorAnalysisEventArgs(BehaviorAnalysisEventType.Warning, 
                        $"Suspicious network connection detected: {connectionInfo.RemoteEndPoint} (score: {analysisResult.Score:F2})"));
                }

                // 记录分析结果
                LogAnalysisResult(analysisResult);
            }
            catch (Exception ex)
            {
                Logger.Error($"Network connection analysis error: {ex.Message}");
            }
        }

        private ProcessInfo CreateProcessInfo(Process process)
        {
            var processInfo = new ProcessInfo
            {
                ProcessId = process.Id,
                ProcessName = process.ProcessName,
                StartTime = process.StartTime,
                FilePath = GetProcessFilePath(process),
                CommandLine = GetProcessCommandLine(process),
                ParentProcessId = GetParentProcessId(process.Id),
                MemoryUsage = process.WorkingSet64,
                CpuUsage = 0.0
            };

            return processInfo;
        }

        private void UpdateProcessInfo(ProcessInfo processInfo, Process process)
        {
            try
            {
                processInfo.MemoryUsage = process.WorkingSet64;
                // 计算CPU使用率（简化处理）
                processInfo.CpuUsage = 0.0;
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "BehaviorAnalysis.cs 捕获异常", ex.Message); }
        }

        private BehaviorNetworkConnectionInfo CreateBehaviorNetworkConnectionInfo(TcpConnectionInformation connection)
        {
            return new BehaviorNetworkConnectionInfo
            {
                LocalEndPoint = connection.LocalEndPoint,
                RemoteEndPoint = connection.RemoteEndPoint,
                State = connection.State,
                StartTime = DateTime.UtcNow
            };
        }

        private void UpdateBehaviorNetworkConnectionInfo(BehaviorNetworkConnectionInfo connectionInfo, TcpConnectionInformation connection)
        {
            connectionInfo.State = connection.State;
        }

        private string GetProcessFilePath(Process process)
        {
            try
            {
                return process.MainModule.FileName;
            }
            catch
            {
                return null;
            }
        }

        private string GetProcessCommandLine(Process process)
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher($"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {process.Id}"))
                {
                    foreach (var obj in searcher.Get())
                    {
                        return obj["CommandLine"] as string;
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "BehaviorAnalysis.cs 捕获异常", ex.Message); }
            return null;
        }

        private int GetParentProcessId(int processId)
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher($"SELECT ParentProcessId FROM Win32_Process WHERE ProcessId = {processId}"))
                {
                    foreach (var obj in searcher.Get())
                    {
                        return Convert.ToInt32(obj["ParentProcessId"]);
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "BehaviorAnalysis.cs 捕获异常", ex.Message); }
            return 0;
        }

        private void LogProcessTermination(ProcessInfo processInfo)
        {
            try
            {
                var logEntry = new ProcessTerminationLog
                {
                    ProcessId = processInfo.ProcessId,
                    ProcessName = processInfo.ProcessName,
                    FilePath = processInfo.FilePath,
                    TerminationTime = DateTime.UtcNow,
                    Duration = DateTime.UtcNow - processInfo.StartTime
                };

                LogToFile("ProcessTermination.log", logEntry);
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "BehaviorAnalysis.cs 捕获异常", ex.Message); }
        }

        private void LogNetworkConnectionClose(BehaviorNetworkConnectionInfo connectionInfo)
        {
            try
            {
                var logEntry = new NetworkConnectionCloseLog
                {
                    LocalEndPoint = connectionInfo.LocalEndPoint.ToString(),
                    RemoteEndPoint = connectionInfo.RemoteEndPoint.ToString(),
                    State = connectionInfo.State.ToString(),
                    CloseTime = DateTime.UtcNow,
                    Duration = DateTime.UtcNow - connectionInfo.StartTime
                };

                LogToFile("NetworkConnectionClose.log", logEntry);
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "BehaviorAnalysis.cs 捕获异常", ex.Message); }
        }

        private void LogAnalysisResult(BehaviorAnalysisResult result)
        {
            try
            {
                LogToFile("BehaviorAnalysis.log", result);
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "BehaviorAnalysis.cs 捕获异常", ex.Message); }
        }

        private void LogToFile(string fileName, object data)
        {
            try
            {
                var logFile = Path.Combine(_logDirectory, fileName);
                var json = Newtonsoft.Json.JsonConvert.SerializeObject(data);

                // 检查文件大小
                if (File.Exists(logFile))
                {
                    var fileInfo = new FileInfo(logFile);
                    if (fileInfo.Length > _maxLogSize)
                    {
                        // 重命名旧日志文件
                        var backupFile = Path.Combine(_logDirectory, $"{Path.GetFileNameWithoutExtension(fileName)}_{DateTime.UtcNow:yyyyMMddHHmmss}.log");
                        File.Move(logFile, backupFile);
                    }
                }

                File.AppendAllText(logFile, json + Environment.NewLine);
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "BehaviorAnalysis.cs 捕获异常", ex.Message); }
        }

        public async Task<BehaviorAnalysisResult> AnalyzeProcessByIdAsync(int processId)
        {
            try
            {
                var process = Process.GetProcessById(processId);
                if (process == null)
                {
                    throw new ArgumentException("Process not found");
                }

                var processInfo = CreateProcessInfo(process);
                
                // 首先检查白名单 - 白名单进程直接返回安全
                if (SystemServiceWhitelist.Contains(processInfo.ProcessName))
                {
                    return new BehaviorAnalysisResult
                    {
                        AnalysisType = AnalysisType.Process,
                        Target = processInfo.ProcessName,
                        Score = 0.0,
                        IsSuspicious = false,
                        Details = new List<string> { "Process in system whitelist" },
                        Timestamp = DateTime.UtcNow
                    };
                }

                var analysisResult = new BehaviorAnalysisResult
                {
                    AnalysisType = AnalysisType.Process,
                    Target = processInfo.ProcessName,
                    Score = 0.0,
                    Details = new List<string>(),
                    Timestamp = DateTime.UtcNow
                };

                // 执行与MonitorProcessesAsync相同的分析逻辑
                // 检查进程路径
                if (string.IsNullOrEmpty(processInfo.FilePath))
                {
                    analysisResult.Details.Add("Process path not available (may be system process)");
                }
                else
                {
                    // 检查是否在受信任路径
                    bool isTrustedPath = TrustedPaths.Any(path => 
                        !string.IsNullOrEmpty(path) && 
                        processInfo.FilePath.StartsWith(path, StringComparison.OrdinalIgnoreCase));

                    if (!isTrustedPath)
                    {
                        analysisResult.Score += 0.1;
                        analysisResult.Details.Add("Process not in trusted directory");
                    }

                    // 检查文件是否存在
                    if (!File.Exists(processInfo.FilePath))
                    {
                        analysisResult.Score += 0.2;
                        analysisResult.Details.Add("Process file not found");
                    }
                }

                // 检查命令行参数
                if (!string.IsNullOrEmpty(processInfo.CommandLine))
                {
                    var dangerousCommands = new List<string> { 
                        "-EncodedCommand", "-ExecutionPolicy Bypass", "-WindowStyle Hidden",
                        "IEX", "DownloadString", "DownloadFile" 
                    };
                    int suspiciousCount = 0;
                    foreach (var command in dangerousCommands)
                    {
                        if (processInfo.CommandLine.Contains(command, StringComparison.OrdinalIgnoreCase))
                        {
                            suspiciousCount++;
                        }
                    }
                    if (suspiciousCount >= 2)
                    {
                        analysisResult.Score += 0.4;
                        analysisResult.Details.Add("Multiple suspicious command line parameters detected");
                    }
                }

                // 使用更高的阈值判断
                if (analysisResult.Score >= SuspiciousThreshold)
                {
                    analysisResult.IsSuspicious = true;
                }

                return analysisResult;
            }
            catch (Exception ex)
            {
                Logger.Error($"Process analysis by ID error: {ex.Message}");
                return new BehaviorAnalysisResult
                {
                    AnalysisType = AnalysisType.Process,
                    Target = processId.ToString(),
                    Score = 0.0,
                    IsSuspicious = false,
                    Details = new List<string> { ex.Message },
                    Timestamp = DateTime.UtcNow
                };
            }
        }

        public async Task<BehaviorAnalysisResult> AnalyzeNetworkConnectionAsync(string localEndPoint, string remoteEndPoint)
        {
            try
            {
                var analysisResult = new BehaviorAnalysisResult
                {
                    AnalysisType = AnalysisType.Network,
                    Target = remoteEndPoint,
                    Score = 0.0,
                    Details = new List<string>(),
                    Timestamp = DateTime.UtcNow
                };

                // 检查远程IP地址
                var ipAddress = remoteEndPoint.Split(':')[0];
                if (ipAddress == "127.0.0.1" || ipAddress.StartsWith("192.168.") || ipAddress.StartsWith("10.") || ipAddress.StartsWith("172.16.") || ipAddress.StartsWith("172.17.") || ipAddress.StartsWith("172.18.") || ipAddress.StartsWith("172.19.") || ipAddress.StartsWith("172.20.") || ipAddress.StartsWith("172.21.") || ipAddress.StartsWith("172.22.") || ipAddress.StartsWith("172.23.") || ipAddress.StartsWith("172.24.") || ipAddress.StartsWith("172.25.") || ipAddress.StartsWith("172.26.") || ipAddress.StartsWith("172.27.") || ipAddress.StartsWith("172.28.") || ipAddress.StartsWith("172.29.") || ipAddress.StartsWith("172.30.") || ipAddress.StartsWith("172.31.") || ipAddress == "::1" || ipAddress.StartsWith("fe80::"))
                {
                    // 本地网络或私有网络，风险较低
                    analysisResult.Details.Add("Local or private network address");
                }
                else
                {
                    // 外部IP - 不直接加分，只有当端口也可疑时才标记
                    analysisResult.Details.Add("External network address");
                }

                // 检查端口 - 只有当是外部IP且端口敏感时才加分
                try
                {
                    var port = int.Parse(remoteEndPoint.Split(':')[1]);
                    var suspiciousPorts = new List<int> { 21, 22, 23, 25, 445, 1433, 3306, 3389, 5432, 8080 };
                    if (suspiciousPorts.Contains(port))
                    {
                        analysisResult.Score += 0.3;
                        analysisResult.Details.Add($"Sensitive port: {port}");
                    }
                }
                catch
                {
                    // 端口解析失败，忽略
                }

                // 使用更高的阈值判断
                if (analysisResult.Score >= SuspiciousThreshold)
                {
                    analysisResult.IsSuspicious = true;
                }

                return analysisResult;
            }
            catch (Exception ex)
            {
                Logger.Error($"Network connection analysis error: {ex.Message}");
                return new BehaviorAnalysisResult
                {
                    AnalysisType = AnalysisType.Network,
                    Target = remoteEndPoint,
                    Score = 0.0,
                    IsSuspicious = false,
                    Details = new List<string> { ex.Message },
                    Timestamp = DateTime.UtcNow
                };
            }
        }

        public List<ProcessInfo> GetProcesses()
        {
            lock (_lockObject)
            {
                return _processes.Values.ToList();
            }
        }

        public List<BehaviorNetworkConnectionInfo> GetNetworkConnections()
        {
            lock (_lockObject)
            {
                return _networkConnections.Values.ToList();
            }
        }

        public void SetAnalysisInterval(int interval)
        {
            _analysisInterval = interval;
        }

        public void SetMaxLogSize(int size)
        {
            _maxLogSize = size;
        }

        public void EnableRealTimeMonitoring(bool enable)
        {
            _enableRealTimeMonitoring = enable;
        }

        public void EnableNetworkMonitoring(bool enable)
        {
            _enableNetworkMonitoring = enable;
        }

        public void EnableFileMonitoring(bool enable)
        {
            _enableFileMonitoring = enable;
        }

        public void EnableRegistryMonitoring(bool enable)
        {
            _enableRegistryMonitoring = enable;
        }

        public void EnableProcessMonitoring(bool enable)
        {
            _enableProcessMonitoring = enable;
        }

        private void RaiseBehaviorAnalysisEvent(BehaviorAnalysisEventArgs e)
        {
            BehaviorAnalysisEvent?.Invoke(this, e);
        }
    }

    public class BehaviorNetworkConnectionInfo
    {
        public System.Net.IPEndPoint LocalEndPoint { get; set; }
        public System.Net.IPEndPoint RemoteEndPoint { get; set; }
        public System.Net.NetworkInformation.TcpState State { get; set; }
        public DateTime StartTime { get; set; }
    }

    public class FileOperationInfo
    {
        public string FilePath { get; set; }
        public FileOperationType OperationType { get; set; }
        public int ProcessId { get; set; }
        public string ProcessName { get; set; }
        public DateTime Timestamp { get; set; }
    }

    public class RegistryOperationInfo
    {
        public string RegistryPath { get; set; }
        public RegistryOperationType OperationType { get; set; }
        public int ProcessId { get; set; }
        public string ProcessName { get; set; }
        public DateTime Timestamp { get; set; }
    }

    public class BehaviorAnalysisResult
    {
        public AnalysisType AnalysisType { get; set; }
        public string Target { get; set; }
        public double Score { get; set; }
        public bool IsSuspicious { get; set; }
        public List<string> Details { get; set; } = new List<string>();
        public DateTime Timestamp { get; set; }
    }

    public class ProcessTerminationLog
    {
        public int ProcessId { get; set; }
        public string ProcessName { get; set; }
        public string FilePath { get; set; }
        public DateTime TerminationTime { get; set; }
        public TimeSpan Duration { get; set; }
    }

    public class NetworkConnectionCloseLog
    {
        public string LocalEndPoint { get; set; }
        public string RemoteEndPoint { get; set; }
        public string State { get; set; }
        public DateTime CloseTime { get; set; }
        public TimeSpan Duration { get; set; }
    }

    public class BehaviorAnalysisEventArgs : EventArgs
    {
        public BehaviorAnalysisEventType EventType { get; set; }
        public string Message { get; set; }
        public DateTime Timestamp { get; set; }

        public BehaviorAnalysisEventArgs(BehaviorAnalysisEventType eventType, string message)
        {
            EventType = eventType;
            Message = message;
            Timestamp = DateTime.UtcNow;
        }
    }

    public enum AnalysisType
    {
        Process,
        Network,
        File,
        Registry
    }

    public enum FileOperationType
    {
        Create,
        Read,
        Write,
        Delete,
        Rename,
        Move
    }

    public enum RegistryOperationType
    {
        CreateKey,
        DeleteKey,
        SetValue,
        DeleteValue,
        QueryValue
    }

    public enum BehaviorAnalysisEventType
    {
        Info,
        Warning,
        Error,
        ProcessCreated,
        ProcessTerminated,
        NetworkConnectionEstablished,
        NetworkConnectionClosed,
        FileOperationDetected,
        RegistryOperationDetected,
        SuspiciousActivityDetected
    }
}