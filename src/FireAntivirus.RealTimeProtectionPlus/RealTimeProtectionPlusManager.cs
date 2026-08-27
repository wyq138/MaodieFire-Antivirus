using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using FireAntivirus.Common;
using FireAntivirus.Data;
using FireAntivirus.Engine;

namespace FireAntivirus.RealTimeProtectionPlus
{
    public class RealTimeProtectionPlusManager
    {
        private DataManager _dataManager;
        private AntivirusEngine _antivirusEngine;
        private List<ProtectionModule> _protectionModules;
        private bool _isEnabled;
        
        // 监控组件
        private ManagementEventWatcher _processWatcher;
        private List<FileSystemWatcher> _fileWatchers;
        private ManagementEventWatcher _registryWatcher;
        private Thread _networkMonitorThread;
        private Thread _behaviorMonitorThread;
        private bool _isMonitoring;
        
        // 可疑进程名称（从外部 JSON 加载：ThreatData/malicious_indicators.json 的 suspiciousProcessNames，
        // 不内嵌于 DLL，避免杀软误报，也便于更新）
        private readonly HashSet<string> _suspiciousProcessNames;
        public HashSet<string> SuspiciousProcessNames => _suspiciousProcessNames;
        
        // 可疑网络端口
        private static readonly HashSet<int> SuspiciousPorts = new HashSet<int>
        {
            4444, 5555, 6666, 7777, 8888, 9999, // 常见后门端口
            31337, 12345, 27374, // 知名木马端口
            4443, 5554, 6667, 6668, 6669 // IRC和反向Shell端口
        };

        public RealTimeProtectionPlusManager(DataManager dataManager, AntivirusEngine antivirusEngine)
        {
            FireAntivirus.Engine.ExternalThreatData.EnsureLoaded();
            _suspiciousProcessNames = new HashSet<string>(FireAntivirus.Engine.ExternalThreatData.SuspiciousProcessNames, StringComparer.OrdinalIgnoreCase);
            _dataManager = dataManager;
            _antivirusEngine = antivirusEngine;
            _protectionModules = new List<ProtectionModule>();
            _isEnabled = true;
            _isMonitoring = false;
            _fileWatchers = new List<FileSystemWatcher>();
            InitializeProtection();
        }

        private void InitializeProtection()
        {
            _protectionModules.Add(new ProtectionModule
            {
                Name = "ProcessProtection",
                Description = "进程防护",
                Enabled = true,
                Type = ProtectionType.Process
            });

            _protectionModules.Add(new ProtectionModule
            {
                Name = "FileProtection",
                Description = "文件防护",
                Enabled = true,
                Type = ProtectionType.File
            });

            _protectionModules.Add(new ProtectionModule
            {
                Name = "RegistryProtection",
                Description = "注册表防护",
                Enabled = true,
                Type = ProtectionType.Registry
            });

            _protectionModules.Add(new ProtectionModule
            {
                Name = "NetworkProtection",
                Description = "网络防护",
                Enabled = true,
                Type = ProtectionType.Network
            });

            _protectionModules.Add(new ProtectionModule
            {
                Name = "BehaviorProtection",
                Description = "行为防护",
                Enabled = true,
                Type = ProtectionType.Behavior
            });
        }

        public void StartProtection()
        {
            _isEnabled = true;
            _isMonitoring = true;
            
            foreach (var module in _protectionModules)
            {
                if (module.Enabled)
                {
                    StartModule(module);
                }
            }
            
            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "RealTimeProtectionPlusStarted",
                Message = "增强型实时防护已启动"
            });
        }

        public void StopProtection()
        {
            _isEnabled = false;
            _isMonitoring = false;
            
            foreach (var module in _protectionModules)
            {
                if (module.Enabled)
                {
                    StopModule(module);
                }
            }
            
            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "RealTimeProtectionPlusStopped",
                Message = "增强型实时防护已停止"
            });
        }

        public bool IsEnabled()
        {
            return _isEnabled;
        }

        public void EnableModule(ProtectionType type)
        {
            var module = _protectionModules.FirstOrDefault(m => m.Type == type);
            if (module != null)
            {
                module.Enabled = true;
                if (_isEnabled)
                {
                    StartModule(module);
                }
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "ProtectionModuleEnabled",
                    Message = "防护模块已启用",
                    Details = $"模块: {module.Name}"
                });
            }
        }

        public void DisableModule(ProtectionType type)
        {
            var module = _protectionModules.FirstOrDefault(m => m.Type == type);
            if (module != null)
            {
                module.Enabled = false;
                if (_isEnabled)
                {
                    StopModule(module);
                }
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "ProtectionModuleDisabled",
                    Message = "防护模块已禁用",
                    Details = $"模块: {module.Name}"
                });
            }
        }

        public List<ProtectionModule> GetProtectionModules()
        {
            return _protectionModules;
        }

        /// <summary>运行无杀伤力功能自检（引擎查杀/特征库解析/实时防护/不误删），供 UI "立即自检" 调用。</summary>
        public async Task<List<SelfTestItem>> RunSelfTestAsync()
        {
            return await FeatureSelfTest.RunAllAsync(_dataManager, _antivirusEngine, this);
        }

        private void StartModule(ProtectionModule module)
        {
            switch (module.Type)
            {
                case ProtectionType.Process:
                    StartProcessProtection();
                    break;
                case ProtectionType.File:
                    StartFileProtection();
                    break;
                case ProtectionType.Registry:
                    StartRegistryProtection();
                    break;
                case ProtectionType.Network:
                    StartNetworkProtection();
                    break;
                case ProtectionType.Behavior:
                    StartBehaviorProtection();
                    break;
            }
        }

        private void StopModule(ProtectionModule module)
        {
            switch (module.Type)
            {
                case ProtectionType.Process:
                    StopProcessProtection();
                    break;
                case ProtectionType.File:
                    StopFileProtection();
                    break;
                case ProtectionType.Registry:
                    StopRegistryProtection();
                    break;
                case ProtectionType.Network:
                    StopNetworkProtection();
                    break;
                case ProtectionType.Behavior:
                    StopBehaviorProtection();
                    break;
            }
        }

        private void StartProcessProtection()
        {
            try
            {
                // 使用WMI监控进程创建
                var query = new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace");
                _processWatcher = new ManagementEventWatcher(query);
                _processWatcher.EventArrived += OnProcessCreated;
                _processWatcher.Start();
                
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "ProcessProtectionStarted",
                    Message = "进程防护已启动"
                });
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "ProcessProtectionError",
                    Message = "进程防护启动失败",
                    Details = ex.Message
                });
            }
        }

        private void StopProcessProtection()
        {
            try
            {
                if (_processWatcher != null)
                {
                    _processWatcher.Stop();
                    _processWatcher.Dispose();
                    _processWatcher = null;
                }
            }
            catch (Exception ex) { LogHelper.Log(LogHelper.LogLevel.Error, "停止进程监控失败", ex.Message); }
        }

        private void OnProcessCreated(object sender, EventArrivedEventArgs e)
        {
            try
            {
                var processName = e.NewEvent.Properties["ProcessName"]?.Value?.ToString();
                var processId = e.NewEvent.Properties["ProcessID"]?.Value?.ToString();
                var parentProcessId = e.NewEvent.Properties["ParentProcessID"]?.Value?.ToString();
                
                var protectionEvent = new ProtectionEvent
                {
                    EventId = Guid.NewGuid().ToString(),
                    EventType = "ProcessCreated",
                    ProtectionType = ProtectionType.Process,
                    Timestamp = DateTime.Now,
                    ProcessName = processName,
                    Details = $"ProcessName={processName},ProcessId={processId},ParentProcessId={parentProcessId}"
                };
                
                var result = AnalyzeProcessEvent(protectionEvent);
                if (result.Action == ProtectionAction.Block)
                {
                    // 尝试终止可疑进程
                    try
                    {
                        if (int.TryParse(processId, out var pid))
                        {
                            var process = Process.GetProcessById(pid);
                            process.Kill();
                        }
                    }
                    catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "RealTimeProtectionPlusManager.cs 捕获异常", ex.Message); }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "RealTimeProtectionPlusManager.cs 捕获异常", ex.Message); }
        }

        private void StartFileProtection()
        {
            try
            {
                // 监控关键目录
                var watchPaths = new[]
                {
                    Environment.GetFolderPath(Environment.SpecialFolder.System),
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32"),
                    Environment.GetFolderPath(Environment.SpecialFolder.Startup)
                };

                foreach (var path in watchPaths)
                {
                    if (Directory.Exists(path))
                    {
                        var watcher = new FileSystemWatcher(path)
                        {
                            EnableRaisingEvents = true,
                            IncludeSubdirectories = true,
                            NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size
                        };
                        
                        watcher.Created += OnFileCreated;
                        watcher.Changed += OnFileChanged;
                        _fileWatchers.Add(watcher);
                    }
                }
                
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "FileProtectionStarted",
                    Message = "文件防护已启动"
                });
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "FileProtectionError",
                    Message = "文件防护启动失败",
                    Details = ex.Message
                });
            }
        }

        private void StopFileProtection()
        {
            foreach (var watcher in _fileWatchers)
            {
                try
                {
                    watcher.EnableRaisingEvents = false;
                    watcher.Dispose();
                }
                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "RealTimeProtectionPlusManager.cs 捕获异常", ex.Message); }
            }
            _fileWatchers.Clear();
        }

        private void OnFileCreated(object sender, FileSystemEventArgs e)
        {
            var protectionEvent = new ProtectionEvent
            {
                EventId = Guid.NewGuid().ToString(),
                EventType = "FileCreated",
                ProtectionType = ProtectionType.File,
                Timestamp = DateTime.Now,
                FilePath = e.FullPath,
                Details = $"FilePath={e.FullPath},ChangeType={e.ChangeType}"
            };
            
            var result = AnalyzeFileEvent(protectionEvent);
            if (result.Action == ProtectionAction.Block)
            {
                // 多引擎确认威胁: 可逆隔离(move到隔离区), 绝不永久删除, 避免误杀后无法找回
                try
                {
                    _dataManager.QuarantineFile(e.FullPath, result.Message ?? "RealTime-Threat",
                        "RealTimeProtection", "RealTimeProtectionPlus", 0.8);
                    _dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "RealTimeFileQuarantined",
                        Message = $"实时防护已隔离可逆处置文件: {e.FullPath}",
                        Details = result.Message
                    });
                }
                catch (Exception ex)
                {
                    _dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "RealTimeQuarantineError",
                        Message = $"文件隔离失败(已停止自动处置,避免误杀): {e.FullPath}",
                        Details = ex.Message
                    });
                }
            }
            else if (result.Action == ProtectionAction.Alert)
            {
                // 弱信号仅告警, 不做任何处置
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "RealTimeFileAlert",
                    Message = $"实时防护提示(未处置,待确认): {e.FullPath}",
                    Details = result.Message
                });
            }
        }

        private void OnFileChanged(object sender, FileSystemEventArgs e)
        {
            // 只监控可执行文件的修改
            var ext = Path.GetExtension(e.FullPath).ToLower();
            if (ext == ".exe" || ext == ".dll" || ext == ".sys" || ext == ".bat" || ext == ".ps1" || ext == ".vbs")
            {
                var protectionEvent = new ProtectionEvent
                {
                    EventId = Guid.NewGuid().ToString(),
                    EventType = "FileChanged",
                    ProtectionType = ProtectionType.File,
                    Timestamp = DateTime.Now,
                    FilePath = e.FullPath,
                    Details = $"FilePath={e.FullPath},ChangeType={e.ChangeType}"
                };
                
                AnalyzeFileEvent(protectionEvent);
            }
        }

        private void StartRegistryProtection()
        {
            try
            {
                // 监控注册表修改
                var query = new WqlEventQuery(
                    "SELECT * FROM RegistryValueChangeEvent WHERE " +
                    "Hive = 'HKEY_LOCAL_MACHINE' AND " +
                    "KeyPath = 'SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run'");
                
                _registryWatcher = new ManagementEventWatcher(query);
                _registryWatcher.EventArrived += OnRegistryChanged;
                _registryWatcher.Start();
                
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "RegistryProtectionStarted",
                    Message = "注册表防护已启动"
                });
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "RegistryProtectionError",
                    Message = "注册表防护启动失败",
                    Details = ex.Message
                });
            }
        }

        private void StopRegistryProtection()
        {
            try
            {
                if (_registryWatcher != null)
                {
                    _registryWatcher.Stop();
                    _registryWatcher.Dispose();
                    _registryWatcher = null;
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "RealTimeProtectionPlusManager.cs 捕获异常", ex.Message); }
        }

        private void OnRegistryChanged(object sender, EventArrivedEventArgs e)
        {
            var protectionEvent = new ProtectionEvent
            {
                EventId = Guid.NewGuid().ToString(),
                EventType = "RegistryChanged",
                ProtectionType = ProtectionType.Registry,
                Timestamp = DateTime.Now,
                RegistryPath = @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                Details = "Hive=HKEY_LOCAL_MACHINE,KeyPath=SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
            };
            
            AnalyzeRegistryEvent(protectionEvent);
        }

        private void StartNetworkProtection()
        {
            _networkMonitorThread = new Thread(NetworkMonitorLoop)
            {
                IsBackground = true
            };
            _networkMonitorThread.Start();
            
            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "NetworkProtectionStarted",
                Message = "网络防护已启动"
            });
        }

        private void StopNetworkProtection()
        {
            _isMonitoring = false;
            if (_networkMonitorThread != null && _networkMonitorThread.IsAlive)
            {
                _networkMonitorThread.Join(2000);
            }
        }

        private void NetworkMonitorLoop()
        {
            var knownConnections = new HashSet<string>();
            
            while (_isMonitoring)
            {
                try
                {
                    var properties = IPGlobalProperties.GetIPGlobalProperties();
                    var connections = properties.GetActiveTcpConnections()
                        .Where(c => c.State == TcpState.Established);
                    
                    foreach (var conn in connections)
                    {
                        var connKey = $"{conn.LocalEndPoint}:{conn.RemoteEndPoint}";
                        if (!knownConnections.Contains(connKey))
                        {
                            knownConnections.Add(connKey);
                            
                            if (SuspiciousPorts.Contains(conn.RemoteEndPoint.Port))
                            {
                                var protectionEvent = new ProtectionEvent
                                {
                                    EventId = Guid.NewGuid().ToString(),
                                    EventType = "SuspiciousConnection",
                                    ProtectionType = ProtectionType.Network,
                                    Timestamp = DateTime.Now,
                                    NetworkAddress = conn.RemoteEndPoint.ToString(),
                                    Details = $"LocalEndPoint={conn.LocalEndPoint},RemoteEndPoint={conn.RemoteEndPoint},RemotePort={conn.RemoteEndPoint.Port}"
                                };
                                
                                AnalyzeNetworkEvent(protectionEvent);
                            }
                        }
                    }
                }
                catch (Exception ex) { LogHelper.Log(LogHelper.LogLevel.Error, "网络事件监控失败", ex.Message); }
                
                Thread.Sleep(5000);
            }
        }

        private void StartBehaviorProtection()
        {
            _behaviorMonitorThread = new Thread(BehaviorMonitorLoop)
            {
                IsBackground = true
            };
            _behaviorMonitorThread.Start();
            
            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "BehaviorProtectionStarted",
                Message = "行为防护已启动"
            });
        }

        private void StopBehaviorProtection()
        {
            if (_behaviorMonitorThread != null && _behaviorMonitorThread.IsAlive)
            {
                _behaviorMonitorThread.Join(2000);
            }
        }

        private void BehaviorMonitorLoop()
        {
            while (_isMonitoring)
            {
                try
                {
                    // 监控可疑行为
                    var processes = Process.GetProcesses();
                    foreach (var process in processes)
                    {
                        try
                        {
                            var processName = process.ProcessName.ToLower();
                            
                            // 检查可疑进程名称
                            if (SuspiciousProcessNames.Contains(processName))
                            {
                                // 检查命令行参数
                                var cmdLine = GetProcessCommandLine(process.Id);
                                if (!string.IsNullOrEmpty(cmdLine) && IsSuspiciousCommandLine(cmdLine))
                                {
                                    var protectionEvent = new ProtectionEvent
                                    {
                                        EventId = Guid.NewGuid().ToString(),
                                        EventType = "SuspiciousBehavior",
                                        ProtectionType = ProtectionType.Behavior,
                                        Timestamp = DateTime.Now,
                                        ProcessName = process.ProcessName,
                                        Details = $"ProcessName={process.ProcessName},ProcessId={process.Id},CommandLine={cmdLine}"
                                    };
                                    
                                    var result = AnalyzeBehaviorEvent(protectionEvent);
                                    if (result.Action == ProtectionAction.Block)
                                    {
                                        process.Kill();
                                    }
                                }
                            }
                        }
                        catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "RealTimeProtectionPlusManager.cs 捕获异常", ex.Message); }
                    }
                }
                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "RealTimeProtectionPlusManager.cs 捕获异常", ex.Message); }
                
                Thread.Sleep(10000);
            }
        }

        private string GetProcessCommandLine(int processId)
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {processId}");
                foreach (var obj in searcher.Get())
                {
                    return obj["CommandLine"]?.ToString() ?? "";
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "RealTimeProtectionPlusManager.cs 捕获异常", ex.Message); }
            return "";
        }

        private bool IsSuspiciousCommandLine(string cmdLine)
        {
            var suspiciousPatterns = new[]
            {
                "-enc", "-encodedcommand", "-executionpolicy bypass", "-windowstyle hidden",
                "invoke-webrequest", "iwr ", "downloadstring", "downloadfile",
                "net.webclient", "start-bitstransfer", "certutil -urlcache",
                "reg save", "reg export", "ntdsutil", "vssadmin delete",
                "wmic ", "mshta vbscript", "mshta http", "rundll32.exe javascript",
                "powershell -w hidden", "bypass -c ", "frombase64string"
            };
            
            var lowerCmd = cmdLine.ToLower();
            return suspiciousPatterns.Any(p => lowerCmd.Contains(p));
        }

        public ProtectionEventResult OnProtectionEvent(ProtectionEvent protectionEvent)
        {
            var result = new ProtectionEventResult
            {
                EventId = protectionEvent.EventId,
                Timestamp = DateTime.Now
            };

            try
            {
                if (!_isEnabled)
                {
                    result.Action = ProtectionAction.Allow;
                    result.Message = "防护已禁用";
                    return result;
                }

                var module = _protectionModules.FirstOrDefault(m => m.Type == protectionEvent.ProtectionType);
                if (module == null || !module.Enabled)
                {
                    result.Action = ProtectionAction.Allow;
                    result.Message = "模块已禁用";
                    return result;
                }

                switch (protectionEvent.ProtectionType)
                {
                    case ProtectionType.Process:
                        result = AnalyzeProcessEvent(protectionEvent);
                        break;
                    case ProtectionType.File:
                        result = AnalyzeFileEvent(protectionEvent);
                        break;
                    case ProtectionType.Registry:
                        result = AnalyzeRegistryEvent(protectionEvent);
                        break;
                    case ProtectionType.Network:
                        result = AnalyzeNetworkEvent(protectionEvent);
                        break;
                    case ProtectionType.Behavior:
                        result = AnalyzeBehaviorEvent(protectionEvent);
                        break;
                }

                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "ProtectionEvent",
                    Message = $"防护事件: {protectionEvent.EventType}",
                    Details = $"类型: {protectionEvent.ProtectionType}, 动作: {result.Action}, 消息: {result.Message}"
                });
            }
            catch (Exception ex)
            {
                result.Action = ProtectionAction.Allow;
                result.Message = $"分析错误: {ex.Message}";
            }

            return result;
        }

        // 由进程名解析其真实可执行文件路径(用于对进程做真正的文件查杀)
        private string ResolveProcessExecutablePath(string processName)
        {
            try
            {
                var pname = Path.GetFileNameWithoutExtension(processName);
                foreach (var p in Process.GetProcessesByName(pname))
                {
                    try
                    {
                        if (!string.IsNullOrEmpty(p.MainModule?.FileName))
                        {
                            return p.MainModule.FileName;
                        }
                    }
                    catch (Exception ex) { LogHelper.Log(LogHelper.LogLevel.Error, "获取进程路径失败", ex.Message); }
                }
            }
            catch (Exception ex) { LogHelper.Log(LogHelper.LogLevel.Error, "查找进程失败", ex.Message); }
            return null;
        }

        private ProtectionEventResult AnalyzeProcessEvent(ProtectionEvent protectionEvent)
        {
            var result = new ProtectionEventResult
            {
                EventId = protectionEvent.EventId,
                Timestamp = DateTime.Now
            };

            try
            {
                var processName = protectionEvent.ProcessName?.ToLower() ?? "";
                
                // 检查是否是已知可疑进程
                if (SuspiciousProcessNames.Contains(processName))
                {
                    result.Action = ProtectionAction.Block;
                    result.Message = $"检测到可疑进程: {processName}";
                    return result;
                }
                
                // 使用杀毒引擎扫描进程真实可执行文件(修复:先前误把进程名当文件路径,属假功能)
                if (!string.IsNullOrEmpty(processName))
                {
                    var exePath = ResolveProcessExecutablePath(processName);
                    if (!string.IsNullOrEmpty(exePath) && File.Exists(exePath))
                    {
                        var scanResult = _antivirusEngine.ScanFile(exePath);
                        // 多引擎确认(置信度>=0.8)才阻断, 弱信号仅告警, 杜绝误杀正常进程
                        if (scanResult != null && scanResult.IsInfected)
                        {
                            if (scanResult.Confidence >= 0.8)
                            {
                                result.Action = ProtectionAction.Block;
                                result.Message = $"多引擎确认恶意进程: {exePath} ({scanResult.ThreatName})";
                            }
                            else
                            {
                                result.Action = ProtectionAction.Alert;
                                result.Message = $"进程可疑(待确认,避免误杀): {exePath} ({scanResult.ThreatName})";
                            }
                            return result;
                        }
                    }
                }
                
                result.Action = ProtectionAction.Allow;
                result.Message = "进程安全";
            }
            catch
            {
                result.Action = ProtectionAction.Allow;
                result.Message = "分析完成";
            }

            return result;
        }

        private ProtectionEventResult AnalyzeFileEvent(ProtectionEvent protectionEvent)
        {
            var result = new ProtectionEventResult
            {
                EventId = protectionEvent.EventId,
                Timestamp = DateTime.Now
            };

            try
            {
                var filePath = protectionEvent.FilePath ?? "";

                if (!string.IsNullOrEmpty(filePath) && File.Exists(filePath))
                {
                    // 检查文件扩展名
                    var ext = Path.GetExtension(filePath).ToLower();
                    var dangerousExtensions = new[] { ".exe", ".dll", ".bat", ".ps1", ".vbs", ".js", ".hta", ".scr", ".pif", ".com" };
                    
                    if (dangerousExtensions.Contains(ext))
                    {
                        // 使用杀毒引擎扫描(多引擎共识:置信度>=0.8才算确认威胁)
                        var scanResult = _antivirusEngine.ScanFile(filePath);
                        if (scanResult != null && scanResult.IsInfected && scanResult.Confidence >= 0.8)
                        {
                            result.Action = ProtectionAction.Block;
                            result.Message = $"多引擎确认威胁: {filePath} ({scanResult.ThreatName})";
                            return result;
                        }
                        else if (scanResult != null && scanResult.IsInfected)
                        {
                            // 单一/弱信号: 仅告警, 不处置, 杜绝误杀正常文件
                            result.Action = ProtectionAction.Alert;
                            result.Message = $"文件可疑(待人工确认,避免误报): {filePath} ({scanResult.ThreatName})";
                            return result;
                        }
                    }
                }
                
                result.Action = ProtectionAction.Allow;
                result.Message = "文件安全";
            }
            catch
            {
                result.Action = ProtectionAction.Allow;
                result.Message = "分析完成";
            }

            return result;
        }

        private ProtectionEventResult AnalyzeRegistryEvent(ProtectionEvent protectionEvent)
        {
            var result = new ProtectionEventResult
            {
                EventId = protectionEvent.EventId,
                Timestamp = DateTime.Now
            };

            try
            {
                // 获取最近修改的启动项
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", false);
                
                if (key != null)
                {
                    foreach (var valueName in key.GetValueNames())
                    {
                        var value = key.GetValue(valueName)?.ToString() ?? "";
                        
                        // 检查可疑路径
                        if (value.Contains("%TEMP%") || value.Contains("%APPDATA%") || 
                            value.Contains("Downloads") || value.Contains("Public"))
                        {
                            result.Action = ProtectionAction.Alert;
                            result.Message = $"检测到可疑启动项: {valueName} = {value}";
                            return result;
                        }
                        
                        // 检查可疑命令
                        if (IsSuspiciousCommandLine(value))
                        {
                            result.Action = ProtectionAction.Block;
                            result.Message = $"检测到恶意启动项: {valueName}";
                            return result;
                        }
                    }
                }
                
                result.Action = ProtectionAction.Allow;
                result.Message = "注册表操作安全";
            }
            catch
            {
                result.Action = ProtectionAction.Allow;
                result.Message = "分析完成";
            }

            return result;
        }

        private ProtectionEventResult AnalyzeNetworkEvent(ProtectionEvent protectionEvent)
        {
            var result = new ProtectionEventResult
            {
                EventId = protectionEvent.EventId,
                Timestamp = DateTime.Now
            };

            try
            {
                // 网页/网络拦截：优先使用自动更新的恶意特征库(URLhaus 恶意 URL + Feodo C2 IP)。
                // 这是核心真实能力，硬编码 IP 段只是离线兜底。
                var details = protectionEvent.Details ?? "";
                var remoteEndpoint = protectionEvent.NetworkAddress ?? "";

                // 1) 恶意 URL 拦截：从 Details 中提取 URL，命中 URLhaus 特征库即阻断网页访问
                var url = ExtractUrl(details);
                if (!string.IsNullOrEmpty(url) && FireAntivirus.Engine.SignatureDatabaseUpdater.IsMaliciousUrl(url))
                {
                    result.Action = ProtectionAction.Block;
                    result.Message = $"已拦截恶意网址: {url}";
                    return result;
                }

                // 2) 恶意 C2 IP 拦截：命中 Feodo/IP 特征库即阻断连接
                var ip = ExtractIp(remoteEndpoint.Length > 0 ? remoteEndpoint : details);
                if (!string.IsNullOrEmpty(ip) && FireAntivirus.Engine.SignatureDatabaseUpdater.IsMaliciousIp(ip))
                {
                    result.Action = ProtectionAction.Block;
                    result.Message = $"已拦截恶意C2连接: {ip}";
                    return result;
                }

                // 3) 内置已知恶意 IP 段兜底(离线、不依赖特征库)
                var knownMaliciousIPs = new[]
                {
                    "185.220.101.", "23.129.64.", "23.129.128." // 已知恶意IP段
                };

                foreach (var maliciousIP in knownMaliciousIPs)
                {
                    if (remoteEndpoint.StartsWith(maliciousIP))
                    {
                        result.Action = ProtectionAction.Block;
                        result.Message = $"检测到可疑IP连接: {remoteEndpoint}";
                        return result;
                    }
                }

                result.Action = ProtectionAction.Allow;
                result.Message = "网络连接安全";
            }
            catch
            {
                result.Action = ProtectionAction.Allow;
                result.Message = "分析完成";
            }

            return result;
        }

        /// <summary>从文本中提取首个 http(s) URL（用于网页拦截特征比对）。</summary>
        private static string ExtractUrl(string text)
        {
            if (string.IsNullOrWhiteSpace(text)) return null;
            var m = System.Text.RegularExpressions.Regex.Match(text, @"https?://[^\s""',;]+", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            return m.Success ? m.Value : null;
        }

        /// <summary>从文本中提取首个 IPv4 地址（用于 C2/IP 拦截特征比对）。</summary>
        private static string ExtractIp(string text)
        {
            if (string.IsNullOrWhiteSpace(text)) return null;
            var m = System.Text.RegularExpressions.Regex.Match(text, @"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b");
            return m.Success ? m.Value : null;
        }

        private ProtectionEventResult AnalyzeBehaviorEvent(ProtectionEvent protectionEvent)
        {
            var result = new ProtectionEventResult
            {
                EventId = protectionEvent.EventId,
                Timestamp = DateTime.Now
            };

            try
            {
                var details = protectionEvent.Details?.ToLower() ?? "";
                var processName = protectionEvent.ProcessName?.ToLower() ?? "";

                // 检测危险行为模式
                var dangerPatterns = new Dictionary<string, int>
                {
                    { "encodedcommand", 90 },
                    { "executionpolicy bypass", 85 },
                    { "windowstyle hidden", 70 },
                    { "downloadstring", 95 },
                    { "downloadfile", 90 },
                    { "invoke-webrequest", 70 },
                    { "certutil -urlcache", 85 },
                    { "vssadmin delete", 95 },
                    { "ntdsutil", 90 },
                    { "reg save hklm\\sam", 95 },
                    { "reg save hklm\\system", 95 },
                    { "reg save hklm\\security", 95 },
                    { "wmic process call create", 75 },
                    { "mshta vbscript", 90 },
                    { "mshta http", 85 },
                    { "rundll32.exe javascript", 95 }
                };

                var maxRisk = 0;
                var matchedPattern = "";
                
                foreach (var pattern in dangerPatterns)
                {
                    if (details.Contains(pattern.Key))
                    {
                        if (pattern.Value > maxRisk)
                        {
                            maxRisk = pattern.Value;
                            matchedPattern = pattern.Key;
                        }
                    }
                }

                if (maxRisk >= 90)
                {
                    result.Action = ProtectionAction.Block;
                    result.Message = $"检测到高风险行为: {matchedPattern}";
                }
                else if (maxRisk >= 70)
                {
                    result.Action = ProtectionAction.Alert;
                    result.Message = $"检测到可疑行为: {matchedPattern}";
                }
                else
                {
                    result.Action = ProtectionAction.Allow;
                    result.Message = "行为安全";
                }
            }
            catch
            {
                result.Action = ProtectionAction.Allow;
                result.Message = "分析完成";
            }

            return result;
        }
    }
}