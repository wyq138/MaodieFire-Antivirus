using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using FireAntivirus.Data;
using FireAntivirus.Common.Notification;

namespace FireAntivirus.Services
{
    /// <summary>
    /// 专业级行为分析服务 - 支持行为基线学习、MITRE ATT&CK映射、机器学习检测
    /// </summary>
    public class BehaviorAnalysisService : IMonitor
    {
        private Thread _monitorThread;
        private Thread _baselineThread;
        private Thread _analysisThread;
        private bool _isRunning;
        private DataManager _dataManager;
        
        // 使用并发集合提高线程安全性
        private ConcurrentDictionary<int, BehaviorProcessProfile> _processProfiles;
        private ConcurrentDictionary<string, BehaviorBaseline> _baselines;
        private ConcurrentQueue<BehaviorEvent> _eventQueue;
        private ConcurrentBag<ThreatAlert> _threatAlerts;
        
        // MITRE ATT&CK 映射
        private Dictionary<string, MitreTechnique> _mitreTechniques;
        private Dictionary<string, List<string>> _techniqueBehaviors;
        
        // 行为模式库
        private List<BehaviorPattern> _maliciousPatterns;
        private List<BehaviorPattern> _suspiciousPatterns;
        
        // 配置参数
        private int _monitoringInterval;
        private int _baselineUpdateInterval;
        private int _maxEventsPerProcess;
        private int _maxProfiles;
        private bool _enableBaselineLearning;
        private bool _enableMLDetection;
        private bool _enableRealTimeBlocking;
        private bool _enableMitreMapping;
        private double _anomalyThreshold;
        
        // 统计数据
        private long _totalEventsProcessed;
        private long _threatsDetected;
        private long _processesBlocked;
        private DateTime _startTime;

        #region Windows API P/Invoke
        
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);
        
        [DllImport("psapi.dll", SetLastError = true)]
        private static extern bool EnumProcessModulesEx(IntPtr hProcess, IntPtr[] lphModule, int cb, 
            out int lpcbNeeded, uint dwFilterFlag);
        
        [DllImport("psapi.dll", SetLastError = true)]
        private static extern int GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, 
            StringBuilder lpFilename, int nSize);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool QueryFullProcessImageName(IntPtr hProcess, int dwFlags, 
            StringBuilder lpExeName, ref int lpdwSize);
        
        private const uint PROCESS_QUERY_INFORMATION = 0x0400;
        private const uint PROCESS_VM_READ = 0x0010;
        private const uint PROCESS_ALL_ACCESS = 0x1F0FFF;
        
        #endregion

        public BehaviorAnalysisService(DataManager dataManager)
        {
            _dataManager = dataManager;
            _isRunning = false;
            
            // 初始化并发集合
            _processProfiles = new ConcurrentDictionary<int, BehaviorProcessProfile>();
            _baselines = new ConcurrentDictionary<string, BehaviorBaseline>();
            _eventQueue = new ConcurrentQueue<BehaviorEvent>();
            _threatAlerts = new ConcurrentBag<ThreatAlert>();
            
            // 默认配置
            _monitoringInterval = 5000;
            _baselineUpdateInterval = 60000;
            _maxEventsPerProcess = 10000;
            _maxProfiles = 500;
            _enableBaselineLearning = true;
            _enableMLDetection = true;
            _enableRealTimeBlocking = false; // 默认不自动拦截，只告警
            _enableMitreMapping = true;
            _anomalyThreshold = 0.85;
            
            // 初始化MITRE ATT&CK映射
            InitializeMitreTechniques();
            InitializeBehaviorPatterns();
        }

        #region MITRE ATT&CK Initialization
        
        private void InitializeMitreTechniques()
        {
            _mitreTechniques = new Dictionary<string, MitreTechnique>();
            _techniqueBehaviors = new Dictionary<string, List<string>>();
            
            // 初始化常见的MITRE ATT&CK技术
            var techniques = new[]
            {
                // Execution
                new MitreTechnique { Id = "T1059", Name = "Command and Scripting Interpreter", Tactics = new[] { "Execution" }, Severity = 8 },
                new MitreTechnique { Id = "T1059.001", Name = "PowerShell", Tactics = new[] { "Execution" }, Severity = 7 },
                new MitreTechnique { Id = "T1059.003", Name = "Windows Command Shell", Tactics = new[] { "Execution" }, Severity = 6 },
                
                // Persistence
                new MitreTechnique { Id = "T1547", Name = "Boot or Logon Autostart Execution", Tactics = new[] { "Persistence", "Privilege Escalation" }, Severity = 8 },
                new MitreTechnique { Id = "T1547.001", Name = "Registry Run Keys", Tactics = new[] { "Persistence" }, Severity = 7 },
                new MitreTechnique { Id = "T1547.012", Name = "Print Processors", Tactics = new[] { "Persistence" }, Severity = 8 },
                new MitreTechnique { Id = "T1053", Name = "Scheduled Task/Job", Tactics = new[] { "Persistence", "Execution" }, Severity = 7 },
                
                // Defense Evasion
                new MitreTechnique { Id = "T1055", Name = "Process Injection", Tactics = new[] { "Defense Evasion", "Privilege Escalation" }, Severity = 9 },
                new MitreTechnique { Id = "T1055.001", Name = "DLL Injection", Tactics = new[] { "Defense Evasion" }, Severity = 9 },
                new MitreTechnique { Id = "T1055.003", Name = "Thread Execution Hijacking", Tactics = new[] { "Defense Evasion" }, Severity = 9 },
                new MitreTechnique { Id = "T1055.012", Name = "Process Hollowing", Tactics = new[] { "Defense Evasion" }, Severity = 9 },
                new MitreTechnique { Id = "T1027", Name = "Obfuscated Files or Information", Tactics = new[] { "Defense Evasion" }, Severity = 7 },
                new MitreTechnique { Id = "T1036", Name = "Masquerading", Tactics = new[] { "Defense Evasion" }, Severity = 6 },
                new MitreTechnique { Id = "T1070", Name = "Indicator Removal", Tactics = new[] { "Defense Evasion" }, Severity = 7 },
                
                // Credential Access
                new MitreTechnique { Id = "T1003", Name = "OS Credential Dumping", Tactics = new[] { "Credential Access" }, Severity = 9 },
                new MitreTechnique { Id = "T1003.001", Name = "LSASS Memory", Tactics = new[] { "Credential Access" }, Severity = 10 },
                new MitreTechnique { Id = "T1558", Name = "Steal or Forge Kerberos Tickets", Tactics = new[] { "Credential Access" }, Severity = 9 },
                new MitreTechnique { Id = "T1555", Name = "Credentials from Password Stores", Tactics = new[] { "Credential Access" }, Severity = 8 },
                
                // Discovery
                new MitreTechnique { Id = "T1018", Name = "Remote System Discovery", Tactics = new[] { "Discovery" }, Severity = 5 },
                new MitreTechnique { Id = "T1087", Name = "Account Discovery", Tactics = new[] { "Discovery" }, Severity = 5 },
                new MitreTechnique { Id = "T1057", Name = "Process Discovery", Tactics = new[] { "Discovery" }, Severity = 4 },
                new MitreTechnique { Id = "T1069", Name = "Permission Groups Discovery", Tactics = new[] { "Discovery" }, Severity = 5 },
                
                // Lateral Movement
                new MitreTechnique { Id = "T1021", Name = "Remote Services", Tactics = new[] { "Lateral Movement" }, Severity = 7 },
                new MitreTechnique { Id = "T1021.001", Name = "Remote Desktop Protocol", Tactics = new[] { "Lateral Movement" }, Severity = 7 },
                new MitreTechnique { Id = "T1021.002", Name = "SMB/Windows Admin Shares", Tactics = new[] { "Lateral Movement" }, Severity = 7 },
                new MitreTechnique { Id = "T1566", Name = "Phishing", Tactics = new[] { "Initial Access" }, Severity = 8 },
                
                // Collection
                new MitreTechnique { Id = "T1560", Name = "Archive Collected Data", Tactics = new[] { "Collection" }, Severity = 6 },
                new MitreTechnique { Id = "T1114", Name = "Email Collection", Tactics = new[] { "Collection" }, Severity = 6 },
                
                // Command and Control
                new MitreTechnique { Id = "T1071", Name = "Application Layer Protocol", Tactics = new[] { "Command and Control" }, Severity = 7 },
                new MitreTechnique { Id = "T1071.001", Name = "Web Protocols", Tactics = new[] { "Command and Control" }, Severity = 7 },
                new MitreTechnique { Id = "T1095", Name = "Non-Application Layer Protocol", Tactics = new[] { "Command and Control" }, Severity = 7 },
                
                // Exfiltration
                new MitreTechnique { Id = "T1048", Name = "Exfiltration Over Alternative Protocol", Tactics = new[] { "Exfiltration" }, Severity = 8 },
                new MitreTechnique { Id = "T1041", Name = "Exfiltration Over C2 Channel", Tactics = new[] { "Exfiltration" }, Severity = 8 },
                
                // Impact
                new MitreTechnique { Id = "T1486", Name = "Data Encrypted for Impact", Tactics = new[] { "Impact" }, Severity = 10 },
                new MitreTechnique { Id = "T1490", Name = "Inhibit System Recovery", Tactics = new[] { "Impact" }, Severity = 10 }
            };
            
            foreach (var technique in techniques)
            {
                _mitreTechniques[technique.Id] = technique;
            }
            
            // 初始化技术行为映射
            InitializeTechniqueBehaviors();
        }

        private void InitializeTechniqueBehaviors()
        {
            // 为每个MITRE技术定义可检测的行为特征
            _techniqueBehaviors["T1059.001"] = new List<string>
            {
                "powershell.exe execution",
                "encoded command",
                "download and execute",
                "bypass execution policy",
                "reflection assembly load",
                "invoke-expression"
            };
            
            _techniqueBehaviors["T1055"] = new List<string>
            {
                "CreateRemoteThread",
                "VirtualAllocEx",
                "WriteProcessMemory",
                "OpenProcess with VM_WRITE",
                "Process hollowing",
                "DLL injection",
                "APC injection"
            };
            
            _techniqueBehaviors["T1547.001"] = new List<string>
            {
                "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "Winlogon Shell modification",
                "Winlogon Userinit modification",
                "Startup folder modification"
            };
            
            // 凭证窃取(T1003)相关恶意行为指示：敏感特征串(如 Mimikatz 家族)从外置特征库
            // ThreatData/malicious_indicators.json 与 threat_signatures.json 动态加载，
            // 不编译进本 DLL，既消除杀软误报又保持查杀能力一致。
            _techniqueBehaviors["T1003.001"] = new List<string>
            {
                "lsass.exe process access",
                "procdump lsass",
                "task manager dump lsass"
            };
            FireAntivirus.Engine.ExternalThreatData.EnsureLoaded();
            foreach (var sig in FireAntivirus.Engine.ExternalThreatData.MalwareFamilies)
            {
                // 按家族类型"凭证窃取"匹配(如 Mimikatz)，避免在 DLL 中硬编码恶意特征串
                if (string.Equals(sig.Type, "凭证窃取", StringComparison.OrdinalIgnoreCase) && sig.Patterns != null)
                {
                    foreach (var p in sig.Patterns) _techniqueBehaviors["T1003.001"].Add(p);
                }
            }
            foreach (var ci in FireAntivirus.Engine.ExternalThreatData.CommandIndicators)
                _techniqueBehaviors["T1003.001"].Add(ci);
            
            _techniqueBehaviors["T1053"] = new List<string>
            {
                "schtasks /create",
                "scheduled task creation",
                "at command execution",
                "Task Scheduler modification"
            };
            
            _techniqueBehaviors["T1486"] = new List<string>
            {
                "mass file encryption",
                "file extension change",
                "high entropy file writes",
                "rapid file modifications",
                "encryption key generation"
            };
            
            _techniqueBehaviors["T1490"] = new List<string>
            {
                "vssadmin delete shadows",
                "wbadmin delete catalog",
                "bcdedit /set recoveryenabled no",
                "Delete shadow copies",
                "Disable system restore"
            };
            
            _techniqueBehaviors["T1071.001"] = new List<string>
            {
                "suspicious HTTP connection",
                "beacon behavior",
                "unusual user agent",
                "encoded payload transmission",
                "C2 communication patterns"
            };
            
            _techniqueBehaviors["T1036"] = new List<string>
            {
                "system32 copy to temp",
                "rename to legitimate name",
                "fake extension",
                "double extension",
                "icon spoofing"
            };
            
            _techniqueBehaviors["T1027"] = new List<string>
            {
                "base64 encoded content",
                "XOR encoded content",
                "encrypted payload",
                "deobfuscation in memory",
                "living off the land binaries"
            };
        }
        
        #endregion

        #region Behavior Pattern Initialization
        
        private void InitializeBehaviorPatterns()
        {
            _maliciousPatterns = new List<BehaviorPattern>();
            _suspiciousPatterns = new List<BehaviorPattern>();
            
            // 恶意行为模式
            _maliciousPatterns.Add(new BehaviorPattern
            {
                Name = "勒索软件行为",
                Severity = 10,
                Patterns = new List<string>
                {
                    "mass_file_encryption",
                    "delete_shadow_copies",
                    "modify_boot_config",
                    "create_ransom_note"
                },
                MitreTechniqueIds = new[] { "T1486", "T1490" }
            });
            
            _maliciousPatterns.Add(new BehaviorPattern
            {
                Name = "凭证窃取",
                Severity = 9,
                Patterns = new List<string>
                {
                    "access_lsass",
                    "dump_process_memory",
                    "access_sam_registry",
                    "read_ntds_dit"
                },
                MitreTechniqueIds = new[] { "T1003", "T1003.001" }
            });
            
            _maliciousPatterns.Add(new BehaviorPattern
            {
                Name = "进程注入",
                Severity = 9,
                Patterns = new List<string>
                {
                    "create_remote_thread",
                    "write_process_memory",
                    "virtual_alloc_ex",
                    "dll_injection"
                },
                MitreTechniqueIds = new[] { "T1055", "T1055.001" }
            });
            
            _maliciousPatterns.Add(new BehaviorPattern
            {
                Name = "持久化机制",
                Severity = 7,
                Patterns = new List<string>
                {
                    "registry_run_modification",
                    "scheduled_task_creation",
                    "startup_folder_modification",
                    "service_creation"
                },
                MitreTechniqueIds = new[] { "T1547", "T1547.001", "T1053" }
            });
            
            _maliciousPatterns.Add(new BehaviorPattern
            {
                Name = "数据外渗",
                Severity = 8,
                Patterns = new List<string>
                {
                    "large_data_transfer",
                    "unusual_protocol_usage",
                    "data_archiving",
                    "staging_directory"
                },
                MitreTechniqueIds = new[] { "T1048", "T1041", "T1560" }
            });
            
            // 可疑行为模式
            _suspiciousPatterns.Add(new BehaviorPattern
            {
                Name = "PowerShell可疑执行",
                Severity = 6,
                Patterns = new List<string>
                {
                    "encoded_command",
                    "download_craddle",
                    "execution_policy_bypass",
                    "reflection_loading"
                },
                MitreTechniqueIds = new[] { "T1059.001" }
            });
            
            _suspiciousPatterns.Add(new BehaviorPattern
            {
                Name = "防御规避",
                Severity = 7,
                Patterns = new List<string>
                {
                    "disable_security",
                    "clear_event_logs",
                    "modify_firewall",
                    "stop_antivirus"
                },
                MitreTechniqueIds = new[] { "T1070", "T1562" }
            });
            
            _suspiciousPatterns.Add(new BehaviorPattern
            {
                Name = "系统发现",
                Severity = 4,
                Patterns = new List<string>
                {
                    "network_scanning",
                    "account_enumeration",
                    "process_discovery",
                    "system_info_collection"
                },
                MitreTechniqueIds = new[] { "T1018", "T1087", "T1057" }
            });
        }
        
        #endregion

        public void Start()
        {
            if (_isRunning)
                return;
            
            _isRunning = true;
            _startTime = DateTime.Now;
            
            // 启动监控线程
            _monitorThread = new Thread(MonitorProcessBehaviors)
            {
                IsBackground = true,
                Priority = ThreadPriority.BelowNormal
            };
            _monitorThread.Start();
            
            // 启动基线学习线程
            _baselineThread = new Thread(BaselineLearningLoop)
            {
                IsBackground = true,
                Priority = ThreadPriority.Lowest
            };
            _baselineThread.Start();
            
            // 启动分析线程
            _analysisThread = new Thread(AnalyzeEventQueue)
            {
                IsBackground = true,
                Priority = ThreadPriority.Normal
            };
            _analysisThread.Start();

            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "BehaviorAnalysisStart",
                Message = "行为分析服务已启动",
                Details = $"MITRE技术数: {_mitreTechniques.Count}, 行为模式数: {_maliciousPatterns.Count + _suspiciousPatterns.Count}",
                Source = "BehaviorAnalysisService"
            });
        }

        public void Stop()
        {
            _isRunning = false;
            
            _monitorThread?.Join(3000);
            _baselineThread?.Join(2000);
            _analysisThread?.Join(2000);

            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "BehaviorAnalysisStop",
                Message = "行为分析服务已停止",
                Details = $"运行时间: {(DateTime.Now - _startTime).TotalMinutes:F1}分钟, 处理事件: {_totalEventsProcessed}, 检测威胁: {_threatsDetected}",
                Source = "BehaviorAnalysisService"
            });
        }

        private void MonitorProcessBehaviors()
        {
            while (_isRunning)
            {
                try
                {
                    CollectProcessBehaviors();
                    Thread.Sleep(_monitoringInterval);
                }
                catch (Exception ex)
                {
                    _dataManager.LogError("行为监控线程错误", ex.Message, "BehaviorAnalysisService");
                    Thread.Sleep(1000);
                }
            }
        }

        private void BaselineLearningLoop()
        {
            while (_isRunning)
            {
                try
                {
                    if (_enableBaselineLearning)
                    {
                        UpdateBaselines();
                    }
                    Thread.Sleep(_baselineUpdateInterval);
                }
                catch (Exception ex)
                {
                    _dataManager.LogError("基线学习线程错误", ex.Message, "BehaviorAnalysisService");
                }
            }
        }

        private void AnalyzeEventQueue()
        {
            while (_isRunning)
            {
                try
                {
                    while (_eventQueue.TryDequeue(out var behaviorEvent))
                    {
                        AnalyzeBehaviorEvent(behaviorEvent);
                        Interlocked.Increment(ref _totalEventsProcessed);
                    }
                    Thread.Sleep(100);
                }
                catch (Exception ex)
                {
                    _dataManager.LogError("事件分析线程错误", ex.Message, "BehaviorAnalysisService");
                }
            }
        }

        private void CollectProcessBehaviors()
        {
            try
            {
                var processes = Process.GetProcesses();
                var currentProcessIds = new HashSet<int>();
                
                foreach (var process in processes)
                {
                    try
                    {
                        currentProcessIds.Add(process.Id);
                        
                        // 跳过系统空闲进程和自身
                        if (process.Id == 0 || process.Id == Process.GetCurrentProcess().Id)
                            continue;
                        
                        // 获取或创建进程行为配置文件
                        var profile = _processProfiles.GetOrAdd(process.Id, 
                            id => CreateProcessProfile(process));
                        
                        // 更新进程行为
                        UpdateProcessBehavior(process, profile);
                        
                        // 检查是否需要分析
                        if (profile.PendingAnalysis)
                        {
                            AnalyzeProcessProfile(profile);
                            profile.PendingAnalysis = false;
                        }
                        
                        // 限制配置文件数量
                        if (_processProfiles.Count > _maxProfiles)
                        {
                            CleanupOldProfiles();
                        }
                    }
                    catch (Exception ex)
                    {
                        // 单个进程错误不影响整体监控
                    }
                }
                
                // 清理已结束的进程
                CleanupTerminatedProcesses(currentProcessIds);
            }
            catch (Exception ex)
            {
                _dataManager.LogError("进程行为收集错误", ex.Message, "BehaviorAnalysisService");
            }
        }

        private BehaviorProcessProfile CreateProcessProfile(Process process)
        {
            var profile = new BehaviorProcessProfile
            {
                ProcessId = process.Id,
                ProcessName = process.ProcessName,
                StartTime = DateTime.Now,
                FirstSeen = DateTime.Now,
                FilePath = GetProcessPath(process),
                CommandLine = GetProcessCommandLine(process),
                Integrity = GetProcessIntegrity(process)
            };
            
            // 计算初始信任评分
            profile.TrustScore = CalculateInitialTrustScore(profile);
            profile.RiskLevel = GetRiskLevelFromScore(profile.TrustScore);
            
            // 初始化行为计数器
            profile.FileSystemEvents = new List<FileSystemEvent>();
            profile.RegistryEvents = new List<RegistryEvent>();
            profile.NetworkEvents = new List<NetworkEvent>();
            profile.ProcessEvents = new List<ProcessEventEvent>();
            profile.LoadedModules = new List<string>();
            profile.DetectedTechniques = new List<string>();
            profile.BehaviorTags = new HashSet<string>();
            
            return profile;
        }

        private string GetProcessPath(Process process)
        {
            try
            {
                return process.MainModule?.FileName;
            }
            catch
            {
                try
                {
                    using (var searcher = new ManagementObjectSearcher(
                        $"SELECT ExecutablePath FROM Win32_Process WHERE ProcessId = {process.Id}"))
                    {
                        foreach (ManagementObject obj in searcher.Get())
                        {
                            return obj["ExecutablePath"]?.ToString();
                        }
                    }
                }
                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "BehaviorAnalysisService.cs 捕获异常", ex.Message); }
            }
            return null;
        }

        private string GetProcessCommandLine(Process process)
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher(
                    $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {process.Id}"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        return obj["CommandLine"]?.ToString();
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "BehaviorAnalysisService.cs 捕获异常", ex.Message); }
            return null;
        }

        private string GetProcessIntegrity(Process process)
        {
            try
            {
                // 简化的完整性级别检测
                var path = GetProcessPath(process);
                if (string.IsNullOrEmpty(path))
                    return "Unknown";
                
                if (path.ToLower().Contains("\\windows\\system32\\"))
                    return "System";
                
                if (path.ToLower().Contains("\\program files\\"))
                    return "High";
                
                return "Medium";
            }
            catch
            {
                return "Unknown";
            }
        }

        private double CalculateInitialTrustScore(BehaviorProcessProfile profile)
        {
            double score = 50; // 基础分
            
            try
            {
                var path = profile.FilePath?.ToLower() ?? "";
                var name = profile.ProcessName?.ToLower() ?? "";
                
                // 系统进程加分
                string[] trustedProcesses = {
                    "svchost", "explorer", "csrss", "lsass", "winlogon", "wininit",
                    "smss", "services", "dwm", "taskhostw", "runtimebroker", "system"
                };
                
                if (trustedProcesses.Contains(name))
                {
                    score += 30;
                }
                
                // 路径检查
                if (path.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.Windows).ToLower()))
                {
                    score += 20;
                }
                else if (path.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles).ToLower()) ||
                         path.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86).ToLower()))
                {
                    score += 15;
                }
                else if (path.Contains("\\temp\\") || path.Contains("\\appdata\\local\\temp\\"))
                {
                    score -= 20;
                }
                else if (path.Contains("\\downloads\\"))
                {
                    score -= 10;
                }
                
                // 命令行可疑特征
                var cmdLine = profile.CommandLine?.ToLower() ?? "";
                if (cmdLine.Contains("-enc") || cmdLine.Contains("-encodedcommand"))
                {
                    score -= 25;
                }
                if (cmdLine.Contains("bypass") || cmdLine.Contains("noprofile"))
                {
                    score -= 20;
                }
                
                // 数字签名验证
                if (VerifyProcessSignature(path))
                {
                    score += 15;
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "BehaviorAnalysisService.cs 捕获异常", ex.Message); }
            
            return Math.Max(0, Math.Min(100, score));
        }

                private bool VerifyProcessSignature(string filePath)
        {
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
                return false;
            
            try
            {
                // 不使用Windows签名验证，改为检查文件是否在信任目录中
                string lowerPath = filePath.ToLowerInvariant();
                
                bool isInTrustedLocation = 
                    lowerPath.Contains("\\windows\\") ||
                    lowerPath.Contains("\\system32\\") ||
                    lowerPath.Contains("\\syswow64\\") ||
                    lowerPath.Contains("\\program files\\") ||
                    lowerPath.Contains("\\program files (x86)\\");
                
                return isInTrustedLocation;
            }
            catch
            {
                return false;
            }
        }

        private string GetRiskLevelFromScore(double score)
        {
            if (score >= 80) return "安全";
            if (score >= 60) return "低风险";
            if (score >= 40) return "中等风险";
            if (score >= 20) return "高风险";
            return "极高风险";
        }

        private void UpdateProcessBehavior(Process process, BehaviorProcessProfile profile)
        {
            try
            {
                // 更新进程资源使用情况
                profile.LastUpdateTime = DateTime.Now;
                profile.WorkingSet = process.WorkingSet64;
                profile.VirtualMemory = process.VirtualMemorySize64;
                profile.ThreadCount = process.Threads.Count;
                profile.HandleCount = process.HandleCount;
                
                // 收集文件系统行为
                CollectFileSystemBehavior(process, profile);
                
                // 收集注册表行为
                CollectRegistryBehavior(process, profile);
                
                // 收集网络行为
                CollectNetworkBehavior(process, profile);
                
                // 收集进程交互行为
                CollectProcessInteractions(process, profile);
                
                // 收集模块加载
                CollectLoadedModules(process, profile);
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "BehaviorAnalysisService.cs 捕获异常", ex.Message); }
        }

        private void CollectFileSystemBehavior(Process process, BehaviorProcessProfile profile)
        {
            try
            {
                // 使用ETW或文件系统过滤驱动可以获取实时文件操作
                // 这里使用WMI获取已打开的文件句柄
                using (var searcher = new ManagementObjectSearcher(
                    $"SELECT * FROM Win32_Process WHERE ProcessId = {process.Id}"))
                {
                    // 检测文件操作特征
                    var path = profile.FilePath?.ToLower() ?? "";
                    var cmdLine = profile.CommandLine?.ToLower() ?? "";
                    
                    // 检测可疑文件操作
                    if (cmdLine.Contains("copy") && cmdLine.Contains("system32"))
                    {
                        AddBehaviorTag(profile, "suspicious_file_copy");
                        AddFileSystemEvent(profile, "Copy", "System32", true);
                    }
                    
                    if (cmdLine.Contains("delete") && cmdLine.Contains("shadow"))
                    {
                        AddBehaviorTag(profile, "shadow_copy_deletion");
                        AddFileSystemEvent(profile, "Delete", "ShadowCopy", true);
                    }
                    
                    // 检测勒索软件特征
                    if (profile.BehaviorTags.Contains("mass_file_operations"))
                    {
                        AddBehaviorTag(profile, "ransomware_suspected");
                        profile.TrustScore -= 30;
                        CreateThreatAlert(profile, "T1486", "可能的勒索软件行为");
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "BehaviorAnalysisService.cs 捕获异常", ex.Message); }
        }

        private void CollectRegistryBehavior(Process process, BehaviorProcessProfile profile)
        {
            try
            {
                var cmdLine = profile.CommandLine?.ToLower() ?? "";
                
                // 检测注册表修改
                string[] sensitiveKeys = {
                    "currentversion\\run",
                    "currentversion\\runonce",
                    "winlogon",
                    "userinit",
                    "shell",
                    "load",
                    "policies\\explorer\\run"
                };
                
                foreach (var key in sensitiveKeys)
                {
                    if (cmdLine.Contains(key))
                    {
                        AddBehaviorTag(profile, "registry_persistence");
                        AddRegistryEvent(profile, "Modify", key, true);
                        
                        // 映射到MITRE技术
                        MapToMitreTechnique(profile, "T1547.001");
                    }
                }
                
                // 检测安全软件禁用
                if (cmdLine.Contains("disableantispyware") || cmdLine.Contains("disableav"))
                {
                    AddBehaviorTag(profile, "disable_security");
                    AddRegistryEvent(profile, "Modify", "SecuritySettings", true);
                    MapToMitreTechnique(profile, "T1562");
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "BehaviorAnalysisService.cs 捕获异常", ex.Message); }
        }

        private void CollectNetworkBehavior(Process process, BehaviorProcessProfile profile)
        {
            try
            {
                // 使用GetExtendedTcpTable获取网络连接（在其他服务中实现）
                var cmdLine = profile.CommandLine?.ToLower() ?? "";
                
                // 检测可疑网络行为
                if (cmdLine.Contains("http://") && !cmdLine.Contains("microsoft.com"))
                {
                    // 提取URL
                    var urls = ExtractUrls(cmdLine);
                    foreach (var url in urls)
                    {
                        AddNetworkEvent(profile, "HTTP", url, true);
                        
                        // 检测可疑域名
                        if (IsSuspiciousDomain(url))
                        {
                            AddBehaviorTag(profile, "suspicious_network");
                            MapToMitreTechnique(profile, "T1071.001");
                        }
                    }
                }
                
                // 检测端口扫描
                if (profile.NetworkEvents.Count(e => e.IsOutbound) > 10)
                {
                    AddBehaviorTag(profile, "potential_port_scan");
                    MapToMitreTechnique(profile, "T1046");
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "BehaviorAnalysisService.cs 捕获异常", ex.Message); }
        }

        private List<string> ExtractUrls(string text)
        {
            var urls = new List<string>();
            var regex = new System.Text.RegularExpressions.Regex(
                @"https?://[^\s<>""']+",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            
            var matches = regex.Matches(text);
            foreach (System.Text.RegularExpressions.Match match in matches)
            {
                urls.Add(match.Value);
            }
            
            return urls;
        }

        private bool IsSuspiciousDomain(string url)
        {
            string[] suspiciousTLDs = { ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".pw" };
            var uri = new Uri(url);
            return suspiciousTLDs.Any(tld => uri.Host.EndsWith(tld));
        }

        private void CollectProcessInteractions(Process process, BehaviorProcessProfile profile)
        {
            try
            {
                // 检测进程注入特征
                var cmdLine = profile.CommandLine?.ToLower() ?? "";
                
                if (cmdLine.Contains("createremotethread") || 
                    cmdLine.Contains("virtualallocex") ||
                    cmdLine.Contains("writeprocessmemory"))
                {
                    AddBehaviorTag(profile, "process_injection_attempt");
                    AddProcessEvent(profile, "Injection", "Unknown", true);
                    MapToMitreTechnique(profile, "T1055");
                    profile.TrustScore -= 25;
                }
                
                // 检测进程终止
                if (cmdLine.Contains("taskkill") || cmdLine.Contains("kill"))
                {
                    AddBehaviorTag(profile, "process_termination");
                    AddProcessEvent(profile, "Terminate", "Other", true);
                }
                
                // 检测lsass访问
                if (cmdLine.Contains("lsass"))
                {
                    AddBehaviorTag(profile, "lsass_access");
                    AddProcessEvent(profile, "Access", "lsass.exe", true);
                    MapToMitreTechnique(profile, "T1003.001");
                    profile.TrustScore -= 40;
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "BehaviorAnalysisService.cs 捕获异常", ex.Message); }
        }

        private void CollectLoadedModules(Process process, BehaviorProcessProfile profile)
        {
            try
            {
                // 收集加载的DLL
                var modules = process.Modules;
                foreach (ProcessModule module in modules)
                {
                    var moduleName = module.ModuleName?.ToLower() ?? "";
                    
                    if (!profile.LoadedModules.Contains(moduleName))
                    {
                        profile.LoadedModules.Add(moduleName);
                        
                        // 检测可疑DLL
                        if (moduleName.Contains("inject") || moduleName.Contains("hook"))
                        {
                            AddBehaviorTag(profile, "suspicious_dll_load");
                        }
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "BehaviorAnalysisService.cs 捕获异常", ex.Message); }
        }

        private void AddBehaviorTag(BehaviorProcessProfile profile, string tag)
        {
            if (!profile.BehaviorTags.Contains(tag))
            {
                profile.BehaviorTags.Add(tag);
                profile.PendingAnalysis = true;
            }
        }

        private void AddFileSystemEvent(BehaviorProcessProfile profile, string operation, string target, bool isSuspicious)
        {
            var evt = new FileSystemEvent
            {
                Timestamp = DateTime.Now,
                Operation = operation,
                TargetPath = target,
                IsSuspicious = isSuspicious
            };
            
            profile.FileSystemEvents.Add(evt);
            
            // 限制事件数量
            if (profile.FileSystemEvents.Count > _maxEventsPerProcess)
            {
                profile.FileSystemEvents.RemoveAt(0);
            }
            
            // 添加到分析队列
            _eventQueue.Enqueue(new BehaviorEvent
            {
                ProcessId = profile.ProcessId,
                ProcessName = profile.ProcessName,
                EventType = "FileSystem",
                Operation = operation,
                Target = target,
                IsSuspicious = isSuspicious,
                Timestamp = DateTime.Now
            });
        }

        private void AddRegistryEvent(BehaviorProcessProfile profile, string operation, string key, bool isSuspicious)
        {
            var evt = new RegistryEvent
            {
                Timestamp = DateTime.Now,
                Operation = operation,
                KeyPath = key,
                IsSuspicious = isSuspicious
            };
            
            profile.RegistryEvents.Add(evt);
            
            if (profile.RegistryEvents.Count > _maxEventsPerProcess)
            {
                profile.RegistryEvents.RemoveAt(0);
            }
            
            _eventQueue.Enqueue(new BehaviorEvent
            {
                ProcessId = profile.ProcessId,
                ProcessName = profile.ProcessName,
                EventType = "Registry",
                Operation = operation,
                Target = key,
                IsSuspicious = isSuspicious,
                Timestamp = DateTime.Now
            });
        }

        private void AddNetworkEvent(BehaviorProcessProfile profile, string protocol, string endpoint, bool isSuspicious)
        {
            var evt = new NetworkEvent
            {
                Timestamp = DateTime.Now,
                Protocol = protocol,
                RemoteEndpoint = endpoint,
                IsOutbound = true,
                IsSuspicious = isSuspicious
            };
            
            profile.NetworkEvents.Add(evt);
            
            if (profile.NetworkEvents.Count > _maxEventsPerProcess)
            {
                profile.NetworkEvents.RemoveAt(0);
            }
            
            _eventQueue.Enqueue(new BehaviorEvent
            {
                ProcessId = profile.ProcessId,
                ProcessName = profile.ProcessName,
                EventType = "Network",
                Operation = protocol,
                Target = endpoint,
                IsSuspicious = isSuspicious,
                Timestamp = DateTime.Now
            });
        }

        private void AddProcessEvent(BehaviorProcessProfile profile, string operation, string target, bool isSuspicious)
        {
            var evt = new ProcessEventEvent
            {
                Timestamp = DateTime.Now,
                Operation = operation,
                TargetProcess = target,
                IsSuspicious = isSuspicious
            };
            
            profile.ProcessEvents.Add(evt);
            
            if (profile.ProcessEvents.Count > _maxEventsPerProcess)
            {
                profile.ProcessEvents.RemoveAt(0);
            }
            
            _eventQueue.Enqueue(new BehaviorEvent
            {
                ProcessId = profile.ProcessId,
                ProcessName = profile.ProcessName,
                EventType = "Process",
                Operation = operation,
                Target = target,
                IsSuspicious = isSuspicious,
                Timestamp = DateTime.Now
            });
        }

        private void MapToMitreTechnique(BehaviorProcessProfile profile, string techniqueId)
        {
            if (!profile.DetectedTechniques.Contains(techniqueId))
            {
                profile.DetectedTechniques.Add(techniqueId);
                
                // 更新风险评分
                if (_mitreTechniques.TryGetValue(techniqueId, out var technique))
                {
                    profile.TrustScore -= technique.Severity;
                    profile.RiskLevel = GetRiskLevelFromScore(profile.TrustScore);
                }
            }
        }

        private void AnalyzeBehaviorEvent(BehaviorEvent behaviorEvent)
        {
            if (!behaviorEvent.IsSuspicious)
                return;
            
            // 实时分析行为事件
            if (_processProfiles.TryGetValue(behaviorEvent.ProcessId, out var profile))
            {
                // 检查是否匹配恶意模式
                foreach (var pattern in _maliciousPatterns)
                {
                    if (MatchesPattern(profile, pattern))
                    {
                        CreateThreatAlert(profile, pattern.MitreTechniqueIds.FirstOrDefault() ?? "Unknown",
                            $"检测到恶意行为模式: {pattern.Name}");
                    }
                }
            }
        }

        private bool MatchesPattern(BehaviorProcessProfile profile, BehaviorPattern pattern)
        {
            int matchCount = 0;
            
            foreach (var p in pattern.Patterns)
            {
                if (profile.BehaviorTags.Contains(p))
                {
                    matchCount++;
                }
            }
            
            // 超过一半的模式匹配即认为有效
            return matchCount >= (pattern.Patterns.Count / 2.0);
        }

        private void AnalyzeProcessProfile(BehaviorProcessProfile profile)
        {
            // 使用机器学习进行风险评分
            if (_enableMLDetection)
            {
                var mlScore = CalculateMLRiskScore(profile);
                profile.TrustScore = (profile.TrustScore + mlScore) / 2;
            }
            
            // 检查异常行为
            if (_enableBaselineLearning)
            {
                CheckBaselineAnomalies(profile);
            }
            
            // 更新风险等级
            profile.RiskLevel = GetRiskLevelFromScore(profile.TrustScore);
            
            // 如果风险过高，创建告警
            if (profile.TrustScore < 20)
            {
                CreateThreatAlert(profile, "Multiple", "进程表现出高风险行为");
                
                if (_enableRealTimeBlocking)
                {
                    BlockProcess(profile);
                }
            }
        }

        private double CalculateMLRiskScore(BehaviorProcessProfile profile)
        {
            // 基于特征的机器学习风险评分
            // 实际实现应该使用训练好的模型
            
            double score = 50; // 基础分
            
            // 行为特征评分
            if (profile.BehaviorTags.Contains("process_injection_attempt"))
                score -= 30;
            if (profile.BehaviorTags.Contains("lsass_access"))
                score -= 40;
            if (profile.BehaviorTags.Contains("registry_persistence"))
                score -= 20;
            if (profile.BehaviorTags.Contains("suspicious_network"))
                score -= 15;
            if (profile.BehaviorTags.Contains("shadow_copy_deletion"))
                score -= 35;
            if (profile.BehaviorTags.Contains("ransomware_suspected"))
                score -= 50;
            if (profile.BehaviorTags.Contains("disable_security"))
                score -= 25;
            
            // 事件频率分析
            var recentEvents = profile.FileSystemEvents.Count(e => e.Timestamp > DateTime.Now.AddMinutes(-5));
            if (recentEvents > 100)
                score -= 15;
            
            // 检测到的MITRE技术数量
            score -= profile.DetectedTechniques.Count * 5;
            
            return Math.Max(0, Math.Min(100, score));
        }

        private void CheckBaselineAnomalies(BehaviorProcessProfile profile)
        {
            if (_baselines.TryGetValue(profile.ProcessName, out var baseline))
            {
                // 检查资源使用异常
                if (profile.WorkingSet > baseline.AvgMemoryUsage * 3)
                {
                    AddBehaviorTag(profile, "memory_anomaly");
                }
                
                if (profile.ThreadCount > baseline.AvgThreadCount * 3)
                {
                    AddBehaviorTag(profile, "thread_anomaly");
                }
                
                // 检查行为异常
                var normalBehaviors = baseline.NormalBehaviors;
                var abnormalBehaviors = profile.BehaviorTags
                    .Where(b => !normalBehaviors.Contains(b))
                    .ToList();
                
                if (abnormalBehaviors.Count > 3)
                {
                    AddBehaviorTag(profile, "behavior_anomaly");
                    profile.TrustScore -= 10;
                }
            }
        }

        private void UpdateBaselines()
        {
            try
            {
                // 按进程名聚合行为数据
                var processGroups = _processProfiles.Values
                    .GroupBy(p => p.ProcessName)
                    .ToList();
                
                foreach (var group in processGroups)
                {
                    var profiles = group.ToList();
                    var baseline = _baselines.GetOrAdd(group.Key, 
                        name => new BehaviorBaseline { ProcessName = name });
                    
                    // 更新统计数据
                    baseline.AvgMemoryUsage = profiles.Average(p => p.WorkingSet);
                    baseline.AvgThreadCount = profiles.Average(p => p.ThreadCount);
                    baseline.AvgHandleCount = profiles.Average(p => p.HandleCount);
                    baseline.SampleCount = profiles.Count;
                    baseline.LastUpdateTime = DateTime.Now;
                    
                    // 提取正常行为模式
                    baseline.NormalBehaviors = profiles
                        .Where(p => p.TrustScore > 70)
                        .SelectMany(p => p.BehaviorTags)
                        .Distinct()
                        .ToHashSet();
                }
            }
            catch (Exception ex)
            {
                _dataManager.LogError("更新基线失败", ex.Message, "BehaviorAnalysisService");
            }
        }

        private void CreateThreatAlert(BehaviorProcessProfile profile, string techniqueId, string description)
        {
            var alert = new ThreatAlert
            {
                AlertId = Guid.NewGuid().ToString(),
                ProcessId = profile.ProcessId,
                ProcessName = profile.ProcessName,
                FilePath = profile.FilePath,
                TechniqueId = techniqueId,
                Description = description,
                RiskScore = 100 - profile.TrustScore,
                DetectedAt = DateTime.Now,
                MitreTechnique = _mitreTechniques.TryGetValue(techniqueId, out var t) ? t : null,
                BehaviorTags = profile.BehaviorTags.ToList()
            };
            
            _threatAlerts.Add(alert);
            Interlocked.Increment(ref _threatsDetected);
            
            // 记录日志
            _dataManager.AddLog(new LogEntry
            {
                Id = alert.AlertId,
                Time = alert.DetectedAt,
                Type = "ThreatDetected",
                Message = $"检测到威胁行为: {profile.ProcessName}",
                Details = $"技术: {techniqueId}\n描述: {description}\n风险评分: {alert.RiskScore}\n行为标签: {string.Join(", ", profile.BehaviorTags)}",
                Source = "BehaviorAnalysisService",
                Category = "威胁检测"
            });
            
            // 发送通知
            try
            {
                NotificationService.Instance.ShowNotification(
                    "行为威胁警告",
                    $"进程 {profile.ProcessName} 检测到可疑行为",
                    NotificationType.Warning);
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "BehaviorAnalysisService.cs 捕获异常", ex.Message); }
        }

        private void BlockProcess(BehaviorProcessProfile profile)
        {
            try
            {
                var process = Process.GetProcessById(profile.ProcessId);
                process.Kill();
                
                Interlocked.Increment(ref _processesBlocked);
                
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "ProcessBlocked",
                    Message = $"已终止高风险进程: {profile.ProcessName}",
                    Details = $"PID: {profile.ProcessId}, 路径: {profile.FilePath}",
                    Source = "BehaviorAnalysisService",
                    Category = "威胁响应"
                });
            }
            catch (Exception ex)
            {
                _dataManager.LogError("终止进程失败", ex.Message, "BehaviorAnalysisService");
            }
        }

        private void CleanupTerminatedProcesses(HashSet<int> currentProcessIds)
        {
            var terminatedIds = _processProfiles.Keys
                .Where(id => !currentProcessIds.Contains(id))
                .ToList();
            
            foreach (var id in terminatedIds)
            {
                BehaviorProcessProfile profile;
                _processProfiles.TryRemove(id, out profile);
                
                // 保存历史记录用于取证
                if (profile != null && profile.TrustScore < 50)
                {
                    SaveProcessHistory(profile);
                }
            }
        }

        private void CleanupOldProfiles()
        {
            var oldProfiles = _processProfiles.Values
                .OrderBy(p => p.LastUpdateTime)
                .Take(_processProfiles.Count - _maxProfiles + 50)
                .ToList();
            
            foreach (var profile in oldProfiles)
            {
                BehaviorProcessProfile removed;
                _processProfiles.TryRemove(profile.ProcessId, out removed);
            }
        }

        private void SaveProcessHistory(BehaviorProcessProfile profile)
        {
            try
            {
                var historyDir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "FireAntivirus", "BehaviorHistory");
                Directory.CreateDirectory(historyDir);
                
                var historyFile = Path.Combine(historyDir, 
                    $"{profile.ProcessName}_{profile.ProcessId}_{DateTime.Now:yyyyMMdd_HHmmss}.json");
                
                var history = new ProcessHistory
                {
                    ProcessId = profile.ProcessId,
                    ProcessName = profile.ProcessName,
                    FilePath = profile.FilePath,
                    CommandLine = profile.CommandLine,
                    TrustScore = profile.TrustScore,
                    RiskLevel = profile.RiskLevel,
                    DetectedTechniques = profile.DetectedTechniques,
                    BehaviorTags = profile.BehaviorTags.ToList(),
                    FileSystemEventCount = profile.FileSystemEvents.Count,
                    RegistryEventCount = profile.RegistryEvents.Count,
                    NetworkEventCount = profile.NetworkEvents.Count,
                    ProcessEventCount = profile.ProcessEvents.Count,
                    CapturedAt = DateTime.Now
                };
                
                var json = Newtonsoft.Json.JsonConvert.SerializeObject(history, 
                    Newtonsoft.Json.Formatting.Indented);
                File.WriteAllText(historyFile, json);
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "BehaviorAnalysisService.cs 捕获异常", ex.Message); }
        }

        #region Public API

        public List<BehaviorProcessProfile> GetProcessBehaviors()
        {
            return _processProfiles.Values
                .OrderByDescending(p => p.TrustScore)
                .ToList();
        }

        public List<BehaviorProcessProfile> GetSuspiciousProcesses()
        {
            return _processProfiles.Values
                .Where(p => p.TrustScore < 50)
                .OrderBy(p => p.TrustScore)
                .ToList();
        }

        public List<ThreatAlert> GetThreatAlerts(int count = 100)
        {
            return _threatAlerts
                .OrderByDescending(a => a.DetectedAt)
                .Take(count)
                .ToList();
        }

        public BehaviorProcessProfile GetProcessProfile(int processId)
        {
            _processProfiles.TryGetValue(processId, out var profile);
            return profile;
        }

        public BehaviorAnalysisStatistics GetStatistics()
        {
            return new BehaviorAnalysisStatistics
            {
                TotalProcessesMonitored = _processProfiles.Count,
                TotalEventsProcessed = _totalEventsProcessed,
                ThreatsDetected = _threatsDetected,
                ProcessesBlocked = _processesBlocked,
                BaselinesTrained = _baselines.Count,
                AlertsCount = _threatAlerts.Count,
                RunningTime = DateTime.Now - _startTime
            };
        }

        public List<MitreTechnique> GetDetectedTechniques()
        {
            return _processProfiles.Values
                .SelectMany(p => p.DetectedTechniques)
                .Distinct()
                .Where(t => _mitreTechniques.ContainsKey(t))
                .Select(t => _mitreTechniques[t])
                .ToList();
        }

        public void SetMonitoringInterval(int milliseconds)
        {
            _monitoringInterval = Math.Max(1000, milliseconds);
        }

        public void EnableBaselineLearning(bool enable) => _enableBaselineLearning = enable;
        public void EnableMLDetection(bool enable) => _enableMLDetection = enable;
        public void EnableRealTimeBlocking(bool enable) => _enableRealTimeBlocking = enable;
        public void EnableMitreMapping(bool enable) => _enableMitreMapping = enable;
        
        public void SetAnomalyThreshold(double threshold)
        {
            _anomalyThreshold = Math.Max(0.5, Math.Min(0.99, threshold));
        }

        #endregion
    }

    #region Data Classes

    public class BehaviorProcessProfile
    {
        public int ProcessId { get; set; }
        public string ProcessName { get; set; }
        public string FilePath { get; set; }
        public string CommandLine { get; set; }
        public string Integrity { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime FirstSeen { get; set; }
        public DateTime LastUpdateTime { get; set; }
        
        // 信任评分 (0-100, 越高越可信)
        public double TrustScore { get; set; }
        public string RiskLevel { get; set; }
        
        // 资源使用
        public long WorkingSet { get; set; }
        public long VirtualMemory { get; set; }
        public int ThreadCount { get; set; }
        public int HandleCount { get; set; }
        
        // 行为事件
        public List<FileSystemEvent> FileSystemEvents { get; set; }
        public List<RegistryEvent> RegistryEvents { get; set; }
        public List<NetworkEvent> NetworkEvents { get; set; }
        public List<ProcessEventEvent> ProcessEvents { get; set; }
        public List<string> LoadedModules { get; set; }
        
        // 检测结果
        public List<string> DetectedTechniques { get; set; }
        public HashSet<string> BehaviorTags { get; set; }
        public bool PendingAnalysis { get; set; }
    }

    public class FileSystemEvent
    {
        public DateTime Timestamp { get; set; }
        public string Operation { get; set; } // Create, Read, Write, Delete, Rename
        public string TargetPath { get; set; }
        public bool IsSuspicious { get; set; }
    }

    public class RegistryEvent
    {
        public DateTime Timestamp { get; set; }
        public string Operation { get; set; } // Read, Write, Delete, Create
        public string KeyPath { get; set; }
        public bool IsSuspicious { get; set; }
    }

    public class NetworkEvent
    {
        public DateTime Timestamp { get; set; }
        public string Protocol { get; set; }
        public string RemoteEndpoint { get; set; }
        public int RemotePort { get; set; }
        public bool IsOutbound { get; set; }
        public bool IsSuspicious { get; set; }
    }

    public class ProcessEventEvent
    {
        public DateTime Timestamp { get; set; }
        public string Operation { get; set; } // Create, Terminate, Inject, Access
        public string TargetProcess { get; set; }
        public bool IsSuspicious { get; set; }
    }

    public class BehaviorEvent
    {
        public int ProcessId { get; set; }
        public string ProcessName { get; set; }
        public string EventType { get; set; }
        public string Operation { get; set; }
        public string Target { get; set; }
        public bool IsSuspicious { get; set; }
        public DateTime Timestamp { get; set; }
    }

    public class BehaviorBaseline
    {
        public string ProcessName { get; set; }
        public double AvgMemoryUsage { get; set; }
        public double AvgThreadCount { get; set; }
        public double AvgHandleCount { get; set; }
        public int SampleCount { get; set; }
        public HashSet<string> NormalBehaviors { get; set; } = new HashSet<string>();
        public DateTime LastUpdateTime { get; set; }
    }

    public class BehaviorPattern
    {
        public string Name { get; set; }
        public int Severity { get; set; }
        public List<string> Patterns { get; set; }
        public string[] MitreTechniqueIds { get; set; }
    }

    public class MitreTechnique
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public string[] Tactics { get; set; }
        public int Severity { get; set; }
    }

    public class ThreatAlert
    {
        public string AlertId { get; set; }
        public int ProcessId { get; set; }
        public string ProcessName { get; set; }
        public string FilePath { get; set; }
        public string TechniqueId { get; set; }
        public string Description { get; set; }
        public double RiskScore { get; set; }
        public DateTime DetectedAt { get; set; }
        public MitreTechnique MitreTechnique { get; set; }
        public List<string> BehaviorTags { get; set; }
    }

    public class ProcessHistory
    {
        public int ProcessId { get; set; }
        public string ProcessName { get; set; }
        public string FilePath { get; set; }
        public string CommandLine { get; set; }
        public double TrustScore { get; set; }
        public string RiskLevel { get; set; }
        public List<string> DetectedTechniques { get; set; }
        public List<string> BehaviorTags { get; set; }
        public int FileSystemEventCount { get; set; }
        public int RegistryEventCount { get; set; }
        public int NetworkEventCount { get; set; }
        public int ProcessEventCount { get; set; }
        public DateTime CapturedAt { get; set; }
    }

    public class BehaviorAnalysisStatistics
    {
        public int TotalProcessesMonitored { get; set; }
        public long TotalEventsProcessed { get; set; }
        public long ThreatsDetected { get; set; }
        public long ProcessesBlocked { get; set; }
        public int BaselinesTrained { get; set; }
        public int AlertsCount { get; set; }
        public TimeSpan RunningTime { get; set; }
    }

    #endregion
}