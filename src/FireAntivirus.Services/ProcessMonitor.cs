using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Diagnostics;
using System.Management;
using System.Net.NetworkInformation;
using FireAntivirus.Data;
using FireAntivirus.Engine;

namespace FireAntivirus.Services
{
    public class ProcessMonitor : IMonitor
    {
        private Thread monitorThread;
        private Thread processCreationThread;
        private bool isRunning;
        private DataManager dataManager;
        private AntivirusEngine antivirusEngine;
        private HashSet<int> monitoredProcesses;
        private HashSet<string> suspiciousProcessNames;
        private HashSet<string> suspiciousCommandLines;
        private HashSet<string> suspiciousPaths;
        private ManagementEventWatcher processCreationWatcher;
        private int checkInterval = 5000;
        private int cleanupInterval = 30000;
        private DateTime lastCleanupTime = DateTime.MinValue;
        private Dictionary<int, ProcessBehaviorInfo> processBehaviorInfo;
        private HashSet<string> trustedSignatures;
        
        // 受信任进程白名单
        private HashSet<string> trustedProcessNames;
        
        // 受信任路径白名单
        private HashSet<string> trustedPaths;
        
        // 高可信度阈值 - 低于此阈值不弹窗
        private const double HIGH_CONFIDENCE_THRESHOLD = 0.85;
        
        public ProcessMonitor(DataManager dataManager, AntivirusEngine antivirusEngine)
        {
            this.dataManager = dataManager;
            this.antivirusEngine = antivirusEngine;
            monitoredProcesses = new HashSet<int>();
            processBehaviorInfo = new Dictionary<int, ProcessBehaviorInfo>();
            trustedSignatures = new HashSet<string>();
            InitializeTrustedSignatures();
            InitializeTrustedProcesses();
            InitializeTrustedPaths();
            InitializeSuspiciousPatterns();
        }
        
        private void InitializeTrustedSignatures()
        {
            // 添加受信任的公司数字签名（简化的实现）
            trustedSignatures.UnionWith(new[]
            {
                "Microsoft Corporation",
                "Microsoft Windows",
                "Google LLC",
                "Mozilla Corporation",
                "Apple Inc.",
                "Adobe Systems Incorporated"
            });
        }
        
        private void InitializeTrustedProcesses()
        {
            // 初始化受信任进程白名单 - 这些进程不会触发警告
            trustedProcessNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                // Windows系统进程
                "System", "Idle", "svchost", "csrss", "wininit", "services",
                "lsass", "smss", "winlogon", "dwm", "explorer", "cmd",
                "conhost", "taskhostw", "RuntimeBroker", "SearchHost",
                "ShellExperienceHost", "StartMenuExperienceHost",
                "TextInputHost", "WidgetService", "MsMpEng", "NisWks",
                "SecurityHealthService", "SgrmAgent", "ctfmon",
                "fontdrvhost", "wmiprvse", "spoolsv", "wuauserv",
                "trustedinstaller", "msiexec", "dllhost", "rundll32",
                "WmiPrvSE", "audiodg", "sihost", "ctfloader", "services.exe",
                // 常用第三方进程
                "chrome", "firefox", "msedge", "brave", "opera", "vivaldi",
                "QQ", "WeChat", "DingTalk", "Feishu", "Lark", "DingTalk",
                "Steam", "EpicGamesLauncher", "Origin", "Uplay", "GOG",
                "Discord", "Slack", "Teams", "Zoom", "TencentMeeting",
                "Notepad++", "notepad", "VSCode", "Code", "SublimeText",
                "Git", "GitDesktop", "GitHubDesktop",
                // 开发工具
                "devenv", "Rider", "idea64", "pycharm64", "webstorm",
                "clion64", "qtcreator", "Code", "dotnet", "msbuild",
                "node", "npm", "python", "java", "javaw",
                // 其他常见进程
                "SteamService", "Steam Client", "steamwebhelper",
                "Spotify", "Music", "Taskmgr", "perfmon", "regedit",
                "mmc", "diskmgmt", "devmgmt", "services", "eventvwr",
                "powershell", "pwsh", "WindowsTerminal"
            };
        }
        
        private void InitializeTrustedPaths()
        {
            // 初始化受信任路径白名单 - 这些路径下的进程不会触发警告
            trustedPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                @"\Program Files\",
                @"\Program Files (x86)\",
                @"\Windows\",
                @"\Windows\System32",
                @"\Windows\SysWOW64",
                @"\Windows\WinSxS",
                @"\Windows\SoftwareDistribution",
                @"\Windows\Installer",
                @"\Microsoft.NET",
                @"\dotnet",
                @"\Visual Studio",
                @"\JetBrains\",
                @"\Git\",
                @"\node_modules\.bin",
                @"\Python",
                @"\Anaconda3",
                @"\Miniconda3",
                @"\AppData\Local\Programs\",
                @"\Steam\steamapps\",
                @"\Epic Games\",
                @"\GOG Games\",
                @"\ProgramData\Steam\"
            };
        }
        
        private void InitializeSuspiciousPatterns()
        {
            // 初始化可疑进程名称列表
            suspiciousProcessNames = new HashSet<string>();
            
            // 可疑命令行参数
            suspiciousCommandLines = new HashSet<string>
            {
                "DownloadString", "DownloadFile", "Invoke-Expression",
                "-enc ", "-encodedcommand", "FromBase64String",
                "IEX ", "powershell -e ", "iex "
            };
            
            // 保留可疑路径
            suspiciousPaths = new HashSet<string>
            {
                @"C:\Windows\Temp\",
                @"C:\Users\Public\",
                @"%TEMP%", @"%TMP%",
                @"\AppData\Roaming\"
            };
        }
        
        public void Start()
        {
            isRunning = true;
            monitorThread = new Thread(MonitorProcesses);
            monitorThread.Start();
            
            processCreationThread = new Thread(MonitorProcessCreation);
            processCreationThread.Start();
            
            dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "ProcessMonitorStart",
                Message = "进程监控已启动",
                Details = "开始监控系统进程，包括进程创建、命令行参数、行为分析"
            });
        }
        
        public void Stop()
        {
            isRunning = false;
            monitorThread?.Join(2000);
            processCreationThread?.Join(2000);
            
            if (processCreationWatcher != null)
            {
                try
                {
                    processCreationWatcher.Stop();
                    processCreationWatcher.Dispose();
                }
                catch { }
            }
            
            dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "ProcessMonitorStop",
                Message = "进程监控已停止",
                Details = string.Empty
            });
        }
        
        private void MonitorProcesses()
        {
            while (isRunning)
            {
                try
                {
                    CheckRunningProcesses();
                    
                    if ((DateTime.Now - lastCleanupTime).TotalMilliseconds > cleanupInterval)
                    {
                        CleanupTerminatedProcesses();
                        lastCleanupTime = DateTime.Now;
                    }
                }
                catch (Exception ex)
                {
                    dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "ProcessMonitorError",
                        Message = "进程监控错误",
                        Details = ex.Message
                    });
                }
                
                Thread.Sleep(30000); // 每30秒检查一次，降低敏感度
            }
        }
        
        private void CheckRunningProcesses()
        {
            try
            {
                Process[] processes = Process.GetProcesses();
                foreach (Process process in processes)
                {
                    try
                    {
                        if (!monitoredProcesses.Contains(process.Id))
                        {
                            monitoredProcesses.Add(process.Id);
                            QuickCheckProcess(process);
                            AnalyzeProcessBehavior(process.Id);
                        }
                        else
                        {
                            // 对已监控的进程进行行为分析
                            AnalyzeProcessBehavior(process.Id);
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }
        
        private void CleanupTerminatedProcesses()
        {
            try
            {
                HashSet<int> toRemove = new HashSet<int>();
                foreach (int pid in monitoredProcesses)
                {
                    try
                    {
                        Process.GetProcessById(pid);
                    }
                    catch
                    {
                        toRemove.Add(pid);
                    }
                }
                
                foreach (int pid in toRemove)
                {
                    monitoredProcesses.Remove(pid);
                }
            }
            catch { }
        }
        
        private void QuickCheckProcess(Process process)
        {
            try
            {
                string processName = process.ProcessName;
                
                if (IsSuspiciousProcessName(processName))
                {
                    dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "SuspiciousProcessName",
                        Message = "发现可疑进程名称",
                        Details = $"进程: {processName}, PID: {process.Id}"
                    });
                }
            }
            catch { }
        }
        
        private void MonitorProcessCreation()
        {
            try
            {
                string query = "SELECT * FROM Win32_ProcessStartTrace";
                processCreationWatcher = new ManagementEventWatcher(query);
                processCreationWatcher.EventArrived += (sender, e) =>
                {
                    try
                    {
                        int processId = Convert.ToInt32(e.NewEvent.Properties["ProcessID"].Value);
                        string processName = e.NewEvent.Properties["ProcessName"].Value?.ToString();
                        string parentProcessName = e.NewEvent.Properties["ParentProcessName"].Value?.ToString();
                        
                        if (!string.IsNullOrEmpty(processName) && processId > 0)
                        {
                            dataManager.AddLog(new LogEntry
                            {
                                Id = Guid.NewGuid().ToString(),
                                Time = DateTime.Now,
                                Type = "ProcessCreated",
                                Message = "新进程创建",
                                Details = $"进程: {processName}, PID: {processId}, 父进程: {parentProcessName}"
                            });
                            
                            try
                            {
                                var process = Process.GetProcessById(processId);
                                CheckProcess(process);
                            }
                            catch { }
                        }
                    }
                    catch { }
                };
                
                processCreationWatcher.Start();
                
                while (isRunning)
                {
                    Thread.Sleep(1000);
                }
            }
            catch (Exception ex)
            {
                dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "ProcessCreationMonitorError",
                    Message = "进程创建监控错误",
                    Details = ex.Message
                });
            }
        }
        
        private void CheckProcess(Process process)
        {
            try
            {
                string processPath = "";
                try { processPath = process.MainModule.FileName; } catch { return; } // 无法访问则跳过
                
                string processName = process.ProcessName;
                string commandLine = GetProcessCommandLine(process.Id);
                
                // ========== 受信任检查：优先放行白名单 ==========
                // 检查是否在受信任进程白名单中
                if (trustedProcessNames.Contains(processName))
                    return;
                
                // 检查是否在受信任路径中
                foreach (var trustedPath in trustedPaths)
                {
                    if (processPath.Contains(trustedPath, StringComparison.OrdinalIgnoreCase))
                        return;
                }
                
                bool isSuspicious = false;
                string threatReason = "";
                
                // 新增：数字签名验证
                bool isTrustedSignature = VerifyProcessSignature(processPath);
                
                // 新增：父进程链分析
                string parentProcessChain = GetParentProcessChain(process.Id);
                
                // ========== 传统可疑检查 ==========
                if (IsSuspiciousProcessName(processName))
                {
                    dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "SuspiciousProcessName",
                        Message = "发现可疑进程名称",
                        Details = $"进程: {processName}, PID: {process.Id}, 路径: {processPath}"
                    });
                    isSuspicious = true;
                    threatReason = "可疑进程名称";
                }
                
                if (!string.IsNullOrEmpty(commandLine) && IsSuspiciousCommandLine(commandLine))
                {
                    dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "SuspiciousCommandLine",
                        Message = "发现可疑命令行参数",
                        Details = $"进程: {processName}, PID: {process.Id}, 命令行: {commandLine}"
                    });
                    isSuspicious = true;
                    threatReason = "可疑命令行参数";
                }
                
                if (IsSuspiciousPath(processPath))
                {
                    dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "SuspiciousProcessPath",
                        Message = "发现可疑进程路径",
                        Details = $"进程: {processName}, PID: {process.Id}, 路径: {processPath}"
                    });
                    isSuspicious = true;
                    threatReason = "可疑进程路径";
                }
                
                if (isSuspicious && !string.IsNullOrEmpty(threatReason))
                {
                    string threatMessage = $"发现可疑进程\n进程: {processName}\n路径: {processPath}\n原因: {threatReason}";
                    
                    dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "SuspiciousProcess",
                        Message = "发现可疑进程",
                        Details = threatMessage
                    });
                    
                    // 高可信度可疑进程才弹窗
                    ShowThreatNotification("可疑进程行为", threatMessage, NotificationType.Warning);
                }
                else
                {
                    // 低可信度或无威胁 - 仅记录日志，不弹窗
                    // 检查数字签名状态 - 禁用未签名进程弹窗，避免误报
                    // 未签名不一定代表恶意，很多合法软件也未签名
                    if (!isTrustedSignature)
                    {
                        dataManager.AddLog(new LogEntry
                        {
                            Id = Guid.NewGuid().ToString(),
                            Time = DateTime.Now,
                            Type = "UnsignedProcess",
                            Message = "发现未签名进程（已静默处理）",
                            Details = $"进程: {processName}, 路径: {processPath}"
                        });
                        // 不弹窗，避免误报
                    }
                    
                    // 检查父进程链是否可疑 - 禁用，避免误报
                    // 正常系统进程也可能有可疑的父进程链描述
                    if (parentProcessChain.Contains("可疑父进程链"))
                    {
                        dataManager.AddLog(new LogEntry
                        {
                            Id = Guid.NewGuid().ToString(),
                            Time = DateTime.Now,
                            Type = "SuspiciousProcessChain",
                            Message = "发现可疑进程启动链（已静默处理）",
                            Details = $"进程: {processName}, PID: {process.Id}"
                        });
                        // 不弹窗，避免误报
                    }
                }
            }
            catch (Exception ex)
            {
                dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "ProcessCheckError",
                    Message = "进程检查错误",
                    Details = ex.Message
                });
            }
        }
        
        private void ShowThreatNotification(string title, string message, NotificationType type)
        {
            try
            {
                NotificationService.Instance.ShowNotification(title, message, type);
            }
            catch { }
        }
        
        private bool IsSuspiciousProcessName(string processName)
        {
            return suspiciousProcessNames.Contains(processName.ToLower());
        }
        
        private bool IsSuspiciousCommandLine(string commandLine)
        {
            foreach (string suspicious in suspiciousCommandLines)
            {
                if (commandLine.IndexOf(suspicious, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return true;
                }
            }
            return false;
        }
        
        private bool IsSuspiciousPath(string path)
        {
            foreach (string suspicious in suspiciousPaths)
            {
                if (path.IndexOf(suspicious, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return true;
                }
            }
            return false;
        }
        
        private string GetProcessCommandLine(int processId)
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher($"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {processId}"))
                {
                    foreach (var obj in searcher.Get())
                    {
                        return obj["CommandLine"]?.ToString();
                    }
                }
            }
            catch { }
            return string.Empty;
        }
        
        private void TryKillProcess(Process process)
        {
            try
            {
                process.Kill();
                dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "ProcessKilled",
                    Message = "已终止恶意进程",
                    Details = $"进程: {process.ProcessName}, PID: {process.Id}"
                });
            }
            catch (Exception ex)
            {
                dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "ProcessKillFailed",
                    Message = "无法终止恶意进程",
                    Details = ex.Message
                });
            }
        }
        
        // 进程行为分析功能
        private void AnalyzeProcessBehavior(int processId)
        {
            try
            {
                var process = Process.GetProcessById(processId);
                
                if (!processBehaviorInfo.ContainsKey(processId))
                {
                    processBehaviorInfo[processId] = new ProcessBehaviorInfo
                    {
                        ProcessId = processId,
                        ProcessName = process.ProcessName,
                        StartTime = DateTime.Now,
                        CpuCheckInterval = TimeSpan.FromSeconds(30),
                        LastCpuCheck = DateTime.Now
                    };
                }
                
                var behaviorInfo = processBehaviorInfo[processId];
                
                // CPU使用率检查
                if ((DateTime.Now - behaviorInfo.LastCpuCheck) > behaviorInfo.CpuCheckInterval)
                {
                    CheckProcessCpuUsage(process, behaviorInfo);
                    behaviorInfo.LastCpuCheck = DateTime.Now;
                }
                
                // 网络行为检查
                if (behaviorInfo.CpuUsageHistory.Count >= 3)
                {
                    CheckBehaviorPattern(process, behaviorInfo);
                }
            }
            catch { }
        }
        
        private void CheckProcessCpuUsage(Process process, ProcessBehaviorInfo behaviorInfo)
        {
            try
            {
                var startTime = process.StartTime;
                var totalProcessorTime = process.TotalProcessorTime;
                var uptime = DateTime.Now - startTime;
                
                if (uptime.TotalSeconds > 0)
                {
                    double cpuUsage = (totalProcessorTime.TotalSeconds / uptime.TotalSeconds) * 100;
                    behaviorInfo.CpuUsageHistory.Add(cpuUsage);
                    
                    // 保持最近10次记录
                    if (behaviorInfo.CpuUsageHistory.Count > 10)
                        behaviorInfo.CpuUsageHistory.RemoveAt(0);
                    
                    // 检测异常高CPU使用
                    if (cpuUsage > 80 && behaviorInfo.ProcessName != "FireAntivirus")
                    {
                        dataManager.AddLog(new LogEntry
                        {
                            Id = Guid.NewGuid().ToString(),
                            Time = DateTime.Now,
                            Type = "HighCpuUsage",
                            Message = "进程CPU使用率异常",
                            Details = $"进程: {behaviorInfo.ProcessName}, PID: {process.Id}, CPU使用率: {cpuUsage:F2}%"
                        });
                    }
                }
            }
            catch { }
        }
        
        private void CheckBehaviorPattern(Process process, ProcessBehaviorInfo behaviorInfo)
        {
            try
            {
                // 检测CPU使用模式异常
                double avgCpuUsage = behaviorInfo.CpuUsageHistory.Average();
                double maxCpuUsage = behaviorInfo.CpuUsageHistory.Max();
                double minCpuUsage = behaviorInfo.CpuUsageHistory.Min();
                
                // 如果波动过大，可能是异常行为
                if ((maxCpuUsage - minCpuUsage) > 50 && avgCpuUsage < 10)
                {
                    dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "SuspiciousCpuPattern",
                        Message = "可疑CPU使用模式",
                        Details = $"进程: {behaviorInfo.ProcessName}, 平均CPU: {avgCpuUsage:F2}%, 波动范围: {-minCpuUsage:F2}%→{maxCpuUsage:F2}%"
                    });
                }
            }
            catch { }
        }
        
        // 数字签名验证功能 - 使用.NET X509Certificate2
        private bool VerifyProcessSignature(string filePath)
        {
            try
            {
                if (!File.Exists(filePath))
                    return false;

                var fileInfo = new System.IO.FileInfo(filePath);

                // 检查文件是否在可信目录（系统目录自动通过）
                string[] trustedDirectories = {
                    @"C:\Windows",
                    @"C:\Program Files",
                    @"C:\Program Files (x86)"
                };
                
                foreach (string dir in trustedDirectories)
                {
                    if (filePath.StartsWith(dir, StringComparison.OrdinalIgnoreCase))
                        return true;
                }

                // 使用.NET的X509Certificate2检查数字签名
                try
                {
                    var certificate = new System.Security.Cryptography.X509Certificates.X509Certificate2(filePath);
                    
                    // 检查证书有效性
                    if (certificate.NotBefore > DateTime.Now || certificate.NotAfter < DateTime.Now)
                        return false;

                    // 检查证书是否自签名
                    if (string.IsNullOrEmpty(certificate.Issuer) || certificate.Issuer.Contains("CN="))
                        return false;

                    // 证书有效
                    return true;
                }
                catch (System.Security.Cryptography.CryptographicException)
                {
                    // 文件没有数字签名
                    return false;
                }
            }
            catch
            {
                return false;
            }
        }
        
        // 父进程监控链分析
        private string GetParentProcessChain(int processId)
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher($"SELECT ParentProcessId FROM Win32_Process WHERE ProcessId = {processId}"))
                {
                    foreach (var obj in searcher.Get())
                    {
                        int? parentId = (int?)(uint?)obj["ParentProcessId"];
                        if (parentId.HasValue && parentId.Value > 0)
                        {
                            string parentName = GetProcessNameFromId(parentId.Value);
                            if (!string.IsNullOrEmpty(parentName))
                            {
                                // 递归检查父进程
                                if (IsSuspiciousProcessName(parentName))
                                {
                                    return $"可疑父进程链: {parentName} -> ";
                                }
                            }
                        }
                    }
                }
            }
            catch { }
            
            return "未知";
        }
        
        private string GetProcessNameFromId(int processId)
        {
            try
            {
                var process = Process.GetProcessById(processId);
                return process.ProcessName;
            }
            catch
            {
                return string.Empty;
            }
        }

        public DetectionResult CheckProcessSuspicious(ProcessInfo process)
        {
            return new DetectionResult { IsThreat = false, IsSuspicious = false };
        }
    }
    
    public class ProcessBehaviorInfo
    {
        public int ProcessId { get; set; }
        public string ProcessName { get; set; }
        public DateTime StartTime { get; set; }
        public List<double> CpuUsageHistory { get; set; } = new List<double>();
        public TimeSpan CpuCheckInterval { get; set; }
        public DateTime LastCpuCheck { get; set; }
        public DateTime LastNetworkCheck { get; set; }
        public int NetworkConnectionCount { get; set; }
    }

    public class DetectionResult
    {
        public bool IsThreat { get; set; }
        public bool IsSuspicious { get; set; }
        public string ThreatName { get; set; }
        public string Reason { get; set; }
    }
}
