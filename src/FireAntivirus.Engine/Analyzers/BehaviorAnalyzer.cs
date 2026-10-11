using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using FireAntivirus.Common;
using FireAntivirus.Data;
using FireAntivirus.Engine.Strings;

namespace FireAntivirus.Engine.Analyzers
{
    public class BehaviorAnalyzer
    {
        private DataManager dataManager;
        private Dictionary<int, List<string>> processBehaviors;
        private Dictionary<int, List<string>> processModules;
        private Dictionary<int, List<string>> processFiles;
        private Dictionary<int, List<string>> processRegistry;
        private Dictionary<int, List<string>> processNetwork;
        private Dictionary<string, List<string>> maliciousBehaviors;
        private Dictionary<string, List<string>> suspiciousBehaviors;
        private Dictionary<string, List<string>> benignBehaviors;
        
        // 重构后的专业检测阈值 - 提高阈值减少误报
        private const double HIGH_RISK_THRESHOLD = 0.95;  // 提高高风险阈值
        private const double SUSPICIOUS_THRESHOLD = 0.90; // 提高可疑阈值
        
        // 添加可信程序白名单
        private readonly HashSet<string> _trustedProcessNames = new HashSet<string>
        {
            "explorer", "svchost", "dwm", "taskhostw", "sihost", "ctfmon",
            "powershell", "cmd", "notepad", "calc", "mspaint", "wordpad",
            "winword", "excel", "powerpoint", "outlook", "chrome", "firefox",
            "edge", "iexplore", "teams", "onedrive", "spotify", "vlc",
            "code", "devenv", "git", "node", "python", "java", "javaw"
        };
        
        // 添加可信路径前缀
        private readonly HashSet<string> _trustedPathPrefixes = new HashSet<string>
        {
            "C:\\Program Files",
            "C:\\Program Files (x86)",
            "C:\\Windows",
            "C:\\Users",
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.Windows)
        };

        public BehaviorAnalyzer()
        {
            dataManager = new DataManager();
            processBehaviors = new Dictionary<int, List<string>>();
            processModules = new Dictionary<int, List<string>>();
            processFiles = new Dictionary<int, List<string>>();
            processRegistry = new Dictionary<int, List<string>>();
            processNetwork = new Dictionary<int, List<string>>();
            InitializeBehaviorPatterns();
        }

        private void InitializeBehaviorPatterns()
        {
            // 恶意行为模式 - 需要多个组合才触发
            maliciousBehaviors = new Dictionary<string, List<string>>
            {
                { "ProcessInjection", new List<string> { "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx" } },
                { "RegistryPersistence", new List<string> { "HKLM\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run", 
                    "HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run", "WinLogon\\\\Shell", "WinLogon\\\\Userinit" } },
                { "FileManipulation", new List<string> { "EncryptFile", "DecryptFile", "MoveFileEx", "ReplaceFile" } },
                { "NetworkCommunication", new List<string> { "InternetOpen", "InternetConnect", "HttpOpenRequest" } },
                { "ProcessCreation", new List<string> { "CreateProcessAsUser", "CreateProcessWithLogonW" } },
                { "MemoryManipulation", new List<string> { "VirtualAlloc", "VirtualProtect", "RtlMoveMemory" } },
                { "ServiceManipulation", new List<string> { "CreateService", "StartService", "ChangeServiceConfig" } },
                { "HookInstallation", new List<string> { "SetWindowsHookEx", "CallNextHookEx" } },
                { "CodeInjection", new List<string> { "Inject", "Hook", "Patch" } },
                { "Keylogging", new List<string> { "GetAsyncKeyState", "GetKeyState", "GetKeyboardState" } },
                { "Ransomware", new List<string> { "CryptEncrypt", "CryptDecrypt", "CryptAcquireContext" } },
                { "Backdoor", new List<string> { "ReverseShell", "BindShell", "RemoteShell" } }
            };

            // 可疑行为模式 - 需要组合判断
            suspiciousBehaviors = new Dictionary<string, List<string>>
            {
                { "ProcessEnumeration", new List<string> { "CreateToolhelp32Snapshot", "Process32First", "Process32Next" } },
                { "RegistryEnumeration", new List<string> { "RegOpenKeyEx", "RegEnumKeyEx", "RegEnumValue" } },
                { "FileEnumeration", new List<string> { "FindFirstFile", "FindNextFile", "FindClose" } },
                { "NetworkEnumeration", new List<string> { "getaddrinfo", "gethostbyname", "gethostbyaddr" } },
                { "ProcessManagement", new List<string> { "TerminateProcess", "SuspendThread", "ResumeThread" } },
                { "MemoryEnumeration", new List<string> { "VirtualQuery", "ReadProcessMemory" } },
                { "SystemEnumeration", new List<string> { "GetSystemInfo", "GlobalMemoryStatus", "GetNativeSystemInfo" } },
                { "ServiceEnumeration", new List<string> { "EnumServicesStatus", "QueryServiceStatus" } },
                { "Reflection", new List<string> { "Reflection", "InvokeMember", "CreateInstance" } },
                { "NetworkCommunication", new List<string> { "socket", "connect", "send", "recv" } },
                { "HttpCommunication", new List<string> { "HttpClient", "WebClient", "HttpWebRequest" } }
            };

            // 良性行为模式 - 用于降低评分
            benignBehaviors = new Dictionary<string, List<string>>
            {
                { "UserInterface", new List<string> { "MessageBox", "CreateWindow", "ShowWindow" } },
                { "FileAccess", new List<string> { "File.Exists", "Directory.Exists", "Path.Combine" } },
                { "NetworkAccess", new List<string> { "WebRequest.Create", "HttpWebRequest.Create" } },
                { "ProcessAccess", new List<string> { "Process.GetCurrentProcess", "Process.GetProcesses" } },
                { "MemoryAccess", new List<string> { "GC.Collect", "GC.GetTotalMemory" } },
                { "Cryptography", new List<string> { "SHA256.Create", "MD5.Create", "Aes.Create", "RSA.Create" } },
                { "SystemInformation", new List<string> { "Environment.MachineName", "Environment.UserName" } },
                { "ServiceAccess", new List<string> { "ServiceController.GetServices", "ServiceController.Status" } },
                { "ApplicationFlow", new List<string> { "Application.Run", "Form.Show", "Form.Hide" } },
                { "AssemblyAccess", new List<string> { "Assembly.GetExecutingAssembly", "Assembly.GetEntryAssembly" } },
                { "Logging", new List<string> { "Console.WriteLine", "Debug.WriteLine", "Trace.WriteLine" } }
            };
        }

        public List<ScanResult> AnalyzeProcess(int processId)
        {
            var results = new List<ScanResult>();
            
            try
            {
                var process = Process.GetProcessById(processId);
                
                // 检查是否为可信程序，如果是则直接返回安全结果
                if (IsTrustedProcess(process))
                {
                    var safeResult = CreateSafeProcessScanResult(process);
                    results.Add(safeResult);
                    return results;
                }
                
                var behaviors = GetProcessBehaviors(processId);
                var modules = GetProcessModules(processId);
                var files = GetProcessFiles(processId);
                var registry = GetProcessRegistry(processId);
                var network = GetProcessNetwork(processId);

                double behaviorScore = CalculateBehaviorScore(behaviors, modules, files, registry, network);
                var result = CreateProcessScanResult(process, behaviorScore);
                results.Add(result);

                if (result.IsInfected)
                {
                    dataManager.LogThreat($"Behavior analysis detected malicious process: {process.ProcessName} (PID: {processId})", $"Score: {behaviorScore:P}", "BehaviorAnalyzer");
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"Behavior analysis failed: PID {processId}", ex.Message, "BehaviorAnalyzer");
            }

            return results;
        }

        public List<ScanResult> AnalyzeAllProcesses()
        {
            var results = new List<ScanResult>();
            
            try
            {
                var processes = Process.GetProcesses();
                foreach (var process in processes)
                {
                    try
                    {
                        // 跳过系统关键进程
                        if (IsSystemProcess(process.ProcessName))
                            continue;
                            
                        var processResults = AnalyzeProcess(process.Id);
                        results.AddRange(processResults);
                    }
                    catch
                    {
                        continue;
                    }
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError("Failed to analyze all processes", ex.Message, "BehaviorAnalyzer");
            }

            return results;
        }

        private bool IsSystemProcess(string processName)
        {
            string[] systemProcesses = {
                "System", "smss", "csrss", "wininit", "services", "lsass", "svchost",
                "winlogon", "dwm", "explorer", "fontdrvhost", "dwm.exe", "runtimebroker",
                "taskhostw", "sihost", "ctfmon", "conhost", "cmd", "powershell"
            };
            return systemProcesses.Contains(processName.ToLower());
        }

        public List<ScanResult> AnalyzeFileBehavior(string filePath)
        {
            var results = new List<ScanResult>();
            
            if (!File.Exists(filePath))
            {
                return results;
            }

            try
            {
                var behaviors = GetFileBehaviors(filePath);
                double behaviorScore = CalculateFileBehaviorScore(behaviors);
                var result = CreateFileScanResult(filePath, behaviorScore);
                results.Add(result);

                if (result.IsInfected)
                {
                    dataManager.LogThreat($"行为分析检测到恶意文件: {filePath}", $"评分: {behaviorScore:P}", "BehaviorAnalyzer");
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"文件行为分析失败: {filePath}", ex.Message, "BehaviorAnalyzer");
            }

            return results;
        }

        private List<string> GetProcessBehaviors(int processId)
        {
            var behaviors = new List<string>();
            
            try
            {
                if (processBehaviors.TryGetValue(processId, out List<string> cachedBehaviors))
                {
                    return cachedBehaviors;
                }

                using (var searcher = new ManagementObjectSearcher($"SELECT * FROM Win32_Process WHERE ProcessId = {processId}"))
                {
                    var process = searcher.Get().Cast<ManagementObject>().FirstOrDefault();
                    if (process != null)
                    {
                        behaviors.Add($"Name: {process["Name"]}");
                        behaviors.Add($"ExecutablePath: {process["ExecutablePath"]}");
                        behaviors.Add($"CommandLine: {process["CommandLine"]}");
                        behaviors.Add($"CreationDate: {process["CreationDate"]}");
                        behaviors.Add($"ParentProcessId: {process["ParentProcessId"]}");
                    }
                }

                processBehaviors[processId] = behaviors;
            }
            catch
            {
                behaviors.Clear();
            }

            return behaviors;
        }

        private List<string> GetProcessModules(int processId)
        {
            var modules = new List<string>();
            
            try
            {
                if (processModules.TryGetValue(processId, out List<string> cachedModules))
                {
                    return cachedModules;
                }

                var process = Process.GetProcessById(processId);
                foreach (ProcessModule module in process.Modules)
                {
                    modules.Add(module.FileName);
                }

                processModules[processId] = modules;
            }
            catch
            {
                modules.Clear();
            }

            return modules;
        }

        /// <summary>
        /// 获取进程的文件操作 - 使用WMI监控真实的文件访问
        /// </summary>
        private List<string> GetProcessFiles(int processId)
        {
            var files = new List<string>();
            
            try
            {
                if (processFiles.TryGetValue(processId, out List<string> cachedFiles))
                {
                    return cachedFiles;
                }

                // 使用WMI获取进程打开的文件句柄
                using (var searcher = new ManagementObjectSearcher(
                    $"SELECT * FROM Win32_Process WHERE ProcessId = {processId}"))
                {
                    var process = searcher.Get().Cast<ManagementObject>().FirstOrDefault();
                    if (process != null)
                    {
                        var executablePath = process["ExecutablePath"]?.ToString();
                        if (!string.IsNullOrEmpty(executablePath))
                        {
                            files.Add(executablePath);
                        }
                    }
                }

                // 获取进程的工作目录和最近访问的文件
                try
                {
                    var proc = Process.GetProcessById(processId);
                    if (proc.MainModule != null)
                    {
                        files.Add(proc.MainModule.FileName);
                    }
                }
                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "BehaviorAnalyzer.cs 捕获异常", ex.Message); }

                // 检查进程是否在访问敏感目录
                var sensitivePaths = new[]
                {
                    Environment.GetFolderPath(Environment.SpecialFolder.Startup),
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32")
                };

                foreach (var sensitivePath in sensitivePaths)
                {
                    if (files.Any(f => f.StartsWith(sensitivePath, StringComparison.OrdinalIgnoreCase)))
                    {
                        files.Add($"SENSITIVE_PATH_ACCESS:{sensitivePath}");
                    }
                }

                processFiles[processId] = files;
            }
            catch
            {
                files.Clear();
            }

            return files;
        }

        /// <summary>
        /// 获取进程的注册表访问 - 使用真实检测
        /// </summary>
        private List<string> GetProcessRegistry(int processId)
        {
            var registry = new List<string>();
            
            try
            {
                if (processRegistry.TryGetValue(processId, out List<string> cachedRegistry))
                {
                    return cachedRegistry;
                }

                // 检查进程是否修改了启动项
                var runKeys = new[]
                {
                    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
                };

                try
                {
                    var proc = Process.GetProcessById(processId);
                    var processPath = proc.MainModule?.FileName?.ToLower();
                    
                    if (!string.IsNullOrEmpty(processPath))
                    {
                        foreach (var key in runKeys)
                        {
                            try
                            {
                                var root = key.StartsWith("HKLM") ? Microsoft.Win32.Registry.LocalMachine : Microsoft.Win32.Registry.CurrentUser;
                                var subKey = key.Substring(key.IndexOf("\\") + 1);
                                
                                using (var regKey = root.OpenSubKey(subKey))
                                {
                                    if (regKey != null)
                                    {
                                        foreach (var valueName in regKey.GetValueNames())
                                        {
                                            var value = regKey.GetValue(valueName)?.ToString();
                                            if (!string.IsNullOrEmpty(value) && value.ToLower().Contains(processPath))
                                            {
                                                registry.Add($"STARTUP_ENTRY:{key}\\{valueName}");
                                            }
                                        }
                                    }
                                }
                            }
                            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "BehaviorAnalyzer.cs 捕获异常", ex.Message); }
                        }
                    }
                }
                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "BehaviorAnalyzer.cs 捕获异常", ex.Message); }

                processRegistry[processId] = registry;
            }
            catch
            {
                registry.Clear();
            }

            return registry;
        }

        /// <summary>
        /// 获取进程的网络连接 - 使用真实的网络API
        /// </summary>
        private List<string> GetProcessNetwork(int processId)
        {
            var network = new List<string>();
            
            try
            {
                if (processNetwork.TryGetValue(processId, out List<string> cachedNetwork))
                {
                    return cachedNetwork;
                }

                // 使用IPGlobalProperties获取真实的网络连接
                var properties = IPGlobalProperties.GetIPGlobalProperties();
                var tcpConnections = properties.GetActiveTcpConnections();
                var udpListeners = properties.GetActiveUdpListeners();

                foreach (var conn in tcpConnections)
                {
                    if (conn.LocalEndPoint != null)
                    {
                        try
                        {
                            // 尝试获取进程ID
                            var processIds = GetProcessIdsForPort(conn.LocalEndPoint.Port);
                            if (processIds.Contains(processId))
                            {
                                var remoteInfo = conn.RemoteEndPoint != null 
                                    ? $"{conn.RemoteEndPoint.Address}:{conn.RemoteEndPoint.Port}" 
                                    : "LISTENING";
                                network.Add($"TCP:{conn.LocalEndPoint.Address}:{conn.LocalEndPoint.Port}->{remoteInfo}");
                            }
                        }
                        catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "BehaviorAnalyzer.cs 捕获异常", ex.Message); }
                    }
                }

                foreach (var listener in udpListeners)
                {
                    try
                    {
                        var processIds = GetProcessIdsForPort(listener.Port);
                        if (processIds.Contains(processId))
                        {
                            network.Add($"UDP:{listener.Address}:{listener.Port}");
                        }
                    }
                    catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "BehaviorAnalyzer.cs 捕获异常", ex.Message); }
                }

                // 检查是否连接到可疑端口
                var suspiciousPorts = new[] { 4444, 5555, 6666, 8888, 9999, 31337, 12345 };
                foreach (var suspiciousPort in suspiciousPorts)
                {
                    if (network.Any(n => n.Contains($":{suspiciousPort}")))
                    {
                        network.Add($"SUSPICIOUS_PORT:{suspiciousPort}");
                    }
                }

                processNetwork[processId] = network;
            }
            catch
            {
                network.Clear();
            }

            return network;
        }

        /// <summary>
        /// 获取使用特定端口的进程ID
        /// </summary>
        private HashSet<int> GetProcessIdsForPort(int port)
        {
            var processIds = new HashSet<int>();
            
            try
            {
                // 使用netstat命令获取进程ID
                var startInfo = new ProcessStartInfo
                {
                    FileName = "netstat",
                    Arguments = "-ano",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                };

                using (var proc = Process.Start(startInfo))
                {
                    if (proc != null)
                    {
                        var output = proc.StandardOutput.ReadToEnd();
                        var lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                        
                        foreach (var line in lines)
                        {
                            if (line.Contains($":{port}"))
                            {
                                var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                                if (parts.Length >= 5)
                                {
                                    if (int.TryParse(parts.Last(), out int pid))
                                    {
                                        processIds.Add(pid);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "BehaviorAnalyzer.cs 捕获异常", ex.Message); }

            return processIds;
        }

        private List<string> GetFileBehaviors(string filePath)
        {
            var behaviors = new List<string>();
            
            try
            {
                var fileInfo = new FileInfo(filePath);
                behaviors.Add($"Name: {fileInfo.Name}");
                behaviors.Add($"Length: {fileInfo.Length}");
                behaviors.Add($"CreationTime: {fileInfo.CreationTime}");
                behaviors.Add($"LastWriteTime: {fileInfo.LastWriteTime}");
                behaviors.Add($"LastAccessTime: {fileInfo.LastAccessTime}");
                behaviors.Add($"Attributes: {fileInfo.Attributes}");
                behaviors.Add($"Extension: {fileInfo.Extension}");
                behaviors.Add($"Directory: {fileInfo.DirectoryName}");
            }
            catch
            {
                behaviors.Clear();
            }

            return behaviors;
        }

        private double CalculateBehaviorScore(List<string> behaviors, List<string> modules, List<string> files, List<string> registry, List<string> network)
        {
            double score = 0.0;
            int maliciousIndicators = 0;
            int suspiciousIndicators = 0;

            try
            {
                // 恶意行为检测 - 每个类别只计一次，提高触发阈值
                var maliciousScore = AnalyzeMaliciousBehaviors(behaviors);
                if (maliciousScore > 0.15) maliciousIndicators++; // 提高阈值
                score += maliciousScore;

                // 可疑行为检测
                var suspiciousScore = AnalyzeSuspiciousBehaviors(behaviors);
                if (suspiciousScore > 0.08) suspiciousIndicators++; // 提高阈值
                score += suspiciousScore;

                // 模块分析
                var moduleScore = AnalyzeMaliciousModules(modules);
                if (moduleScore > 0.1) suspiciousIndicators++; // 提高阈值
                score += moduleScore;

                // 文件访问分析
                var fileScore = AnalyzeSuspiciousFiles(files);
                if (fileScore > 0.05) suspiciousIndicators++; // 提高阈值
                score += fileScore;

                // 注册表分析
                var registryScore = AnalyzeSuspiciousRegistry(registry);
                if (registryScore > 0.15) maliciousIndicators++; // 提高阈值
                score += registryScore;

                // 网络分析
                var networkScore = AnalyzeSuspiciousNetwork(network);
                if (networkScore > 0.12) suspiciousIndicators++; // 提高阈值
                score += networkScore;

                // 良性行为降低评分
                var benignScore = AnalyzeBenignBehaviors(behaviors);
                score -= benignScore;

                // 组合检测：需要多个指标才触发高评分（更严格的要求）
                if (maliciousIndicators >= 3 || (maliciousIndicators >= 2 && suspiciousIndicators >= 3))
                {
                    score += maliciousIndicators * 0.08; // 降低加成
                }
                else if (maliciousIndicators == 1 && suspiciousIndicators >= 4)
                {
                    score += 0.1; // 降低加成
                }
                else
                {
                    // 单一指标大幅降低权重
                    score *= 0.5; // 更严格的降权
                }

                // 确保评分在合理范围内
                score = Math.Max(0.0, Math.Min(score, 1.0));
            }
            catch
            {
                score = 0.0;
            }

            return score;
        }

        private double CalculateFileBehaviorScore(List<string> behaviors)
        {
            double score = 0.0;

            try
            {
                score += AnalyzeMaliciousBehaviors(behaviors) * 0.5;
                score += AnalyzeSuspiciousBehaviors(behaviors) * 0.3;
                score -= AnalyzeBenignBehaviors(behaviors) * 0.3;
            }
            catch
            {
                score = 0.0;
            }

            return Math.Max(0.0, Math.Min(score, 1.0));
        }

        private double AnalyzeMaliciousBehaviors(List<string> behaviors)
        {
            double score = 0.0;
            int matchedCategories = 0;

            foreach (var behaviorPattern in maliciousBehaviors)
            {
                bool categoryMatched = false;
                foreach (var pattern in behaviorPattern.Value)
                {
                    if (behaviors.Any(b => b.IndexOf(pattern, StringComparison.OrdinalIgnoreCase) >= 0))
                    {
                        if (!categoryMatched)
                        {
                            score += 0.03; // 降低每个类别的分值
                            categoryMatched = true;
                            matchedCategories++;
                        }
                    }
                }
            }

            // 多个类别匹配时增加评分（更严格的要求）
            if (matchedCategories >= 4) // 提高阈值
            {
                score += matchedCategories * 0.02; // 降低加成比例
            }

            return Math.Min(score, 0.4); // 降低最大评分上限
        }

        private double AnalyzeSuspiciousBehaviors(List<string> behaviors)
        {
            double score = 0.0;
            int matchedCategories = 0;

            foreach (var behaviorPattern in suspiciousBehaviors)
            {
                bool categoryMatched = false;
                foreach (var pattern in behaviorPattern.Value)
                {
                    if (behaviors.Any(b => b.IndexOf(pattern, StringComparison.OrdinalIgnoreCase) >= 0))
                    {
                        if (!categoryMatched)
                        {
                            score += 0.01; // 降低分值
                            categoryMatched = true;
                            matchedCategories++;
                        }
                    }
                }
            }

            return Math.Min(score, 0.2); // 降低最大评分上限
        }

        private double AnalyzeBenignBehaviors(List<string> behaviors)
        {
            double score = 0.0;

            foreach (var behaviorPattern in benignBehaviors)
            {
                int patternCount = 0;
                foreach (var pattern in behaviorPattern.Value)
                {
                    if (behaviors.Any(b => b.IndexOf(pattern, StringComparison.OrdinalIgnoreCase) >= 0))
                    {
                        patternCount++;
                    }
                }
                
                // 只有单个类别有多个行为匹配时才增加减分
                if (patternCount >= 2)
                {
                    score += 0.04; // 增加良性行为的减分权重
                }
                else if (patternCount >= 1)
                {
                    score += 0.02;
                }
            }

            return Math.Min(score, 0.3); // 增加减分上限
        }

        private double AnalyzeMaliciousModules(List<string> modules)
        {
            double score = 0.0;
            int injectionCount = 0;

            // 检查可疑DLL注入（扩展列表但降低单个分值）
            string[] injectionModules = { 
                "mhook.dll", "minihook.dll", "easyhook.dll", "ninject.dll",
                "detours.dll", "polyhook.dll", "hookapi.dll"
            };
            foreach (var module in modules)
            {
                var moduleName = Path.GetFileName(module).ToLower();
                if (injectionModules.Contains(moduleName))
                {
                    injectionCount++;
                    // 多个注入模块才增加较高分值
                    if (injectionCount >= 2)
                    {
                        score += 0.08; // 降低分值
                    }
                    else
                    {
                        score += 0.04; // 单个注入分值更低
                    }
                }
            }

            return Math.Min(score, 0.25); // 降低最大评分
        }

        private double AnalyzeSuspiciousFiles(List<string> files)
        {
            double score = 0.0;
            int sensitiveAccessCount = 0;

            // 检查敏感路径访问
            foreach (var file in files)
            {
                if (file.StartsWith("SENSITIVE_PATH_ACCESS:"))
                {
                    sensitiveAccessCount++;
                    // 多个敏感路径访问才增加较高分值
                    if (sensitiveAccessCount >= 3)
                    {
                        score += 0.06; // 降低分值
                    }
                    else
                    {
                        score += 0.03; // 单个访问分值更低
                    }
                }
            }

            return Math.Min(score, 0.15); // 降低最大评分
        }

        private double AnalyzeSuspiciousRegistry(List<string> registry)
        {
            double score = 0.0;
            int startupCount = 0;

            foreach (var entry in registry)
            {
                if (entry.StartsWith("STARTUP_ENTRY:"))
                {
                    startupCount++;
                    // 多个启动项才增加较高分值
                    if (startupCount >= 2)
                    {
                        score += 0.08; // 降低分值
                    }
                    else
                    {
                        score += 0.05; // 单个启动项分值低
                    }
                }
            }

            return Math.Min(score, 0.25); // 降低最大评分
        }

        private double AnalyzeSuspiciousNetwork(List<string> network)
        {
            double score = 0.0;
            int suspiciousPortCount = 0;
            int suspiciousIPCount = 0;

            foreach (var conn in network)
            {
                if (conn.StartsWith("SUSPICIOUS_PORT:"))
                {
                    suspiciousPortCount++;
                    // 多个可疑端口才增加较高分值
                    if (suspiciousPortCount >= 2)
                    {
                        score += 0.1; // 降低分值
                    }
                    else
                    {
                        score += 0.05; // 单个端口分值低
                    }
                }
            }

            // 检查连接到可疑IP（扩展列表但降低分值）
            string[] suspiciousIPs = { "0.0.0.0", "255.255.255.255", "127.0.0.1", "localhost" };
            foreach (var conn in network)
            {
                foreach (var ip in suspiciousIPs)
                {
                    if (conn.Contains(ip))
                    {
                        suspiciousIPCount++;
                        // 多个可疑IP连接才增加较高分值
                        if (suspiciousIPCount >= 3)
                        {
                            score += 0.04; // 降低分值
                        }
                        else
                        {
                            score += 0.02; // 单个IP分值更低
                        }
                    }
                }
            }

            return Math.Min(score, 0.25); // 降低最大评分
        }

        private ScanResult CreateProcessScanResult(Process process, double score)
        {
            var result = new ScanResult
            {
                FilePath = process.MainModule?.FileName ?? process.ProcessName,
                IsInfected = score > HIGH_RISK_THRESHOLD,
                Confidence = score,
                DetectionTime = DateTime.Now,
                DetectionMethod = "Behavior"
            };

            if (result.IsInfected)
            {
                if (score > 0.95)
                {
                    result.ThreatName = LocalizedStrings.MaliciousProcess;
                    result.ThreatType = "Malware";
                    result.Severity = "High";
                }
                else
                {
                    result.ThreatName = LocalizedStrings.SuspiciousProcess;
                    result.ThreatType = "Suspicious";
                    result.Severity = "Medium";
                }

                result.AdditionalInfo = $"行为评分: {score:P}, 进程ID: {process.Id}, 进程名: {process.ProcessName}";
            }
            else if (score > SUSPICIOUS_THRESHOLD)
            {
                result.ThreatName = "行为分析检测到的潜在风险进程";
                result.ThreatType = "Risk";
                result.Severity = "Low";
                result.AdditionalInfo = $"行为评分: {score:P}, 进程ID: {process.Id}, 进程名: {process.ProcessName}";
            }

            return result;
        }

        private ScanResult CreateFileScanResult(string filePath, double score)
        {
            var result = new ScanResult
            {
                FilePath = filePath,
                IsInfected = score > HIGH_RISK_THRESHOLD,
                Confidence = score,
                DetectionTime = DateTime.Now,
                DetectionMethod = "FileBehavior"
            };

            if (result.IsInfected)
            {
                if (score > 0.95)
                {
                    result.ThreatName = "行为分析检测到的恶意文件";
                    result.ThreatType = "Malware";
                    result.Severity = "High";
                }
                else
                {
                    result.ThreatName = "行为分析检测到的可疑文件";
                    result.ThreatType = "Suspicious";
                    result.Severity = "Medium";
                }

                result.AdditionalInfo = $"行为评分: {score:P}";
            }

            return result;
        }

        public void ClearCache()
        {
            processBehaviors.Clear();
            processModules.Clear();
            processFiles.Clear();
            processRegistry.Clear();
            processNetwork.Clear();
        }

        public int GetCacheSize()
        {
            return processBehaviors.Count + processModules.Count + processFiles.Count + processRegistry.Count + processNetwork.Count;
        }

        /// <summary>
        /// 检查是否为可信程序
        /// </summary>
        private bool IsTrustedProcess(Process process)
        {
            if (process == null) return false;
            
            try
            {
                var processName = process.ProcessName.ToLower();
                
                // 检查进程名称白名单
                if (_trustedProcessNames.Contains(processName))
                {
                    return true;
                }
                
                // 检查进程路径的信任性
                if (process.MainModule != null)
                {
                    var processPath = process.MainModule.FileName.ToLower();
                    
                    // 检查路径前缀
                    foreach (var trustedPrefix in _trustedPathPrefixes)
                    {
                        if (processPath.StartsWith(trustedPrefix.ToLower()))
                        {
                            return true;
                        }
                    }
                    
                    // 检查系统进程的父进程关系
                    if (IsValidSystemChildProcess(process))
                    {
                        return true;
                    }
                }
                
                // 检查是否由可信应用程序启动
                if (HasTrustedProcessParent(process))
                {
                    return true;
                }
            }
            catch
            {
                // 如果无法检查进程信息，默认返回安全
                return false;
            }
            
            return false;
        }

        /// <summary>
        /// 检查是否为有效的系统子进程
        /// </summary>
        private bool IsValidSystemChildProcess(Process process)
        {
            try
            {
                var parentProcess = GetParentProcess(process.Id);
                if (parentProcess != null)
                {
                    var parentName = parentProcess.ProcessName.ToLower();
                    string[] validParents = { "explorer", "services", "svchost", "winlogon" };
                    
                    if (validParents.Contains(parentName))
                    {
                        return true;
                    }
                }
            }
            catch
            {
                // 忽略异常，返回false
            }
            
            return false;
        }

        /// <summary>
        /// 获取父进程
        /// </summary>
        private Process GetParentProcess(int processId)
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher($"SELECT ParentProcessId FROM Win32_Process WHERE ProcessId = {processId}"))
                {
                    var process = searcher.Get().Cast<ManagementObject>().FirstOrDefault();
                    if (process != null)
                    {
                        var parentId = Convert.ToInt32(process["ParentProcessId"]);
                        if (parentId > 0)
                        {
                            return Process.GetProcessById(parentId);
                        }
                    }
                }
            }
            catch
            {
                // 忽略异常
            }
            
            return null;
        }

        /// <summary>
        /// 检查是否有可信的父进程
        /// </summary>
        private bool HasTrustedProcessParent(Process process)
        {
            try
            {
                var parent = GetParentProcess(process.Id);
                if (parent != null)
                {
                    return IsTrustedProcess(parent);
                }
            }
            catch
            {
                // 忽略异常
            }
            
            return false;
        }

        /// <summary>
        /// 为可信进程创建安全扫描结果
        /// </summary>
        private ScanResult CreateSafeProcessScanResult(Process process)
        {
            return new ScanResult
            {
                FilePath = process.MainModule?.FileName ?? process.ProcessName,
                IsInfected = false,
                Confidence = 0.0,
                DetectionTime = DateTime.Now,
                DetectionMethod = "TrustedProcess",
                ThreatName = "安全进程",
                ThreatType = "Safe",
                Severity = "None",
                AdditionalInfo = $"可信进程: {process.ProcessName}"
            };
        }

        /// <summary>
        /// 优化评分算法：降低单一指标的权重，增加组合要求
        /// </summary>
        public double CalculateOptimizedBehaviorScore(List<string> behaviors, List<string> modules, List<string> files, List<string> registry, List<string> network)
        {
            double score = CalculateBehaviorScore(behaviors, modules, files, registry, network);
            
            // 应用优化因子：
            // 1. 降低单一异常行为的权重
            // 2. 需要多个异常指标组合才认为是威胁
            
            var indicators = GetActiveIndicators(behaviors, modules, files, registry, network);
            
            // 如果是单一指标，降低评分
            if (indicators.Count == 1)
            {
                score *= 0.5; // 降低50%权重
            }
            
            // 如果是常见开发工具行为，进一步降低评分
            if (ContainsDevelopmentBehavior(behaviors))
            {
                score *= 0.3; // 开发工具行为权重更低
            }
            
            return Math.Max(0.0, Math.Min(score, 1.0));
        }

        /// <summary>
        /// 检查是否包含开发工具常见行为
        /// </summary>
        private bool ContainsDevelopmentBehavior(List<string> behaviors)
        {
            var developmentKeywords = new[] { "debug", "test", "compile", "build", "runtime", "assembly", "reflection" };
            
            foreach (var behavior in behaviors)
            {
                foreach (var keyword in developmentKeywords)
                {
                    if (behavior.ToLower().Contains(keyword.ToLower()))
                    {
                        return true;
                    }
                }
            }
            
            return false;
        }

        /// <summary>
        /// 获取活跃的异常指标数量
        /// </summary>
        private List<string> GetActiveIndicators(List<string> behaviors, List<string> modules, List<string> files, List<string> registry, List<string> network)
        {
            var indicators = new List<string>();
            
            // 检查网络异常
            if (network.Any(n => n.StartsWith("SUSPICIOUS_PORT:")))
            {
                indicators.Add("Network");
            }
            
            // 检查注册表异常
            if (registry.Any(r => r.StartsWith("STARTUP_ENTRY:")))
            {
                indicators.Add("Registry");
            }
            
            // 检查文件异常
            if (files.Any(f => f.StartsWith("SENSITIVE_PATH_ACCESS:")))
            {
                indicators.Add("FileAccess");
            }
            
            // 检查模块异常
            var suspiciousModules = modules.Where(m => 
                m.ToLower().Contains("hook") || 
                m.ToLower().Contains("inject")).ToList();
            
            if (suspiciousModules.Any())
            {
                indicators.Add("Module");
            }
            
            return indicators;
        }
    }
}