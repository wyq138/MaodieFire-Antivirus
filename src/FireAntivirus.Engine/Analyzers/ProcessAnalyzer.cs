using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Text;
using System.Threading.Tasks;
using FireAntivirus.Common;
using FireAntivirus.Data;

namespace FireAntivirus.Engine.Analyzers
{
    public class ProcessAnalyzer
    {
        private DataManager dataManager;
        private Dictionary<int, List<string>> processCache;
        private Dictionary<string, List<string>> processPatterns;
        private Dictionary<string, List<string>> maliciousProcessSignatures;
        private Dictionary<string, List<string>> suspiciousProcessSignatures;
        private Dictionary<string, List<string>> benignProcessSignatures;

        public ProcessAnalyzer()
        {
            dataManager = new DataManager();
            processCache = new Dictionary<int, List<string>>();
            InitializeProcessPatterns();
            InitializeProcessSignatures();
        }

        private void InitializeProcessPatterns()
        {
            processPatterns = new Dictionary<string, List<string>>
            {
                { "ProcessNames", new List<string> {
                    "svchost.exe", "explorer.exe", "winlogon.exe", "lsass.exe",
                    "csrss.exe", "smss.exe", "services.exe", "wininit.exe",
                    "taskhost.exe", "dwm.exe", "conhost.exe", "cmd.exe",
                    "powershell.exe", "regsvr32.exe", "rundll32.exe", "msiexec.exe"
                }},
                { "Modules", new List<string> {
                    "kernel32.dll", "user32.dll", "advapi32.dll", "shell32.dll",
                    "netapi32.dll", "ws2_32.dll", "wininet.dll", "urlmon.dll",
                    "crypt32.dll", "ole32.dll", "oleaut32.dll", "comctl32.dll"
                }},
                { "Paths", new List<string> {
                    "C:\\Windows\\System32", "C:\\Windows\\SysWOW64", "C:\\Program Files",
                    "C:\\Program Files (x86)", "C:\\Users", "C:\\AppData", "C:\\Temp",
                    "C:\\Windows\\Temp", "C:\\Downloads", "C:\\Desktop"
                }},
                { "Commands", new List<string> {
                    "-exec", "-c", "-e", "-f", "-i", "-o", "-p", "-r", "-s", "-t"
                }}
            };
        }

        private void InitializeProcessSignatures()
        {
            maliciousProcessSignatures = new Dictionary<string, List<string>>
            {
                { "Malware", new List<string> {
                    "virus", "trojan", "worm", "ransomware", "spyware", "adware",
                    "keylogger", "backdoor", "bot", "rootkit", "miner", "pup"
                }},
                { "Suspicious", new List<string> {
                    "cmd.exe", "powershell.exe", "regsvr32.exe", "rundll32.exe",
                    "msiexec.exe", "wscript.exe", "cscript.exe", "mshta.exe"
                }},
                { "Injection", new List<string> {
                    "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx", "OpenProcess"
                }},
                { "Network", new List<string> {
                    "InternetOpen", "InternetConnect", "HttpOpenRequest", "HttpSendRequest"
                }}
            };

            suspiciousProcessSignatures = new Dictionary<string, List<string>>
            {
                { "Processes", new List<string> {
                    "cmd.exe", "powershell.exe", "regsvr32.exe", "rundll32.exe",
                    "msiexec.exe", "wscript.exe", "cscript.exe", "mshta.exe",
                    "notepad.exe", "wordpad.exe", "mspaint.exe", "calc.exe"
                }},
                { "Modules", new List<string> {
                    "kernel32.dll", "user32.dll", "advapi32.dll", "shell32.dll",
                    "netapi32.dll", "ws2_32.dll", "wininet.dll", "urlmon.dll"
                }},
                { "Paths", new List<string> {
                    "C:\\Temp", "C:\\Windows\\Temp", "C:\\AppData\\Local\\Temp",
                    "C:\\Downloads", "C:\\Desktop", "C:\\Users\\Public"
                }}
            };

            benignProcessSignatures = new Dictionary<string, List<string>>
            {
                { "Processes", new List<string> {
                    "svchost.exe", "explorer.exe", "winlogon.exe", "lsass.exe",
                    "csrss.exe", "smss.exe", "services.exe", "wininit.exe",
                    "taskhost.exe", "dwm.exe", "conhost.exe", "taskmgr.exe",
                    "services.msc", "eventvwr.exe", "mmc.exe", "regedit.exe"
                }},
                { "Modules", new List<string> {
                    "kernel32.dll", "user32.dll", "advapi32.dll", "shell32.dll",
                    "gdi32.dll", "ntdll.dll", "msvcrt.dll", "comctl32.dll"
                }},
                { "Paths", new List<string> {
                    "C:\\Windows\\System32", "C:\\Windows\\SysWOW64", "C:\\Program Files",
                    "C:\\Program Files (x86)", "C:\\Windows", "C:\\ProgramData"
                }}
            };
        }

        public List<ScanResult> AnalyzeProcess(int processId)
        {
            var results = new List<ScanResult>();
            
            try
            {
                var process = Process.GetProcessById(processId);
                var processInfo = GetProcessInfo(processId);
                var modules = GetProcessModules(processId);
                var connections = GetProcessConnections(processId);

                double processScore = CalculateProcessScore(processInfo, modules, connections);
                var result = CreateProcessScanResult(process, processScore);
                results.Add(result);

                if (result.IsInfected)
                {
                    dataManager.LogThreat($"进程分析检测到恶意进程: {process.ProcessName} (PID: {processId})", $"评分: {processScore:P}", "ProcessAnalyzer");
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"进程分析失败: PID {processId}", ex.Message, "ProcessAnalyzer");
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
                dataManager.LogError("分析所有进程失败", ex.Message, "ProcessAnalyzer");
            }

            return results;
        }

        private List<string> GetProcessInfo(int processId)
        {
            var info = new List<string>();
            
            if (processCache.TryGetValue(processId, out List<string> cachedInfo))
            {
                return cachedInfo;
            }

            try
            {
                var process = Process.GetProcessById(processId);
                info.Add($"Name: {process.ProcessName}");
                info.Add($"Id: {process.Id}");
                info.Add($"MainModule: {process.MainModule?.FileName}");
                info.Add($"StartTime: {process.StartTime}");
                info.Add($"TotalProcessorTime: {process.TotalProcessorTime}");
                info.Add($"WorkingSet64: {process.WorkingSet64}");
                info.Add($"PrivateMemorySize64: {process.PrivateMemorySize64}");
                info.Add($"VirtualMemorySize64: {process.VirtualMemorySize64}");

                using (var searcher = new ManagementObjectSearcher($"SELECT * FROM Win32_Process WHERE ProcessId = {processId}"))
                {
                    var mo = searcher.Get().Cast<ManagementObject>().FirstOrDefault();
                    if (mo != null)
                    {
                        info.Add($"CommandLine: {mo["CommandLine"]}");
                        info.Add($"ParentProcessId: {mo["ParentProcessId"]}");
                        info.Add($"ExecutablePath: {mo["ExecutablePath"]}");
                        info.Add($"CreationDate: {mo["CreationDate"]}");
                    }
                }

                processCache[processId] = info;
            }
            catch
            {
                info.Clear();
            }

            return info;
        }

        private List<string> GetProcessModules(int processId)
        {
            var modules = new List<string>();
            
            try
            {
                var process = Process.GetProcessById(processId);
                foreach (ProcessModule module in process.Modules)
                {
                    modules.Add(module.FileName);
                }
            }
            catch
            {
                modules.Clear();
            }

            return modules;
        }

        private List<string> GetProcessConnections(int processId)
        {
            var connections = new List<string>();
            
            try
            {
                using (var searcher = new ManagementObjectSearcher($"SELECT * FROM Win32_PerfRawData_Tcpip_NetworkInterface"))
                {
                    foreach (var connection in searcher.Get())
                    {
                        connections.Add($"{connection["Name"]}: {connection["BytesTotalPersec"]}");
                    }
                }
            }
            catch
            {
                connections.Clear();
            }

            return connections;
        }

        private double CalculateProcessScore(List<string> processInfo, List<string> modules, List<string> connections)
        {
            double score = 0.0;

            try
            {
                score += AnalyzeMaliciousProcessSignatures(processInfo, modules);
                score += AnalyzeSuspiciousProcessSignatures(processInfo, modules);
                score += AnalyzeBenignProcessSignatures(processInfo, modules);
                score += AnalyzeProcessConnections(connections);
            }
            catch
            {
                score = 0.0;
            }

            return Math.Max(0.0, Math.Min(score, 1.0));
        }

        private double AnalyzeMaliciousProcessSignatures(List<string> processInfo, List<string> modules)
        {
            double score = 0.0;

            foreach (var info in processInfo)
            {
                foreach (var signatureCategory in maliciousProcessSignatures)
                {
                    foreach (var signature in signatureCategory.Value)
                    {
                        if (info.Contains(signature, StringComparison.OrdinalIgnoreCase))
                        {
                            score += 0.1;
                        }
                    }
                }
            }

            foreach (var module in modules)
            {
                foreach (var signatureCategory in maliciousProcessSignatures)
                {
                    foreach (var signature in signatureCategory.Value)
                    {
                        if (module.Contains(signature, StringComparison.OrdinalIgnoreCase))
                        {
                            score += 0.05;
                        }
                    }
                }
            }

            return score;
        }

        private double AnalyzeSuspiciousProcessSignatures(List<string> processInfo, List<string> modules)
        {
            double score = 0.0;

            foreach (var info in processInfo)
            {
                foreach (var signatureCategory in suspiciousProcessSignatures)
                {
                    foreach (var signature in signatureCategory.Value)
                    {
                        if (info.Contains(signature, StringComparison.OrdinalIgnoreCase))
                        {
                            score += 0.05;
                        }
                    }
                }
            }

            foreach (var module in modules)
            {
                foreach (var signatureCategory in suspiciousProcessSignatures)
                {
                    foreach (var signature in signatureCategory.Value)
                    {
                        if (module.Contains(signature, StringComparison.OrdinalIgnoreCase))
                        {
                            score += 0.02;
                        }
                    }
                }
            }

            return score;
        }

        private double AnalyzeBenignProcessSignatures(List<string> processInfo, List<string> modules)
        {
            double score = 0.0;

            foreach (var info in processInfo)
            {
                foreach (var signatureCategory in benignProcessSignatures)
                {
                    foreach (var signature in signatureCategory.Value)
                    {
                        if (info.Contains(signature, StringComparison.OrdinalIgnoreCase))
                        {
                            score -= 0.03;
                        }
                    }
                }
            }

            foreach (var module in modules)
            {
                foreach (var signatureCategory in benignProcessSignatures)
                {
                    foreach (var signature in signatureCategory.Value)
                    {
                        if (module.Contains(signature, StringComparison.OrdinalIgnoreCase))
                        {
                            score -= 0.02;
                        }
                    }
                }
            }

            return score;
        }

        private double AnalyzeProcessConnections(List<string> connections)
        {
            double score = 0.0;

            foreach (var connection in connections)
            {
                if (connection.Contains("BytesTotalPersec") && long.Parse(connection.Split(':')[1].Trim()) > 1000000)
                {
                    score += 0.1;
                }
            }

            return score;
        }

        private ScanResult CreateProcessScanResult(Process process, double processScore)
        {
            var result = new ScanResult
            {
                FilePath = process.MainModule?.FileName ?? process.ProcessName,
                IsInfected = processScore > 0.85,
                Confidence = processScore,
                DetectionTime = DateTime.Now,
                DetectionMethod = "Process"
            };

            if (result.IsInfected)
            {
                if (processScore > 0.95)
                {
                    result.ThreatName = "进程分析检测到恶意进程";
                    result.ThreatType = "Malware";
                    result.Severity = "High";
                }
                else
                {
                    result.ThreatName = "进程分析检测到可疑进程";
                    result.ThreatType = "Suspicious";
                    result.Severity = "Medium";
                }

                result.AdditionalInfo = $"进程评分: {processScore:P}, 进程ID: {process.Id}, 进程名: {process.ProcessName}";
            }

            return result;
        }

        public void ClearCache()
        {
            processCache.Clear();
        }

        public int GetCacheSize()
        {
            return processCache.Count;
        }
    }
}
