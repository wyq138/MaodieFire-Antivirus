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
    public class SystemAnalyzer
    {
        private DataManager dataManager;
        private Dictionary<string, List<string>> systemCache;
        private Dictionary<string, List<string>> systemPatterns;
        private Dictionary<string, List<string>> maliciousSystemSignatures;
        private Dictionary<string, List<string>> suspiciousSystemSignatures;
        private Dictionary<string, List<string>> benignSystemSignatures;

        public SystemAnalyzer()
        {
            dataManager = new DataManager();
            systemCache = new Dictionary<string, List<string>>();
            InitializeSystemPatterns();
            InitializeSystemSignatures();
        }

        private void InitializeSystemPatterns()
        {
            systemPatterns = new Dictionary<string, List<string>>
            {
                { "Processes", new List<string> {
                    "svchost.exe", "explorer.exe", "winlogon.exe", "lsass.exe",
                    "csrss.exe", "smss.exe", "services.exe", "wininit.exe",
                    "taskhost.exe", "dwm.exe", "conhost.exe", "cmd.exe"
                }},
                { "Services", new List<string> {
                    "Windows Defender", "Windows Firewall", "Windows Update",
                    "Background Intelligent Transfer Service", "Cryptographic Services",
                    "Event Log", "Plug and Play", "Remote Procedure Call"
                }},
                { "Drivers", new List<string> {
                    "ntoskrnl.exe", "hal.dll", "ndis.sys", "tcpip.sys",
                    "usbhub.sys", "usbd.sys", "kbdclass.sys", "mouclass.sys"
                }},
                { "Registry", new List<string> {
                    "HKLM\\SYSTEM", "HKLM\\SOFTWARE", "HKCU\\SOFTWARE",
                    "HKLM\\HARDWARE", "HKCR", "HKU", "HKCC"
                }}
            };
        }

        private void InitializeSystemSignatures()
        {
            maliciousSystemSignatures = new Dictionary<string, List<string>>
            {
                { "Malware", new List<string> {
                    "virus", "trojan", "worm", "ransomware", "spyware", "adware",
                    "keylogger", "backdoor", "bot", "rootkit", "miner", "pup"
                }},
                { "Services", new List<string> {
                    "fake", "malicious", "virus", "trojan", "backdoor", "bot"
                }},
                { "Drivers", new List<string> {
                    "rootkit", "keylogger", "backdoor", "bot", "miner"
                }},
                { "Registry", new List<string> {
                    "Run", "RunOnce", "Startup", "Winlogon", "Shell", "Userinit"
                }}
            };

            suspiciousSystemSignatures = new Dictionary<string, List<string>>
            {
                { "Processes", new List<string> {
                    "cmd.exe", "powershell.exe", "regsvr32.exe", "rundll32.exe",
                    "msiexec.exe", "wscript.exe", "cscript.exe", "mshta.exe"
                }},
                { "Services", new List<string> {
                    "unknown", "suspicious", "questionable", "unrecognized"
                }},
                { "Drivers", new List<string> {
                    "unknown", "suspicious", "questionable", "unrecognized"
                }},
                { "Registry", new List<string> {
                    "Unknown", "Suspicious", "Questionable", "Unrecognized"
                }}
            };

            benignSystemSignatures = new Dictionary<string, List<string>>
            {
                { "Processes", new List<string> {
                    "svchost.exe", "explorer.exe", "winlogon.exe", "lsass.exe",
                    "csrss.exe", "smss.exe", "services.exe", "wininit.exe",
                    "taskhost.exe", "dwm.exe", "conhost.exe", "taskmgr.exe"
                }},
                { "Services", new List<string> {
                    "Windows Defender", "Windows Firewall", "Windows Update",
                    "Background Intelligent Transfer Service", "Cryptographic Services",
                    "Event Log", "Plug and Play", "Remote Procedure Call"
                }},
                { "Drivers", new List<string> {
                    "ntoskrnl.exe", "hal.dll", "ndis.sys", "tcpip.sys",
                    "usbhub.sys", "usbd.sys", "kbdclass.sys", "mouclass.sys"
                }},
                { "Registry", new List<string> {
                    "Microsoft", "Windows", "System", "Control", "CurrentVersion"
                }}
            };
        }

        public List<ScanResult> AnalyzeSystem()
        {
            var results = new List<ScanResult>();
            
            try
            {
                var processes = GetSystemProcesses();
                var services = GetSystemServices();
                var drivers = GetSystemDrivers();
                var registry = GetSystemRegistry();

                double systemScore = CalculateSystemScore(processes, services, drivers, registry);
                var result = CreateSystemScanResult("System", systemScore);
                results.Add(result);

                if (result.IsInfected)
                {
                    dataManager.LogThreat("系统分析检测到恶意活动", $"评分: {systemScore:P}", "SystemAnalyzer");
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError("系统分析失败", ex.Message, "SystemAnalyzer");
            }

            return results;
        }

        public List<ScanResult> AnalyzeProcesses()
        {
            return AnalyzeSystemComponent("Processes", GetSystemProcesses());
        }

        public List<ScanResult> AnalyzeServices()
        {
            return AnalyzeSystemComponent("Services", GetSystemServices());
        }

        public List<ScanResult> AnalyzeDrivers()
        {
            return AnalyzeSystemComponent("Drivers", GetSystemDrivers());
        }

        public List<ScanResult> AnalyzeRegistry()
        {
            return AnalyzeSystemComponent("Registry", GetSystemRegistry());
        }

        private List<string> GetSystemProcesses()
        {
            var processes = new List<string>();
            
            if (systemCache.TryGetValue("Processes", out List<string> cachedProcesses))
            {
                return cachedProcesses;
            }

            try
            {
                var processList = Process.GetProcesses();
                foreach (var process in processList)
                {
                    processes.Add($"{process.ProcessName} (PID: {process.Id})");
                }

                systemCache["Processes"] = processes;
            }
            catch
            {
                processes.Clear();
            }

            return processes;
        }

        private List<string> GetSystemServices()
        {
            var services = new List<string>();
            
            if (systemCache.TryGetValue("Services", out List<string> cachedServices))
            {
                return cachedServices;
            }

            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Service"))
                {
                    foreach (var service in searcher.Get())
                    {
                        services.Add($"{service["Name"]}: {service["DisplayName"]} ({service["State"]})");
                    }
                }

                systemCache["Services"] = services;
            }
            catch
            {
                services.Clear();
            }

            return services;
        }

        private List<string> GetSystemDrivers()
        {
            var drivers = new List<string>();
            
            if (systemCache.TryGetValue("Drivers", out List<string> cachedDrivers))
            {
                return cachedDrivers;
            }

            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_SystemDriver"))
                {
                    foreach (var driver in searcher.Get())
                    {
                        drivers.Add($"{driver["Name"]}: {driver["DisplayName"]} ({driver["State"]})");
                    }
                }

                systemCache["Drivers"] = drivers;
            }
            catch
            {
                drivers.Clear();
            }

            return drivers;
        }

        private List<string> GetSystemRegistry()
        {
            var registry = new List<string>();
            
            if (systemCache.TryGetValue("Registry", out List<string> cachedRegistry))
            {
                return cachedRegistry;
            }

            try
            {
                registry.AddRange(systemPatterns["Registry"]);
                systemCache["Registry"] = registry;
            }
            catch
            {
                registry.Clear();
            }

            return registry;
        }

        private List<ScanResult> AnalyzeSystemComponent(string component, List<string> items)
        {
            var results = new List<ScanResult>();
            
            try
            {
                double componentScore = CalculateComponentScore(items, component);
                var result = CreateComponentScanResult(component, componentScore);
                results.Add(result);

                if (result.IsInfected)
                {
                    dataManager.LogThreat($"系统分析检测到恶意{component}: {component}", $"评分: {componentScore:P}", "SystemAnalyzer");
                }
            }
            catch
            {
                // 忽略错误
            }

            return results;
        }

        private double CalculateSystemScore(List<string> processes, List<string> services, List<string> drivers, List<string> registry)
        {
            double score = 0.0;

            try
            {
                score += CalculateComponentScore(processes, "Processes");
                score += CalculateComponentScore(services, "Services");
                score += CalculateComponentScore(drivers, "Drivers");
                score += CalculateComponentScore(registry, "Registry");
                score /= 4.0; // 平均分数
            }
            catch
            {
                score = 0.0;
            }

            return Math.Max(0.0, Math.Min(score, 1.0));
        }

        private double CalculateComponentScore(List<string> items, string component)
        {
            double score = 0.0;

            try
            {
                score += AnalyzeMaliciousSystemSignatures(items, component);
                score += AnalyzeSuspiciousSystemSignatures(items, component);
                score += AnalyzeBenignSystemSignatures(items, component);
            }
            catch
            {
                score = 0.0;
            }

            return Math.Max(0.0, Math.Min(score, 1.0));
        }

        private double AnalyzeMaliciousSystemSignatures(List<string> items, string component)
        {
            double score = 0.0;

            foreach (var item in items)
            {
                foreach (var signatureCategory in maliciousSystemSignatures)
                {
                    foreach (var signature in signatureCategory.Value)
                    {
                        if (item.Contains(signature, StringComparison.OrdinalIgnoreCase))
                        {
                            score += 0.1;
                        }
                    }
                }
            }

            return score;
        }

        private double AnalyzeSuspiciousSystemSignatures(List<string> items, string component)
        {
            double score = 0.0;

            foreach (var item in items)
            {
                foreach (var signatureCategory in suspiciousSystemSignatures)
                {
                    foreach (var signature in signatureCategory.Value)
                    {
                        if (item.Contains(signature, StringComparison.OrdinalIgnoreCase))
                        {
                            score += 0.05;
                        }
                    }
                }
            }

            return score;
        }

        private double AnalyzeBenignSystemSignatures(List<string> items, string component)
        {
            double score = 0.0;

            foreach (var item in items)
            {
                foreach (var signatureCategory in benignSystemSignatures)
                {
                    foreach (var signature in signatureCategory.Value)
                    {
                        if (item.Contains(signature, StringComparison.OrdinalIgnoreCase))
                        {
                            score -= 0.03;
                        }
                    }
                }
            }

            return score;
        }

        private ScanResult CreateSystemScanResult(string target, double systemScore)
        {
            var result = new ScanResult
            {
                FilePath = target,
                IsInfected = systemScore > 0.85,
                Confidence = systemScore,
                DetectionTime = DateTime.Now,
                DetectionMethod = "System"
            };

            if (result.IsInfected)
            {
                if (systemScore > 0.95)
                {
                    result.ThreatName = "系统分析检测到恶意活动";
                    result.ThreatType = "Malware";
                    result.Severity = "High";
                }
                else
                {
                    result.ThreatName = "系统分析检测到可疑活动";
                    result.ThreatType = "Suspicious";
                    result.Severity = "Medium";
                }

                result.AdditionalInfo = $"系统评分: {systemScore:P}";
            }

            return result;
        }

        private ScanResult CreateComponentScanResult(string component, double componentScore)
        {
            var result = new ScanResult
            {
                FilePath = component,
                IsInfected = componentScore > 0.85,
                Confidence = componentScore,
                DetectionTime = DateTime.Now,
                DetectionMethod = "System"
            };

            if (result.IsInfected)
            {
                if (componentScore > 0.95)
                {
                    result.ThreatName = $"系统分析检测到恶意{component}";
                    result.ThreatType = "Malware";
                    result.Severity = "High";
                }
                else
                {
                    result.ThreatName = $"系统分析检测到可疑{component}";
                    result.ThreatType = "Suspicious";
                    result.Severity = "Medium";
                }

                result.AdditionalInfo = $"{component}评分: {componentScore:P}";
            }

            return result;
        }

        public void ClearCache()
        {
            systemCache.Clear();
        }

        public int GetCacheSize()
        {
            return systemCache.Count;
        }
    }
}
