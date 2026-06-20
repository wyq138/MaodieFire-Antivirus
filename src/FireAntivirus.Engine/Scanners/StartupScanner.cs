using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32;
using FireAntivirus.Common;
using FireAntivirus.Data;
using FireAntivirus.Engine;

namespace FireAntivirus.Engine.Scanners
{
    public class StartupScanner
    {
        private DataManager dataManager;
        private Dictionary<string, List<string>> startupCache;
        private Dictionary<string, List<string>> startupLocations;
        private Dictionary<string, List<string>> maliciousStartupPatterns;
        private Dictionary<string, List<string>> suspiciousStartupPatterns;
        private Dictionary<string, List<string>> benignStartupPatterns;

        public StartupScanner()
        {
            dataManager = new DataManager();
            startupCache = new Dictionary<string, List<string>>();
            InitializeStartupLocations();
            InitializeStartupPatterns();
        }

        private void InitializeStartupLocations()
        {
            startupLocations = new Dictionary<string, List<string>>
            {
                { "Registry", new List<string> {
                    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx",
                    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx",
                    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
                    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
                    "HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\load",
                    "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\load",
                    "HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\run",
                    "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\run",
                    "HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell",
                    "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell",
                    "HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit",
                    "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit",
                    "HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\GinaDLL",
                    "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\GinaDLL",
                    "HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Taskman",
                    "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Taskman",
                    "HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\System",
                    "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\System",
                    "HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\UIHost",
                    "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\UIHost"
                }},
                { "StartupFolders", new List<string> {
                    Environment.GetFolderPath(Environment.SpecialFolder.Startup),
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.StartMenu), "Programs", "Startup"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartMenu), "Programs", "Startup")
                }},
                { "Services", new List<string> {
                    "HKLM\\SYSTEM\\CurrentControlSet\\Services",
                    "HKLM\\SYSTEM\\ControlSet001\\Services",
                    "HKLM\\SYSTEM\\ControlSet002\\Services"
                }},
                { "ScheduledTasks", new List<string> {
                    "C:\\Windows\\System32\\Tasks",
                    "C:\\Windows\\SysWOW64\\Tasks"
                }},
                { "WMI", new List<string> {
                    "root\\cimv2:Win32_StartupCommand"
                }}
            };
        }

        private void InitializeStartupPatterns()
        {
            maliciousStartupPatterns = new Dictionary<string, List<string>>
            {
                { "FilePaths", new List<string> {
                    "Temp", "AppData", "Local", "Roaming", "Downloads", "Desktop",
                    "Microsoft", "Windows", "System32", "SysWOW64", "Program Files"
                }},
                { "FileExtensions", new List<string> {
                    ".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".js",
                    ".jse", ".wsf", ".hta", ".scr", ".com", ".pif", ".url", ".lnk"
                }},
                { "ProcessNames", new List<string> {
                    "svchost.exe", "explorer.exe", "winlogon.exe", "lsass.exe",
                    "csrss.exe", "smss.exe", "services.exe", "wininit.exe",
                    "taskhost.exe", "dwm.exe", "conhost.exe", "cmd.exe",
                    "powershell.exe", "regsvr32.exe", "rundll32.exe", "msiexec.exe"
                }},
                { "Keywords", new List<string> {
                    "Run", "RunOnce", "Startup", "Winlogon", "Shell", "Userinit",
                    "GinaDLL", "Taskman", "load", "run", "Policy", "Explorer"
                }}
            };

            suspiciousStartupPatterns = new Dictionary<string, List<string>>
            {
                { "FilePaths", new List<string> {
                    "ProgramData", "LocalLow", "Application Data", "Local Settings",
                    "Common Files", "Common Application Data", "Common Desktop Directory"
                }},
                { "FileExtensions", new List<string> {
                    ".msi", ".msp", ".mst", ".cab", ".zip", ".rar", ".7z", ".tar"
                }},
                { "ProcessNames", new List<string> {
                    "notepad.exe", "wordpad.exe", "mspaint.exe", "calc.exe",
                    "explorer.exe", "cmd.exe", "powershell.exe", "regedit.exe"
                }},
                { "Keywords", new List<string> {
                    "Application", "Program", "Software", "Tool", "Utility", "Helper"
                }}
            };

            benignStartupPatterns = new Dictionary<string, List<string>>
            {
                { "FilePaths", new List<string> {
                    "Program Files", "Program Files (x86)", "Windows", "System32",
                    "SysWOW64", "Common Files", "Microsoft", "Google", "Mozilla"
                }},
                { "FileExtensions", new List<string> {
                    ".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1"
                }},
                { "ProcessNames", new List<string> {
                    "explorer.exe", "svchost.exe", "services.exe", "winlogon.exe",
                    "lsass.exe", "csrss.exe", "smss.exe", "wininit.exe"
                }},
                { "Keywords", new List<string> {
                    "Microsoft", "Windows", "System", "Service", "Update", "Security"
                }}
            };
        }

        public List<ScanResult> ScanStartupItems()
        {
            var results = new List<ScanResult>();
            
            try
            {
                var registryResults = ScanRegistryStartupItems();
                var folderResults = ScanFolderStartupItems();
                var serviceResults = ScanServiceStartupItems();
                var taskResults = ScanScheduledTaskStartupItems();
                var wmiResults = ScanWMIStartupItems();

                results.AddRange(registryResults);
                results.AddRange(folderResults);
                results.AddRange(serviceResults);
                results.AddRange(taskResults);
                results.AddRange(wmiResults);
            }
            catch (Exception ex)
            {
                dataManager.LogError("启动项扫描失败", ex.Message, "StartupScanner");
            }

            return results;
        }

        public List<ScanResult> ScanRegistryStartupItems()
        {
            return ScanStartupLocation(startupLocations["Registry"], "Registry");
        }

        public List<ScanResult> ScanFolderStartupItems()
        {
            return ScanStartupLocation(startupLocations["StartupFolders"], "Folder");
        }

        public List<ScanResult> ScanServiceStartupItems()
        {
            return ScanStartupLocation(startupLocations["Services"], "Service");
        }

        public List<ScanResult> ScanScheduledTaskStartupItems()
        {
            return ScanStartupLocation(startupLocations["ScheduledTasks"], "ScheduledTask");
        }

        public List<ScanResult> ScanWMIStartupItems()
        {
            return ScanStartupLocation(startupLocations["WMI"], "WMI");
        }

        private List<ScanResult> ScanStartupLocation(List<string> locations, string category)
        {
            var results = new List<ScanResult>();
            
            foreach (var location in locations)
            {
                try
                {
                    var items = GetStartupItems(location, category);
                    double startupScore = CalculateStartupScore(items, category);
                    var result = CreateStartupScanResult(location, startupScore, category);
                    results.Add(result);

                    if (result.IsInfected)
                    {
                        dataManager.LogThreat($"启动项扫描检测到恶意项: {location}", $"评分: {startupScore:P}", "StartupScanner");
                    }
                }
                catch
                {
                    continue;
                }
            }

            return results;
        }

        private List<string> GetStartupItems(string location, string category)
        {
            var items = new List<string>();
            
            if (startupCache.TryGetValue($"{category}:{location}", out List<string> cachedItems))
            {
                return cachedItems;
            }

            try
            {
                switch (category)
                {
                    case "Registry":
                        items = GetRegistryStartupItems(location);
                        break;
                    case "Folder":
                        items = GetFolderStartupItems(location);
                        break;
                    case "Service":
                        items = GetServiceStartupItems(location);
                        break;
                    case "ScheduledTask":
                        items = GetScheduledTaskStartupItems(location);
                        break;
                    case "WMI":
                        items = GetWMIStartupItems(location);
                        break;
                }

                startupCache[$"{category}:{location}"] = items;
            }
            catch
            {
                items.Clear();
            }

            return items;
        }

        private List<string> GetRegistryStartupItems(string registryPath)
        {
            var items = new List<string>();
            
            try
            {
                string hive = registryPath.Split('\\')[0];
                string subKey = registryPath.Substring(registryPath.IndexOf('\\') + 1);

                RegistryKey rootKey = null;
                switch (hive.ToUpper())
                {
                    case "HKCU":
                        rootKey = Registry.CurrentUser;
                        break;
                    case "HKLM":
                        rootKey = Registry.LocalMachine;
                        break;
                }

                if (rootKey != null)
                {
                    using (RegistryKey key = rootKey.OpenSubKey(subKey))
                    {
                        if (key != null)
                        {
                            foreach (string valueName in key.GetValueNames())
                            {
                                object value = key.GetValue(valueName);
                                if (value != null)
                                {
                                    items.Add($"{valueName}: {value}");
                                }
                            }
                        }
                    }
                }
            }
            catch
            {
                items.Clear();
            }

            return items;
        }

        private List<string> GetFolderStartupItems(string folderPath)
        {
            var items = new List<string>();
            
            try
            {
                if (Directory.Exists(folderPath))
                {
                    var files = Directory.GetFiles(folderPath);
                    foreach (var file in files)
                    {
                        items.Add(file);
                    }
                }
            }
            catch
            {
                items.Clear();
            }

            return items;
        }

        private List<string> GetServiceStartupItems(string registryPath)
        {
            var items = new List<string>();
            
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Service"))
                {
                    foreach (var service in searcher.Get())
                    {
                        items.Add($"{service["Name"]}: {service["PathName"]}");
                    }
                }
            }
            catch
            {
                items.Clear();
            }

            return items;
        }

        private List<string> GetScheduledTaskStartupItems(string folderPath)
        {
            var items = new List<string>();
            
            try
            {
                if (Directory.Exists(folderPath))
                {
                    var files = Directory.GetFiles(folderPath, "*.xml", SearchOption.AllDirectories);
                    foreach (var file in files)
                    {
                        items.Add(file);
                    }
                }
            }
            catch
            {
                items.Clear();
            }

            return items;
        }

        private List<string> GetWMIStartupItems(string wmiClass)
        {
            var items = new List<string>();
            
            try
            {
                using (var searcher = new ManagementObjectSearcher(wmiClass))
                {
                    foreach (var item in searcher.Get())
                    {
                        items.Add($"{item["Name"]}: {item["Command"]}");
                    }
                }
            }
            catch
            {
                items.Clear();
            }

            return items;
        }

        private double CalculateStartupScore(List<string> items, string category)
        {
            double score = 0.0;

            try
            {
                score += AnalyzeMaliciousStartupPatterns(items, category);
                score += AnalyzeSuspiciousStartupPatterns(items, category);
                score += AnalyzeBenignStartupPatterns(items, category);
            }
            catch
            {
                score = 0.0;
            }

            return Math.Max(0.0, Math.Min(score, 1.0));
        }

        private double AnalyzeMaliciousStartupPatterns(List<string> items, string category)
        {
            double score = 0.0;

            foreach (var item in items)
            {
                foreach (var patternCategory in maliciousStartupPatterns)
                {
                    foreach (var pattern in patternCategory.Value)
                    {
                        if (item.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                        {
                            score += 0.05;
                        }
                    }
                }
            }

            return score;
        }

        private double AnalyzeSuspiciousStartupPatterns(List<string> items, string category)
        {
            double score = 0.0;

            foreach (var item in items)
            {
                foreach (var patternCategory in suspiciousStartupPatterns)
                {
                    foreach (var pattern in patternCategory.Value)
                    {
                        if (item.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                        {
                            score += 0.02;
                        }
                    }
                }
            }

            return score;
        }

        private double AnalyzeBenignStartupPatterns(List<string> items, string category)
        {
            double score = 0.0;

            foreach (var item in items)
            {
                foreach (var patternCategory in benignStartupPatterns)
                {
                    foreach (var pattern in patternCategory.Value)
                    {
                        if (item.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                        {
                            score -= 0.03;
                        }
                    }
                }
            }

            return score;
        }

        private ScanResult CreateStartupScanResult(string location, double startupScore, string category)
        {
            var result = new ScanResult
            {
                FilePath = location,
                IsInfected = startupScore > 0.85,
                Confidence = startupScore,
                DetectionTime = DateTime.Now,
                DetectionMethod = "Startup"
            };

            if (result.IsInfected)
            {
                if (startupScore > 0.95)
                {
                    result.ThreatName = $"启动项扫描检测到恶意项 ({category})";
                    result.ThreatType = "Malware";
                    result.Severity = "High";
                }
                else
                {
                    result.ThreatName = $"启动项扫描检测到可疑项 ({category})";
                    result.ThreatType = "Suspicious";
                    result.Severity = "Medium";
                }

                result.AdditionalInfo = $"启动项评分: {startupScore:P}, 类别: {category}";
            }

            return result;
        }

        public void ClearCache()
        {
            startupCache.Clear();
        }

        public int GetCacheSize()
        {
            return startupCache.Count;
        }
    }
}
