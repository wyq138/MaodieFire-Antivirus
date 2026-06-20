using System;
using System.Collections.Generic;
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
    public class RegistryScanner
    {
        private DataManager dataManager;
        private Dictionary<string, List<string>> registryCache;
        private Dictionary<string, List<string>> maliciousRegistryKeys;
        private Dictionary<string, List<string>> suspiciousRegistryKeys;
        private Dictionary<string, List<string>> benignRegistryKeys;

        public RegistryScanner()
        {
            dataManager = new DataManager();
            registryCache = new Dictionary<string, List<string>>();
            InitializeRegistryPatterns();
        }

        private void InitializeRegistryPatterns()
        {
            maliciousRegistryKeys = new Dictionary<string, List<string>>
            {
                { "Startup", new List<string> {
                    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx",
                    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx",
                    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
                    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
                    "HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\load",
                    "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\load"
                }},
                { "Services", new List<string> {
                    "HKLM\\SYSTEM\\CurrentControlSet\\Services",
                    "HKLM\\SYSTEM\\ControlSet001\\Services",
                    "HKLM\\SYSTEM\\ControlSet002\\Services"
                }},
                { "Browser", new List<string> {
                    "HKCU\\Software\\Microsoft\\Internet Explorer\\Main",
                    "HKCU\\Software\\Microsoft\\Internet Explorer\\Search",
                    "HKCU\\Software\\Microsoft\\Internet Explorer\\Toolbar",
                    "HKCU\\Software\\Mozilla\\Firefox\\Extensions",
                    "HKCU\\Software\\Google\\Chrome\\Extensions"
                }},
                { "FileAssociations", new List<string> {
                    "HKCU\\Software\\Classes\\.exe",
                    "HKLM\\Software\\Classes\\.exe",
                    "HKCU\\Software\\Classes\\.dll",
                    "HKLM\\Software\\Classes\\.dll",
                    "HKCU\\Software\\Classes\\.bat",
                    "HKLM\\Software\\Classes\\.bat",
                    "HKCU\\Software\\Classes\\.cmd",
                    "HKLM\\Software\\Classes\\.cmd"
                }},
                { "System", new List<string> {
                    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\BootExecute",
                    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls",
                    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDlls",
                    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\SubSystems",
                    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot"
                }},
                { "WinLogon", new List<string> {
                    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell",
                    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit",
                    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\GinaDLL",
                    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Taskman",
                    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\System",
                    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\UIHost"
                }},
                { "Network", new List<string> {
                    "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
                    "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Winsock2\\Parameters",
                    "HKLM\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters",
                    "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Dhcp\\Parameters"
                }},
                { "Security", new List<string> {
                    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                    "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
                    "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"
                }}
            };

            suspiciousRegistryKeys = new Dictionary<string, List<string>>
            {
                { "Applications", new List<string> {
                    "HKCU\\Software",
                    "HKLM\\Software",
                    "HKCU\\Software\\Microsoft",
                    "HKLM\\Software\\Microsoft"
                }},
                { "Environment", new List<string> {
                    "HKCU\\Environment",
                    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment"
                }},
                { "Hardware", new List<string> {
                    "HKLM\\HARDWARE",
                    "HKLM\\SYSTEM\\CurrentControlSet\\Enum",
                    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class"
                }},
                { "Printers", new List<string> {
                    "HKCU\\Printers",
                    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print"
                }},
                { "Software", new List<string> {
                    "HKCR",
                    "HKCU\\Software\\Classes",
                    "HKLM\\Software\\Classes"
                }}
            };

            benignRegistryKeys = new Dictionary<string, List<string>>
            {
                { "System", new List<string> {
                    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation",
                    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\International",
                    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\ComputerName",
                    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management"
                }},
                { "Windows", new List<string> {
                    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
                    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer",
                    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Setup",
                    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths"
                }},
                { "User", new List<string> {
                    "HKCU\\Control Panel",
                    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer",
                    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Themes",
                    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"
                }}
            };
        }

        public List<ScanResult> ScanRegistry()
        {
            var results = new List<ScanResult>();
            
            try
            {
                var startupResults = ScanStartupRegistry();
                var servicesResults = ScanServicesRegistry();
                var browserResults = ScanBrowserRegistry();
                var fileAssociationsResults = ScanFileAssociationsRegistry();
                var systemResults = ScanSystemRegistry();
                var winlogonResults = ScanWinlogonRegistry();
                var networkResults = ScanNetworkRegistry();
                var securityResults = ScanSecurityRegistry();

                results.AddRange(startupResults);
                results.AddRange(servicesResults);
                results.AddRange(browserResults);
                results.AddRange(fileAssociationsResults);
                results.AddRange(systemResults);
                results.AddRange(winlogonResults);
                results.AddRange(networkResults);
                results.AddRange(securityResults);
            }
            catch (Exception ex)
            {
                dataManager.LogError("注册表扫描失败", ex.Message, "RegistryScanner");
            }

            return results;
        }

        public List<ScanResult> ScanStartupRegistry()
        {
            return ScanRegistryKeys(maliciousRegistryKeys["Startup"], "Startup");
        }

        public List<ScanResult> ScanServicesRegistry()
        {
            return ScanRegistryKeys(maliciousRegistryKeys["Services"], "Services");
        }

        public List<ScanResult> ScanBrowserRegistry()
        {
            return ScanRegistryKeys(maliciousRegistryKeys["Browser"], "Browser");
        }

        public List<ScanResult> ScanFileAssociationsRegistry()
        {
            return ScanRegistryKeys(maliciousRegistryKeys["FileAssociations"], "FileAssociations");
        }

        public List<ScanResult> ScanSystemRegistry()
        {
            return ScanRegistryKeys(maliciousRegistryKeys["System"], "System");
        }

        public List<ScanResult> ScanWinlogonRegistry()
        {
            return ScanRegistryKeys(maliciousRegistryKeys["WinLogon"], "WinLogon");
        }

        public List<ScanResult> ScanNetworkRegistry()
        {
            return ScanRegistryKeys(maliciousRegistryKeys["Network"], "Network");
        }

        public List<ScanResult> ScanSecurityRegistry()
        {
            return ScanRegistryKeys(maliciousRegistryKeys["Security"], "Security");
        }

        private List<ScanResult> ScanRegistryKeys(List<string> registryKeys, string category)
        {
            var results = new List<ScanResult>();
            
            foreach (var keyPath in registryKeys)
            {
                try
                {
                    var values = GetRegistryValues(keyPath);
                    double registryScore = CalculateRegistryScore(values, category);
                    var result = CreateRegistryScanResult(keyPath, registryScore, category);
                    results.Add(result);

                    if (result.IsInfected)
                    {
                        dataManager.LogThreat($"注册表扫描检测到恶意键值: {keyPath}", $"评分: {registryScore:P}", "RegistryScanner");
                    }
                }
                catch
                {
                    continue;
                }
            }

            return results;
        }

        private List<string> GetRegistryValues(string keyPath)
        {
            var values = new List<string>();
            
            if (registryCache.TryGetValue(keyPath, out List<string> cachedValues))
            {
                return cachedValues;
            }

            try
            {
                string hive = keyPath.Split('\\')[0];
                string subKey = keyPath.Substring(keyPath.IndexOf('\\') + 1);

                RegistryKey rootKey = null;
                switch (hive.ToUpper())
                {
                    case "HKCU":
                        rootKey = Registry.CurrentUser;
                        break;
                    case "HKLM":
                        rootKey = Registry.LocalMachine;
                        break;
                    case "HKCR":
                        rootKey = Registry.ClassesRoot;
                        break;
                    case "HKU":
                        rootKey = Registry.Users;
                        break;
                    case "HKCC":
                        rootKey = Registry.CurrentConfig;
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
                                    values.Add($"{valueName}: {value}");
                                }
                            }

                            foreach (string subKeyName in key.GetSubKeyNames())
                            {
                                values.Add($"SubKey: {subKeyName}");
                            }
                        }
                    }
                }

                registryCache[keyPath] = values;
            }
            catch
            {
                values.Clear();
            }

            return values;
        }

        private double CalculateRegistryScore(List<string> values, string category)
        {
            double score = 0.0;

            try
            {
                score += AnalyzeMaliciousRegistryValues(values, category);
                score += AnalyzeSuspiciousRegistryValues(values, category);
                score += AnalyzeBenignRegistryValues(values, category);
            }
            catch
            {
                score = 0.0;
            }

            return Math.Max(0.0, Math.Min(score, 1.0));
        }

        private double AnalyzeMaliciousRegistryValues(List<string> values, string category)
        {
            double score = 0.0;

            string[] maliciousPatterns = {
                "exe", "dll", "sys", "bat", "cmd", "ps1", "vbs", "js",
                "jse", "wsf", "hta", "scr", "com", "pif", "url", "lnk",
                "Temp", "AppData", "Local", "Roaming", "Downloads", "Desktop",
                "Microsoft", "Windows", "System32", "SysWOW64", "Program Files",
                "Run", "RunOnce", "Startup", "Services", "Winlogon", "Shell",
                "Userinit", "GinaDLL", "Taskman", "load", "Policy", "Explorer"
            };

            foreach (var value in values)
            {
                foreach (var pattern in maliciousPatterns)
                {
                    if (value.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        score += 0.02;
                    }
                }
            }

            return score;
        }

        private double AnalyzeSuspiciousRegistryValues(List<string> values, string category)
        {
            double score = 0.0;

            string[] suspiciousPatterns = {
                "Internet Explorer", "Firefox", "Chrome", "Safari", "Opera",
                "Browser", "Toolbar", "Extension", "Addon", "Plugin",
                "Search", "HomePage", "StartPage", "DefaultSearch", "SearchProvider",
                "FileAssociations", ".exe", ".dll", ".bat", ".cmd",
                "Environment", "Path", "Temp", "TMP", "ProgramFiles"
            };

            foreach (var value in values)
            {
                foreach (var pattern in suspiciousPatterns)
                {
                    if (value.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        score += 0.01;
                    }
                }
            }

            return score;
        }

        private double AnalyzeBenignRegistryValues(List<string> values, string category)
        {
            double score = 0.0;

            string[] benignPatterns = {
                "Microsoft", "Windows", "System", "Control", "CurrentVersion",
                "Uninstall", "Installer", "Setup", "App Paths", "Common Files",
                "Program Files", "Program Files (x86)", "System32", "SysWOW64",
                "TimeZoneInformation", "International", "ComputerName", "Memory Management",
                "Control Panel", "Explorer", "Themes", "Internet Settings", "Display"
            };

            foreach (var value in values)
            {
                foreach (var pattern in benignPatterns)
                {
                    if (value.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        score -= 0.03;
                    }
                }
            }

            return score;
        }

        private ScanResult CreateRegistryScanResult(string keyPath, double registryScore, string category)
        {
            var result = new ScanResult
            {
                FilePath = keyPath,
                IsInfected = registryScore > 0.85,
                Confidence = registryScore,
                DetectionTime = DateTime.Now,
                DetectionMethod = "Registry"
            };

            if (result.IsInfected)
            {
                if (registryScore > 0.95)
                {
                    result.ThreatName = $"注册表扫描检测到恶意键值 ({category})";
                    result.ThreatType = "Malware";
                    result.Severity = "High";
                }
                else
                {
                    result.ThreatName = $"注册表扫描检测到可疑键值 ({category})";
                    result.ThreatType = "Suspicious";
                    result.Severity = "Medium";
                }

                result.AdditionalInfo = $"注册表评分: {registryScore:P}, 类别: {category}";
            }

            return result;
        }

        public void ClearCache()
        {
            registryCache.Clear();
        }

        public int GetCacheSize()
        {
            return registryCache.Count;
        }
    }
}
