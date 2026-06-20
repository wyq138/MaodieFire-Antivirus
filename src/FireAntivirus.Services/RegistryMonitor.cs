using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Linq;
using FireAntivirus.Data;
using FireAntivirus.Engine;

namespace FireAntivirus.Services
{
    public class RegistryMonitor : IMonitor
    {
        private Thread monitorThread;
        private bool isRunning;
        private DataManager dataManager;
        private AntivirusEngine antivirusEngine;
        private List<string> monitoredKeys;
        private HashSet<int> monitoredProcesses;
        private Dictionary<string, string> knownStartupItems;
        private Dictionary<string, RegistryKeyHash> registryHashes;
        private Dictionary<string, RegistryChangeInfo> suspiciousChanges;
        private List<string> criticalProcessKeys;
        private List<string> securityPolicyKeys;
        
        // 受信任路径白名单
        private HashSet<string> trustedPaths;
        
        public RegistryMonitor(DataManager dataManager, AntivirusEngine antivirusEngine)
        {
            this.dataManager = dataManager;
            this.antivirusEngine = antivirusEngine;
            InitializeTrustedPaths();
            
            monitoredKeys = new List<string>
            {
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx",
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
                "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
                "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
            };
            
            criticalProcessKeys = new List<string>
            {
                "SYSTEM\\CurrentControlSet\\Control\\Session Manager",
                "SYSTEM\\CurrentControlSet\\Services",
                "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"
            };
            
            securityPolicyKeys = new List<string>
            {
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
                "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
            };
            
            monitoredProcesses = new HashSet<int>();
            knownStartupItems = new Dictionary<string, string>();
            registryHashes = new Dictionary<string, RegistryKeyHash>();
            suspiciousChanges = new Dictionary<string, RegistryChangeInfo>();
        }
        
        private void InitializeTrustedPaths()
        {
            trustedPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                @"\Program Files\", @"\Program Files (x86)\",
                @"\Windows\", @"\Windows\System32", @"\Windows\SysWOW64",
                @"\Microsoft.NET", @"\dotnet"
            };
        }
        
        // 检查路径是否受信任
        private bool IsTrustedPath(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            foreach (var tp in trustedPaths)
            {
                if (path.Contains(tp, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }
        
        public void Start()
        {
            isRunning = true;
            monitorThread = new Thread(MonitorRegistry);
            monitorThread.Start();
            
            // 初始化已知启动项基线和注册表哈希
            InitializeBaseline();
            CalculateRegistryHashes();
            
            dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "RegistryMonitorStart",
                Message = "注册表监控已启动",
                Details = "开始监控系统启动项和关键注册表"
            });
        }
        
        public void Stop()
        {
            isRunning = false;
            monitorThread?.Join(2000);
            
            dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "RegistryMonitorStop",
                Message = "注册表监控已停止",
                Details = string.Empty
            });
        }
        
        private void InitializeBaseline()
        {
            try
            {
                foreach (string keyPath in monitoredKeys.Concat(criticalProcessKeys).Concat(securityPolicyKeys))
                {
                    using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(keyPath))
                    {
                        if (key != null)
                        {
                            foreach (string valueName in key.GetValueNames())
                            {
                                string value = key.GetValue(valueName)?.ToString() ?? "";
                                if (!string.IsNullOrEmpty(value))
                                {
                                    knownStartupItems[$"{keyPath}\\{valueName}"] = value;
                                }
                            }
                        }
                    }
                }
            }
            catch { }
        }
        
        private void CalculateRegistryHashes()
        {
            try
            {
                foreach (string keyPath in criticalProcessKeys.Concat(securityPolicyKeys))
                {
                    using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(keyPath))
                    {
                        if (key != null)
                        {
                            var hashBuilder = new StringBuilder();
                            foreach (string valueName in key.GetValueNames())
                            {
                                string value = key.GetValue(valueName)?.ToString() ?? "";
                                hashBuilder.Append($"{valueName}={value};");
                            }
                            
                            using (var sha256 = SHA256.Create())
                            {
                                byte[] hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(hashBuilder.ToString()));
                                string hashString = BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
                                
                                registryHashes[keyPath] = new RegistryKeyHash
                                {
                                    KeyPath = keyPath,
                                    HashValue = hashString,
                                    LastModified = DateTime.Now
                                };
                            }
                        }
                    }
                }
            }
            catch { }
        }
        
        private void MonitorRegistry()
        {
            while (isRunning)
            {
                try
                {
                    CheckRegistryKeys();
                    CheckCriticalRegistryHashes();
                    CheckSecurityPolicyKeys();
                    AnalyzeSuspiciousChanges();
                }
                catch (Exception ex)
                {
                    dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "RegistryMonitorError",
                        Message = "注册表监控错误",
                        Details = ex.Message
                    });
                }
                
                Thread.Sleep(30000); // 每30秒检查一次，降低敏感度
            }
        }
        
        private void CheckRegistryKeys()
        {
            foreach (string keyPath in monitoredKeys)
            {
                try
                {
                    using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(keyPath))
                    {
                        if (key != null)
                        {
                            foreach (string valueName in key.GetValueNames())
                            {
                                string value = key.GetValue(valueName) as string;
                                if (!string.IsNullOrEmpty(value))
                                {
                                    string itemKey = $"{keyPath}\\{valueName}";
                                    
                                    // 检查是否是新添加的启动项
                                    if (!knownStartupItems.ContainsKey(itemKey))
                                    {
                                        // 新启动项
                                        HandleNewStartupItem(valueName, value, keyPath);
                                    }
                                    else if (knownStartupItems[itemKey] != value)
                                    {
                                        // 启动项被修改
                                        HandleModifiedStartupItem(valueName, knownStartupItems[itemKey], value, keyPath);
                                    }
                                    
                                    // 检查可疑启动项
                                    CheckSuspiciousStartup(valueName, value, keyPath);
                                    
                                    // 检查恶意软件行为模式
                                    CheckMalwarePatterns(valueName, value, keyPath);
                                }
                            }
                        }
                    }
                }
                catch { }
            }
        }
        
        private void CheckCriticalRegistryHashes()
        {
            foreach (string keyPath in criticalProcessKeys)
            {
                try
                {
                    using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(keyPath))
                    {
                        if (key != null)
                        {
                            var hashBuilder = new StringBuilder();
                            foreach (string valueName in key.GetValueNames())
                            {
                                string value = key.GetValue(valueName)?.ToString() ?? "";
                                hashBuilder.Append($"{valueName}={value};");
                            }
                            
                            using (var sha256 = SHA256.Create())
                            {
                                byte[] hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(hashBuilder.ToString()));
                                string currentHash = BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
                                
                                if (registryHashes.ContainsKey(keyPath) && registryHashes[keyPath].HashValue != currentHash)
                                {
                                    HandleRegistryTampering(keyPath, registryHashes[keyPath].HashValue, currentHash);
                                    registryHashes[keyPath] = new RegistryKeyHash
                                    {
                                        KeyPath = keyPath,
                                        HashValue = currentHash,
                                        LastModified = DateTime.Now
                                    };
                                }
                            }
                        }
                    }
                }
                catch { }
            }
        }
        
        private void CheckSecurityPolicyKeys()
        {
            foreach (string keyPath in securityPolicyKeys)
            {
                try
                {
                    using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(keyPath))
                    {
                        if (key != null)
                        {
                            var hashBuilder = new StringBuilder();
                            foreach (string valueName in key.GetValueNames())
                            {
                                string value = key.GetValue(valueName)?.ToString() ?? "";
                                hashBuilder.Append($"{valueName}={value};");
                                
                                // 检查安全策略篡改
                                CheckSecurityPolicyTampering(keyPath, valueName, value);
                            }
                        }
                    }
                }
                catch { }
            }
        }
        
        private void AnalyzeSuspiciousChanges()
        {
            var threshold = DateTime.Now.AddMinutes(-5);
            var recentChanges = suspiciousChanges.Values
                .Where(c => c.DetectionTime >= threshold)
                .ToList();
                
            if (recentChanges.Count >= 3)
            {
                string message = $"检测到注册表持续异常修改\n最近5分钟内检测到{recentChanges.Count}次可疑更改\n可能为恶意软件活动";
                
                dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "RegistryAttackPattern",
                    Message = "注册表攻击模式检测",
                    Details = message
                });
                
                ShowThreatNotification("注册表攻击检测", message, NotificationType.Error);
            }
        }
        
        private void HandleNewStartupItem(string name, string value, string keyPath)
        {
            string itemKey = $"{keyPath}\\{name}";
            string message = $"检测到新启动项\n名称: {name}\n值: {value}\n位置: {keyPath}";
            
            dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "NewStartupItem",
                Message = "检测到新启动项",
                Details = message
            });
            
            // 弹窗通知
            ShowThreatNotification("新启动项检测", message, NotificationType.Info);
            
            knownStartupItems[itemKey] = value;
        }
        
        private void HandleModifiedStartupItem(string name, string oldValue, string newValue, string keyPath)
        {
            string itemKey = $"{keyPath}\\{name}";
            string message = $"启动项被修改\n名称: {name}\n原值: {oldValue}\n新值: {newValue}\n位置: {keyPath}";
            
            dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "StartupItemModified",
                Message = "启动项被修改",
                Details = message
            });
            
            // 弹窗警告
            ShowThreatNotification("启动项修改警告", message, NotificationType.Warning);
            
            knownStartupItems[itemKey] = newValue;
            
            // 记录可疑更改
            RecordSuspiciousChange(itemKey, $"启动项修改: {oldValue} -> {newValue}");
        }
        
        private void HandleRegistryTampering(string keyPath, string oldHash, string newHash)
        {
            string message = $"关键注册表哈希值改变\n路径: {keyPath}\n原哈希: {oldHash.Substring(0, 16)}...\n新哈希: {newHash.Substring(0, 16)}...";
            
            dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "RegistryHashChange",
                Message = "注册表哈希值变更",
                Details = message
            });
            
            ShowThreatNotification("注册表完整性警告", message, NotificationType.Error);
            
            RecordSuspiciousChange(keyPath, $"哈希值变更: {oldHash.Substring(0, 16)} -> {newHash.Substring(0, 16)}");
        }
        
        private void CheckSuspiciousStartup(string name, string value, string keyPath)
        {
            // 如果路径在受信任白名单中，跳过检查
            if (IsTrustedPath(value))
                return;
            
            string[] suspiciousValues = {
                "-encodedcommand", "-enc ", "downloadstring", "invoke-expression",
                ".tmp", ".temp", "%temp%", "%tmp%"
            };
            
            foreach (string suspicious in suspiciousValues)
            {
                if (value.IndexOf(suspicious, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    string message = $"发现可疑启动项\n名称: {name}\n值: {value}\n位置: {keyPath}\n可疑特征: {suspicious}";
                    
                    dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "SuspiciousStartup",
                        Message = "发现可疑启动项",
                        Details = message
                    });
                    
                    // 弹窗警告
                    ShowThreatNotification("可疑启动项警告", message, NotificationType.Error);
                    RecordSuspiciousChange($"{keyPath}\\{name}", $"可疑特征: {suspicious}");
                    break;
                }
            }
        }
        
        private void CheckMalwarePatterns(string name, string value, string keyPath)
        {
            // 检测常见的恶意软件注册表模式
            if (value.Contains("schtasks") && value.Contains("/create") && value.Contains("/tn"))
            {
                HandleMalwarePattern(name, value, keyPath, "计划任务注入模式");
            }
            else if (value.Contains("reg add") && value.Contains("/f"))
            {
                HandleMalwarePattern(name, value, keyPath, "注册表强制添加模式");
            }
            else if (value.Contains("base64") && value.Contains("decode"))
            {
                HandleMalwarePattern(name, value, keyPath, "Base64编码隐藏模式");
            }
            else if (value.Contains("bitsadmin") && (value.Contains("/transfer") || value.Contains("/download")))
            {
                HandleMalwarePattern(name, value, keyPath, "BITS后台下载模式");
            }
        }
        
        private void CheckSecurityPolicyTampering(string keyPath, string valueName, string value)
        {
            var criticalPolicies = new[]
            {
                "NoDriveTypeAutoRun", "DisableCAD", "LegalNoticeCaption", "LegalNoticeText",
                "ShutdownWithoutLogon", "UndockWithoutLogon", "EnableLUA"
            };
            
            if (criticalPolicies.Contains(valueName))
            {
                string message = $"安全策略被修改\n策略: {valueName}\n新值: {value}\n位置: {keyPath}";
                
                dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "SecurityPolicyModified",
                    Message = "安全策略修改",
                    Details = message
                });
                
                if (valueName == "EnableLUA" && value == "0")
                {
                    ShowThreatNotification("高危: UAC被禁用", $"用户账户控制(UAC)被禁用\n这会降低系统安全性", NotificationType.Error);
                }
            }
        }
        
        private void HandleMalwarePattern(string name, string value, string keyPath, string patternType)
        {
            string message = $"检测到恶意软件模式\n名称: {name}\n值: {value}\n位置: {keyPath}\n模式类型: {patternType}";
            
            dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "MalwarePatternDetected",
                Message = $"恶意软件模式检测: {patternType}",
                Details = message
            });
            
            ShowThreatNotification("恶意软件行为检测", message, NotificationType.Error);
            RecordSuspiciousChange($"{keyPath}\\{name}", $"恶意软件模式: {patternType}");
        }
        
        private void RecordSuspiciousChange(string key, string description)
        {
            if (suspiciousChanges.ContainsKey(key))
            {
                suspiciousChanges[key].DetectionCount++;
                suspiciousChanges[key].DetectionTime = DateTime.Now;
            }
            else
            {
                suspiciousChanges[key] = new RegistryChangeInfo
                {
                    KeyPath = key,
                    Description = description,
                    DetectionCount = 1,
                    DetectionTime = DateTime.Now
                };
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

        public void ProtectRegistryKey(string keyPath, object level) { }
        public RegistryChangeResult CheckRegistryChange(string keyPath, string processName) { return new RegistryChangeResult { Allowed = true }; }
        public RegistryChangeAnalysisResult AnalyzeRegistryChange(RegistryChange change) { return new RegistryChangeAnalysisResult { IsMalicious = false, ShouldBlock = false }; }
    }
    
    public class RegistryKeyHash
    {
        public string KeyPath { get; set; }
        public string HashValue { get; set; }
        public DateTime LastModified { get; set; }
    }
    
    public class RegistryChangeInfo
    {
        public string KeyPath { get; set; }
        public string Description { get; set; }
        public int DetectionCount { get; set; }
        public DateTime DetectionTime { get; set; }
    }

    public class RegistryChangeResult
    {
        public bool Allowed { get; set; } = true;
        public string Reason { get; set; }
    }

    public class RegistryChangeAnalysisResult
    {
        public bool IsMalicious { get; set; }
        public bool ShouldBlock { get; set; }
    }

    public class RegistryChange
    {
        public string KeyPath { get; set; }
        public string ProcessName { get; set; }
        public RegistryChangeType ChangeType { get; set; }
        public string ValueName { get; set; }
    }

    public enum RegistryChangeType
    {
        CreateKey, DeleteKey, CreateValue, DeleteValue, ModifyValue
    }

    public enum RegistryProtectionLevel { Low, Medium, High }
}