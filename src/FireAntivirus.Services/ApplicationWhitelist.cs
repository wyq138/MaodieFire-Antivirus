using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Xml.Serialization;
using FireAntivirus.Data;
using FireAntivirus.Common.Notification;

namespace FireAntivirus.Services
{
    public class ApplicationWhitelist : IMonitor
    {
        #region .NET Authenticode Verification
        /// <summary>
        /// 使用 .NET API 验证文件数字签名
        /// </summary>
        
        #endregion
        private Thread _updateThread;
        private Thread _monitorThread;
        private bool _isRunning;
        private DataManager _dataManager;
        private WhitelistConfig _config;
        private HashSet<string> _whitelistedHashes;
        private HashSet<string> _whitelistedPaths;
        private HashSet<string> _whitelistedNames;
        private Dictionary<string, WhitelistEntry> _whitelistEntries;
        private Dictionary<string, int> _violationCounts;
        private bool _enforceWhitelist;
        private bool _logOnlyMode;
        private string _configFilePath;
        
        public ApplicationWhitelist(DataManager dataManager)
        {
            _dataManager = dataManager;
            _isRunning = false;
            _config = new WhitelistConfig();
            _whitelistedHashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _whitelistedPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _whitelistedNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _whitelistEntries = new Dictionary<string, WhitelistEntry>(StringComparer.OrdinalIgnoreCase);
            _violationCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            _enforceWhitelist = false;
            _logOnlyMode = true; // 默认只记录不阻止
            
            _configFilePath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "FireAntivirus", "whitelist.config");
            
            InitializeDefaultWhitelist();
            LoadConfiguration();
        }
        
        public void Start()
        {
            _isRunning = true;
            
            // 启动配置更新线程
            _updateThread = new Thread(UpdateThread);
            _updateThread.IsBackground = true;
            _updateThread.Start();
            
            // 启动监控线程
            _monitorThread = new Thread(MonitorThread);
            _monitorThread.IsBackground = true;
            _monitorThread.Start();
            
            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "WhitelistStart",
                Message = "应用白名单服务已启动",
                Details = $"白名单模式: {(_logOnlyMode ? "记录模式" : "强制模式")}, 白名单条目数: {_whitelistEntries.Count}"
            });
        }
        
        public void Stop()
        {
            _isRunning = false;
            _updateThread?.Join(2000);
            _monitorThread?.Join(2000);
            
            SaveConfiguration();
            
            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "WhitelistStop",
                Message = "应用白名单服务已停止",
                Details = string.Empty
            });
        }
        
        private void InitializeDefaultWhitelist()
        {
            // 操作系统核心进程
            AddSystemProcess("explorer.exe");
            AddSystemProcess("svchost.exe");
            AddSystemProcess("services.exe");
            AddSystemProcess("lsass.exe");
            AddSystemProcess("winlogon.exe");
            AddSystemProcess("csrss.exe");
            AddSystemProcess("wininit.exe");
            AddSystemProcess("smss.exe");
            
            // 常见浏览器进程
            AddTrustedApplication("chrome.exe", @"C:\Program Files\Google\Chrome\Application\");
            AddTrustedApplication("msedge.exe", @"C:\Program Files (x86)\Microsoft\Edge\Application\");
            AddTrustedApplication("firefox.exe", @"C:\Program Files\Mozilla Firefox\");
            
            // 办公软件
            AddTrustedApplication("winword.exe", @"C:\Program Files\Microsoft Office\root\Office16\");
            AddTrustedApplication("excel.exe", @"C:\Program Files\Microsoft Office\root\Office16\");
            AddTrustedApplication("powerpnt.exe", @"C:\Program Files\Microsoft Office\root\Office16\");
            
            // 开发工具
            AddTrustedApplication("devenv.exe", @"C:\Program Files\Microsoft Visual Studio\");
            AddTrustedApplication("Code.exe", @"C:\Users\{0}\AppData\Local\Programs\Microsoft VS Code\");
        }
        
        private void AddSystemProcess(string processName)
        {
            _whitelistedNames.Add(processName);
            var entry = new WhitelistEntry
            {
                Name = processName,
                Type = WhitelistType.SystemProcess,
                TrustLevel = TrustLevel.Trusted,
                AddedDate = DateTime.Now,
                Description = "Windows系统核心进程"
            };
            _whitelistEntries[processName] = entry;
        }
        
        private void AddTrustedApplication(string processName, string expectedPathPattern)
        {
            _whitelistedNames.Add(processName);
            _whitelistedPaths.Add(expectedPathPattern);
            
            var entry = new WhitelistEntry
            {
                Name = processName,
                Type = WhitelistType.TrustedApplication,
                TrustLevel = TrustLevel.User,
                AddedDate = DateTime.Now,
                Description = $"可信应用程序: {processName}",
                ExpectedPath = expectedPathPattern
            };
            _whitelistEntries[processName] = entry;
        }
        
        private void UpdateThread()
        {
            while (_isRunning)
            {
                try
                {
                    UpdateWhitelistFromDatabase();
                    CleanupViolationCounts();
                    
                    Thread.Sleep(300000); // 5分钟更新一次
                }
                catch (Exception ex)
                {
                    LogError("更新线程错误", ex);
                    Thread.Sleep(60000);
                }
            }
        }
        
        private void MonitorThread()
        {
            while (_isRunning)
            {
                try
                {
                    ScanRunningProcesses();
                    Thread.Sleep(10000); // 10秒扫描一次
                }
                catch (Exception ex)
                {
                    LogError("监控线程错误", ex);
                    Thread.Sleep(30000);
                }
            }
        }
        
        private void ScanRunningProcesses()
        {
            var processes = System.Diagnostics.Process.GetProcesses();
            
            foreach (var process in processes)
            {
                try
                {
                    if (process.HasExited)
                        continue;
                    
                    // 跳过系统进程和本程序
                    if (process.Id == 0 || process.Id == System.Diagnostics.Process.GetCurrentProcess().Id)
                        continue;
                    
                    CheckProcess(process);
                }
                catch
                {
                    // 忽略无法访问的进程
                }
            }
        }
        
        private void CheckProcess(System.Diagnostics.Process process)
        {
            var processInfo = GetProcessInfo(process);
            
            if (IsWhitelisted(processInfo))
            {
                return; // 在白名单中，安全
            }
            
            HandleNonWhitelistedProcess(processInfo);
        }
        
        private ProcessInfo GetProcessInfo(System.Diagnostics.Process process)
        {
            var info = new ProcessInfo
            {
                ProcessId = process.Id,
                ProcessName = process.ProcessName,
                FilePath = GetProcessFilePath(process),
                ParentProcessId = GetParentProcessId(process.Id),
                StartTime = process.StartTime,
                CommandLine = GetProcessCommandLine(process.Id)
            };
            
            // 计算文件哈希
            if (!string.IsNullOrEmpty(info.FilePath) && File.Exists(info.FilePath))
            {
                info.FileHash = CalculateFileHash(info.FilePath);
                info.FileSize = new FileInfo(info.FilePath).Length;
                // 移除系统签名验证
                info.DigitalSignature = false;
            }
            
            return info;
        }
        
        private string GetProcessFilePath(System.Diagnostics.Process process)
        {
            try
            {
                return process.MainModule?.FileName;
            }
            catch
            {
                return GetProcessPathFromWMI(process.Id);
            }
        }
        
        private string GetProcessPathFromWMI(int processId)
        {
            try
            {
                using (var searcher = new System.Management.ManagementObjectSearcher(
                    $"SELECT ExecutablePath FROM Win32_Process WHERE ProcessId = {processId}"))
                {
                    foreach (System.Management.ManagementObject obj in searcher.Get())
                    {
                        return obj["ExecutablePath"]?.ToString();
                    }
                }
            }
            catch { }
            
            return null;
        }
        
        private int GetParentProcessId(int processId)
        {
            try
            {
                using (var searcher = new System.Management.ManagementObjectSearcher(
                    $"SELECT ParentProcessId FROM Win32_Process WHERE ProcessId = {processId}"))
                {
                    foreach (System.Management.ManagementObject obj in searcher.Get())
                    {
                        return Convert.ToInt32(obj["ParentProcessId"]);
                    }
                }
            }
            catch { }
            
            return 0;
        }
        
        private string GetProcessCommandLine(int processId)
        {
            try
            {
                using (var searcher = new System.Management.ManagementObjectSearcher(
                    $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {processId}"))
                {
                    foreach (System.Management.ManagementObject obj in searcher.Get())
                    {
                        return obj["CommandLine"]?.ToString();
                    }
                }
            }
            catch { }
            
            return null;
        }
        
        private string CalculateFileHash(string filePath)
        {
            try
            {
                using (var sha256 = SHA256.Create())
                using (var stream = File.OpenRead(filePath))
                {
                    var hash = sha256.ComputeHash(stream);
                    return BitConverter.ToString(hash).Replace("-", "").ToLower();
                }
            }
            catch
            {
                return null;
            }
        }
        
        
        
        private bool IsWhitelisted(ProcessInfo processInfo)
        {
            // 检查进程名白名单
            if (_whitelistedNames.Contains(processInfo.ProcessName))
            {
                return true;
            }
            
            // 检查路径白名单
            if (!string.IsNullOrEmpty(processInfo.FilePath) && 
                _whitelistedPaths.Any(path => processInfo.FilePath.StartsWith(path, StringComparison.OrdinalIgnoreCase)))
            {
                return true;
            }
            
            // 检查哈希白名单
            if (!string.IsNullOrEmpty(processInfo.FileHash) && 
                _whitelistedHashes.Contains(processInfo.FileHash))
            {
                return true;
            }
            
            // 检查数字签名
            if (processInfo.DigitalSignature)
            {
                return true; // 有数字签名的可执行文件自动信任
            }
            
            return false;
        }
        
        private void HandleNonWhitelistedProcess(ProcessInfo processInfo)
        {
            var fileHash = processInfo.FileHash ?? "unknown";
            var violationKey = $"{processInfo.ProcessName}_{fileHash}";
            
            // 更新违规计数
            if (!_violationCounts.ContainsKey(violationKey))
            {
                _violationCounts[violationKey] = 0;
            }
            _violationCounts[violationKey]++;
            
            var violationCount = _violationCounts[violationKey];
            var severity = GetViolationSeverity(processInfo, violationCount);
            
            // 记录违规
            LogViolation(processInfo, violationCount, severity);
            
            // 根据严重程度决定是否阻止
            if (ShouldBlockProcess(processInfo, severity))
            {
                HandleBlockProcess(processInfo);
            }
            else if (severity == ViolationSeverity.High)
            {
                // 高严重度警告
                ShowWarning(processInfo);
            }
        }
        
        private ViolationSeverity GetViolationSeverity(ProcessInfo processInfo, int violationCount)
        {
            // 基于多个因素计算严重程度
            int score = 0;
            
            // 进程特征
            if (processInfo.ProcessName.ToLower().Contains("temp")) score += 2;
            if (processInfo.FilePath?.ToLower().Contains("temp") == true) score += 3;
            if (processInfo.FilePath?.ToLower().Contains("download") == true) score += 2;
            
            // 系统相关
            if (processInfo.ParentProcessId == 0) score += 1; // 孤儿进程
            if (processInfo.CommandLine?.Contains("-enc") == true) score += 4; // 编码命令
            if (processInfo.CommandLine?.Contains("bypass") == true) score += 3; // 绕过执行策略
            
            // 数字签名状态
            if (!processInfo.DigitalSignature) score += 2;
            
            // 违规频率
            if (violationCount > 5) score += 2;
            if (violationCount > 10) score += 3;
            
            if (score >= 8) return ViolationSeverity.Critical;
            if (score >= 5) return ViolationSeverity.High;
            if (score >= 3) return ViolationSeverity.Medium;
            return ViolationSeverity.Low;
        }
        
        private bool ShouldBlockProcess(ProcessInfo processInfo, ViolationSeverity severity)
        {
            if (_logOnlyMode)
                return false;
                
            return severity == ViolationSeverity.Critical || 
                   (severity == ViolationSeverity.High && _enforceWhitelist);
        }
        
        private void HandleBlockProcess(ProcessInfo processInfo)
        {
            try
            {
                var process = System.Diagnostics.Process.GetProcessById(processInfo.ProcessId);
                process.Kill();
                
                LogBlockAction(processInfo);
                
                // 通知用户
                NotificationService.Instance.ShowNotification(
                    "阻止非白名单进程",
                    $"已阻止进程: {processInfo.ProcessName}\n原因: 未在白名单中",
                    NotificationType.Warning);
            }
            catch (Exception ex)
            {
                LogError($"阻止进程失败: {processInfo.ProcessName}", ex);
            }
        }
        
        private void ShowWarning(ProcessInfo processInfo)
        {
            NotificationService.Instance.ShowNotification(
                "警告: 可疑进程",
                $"检测到可疑进程: {processInfo.ProcessName}\n建议添加到白名单或终止",
                NotificationType.Warning);
        }
        
        private void LogViolation(ProcessInfo processInfo, int violationCount, ViolationSeverity severity)
        {
            var filePath = processInfo.FilePath ?? "未知";
            var message = $"非白名单进程检测\n进程: {processInfo.ProcessName}\n路径: {filePath}\n严重程度: {severity}\n违规次数: {violationCount}";
            
            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "WhitelistViolation",
                Message = $"白名单违规: {processInfo.ProcessName}",
                Details = message,
                Severity = GetLogSeverity(severity).ToString()
            });
        }
        
        private void LogBlockAction(ProcessInfo processInfo)
        {
            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "ProcessBlocked",
                Message = $"阻止进程: {processInfo.ProcessName}",
                Details = $"PID: {processInfo.ProcessId}, 路径: {processInfo.FilePath}",
                Severity = LogSeverity.High.ToString()
            });
        }
        
        private void LogError(string message, Exception ex)
        {
            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "WhitelistError",
                Message = message,
                Details = ex.Message,
                Severity = LogSeverity.Medium.ToString()
            });
        }
        
        private LogSeverity GetLogSeverity(ViolationSeverity severity)
        {
            return severity switch
            {
                ViolationSeverity.Critical => LogSeverity.Critical,
                ViolationSeverity.High => LogSeverity.High,
                ViolationSeverity.Medium => LogSeverity.Medium,
                _ => LogSeverity.Low
            };
        }
        
        private void UpdateWhitelistFromDatabase()
        {
            try
            {
                // 从数据库或配置文件中加载更新的白名单
                var newEntries = _dataManager.GetWhitelistEntries();
                
                foreach (var entry in newEntries)
                {
                    if (!_whitelistEntries.ContainsKey(entry.Name))
                    {
                        var whitelistEntry = new WhitelistEntry
                        {
                            Name = entry.Name,
                            Type = entry.Type == "HashBased" ? WhitelistType.HashBased :
                                   entry.Type == "PathBased" ? WhitelistType.PathBased :
                                   entry.Type == "NameBased" ? WhitelistType.NameBased :
                                   entry.Type == "SystemProcess" ? WhitelistType.SystemProcess :
                                   WhitelistType.TrustedApplication,
                            HashValue = entry.HashValue,
                            ExpectedPath = entry.ExpectedPath,
                            Description = entry.Description,
                            AddedDate = entry.AddTime
                        };
                        _whitelistEntries[entry.Name] = whitelistEntry;
                        
                        switch (entry.Type)
                        {
                            case "HashBased":
                                _whitelistedHashes.Add(entry.HashValue);
                                break;
                            case "PathBased":
                                _whitelistedPaths.Add(entry.ExpectedPath);
                                break;
                            case "NameBased":
                                _whitelistedNames.Add(entry.Name);
                                break;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                LogError("更新白名单失败", ex);
            }
        }
        
        private void CleanupViolationCounts()
        {
            // 清理过期的违规计数
            var expiredKeys = _violationCounts
                .Where(kv => kv.Value > 0 && DateTime.Now.Hour == 0) // 每天凌晨清理
                .Select(kv => kv.Key)
                .ToList();
                
            foreach (var key in expiredKeys)
            {
                _violationCounts.Remove(key);
            }
        }
        
        private void LoadConfiguration()
        {
            try
            {
                if (File.Exists(_configFilePath))
                {
                    var serializer = new XmlSerializer(typeof(WhitelistConfig));
                    using (var reader = new StreamReader(_configFilePath))
                    {
                        _config = (WhitelistConfig)serializer.Deserialize(reader);
                        _enforceWhitelist = _config.EnforceWhitelist;
                        _logOnlyMode = _config.LogOnlyMode;
                    }
                }
            }
            catch (Exception ex)
            {
                LogError("加载配置失败", ex);
            }
        }
        
        private void SaveConfiguration()
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(_configFilePath));
                
                var serializer = new XmlSerializer(typeof(WhitelistConfig));
                using (var writer = new StreamWriter(_configFilePath))
                {
                    serializer.Serialize(writer, _config);
                }
            }
            catch (Exception ex)
            {
                LogError("保存配置失败", ex);
            }
        }
        
        #region Public API
        
        public void AddToWhitelist(string processName, string filePath, WhitelistType type)
        {
            var entry = new WhitelistEntry
            {
                Name = processName,
                Type = type,
                TrustLevel = TrustLevel.Low,
                AddedDate = DateTime.Now,
                ExpectedPath = filePath
            };
            
            if (type == WhitelistType.HashBased && File.Exists(filePath))
            {
                entry.HashValue = CalculateFileHash(filePath);
                _whitelistedHashes.Add(entry.HashValue);
            }
            else if (type == WhitelistType.PathBased)
            {
                _whitelistedPaths.Add(filePath);
            }
            else if (type == WhitelistType.NameBased)
            {
                _whitelistedNames.Add(processName);
            }
            
            _whitelistEntries[processName] = entry;
            
            // 保存配置
            SaveConfiguration();
        }
        
        public void RemoveFromWhitelist(string processName)
        {
            if (_whitelistEntries.TryGetValue(processName, out var entry))
            {
                _whitelistEntries.Remove(processName);
                
                switch (entry.Type)
                {
                    case WhitelistType.HashBased:
                        _whitelistedHashes.Remove(entry.HashValue);
                        break;
                    case WhitelistType.PathBased:
                        _whitelistedPaths.Remove(entry.ExpectedPath);
                        break;
                    case WhitelistType.NameBased:
                        _whitelistedNames.Remove(entry.Name);
                        break;
                }
                
                SaveConfiguration();
            }
        }
        
        public void SetEnforcementMode(bool enforce)
        {
            _enforceWhitelist = enforce;
            _logOnlyMode = !enforce;
            _config.EnforceWhitelist = enforce;
            _config.LogOnlyMode = !enforce;
            SaveConfiguration();
        }
        
        public List<WhitelistEntry> GetWhitelistEntries() => _whitelistEntries.Values.ToList();
        public Dictionary<string, int> GetViolationStats() => _violationCounts;
        public bool IsEnforcementEnabled() => _enforceWhitelist;
        
        #endregion
    }
    
    public class WhitelistConfig
    {
        public bool EnforceWhitelist { get; set; }
        public bool LogOnlyMode { get; set; } = true;
        public bool AutoAddTrustedApps { get; set; } = true;
        public bool CheckDigitalSignatures { get; set; } = true;
    }
    
    public class WhitelistEntry
    {
        public string Name { get; set; }
        public WhitelistType Type { get; set; }
        public TrustLevel TrustLevel { get; set; }
        public string Description { get; set; }
        public string ExpectedPath { get; set; }
        public string HashValue { get; set; }
        public DateTime AddedDate { get; set; }
        public DateTime LastUsed { get; set; }
    }
    
    public enum WhitelistType
    {
        SystemProcess,
        TrustedApplication,
        HashBased,
        PathBased,
        NameBased
    }
    
    public enum TrustLevel
    {
        Unknown = 0,
        Suspicious = 1,
        Low = 2,
        Medium = 3,
        High = 4,
        User = 5,
        Trusted = 6,
        System = 7,
        Blocked = -1
    }
    
    public enum ViolationSeverity
    {
        Low,      // 临时文件中的可执行文件
        Medium,   // 常见名称，可疑位置
        High,     // 编码命令，绕过策略
        Critical  // 关键系统进程冒充
    }
    
    public enum LogSeverity
    {
        Low,
        Medium,
        High,
        Critical
    }
}
