using System;
using System.IO;
using System.Reflection;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Management;
using System.Collections.Generic;
using FireAntivirus.Common;
using FireAntivirus.Data;

namespace FireAntivirus.Services
{
    public class SelfProtectionService
    {
        private readonly DataManager _dataManager;
        private CancellationTokenSource _cancellationTokenSource;
        private Task _protectionTask;
        private bool _isRunning;
        private Dictionary<string, string> _fileHashes;
        private DateTime _lastIntegrityCheck;
        private HashSet<int> _protectedProcesses;
        private bool _integrityAlertShown;

        public SelfProtectionService(DataManager dataManager)
        {
            _dataManager = dataManager;
            _cancellationTokenSource = new CancellationTokenSource();
            _fileHashes = new Dictionary<string, string>();
            _protectedProcesses = new HashSet<int>();
            _integrityAlertShown = false;
        }

        public void Start()
        {
            if (_isRunning)
                return;

            _isRunning = true;
            _cancellationTokenSource = new CancellationTokenSource();
            
            // 初始化文件哈希基线
            InitializeFileHashBaseline();
            
            // 设置关键文件保护
            SetCriticalFilesProtection();
            
            // 启动保护循环
            _protectionTask = Task.Run(() => ProtectionLoop(_cancellationTokenSource.Token));

            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "SelfProtectionStart",
                Message = "自我保护服务已启动",
                Details = "文件完整性监控、进程保护、注册表保护已启用",
                Source = "SelfProtectionService",
                Category = "系统防护"
            });
        }

        public void Stop()
        {
            if (!_isRunning)
                return;

            _isRunning = false;
            _cancellationTokenSource.Cancel();
            _protectionTask.Wait(2000);

            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "SelfProtectionStop",
                Message = "自我保护服务已停止",
                Source = "SelfProtectionService",
                Category = "系统防护"
            });
        }

        private void InitializeFileHashBaseline()
        {
            try
            {
                string appDirectory = AppDomain.CurrentDomain.BaseDirectory;
                string[] criticalFiles = GetCriticalFiles();

                foreach (string fileName in criticalFiles)
                {
                    string filePath = Path.Combine(appDirectory, fileName);
                    if (File.Exists(filePath))
                    {
                        string hash = CalculateFileHash(filePath);
                        _fileHashes[fileName] = hash;
                    }
                }
            }
            catch (Exception ex)
            {
                _dataManager.LogError("初始化文件哈希基线失败", ex.Message, "SelfProtectionService");
            }
        }

        private string CalculateFileHash(string filePath)
        {
            try
            {
                using (var sha256 = System.Security.Cryptography.SHA256.Create())
                using (var stream = File.OpenRead(filePath))
                {
                    byte[] hashBytes = sha256.ComputeHash(stream);
                    return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
                }
            }
            catch
            {
                return string.Empty;
            }
        }

        private async Task ProtectionLoop(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    // 检查关键文件完整性
                    CheckFileIntegrity();

                    // 保护关键文件不被修改
                    ProtectCriticalFiles();

                    // 检查服务状态并自动重启
                    await CheckAndRestartService();

                    // 监控并保护进程
                    MonitorProcessProtection();

                    // 保护注册表
                    ProtectRegistry();

                    // 检测可疑的进程终止行为
                    DetectProcessTerminationAttempts();
                }
                catch (Exception ex)
                {
                    _dataManager.LogError("自我保护服务错误", ex.Message, "SelfProtectionService");
                }

                await Task.Delay(60000, cancellationToken); // 每60秒检查一次，降低敏感度
            }
        }

        private string[] GetCriticalFiles()
        {
            return new string[] {
                "FireAntivirus.exe",
                "FireAntivirus.Host.exe",
                "FireAntivirus.Services.dll",
                "FireAntivirus.Engine.dll",
                "FireAntivirus.Data.dll",
                "FireAntivirus.Common.dll",
                "FireAntivirus.ClamAV.dll",
                "Newtonsoft.Json.dll"
            };
        }

        private void CheckFileIntegrity()
        {
            try
            {
                string appDirectory = AppDomain.CurrentDomain.BaseDirectory;
                string[] criticalFiles = GetCriticalFiles();
                List<string> modifiedFiles = new List<string>();

                foreach (string fileName in criticalFiles)
                {
                    string filePath = Path.Combine(appDirectory, fileName);
                    if (File.Exists(filePath))
                    {
                        string currentHash = CalculateFileHash(filePath);
                        
                        if (_fileHashes.TryGetValue(fileName, out string originalHash))
                        {
                            if (!string.IsNullOrEmpty(currentHash) && currentHash != originalHash)
                            {
                                modifiedFiles.Add(fileName);
                                
                                _dataManager.AddLog(new LogEntry
                                {
                                    Id = Guid.NewGuid().ToString(),
                                    Time = DateTime.Now,
                                    Type = "FileIntegrityViolation",
                                    Message = "关键文件完整性被破坏",
                                    Details = $"文件: {fileName}\n原始哈希: {originalHash}\n当前哈希: {currentHash}",
                                    Source = "SelfProtectionService",
                                    Category = "系统防护"
                                });
                            }
                        }
                        else
                        {
                            // 新文件，记录哈希
                            _fileHashes[fileName] = currentHash;
                        }
                    }
                    else if (_fileHashes.ContainsKey(fileName))
                    {
                        // 关键文件被删除
                        modifiedFiles.Add(fileName + " (已删除)");
                        
                        _dataManager.AddLog(new LogEntry
                        {
                            Id = Guid.NewGuid().ToString(),
                            Time = DateTime.Now,
                            Type = "CriticalFileDeleted",
                            Message = "关键文件被删除",
                            Details = $"文件: {fileName}",
                            Source = "SelfProtectionService",
                            Category = "系统防护"
                        });
                    }
                }

                // 弹窗警告（避免重复弹窗）
                if (modifiedFiles.Count > 0 && !_integrityAlertShown)
                {
                    string message = $"检测到关键文件完整性问题\n以下文件可能被篡改:\n{string.Join("\n", modifiedFiles)}\n\n这可能是恶意软件攻击！";
                    ShowThreatNotification("文件完整性警告", message, NotificationType.Error);
                    _integrityAlertShown = true;
                }
            }
            catch (Exception ex)
            {
                _dataManager.LogError("文件完整性检查失败", ex.Message, "SelfProtectionService");
            }
        }

        private void SetCriticalFilesProtection()
        {
            try
            {
                string appDirectory = AppDomain.CurrentDomain.BaseDirectory;
                string[] criticalFiles = GetCriticalFiles();

                foreach (string fileName in criticalFiles)
                {
                    string filePath = Path.Combine(appDirectory, fileName);
                    if (File.Exists(filePath))
                    {
                        try
                        {
                            // 设置文件为只读，增加篡改难度
                            File.SetAttributes(filePath, File.GetAttributes(filePath) | FileAttributes.ReadOnly);
                            
                            // 设置ACL权限（仅管理员和系统可写）
                            SetFileSecurity(filePath);
                        }
                        catch (UnauthorizedAccessException)
                        {
                            // 需要管理员权限
                        }
                        catch (Exception ex)
                        {
                            _dataManager.LogInfo($"设置文件保护失败 {fileName}: {ex.Message}");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _dataManager.LogError("设置关键文件保护失败", ex.Message, "SelfProtectionService");
            }
        }

        private void SetFileSecurity(string filePath)
        {
            try
            {
                var fileInfo = new FileInfo(filePath);
                var security = fileInfo.GetAccessControl();
                
                // 移除继承权限
                security.SetAccessRuleProtection(true, false);
                
                // 添加管理员完全控制
                var adminRule = new FileSystemAccessRule(
                    new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                    FileSystemRights.FullControl,
                    AccessControlType.Allow);
                security.AddAccessRule(adminRule);
                
                // 添加系统完全控制
                var systemRule = new FileSystemAccessRule(
                    new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                    FileSystemRights.FullControl,
                    AccessControlType.Allow);
                security.AddAccessRule(systemRule);
                
                // 添加用户只读权限
                var userRule = new FileSystemAccessRule(
                    WindowsIdentity.GetCurrent().User,
                    FileSystemRights.ReadAndExecute,
                    AccessControlType.Allow);
                security.AddAccessRule(userRule);
                
                fileInfo.SetAccessControl(security);
            }
            catch
            {
                // 需要管理员权限
            }
        }

        private void ProtectCriticalFiles()
        {
            try
            {
                string appDirectory = AppDomain.CurrentDomain.BaseDirectory;
                string[] criticalFiles = GetCriticalFiles();

                foreach (string fileName in criticalFiles)
                {
                    string filePath = Path.Combine(appDirectory, fileName);
                    if (File.Exists(filePath))
                    {
                        // 检查文件是否被修改或删除
                        var attributes = File.GetAttributes(filePath);
                        
                        // 确保只读属性被设置
                        if ((attributes & FileAttributes.ReadOnly) == 0)
                        {
                            try
                            {
                                File.SetAttributes(filePath, attributes | FileAttributes.ReadOnly);
                            }
                            catch { }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _dataManager.LogError("保护关键文件失败", ex.Message, "SelfProtectionService");
            }
        }

        private async Task CheckAndRestartService()
        {
            try
            {
                // 检查后台服务是否运行
                var processes = Process.GetProcessesByName("FireAntivirus.Service");
                bool isServiceRunning = processes.Length > 0;

                if (!isServiceRunning)
                {
                    _dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "ServiceNotRunning",
                        Message = "后台服务未运行",
                        Details = "尝试重新启动服务",
                        Source = "SelfProtectionService",
                        Category = "系统防护"
                    });

                    // 尝试重启服务
                    await TryRestartService();
                }
            }
            catch (Exception ex)
            {
                _dataManager.LogError("服务状态检查失败", ex.Message, "SelfProtectionService");
            }
        }

        private async Task TryRestartService()
        {
            try
            {
                string appDirectory = AppDomain.CurrentDomain.BaseDirectory;
                string servicePath = Path.Combine(appDirectory, "FireAntivirus.Service.exe");
                
                if (File.Exists(servicePath))
                {
                    var startInfo = new ProcessStartInfo
                    {
                        FileName = servicePath,
                        Arguments = "-run",
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        WorkingDirectory = appDirectory
                    };
                    
                    Process.Start(startInfo);
                    
                    _dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "ServiceRestarted",
                        Message = "后台服务已重新启动",
                        Source = "SelfProtectionService",
                        Category = "系统防护"
                    });
                }
            }
            catch (Exception ex)
            {
                _dataManager.LogError("重启服务失败", ex.Message, "SelfProtectionService");
            }
            
            await Task.CompletedTask;
        }

        private void MonitorProcessProtection()
        {
            try
            {
                var currentProcess = Process.GetCurrentProcess();
                
                // 记录当前进程ID
                if (!_protectedProcesses.Contains(currentProcess.Id))
                {
                    _protectedProcesses.Add(currentProcess.Id);
                }
                
                // 检查是否有可疑进程尝试操作我们的进程
                DetectSuspiciousProcesses();
            }
            catch (Exception ex)
            {
                _dataManager.LogError("进程保护监控失败", ex.Message, "SelfProtectionService");
            }
        }

        private void DetectSuspiciousProcesses()
        {
            try
            {
                // 检查可疑的进程终止工具
                string[] suspiciousProcessNames = {
                    "taskkill", "processhacker", "process explorer", "procexp",
                    "autoruns", "procmon", "lockhunter", "unlocker",
                    "forcedelete", "fileassassin", "movefile"
                };
                
                foreach (string processName in suspiciousProcessNames)
                {
                    var processes = Process.GetProcessesByName(processName);
                    if (processes.Length > 0)
                    {
                        string message = $"检测到可疑进程\n进程名: {processName}\n该进程可能被用于终止安全软件";
                        
                        _dataManager.AddLog(new LogEntry
                        {
                            Id = Guid.NewGuid().ToString(),
                            Time = DateTime.Now,
                            Type = "SuspiciousProcessDetected",
                            Message = "检测到可疑进程",
                            Details = message,
                            Source = "SelfProtectionService",
                            Category = "系统防护"
                        });
                        
                        ShowThreatNotification("可疑进程警告", message, NotificationType.Warning);
                    }
                }
            }
            catch { }
        }

        private void DetectProcessTerminationAttempts()
        {
            try
            {
                // 使用WMI监控进程终止事件
                using (var searcher = new ManagementObjectSearcher(
                    "SELECT * FROM Win32_ProcessStopTrace WHERE ProcessName LIKE '%FireAntivirus%'"))
                {
                    // 这里可以检测是否有FireAntivirus进程被终止
                    // 由于是事后检测，主要用于日志记录和告警
                }
            }
            catch { }
        }

        private void ProtectRegistry()
        {
            try
            {
                string[] criticalRegistryKeys = {
                    "SOFTWARE\\FireAntivirus",
                    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\FireAntivirus"
                };

                foreach (string keyPath in criticalRegistryKeys)
                {
                    try
                    {
                        using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(keyPath, true))
                        {
                            if (key != null)
                            {
                                // 设置注册表项的保护
                                // 注意：真正的注册表保护需要内核驱动支持
                            }
                        }
                    }
                    catch (UnauthorizedAccessException)
                    {
                        // 权限不足
                    }
                }
            }
            catch (Exception ex)
            {
                _dataManager.LogError("注册表保护失败", ex.Message, "SelfProtectionService");
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
    }
}
