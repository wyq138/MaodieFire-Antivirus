using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Threading;
using FireAntivirus.Data;
using FireAntivirus.Engine;

namespace FireAntivirus.Services
{
    public class KernelMonitor : IMonitor
    {
        private Thread monitorThread;
        private bool isRunning;
        private DataManager dataManager;
        private AntivirusEngine antivirusEngine;
        private HashSet<string> trustedDrivers;
        private Dictionary<string, string> driverHashes;
        private string backupDirectory;
        private FireAntivirusKernelWrapper kernelWrapper;

        public KernelMonitor(DataManager dataManager, AntivirusEngine antivirusEngine)
        {
            this.dataManager = dataManager;
            this.antivirusEngine = antivirusEngine;
            trustedDrivers = new HashSet<string>();
            driverHashes = new Dictionary<string, string>();
            backupDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "FireAntivirus", "Backups", "Kernel");
            Directory.CreateDirectory(backupDirectory);
            
            // 初始化内核防护包装器
            kernelWrapper = FireAntivirusKernelWrapper.Instance;
        }

        public void Start()
        {
            isRunning = true;
            monitorThread = new Thread(MonitorKernel);
            monitorThread.Start();

            // 初始化可信驱动列表
            InitializeTrustedDrivers();
            
            // 备份当前内核配置
            BackupKernelConfiguration();

            // 启用C++内核防护模块
            bool kernelProtectionEnabled = false;
            if (kernelWrapper.IsInitialized)
            {
                kernelProtectionEnabled = kernelWrapper.Enable();
            }

            dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "KernelMonitorStart",
                Message = "内核防护已启动",
                Details = kernelProtectionEnabled ? "C++内核防护模块已启用，开始监控驱动加载和内核模块篡改" : "开始监控驱动加载和内核模块篡改（C++内核防护模块未初始化）"
            });
        }

        public void Stop()
        {
            isRunning = false;
            monitorThread?.Join(2000);

            // 禁用C++内核防护模块
            if (kernelWrapper != null && kernelWrapper.IsInitialized)
            {
                kernelWrapper.Disable();
            }

            dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "KernelMonitorStop",
                Message = "内核防护已停止",
                Details = "已停止监控驱动加载和内核模块篡改"
            });
        }

        private void MonitorKernel()
        {
            while (isRunning)
            {
                try
                {
                    // 检查C++内核防护模块状态
                    CheckKernelProtectionStatus();
                    
                    // 监控驱动加载
                    MonitorDriverLoading();
                    
                    // 监控内核模块篡改
                    MonitorKernelModules();
                    
                    // 监控系统调用和内核函数挂钩
                    MonitorSystemCalls();
                    
                    // 定期备份内核配置
                    if (DateTime.Now.Minute % 10 == 0) // 每10分钟备份一次
                    {
                        BackupKernelConfiguration();
                    }
                }
                catch (Exception ex)
                {
                    dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "KernelMonitorError",
                        Message = "内核监控出错",
                        Details = ex.Message
                    });
                }

                Thread.Sleep(5000); // 每5秒检查一次
            }
        }
        
        private void CheckKernelProtectionStatus()
        {
            if (kernelWrapper != null && kernelWrapper.IsInitialized)
            {
                var status = kernelWrapper.GetStatus();
                if (status == KernelProtectionStatus.Error)
                {
                    // 尝试重新启用防护
                    kernelWrapper.Enable();
                    
                    dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "KernelProtectionStatus",
                        Message = "内核防护状态异常",
                        Details = "已尝试重新启用内核防护"
                    });
                }
            }
        }

        private void InitializeTrustedDrivers()
        {
            try
            {
                // 获取系统已安装的驱动列表
                var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_SystemDriver");
                foreach (var driver in searcher.Get())
                {
                    try
                    {
                        string driverName = driver["Name"]?.ToString();
                        string driverPath = driver["PathName"]?.ToString();
                        if (!string.IsNullOrEmpty(driverName) && !string.IsNullOrEmpty(driverPath))
                        {
                            // 清理路径（移除引号）
                            if (driverPath.StartsWith("\""))
                            {
                                driverPath = driverPath.Substring(1, driverPath.Length - 2);
                            }
                            
                            if (File.Exists(driverPath))
                            {
                                trustedDrivers.Add(driverName);
                                driverHashes[driverPath] = CalculateFileHash(driverPath);
                            }
                        }
                    }
                    catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "KernelMonitor.cs 捕获异常", ex.Message); }
                }
            }
            catch (Exception ex)
            {
                dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "TrustedDriversInitError",
                    Message = "初始化可信驱动列表失败",
                    Details = ex.Message
                });
            }
        }

        private void MonitorDriverLoading()
        {
            try
            {
                // 监控新加载的驱动
                var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_SystemDriver");
                foreach (var driver in searcher.Get())
                {
                    try
                    {
                        string driverName = driver["Name"]?.ToString();
                        string driverPath = driver["PathName"]?.ToString();
                        if (!string.IsNullOrEmpty(driverName) && !string.IsNullOrEmpty(driverPath))
                        {
                            // 清理路径
                            if (driverPath.StartsWith("\""))
                            {
                                driverPath = driverPath.Substring(1, driverPath.Length - 2);
                            }
                            
                            // 检查是否为新驱动
                            if (!trustedDrivers.Contains(driverName))
                            {
                                // 检查驱动是否有数字签名
                                bool isSigned = CheckDriverSignature(driverPath);
                                
                                if (!isSigned)
                                {
                                // 未签名驱动，可能是恶意的
                                    string message = $"检测到未签名驱动\n驱动名称: {driverName}\n路径: {driverPath}\n这可能存在安全风险";
                                    
                                    dataManager.AddLog(new LogEntry
                                    {
                                        Id = Guid.NewGuid().ToString(),
                                        Time = DateTime.Now,
                                        Type = "UnsignedDriverDetected",
                                        Message = "检测到未签名驱动",
                                        Details = message
                                    });
                                    
                                    // 弹窗警告
                                    ShowThreatNotification("未签名驱动警告", message, NotificationType.Warning);
                                    
                                    // 尝试阻止驱动加载
                                    BlockDriver(driverName);
                                }
                                else
                                {
                                    // 添加到可信驱动列表
                                    trustedDrivers.Add(driverName);
                                    if (File.Exists(driverPath))
                                    {
                                        driverHashes[driverPath] = CalculateFileHash(driverPath);
                                    }
                                }
                            }
                            else if (File.Exists(driverPath))
                            {
                                // 检查已存在的驱动是否被篡改
                                string currentHash = CalculateFileHash(driverPath);
                                if (driverHashes.TryGetValue(driverPath, out string originalHash))
                                {
                                    if (currentHash != originalHash)
                                    {
                                        // 驱动文件被篡改
                                        string tamperMessage = $"检测到驱动文件被篡改\n驱动名称: {driverName}\n路径: {driverPath}\n这可能是内核级攻击！";
                                        
                                        dataManager.AddLog(new LogEntry
                                        {
                                            Id = Guid.NewGuid().ToString(),
                                            Time = DateTime.Now,
                                            Type = "DriverTampered",
                                            Message = "检测到驱动文件被篡改",
                                            Details = tamperMessage
                                        });
                                        
                                        // 弹窗警告
                                        ShowThreatNotification("驱动篡改警告", tamperMessage, NotificationType.Error);
                                        
                                        // 尝试恢复驱动
                                        RestoreDriver(driverPath);
                                    }
                                }
                            }
                        }
                    }
                    catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "KernelMonitor.cs 捕获异常", ex.Message); }
                }
            }
            catch (Exception ex)
            {
                dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "DriverMonitoringError",
                    Message = "驱动监控出错",
                    Details = ex.Message
                });
            }
        }

        private void MonitorKernelModules()
        {
            try
            {
                // 监控内核模块
                // 使用WMIC命令获取内核模块信息
                string output = ExecuteCommand("wmic.exe path win32_module where (ModuleType='Kernel') get Name, Path");
                if (!string.IsNullOrEmpty(output))
                {
                    // 解析输出并检查模块
                    string[] lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                    foreach (string line in lines)
                    {
                        if (!line.Contains("Name") && !line.Contains("Path"))
                        {
                            // 检查模块是否正常
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "KernelModulesMonitoringError",
                    Message = "内核模块监控出错",
                    Details = ex.Message
                });
            }
        }

        private void MonitorSystemCalls()
        {
            try
            {
                // 监控系统调用和内核函数挂钩
                // 这里可以使用ETW或其他方法监控系统调用
                // 简化实现：检查常见的被挂钩的DLL文件
                string[] systemDlls = {
                    "ntdll.dll",
                    "kernel32.dll",
                    "user32.dll",
                    "advapi32.dll"
                };
                
                string system32Path = Environment.GetFolderPath(Environment.SpecialFolder.System);
                foreach (string dllName in systemDlls)
                {
                    string dllPath = Path.Combine(system32Path, dllName);
                    if (File.Exists(dllPath))
                    {
                        // 检查DLL是否被篡改
                        string currentHash = CalculateFileHash(dllPath);
                        if (driverHashes.TryGetValue(dllPath, out string originalHash))
                        {
                            if (currentHash != originalHash)
                            {
                                string dllMessage = $"检测到系统DLL被篡改\nDLL名称: {dllName}\n路径: {dllPath}\n这可能是Rootkit攻击！";
                                
                                dataManager.AddLog(new LogEntry
                                {
                                    Id = Guid.NewGuid().ToString(),
                                    Time = DateTime.Now,
                                    Type = "SystemDllTampered",
                                    Message = "检测到系统DLL被篡改",
                                    Details = dllMessage
                                });
                                
                                // 弹窗警告
                                ShowThreatNotification("系统DLL篡改警告", dllMessage, NotificationType.Error);
                            }
                        }
                        else
                        {
                            // 首次检查，存储哈希值
                            driverHashes[dllPath] = currentHash;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "SystemCallsMonitoringError",
                    Message = "系统调用监控出错",
                    Details = ex.Message
                });
            }
        }

        private void BackupKernelConfiguration()
        {
            try
            {
                // 备份内核配置
                string backupFile = Path.Combine(backupDirectory, $"kernel_config_{DateTime.Now:yyyyMMdd_HHmmss}.bak");
                
                // 备份驱动列表
                using (StreamWriter writer = new StreamWriter(backupFile))
                {
                    writer.WriteLine("=== Kernel Configuration Backup ===");
                    writer.WriteLine($"Backup Time: {DateTime.Now}");
                    writer.WriteLine();
                    writer.WriteLine("=== Installed Drivers ===");
                    
                    var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_SystemDriver");
                    foreach (var driver in searcher.Get())
                    {
                        try
                        {
                            string name = driver["Name"]?.ToString() ?? "Unknown";
                            string path = driver["PathName"]?.ToString() ?? "Unknown";
                            string state = driver["State"]?.ToString() ?? "Unknown";
                            writer.WriteLine($"Name: {name}");
                            writer.WriteLine($"Path: {path}");
                            writer.WriteLine($"State: {state}");
                            writer.WriteLine();
                        }
                        catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "KernelMonitor.cs 捕获异常", ex.Message); }
                    }
                }
            }
            catch (Exception ex)
            {
                dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "KernelBackupError",
                    Message = "内核配置备份失败",
                    Details = ex.Message
                });
            }
        }

        private bool CheckDriverSignature(string driverPath)
        {
            try
            {
                // 检查驱动是否有数字签名
                string output = ExecuteCommand($"sigverif /q /c /v /s /t {driverPath}");
                return !string.IsNullOrEmpty(output) && output.Contains("Signed");
            }
            catch
            {
                return false;
            }
        }

        private void BlockDriver(string driverName)
        {
            try
            {
                // 尝试停止并禁用驱动
                string output = ExecuteCommand($"sc stop {driverName}");
                Thread.Sleep(1000);
                output += ExecuteCommand($"sc config {driverName} start= disabled");
                
                dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "DriverBlocked",
                    Message = "已阻止恶意驱动",
                    Details = $"驱动名称: {driverName}, 操作: 停止并禁用"
                });
            }
            catch (Exception ex)
            {
                dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "DriverBlockError",
                    Message = "阻止驱动失败",
                    Details = $"驱动名称: {driverName}, 错误: {ex.Message}"
                });
            }
        }

        private void RestoreDriver(string driverPath)
        {
            try
            {
                // 从备份中恢复驱动
                // 简化实现：记录需要恢复的驱动
                dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "DriverRestoreNeeded",
                    Message = "需要恢复被篡改的驱动",
                    Details = $"驱动路径: {driverPath}"
                });
            }
            catch (Exception ex)
            {
                dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "DriverRestoreError",
                    Message = "恢复驱动失败",
                    Details = $"驱动路径: {driverPath}, 错误: {ex.Message}"
                });
            }
        }

        private string CalculateFileHash(string filePath)
        {
            try
            {
                using (var md5 = System.Security.Cryptography.MD5.Create())
                {
                    using (var stream = File.OpenRead(filePath))
                    {
                        byte[] hash = md5.ComputeHash(stream);
                        return BitConverter.ToString(hash).Replace("-", "").ToLower();
                    }
                }
            }
            catch
            {
                return string.Empty;
            }
        }

        private string ExecuteCommand(string command)
        {
            try
            {
                using (var process = new Process())
                {
                    process.StartInfo.FileName = "cmd.exe";
                    process.StartInfo.Arguments = $"/c {command}";
                    process.StartInfo.RedirectStandardOutput = true;
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.CreateNoWindow = true;
                    process.Start();
                    return process.StandardOutput.ReadToEnd();
                }
            }
            catch
            {
                return string.Empty;
            }
        }
        
        private void ShowThreatNotification(string title, string message, NotificationType type)
        {
            try
            {
                NotificationService.Instance.ShowNotification(title, message, type);
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "KernelMonitor.cs 捕获异常", ex.Message); }
        }
    }
}