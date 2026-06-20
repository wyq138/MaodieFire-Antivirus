using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.ServiceProcess;
using Microsoft.Win32;
using FireAntivirus.Data;
using FireAntivirus.Engine;

namespace FireAntivirus.Services
{
    public class SystemRepair
    {
        private DataManager dataManager;
        private AntivirusEngine antivirusEngine;
        private bool isRepairing;

        public SystemRepair(DataManager dataManager, AntivirusEngine antivirusEngine)
        {
            this.dataManager = dataManager;
            this.antivirusEngine = antivirusEngine;
            this.isRepairing = false;
        }

        public List<RepairItem> ScanSystemIssues()
        {
            List<RepairItem> issues = new List<RepairItem>();

            try
            {
                LogInfo("开始扫描系统问题");

                issues.AddRange(CheckSystemFiles());
                issues.AddRange(CheckRegistryIssues());
                issues.AddRange(CheckServiceIssues());
                issues.AddRange(CheckStartupIssues());
                issues.AddRange(CheckNetworkIssues());
                issues.AddRange(CheckSecurityIssues());
                issues.AddRange(CheckPerformanceIssues());

                LogInfo($"系统问题扫描完成，发现 {issues.Count} 个问题");
            }
            catch (Exception ex)
            {
                LogError("扫描系统问题失败: " + ex.Message);
            }

            return issues;
        }

        public bool RepairSystemIssues(List<RepairItem> issues)
        {
            if (isRepairing)
            {
                LogWarning("系统修复正在进行中");
                return false;
            }

            isRepairing = true;
            int successCount = 0;
            int failCount = 0;

            try
            {
                LogInfo($"开始修复 {issues.Count} 个系统问题");

                foreach (var issue in issues)
                {
                    try
                    {
                        bool result = RepairIssue(issue);
                        if (result)
                        {
                            successCount++;
                            issue.IsFixed = true;
                        }
                        else
                        {
                            failCount++;
                        }
                    }
                    catch (Exception ex)
                    {
                        LogError($"修复问题失败 {issue.Id}: " + ex.Message);
                        failCount++;
                    }
                }

                LogInfo($"系统修复完成: 成功 {successCount}, 失败 {failCount}");
                return failCount == 0;
            }
            catch (Exception ex)
            {
                LogError("系统修复异常: " + ex.Message);
                return false;
            }
            finally
            {
                isRepairing = false;
            }
        }

        public bool RepairIssue(RepairItem issue)
        {
            try
            {
                LogInfo($"修复问题: {issue.Name}");

                switch (issue.Category)
                {
                    case RepairCategory.SystemFiles:
                        return RepairSystemFile(issue);
                    case RepairCategory.Registry:
                        return RepairRegistryIssue(issue);
                    case RepairCategory.Services:
                        return RepairServiceIssue(issue);
                    case RepairCategory.Startup:
                        return RepairStartupIssue(issue);
                    case RepairCategory.Network:
                        return RepairNetworkIssue(issue);
                    case RepairCategory.Security:
                        return RepairSecurityIssue(issue);
                    case RepairCategory.Performance:
                        return RepairPerformanceIssue(issue);
                    default:
                        return false;
                }
            }
            catch (Exception ex)
            {
                LogError($"修复问题异常 {issue.Name}: " + ex.Message);
                return false;
            }
        }

        private List<RepairItem> CheckSystemFiles()
        {
            List<RepairItem> issues = new List<RepairItem>();

            try
            {
                string system32Path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32");
                string[] criticalFiles = {
                    "kernel32.dll", "user32.dll", "shell32.dll", "explorer.exe",
                    "svchost.exe", "services.exe", "lsass.exe", "winlogon.exe"
                };

                foreach (string file in criticalFiles)
                {
                    string filePath = Path.Combine(system32Path, file);
                    if (File.Exists(filePath))
                    {
                        FileInfo fileInfo = new FileInfo(filePath);
                        if (fileInfo.Length == 0)
                        {
                            issues.Add(new RepairItem
                            {
                                Id = $"SYSFILE-{file}",
                                Name = $"系统文件损坏: {file}",
                                Description = $"{file} 文件大小为0，可能已损坏",
                                Category = RepairCategory.SystemFiles,
                                Severity = RepairSeverity.Critical,
                                CanRepair = true
                            });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                LogError("检查系统文件失败: " + ex.Message);
            }

            return issues;
        }

        private List<RepairItem> CheckRegistryIssues()
        {
            List<RepairItem> issues = new List<RepairItem>();

            try
            {
                string[] registryKeys = {
                    @"Software\Microsoft\Windows\CurrentVersion\Run",
                    @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                    @"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"
                };

                foreach (string keyPath in registryKeys)
                {
                    try
                    {
                        using (Microsoft.Win32.RegistryKey key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(keyPath))
                        {
                            if (key != null)
                            {
                                string[] valueNames = key.GetValueNames();
                                foreach (string valueName in valueNames)
                                {
                                    try
                                    {
                                        string value = key.GetValue(valueName)?.ToString();
                                        if (!string.IsNullOrEmpty(value) && !File.Exists(value))
                                        {
                                            issues.Add(new RepairItem
                                            {
                                                Id = $"REG-INVALID-{valueName.GetHashCode()}",
                                                Name = $"无效的启动项: {valueName}",
                                                Description = $"启动项指向不存在的文件: {value}",
                                                Category = RepairCategory.Registry,
                                                Severity = RepairSeverity.Medium,
                                                CanRepair = true
                                            });
                                        }
                                    }
                                    catch
                                    {
                                    }
                                }
                            }
                        }
                    }
                    catch
                    {
                    }
                }
            }
            catch (Exception ex)
            {
                LogError("检查注册表问题失败: " + ex.Message);
            }

            return issues;
        }

        private List<RepairItem> CheckServiceIssues()
        {
            List<RepairItem> issues = new List<RepairItem>();

            try
            {
                ServiceController[] services = ServiceController.GetServices();
                List<string> criticalServices = new List<string>
                {
                    "Windows Update", "Windows Firewall", "Security Center",
                    "Windows Defender", "Windows Security Center", "DHCP Client"
                };

                foreach (string serviceName in criticalServices)
                {
                    try
                    {
                        ServiceController service = services.FirstOrDefault(s => s.DisplayName.Contains(serviceName));
                        if (service != null && service.Status != ServiceControllerStatus.Running)
                        {
                            issues.Add(new RepairItem
                            {
                                Id = $"SVC-{serviceName.Replace(" ", "-")}",
                                Name = $"关键服务未运行: {serviceName}",
                                Description = $"服务 {serviceName} 未运行，可能影响系统功能",
                                Category = RepairCategory.Services,
                                Severity = RepairSeverity.High,
                                CanRepair = true
                            });
                        }
                    }
                    catch
                    {
                    }
                }
            }
            catch (Exception ex)
            {
                LogError("检查服务问题失败: " + ex.Message);
            }

            return issues;
        }

        private List<RepairItem> CheckStartupIssues()
        {
            List<RepairItem> issues = new List<RepairItem>();

            try
            {
                string startupFolder = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
                if (Directory.Exists(startupFolder))
                {
                    string[] startupFiles = Directory.GetFiles(startupFolder);
                    foreach (string file in startupFiles)
                    {
                        try
                        {
                            string shortcutTarget = GetShortcutTarget(file);
                            if (!string.IsNullOrEmpty(shortcutTarget) && !File.Exists(shortcutTarget))
                            {
                                issues.Add(new RepairItem
                                {
                                    Id = $"STARTUP-{Path.GetFileName(file)}",
                                    Name = $"无效的启动项: {Path.GetFileName(file)}",
                                    Description = $"启动项指向不存在的文件: {shortcutTarget}",
                                    Category = RepairCategory.Startup,
                                    Severity = RepairSeverity.Medium,
                                    CanRepair = true
                                });
                            }
                        }
                        catch
                        {
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                LogError("检查启动项问题失败: " + ex.Message);
            }

            return issues;
        }

        private string GetShortcutTarget(string shortcutPath)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = "powershell",
                    Arguments = $"-Command \"(New-Object -ComObject WScript.Shell).CreateShortcut('{shortcutPath}').TargetPath\"",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using (Process process = Process.Start(psi))
                {
                    string output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();
                    return output.Trim();
                }
            }
            catch
            {
                return null;
            }
        }

        private List<RepairItem> CheckNetworkIssues()
        {
            List<RepairItem> issues = new List<RepairItem>();

            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_NetworkAdapter WHERE NetEnabled = TRUE"))
                {
                    var adapters = searcher.Get();

                    foreach (ManagementObject adapter in adapters)
                    {
                        string name = adapter["Name"]?.ToString();
                        bool isConnected = Convert.ToBoolean(Convert.ToInt32(adapter["NetConnectionStatus"]) == 2);

                        if (!isConnected)
                        {
                            issues.Add(new RepairItem
                            {
                                Id = $"NET-{name.GetHashCode()}",
                                Name = $"网络适配器未连接: {name}",
                                Description = $"网络适配器 {name} 未连接到网络",
                                Category = RepairCategory.Network,
                                Severity = RepairSeverity.Low,
                                CanRepair = false
                            });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                LogError("检查网络问题失败: " + ex.Message);
            }

            return issues;
        }

        private List<RepairItem> CheckSecurityIssues()
        {
            List<RepairItem> issues = new List<RepairItem>();

            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_UserAccount WHERE LocalAccount = TRUE"))
                {
                    var users = searcher.Get();

                    foreach (ManagementObject user in users)
                    {
                        string userName = user["Name"]?.ToString();
                        bool disabled = Convert.ToBoolean(user["Disabled"]);

                        if (userName == "Guest" && !disabled)
                        {
                            issues.Add(new RepairItem
                            {
                                Id = "SEC-GUEST-001",
                                Name = "Guest账户已启用",
                                Description = "Guest账户已启用，可能存在安全风险",
                                Category = RepairCategory.Security,
                                Severity = RepairSeverity.High,
                                CanRepair = true
                            });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                LogError("检查安全问题失败: " + ex.Message);
            }

            return issues;
        }

        private List<RepairItem> CheckPerformanceIssues()
        {
            List<RepairItem> issues = new List<RepairItem>();

            try
            {
                string tempPath = Path.GetTempPath();
                if (Directory.Exists(tempPath))
                {
                    DirectoryInfo tempDir = new DirectoryInfo(tempPath);
                    long tempSize = GetDirectorySize(tempDir);

                    if (tempSize > 1024 * 1024 * 1024)
                    {
                        issues.Add(new RepairItem
                        {
                            Id = "PERF-TEMP-001",
                            Name = "临时文件过多",
                            Description = $"临时文件夹占用 {tempSize / (1024 * 1024)} MB 空间",
                            Category = RepairCategory.Performance,
                            Severity = RepairSeverity.Low,
                            CanRepair = true
                        });
                    }
                }

                using (PerformanceCounter diskCounter = new PerformanceCounter("PhysicalDisk", "% Disk Time", "_Total"))
                {
                    float diskUsage = diskCounter.NextValue();
                    if (diskUsage > 80)
                    {
                        issues.Add(new RepairItem
                        {
                            Id = "PERF-DISK-001",
                            Name = "磁盘使用率过高",
                            Description = $"磁盘使用率: {diskUsage:F1}%",
                            Category = RepairCategory.Performance,
                            Severity = RepairSeverity.Medium,
                            CanRepair = false
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                LogError("检查性能问题失败: " + ex.Message);
            }

            return issues;
        }

        private long GetDirectorySize(DirectoryInfo directory)
        {
            long totalSize = 0;

            try
            {
                FileInfo[] files = directory.GetFiles("*", SearchOption.AllDirectories);
                foreach (FileInfo file in files)
                {
                    try
                    {
                        totalSize += file.Length;
                    }
                    catch
                    {
                    }
                }
            }
            catch
            {
            }

            return totalSize;
        }

        private bool RepairSystemFile(RepairItem issue)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = "sfc",
                    Arguments = "/scannow",
                    UseShellExecute = true,
                    Verb = "runas"
                };

                Process.Start(psi);
                LogInfo($"已启动系统文件检查器修复: {issue.Name}");
                return true;
            }
            catch (Exception ex)
            {
                LogError($"修复系统文件失败: " + ex.Message);
                return false;
            }
        }

        private bool RepairRegistryIssue(RepairItem issue)
        {
            try
            {
                string keyPath = issue.Description.Split(':')[0].Replace("启动项指向不存在的文件: ", "");
                using (Microsoft.Win32.RegistryKey key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", true))
                {
                    if (key != null)
                    {
                        key.DeleteValue(issue.Name.Split(':')[1].Trim(), false);
                        LogInfo($"已删除无效注册表项: {issue.Name}");
                        return true;
                    }
                }
                return false;
            }
            catch (Exception ex)
            {
                LogError($"修复注册表问题失败: " + ex.Message);
                return false;
            }
        }

        private bool RepairServiceIssue(RepairItem issue)
        {
            try
            {
                string serviceName = issue.Name.Split(':')[1].Trim();
                ServiceController service = ServiceController.GetServices()
                    .FirstOrDefault(s => s.DisplayName.Contains(serviceName));

                if (service != null && service.Status != ServiceControllerStatus.Running)
                {
                    service.Start();
                    service.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
                    LogInfo($"已启动服务: {serviceName}");
                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                LogError($"修复服务问题失败: " + ex.Message);
                return false;
            }
        }

        private bool RepairStartupIssue(RepairItem issue)
        {
            try
            {
                string startupFolder = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
                string filePath = Path.Combine(startupFolder, issue.Name.Split(':')[1].Trim());

                if (File.Exists(filePath))
                {
                    File.Delete(filePath);
                    LogInfo($"已删除无效启动项: {issue.Name}");
                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                LogError($"修复启动项问题失败: " + ex.Message);
                return false;
            }
        }

        private bool RepairNetworkIssue(RepairItem issue)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = "winsock reset",
                    UseShellExecute = true,
                    Verb = "runas"
                };

                Process.Start(psi);
                LogInfo($"已重置网络设置: {issue.Name}");
                return true;
            }
            catch (Exception ex)
            {
                LogError($"修复网络问题失败: " + ex.Message);
                return false;
            }
        }

        private bool RepairSecurityIssue(RepairItem issue)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = "net",
                    Arguments = "user guest /active:no",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    Verb = "runas"
                };

                Process process = Process.Start(psi);
                process.WaitForExit();

                if (process.ExitCode == 0)
                {
                    LogInfo($"已禁用Guest账户: {issue.Name}");
                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                LogError($"修复安全问题失败: " + ex.Message);
                return false;
            }
        }

        private bool RepairPerformanceIssue(RepairItem issue)
        {
            try
            {
                string tempPath = Path.GetTempPath();
                DirectoryInfo tempDir = new DirectoryInfo(tempPath);

                foreach (FileInfo file in tempDir.GetFiles())
                {
                    try
                    {
                        file.Delete();
                    }
                    catch
                    {
                    }
                }

                foreach (DirectoryInfo dir in tempDir.GetDirectories())
                {
                    try
                    {
                        dir.Delete(true);
                    }
                    catch
                    {
                    }
                }

                LogInfo($"已清理临时文件: {issue.Name}");
                return true;
            }
            catch (Exception ex)
            {
                LogError($"修复性能问题失败: " + ex.Message);
                return false;
            }
        }

        public bool IsRepairing()
        {
            return isRepairing;
        }

        private void LogInfo(string message)
        {
            dataManager.LogInfo("[系统修复] " + message);
        }

        private void LogWarning(string message)
        {
            dataManager.LogWarning("[系统修复] " + message);
        }

        private void LogError(string message)
        {
            dataManager.LogError("[系统修复] " + message);
        }
    }

    public class RepairItem
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public RepairCategory Category { get; set; }
        public RepairSeverity Severity { get; set; }
        public bool CanRepair { get; set; }
        public bool IsFixed { get; set; }
    }

    public enum RepairCategory
    {
        SystemFiles,
        Registry,
        Services,
        Startup,
        Network,
        Security,
        Performance
    }

    public enum RepairSeverity
    {
        Low,
        Medium,
        High,
        Critical
    }
}