using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Security.AccessControl;
using System.ServiceProcess;
using Microsoft.Win32;
using FireAntivirus.Data;
using FireAntivirus.Engine;

namespace FireAntivirus.Services
{
    public class SystemHardener
    {
        private DataManager dataManager;
        private AntivirusEngine antivirusEngine;

        public SystemHardener(DataManager dataManager, AntivirusEngine antivirusEngine)
        {
            this.dataManager = dataManager;
            this.antivirusEngine = antivirusEngine;
        }

        public List<SecurityItem> ScanSystemSecurity()
        {
            List<SecurityItem> items = new List<SecurityItem>();

            try
            {
                items.AddRange(CheckAccountSecurity());
                items.AddRange(CheckPasswordSecurity());
                items.AddRange(CheckUACSettings());
                items.AddRange(CheckFirewallSettings());
                items.AddRange(CheckWindowsUpdate());
                items.AddRange(CheckDefenderSettings());
                items.AddRange(CheckServiceSecurity());
                items.AddRange(CheckNetworkSecurity());
                items.AddRange(CheckFileSecurity());
                items.AddRange(CheckRegistrySecurity());
                items.AddRange(CheckRemoteDesktopSettings());

                dataManager.LogInfo($"系统安全扫描完成，发现 {items.Count} 个安全问题");
            }
            catch (Exception ex)
            {
                dataManager.LogError($"系统安全扫描失败: {ex.Message}");
            }

            return items;
        }

        public HardeningResult HardenSystem(List<SecurityItem> items)
        {
            HardeningResult result = new HardeningResult
            {
                StartTime = DateTime.Now,
                HardenedItems = new List<SecurityItem>(),
                FailedItems = new List<SecurityItem>()
            };

            try
            {
                foreach (var item in items)
                {
                    try
                    {
                        bool success = ApplyHardening(item);
                        if (success)
                        {
                            result.HardenedItems.Add(item);
                        }
                        else
                        {
                            result.FailedItems.Add(item);
                        }
                    }
                    catch
                    {
                        result.FailedItems.Add(item);
                    }
                }

                result.EndTime = DateTime.Now;
                dataManager.LogInfo($"系统加固完成: 成功 {result.HardenedItems.Count}，失败 {result.FailedItems.Count}");
            }
            catch (Exception ex)
            {
                dataManager.LogError($"系统加固失败: {ex.Message}");
            }

            return result;
        }

        public HardeningResult HardenAll()
        {
            List<SecurityItem> items = ScanSystemSecurity();
            return HardenSystem(items);
        }

        private List<SecurityItem> CheckAccountSecurity()
        {
            List<SecurityItem> items = new List<SecurityItem>();

            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_UserAccount WHERE LocalAccount = TRUE"))
                {
                    foreach (ManagementObject user in searcher.Get())
                    {
                        string userName = user["Name"]?.ToString();
                        bool accountDisabled = Convert.ToBoolean(user["Disabled"]?.ToString() ?? "false");
                        bool passwordRequired = Convert.ToBoolean(user["PasswordRequired"]?.ToString() ?? "true");
                        string accountType = user["AccountType"]?.ToString();

                        if (accountType == "512" && !accountDisabled)
                        {
                            items.Add(new SecurityItem
                            {
                                Name = "管理员账户未禁用",
                                Type = SecurityType.Account,
                                Severity = SecuritySeverity.Medium,
                                Description = $"管理员账户 {userName} 未禁用",
                                CanHarden = true,
                                Recommendation = "禁用不必要的管理员账户"
                            });
                        }

                        if (userName == "Guest" && !accountDisabled)
                        {
                            items.Add(new SecurityItem
                            {
                                Name = "Guest账户已启用",
                                Type = SecurityType.Account,
                                Severity = SecuritySeverity.High,
                                Description = "Guest账户已启用，可能被攻击者利用",
                                CanHarden = true,
                                Recommendation = "禁用Guest账户"
                            });
                        }

                        if (!passwordRequired)
                        {
                            items.Add(new SecurityItem
                            {
                                Name = $"账户 {userName} 无密码",
                                Type = SecurityType.Account,
                                Severity = SecuritySeverity.High,
                                Description = $"账户 {userName} 没有设置密码",
                                CanHarden = false,
                                Recommendation = "为账户设置强密码"
                            });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"检查账户安全失败: {ex.Message}");
            }

            return items;
        }

        private List<SecurityItem> CheckPasswordSecurity()
        {
            List<SecurityItem> items = new List<SecurityItem>();

            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Lsa"))
                {
                    object limitBlankPasswordUse = key.GetValue("LimitBlankPasswordUse");
                    if (limitBlankPasswordUse != null && Convert.ToInt32(limitBlankPasswordUse) != 1)
                    {
                        items.Add(new SecurityItem
                        {
                            Name = "允许空密码",
                            Type = SecurityType.Password,
                            Severity = SecuritySeverity.High,
                            Description = "系统允许使用空密码",
                            CanHarden = true,
                            Recommendation = "禁用空密码使用"
                        });
                    }
                }

                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Lsa"))
                {
                    object restrictAnonymous = key.GetValue("RestrictAnonymous");
                    if (restrictAnonymous != null && Convert.ToInt32(restrictAnonymous) != 1)
                    {
                        items.Add(new SecurityItem
                        {
                            Name = "允许匿名访问",
                            Type = SecurityType.Password,
                            Severity = SecuritySeverity.Medium,
                            Description = "系统允许匿名访问",
                            CanHarden = true,
                            Recommendation = "禁用匿名访问"
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"检查密码安全失败: {ex.Message}");
            }

            return items;
        }

        private List<SecurityItem> CheckUACSettings()
        {
            List<SecurityItem> items = new List<SecurityItem>();

            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"))
                {
                    object consentPromptBehaviorAdmin = key.GetValue("ConsentPromptBehaviorAdmin");
                    object consentPromptBehaviorUser = key.GetValue("ConsentPromptBehaviorUser");

                    if (consentPromptBehaviorAdmin == null || consentPromptBehaviorUser == null)
                    {
                        items.Add(new SecurityItem
                        {
                            Name = "UAC提示行为未配置",
                            Type = SecurityType.UAC,
                            Severity = SecuritySeverity.Low,
                            Description = "UAC提示行为未明确配置",
                            CanHarden = true,
                            Recommendation = "配置UAC提示行为为始终通知"
                        });
                    }
                }

                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"))
                {
                    object enableLUA = key.GetValue("EnableLUA");
                    if (enableLUA != null && Convert.ToInt32(enableLUA) != 1)
                    {
                        items.Add(new SecurityItem
                        {
                            Name = "UAC未启用",
                            Type = SecurityType.UAC,
                            Severity = SecuritySeverity.High,
                            Description = "用户账户控制(UAC)未启用",
                            CanHarden = true,
                            Recommendation = "启用UAC以提升系统安全性"
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"检查UAC设置失败: {ex.Message}");
            }

            return items;
        }

        private List<SecurityItem> CheckFirewallSettings()
        {
            List<SecurityItem> items = new List<SecurityItem>();

            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_FirewallProfile"))
                {
                    foreach (ManagementObject profile in searcher.Get())
                    {
                        bool enabled = Convert.ToBoolean(profile["Enabled"]?.ToString() ?? "false");
                        if (!enabled)
                        {
                            items.Add(new SecurityItem
                            {
                                Name = "Windows防火墙未启用",
                                Type = SecurityType.Firewall,
                                Severity = SecuritySeverity.High,
                                Description = "Windows防火墙未启用",
                                CanHarden = true,
                                Recommendation = "启用Windows防火墙"
                            });
                        }
                    }
                }

                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = "advfirewall show allprofiles state",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using (Process process = Process.Start(psi))
                {
                    string output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit(5000);

                    if (output.Contains("状态") && output.Contains("关闭"))
                    {
                        items.Add(new SecurityItem
                        {
                            Name = "Windows防火墙已关闭",
                            Type = SecurityType.Firewall,
                            Severity = SecuritySeverity.High,
                            Description = "Windows防火墙已关闭",
                            CanHarden = true,
                            Recommendation = "启用Windows防火墙"
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"检查防火墙设置失败: {ex.Message}");
            }

            return items;
        }

        private List<SecurityItem> CheckWindowsUpdate()
        {
            List<SecurityItem> items = new List<SecurityItem>();

            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"))
                {
                    object disableWUDriver = key.GetValue("DisableWUDriver");
                    if (disableWUDriver != null && Convert.ToInt32(disableWUDriver) == 1)
                    {
                        items.Add(new SecurityItem
                        {
                            Name = "Windows更新驱动已禁用",
                            Type = SecurityType.WindowsUpdate,
                            Severity = SecuritySeverity.Medium,
                            Description = "Windows更新驱动程序被禁用",
                            CanHarden = true,
                            Recommendation = "启用Windows更新驱动程序"
                        });
                    }

                    object disableOSUpgrade = key.GetValue("DisableOSUpgrade");
                    if (disableOSUpgrade != null && Convert.ToInt32(disableOSUpgrade) == 1)
                    {
                        items.Add(new SecurityItem
                        {
                            Name = "系统升级已禁用",
                            Type = SecurityType.WindowsUpdate,
                            Severity = SecuritySeverity.Medium,
                            Description = "操作系统升级被禁用",
                            CanHarden = true,
                            Recommendation = "启用系统升级"
                        });
                    }
                }

                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate"))
                {
                    object setDisableUXWUAccess = key.GetValue("SetDisableUXWUAccess");
                    if (setDisableUXWUAccess != null && Convert.ToInt32(setDisableUXWUAccess) == 1)
                    {
                        items.Add(new SecurityItem
                        {
                            Name = "Windows更新UX已禁用",
                            Type = SecurityType.WindowsUpdate,
                            Severity = SecuritySeverity.Low,
                            Description = "Windows更新用户体验已禁用",
                            CanHarden = true,
                            Recommendation = "启用Windows更新用户体验"
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"检查Windows更新设置失败: {ex.Message}");
            }

            return items;
        }

        private List<SecurityItem> CheckDefenderSettings()
        {
            List<SecurityItem> items = new List<SecurityItem>();

            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows Defender"))
                {
                    object disableAntiSpyware = key.GetValue("DisableAntiSpyware");
                    if (disableAntiSpyware != null && Convert.ToInt32(disableAntiSpyware) == 1)
                    {
                        items.Add(new SecurityItem
                        {
                            Name = "Windows Defender反间谍软件已禁用",
                            Type = SecurityType.WindowsDefender,
                            Severity = SecuritySeverity.High,
                            Description = "Windows Defender反间谍软件功能被禁用",
                            CanHarden = true,
                            Recommendation = "启用Windows Defender反间谍软件"
                        });
                    }

                    object disableAntiVirus = key.GetValue("DisableAntiVirus");
                    if (disableAntiVirus != null && Convert.ToInt32(disableAntiVirus) == 1)
                    {
                        items.Add(new SecurityItem
                        {
                            Name = "Windows Defender反病毒已禁用",
                            Type = SecurityType.WindowsDefender,
                            Severity = SecuritySeverity.Critical,
                            Description = "Windows Defender反病毒功能被禁用",
                            CanHarden = true,
                            Recommendation = "启用Windows Defender反病毒功能"
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"检查Windows Defender设置失败: {ex.Message}");
            }

            return items;
        }

        private List<SecurityItem> CheckServiceSecurity()
        {
            List<SecurityItem> items = new List<SecurityItem>();

            try
            {
                ServiceController[] services = ServiceController.GetServices();
                List<string> criticalServices = new List<string>
                {
                    "Windows Update", "Windows Firewall", "Security Center",
                    "Windows Defender", "Windows Security Center", "DHCP Client",
                    "DNS Client", "Remote Procedure Call (RPC)", "Server"
                };

                foreach (ServiceController service in services)
                {
                    if (criticalServices.Contains(service.DisplayName, StringComparer.OrdinalIgnoreCase))
                    {
                        if (service.Status != ServiceControllerStatus.Running)
                        {
                            items.Add(new SecurityItem
                            {
                                Name = $"关键服务未运行: {service.DisplayName}",
                                Type = SecurityType.Service,
                                Severity = SecuritySeverity.High,
                                Description = $"关键服务 {service.DisplayName} 未运行",
                                CanHarden = true,
                                Recommendation = $"启动 {service.DisplayName} 服务"
                            });
                        }

                        if ((int)service.StartType == 4) // Disabled
                        {
                            items.Add(new SecurityItem
                            {
                                Name = $"关键服务已禁用: {service.DisplayName}",
                                Type = SecurityType.Service,
                                Severity = SecuritySeverity.High,
                                Description = $"关键服务 {service.DisplayName} 已禁用",
                                CanHarden = true,
                                Recommendation = $"启用 {service.DisplayName} 服务"
                            });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"检查服务安全失败: {ex.Message}");
            }

            return items;
        }

        private List<SecurityItem> CheckNetworkSecurity()
        {
            List<SecurityItem> items = new List<SecurityItem>();

            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_NetworkAdapterConfiguration"))
                {
                    foreach (ManagementObject config in searcher.Get())
                    {
                        bool dhcpEnabled = Convert.ToBoolean(config["DHCPEnabled"]?.ToString() ?? "false");
                        if (!dhcpEnabled)
                        {
                            items.Add(new SecurityItem
                            {
                                Name = "DHCP未启用",
                                Type = SecurityType.Network,
                                Severity = SecuritySeverity.Medium,
                                Description = "网络适配器未使用DHCP",
                                CanHarden = true,
                                Recommendation = "启用DHCP以自动获取IP地址"
                            });
                        }
                    }
                }

                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_NetworkAdapter WHERE NetEnabled = TRUE"))
                {
                    foreach (ManagementObject adapter in searcher.Get())
                    {
                        string name = adapter["Name"]?.ToString();
                        bool isConnected = false;
                        if (adapter["NetConnectionStatus"] != null)
                        {
                            isConnected = Convert.ToInt32(adapter["NetConnectionStatus"]) == 2;
                        }

                        if (!isConnected)
                        {
                            items.Add(new SecurityItem
                            {
                                Name = $"网络适配器未连接: {name}",
                                Type = SecurityType.Network,
                                Severity = SecuritySeverity.Low,
                                Description = $"网络适配器 {name} 未连接",
                                CanHarden = false,
                                Recommendation = "检查网络连接"
                            });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"检查网络安全失败: {ex.Message}");
            }

            return items;
        }

        private List<SecurityItem> CheckFileSecurity()
        {
            List<SecurityItem> items = new List<SecurityItem>();

            try
            {
                string[] criticalPaths = {
                    Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64")
                };

                foreach (string path in criticalPaths)
                {
                    if (Directory.Exists(path))
                    {
                        DirectoryInfo dirInfo = new DirectoryInfo(path);
                        FileSystemSecurity security = dirInfo.GetAccessControl();

                        bool everyoneHasFullControl = false;
                        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(System.Security.Principal.NTAccount)))
                        {
                            if (rule.IdentityReference.Value.Equals("Everyone", StringComparison.OrdinalIgnoreCase) &&
                                rule.FileSystemRights == FileSystemRights.FullControl)
                            {
                                everyoneHasFullControl = true;
                                break;
                            }
                        }

                        if (everyoneHasFullControl)
                        {
                            items.Add(new SecurityItem
                            {
                                Name = $"关键目录权限过宽: {path}",
                                Type = SecurityType.File,
                                Severity = SecuritySeverity.High,
                                Description = $"目录 {path} 对Everyone有完全控制权限",
                                CanHarden = true,
                                Recommendation = "限制关键目录的访问权限"
                            });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"检查文件安全失败: {ex.Message}");
            }

            return items;
        }

        private List<SecurityItem> CheckRegistrySecurity()
        {
            List<SecurityItem> items = new List<SecurityItem>();

            try
            {
                string[] registryPaths = {
                    @"HKEY_LOCAL_MACHINE\SOFTWARE",
                    @"HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node",
                    @"HKEY_LOCAL_MACHINE\SYSTEM",
                    @"HKEY_LOCAL_MACHINE\SECURITY"
                };

                foreach (string registryPath in registryPaths)
                {
                    try
                    {
                        using (RegistryKey key = Registry.LocalMachine.OpenSubKey(registryPath.Replace("HKEY_LOCAL_MACHINE\\", "")))
                        {
                            if (key != null)
                            {
                                RegistrySecurity security = key.GetAccessControl();

                                bool everyoneHasFullControl = false;
                                foreach (RegistryAccessRule rule in security.GetAccessRules(true, true, typeof(System.Security.Principal.NTAccount)))
                                {
                                    if (rule.IdentityReference.Value.Equals("Everyone", StringComparison.OrdinalIgnoreCase) &&
                                        rule.RegistryRights == RegistryRights.FullControl)
                                    {
                                        everyoneHasFullControl = true;
                                        break;
                                    }
                                }

                                if (everyoneHasFullControl)
                                {
                                    items.Add(new SecurityItem
                                    {
                                        Name = $"注册表权限过宽: {registryPath}",
                                        Type = SecurityType.Registry,
                                        Severity = SecuritySeverity.High,
                                        Description = $"注册表项 {registryPath} 对Everyone有完全控制权限",
                                        CanHarden = true,
                                        Recommendation = "限制注册表的访问权限"
                                    });
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
                dataManager.LogError($"检查注册表安全失败: {ex.Message}");
            }

            return items;
        }

        private List<SecurityItem> CheckRemoteDesktopSettings()
        {
            List<SecurityItem> items = new List<SecurityItem>();

            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server"))
                {
                    object fDenyTSConnections = key.GetValue("fDenyTSConnections");
                    if (fDenyTSConnections != null && Convert.ToInt32(fDenyTSConnections) != 1)
                    {
                        items.Add(new SecurityItem
                        {
                            Name = "远程桌面未禁用",
                            Type = SecurityType.RemoteDesktop,
                            Severity = SecuritySeverity.High,
                            Description = "远程桌面连接未禁用",
                            CanHarden = true,
                            Recommendation = "禁用远程桌面连接"
                        });
                    }
                }

                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"))
                {
                    object userAuthentication = key.GetValue("UserAuthentication");
                    if (userAuthentication != null && Convert.ToInt32(userAuthentication) != 1)
                    {
                        items.Add(new SecurityItem
                        {
                            Name = "RDP用户验证未启用",
                            Type = SecurityType.RemoteDesktop,
                            Severity = SecuritySeverity.Medium,
                            Description = "RDP用户验证未启用",
                            CanHarden = true,
                            Recommendation = "启用RDP用户验证"
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"检查远程桌面设置失败: {ex.Message}");
            }

            return items;
        }

        private bool ApplyHardening(SecurityItem item)
        {
            try
            {
                switch (item.Type)
                {
                    case SecurityType.Account:
                        return HardenAccountSecurity(item);
                    case SecurityType.Password:
                        return HardenPasswordSecurity(item);
                    case SecurityType.UAC:
                        return HardenUACSettings(item);
                    case SecurityType.Firewall:
                        return HardenFirewallSettings(item);
                    case SecurityType.WindowsUpdate:
                        return HardenWindowsUpdateSettings(item);
                    case SecurityType.WindowsDefender:
                        return HardenDefenderSettings(item);
                    case SecurityType.Service:
                        return HardenServiceSecurity(item);
                    case SecurityType.Network:
                        return HardenNetworkSecurity(item);
                    case SecurityType.File:
                        return HardenFileSecurity(item);
                    case SecurityType.Registry:
                        return HardenRegistrySecurity(item);
                    case SecurityType.RemoteDesktop:
                        return HardenRemoteDesktopSettings(item);
                    default:
                        return false;
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"应用加固失败 {item.Name}: {ex.Message}");
                return false;
            }
        }

        private bool HardenAccountSecurity(SecurityItem item)
        {
            try
            {
                if (item.Name.Contains("Guest账户"))
                {
                    ProcessStartInfo psi = new ProcessStartInfo
                    {
                        FileName = "net",
                        Arguments = "user guest /active:no",
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        Verb = "runas"
                    };

                    using (Process process = Process.Start(psi))
                    {
                        process.WaitForExit(10000);
                        if (process.ExitCode == 0)
                        {
                            dataManager.LogInfo($"已禁用Guest账户");
                            return true;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"加固账户安全失败: {ex.Message}");
                return false;
            }
            return false;
        }

        private bool HardenPasswordSecurity(SecurityItem item)
        {
            try
            {
                if (item.Name.Contains("空密码"))
                {
                    using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Lsa", true))
                    {
                        if (key != null)
                        {
                            key.SetValue("LimitBlankPasswordUse", 1);
                            dataManager.LogInfo($"已禁用空密码使用");
                            return true;
                        }
                    }
                }

                if (item.Name.Contains("匿名访问"))
                {
                    using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Lsa", true))
                    {
                        if (key != null)
                        {
                            key.SetValue("RestrictAnonymous", 1);
                            dataManager.LogInfo($"已禁用匿名访问");
                            return true;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"加固密码安全失败: {ex.Message}");
                return false;
            }
            return false;
        }

        private bool HardenUACSettings(SecurityItem item)
        {
            try
            {
                if (item.Name.Contains("UAC未启用"))
                {
                    using (RegistryKey key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"))
                    {
                        if (key != null)
                        {
                            key.SetValue("EnableLUA", 1);
                            dataManager.LogInfo($"已启用UAC");
                            return true;
                        }
                    }
                }

                if (item.Name.Contains("UAC提示行为"))
                {
                    using (RegistryKey key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"))
                    {
                        if (key != null)
                        {
                            key.SetValue("ConsentPromptBehaviorAdmin", 2);
                            key.SetValue("ConsentPromptBehaviorUser", 2);
                            dataManager.LogInfo($"已配置UAC提示行为");
                            return true;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"加固UAC设置失败: {ex.Message}");
                return false;
            }
            return false;
        }

        private bool HardenFirewallSettings(SecurityItem item)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = "advfirewall set allprofiles state on",
                    UseShellExecute = true,
                    CreateNoWindow = true,
                    Verb = "runas"
                };

                using (Process process = Process.Start(psi))
                {
                    process.WaitForExit(10000);
                    if (process.ExitCode == 0)
                    {
                        dataManager.LogInfo($"已启用Windows防火墙");
                        return true;
                    }
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"加固防火墙设置失败: {ex.Message}");
                return false;
            }
            return false;
        }

        private bool HardenWindowsUpdateSettings(SecurityItem item)
        {
            try
            {
                if (item.Name.Contains("更新驱动已禁用"))
                {
                    using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", true))
                    {
                        if (key != null)
                        {
                            key.DeleteValue("DisableWUDriver");
                            dataManager.LogInfo($"已启用Windows更新驱动");
                            return true;
                        }
                    }
                }

                if (item.Name.Contains("系统升级已禁用"))
                {
                    using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", true))
                    {
                        if (key != null)
                        {
                            key.DeleteValue("DisableOSUpgrade");
                            dataManager.LogInfo($"已启用系统升级");
                            return true;
                        }
                    }
                }

                if (item.Name.Contains("更新UX已禁用"))
                {
                    using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate", true))
                    {
                        if (key != null)
                        {
                            key.DeleteValue("SetDisableUXWUAccess");
                            dataManager.LogInfo($"已启用Windows更新UX");
                            return true;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"加固Windows更新设置失败: {ex.Message}");
                return false;
            }
            return false;
        }

        private bool HardenDefenderSettings(SecurityItem item)
        {
            try
            {
                if (item.Name.Contains("反间谍软件已禁用"))
                {
                    using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows Defender", true))
                    {
                        if (key != null)
                        {
                            key.DeleteValue("DisableAntiSpyware");
                            dataManager.LogInfo($"已启用Windows Defender反间谍软件");
                            return true;
                        }
                    }
                }

                if (item.Name.Contains("反病毒已禁用"))
                {
                    using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows Defender", true))
                    {
                        if (key != null)
                        {
                            key.DeleteValue("DisableAntiVirus");
                            dataManager.LogInfo($"已启用Windows Defender反病毒");
                            return true;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"加固Windows Defender设置失败: {ex.Message}");
                return false;
            }
            return false;
        }

        private bool HardenServiceSecurity(SecurityItem item)
        {
            try
            {
                string serviceName = item.Name.Split(':')[1].Trim();
                ServiceController service = ServiceController.GetServices()
                    .FirstOrDefault(s => s.DisplayName.Contains(serviceName, StringComparison.OrdinalIgnoreCase));

                if (service != null)
                {
                    if (service.Status == ServiceControllerStatus.Stopped)
                    {
                        service.Start();
                        service.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
                        dataManager.LogInfo($"已启动服务: {serviceName}");
                        return true;
                    }

                    using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + service.ServiceName, true))
                    {
                        if (key != null)
                        {
                            int startValue = (int)key.GetValue("Start", 4);
                            if (startValue == 4) // Disabled
                            {
                                key.SetValue("Start", 2);
                                dataManager.LogInfo($"已启用服务: {serviceName}");
                                return true;
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"加固服务安全失败: {ex.Message}");
                return false;
            }
            return false;
        }

        private bool HardenNetworkSecurity(SecurityItem item)
        {
            try
            {
                if (item.Name.Contains("DHCP未启用"))
                {
                    ProcessStartInfo psi = new ProcessStartInfo
                    {
                        FileName = "netsh",
                        Arguments = "interface ip set address name=\"以太网\" source=dhcp",
                        UseShellExecute = true,
                        CreateNoWindow = true,
                        Verb = "runas"
                    };

                    using (Process process = Process.Start(psi))
                    {
                        process.WaitForExit(10000);
                        if (process.ExitCode == 0)
                        {
                            dataManager.LogInfo($"已启用DHCP");
                            return true;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"加固网络安全失败: {ex.Message}");
                return false;
            }
            return false;
        }

        private bool HardenFileSecurity(SecurityItem item)
        {
            try
            {
                string path = item.Description;
                if (Directory.Exists(path))
                {
                    DirectoryInfo dirInfo = new DirectoryInfo(path);
                    DirectorySecurity security = dirInfo.GetAccessControl();

                    FileSystemAccessRule rule = null;
                    var accessRules = security.GetAccessRules(true, true, typeof(System.Security.Principal.NTAccount));
                    foreach (FileSystemAccessRule r in accessRules)
                    {
                        if (r.IdentityReference.Value.Equals("Everyone", StringComparison.OrdinalIgnoreCase))
                        {
                            rule = r;
                            break;
                        }
                    }

                    if (rule != null)
                    {
                        security.RemoveAccessRule(rule);
                        dirInfo.SetAccessControl(security);
                        dataManager.LogInfo($"已限制目录权限: {path}");
                        return true;
                    }
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"加固文件安全失败: {ex.Message}");
                return false;
            }
            return false;
        }

        private bool HardenRegistrySecurity(SecurityItem item)
        {
            try
            {
                string registryPath = item.Description;
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(registryPath.Replace("HKEY_LOCAL_MACHINE\\", ""), true))
                {
                    if (key != null)
                    {
                        RegistrySecurity security = key.GetAccessControl();

                        RegistryAccessRule rule = null;
                        var accessRules = security.GetAccessRules(true, true, typeof(System.Security.Principal.NTAccount));
                        foreach (RegistryAccessRule r in accessRules)
                        {
                            if (r.IdentityReference.Value.Equals("Everyone", StringComparison.OrdinalIgnoreCase))
                            {
                                rule = r;
                                break;
                            }
                        }

                        if (rule != null)
                        {
                            security.RemoveAccessRule(rule);
                            key.SetAccessControl(security);
                            dataManager.LogInfo($"已限制注册表权限: {registryPath}");
                            return true;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"加固注册表安全失败: {ex.Message}");
                return false;
            }
            return false;
        }

        private bool HardenRemoteDesktopSettings(SecurityItem item)
        {
            try
            {
                if (item.Name.Contains("远程桌面未禁用"))
                {
                    using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server", true))
                    {
                        if (key != null)
                        {
                            key.SetValue("fDenyTSConnections", 1);
                            dataManager.LogInfo($"已禁用远程桌面连接");
                            return true;
                        }
                    }
                }

                if (item.Name.Contains("RDP用户验证未启用"))
                {
                    using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", true))
                    {
                        if (key != null)
                        {
                            key.SetValue("UserAuthentication", 1);
                            dataManager.LogInfo($"已启用RDP用户验证");
                            return true;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"加固远程桌面设置失败: {ex.Message}");
                return false;
            }
            return false;
        }
    }

    public class SecurityItem
    {
        public string Name { get; set; }
        public SecurityType Type { get; set; }
        public SecuritySeverity Severity { get; set; }
        public string Description { get; set; }
        public bool CanHarden { get; set; }
        public string Recommendation { get; set; }
        public DateTime DetectedAt { get; set; } = DateTime.Now;
    }

    public class HardeningResult
    {
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public TimeSpan Duration => EndTime - StartTime;
        public List<SecurityItem> HardenedItems { get; set; }
        public List<SecurityItem> FailedItems { get; set; }
    }

    public enum SecurityType
    {
        Account,
        Password,
        UAC,
        Firewall,
        WindowsUpdate,
        WindowsDefender,
        Service,
        Network,
        File,
        Registry,
        RemoteDesktop
    }

    public enum SecuritySeverity
    {
        Low,
        Medium,
        High,
        Critical
    }
}
