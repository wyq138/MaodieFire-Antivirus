using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Win32;
using FireAntivirus.Common;
using FireAntivirus.Data;

namespace FireAntivirus.StartupManager
{
    public class StartupManager
    {
        private DataManager _dataManager;
        private List<StartupItem> _startupItems;
        private string _backupPath;

        public StartupManager(DataManager dataManager)
        {
            _dataManager = dataManager;
            _startupItems = new List<StartupItem>();
            _backupPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "FireAntivirus", "StartupBackup");
        }

        public List<StartupItem> GetStartupItems()
        {
            _startupItems.Clear();

            // 从注册表获取启动项 - HKLM Run
            LoadRegistryStartupItems(Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Run");
            
            // 从注册表获取启动项 - HKLM RunOnce
            LoadRegistryStartupItems(Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\RunOnce");
            
            // 从注册表获取启动项 - HKCU Run
            LoadRegistryStartupItems(Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU\\Run");
            
            // 从注册表获取启动项 - HKCU RunOnce
            LoadRegistryStartupItems(Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU\\RunOnce");

            // 从启动文件夹获取
            LoadStartupFolderItems();

            // 从服务获取自动启动的服务
            LoadAutoStartServices();

            // 从任务计划程序获取
            LoadScheduledTasks();

            return _startupItems;
        }

        private void LoadRegistryStartupItems(RegistryKey rootKey, string subKeyPath, string location)
        {
            try
            {
                using var key = rootKey.OpenSubKey(subKeyPath);
                if (key == null) return;

                foreach (var valueName in key.GetValueNames())
                {
                    var value = key.GetValue(valueName)?.ToString();
                    if (string.IsNullOrEmpty(value)) continue;

                    var item = CreateStartupItem(valueName, value, location, "Registry");
                    _startupItems.Add(item);
                }
            }
            catch { }
        }

        private void LoadStartupFolderItems()
        {
            try
            {
                // 当前用户启动文件夹
                var userStartupPath = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
                LoadStartupFolderItems(userStartupPath, "User Startup Folder");

                // 公共启动文件夹
                var commonStartupPath = Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup);
                LoadStartupFolderItems(commonStartupPath, "Common Startup Folder");
            }
            catch { }
        }

        private void LoadStartupFolderItems(string folderPath, string location)
        {
            try
            {
                if (!Directory.Exists(folderPath)) return;

                foreach (var file in Directory.GetFiles(folderPath, "*.lnk"))
                {
                    try
                    {
                        var targetPath = ResolveShortcut(file);
                        var item = CreateStartupItem(
                            Path.GetFileNameWithoutExtension(file),
                            targetPath ?? file,
                            location,
                            "Shortcut");
                        item.ShortcutPath = file;
                        _startupItems.Add(item);
                    }
                    catch { }
                }

                // 也检查其他可执行文件
                var extensions = new[] { "*.exe", "*.bat", "*.cmd", "*.ps1", "*.vbs", "*.js" };
                foreach (var ext in extensions)
                {
                    foreach (var file in Directory.GetFiles(folderPath, ext))
                    {
                        if (_startupItems.Any(i => i.ShortcutPath == file)) continue;
                        
                        var item = CreateStartupItem(
                            Path.GetFileNameWithoutExtension(file),
                            file,
                            location,
                            "Executable");
                        item.ShortcutPath = file;
                        _startupItems.Add(item);
                    }
                }
            }
            catch { }
        }

        private void LoadAutoStartServices()
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    "SELECT Name, DisplayName, PathName, StartMode FROM Win32_Service WHERE StartMode = 'Auto'");
                
                foreach (var service in searcher.Get())
                {
                    var name = service["Name"]?.ToString();
                    var displayName = service["DisplayName"]?.ToString();
                    var path = service["PathName"]?.ToString();

                    if (string.IsNullOrEmpty(path)) continue;

                    // 排除系统服务
                    if (IsSystemService(name)) continue;

                    var item = new StartupItem
                    {
                        Id = Guid.NewGuid().ToString(),
                        Name = displayName ?? name,
                        Path = path.Trim('"'),
                        Location = "Services",
                        Enabled = true,
                        Type = "Service",
                        ServiceName = name
                    };
                    _startupItems.Add(item);
                }
            }
            catch { }
        }

        private void LoadScheduledTasks()
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    "SELECT * FROM MSFT_ScheduledTask WHERE State = 'Ready'");
                
                // 使用schtasks命令获取任务
                var startInfo = new ProcessStartInfo
                {
                    FileName = "schtasks.exe",
                    Arguments = "/query /fo LIST /v",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                };

                using var process = Process.Start(startInfo);
                if (process == null) return;

                var output = process.StandardOutput.ReadToEnd();
                var lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                
                string currentTask = null;
                string currentPath = null;

                foreach (var line in lines)
                {
                    if (line.StartsWith("TaskName:"))
                    {
                        currentTask = line.Substring("TaskName:".Length).Trim();
                    }
                    else if (line.StartsWith("Task To Run:"))
                    {
                        currentPath = line.Substring("Task To Run:".Length).Trim();
                    }
                    else if (line.StartsWith("Status:") && currentTask != null && currentPath != null)
                    {
                        var status = line.Substring("Status:".Length).Trim();
                        if (status == "Ready" && !string.IsNullOrEmpty(currentPath) && 
                            !currentPath.StartsWith("\"") && !currentPath.Contains("Microsoft\\Windows"))
                        {
                            var item = CreateStartupItem(currentTask, currentPath, "Task Scheduler", "Scheduled Task");
                            _startupItems.Add(item);
                        }
                        currentTask = null;
                        currentPath = null;
                    }
                }
            }
            catch { }
        }

        private StartupItem CreateStartupItem(string name, string path, string location, string type)
        {
            return new StartupItem
            {
                Id = Guid.NewGuid().ToString(),
                Name = name,
                Path = path,
                Location = location,
                Enabled = true,
                Type = type
            };
        }

        private string ResolveShortcut(string shortcutPath)
        {
            try
            {
                // 使用PowerShell解析快捷方式
                var script = $"(New-Object -ComObject WScript.Shell).CreateShortcut('{shortcutPath}').TargetPath";
                var startInfo = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NoProfile -Command \"{script}\"",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                };

                using var process = Process.Start(startInfo);
                return process?.StandardOutput.ReadToEnd().Trim();
            }
            catch { return null; }
        }

        private bool IsSystemService(string serviceName)
        {
            var systemServices = new[]
            {
                "Winmgmt", "EventLog", "PlugPlay", "RpcSs", "Spooler", "lanmanserver",
                "lanmanworkstation", "Schedule", "Winmgmt", "AudioSrv", "Dhcp",
                "Dnscache", "EventSystem", "PolicyAgent", "ProtectedStorage",
                "SamSs", "SENS", "TapiSrv", "TrkWks", "W32Time", "wuauserv",
                "CryptSvc", "DcomLaunch", "LSM", "Power", "ProfSvc", "SysMain"
            };
            return systemServices.Contains(serviceName, StringComparer.OrdinalIgnoreCase);
        }

        public bool EnableStartupItem(string id)
        {
            var item = _startupItems.FirstOrDefault(i => i.Id == id);
            if (item == null) return false;

            try
            {
                if (item.Location.StartsWith("HKLM\\") || item.Location.StartsWith("HKCU\\"))
                {
                    var rootKey = item.Location.StartsWith("HKLM") ? Registry.LocalMachine : Registry.CurrentUser;
                    var subKey = item.Location.Contains("RunOnce") 
                        ? @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" 
                        : @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
                    
                    using var key = rootKey.OpenSubKey(subKey, true);
                    key?.SetValue(item.Name, item.Path);
                }
                
                item.Enabled = true;
                
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "StartupItemEnabled",
                    Message = "启动项已启用",
                    Details = $"名称: {item.Name}"
                });
                return true;
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "StartupItemEnableError",
                    Message = "启用启动项失败",
                    Details = $"错误: {ex.Message}"
                });
                return false;
            }
        }

        public bool DisableStartupItem(string id)
        {
            var item = _startupItems.FirstOrDefault(i => i.Id == id);
            if (item == null) return false;

            try
            {
                if (item.Location.StartsWith("HKLM\\") || item.Location.StartsWith("HKCU\\"))
                {
                    var rootKey = item.Location.StartsWith("HKLM") ? Registry.LocalMachine : Registry.CurrentUser;
                    var subKey = item.Location.Contains("RunOnce") 
                        ? @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" 
                        : @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
                    
                    using var key = rootKey.OpenSubKey(subKey, true);
                    key?.DeleteValue(item.Name, false);
                }
                
                item.Enabled = false;
                
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "StartupItemDisabled",
                    Message = "启动项已禁用",
                    Details = $"名称: {item.Name}"
                });
                return true;
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "StartupItemDisableError",
                    Message = "禁用启动项失败",
                    Details = $"错误: {ex.Message}"
                });
                return false;
            }
        }

        public bool RemoveStartupItem(string id)
        {
            var item = _startupItems.FirstOrDefault(i => i.Id == id);
            if (item == null) return false;

            try
            {
                // 从注册表删除
                if (item.Location.StartsWith("HKLM\\") || item.Location.StartsWith("HKCU\\"))
                {
                    var rootKey = item.Location.StartsWith("HKLM") ? Registry.LocalMachine : Registry.CurrentUser;
                    var subKey = item.Location.Contains("RunOnce") 
                        ? @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" 
                        : @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
                    
                    using var key = rootKey.OpenSubKey(subKey, true);
                    key?.DeleteValue(item.Name, false);
                }
                
                // 删除快捷方式文件
                if (!string.IsNullOrEmpty(item.ShortcutPath) && File.Exists(item.ShortcutPath))
                {
                    File.Delete(item.ShortcutPath);
                }

                _startupItems.Remove(item);
                
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "StartupItemRemoved",
                    Message = "启动项已删除",
                    Details = $"名称: {item.Name}"
                });
                return true;
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "StartupItemRemoveError",
                    Message = "删除启动项失败",
                    Details = $"错误: {ex.Message}"
                });
                return false;
            }
        }

        public bool AddStartupItem(string name, string path, string location)
        {
            try
            {
                // 添加到注册表
                using var key = Registry.CurrentUser.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", true);
                key?.SetValue(name, path);

                var newItem = new StartupItem
                {
                    Id = Guid.NewGuid().ToString(),
                    Name = name,
                    Path = path,
                    Location = "HKCU\\Run",
                    Enabled = true,
                    Type = "Application"
                };

                _startupItems.Add(newItem);
                
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "StartupItemAdded",
                    Message = "启动项已添加",
                    Details = $"名称: {name}, 路径: {path}"
                });

                return true;
            }
            catch { return false; }
        }

        public List<StartupItem> GetDisabledStartupItems()
        {
            return _startupItems.Where(item => !item.Enabled).ToList();
        }

        public List<StartupItem> GetEnabledStartupItems()
        {
            return _startupItems.Where(item => item.Enabled).ToList();
        }

        public int GetStartupItemsCount()
        {
            return _startupItems.Count;
        }

        public int GetEnabledStartupItemsCount()
        {
            return _startupItems.Count(item => item.Enabled);
        }

        public int GetDisabledStartupItemsCount()
        {
            return _startupItems.Count(item => !item.Enabled);
        }

        public StartupAnalysisResult AnalyzeStartupItems()
        {
            var result = new StartupAnalysisResult
            {
                TotalItems = _startupItems.Count,
                EnabledItems = _startupItems.Count(item => item.Enabled),
                DisabledItems = _startupItems.Count(item => !item.Enabled),
                SuspiciousItems = new List<StartupItem>(),
                Recommendations = new List<string>()
            };

            // 检查可疑启动项
            foreach (var item in _startupItems)
            {
                var riskLevel = AnalyzeStartupItemRisk(item);
                if (riskLevel != "Low")
                {
                    item.RiskLevel = riskLevel;
                    result.SuspiciousItems.Add(item);
                }
            }

            // 生成建议
            if (result.EnabledItems > 10)
            {
                result.Recommendations.Add("启动项过多，建议禁用不需要的启动项以提高系统启动速度");
            }

            if (result.SuspiciousItems.Count > 0)
            {
                result.Recommendations.Add($"发现 {result.SuspiciousItems.Count} 个可疑启动项，建议检查");
            }

            // 检查启动时间影响
            var impactItems = _startupItems.Where(i => i.Type == "Executable").ToList();
            if (impactItems.Count > 5)
            {
                result.Recommendations.Add("存在多个可执行文件启动项，可能影响启动速度");
            }

            if (result.Recommendations.Count == 0)
            {
                result.Recommendations.Add("启动项状态良好");
            }

            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "StartupItemsAnalyzed",
                Message = "启动项分析完成",
                Details = $"总启动项: {result.TotalItems}, 启用: {result.EnabledItems}, 禁用: {result.DisabledItems}, 可疑: {result.SuspiciousItems.Count}"
            });

            return result;
        }

        private string AnalyzeStartupItemRisk(StartupItem item)
        {
            // 高风险模式
            var highRiskPatterns = new[]
            {
                "mimikatz", "meterpreter", "beacon", "cobaltstrike",
                "nc.exe", "ncat", "netcat", "psexec", "procdump"
            };

            // 中风险模式
            var mediumRiskPatterns = new[]
            {
                "temp\\", "appdata\\local\\temp\\", "public\\",
                "downloads\\", "\\programdata\\", "mshta", "powershell",
                "cmd.exe", "wscript", "cscript", "regsvr32", "rundll32"
            };

            // 可疑路径
            var suspiciousPaths = new[]
            {
                "\\temp\\", "\\tmp\\", "\\public\\", "\\downloads\\",
                "\\appdata\\local\\temp\\", "\\programdata\\"
            };

            var lowerPath = item.Path.ToLower();

            // 检查高风险模式
            foreach (var pattern in highRiskPatterns)
            {
                if (lowerPath.Contains(pattern)) return "High";
            }

            // 检查中风险模式
            foreach (var pattern in mediumRiskPatterns)
            {
                if (lowerPath.Contains(pattern)) return "Medium";
            }

            // 检查可疑路径
            foreach (var path in suspiciousPaths)
            {
                if (lowerPath.Contains(path)) return "Medium";
            }

            // 检查未签名文件
            if (!IsSignedByTrustedPublisher(item.Path))
            {
                return "Medium";
            }

            return "Low";
        }

        private bool IsSignedByTrustedPublisher(string filePath)
        {
            try
            {
                if (!File.Exists(filePath)) return false;
                
                var cert = System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(filePath);
                if (cert == null) return false;
                
                var cert2 = new System.Security.Cryptography.X509Certificates.X509Certificate2(cert);
                var subject = cert2.Subject.ToLower();
                
                var trustedPublishers = new[]
                {
                    "microsoft", "google", "apple", "mozilla", "adobe",
                    "intel", "nvidia", "amd", "oracle", "vmware"
                };

                return trustedPublishers.Any(p => subject.Contains(p));
            }
            catch { return false; }
        }

        public void BackupStartupItems()
        {
            try
            {
                Directory.CreateDirectory(_backupPath);
                var backupFile = Path.Combine(_backupPath, $"startup_backup_{DateTime.Now:yyyyMMdd_HHmmss}.json");
                
                var backupData = _startupItems.Select(i => new
                {
                    i.Name,
                    i.Path,
                    i.Location,
                    i.Enabled,
                    i.Type
                }).ToList();

                var json = JsonSerializer.Serialize(backupData, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(backupFile, json);

                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "StartupItemsBackedUp",
                    Message = "启动项已备份",
                    Details = $"备份文件: {backupFile}"
                });
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "StartupBackupError",
                    Message = "启动项备份失败",
                    Details = $"错误: {ex.Message}"
                });
            }
        }

        public void RestoreStartupItems()
        {
            try
            {
                var backupFiles = Directory.GetFiles(_backupPath, "startup_backup_*.json")
                    .OrderByDescending(f => f)
                    .FirstOrDefault();

                if (backupFiles == null)
                {
                    _dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "StartupRestoreError",
                        Message = "未找到备份文件"
                    });
                    return;
                }

                var json = File.ReadAllText(backupFiles);
                var backupData = JsonSerializer.Deserialize<List<Dictionary<string, object>>>(json);

                if (backupData == null) return;

                foreach (var item in backupData)
                {
                    try
                    {
                        var name = item["Name"]?.ToString();
                        var path = item["Path"]?.ToString();
                        var location = item["Location"]?.ToString();

                        if (!string.IsNullOrEmpty(name) && !string.IsNullOrEmpty(path))
                        {
                            AddStartupItem(name, path, location);
                        }
                    }
                    catch { }
                }

                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "StartupItemsRestored",
                    Message = "启动项已恢复",
                    Details = $"从备份恢复: {backupFiles}"
                });
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "StartupRestoreError",
                    Message = "启动项恢复失败",
                    Details = $"错误: {ex.Message}"
                });
            }
        }
    }
}
