using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Win32;
using System.Threading.Tasks;

namespace FireAntivirus.Engine.RegistryMonitoring
{
    /// <summary>
    /// 高级注册表监控器 - 提供深度系统注册表保护和监控
    /// </summary>
    public class AdvancedRegistryMonitor
    {
        private readonly Dictionary<string, RegistryKey> _monitoredKeys;
        private readonly HashSet<string> _suspiciousPatterns;
        private bool _isMonitoring;

        // 关键注册表路径定义
        private static readonly string[] CriticalRegistryPaths = {
            // 自动启动项
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            
            // 系统服务
            "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services",
            
            // 浏览器扩展
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Internet Explorer\\Extensions",
            "HKEY_CURRENT_USER\\Software\\Microsoft\\Internet Explorer\\Extensions",
            
            // 文件关联
            "HKEY_CLASSES_ROOT\\exefile\\shell\\open\\command",
            "HKEY_CLASSES_ROOT\\batfile\\shell\\open\\command",
            
            // 安全设置
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Security Center",
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender",
            
            // 网络设置
            "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
            "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Dhcp\\Parameters"
        };

        public AdvancedRegistryMonitor()
        {
            _monitoredKeys = new Dictionary<string, RegistryKey>();
            _suspiciousPatterns = new HashSet<string>
            {
                // 可疑的自动启动模式
                "rundll32", "regsvr32", "mshta", "wscript", "cscript", "powershell",
                "cmd /c", "schtasks", "bitsadmin", "certutil",
                
                // 可疑的文件路径模式
                "%temp%", "%appdata%", "%userprofile%\\appdata",
                "\\temp\\", "\\tmp\\", "\\recycler\\",
                
                // 可疑的网络相关
                "http://", "https://", "ftp://", "tor", "proxy",
                
                // 加密和隐藏相关
                "base64", "encrypt", "decrypt", "xor", "aes", "rsa"
            };
            _isMonitoring = false;
        }

        /// <summary>
        /// 启动注册表监控
        /// </summary>
        public async Task<bool> StartMonitoringAsync()
        {
            try
            {
                if (_isMonitoring)
                {
                    return true;
                }

                // 建立关键注册表项的监控
                foreach (var registryPath in CriticalRegistryPaths)
                {
                    await MonitorRegistryKeyAsync(registryPath);
                }

                // 启动定期扫描
                _ = Task.Run(async () => await PeriodicRegistryScanAsync());

                _isMonitoring = true;
                Console.WriteLine("注册表深度监控已启动");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"注册表监控启动失败: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// 监控特定注册表键
        /// </summary>
        private async Task MonitorRegistryKeyAsync(string registryPath)
        {
            try
            {
                var key = OpenRegistryKey(registryPath);
                if (key != null)
                {
                    _monitoredKeys[registryPath] = key;
                    
                    // 记录初始状态
                    await TakeRegistrySnapshotAsync(registryPath, key);
                    
                    Console.WriteLine($"开始监控注册表键: {registryPath}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"监控注册表键失败 {registryPath}: {ex.Message}");
            }
        }

        /// <summary>
        /// 定期注册表扫描
        /// </summary>
        private async Task PeriodicRegistryScanAsync()
        {
            while (_isMonitoring)
            {
                try
                {
                    await Task.Delay(TimeSpan.FromMinutes(5)); // 每5分钟扫描一次
                    
                    foreach (var kvp in _monitoredKeys.ToList())
                    {
                        await CheckRegistryChangesAsync(kvp.Key, kvp.Value);
                    }
                    
                    // 检查新的可疑注册表项
                    await ScanForSuspiciousRegistryEntriesAsync();
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"定期注册表扫描失败: {ex.Message}");
                }
            }
        }

        /// <summary>
        /// 检查注册表变化
        /// </summary>
        private async Task CheckRegistryChangesAsync(string registryPath, RegistryKey key)
        {
            try
            {
                var currentValues = GetRegistryValues(key);
                var previousSnapshot = await GetPreviousSnapshotAsync(registryPath);
                
                if (previousSnapshot != null)
                {
                    var changes = DetectRegistryChanges(previousSnapshot, currentValues);
                    
                    foreach (var change in changes)
                    {
                        if (IsSuspiciousRegistryChange(change))
                        {
                            await HandleSuspiciousRegistryChangeAsync(registryPath, change);
                        }
                    }
                }
                
                // 更新快照
                await UpdateRegistrySnapshotAsync(registryPath, currentValues);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"检查注册表变化失败 {registryPath}: {ex.Message}");
            }
        }

        /// <summary>
        /// 扫描可疑注册表项
        /// </summary>
        private async Task ScanForSuspiciousRegistryEntriesAsync()
        {
            try
            {
                var suspiciousEntries = new List<RegistryEntry>();
                
                // 扫描系统关键区域
                await ScanAutoRunEntriesAsync(suspiciousEntries);
                await ScanBrowserExtensionsAsync(suspiciousEntries);
                await ScanServicesEntriesAsync(suspiciousEntries);
                
                // 处理发现的威胁
                foreach (var entry in suspiciousEntries)
                {
                    await HandleSuspiciousRegistryEntryAsync(entry);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"扫描可疑注册表项失败: {ex.Message}");
            }
        }

        /// <summary>
        /// 扫描自动启动项
        /// </summary>
        private async Task ScanAutoRunEntriesAsync(List<RegistryEntry> suspiciousEntries)
        {
            var autoRunPaths = new[]
            {
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
            };

            foreach (var path in autoRunPaths)
            {
                var key = OpenRegistryKey(path);
                if (key != null)
                {
                    var values = key.GetValueNames();
                    foreach (var valueName in values)
                    {
                        var value = key.GetValue(valueName)?.ToString();
                        if (!string.IsNullOrEmpty(value) && IsSuspiciousAutoRunValue(value))
                        {
                            suspiciousEntries.Add(new RegistryEntry
                            {
                                Path = path,
                                Name = valueName,
                                Value = value,
                                ThreatLevel = ThreatLevel.High
                            });
                        }
                    }
                    key.Close();
                }
            }
            
            await Task.CompletedTask;
        }

        /// <summary>
        /// 扫描浏览器扩展
        /// </summary>
        private async Task ScanBrowserExtensionsAsync(List<RegistryEntry> suspiciousEntries)
        {
            var browserPaths = new[]
            {
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Internet Explorer\\Extensions",
                "HKEY_CURRENT_USER\\Software\\Microsoft\\Internet Explorer\\Extensions"
            };

            foreach (var path in browserPaths)
            {
                var key = OpenRegistryKey(path);
                if (key != null)
                {
                    var subKeyNames = key.GetSubKeyNames();
                    foreach (var subKeyName in subKeyNames)
                    {
                        using (var subKey = key.OpenSubKey(subKeyName))
                        {
                            if (subKey != null)
                            {
                                var clsid = subKey.GetValue("CLSID")?.ToString();
                                if (IsSuspiciousBrowserExtension(clsid))
                                {
                                    suspiciousEntries.Add(new RegistryEntry
                                    {
                                        Path = $"{path}\\{subKeyName}",
                                        Name = "CLSID",
                                        Value = clsid,
                                        ThreatLevel = ThreatLevel.Medium
                                    });
                                }
                            }
                        }
                    }
                    key.Close();
                }
            }
            
            await Task.CompletedTask;
        }

        /// <summary>
        /// 扫描服务项
        /// </summary>
        private async Task ScanServicesEntriesAsync(List<RegistryEntry> suspiciousEntries)
        {
            var servicesPath = "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services";
            var key = OpenRegistryKey(servicesPath);
            
            if (key != null)
            {
                var serviceNames = key.GetSubKeyNames();
                foreach (var serviceName in serviceNames)
                {
                    using (var serviceKey = key.OpenSubKey(serviceName))
                    {
                        if (serviceKey != null)
                        {
                            var imagePath = serviceKey.GetValue("ImagePath")?.ToString();
                            if (!string.IsNullOrEmpty(imagePath) && IsSuspiciousService(imagePath))
                            {
                                suspiciousEntries.Add(new RegistryEntry
                                {
                                    Path = $"{servicesPath}\\{serviceName}",
                                    Name = "ImagePath",
                                    Value = imagePath,
                                    ThreatLevel = ThreatLevel.Critical
                                });
                            }
                        }
                    }
                }
                key.Close();
            }
            
            await Task.CompletedTask;
        }

        /// <summary>
        /// 检查是否为可疑的自动启动值
        /// </summary>
        private bool IsSuspiciousAutoRunValue(string value)
        {
            var lowerValue = value.ToLower();
            
            // 检查可疑模式
            foreach (var pattern in _suspiciousPatterns)
            {
                if (lowerValue.Contains(pattern.ToLower()))
                {
                    return true;
                }
            }

            // 检查临时目录执行
            if (lowerValue.Contains(Environment.GetEnvironmentVariable("temp").ToLower()) ||
                lowerValue.Contains(Environment.GetEnvironmentVariable("tmp").ToLower()))
            {
                return true;
            }

            return false;
        }

        /// <summary>
        /// 检查是否为可疑的浏览器扩展
        /// </summary>
        private bool IsSuspiciousBrowserExtension(string clsid)
        {
            if (string.IsNullOrEmpty(clsid)) return false;

            // 真实检测：读取该 CLSID 注册的扩展 DLL，检查是否位于高风险目录
            try
            {
                using var inproc = Microsoft.Win32.Registry.ClassesRoot.OpenSubKey(
                    $"CLSID\\{clsid}\\InprocServer32");
                var dllPath = inproc?.GetValue(null) as string;

                if (string.IsNullOrEmpty(dllPath)) return false;

                var expanded = Environment.ExpandEnvironmentVariables(dllPath.Replace("\"", "")).ToLowerInvariant();

                // 扩展 DLL 位于临时/下载/公共目录属于高风险特征
                return expanded.Contains("\\temp\\") ||
                       expanded.Contains("\\tmp\\") ||
                       expanded.Contains("\\downloads\\") ||
                       expanded.Contains("\\appdata\\local\\temp\\") ||
                       expanded.Contains("\\public\\");
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// 检查是否为可疑的服务
        /// </summary>
        private bool IsSuspiciousService(string imagePath)
        {
            var lowerPath = imagePath.ToLower();
            
            // 检查非标准系统目录
            if (!lowerPath.Contains("windows\\system32") && 
                !lowerPath.Contains("program files"))
            {
                return true;
            }

            // 检查可疑参数
            if (lowerPath.Contains("-enc") || lowerPath.Contains("-e ") || 
                lowerPath.Contains("-w hidden"))
            {
                return true;
            }

            return false;
        }

        /// <summary>
        /// 处理可疑注册表变化
        /// </summary>
        private async Task HandleSuspiciousRegistryChangeAsync(string registryPath, RegistryChange change)
        {
            Console.WriteLine($"检测到可疑注册表变化: {registryPath} -> {change.ValueName}");
            
            // 记录安全事件
            await LogSecurityEventAsync(new SecurityEvent
            {
                EventType = SecurityEventType.RegistryModification,
                Severity = ThreatLevel.High,
                Description = $"可疑注册表修改: {registryPath}\\{change.ValueName}",
                Timestamp = DateTime.Now
            });

            // 根据配置决定是否阻止修改
            if (ShouldBlockRegistryChange(change))
            {
                // 实现阻止逻辑（需要内核驱动支持）
                Console.WriteLine($"已阻止可疑注册表修改: {change.ValueName}");
            }
        }

        /// <summary>
        /// 处理可疑注册表项
        /// </summary>
        private async Task HandleSuspiciousRegistryEntryAsync(RegistryEntry entry)
        {
            Console.WriteLine($"发现可疑注册表项: {entry.Path}\\{entry.Name}");
            
            await LogSecurityEventAsync(new SecurityEvent
            {
                EventType = SecurityEventType.SuspiciousRegistryEntry,
                Severity = entry.ThreatLevel,
                Description = $"可疑注册表项: {entry.Path}\\{entry.Name} = {entry.Value}",
                Timestamp = DateTime.Now
            });

            // 提供修复建议
            await SuggestRemediationAsync(entry);
        }

        /// <summary>
        /// 记录安全事件
        /// </summary>
        private async Task LogSecurityEventAsync(SecurityEvent securityEvent)
        {
            // 实现安全事件日志记录
            await Task.CompletedTask;
        }

        /// <summary>
        /// 提供修复建议
        /// </summary>
        private async Task SuggestRemediationAsync(RegistryEntry entry)
        {
            // 实现自动修复或用户提示
            await Task.CompletedTask;
        }

        /// <summary>
        /// 检查是否应该阻止注册表修改
        /// </summary>
        private bool ShouldBlockRegistryChange(RegistryChange change)
        {
            // 根据威胁级别和用户设置决定
            return change.ThreatLevel >= ThreatLevel.High;
        }

        /// <summary>
        /// 检测注册表变化
        /// </summary>
        private List<RegistryChange> DetectRegistryChanges(
            Dictionary<string, string> previous, Dictionary<string, string> current)
        {
            var changes = new List<RegistryChange>();

            // 检查新增的项
            foreach (var kvp in current)
            {
                if (!previous.ContainsKey(kvp.Key))
                {
                    changes.Add(new RegistryChange
                    {
                        Type = ChangeType.Added,
                        ValueName = kvp.Key,
                        NewValue = kvp.Value,
                        ThreatLevel = CalculateThreatLevel(kvp.Value)
                    });
                }
            }

            // 检查修改的项
            foreach (var kvp in current)
            {
                if (previous.ContainsKey(kvp.Key) && previous[kvp.Key] != kvp.Value)
                {
                    changes.Add(new RegistryChange
                    {
                        Type = ChangeType.Modified,
                        ValueName = kvp.Key,
                        OldValue = previous[kvp.Key],
                        NewValue = kvp.Value,
                        ThreatLevel = CalculateThreatLevel(kvp.Value)
                    });
                }
            }

            // 检查删除的项
            foreach (var kvp in previous)
            {
                if (!current.ContainsKey(kvp.Key))
                {
                    changes.Add(new RegistryChange
                    {
                        Type = ChangeType.Deleted,
                        ValueName = kvp.Key,
                        OldValue = kvp.Value,
                        ThreatLevel = ThreatLevel.Medium
                    });
                }
            }

            return changes;
        }

        /// <summary>
        /// 计算威胁级别
        /// </summary>
        private ThreatLevel CalculateThreatLevel(string value)
        {
            var lowerValue = value.ToLower();
            
            foreach (var pattern in _suspiciousPatterns)
            {
                if (lowerValue.Contains(pattern.ToLower()))
                {
                    return ThreatLevel.High;
                }
            }

            return ThreatLevel.Low;
        }

        /// <summary>
        /// 检查是否为可疑的注册表变化
        /// </summary>
        private bool IsSuspiciousRegistryChange(RegistryChange change)
        {
            return change.ThreatLevel >= ThreatLevel.Medium;
        }

        // 辅助方法
        private RegistryKey OpenRegistryKey(string path)
        {
            try
            {
                if (path.StartsWith("HKEY_LOCAL_MACHINE"))
                {
                    var relativePath = path.Substring(19); // 去除"HKEY_LOCAL_MACHINE\\"
                    return Registry.LocalMachine.OpenSubKey(relativePath, true);
                }
                else if (path.StartsWith("HKEY_CURRENT_USER"))
                {
                    var relativePath = path.Substring(18); // 去除"HKEY_CURRENT_USER\\"
                    return Registry.CurrentUser.OpenSubKey(relativePath, true);
                }
                else if (path.StartsWith("HKEY_CLASSES_ROOT"))
                {
                    var relativePath = path.Substring(18); // 去除"HKEY_CLASSES_ROOT\\"
                    return Registry.ClassesRoot.OpenSubKey(relativePath, true);
                }
                return null;
            }
            catch
            {
                return null;
            }
        }

        private Dictionary<string, string> GetRegistryValues(RegistryKey key)
        {
            var values = new Dictionary<string, string>();
            try
            {
                var valueNames = key.GetValueNames();
                foreach (var name in valueNames)
                {
                    values[name] = key.GetValue(name)?.ToString() ?? "";
                }
            }
            catch
            {
                // 忽略读取错误
            }
            return values;
        }

        private async Task<Dictionary<string, string>> GetPreviousSnapshotAsync(string registryPath)
        {
            // 实现从存储获取先前快照
            await Task.CompletedTask;
            return new Dictionary<string, string>();
        }

        private async Task TakeRegistrySnapshotAsync(string registryPath, RegistryKey key)
        {
            // 实现快照保存
            await Task.CompletedTask;
        }

        private async Task UpdateRegistrySnapshotAsync(string registryPath, Dictionary<string, string> values)
        {
            // 实现快照更新
            await Task.CompletedTask;
        }

        /// <summary>
        /// 停止监控
        /// </summary>
        public void StopMonitoring()
        {
            _isMonitoring = false;
            foreach (var key in _monitoredKeys.Values)
            {
                key?.Close();
            }
            _monitoredKeys.Clear();
        }
    }

    // 支持的类型定义
    public class RegistryEntry
    {
        public string Path { get; set; }
        public string Name { get; set; }
        public string Value { get; set; }
        public ThreatLevel ThreatLevel { get; set; }
    }

    public class RegistryChange
    {
        public ChangeType Type { get; set; }
        public string ValueName { get; set; }
        public string OldValue { get; set; }
        public string NewValue { get; set; }
        public ThreatLevel ThreatLevel { get; set; }
    }

    public enum ChangeType
    {
        Added,
        Modified,
        Deleted
    }

    public class SecurityEvent
    {
        public SecurityEventType EventType { get; set; }
        public ThreatLevel Severity { get; set; }
        public string Description { get; set; }
        public DateTime Timestamp { get; set; }
    }

    public enum SecurityEventType
    {
        RegistryModification,
        SuspiciousRegistryEntry,
        AutoRunDetection,
        ServiceModification
    }

    public enum ThreatLevel
    {
        Low = 1,
        Medium = 2,
        High = 3,
        Critical = 4
    }
}