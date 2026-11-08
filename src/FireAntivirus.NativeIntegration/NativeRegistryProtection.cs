using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Win32;

namespace FireAntivirus.NativeIntegration
{
    /// <summary>
    /// 注册表保护模块的C#封装
    /// </summary>
    public class NativeRegistryProtection : IDisposable
    {
        #region 私有字段
        private readonly NativeSecurityCoreWrapper _core;
        private readonly Dictionary<string, RegistryWatcher> _watchers = new Dictionary<string, RegistryWatcher>();
        private bool _isMonitoring;
        private bool _disposed;

        // 受保护的注册表键
        private readonly HashSet<string> _protectedKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        // 恶意注册表键模式
        private readonly List<string> _maliciousKeyPatterns = new List<string>();
        // 被阻止的注册表值
        private readonly Dictionary<string, string> _blockedValues = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        #endregion

        #region 事件
        public event EventHandler<RegistryThreatEventArgs> RegistryThreatDetected;
        public event EventHandler<RegistryChangeEventArgs> RegistryKeyCreated;
        public event EventHandler<RegistryChangeEventArgs> RegistryKeyDeleted;
        public event EventHandler<RegistryChangeEventArgs> RegistryValueChanged;
        #endregion

        #region 构造函数
        public NativeRegistryProtection(NativeSecurityCoreWrapper core)
        {
            _core = core ?? throw new ArgumentNullException(nameof(core));
            InitializeDefaultProtection();
        }

        ~NativeRegistryProtection()
        {
            Dispose(false);
        }
        #endregion

        #region 公共属性
        public bool IsEnabled
        {
            get => _core.RegistryProtectionEnabled;
            set => _core.RegistryProtectionEnabled = value;
        }

        public bool IsMonitoring
        {
            get => _isMonitoring;
        }
        #endregion

        #region 公共方法

        /// <summary>
        /// 开始注册表监控
        /// </summary>
        public void StartMonitoring()
        {
            if (_isMonitoring)
                return;

            try
            {
                // 监控关键注册表键
                var keyPaths = new[]
                {
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                    @"SOFTWARE\Policies\Microsoft\Windows\System",
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"
                };

                foreach (var keyPath in keyPaths)
                {
                    try
                    {
                        var watcher = new RegistryWatcher(keyPath);
                        watcher.RegistryKeyChanged += OnRegistryKeyChanged;
                        watcher.Start();
                        _watchers[keyPath] = watcher;
                    }
                    catch
                    {
                        // 无法监控某些键
                    }
                }

                _isMonitoring = true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"启动注册表监控失败: {ex.Message}");
            }
        }

        /// <summary>
        /// 停止注册表监控
        /// </summary>
        public void StopMonitoring()
        {
            if (!_isMonitoring)
                return;

            try
            {
                foreach (var watcher in _watchers.Values)
                {
                    watcher.Stop();
                }
                _watchers.Clear();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"停止注册表监控失败: {ex.Message}");
            }

            _isMonitoring = false;
        }

        /// <summary>
        /// 添加受保护的注册表键
        /// </summary>
        public void AddProtectedKey(string keyPath)
        {
            lock (_protectedKeys)
            {
                _protectedKeys.Add(keyPath);
            }
        }

        /// <summary>
        /// 移除受保护的注册表键
        /// </summary>
        public void RemoveProtectedKey(string keyPath)
        {
            lock (_protectedKeys)
            {
                _protectedKeys.Remove(keyPath);
            }
        }

        /// <summary>
        /// 添加恶意注册表键模式
        /// </summary>
        public void AddMaliciousKeyPattern(string pattern)
        {
            lock (_maliciousKeyPatterns)
            {
                _maliciousKeyPatterns.Add(pattern);
            }
        }

        /// <summary>
        /// 扫描注册表
        /// </summary>
        public List<RegistryThreatInfo> ScanRegistry()
        {
            var threats = new List<RegistryThreatInfo>();

            try
            {
                // 扫描启动项
                var startupThreats = ScanStartupKeys();
                threats.AddRange(startupThreats);

                // 扫描恶意键模式
                var patternThreats = ScanMaliciousPatterns();
                threats.AddRange(patternThreats);

                // 扫描可疑值
                var valueThreats = ScanBlockedValues();
                threats.AddRange(valueThreats);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"扫描注册表失败: {ex.Message}");
            }

            return threats;
        }

        /// <summary>
        /// 删除恶意注册表项
        /// </summary>
        public bool DeleteRegistryKey(string keyPath)
        {
            try
            {
                var parts = keyPath.Split('\\', 2);
                if (parts.Length < 2)
                    return false;

                var rootKey = GetRootKey(parts[0]);
                if (rootKey == null)
                    return false;

                using var key = Registry.LocalMachine.OpenSubKey(parts[1], true);
                if (key != null)
                {
                    key.DeleteSubKeyTree(parts[1].Split('\\').Last());
                    return true;
                }

                using var key2 = Registry.CurrentUser.OpenSubKey(parts[1], true);
                if (key2 != null)
                {
                    key2.DeleteSubKeyTree(parts[1].Split('\\').Last());
                    return true;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"删除注册表键失败: {ex.Message}");
            }

            return false;
        }

        /// <summary>
        /// 删除恶意注册表值
        /// </summary>
        public bool DeleteRegistryValue(string keyPath, string valueName)
        {
            try
            {
                var parts = keyPath.Split('\\', 2);
                if (parts.Length < 2)
                    return false;

                var rootKey = GetRootKey(parts[0]);
                if (rootKey == null)
                    return false;

                using var key = rootKey.OpenSubKey(parts[1], true);
                if (key != null)
                {
                    key.DeleteValue(valueName, false);
                    return true;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"删除注册表值失败: {ex.Message}");
            }

            return false;
        }

        #endregion

        #region 私有方法
        private void InitializeDefaultProtection()
        {
            // 添加默认受保护的键
            AddProtectedKey(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run");
            AddProtectedKey(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce");
            AddProtectedKey(@"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run");
            AddProtectedKey(@"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce");

            // 添加恶意键模式
            AddMaliciousKeyPattern(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run\\{");
            AddMaliciousKeyPattern(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\\Shell");
            AddMaliciousKeyPattern(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\\Userinit");
            AddMaliciousKeyPattern(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\\Notify");

            // 添加被阻止的值
            _blockedValues[@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Hidden"] = "2";
            _blockedValues[@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\HideFileExt"] = "1";
            _blockedValues[@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA"] = "0";
        }

        private void OnRegistryKeyChanged(object sender, RegistryChangeEventArgs e)
        {
            // 检查是否恶意
            var isMalicious = CheckIfMalicious(e.KeyPath, e.ValueName, e.Value);

            if (isMalicious)
            {
                RegistryThreatDetected?.Invoke(this, new RegistryThreatEventArgs
                {
                    KeyPath = e.KeyPath,
                    ValueName = e.ValueName,
                    Value = e.Value,
                    ChangeType = e.ChangeType,
                    ThreatType = "MaliciousRegistry"
                });
            }

            // 触发常规事件
            switch (e.ChangeType)
            {
                case RegistryChangeType.KeyCreated:
                    RegistryKeyCreated?.Invoke(this, new RegistryChangeEventArgs
                    {
                        KeyPath = e.KeyPath,
                        ValueName = e.ValueName,
                        Value = e.Value,
                        ChangeType = e.ChangeType
                    });
                    break;
                case RegistryChangeType.KeyDeleted:
                    RegistryKeyDeleted?.Invoke(this, new RegistryChangeEventArgs
                    {
                        KeyPath = e.KeyPath,
                        ChangeType = e.ChangeType
                    });
                    break;
                case RegistryChangeType.ValueChanged:
                    RegistryValueChanged?.Invoke(this, new RegistryChangeEventArgs
                    {
                        KeyPath = e.KeyPath,
                        ValueName = e.ValueName,
                        Value = e.Value,
                        ChangeType = e.ChangeType
                    });
                    break;
            }
        }

        private bool CheckIfMalicious(string keyPath, string valueName, object value)
        {
            lock (_maliciousKeyPatterns)
            {
                foreach (var pattern in _maliciousKeyPatterns)
                {
                    if (keyPath.Contains(pattern.Replace("\\", "")))
                        return true;
                }
            }

            return false;
        }

        private List<RegistryThreatInfo> ScanStartupKeys()
        {
            var threats = new List<RegistryThreatInfo>();

            var startupKeyPaths = new[]
            {
                @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
            };

            foreach (var keyPath in startupKeyPaths)
            {
                try
                {
                    var parts = keyPath.Split('\\', 2);
                    var rootKey = GetRootKey(parts[0]);
                    if (rootKey == null) continue;

                    using var key = rootKey.OpenSubKey(parts[1]);
                    if (key == null) continue;

                    foreach (var valueName in key.GetValueNames())
                    {
                        var value = key.GetValue(valueName);
                        if (value == null) continue;

                        var valueString = value.ToString();

                        // 检查可疑值
                        if (IsSuspiciousValue(valueString))
                        {
                            threats.Add(new RegistryThreatInfo
                            {
                                KeyPath = keyPath,
                                ValueName = valueName,
                                Value = valueString,
                                ThreatType = "SuspiciousStartup",
                                Description = "可疑的启动项"
                            });
                        }
                    }
                }
                catch
                {
                    // 无法读取某些键
                }
            }

            return threats;
        }

        private List<RegistryThreatInfo> ScanMaliciousPatterns()
        {
            var threats = new List<RegistryThreatInfo>();

            lock (_maliciousKeyPatterns)
            {
                foreach (var pattern in _maliciousKeyPatterns)
                {
                    // 简化实现
                    var keyPath = @"HKLM\" + pattern;
                    if (Registry.LocalMachine.OpenSubKey(pattern.Replace("SOFTWARE\\", "")) != null)
                    {
                        threats.Add(new RegistryThreatInfo
                        {
                            KeyPath = keyPath,
                            ThreatType = "MaliciousPattern",
                            Description = $"匹配恶意模式: {pattern}"
                        });
                    }
                }
            }

            return threats;
        }

        private List<RegistryThreatInfo> ScanBlockedValues()
        {
            var threats = new List<RegistryThreatInfo>();

            lock (_blockedValues)
            {
                foreach (var kvp in _blockedValues)
                {
                    try
                    {
                        var parts = kvp.Key.Split('\\', 2);
                        var rootKey = GetRootKey(parts[0]);
                        if (rootKey == null) continue;

                        using var key = rootKey.OpenSubKey(parts[1]);
                        if (key == null) continue;

                        var value = key.GetValue("");
                        if (value?.ToString() == kvp.Value)
                        {
                            threats.Add(new RegistryThreatInfo
                            {
                                KeyPath = @"HKLM\" + kvp.Key,
                                Value = kvp.Value,
                                ThreatType = "BlockedValue",
                                Description = $"禁止的注册表值: {kvp.Key} = {kvp.Value}"
                            });
                        }
                    }
                    catch
                    {
                        // 忽略
                    }
                }
            }

            return threats;
        }

        private bool IsSuspiciousValue(string value)
        {
            if (string.IsNullOrEmpty(value))
                return false;

            var lower = value.ToLower();

            // 检查可疑路径
            var suspiciousPaths = new[]
            {
                @"\temp\",
                @"\tmp\",
                @"\appdata\",
                @"\downloads\"
            };

            if (suspiciousPaths.Any(p => lower.Contains(p)))
                return true;

            // 检查可疑进程名
            var suspiciousProcesses = new[]
            {
                "cmd.exe", "powershell.exe", "wscript.exe",
                "cscript.exe", "mshta.exe", "regsvr32.exe",
                "rundll32.exe", "certutil.exe", "bitsadmin.exe"
            };

            return suspiciousProcesses.Any(p => lower.Contains(p));
        }

        private RegistryKey GetRootKey(string rootKeyName)
        {
            return rootKeyName.ToUpper() switch
            {
                "HKEY_LOCAL_MACHINE" or "HKLM" => Registry.LocalMachine,
                "HKEY_CURRENT_USER" or "HKCU" => Registry.CurrentUser,
                "HKEY_CLASSES_ROOT" or "HKCR" => Registry.ClassesRoot,
                "HKEY_USERS" or "HKU" => Registry.Users,
                "HKEY_CURRENT_CONFIG" or "HKCC" => Registry.CurrentConfig,
                _ => null
            };
        }
        #endregion

        #region IDisposable
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                StopMonitoring();
            }

            _disposed = true;
        }
        #endregion
    }

    #region 支持的类
    public class RegistryThreatInfo
    {
        public string KeyPath { get; set; }
        public string ValueName { get; set; }
        public string Value { get; set; }
        public string ThreatType { get; set; }
        public string Description { get; set; }
    }

    public class RegistryThreatEventArgs : EventArgs
    {
        public string KeyPath { get; set; }
        public string ValueName { get; set; }
        public object Value { get; set; }
        public RegistryChangeType ChangeType { get; set; }
        public string ThreatType { get; set; }
    }

    public class RegistryChangeEventArgs : EventArgs
    {
        public string KeyPath { get; set; }
        public string ValueName { get; set; }
        public object Value { get; set; }
        public RegistryChangeType ChangeType { get; set; }
    }

    public enum RegistryChangeType
    {
        KeyCreated,
        KeyDeleted,
        ValueChanged
    }

    /// <summary>
    /// 注册表监控器
    /// </summary>
    public class RegistryWatcher : IDisposable
    {
        private readonly string _keyPath;
        private RegistryKey _monitoredKey;
        private Timer _timer;
        private Dictionary<string, object> _previousValues = new Dictionary<string, object>();
        private bool _disposed;

        public event EventHandler<RegistryChangeEventArgs> RegistryKeyChanged;

        public RegistryWatcher(string keyPath)
        {
            _keyPath = keyPath;
            Initialize();
        }

        private void Initialize()
        {
            try
            {
                var parts = _keyPath.Split('\\', 2);
                var rootKey = GetRootKey(parts[0]);
                if (rootKey != null && parts.Length > 1)
                {
                    _monitoredKey = rootKey.OpenSubKey(parts[1], false);
                    CaptureCurrentValues();
                }
            }
            catch
            {
                // 忽略
            }
        }

        public void Start()
        {
            _timer = new Timer(CheckChanges, null, TimeSpan.Zero, TimeSpan.FromSeconds(2));
        }

        public void Stop()
        {
            _timer?.Dispose();
            _timer = null;
        }

        private void CheckChanges(object state)
        {
            if (_monitoredKey == null)
                return;

            try
            {
                var currentValues = new Dictionary<string, object>();

                foreach (var valueName in _monitoredKey.GetValueNames())
                {
                    var value = _monitoredKey.GetValue(valueName);
                    currentValues[valueName] = value ?? "";

                    // 检查新值或修改的值
                    if (!_previousValues.ContainsKey(valueName))
                    {
                        RegistryKeyChanged?.Invoke(this, new RegistryChangeEventArgs
                        {
                            KeyPath = _keyPath,
                            ValueName = valueName,
                            Value = value,
                            ChangeType = RegistryChangeType.ValueChanged
                        });
                    }
                    else if (!Equals(_previousValues[valueName], value))
                    {
                        RegistryKeyChanged?.Invoke(this, new RegistryChangeEventArgs
                        {
                            KeyPath = _keyPath,
                            ValueName = valueName,
                            Value = value,
                            ChangeType = RegistryChangeType.ValueChanged
                        });
                    }
                }

                // 检查删除的值
                foreach (var prevValue in _previousValues)
                {
                    if (!currentValues.ContainsKey(prevValue.Key))
                    {
                        RegistryKeyChanged?.Invoke(this, new RegistryChangeEventArgs
                        {
                            KeyPath = _keyPath,
                            ValueName = prevValue.Key,
                            ChangeType = RegistryChangeType.KeyDeleted
                        });
                    }
                }

                _previousValues = currentValues;
            }
            catch
            {
                // 忽略
            }
        }

        private void CaptureCurrentValues()
        {
            if (_monitoredKey == null)
                return;

            _previousValues.Clear();
            foreach (var valueName in _monitoredKey.GetValueNames())
            {
                var value = _monitoredKey.GetValue(valueName);
                _previousValues[valueName] = value ?? "";
            }
        }

        private RegistryKey GetRootKey(string rootKeyName)
        {
            return rootKeyName.ToUpper() switch
            {
                "HKEY_LOCAL_MACHINE" or "HKLM" => Registry.LocalMachine,
                "HKEY_CURRENT_USER" or "HKCU" => Registry.CurrentUser,
                "HKEY_CLASSES_ROOT" or "HKCR" => Registry.ClassesRoot,
                "HKEY_USERS" or "HKU" => Registry.Users,
                "HKEY_CURRENT_CONFIG" or "HKCC" => Registry.CurrentConfig,
                _ => null
            };
        }

        public void Dispose()
        {
            Stop();
            _monitoredKey?.Dispose();
            _disposed = true;
        }
    }
    #endregion
}
