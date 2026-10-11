// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace FireAntivirus.NativeIntegration
{
    /// <summary>
    /// 设备保护模块的C#封装
    /// </summary>
    public class NativeDeviceProtection : IDisposable
    {
        #region 私有字段
        private readonly NativeSecurityCoreWrapper _core;
        private ManagementEventWatcher _usbWatcher;
        private ManagementEventWatcher _deviceWatcher;
        private bool _isMonitoring;
        private bool _disposed;

        // 授权设备列表
        private readonly HashSet<string> _authorizedDevices = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        // 阻止的设备ID
        private readonly HashSet<string> _blockedDevices = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        #endregion

        #region 事件
        public event EventHandler<DeviceEventArgs> DeviceConnected;
        public event EventHandler<DeviceEventArgs> DeviceDisconnected;
        public event EventHandler<DeviceThreatEventArgs> DeviceThreatDetected;
        #endregion

        #region 构造函数
        public NativeDeviceProtection(NativeSecurityCoreWrapper core)
        {
            _core = core ?? throw new ArgumentNullException(nameof(core));
            InitializeDefaultDevices();
        }

        ~NativeDeviceProtection()
        {
            Dispose(false);
        }
        #endregion

        #region 公共属性
        public bool IsEnabled
        {
            get => _core.DeviceProtectionEnabled;
            set => _core.DeviceProtectionEnabled = value;
        }

        public bool IsMonitoring
        {
            get => _isMonitoring;
        }

        public IReadOnlyList<string> AuthorizedDevices
        {
            get
            {
                lock (_authorizedDevices)
                {
                    return _authorizedDevices.ToList().AsReadOnly();
                }
            }
        }

        public IReadOnlyList<string> BlockedDevices
        {
            get
            {
                lock (_blockedDevices)
                {
                    return _blockedDevices.ToList().AsReadOnly();
                }
            }
        }
        #endregion

        #region 公共方法

        /// <summary>
        /// 开始设备监控
        /// </summary>
        public void StartMonitoring()
        {
            if (_isMonitoring)
                return;

            try
            {
                // 监控USB设备插入
                var usbQuery = new WqlEventQuery("SELECT * FROM __InstanceCreationEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_USBHub'");
                _usbWatcher = new ManagementEventWatcher(usbQuery);
                _usbWatcher.EventArrived += OnUsbDeviceChanged;
                _usbWatcher.Start();

                // 监控设备变化
                var deviceQuery = new WqlEventQuery("SELECT * FROM Win32_DeviceChangeEvent");
                _deviceWatcher = new ManagementEventWatcher(deviceQuery);
                _deviceWatcher.EventArrived += OnDeviceChanged;
                _deviceWatcher.Start();

                _isMonitoring = true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"启动设备监控失败: {ex.Message}");
            }
        }

        /// <summary>
        /// 停止设备监控
        /// </summary>
        public void StopMonitoring()
        {
            if (!_isMonitoring)
                return;

            try
            {
                if (_usbWatcher != null)
                {
                    _usbWatcher.Stop();
                    _usbWatcher.EventArrived -= OnUsbDeviceChanged;
                    _usbWatcher.Dispose();
                    _usbWatcher = null;
                }

                if (_deviceWatcher != null)
                {
                    _deviceWatcher.Stop();
                    _deviceWatcher.EventArrived -= OnDeviceChanged;
                    _deviceWatcher.Dispose();
                    _deviceWatcher = null;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"停止设备监控失败: {ex.Message}");
            }

            _isMonitoring = false;
        }

        /// <summary>
        /// 授权设备
        /// </summary>
        public void AuthorizeDevice(string deviceId)
        {
            if (string.IsNullOrWhiteSpace(deviceId))
                return;

            lock (_authorizedDevices)
            {
                _authorizedDevices.Add(deviceId);
            }
        }

        /// <summary>
        /// 取消设备授权
        /// </summary>
        public void DeauthorizeDevice(string deviceId)
        {
            if (string.IsNullOrWhiteSpace(deviceId))
                return;

            lock (_authorizedDevices)
            {
                _authorizedDevices.Remove(deviceId);
            }
        }

        /// <summary>
        /// 阻止设备
        /// </summary>
        public void BlockDevice(string deviceId)
        {
            if (string.IsNullOrWhiteSpace(deviceId))
                return;

            lock (_blockedDevices)
            {
                _blockedDevices.Add(deviceId);
            }
        }

        /// <summary>
        /// 取消阻止设备
        /// </summary>
        public void UnblockDevice(string deviceId)
        {
            if (string.IsNullOrWhiteSpace(deviceId))
                return;

            lock (_blockedDevices)
            {
                _blockedDevices.Remove(deviceId);
            }
        }

        /// <summary>
        /// 扫描已连接的设备
        /// </summary>
        public List<DeviceInfo> ScanConnectedDevices()
        {
            var devices = new List<DeviceInfo>();

            try
            {
                // 扫描USB设备
                using var usbSearcher = new ManagementObjectSearcher("SELECT * FROM Win32_USBHub");
                foreach (ManagementObject device in usbSearcher.Get())
                {
                    var deviceId = device["DeviceID"]?.ToString();
                    if (!string.IsNullOrEmpty(deviceId))
                    {
                        var info = new DeviceInfo
                        {
                            DeviceId = deviceId,
                            Name = device["Name"]?.ToString() ?? "Unknown USB Device",
                            Description = device["Description"]?.ToString(),
                            Status = device["Status"]?.ToString(),
                            DeviceType = "USB"
                        };

                        info.IsAuthorized = IsDeviceAuthorized(deviceId);
                        info.IsBlocked = IsDeviceBlocked(deviceId);
                        info.IsThreat = !info.IsAuthorized && !IsKnownDevice(deviceId);

                        devices.Add(info);
                    }
                }

                // 扫描磁盘设备
                using var diskSearcher = new ManagementObjectSearcher("SELECT * FROM Win32_DiskDrive");
                foreach (ManagementObject device in diskSearcher.Get())
                {
                    var deviceId = device["DeviceID"]?.ToString();
                    if (!string.IsNullOrEmpty(deviceId))
                    {
                        var info = new DeviceInfo
                        {
                            DeviceId = deviceId,
                            Name = device["Model"]?.ToString() ?? "Unknown Disk",
                            Description = device["Description"]?.ToString(),
                            Status = device["Status"]?.ToString(),
                            DeviceType = "Disk"
                        };

                        info.IsAuthorized = IsDeviceAuthorized(deviceId);
                        info.IsBlocked = IsDeviceBlocked(deviceId);
                        info.IsThreat = !info.IsAuthorized && !IsKnownDevice(deviceId);

                        devices.Add(info);
                    }
                }

                // 扫描便携设备
                using var portableSearcher = new ManagementObjectSearcher("SELECT * FROM Win32_PortableStorageDevice");
                foreach (ManagementObject device in portableSearcher.Get())
                {
                    var deviceId = device["DeviceID"]?.ToString();
                    if (!string.IsNullOrEmpty(deviceId))
                    {
                        var info = new DeviceInfo
                        {
                            DeviceId = deviceId,
                            Name = device["Name"]?.ToString() ?? "Portable Device",
                            Description = device["Description"]?.ToString(),
                            DeviceType = "Portable"
                        };

                        info.IsAuthorized = IsDeviceAuthorized(deviceId);
                        info.IsBlocked = IsDeviceBlocked(deviceId);
                        info.IsThreat = !info.IsAuthorized && !IsKnownDevice(deviceId);

                        devices.Add(info);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"扫描设备失败: {ex.Message}");
            }

            return devices;
        }

        /// <summary>
        /// 弹出设备
        /// </summary>
        public bool EjectDevice(string deviceId)
        {
            try
            {
                // 简化实现 - 实际应该使用WMI或DeviceIOControl
                return false;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"弹出设备失败: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// 禁用设备
        /// </summary>
        public bool DisableDevice(string deviceId)
        {
            try
            {
                // 简化实现 - 需要管理员权限
                return false;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"禁用设备失败: {ex.Message}");
                return false;
            }
        }

        #endregion

        #region 私有方法
        private void InitializeDefaultDevices()
        {
            // 添加已知的安全设备ID（简化版）
            // 实际应该从配置文件加载
        }

        private void OnUsbDeviceChanged(object sender, EventArrivedEventArgs e)
        {
            try
            {
                var targetInstance = (ManagementBaseObject)e.NewEvent["TargetInstance"];
                var deviceId = targetInstance["DeviceID"]?.ToString();
                var deviceName = targetInstance["Name"]?.ToString();

                if (string.IsNullOrEmpty(deviceId))
                    return;

                // 检查是否被阻止
                if (IsDeviceBlocked(deviceId))
                {
                    DeviceThreatDetected?.Invoke(this, new DeviceThreatEventArgs
                    {
                        DeviceId = deviceId,
                        DeviceName = deviceName,
                        ThreatType = "BlockedDevice",
                        Action = DeviceProtectionAction.Block
                    });
                    return;
                }

                // 检查是否为威胁
                if (!IsDeviceAuthorized(deviceId) && !IsKnownDevice(deviceId))
                {
                    DeviceThreatDetected?.Invoke(this, new DeviceThreatEventArgs
                    {
                        DeviceId = deviceId,
                        DeviceName = deviceName,
                        ThreatType = "UnknownDevice",
                        Action = DeviceProtectionAction.Warn
                    });
                }

                DeviceConnected?.Invoke(this, new DeviceEventArgs
                {
                    DeviceId = deviceId,
                    DeviceName = deviceName
                });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"处理USB设备事件失败: {ex.Message}");
            }
        }

        private void OnDeviceChanged(object sender, EventArrivedEventArgs e)
        {
            try
            {
                var eventType = Convert.ToInt32(e.NewEvent["EventType"]);
                var targetInstance = e.NewEvent["TargetInstance"] as ManagementBaseObject;

                if (targetInstance == null)
                    return;

                var deviceId = targetInstance["DeviceID"]?.ToString();

                // EventType: 2 = Device Inserted, 3 = Device Removed
                if (eventType == 3 && !string.IsNullOrEmpty(deviceId))
                {
                    DeviceDisconnected?.Invoke(this, new DeviceEventArgs
                    {
                        DeviceId = deviceId
                    });
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"处理设备变更事件失败: {ex.Message}");
            }
        }

        private bool IsDeviceAuthorized(string deviceId)
        {
            lock (_authorizedDevices)
            {
                return _authorizedDevices.Contains(deviceId) ||
                       _authorizedDevices.Any(d => deviceId.Contains(d));
            }
        }

        private bool IsDeviceBlocked(string deviceId)
        {
            lock (_blockedDevices)
            {
                return _blockedDevices.Contains(deviceId) ||
                       _blockedDevices.Any(d => deviceId.Contains(d));
            }
        }

        private bool IsKnownDevice(string deviceId)
        {
            // 检查是否为已知的安全设备
            // 这里可以添加已知设备ID的检查
            return false;
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
    public class DeviceInfo
    {
        public string DeviceId { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public string Status { get; set; }
        public string DeviceType { get; set; }
        public bool IsAuthorized { get; set; }
        public bool IsBlocked { get; set; }
        public bool IsThreat { get; set; }
    }

    public class DeviceEventArgs : EventArgs
    {
        public string DeviceId { get; set; }
        public string DeviceName { get; set; }
    }

    public class DeviceThreatEventArgs : EventArgs
    {
        public string DeviceId { get; set; }
        public string DeviceName { get; set; }
        public string ThreatType { get; set; }
        public DeviceProtectionAction Action { get; set; }
    }

    public enum DeviceProtectionAction
    {
        Allow,
        Warn,
        Block,
        Disable
    }
    #endregion

    /// <summary>
    /// 主动防御模块的C#封装
    /// </summary>
    public class NativeActiveDefense : IDisposable
    {
        #region 私有字段
        private readonly NativeSecurityCoreWrapper _core;
        private Timer _behaviorMonitorTimer;
        private bool _isMonitoring;
        private bool _disposed;

        // 行为规则
        private readonly List<BehaviorRule> _rules = new List<BehaviorRule>();
        // 可疑进程列表
        private readonly HashSet<int> _suspiciousProcesses = new HashSet<int>();
        #endregion

        #region 事件
        public event EventHandler<BehaviorThreatEventArgs> ThreatDetected;
        #endregion

        #region 构造函数
        public NativeActiveDefense(NativeSecurityCoreWrapper core)
        {
            _core = core ?? throw new ArgumentNullException(nameof(core));
            InitializeDefaultRules();
        }

        ~NativeActiveDefense()
        {
            Dispose(false);
        }
        #endregion

        #region 公共属性
        public bool IsEnabled
        {
            get => _core.ActiveDefenseEnabled;
            set => _core.ActiveDefenseEnabled = value;
        }

        public bool IsMonitoring
        {
            get => _isMonitoring;
        }
        #endregion

        #region 公共方法

        /// <summary>
        /// 开始行为监控
        /// </summary>
        public void StartMonitoring(int intervalSeconds = 3)
        {
            if (_isMonitoring)
                return;

            _isMonitoring = true;
            _behaviorMonitorTimer = new Timer(MonitorBehavior, null,
                TimeSpan.Zero,
                TimeSpan.FromSeconds(intervalSeconds));
        }

        /// <summary>
        /// 停止行为监控
        /// </summary>
        public void StopMonitoring()
        {
            if (!_isMonitoring)
                return;

            _behaviorMonitorTimer?.Dispose();
            _behaviorMonitorTimer = null;
            _isMonitoring = false;
        }

        /// <summary>
        /// 添加行为规则
        /// </summary>
        public void AddRule(BehaviorRule rule)
        {
            lock (_rules)
            {
                _rules.Add(rule);
            }
        }

        /// <summary>
        /// 移除行为规则
        /// </summary>
        public void RemoveRule(string ruleName)
        {
            lock (_rules)
            {
                _rules.RemoveAll(r => r.Name == ruleName);
            }
        }

        /// <summary>
        /// 扫描可疑进程
        /// </summary>
        public List<BehaviorThreatInfo> ScanForThreats()
        {
            var threats = new List<BehaviorThreatInfo>();

            try
            {
                var processes = System.Diagnostics.Process.GetProcesses();

                foreach (var process in processes)
                {
                    try
                    {
                        var threat = AnalyzeProcessBehavior(process);
                        if (threat != null)
                        {
                            threats.Add(threat);
                        }
                    }
                    catch
                    {
                        // 忽略无法访问的进程
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"扫描威胁失败: {ex.Message}");
            }

            return threats;
        }

        /// <summary>
        /// 终止可疑进程
        /// </summary>
        public bool TerminateProcess(int processId)
        {
            try
            {
                var process = System.Diagnostics.Process.GetProcessById(processId);
                process.Kill();
                return true;
            }
            catch
            {
                return false;
            }
        }

        #endregion

        #region 私有方法
        private void InitializeDefaultRules()
        {
            // 添加默认行为规则
            _rules.Add(new BehaviorRule
            {
                Name = "SuspiciousProcessCreation",
                Description = "可疑进程创建",
                Severity = 3,
                Action = BehaviorAction.Kill
            });

            _rules.Add(new BehaviorRule
            {
                Name = "ProcessInjection",
                Description = "进程注入",
                Severity = 5,
                Action = BehaviorAction.Kill
            });

            _rules.Add(new BehaviorRule
            {
                Name = "SuspiciousFileAccess",
                Description = "可疑文件访问",
                Severity = 2,
                Action = BehaviorAction.Warn
            });

            _rules.Add(new BehaviorRule
            {
                Name = "SuspiciousRegistryAccess",
                Description = "可疑注册表访问",
                Severity = 2,
                Action = BehaviorAction.Warn
            });

            _rules.Add(new BehaviorRule
            {
                Name = "NetworkConnectionFromSuspiciousProcess",
                Description = "可疑进程网络连接",
                Severity = 3,
                Action = BehaviorAction.Block
            });

            _rules.Add(new BehaviorRule
            {
                Name = "HighMemoryUsage",
                Description = "异常高内存使用",
                Severity = 1,
                Action = BehaviorAction.Warn
            });

            _rules.Add(new BehaviorRule
            {
                Name = "HiddenProcess",
                Description = "隐藏进程",
                Severity = 4,
                Action = BehaviorAction.Kill
            });

            _rules.Add(new BehaviorRule
            {
                Name = "SuspiciousChildProcess",
                Description = "可疑子进程",
                Severity = 3,
                Action = BehaviorAction.Warn
            });
        }

        private void MonitorBehavior(object state)
        {
            try
            {
                var threats = ScanForThreats();
                foreach (var threat in threats)
                {
                    ThreatDetected?.Invoke(this, new BehaviorThreatEventArgs
                    {
                        ThreatInfo = threat
                    });

                    // 根据规则采取行动
                    var rule = _rules.FirstOrDefault(r => r.Name == threat.RuleName);
                    if (rule != null && rule.Action == BehaviorAction.Kill)
                    {
                        TerminateProcess(threat.ProcessId);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"监控行为失败: {ex.Message}");
            }
        }

        private BehaviorThreatInfo AnalyzeProcessBehavior(System.Diagnostics.Process process)
        {
            try
            {
                // 检查进程路径
                string processPath;
                try
                {
                    processPath = process.MainModule?.FileName;
                }
                catch
                {
                    // 无法获取路径，可能是隐藏进程
                    return new BehaviorThreatInfo
                    {
                        ProcessId = process.Id,
                        ProcessName = process.ProcessName,
                        RuleName = "HiddenProcess",
                        Description = "无法获取进程路径，可能为隐藏进程",
                        Severity = 4
                    };
                }

                // 检查可疑路径
                if (!string.IsNullOrEmpty(processPath))
                {
                    var suspiciousPaths = new[] { @"\temp\", @"\tmp\", @"\downloads\" };
                    if (suspiciousPaths.Any(p => processPath.ToLower().Contains(p)))
                    {
                        return new BehaviorThreatInfo
                        {
                            ProcessId = process.Id,
                            ProcessName = process.ProcessName,
                            ProcessPath = processPath,
                            RuleName = "SuspiciousProcessCreation",
                            Description = "进程从可疑路径启动",
                            Severity = 3
                        };
                    }
                }

                // 检查内存使用
                var memoryMB = process.WorkingSet64 / (1024 * 1024);
                if (memoryMB > 500) // 超过500MB
                {
                    return new BehaviorThreatInfo
                    {
                        ProcessId = process.Id,
                        ProcessName = process.ProcessName,
                        RuleName = "HighMemoryUsage",
                        Description = $"内存使用异常: {memoryMB}MB",
                        Severity = 1
                    };
                }

                // 检查子进程
                try
                {
                    var children = GetChildProcesses(process.Id);
                    var suspiciousChildren = new[] { "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe" };
                    foreach (var child in children)
                    {
                        if (suspiciousChildren.Any(s => child.ProcessName.ToLower().Contains(s.ToLower())))
                        {
                            return new BehaviorThreatInfo
                            {
                                ProcessId = process.Id,
                                ProcessName = process.ProcessName,
                                RuleName = "SuspiciousChildProcess",
                                Description = $"创建可疑子进程: {child.ProcessName}",
                                Severity = 3
                            };
                        }
                    }
                }
                catch
                {
                    // 无法获取子进程
                }
            }
            catch
            {
                // 忽略异常
            }

            return null;
        }

        private List<System.Diagnostics.Process> GetChildProcesses(int parentId)
        {
            var children = new List<System.Diagnostics.Process>();

            try
            {
                var allProcesses = System.Diagnostics.Process.GetProcesses();
                foreach (var process in allProcesses)
                {
                    try
                    {
                        if (process.Parent()?.Id == parentId)
                        {
                            children.Add(process);
                        }
                    }
                    catch
                    {
                        // 忽略
                    }
                }
            }
            catch
            {
                // 忽略
            }

            return children;
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

    #region 主动防御相关类
    public class BehaviorRule
    {
        public string Name { get; set; }
        public string Description { get; set; }
        public int Severity { get; set; }
        public BehaviorAction Action { get; set; }
    }

    public class BehaviorThreatInfo
    {
        public int ProcessId { get; set; }
        public string ProcessName { get; set; }
        public string ProcessPath { get; set; }
        public string RuleName { get; set; }
        public string Description { get; set; }
        public int Severity { get; set; }
        public DateTime DetectedTime { get; set; } = DateTime.Now;
    }

    public class BehaviorThreatEventArgs : EventArgs
    {
        public BehaviorThreatInfo ThreatInfo { get; set; }
    }

    public enum BehaviorAction
    {
        Allow,
        Warn,
        Block,
        Kill
    }
    #endregion
}
