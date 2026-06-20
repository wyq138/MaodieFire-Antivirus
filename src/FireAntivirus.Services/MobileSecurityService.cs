// 抖音用户 耄耋杀毒软件 开发，严禁非法反编译
// 专业级移动设备安全引擎 - 对标企业MDM安全能力
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace FireAntivirus.Services
{
    public class MobileSecurityService : IDisposable
    {
        private readonly string _adbPath;
        private readonly string _configPath;
        private readonly string _logPath;

        // 设备管理
        private ConcurrentDictionary<string, TrustedDevice> _trustedDevices = new ConcurrentDictionary<string, TrustedDevice>();
        private ConcurrentDictionary<string, BlockedDevice> _blockedDevices = new ConcurrentDictionary<string, BlockedDevice>();
        private ConcurrentDictionary<string, DeviceSession> _activeSessions = new ConcurrentDictionary<string, DeviceSession>();

        // 监控
        private Timer _monitorTimer;
        private bool _isMonitoring = false;

        // 设备指纹缓存
        private ConcurrentDictionary<string, DeviceFingerprint> _fingerprints = new ConcurrentDictionary<string, DeviceFingerprint>();

        // 传输日志
        private List<FileTransferLog> _transferLogs = new List<FileTransferLog>();

        // 敏感文件过滤规则
        private List<SensitiveFileRule> _sensitiveFileRules = new List<SensitiveFileRule>();

        public event EventHandler<DeviceConnectedEventArgs> DeviceConnected;
        public event EventHandler<DeviceDisconnectedEventArgs> DeviceDisconnected;
        public event EventHandler<SuspiciousTransferEventArgs> SuspiciousTransferDetected;
        public event EventHandler<DeviceSecurityAlertEventArgs> SecurityAlert;

        public MobileSecurityService()
        {
            _adbPath = FindAdbPath();

            _configPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "FireAntivirus", "MobileSecurity");

            _logPath = Path.Combine(_configPath, "Logs");

            foreach (var path in new[] { _configPath, _logPath })
            {
                if (!Directory.Exists(path))
                    Directory.CreateDirectory(path);
            }

            LoadConfiguration();
            InitializeSensitiveFileRules();
        }

        #region 初始化

        private void LoadConfiguration()
        {
            try
            {
                var trustedPath = Path.Combine(_configPath, "trusted_devices.json");
                if (File.Exists(trustedPath))
                {
                    var trusted = JsonSerializer.Deserialize<List<TrustedDevice>>(
                        File.ReadAllText(trustedPath));
                    if (trusted != null)
                    {
                        foreach (var device in trusted)
                        {
                            _trustedDevices[device.DeviceId] = device;
                        }
                    }
                }

                var blockedPath = Path.Combine(_configPath, "blocked_devices.json");
                if (File.Exists(blockedPath))
                {
                    var blocked = JsonSerializer.Deserialize<List<BlockedDevice>>(
                        File.ReadAllText(blockedPath));
                    if (blocked != null)
                    {
                        foreach (var device in blocked)
                        {
                            _blockedDevices[device.DeviceId] = device;
                        }
                    }
                }
            }
            catch { }
        }

        private void SaveConfiguration()
        {
            try
            {
                var trustedPath = Path.Combine(_configPath, "trusted_devices.json");
                File.WriteAllText(trustedPath, JsonSerializer.Serialize(_trustedDevices.Values.ToList(),
                    new JsonSerializerOptions { WriteIndented = true }));

                var blockedPath = Path.Combine(_configPath, "blocked_devices.json");
                File.WriteAllText(blockedPath, JsonSerializer.Serialize(_blockedDevices.Values.ToList(),
                    new JsonSerializerOptions { WriteIndented = true }));
            }
            catch { }
        }

        private void InitializeSensitiveFileRules()
        {
            _sensitiveFileRules = new List<SensitiveFileRule>
            {
                new SensitiveFileRule
                {
                    Name = "文档文件",
                    Patterns = new[] { "*.doc", "*.docx", "*.pdf", "*.xls", "*.xlsx", "*.ppt", "*.pptx" },
                    RiskLevel = FileRiskLevel.Medium,
                    Action = FilterAction.Log
                },
                new SensitiveFileRule
                {
                    Name = "源代码文件",
                    Patterns = new[] { "*.cs", "*.cpp", "*.h", "*.java", "*.py", "*.js", "*.ts" },
                    RiskLevel = FileRiskLevel.High,
                    Action = FilterAction.Log | FilterAction.Alert
                },
                new SensitiveFileRule
                {
                    Name = "配置文件",
                    Patterns = new[] { "*.config", "*.xml", "*.json", "*.yaml", "*.yml", "*.ini" },
                    RiskLevel = FileRiskLevel.High,
                    Action = FilterAction.Log | FilterAction.Alert
                },
                new SensitiveFileRule
                {
                    Name = "密钥证书文件",
                    Patterns = new[] { "*.key", "*.pem", "*.p12", "*.pfx", "*.crt", "*.cer" },
                    RiskLevel = FileRiskLevel.Critical,
                    Action = FilterAction.Block | FilterAction.Alert
                },
                new SensitiveFileRule
                {
                    Name = "数据库文件",
                    Patterns = new[] { "*.db", "*.sqlite", "*.mdb", "*.accdb", "*.sql" },
                    RiskLevel = FileRiskLevel.High,
                    Action = FilterAction.Log | FilterAction.Alert
                },
                new SensitiveFileRule
                {
                    Name = "压缩文件",
                    Patterns = new[] { "*.zip", "*.rar", "*.7z", "*.tar", "*.gz" },
                    RiskLevel = FileRiskLevel.Medium,
                    Action = FilterAction.Scan
                }
            };
        }

        #endregion

        #region 公共方法

        /// <summary>
        /// 获取已连接的设备列表
        /// </summary>
        public List<MobileDeviceInfo> GetConnectedDevices()
        {
            var devices = new List<MobileDeviceInfo>();

            // 通过WMI获取USB设备
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_PnPEntity WHERE PNPClass = 'USB'"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        var name = obj["Name"]?.ToString() ?? "";
                        var deviceId = obj["DeviceID"]?.ToString() ?? "";
                        var manufacturer = obj["Manufacturer"]?.ToString() ?? "";

                        if (IsMobileDevice(name, manufacturer))
                        {
                            var device = CreateDeviceInfo(name, deviceId, manufacturer);
                            EnrichDeviceInfo(device);
                            devices.Add(device);
                        }
                    }
                }
            }
            catch { }

            // 通过ADB获取Android设备
            if (!string.IsNullOrEmpty(_adbPath))
            {
                try
                {
                    var adbDevices = GetAdbDevices();
                    foreach (var adbDevice in adbDevices)
                    {
                        var existing = devices.FirstOrDefault(d => d.SerialNumber == adbDevice.Serial);
                        if (existing != null)
                        {
                            existing.SerialNumber = adbDevice.Serial;
                            existing.Model = adbDevice.Model;
                            existing.AndroidVersion = adbDevice.AndroidVersion;
                            existing.IsConnected = true;
                        }
                        else
                        {
                            var device = new MobileDeviceInfo
                            {
                                Name = adbDevice.Model ?? "Android Device",
                                SerialNumber = adbDevice.Serial,
                                Model = adbDevice.Model,
                                AndroidVersion = adbDevice.AndroidVersion,
                                ConnectionType = "USB/ADB",
                                IsAndroid = true,
                                IsConnected = true
                            };
                            EnrichDeviceInfo(device);
                            devices.Add(device);
                        }
                    }
                }
                catch { }
            }

            // 检测便携设备（如iPhone）
            try
            {
                using (var searcher = new ManagementObjectSearcher(
                    "SELECT * FROM Win32_PnPEntity WHERE Name LIKE '%iPhone%' OR Name LIKE '%iPad%'"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        var name = obj["Name"]?.ToString() ?? "";
                        var deviceId = obj["DeviceID"]?.ToString() ?? "";

                        if (!devices.Any(d => d.DeviceId == deviceId))
                        {
                            var device = new MobileDeviceInfo
                            {
                                Name = name,
                                DeviceId = deviceId,
                                Manufacturer = "Apple",
                                ConnectionType = "USB",
                                IsIOS = true,
                                IsConnected = true
                            };
                            EnrichDeviceInfo(device);
                            devices.Add(device);
                        }
                    }
                }
            }
            catch { }

            // 检测可移动存储
            try
            {
                foreach (var drive in DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Removable))
                {
                    if (!devices.Any(d => d.Name.Contains(drive.Name)))
                    {
                        var device = new MobileDeviceInfo
                        {
                            Name = $"可移动存储 ({drive.Name.TrimEnd(':')})",
                            DeviceId = drive.Name,
                            ConnectionType = "USB Storage",
                            TotalSpace = drive.TotalSize,
                            FreeSpace = drive.AvailableFreeSpace,
                            IsConnected = true
                        };
                        EnrichDeviceInfo(device);
                        devices.Add(device);
                    }
                }
            }
            catch { }

            return devices;
        }

        /// <summary>
        /// 获取设备详细信息
        /// </summary>
        public DeviceDetailInfo GetDeviceDetail(MobileDeviceInfo device)
        {
            var detail = new DeviceDetailInfo
            {
                Device = device,
                AnalyzedAt = DateTime.Now
            };

            // 计算设备指纹
            detail.Fingerprint = CalculateFingerprint(device);

            // 获取信任状态
            detail.TrustStatus = GetTrustStatus(device);

            // 获取安全评估
            detail.SecurityAssessment = AssessDeviceSecurity(device);

            // 获取活动历史
            detail.ActivityHistory = GetActivityHistory(device);

            return detail;
        }

        /// <summary>
        /// 扫描设备
        /// </summary>
        public MobileScanResult ScanDevice(MobileDeviceInfo device)
        {
            var result = new MobileScanResult
            {
                Device = device,
                ScanTime = DateTime.Now,
                ScanId = Guid.NewGuid().ToString()
            };

            // 检查是否被阻止
            if (IsDeviceBlocked(device))
            {
                result.IsBlocked = true;
                result.BlockReason = GetBlockReason(device);
                return result;
            }

            // 扫描可移动存储
            if (device.ConnectionType == "USB Storage")
            {
                ScanRemovableStorage(device, result);
            }

            // 扫描Android设备
            if (device.IsAndroid && !string.IsNullOrEmpty(_adbPath) && !string.IsNullOrEmpty(device.SerialNumber))
            {
                ScanAndroidDevice(device, result);
            }

            // 扫描iOS设备（通过iTunes备份）
            if (device.IsIOS)
            {
                ScanIOSDevice(device, result);
            }

            // 计算综合风险评分
            result.RiskScore = CalculateRiskScore(result);

            return result;
        }

        /// <summary>
        /// 添加信任设备
        /// </summary>
        public void AddTrustedDevice(MobileDeviceInfo device, string nickname = null, int trustLevel = 1)
        {
            var fingerprint = CalculateFingerprint(device);

            var trusted = new TrustedDevice
            {
                DeviceId = device.DeviceId ?? device.SerialNumber,
                Fingerprint = fingerprint,
                Nickname = nickname ?? device.Name,
                TrustLevel = trustLevel,
                FirstTrusted = DateTime.Now,
                LastSeen = DateTime.Now
            };

            _trustedDevices[trusted.DeviceId] = trusted;
            SaveConfiguration();

            LogActivity("DEVICE_TRUSTED", trusted.DeviceId, $"设备已信任: {trusted.Nickname}");
        }

        /// <summary>
        /// 移除信任设备
        /// </summary>
        public void RemoveTrustedDevice(string deviceId)
        {
            _trustedDevices.TryRemove(deviceId, out _);
            SaveConfiguration();
            LogActivity("DEVICE_UNTRUSTED", deviceId, "设备信任已移除");
        }

        /// <summary>
        /// 添加阻止设备
        /// </summary>
        public void AddBlockedDevice(MobileDeviceInfo device, string reason)
        {
            var fingerprint = CalculateFingerprint(device);

            var blocked = new BlockedDevice
            {
                DeviceId = device.DeviceId ?? device.SerialNumber,
                Fingerprint = fingerprint,
                BlockReason = reason,
                BlockedAt = DateTime.Now
            };

            _blockedDevices[blocked.DeviceId] = blocked;
            SaveConfiguration();

            LogActivity("DEVICE_BLOCKED", blocked.DeviceId, $"设备已阻止: {reason}");
        }

        /// <summary>
        /// 移除阻止设备
        /// </summary>
        public void RemoveBlockedDevice(string deviceId)
        {
            _blockedDevices.TryRemove(deviceId, out _);
            SaveConfiguration();
            LogActivity("DEVICE_UNBLOCKED", deviceId, "设备阻止已移除");
        }

        /// <summary>
        /// 获取信任设备列表
        /// </summary>
        public List<TrustedDevice> GetTrustedDevices()
        {
            return _trustedDevices.Values.ToList();
        }

        /// <summary>
        /// 获取阻止设备列表
        /// </summary>
        public List<BlockedDevice> GetBlockedDevices()
        {
            return _blockedDevices.Values.ToList();
        }

        /// <summary>
        /// 开始设备监控
        /// </summary>
        public void StartMonitoring()
        {
            if (_isMonitoring) return;

            _isMonitoring = true;
            _monitorTimer = new Timer(MonitorCallback, null, TimeSpan.Zero, TimeSpan.FromSeconds(5));
        }

        /// <summary>
        /// 停止设备监控
        /// </summary>
        public void StopMonitoring()
        {
            _isMonitoring = false;
            _monitorTimer?.Dispose();
            _monitorTimer = null;
        }

        /// <summary>
        /// 弹出设备
        /// </summary>
        public bool EjectDevice(MobileDeviceInfo device)
        {
            try
            {
                if (device.ConnectionType == "USB Storage")
                {
                    var startInfo = new ProcessStartInfo
                    {
                        FileName = "powershell.exe",
                        Arguments = $"-command \"$drive = Get-WmiObject -Class Win32_Volume -Filter \\\"DriveLetter='{device.DeviceId.TrimEnd(':')}'\\\"; $drive.Dismount($false, $false)\"",
                        UseShellExecute = false,
                        CreateNoWindow = true
                    };

                    Process.Start(startInfo)?.WaitForExit(10000);
                }

                LogActivity("DEVICE_EJECTED", device.DeviceId, "设备已弹出");
                return true;
            }
            catch { return false; }
        }

        /// <summary>
        /// 检查文件传输风险
        /// </summary>
        public FileTransferCheckResult CheckFileTransfer(string filePath, TransferDirection direction, MobileDeviceInfo device)
        {
            var result = new FileTransferCheckResult
            {
                FilePath = filePath,
                Direction = direction,
                DeviceId = device.DeviceId ?? device.SerialNumber,
                CheckTime = DateTime.Now
            };

            // 检查敏感文件规则
            foreach (var rule in _sensitiveFileRules)
            {
                foreach (var pattern in rule.Patterns)
                {
                    if (MatchesPattern(Path.GetFileName(filePath), pattern))
                    {
                        result.MatchedRules.Add(rule);
                        result.RiskLevel = (FileRiskLevel)Math.Max((int)result.RiskLevel, (int)rule.RiskLevel);

                        if ((rule.Action & FilterAction.Block) != 0)
                        {
                            result.ShouldBlock = true;
                            result.BlockReason = $"匹配敏感文件规则: {rule.Name}";
                        }

                        if ((rule.Action & FilterAction.Alert) != 0)
                        {
                            result.ShouldAlert = true;
                        }
                    }
                }
            }

            // 记录传输日志
            if (result.RiskLevel >= FileRiskLevel.Medium)
            {
                var log = new FileTransferLog
                {
                    FilePath = filePath,
                    Direction = direction,
                    DeviceId = device.DeviceId ?? device.SerialNumber,
                    RiskLevel = result.RiskLevel,
                    Timestamp = DateTime.Now
                };

                _transferLogs.Add(log);
                SaveTransferLogs();

                // 触发告警
                if (result.ShouldAlert)
                {
                    SuspiciousTransferDetected?.Invoke(this, new SuspiciousTransferEventArgs
                    {
                        FilePath = filePath,
                        Direction = direction,
                        Device = device,
                        RiskLevel = result.RiskLevel
                    });
                }
            }

            return result;
        }

        /// <summary>
        /// 获取传输日志
        /// </summary>
        public List<FileTransferLog> GetTransferLogs(DateTime? from = null, DateTime? to = null)
        {
            var query = _transferLogs.AsEnumerable();

            if (from.HasValue)
                query = query.Where(l => l.Timestamp >= from.Value);

            if (to.HasValue)
                query = query.Where(l => l.Timestamp <= to.Value);

            return query.OrderByDescending(l => l.Timestamp).ToList();
        }

        /// <summary>
        /// 获取安全建议
        /// </summary>
        public List<MobileSecurityRecommendation> GetMobileSecurityRecommendations(MobileDeviceInfo device)
        {
            var recommendations = new List<MobileSecurityRecommendation>();

            if (device.IsAndroid)
            {
                recommendations.Add(new MobileSecurityRecommendation
                {
                    Priority = RecommendationPriority.High,
                    Title = "禁用USB调试",
                    Description = "USB调试模式会增加设备安全风险",
                    Action = "设置 > 开发者选项 > 关闭USB调试"
                });

                recommendations.Add(new MobileSecurityRecommendation
                {
                    Priority = RecommendationPriority.High,
                    Title = "禁用未知来源",
                    Description = "阻止从非官方商店安装应用",
                    Action = "设置 > 安全 > 关闭未知来源"
                });

                recommendations.Add(new MobileSecurityRecommendation
                {
                    Priority = RecommendationPriority.Medium,
                    Title = "检查Root状态",
                    Description = "Root设备存在更高安全风险",
                    Action = "检查设备是否已获取Root权限"
                });

                recommendations.Add(new MobileSecurityRecommendation
                {
                    Priority = RecommendationPriority.Medium,
                    Title = "更新Android系统",
                    Description = "保持系统更新以修复安全漏洞",
                    Action = "设置 > 系统 > 系统更新"
                });
            }
            else if (device.IsIOS)
            {
                recommendations.Add(new MobileSecurityRecommendation
                {
                    Priority = RecommendationPriority.High,
                    Title = "更新iOS",
                    Description = "保持iOS更新到最新版本",
                    Action = "设置 > 通用 > 软件更新"
                });

                recommendations.Add(new MobileSecurityRecommendation
                {
                    Priority = RecommendationPriority.High,
                    Title = "检查越狱状态",
                    Description = "越狱设备存在严重安全风险",
                    Action = "检查设备是否已越狱"
                });

                recommendations.Add(new MobileSecurityRecommendation
                {
                    Priority = RecommendationPriority.Medium,
                    Title = "启用查找我的iPhone",
                    Description = "设备丢失时可以追踪和远程擦除",
                    Action = "设置 > [Apple ID] > 查找 > 查找我的iPhone"
                });
            }
            else if (device.ConnectionType == "USB Storage")
            {
                recommendations.Add(new MobileSecurityRecommendation
                {
                    Priority = RecommendationPriority.High,
                    Title = "扫描病毒",
                    Description = "扫描U盘中的恶意软件",
                    Action = "右键点击驱动器 > 使用火蚁杀毒扫描"
                });

                recommendations.Add(new MobileSecurityRecommendation
                {
                    Priority = RecommendationPriority.Medium,
                    Title = "禁用自动运行",
                    Description = "防止自动运行病毒",
                    Action = "已由系统自动禁用"
                });
            }

            return recommendations;
        }

        #endregion

        #region 私有方法 - 设备检测

        private MobileDeviceInfo CreateDeviceInfo(string name, string deviceId, string manufacturer)
        {
            return new MobileDeviceInfo
            {
                Name = name,
                DeviceId = deviceId,
                Manufacturer = manufacturer,
                ConnectionType = "USB",
                IsAndroid = IsAndroidDevice(name, manufacturer),
                IsIOS = IsIOSDevice(name, manufacturer),
                IsConnected = true
            };
        }

        private void EnrichDeviceInfo(MobileDeviceInfo device)
        {
            // 计算设备指纹
            device.Fingerprint = CalculateFingerprint(device);

            // 检查信任状态
            device.IsTrusted = _trustedDevices.ContainsKey(device.DeviceId ?? device.SerialNumber ?? "");

            // 检查阻止状态
            device.IsBlocked = _blockedDevices.ContainsKey(device.DeviceId ?? device.SerialNumber ?? "");

            // 设置信任等级
            if (device.IsTrusted && _trustedDevices.TryGetValue(device.DeviceId ?? device.SerialNumber ?? "", out var trusted))
            {
                device.TrustLevel = trusted.TrustLevel;
            }
        }

        private DeviceFingerprint CalculateFingerprint(MobileDeviceInfo device)
        {
            var fingerprint = new DeviceFingerprint();

            try
            {
                var components = new List<string>
                {
                    device.Manufacturer ?? "",
                    device.Model ?? "",
                    device.SerialNumber ?? "",
                    device.AndroidVersion ?? ""
                };

                using (var sha256 = SHA256.Create())
                {
                    var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(string.Join("|", components)));
                    fingerprint.Hash = BitConverter.ToString(hash).Replace("-", "").ToLower();
                }

                fingerprint.Components = components;
            }
            catch { }

            return fingerprint;
        }

        private TrustStatus GetTrustStatus(MobileDeviceInfo device)
        {
            var deviceId = device.DeviceId ?? device.SerialNumber ?? "";

            if (_trustedDevices.TryGetValue(deviceId, out var trusted))
            {
                return new TrustStatus
                {
                    IsTrusted = true,
                    TrustLevel = trusted.TrustLevel,
                    FirstTrusted = trusted.FirstTrusted,
                    Nickname = trusted.Nickname
                };
            }

            if (_blockedDevices.TryGetValue(deviceId, out var blocked))
            {
                return new TrustStatus
                {
                    IsBlocked = true,
                    BlockReason = blocked.BlockReason,
                    BlockedAt = blocked.BlockedAt
                };
            }

            return new TrustStatus { IsTrusted = false, IsBlocked = false };
        }

        private DeviceSecurityAssessment AssessDeviceSecurity(MobileDeviceInfo device)
        {
            var assessment = new DeviceSecurityAssessment();

            if (device.IsAndroid)
            {
                assessment.SecurityChecks.Add(new SecurityCheck
                {
                    Name = "USB调试",
                    Status = device.SecurityInfo?.USBDebuggingEnabled == true ? CheckStatus.Warning : CheckStatus.Pass,
                    Description = device.SecurityInfo?.USBDebuggingEnabled == true ? "USB调试已启用" : "USB调试已禁用"
                });

                assessment.SecurityChecks.Add(new SecurityCheck
                {
                    Name = "未知来源",
                    Status = device.SecurityInfo?.UnknownSourcesEnabled == true ? CheckStatus.Warning : CheckStatus.Pass,
                    Description = device.SecurityInfo?.UnknownSourcesEnabled == true ? "允许安装未知来源应用" : "仅允许安装官方应用"
                });

                assessment.SecurityChecks.Add(new SecurityCheck
                {
                    Name = "Root状态",
                    Status = device.SecurityInfo?.IsRooted == true ? CheckStatus.Fail : CheckStatus.Pass,
                    Description = device.SecurityInfo?.IsRooted == true ? "设备已Root" : "设备未Root"
                });
            }

            // 计算安全评分
            assessment.SecurityScore = CalculateSecurityScore(assessment.SecurityChecks);

            return assessment;
        }

        private List<DeviceActivity> GetActivityHistory(MobileDeviceInfo device)
        {
            var deviceId = device.DeviceId ?? device.SerialNumber ?? "";
            return _transferLogs.Where(l => l.DeviceId == deviceId)
                .Select(l => new DeviceActivity
                {
                    Timestamp = l.Timestamp,
                    ActivityType = l.Direction == TransferDirection.ToDevice ? "文件传出" : "文件传入",
                    FilePath = l.FilePath,
                    RiskLevel = l.RiskLevel.ToString()
                })
                .OrderByDescending(a => a.Timestamp)
                .Take(50)
                .ToList();
        }

        private bool IsDeviceBlocked(MobileDeviceInfo device)
        {
            var deviceId = device.DeviceId ?? device.SerialNumber ?? "";
            return _blockedDevices.ContainsKey(deviceId);
        }

        private string GetBlockReason(MobileDeviceInfo device)
        {
            var deviceId = device.DeviceId ?? device.SerialNumber ?? "";
            return _blockedDevices.TryGetValue(deviceId, out var blocked) ? blocked.BlockReason : "";
        }

        #endregion

        #region 私有方法 - 扫描

        private void ScanRemovableStorage(MobileDeviceInfo device, MobileScanResult result)
        {
            try
            {
                var drivePath = device.DeviceId;

                foreach (var file in Directory.GetFiles(drivePath, "*.*", SearchOption.AllDirectories))
                {
                    try
                    {
                        result.FilesScanned++;

                        var extension = Path.GetExtension(file).ToLower();
                        var fileName = Path.GetFileName(file);

                        // 检查可执行文件
                        if (new[] { ".exe", ".bat", ".cmd", ".vbs", ".js", ".ps1" }.Contains(extension))
                        {
                            result.SuspiciousFiles.Add(new MobileSuspiciousFileInfo
                            {
                                FilePath = file,
                                Extension = extension,
                                Reason = "可执行文件",
                                RiskLevel = FileRiskLevel.High
                            });
                        }

                        // 检查自动运行文件
                        if (fileName.ToLower() == "autorun.inf")
                        {
                            result.SuspiciousFiles.Add(new MobileSuspiciousFileInfo
                            {
                                FilePath = file,
                                Extension = ".inf",
                                Reason = "自动运行配置文件",
                                RiskLevel = FileRiskLevel.High
                            });
                        }

                        // 检查APK文件
                        if (extension == ".apk")
                        {
                            result.ApkFiles.Add(new ApkFileInfo
                            {
                                FilePath = file,
                                Size = new FileInfo(file).Length
                            });
                        }

                        // 检查敏感文件
                        foreach (var rule in _sensitiveFileRules)
                        {
                            foreach (var pattern in rule.Patterns)
                            {
                                if (MatchesPattern(fileName, pattern))
                                {
                                    result.SensitiveFiles.Add(new SensitiveFileInfo
                                    {
                                        FilePath = file,
                                        RuleName = rule.Name,
                                        RiskLevel = rule.RiskLevel
                                    });
                                    break;
                                }
                            }
                        }
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                result.Errors.Add($"扫描失败: {ex.Message}");
            }
        }

        private void ScanAndroidDevice(MobileDeviceInfo device, MobileScanResult result)
        {
            if (string.IsNullOrEmpty(_adbPath) || string.IsNullOrEmpty(device.SerialNumber))
                return;

            try
            {
                // 获取已安装应用
                var startInfo = new ProcessStartInfo
                {
                    FileName = _adbPath,
                    Arguments = $"-s {device.SerialNumber} shell pm list packages -3",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                };

                using (var process = Process.Start(startInfo))
                {
                    var output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit(10000);

                    var packages = output.Split('\n')
                        .Where(l => l.StartsWith("package:"))
                        .Select(l => l.Substring(8).Trim())
                        .ToList();

                    foreach (var package in packages)
                    {
                        var appInfo = new InstalledAppInfo
                        {
                            PackageName = package,
                            IsSystemApp = false
                        };

                        // 检查可疑应用
                        if (IsSuspiciousPackage(package))
                        {
                            appInfo.IsSuspicious = true;
                            appInfo.SuspicionReason = "可能的恶意应用";
                        }

                        result.InstalledApps.Add(appInfo);
                    }
                }

                // 获取安全信息
                result.SecurityInfo = GetAndroidSecurityInfo(device.SerialNumber);

                // 检查Root
                result.SecurityInfo.IsRooted = CheckAndroidRoot(device.SerialNumber);
            }
            catch (Exception ex)
            {
                result.Errors.Add($"Android扫描失败: {ex.Message}");
            }
        }

        private void ScanIOSDevice(MobileDeviceInfo device, MobileScanResult result)
        {
            try
            {
                // 检查iTunes备份目录
                var backupPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "Apple Computer", "MobileSync", "Backup");

                if (Directory.Exists(backupPath))
                {
                    result.IOSInfo = new IOSDeviceInfo
                    {
                        BackupPath = backupPath,
                        HasBackup = Directory.GetDirectories(backupPath).Length > 0
                    };
                }

                // 检查越狱迹象
                // iOS设备通过USB连接时，越狱设备可能有特殊文件
            }
            catch { }
        }

        private bool IsSuspiciousPackage(string packageName)
        {
            var suspiciousPatterns = new[]
            {
                "hack", "crack", "cheat", "mod", "patch",
                "keygen", "pirate", "warez"
            };

            return suspiciousPatterns.Any(p => packageName.ToLower().Contains(p));
        }

        private AndroidSecurityInfo GetAndroidSecurityInfo(string serial)
        {
            var info = new AndroidSecurityInfo();

            if (string.IsNullOrEmpty(_adbPath))
                return info;

            try
            {
                // 检查USB调试
                var startInfo = new ProcessStartInfo
                {
                    FileName = _adbPath,
                    Arguments = $"-s {serial} shell settings global adb_enabled",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                };

                using (var process = Process.Start(startInfo))
                {
                    var output = process.StandardOutput.ReadToEnd().Trim();
                    info.USBDebuggingEnabled = output == "1";
                }

                // 检查未知来源
                startInfo.Arguments = $"-s {serial} shell settings global install_non_market_apps";
                using (var process = Process.Start(startInfo))
                {
                    var output = process.StandardOutput.ReadToEnd().Trim();
                    info.UnknownSourcesEnabled = output == "1";
                }

                // 获取Android版本
                startInfo.Arguments = $"-s {serial} shell getprop ro.build.version.release";
                using (var process = Process.Start(startInfo))
                {
                    info.AndroidVersion = process.StandardOutput.ReadToEnd().Trim();
                }

                // 获取安全补丁级别
                startInfo.Arguments = $"-s {serial} shell getprop ro.build.version.security_patch";
                using (var process = Process.Start(startInfo))
                {
                    info.SecurityPatchLevel = process.StandardOutput.ReadToEnd().Trim();
                }
            }
            catch { }

            return info;
        }

        private bool CheckAndroidRoot(string serial)
        {
            if (string.IsNullOrEmpty(_adbPath))
                return false;

            try
            {
                var suPaths = new[] { "/system/bin/su", "/system/xbin/su", "/sbin/su", "/data/local/xbin/su" };

                foreach (var suPath in suPaths)
                {
                    var startInfo = new ProcessStartInfo
                    {
                        FileName = _adbPath,
                        Arguments = $"-s {serial} shell ls {suPath}",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    };

                    using (var process = Process.Start(startInfo))
                    {
                        var output = process.StandardOutput.ReadToEnd().Trim();
                        if (!output.Contains("No such file"))
                        {
                            return true;
                        }
                    }
                }
            }
            catch { }

            return false;
        }

        private int CalculateRiskScore(MobileScanResult result)
        {
            int score = 0;

            // 可疑文件
            score += result.SuspiciousFiles.Count * 10;
            score += result.SuspiciousFiles.Count(f => f.RiskLevel == FileRiskLevel.Critical) * 20;

            // 敏感文件
            score += result.SensitiveFiles.Count(f => f.RiskLevel >= FileRiskLevel.High) * 5;

            // 安全检查
            if (result.SecurityInfo?.IsRooted == true) score += 30;
            if (result.SecurityInfo?.USBDebuggingEnabled == true) score += 10;
            if (result.SecurityInfo?.UnknownSourcesEnabled == true) score += 15;

            // 可疑应用
            score += result.InstalledApps.Count(a => a.IsSuspicious) * 15;

            return Math.Min(score, 100);
        }

        private int CalculateSecurityScore(List<SecurityCheck> checks)
        {
            if (checks.Count == 0) return 100;

            int score = 100;
            foreach (var check in checks)
            {
                score -= check.Status switch
                {
                    CheckStatus.Fail => 20,
                    CheckStatus.Warning => 10,
                    _ => 0
                };
            }

            return Math.Max(0, score);
        }

        #endregion

        #region 私有方法 - 辅助

        private string FindAdbPath()
        {
            var possiblePaths = new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Android", "android-sdk", "platform-tools", "adb.exe"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Android", "android-sdk", "platform-tools", "adb.exe"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Android", "Sdk", "platform-tools", "adb.exe"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "AppData", "Local", "Android", "Sdk", "platform-tools", "adb.exe")
            };

            return possiblePaths.FirstOrDefault(File.Exists);
        }

        private bool IsMobileDevice(string name, string manufacturer)
        {
            var mobileKeywords = new[]
            {
                "iPhone", "iPad", "iPod", "Android", "Samsung", "Xiaomi", "Huawei",
                "OPPO", "vivo", "OnePlus", "Pixel", "Nexus", "LG", "Sony",
                "Motorola", "Nokia", "HTC", "Lenovo", "ZTE", "Meizu", "Realme"
            };

            var combinedText = (name + " " + manufacturer).ToLower();
            return mobileKeywords.Any(k => combinedText.Contains(k.ToLower()));
        }

        private bool IsAndroidDevice(string name, string manufacturer)
        {
            var androidKeywords = new[] { "Android", "Samsung", "Xiaomi", "Huawei", "OPPO", "vivo", "OnePlus", "Pixel", "Nexus" };
            var combinedText = (name + " " + manufacturer).ToLower();
            return androidKeywords.Any(k => combinedText.Contains(k.ToLower()));
        }

        private bool IsIOSDevice(string name, string manufacturer)
        {
            var iosKeywords = new[] { "iPhone", "iPad", "iPod", "Apple" };
            var combinedText = (name + " " + manufacturer).ToLower();
            return iosKeywords.Any(k => combinedText.Contains(k.ToLower()));
        }

        private List<AdbDeviceInfo> GetAdbDevices()
        {
            var devices = new List<AdbDeviceInfo>();

            if (string.IsNullOrEmpty(_adbPath))
                return devices;

            try
            {
                var startInfo = new ProcessStartInfo
                {
                    FileName = _adbPath,
                    Arguments = "devices -l",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                using (var process = Process.Start(startInfo))
                {
                    var output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit(5000);

                    var lines = output.Split('\n').Skip(1);
                    foreach (var line in lines)
                    {
                        if (string.IsNullOrWhiteSpace(line))
                            continue;

                        var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length > 0 && parts[0] != "List")
                        {
                            var device = new AdbDeviceInfo { Serial = parts[0] };

                            foreach (var part in parts.Skip(2))
                            {
                                if (part.StartsWith("model:"))
                                    device.Model = part.Substring(6);
                                else if (part.StartsWith("device:"))
                                    device.DeviceName = part.Substring(7);
                            }

                            device.AndroidVersion = GetAndroidVersion(device.Serial);
                            devices.Add(device);
                        }
                    }
                }
            }
            catch { }

            return devices;
        }

        private string GetAndroidVersion(string serial)
        {
            if (string.IsNullOrEmpty(_adbPath))
                return null;

            try
            {
                var startInfo = new ProcessStartInfo
                {
                    FileName = _adbPath,
                    Arguments = $"-s {serial} shell getprop ro.build.version.release",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                };

                using (var process = Process.Start(startInfo))
                {
                    var output = process.StandardOutput.ReadToEnd().Trim();
                    process.WaitForExit(5000);
                    return output;
                }
            }
            catch { return null; }
        }

        private bool MatchesPattern(string fileName, string pattern)
        {
            try
            {
                var regex = "^" + pattern.Replace("*", ".*").Replace("?", ".") + "$";
                return Regex.IsMatch(fileName, regex, RegexOptions.IgnoreCase);
            }
            catch { return false; }
        }

        private void MonitorCallback(object state)
        {
            try
            {
                var currentDevices = GetConnectedDevices();
                var currentIds = new HashSet<string>(currentDevices.Select(d => d.DeviceId ?? d.SerialNumber ?? d.Name));

                // 检查新设备
                foreach (var device in currentDevices)
                {
                    var id = device.DeviceId ?? device.SerialNumber ?? device.Name;

                    if (!_activeSessions.ContainsKey(id))
                    {
                        // 新设备连接
                        var session = new DeviceSession
                        {
                            DeviceId = id,
                            Device = device,
                            ConnectedAt = DateTime.Now
                        };

                        _activeSessions[id] = session;

                        DeviceConnected?.Invoke(this, new DeviceConnectedEventArgs
                        {
                            Device = device,
                            Session = session
                        });

                        // 检查是否为阻止设备
                        if (_blockedDevices.ContainsKey(id))
                        {
                            SecurityAlert?.Invoke(this, new DeviceSecurityAlertEventArgs
                            {
                                Device = device,
                                AlertType = "BLOCKED_DEVICE_CONNECTED",
                                Message = $"阻止设备尝试连接: {GetBlockReason(device)}"
                            });
                        }

                        LogActivity("DEVICE_CONNECTED", id, $"设备连接: {device.Name}");
                    }
                }

                // 检查断开的设备
                var disconnectedIds = _activeSessions.Keys.Where(id => !currentIds.Contains(id)).ToList();
                foreach (var id in disconnectedIds)
                {
                    if (_activeSessions.TryRemove(id, out var session))
                    {
                        session.DisconnectedAt = DateTime.Now;
                        session.Duration = session.DisconnectedAt - session.ConnectedAt;

                        DeviceDisconnected?.Invoke(this, new DeviceDisconnectedEventArgs
                        {
                            DeviceId = id,
                            Session = session
                        });

                        LogActivity("DEVICE_DISCONNECTED", id, $"设备断开: {session.Duration?.TotalMinutes:F1}分钟");
                    }
                }
            }
            catch { }
        }

        private void LogActivity(string activityType, string deviceId, string description)
        {
            try
            {
                var logFile = Path.Combine(_logPath, $"activity_{DateTime.Now:yyyyMMdd}.log");
                var logEntry = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} | {activityType} | {deviceId} | {description}";
                File.AppendAllText(logFile, logEntry + Environment.NewLine);
            }
            catch { }
        }

        private void SaveTransferLogs()
        {
            try
            {
                var logPath = Path.Combine(_configPath, "transfer_logs.json");
                File.WriteAllText(logPath, JsonSerializer.Serialize(_transferLogs.TakeLast(1000).ToList()));
            }
            catch { }
        }

        #endregion

        public void Dispose()
        {
            StopMonitoring();
        }
    }

    #region 数据模型

    public enum TransferDirection
    {
        ToDevice,
        FromDevice
    }

    public enum FileRiskLevel
    {
        None = 0,
        Low = 1,
        Medium = 2,
        High = 3,
        Critical = 4
    }

    public enum FilterAction
    {
        None = 0,
        Log = 1,
        Scan = 2,
        Alert = 4,
        Block = 8
    }

    public enum CheckStatus
    {
        Pass,
        Warning,
        Fail
    }

    public class MobileDeviceInfo
    {
        public string Name { get; set; }
        public string DeviceId { get; set; }
        public string SerialNumber { get; set; }
        public string Manufacturer { get; set; }
        public string Model { get; set; }
        public string AndroidVersion { get; set; }
        public string ConnectionType { get; set; }
        public bool IsAndroid { get; set; }
        public bool IsIOS { get; set; }
        public bool IsConnected { get; set; }
        public bool IsTrusted { get; set; }
        public bool IsBlocked { get; set; }
        public int TrustLevel { get; set; }
        public long TotalSpace { get; set; }
        public long FreeSpace { get; set; }
        public DeviceFingerprint Fingerprint { get; set; }
        public AndroidSecurityInfo SecurityInfo { get; set; }
    }

    public class DeviceFingerprint
    {
        public string Hash { get; set; }
        public List<string> Components { get; set; } = new List<string>();
    }

    public class DeviceDetailInfo
    {
        public MobileDeviceInfo Device { get; set; }
        public DateTime AnalyzedAt { get; set; }
        public DeviceFingerprint Fingerprint { get; set; }
        public TrustStatus TrustStatus { get; set; }
        public DeviceSecurityAssessment SecurityAssessment { get; set; }
        public List<DeviceActivity> ActivityHistory { get; set; } = new List<DeviceActivity>();
    }

    public class TrustStatus
    {
        public bool IsTrusted { get; set; }
        public bool IsBlocked { get; set; }
        public int TrustLevel { get; set; }
        public string Nickname { get; set; }
        public DateTime? FirstTrusted { get; set; }
        public string BlockReason { get; set; }
        public DateTime? BlockedAt { get; set; }
    }

    public class DeviceSecurityAssessment
    {
        public List<SecurityCheck> SecurityChecks { get; set; } = new List<SecurityCheck>();
        public int SecurityScore { get; set; }
    }

    public class SecurityCheck
    {
        public string Name { get; set; }
        public CheckStatus Status { get; set; }
        public string Description { get; set; }
    }

    public class DeviceActivity
    {
        public DateTime Timestamp { get; set; }
        public string ActivityType { get; set; }
        public string FilePath { get; set; }
        public string RiskLevel { get; set; }
    }

    public class TrustedDevice
    {
        public string DeviceId { get; set; }
        public DeviceFingerprint Fingerprint { get; set; }
        public string Nickname { get; set; }
        public int TrustLevel { get; set; }
        public DateTime FirstTrusted { get; set; }
        public DateTime LastSeen { get; set; }
    }

    public class BlockedDevice
    {
        public string DeviceId { get; set; }
        public DeviceFingerprint Fingerprint { get; set; }
        public string BlockReason { get; set; }
        public DateTime BlockedAt { get; set; }
    }

    public class DeviceSession
    {
        public string DeviceId { get; set; }
        public MobileDeviceInfo Device { get; set; }
        public DateTime ConnectedAt { get; set; }
        public DateTime? DisconnectedAt { get; set; }
        public TimeSpan? Duration { get; set; }
    }

    public class AdbDeviceInfo
    {
        public string Serial { get; set; }
        public string Model { get; set; }
        public string DeviceName { get; set; }
        public string AndroidVersion { get; set; }
    }

    public class MobileScanResult
    {
        public string ScanId { get; set; }
        public MobileDeviceInfo Device { get; set; }
        public DateTime ScanTime { get; set; }
        public int FilesScanned { get; set; }
        public int RiskScore { get; set; }
        public bool IsBlocked { get; set; }
        public string BlockReason { get; set; }

        public List<MobileSuspiciousFileInfo> SuspiciousFiles { get; set; } = new List<MobileSuspiciousFileInfo>();
        public List<SensitiveFileInfo> SensitiveFiles { get; set; } = new List<SensitiveFileInfo>();
        public List<ApkFileInfo> ApkFiles { get; set; } = new List<ApkFileInfo>();
        public List<InstalledAppInfo> InstalledApps { get; set; } = new List<InstalledAppInfo>();
        public AndroidSecurityInfo SecurityInfo { get; set; }
        public IOSDeviceInfo IOSInfo { get; set; }
        public List<string> Errors { get; set; } = new List<string>();
    }

    public class MobileSuspiciousFileInfo
    {
        public string FilePath { get; set; }
        public string Extension { get; set; }
        public string Reason { get; set; }
        public FileRiskLevel RiskLevel { get; set; }
    }

    public class SensitiveFileInfo
    {
        public string FilePath { get; set; }
        public string RuleName { get; set; }
        public FileRiskLevel RiskLevel { get; set; }
    }

    public class ApkFileInfo
    {
        public string FilePath { get; set; }
        public long Size { get; set; }
    }

    public class InstalledAppInfo
    {
        public string PackageName { get; set; }
        public bool IsSystemApp { get; set; }
        public bool IsSuspicious { get; set; }
        public string SuspicionReason { get; set; }
    }

    public class AndroidSecurityInfo
    {
        public bool USBDebuggingEnabled { get; set; }
        public bool UnknownSourcesEnabled { get; set; }
        public bool IsRooted { get; set; }
        public string AndroidVersion { get; set; }
        public string SecurityPatchLevel { get; set; }
    }

    public class IOSDeviceInfo
    {
        public string BackupPath { get; set; }
        public bool HasBackup { get; set; }
        public bool IsJailbroken { get; set; }
    }

    public class SensitiveFileRule
    {
        public string Name { get; set; }
        public string[] Patterns { get; set; }
        public FileRiskLevel RiskLevel { get; set; }
        public FilterAction Action { get; set; }
    }

    public class FileTransferLog
    {
        public string FilePath { get; set; }
        public TransferDirection Direction { get; set; }
        public string DeviceId { get; set; }
        public FileRiskLevel RiskLevel { get; set; }
        public DateTime Timestamp { get; set; }
    }

    public class FileTransferCheckResult
    {
        public string FilePath { get; set; }
        public TransferDirection Direction { get; set; }
        public string DeviceId { get; set; }
        public DateTime CheckTime { get; set; }
        public FileRiskLevel RiskLevel { get; set; }
        public bool ShouldBlock { get; set; }
        public string BlockReason { get; set; }
        public bool ShouldAlert { get; set; }
        public List<SensitiveFileRule> MatchedRules { get; set; } = new List<SensitiveFileRule>();
    }

    public class MobileSecurityRecommendation
    {
        public RecommendationPriority Priority { get; set; }
        public string Title { get; set; }
        public string Description { get; set; }
        public string Action { get; set; }
    }

    public class DeviceConnectedEventArgs : EventArgs
    {
        public MobileDeviceInfo Device { get; set; }
        public DeviceSession Session { get; set; }
    }

    public class DeviceDisconnectedEventArgs : EventArgs
    {
        public string DeviceId { get; set; }
        public DeviceSession Session { get; set; }
    }

    public class SuspiciousTransferEventArgs : EventArgs
    {
        public string FilePath { get; set; }
        public TransferDirection Direction { get; set; }
        public MobileDeviceInfo Device { get; set; }
        public FileRiskLevel RiskLevel { get; set; }
    }

    public class DeviceSecurityAlertEventArgs : EventArgs
    {
        public MobileDeviceInfo Device { get; set; }
        public string AlertType { get; set; }
        public string Message { get; set; }
    }

    #endregion
}
