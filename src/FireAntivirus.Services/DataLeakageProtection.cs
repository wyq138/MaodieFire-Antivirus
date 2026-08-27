using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using FireAntivirus.Data;
using FireAntivirus.Common;

namespace FireAntivirus.Services
{
    public class DataLeakageProtection : IMonitor
    {
        private readonly DataManager _dataManager;
        private Thread _monitoringThread;
        private bool _isRunning;
        private Dictionary<string, DataLeakageEvent> _leakageEvents;
        private Dictionary<string, DataProtectionRule> _protectionRules;
        private List<string> _sensitiveDataPatterns;
        private List<string> _protectedDirectories;
        private List<string> _allowedApplications;
        private int _monitoringInterval;
        private bool _enableFileMonitoring;
        private bool _enableNetworkMonitoring;
        private bool _enableClipboardMonitoring;
        private bool _enablePrinterMonitoring;
        private bool _enableEmailMonitoring;
        private bool _enableCloudStorageMonitoring;
        private bool _enableRealTimeProtection;
        private int _maxLeakageEvents;

        public DataLeakageProtection(DataManager dataManager)
        {
            _dataManager = dataManager;
            _isRunning = false;
            _leakageEvents = new Dictionary<string, DataLeakageEvent>();
            _protectionRules = new Dictionary<string, DataProtectionRule>();
            _sensitiveDataPatterns = new List<string>();
            _protectedDirectories = new List<string>();
            _allowedApplications = new List<string>();
            _monitoringInterval = 5000;
            _enableFileMonitoring = true;
            _enableNetworkMonitoring = true;
            _enableClipboardMonitoring = true;
            _enablePrinterMonitoring = true;
            _enableEmailMonitoring = true;
            _enableCloudStorageMonitoring = true;
            _enableRealTimeProtection = true;
            _maxLeakageEvents = 1000;

            InitializeSensitiveDataPatterns();
            InitializeProtectionRules();
            InitializeProtectedDirectories();
            InitializeAllowedApplications();
        }

        public void Start()
        {
            if (_isRunning)
                return;

            _isRunning = true;
            _monitoringThread = new Thread(RunMonitoring);
            _monitoringThread.IsBackground = true;
            _monitoringThread.Start();

            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "DataLeakageProtectionStart",
                Message = "数据泄露防护已启动",
                Details = "开始监控敏感数据泄露"
            });
        }

        public void Stop()
        {
            _isRunning = false;
            if (_monitoringThread != null && _monitoringThread.IsAlive)
            {
                _monitoringThread.Join(2000);
            }

            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "DataLeakageProtectionStop",
                Message = "数据泄露防护已停止",
                Details = "停止监控敏感数据泄露"
            });
        }

        private void RunMonitoring()
        {
            try
            {
                while (_isRunning)
                {
                    // 监控文件操作
                    if (_enableFileMonitoring)
                    {
                        MonitorFileOperations();
                    }

                    // 监控网络传输
                    if (_enableNetworkMonitoring)
                    {
                        MonitorNetworkTransmission();
                    }

                    // 监控剪贴板
                    if (_enableClipboardMonitoring)
                    {
                        MonitorClipboard();
                    }

                    // 监控打印操作
                    if (_enablePrinterMonitoring)
                    {
                        MonitorPrintOperations();
                    }

                    // 监控邮件发送
                    if (_enableEmailMonitoring)
                    {
                        MonitorEmailSending();
                    }

                    // 监控云存储上传
                    if (_enableCloudStorageMonitoring)
                    {
                        MonitorCloudStorageUploads();
                    }

                    // 清理过期的泄露事件
                    CleanupOldLeakageEvents();

                    Thread.Sleep(_monitoringInterval);
                }
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "DataLeakageProtectionError",
                    Message = "数据泄露防护错误",
                    Details = ex.Message
                });
            }
        }

        private void InitializeSensitiveDataPatterns()
        {
            // 添加敏感数据模式
            _sensitiveDataPatterns.AddRange(new List<string>
            {
                // 信用卡号
                @"\b(?:\d[ -]*?){13,16}\b",
                // 社会安全号码
                @"\b\d{3}[- ]?\d{2}[- ]?\d{4}\b",
                // 护照号码
                @"\b[A-Z0-9]{6,9}\b",
                // 银行账号
                @"\b\d{8,12}\b",
                // 身份证号码
                @"\b\d{17}[\dXx]\b",
                // 电子邮件地址
                @"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
                // 电话号码
                @"\b\d{10,15}\b",
                // IP地址
                @"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
                // MAC地址
                @"\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b",
                // URL
                @"\bhttp[s]?:\/\/[^\s]+\b",
                // 密码
                @"\bpassword[:\s]*[A-Za-z0-9!@#$%^&*()_+]{6,}\b",
                // API密钥
                @"\bapi[_\s]*key[:\s]*[A-Za-z0-9]{16,}\b",
                // 令牌
                @"\btoken[:\s]*[A-Za-z0-9]{16,}\b",
                // 证书
                @"\bcertificate[:\s]*[A-Za-z0-9+/=]{100,}\b"
            });
        }

        private void InitializeProtectionRules()
        {
            // 添加数据保护规则
            _protectionRules["CreditCard"] = new DataProtectionRule
            {
                Id = "CreditCard",
                Name = "信用卡保护",
                Description = "保护信用卡号不被泄露",
                Severity = "High",
                Enabled = true
            };

            _protectionRules["SocialSecurity"] = new DataProtectionRule
            {
                Id = "SocialSecurity",
                Name = "社会安全号码保护",
                Description = "保护社会安全号码不被泄露",
                Severity = "High",
                Enabled = true
            };

            _protectionRules["BankAccount"] = new DataProtectionRule
            {
                Id = "BankAccount",
                Name = "银行账号保护",
                Description = "保护银行账号不被泄露",
                Severity = "High",
                Enabled = true
            };

            _protectionRules["PersonalInfo"] = new DataProtectionRule
            {
                Id = "PersonalInfo",
                Name = "个人信息保护",
                Description = "保护个人信息不被泄露",
                Severity = "Medium",
                Enabled = true
            };

            _protectionRules["Credentials"] = new DataProtectionRule
            {
                Id = "Credentials",
                Name = "凭证保护",
                Description = "保护账号密码不被泄露",
                Severity = "High",
                Enabled = true
            };

            _protectionRules["APIKeys"] = new DataProtectionRule
            {
                Id = "APIKeys",
                Name = "API密钥保护",
                Description = "保护API密钥不被泄露",
                Severity = "High",
                Enabled = true
            };

            _protectionRules["NetworkTransmission"] = new DataProtectionRule
            {
                Id = "NetworkTransmission",
                Name = "网络传输保护",
                Description = "保护敏感数据通过网络传输",
                Severity = "Medium",
                Enabled = true
            };

            _protectionRules["FileAccess"] = new DataProtectionRule
            {
                Id = "FileAccess",
                Name = "文件访问保护",
                Description = "保护敏感文件不被未授权访问",
                Severity = "Medium",
                Enabled = true
            };
        }

        private void InitializeProtectedDirectories()
        {
            // 添加受保护的目录
            _protectedDirectories.AddRange(new List<string>
            {
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads")
            });
        }

        private void InitializeAllowedApplications()
        {
            // 添加允许的应用程序
            _allowedApplications.AddRange(new List<string>
            {
                "chrome.exe",
                "firefox.exe",
                "edge.exe",
                "outlook.exe",
                "word.exe",
                "excel.exe",
                "powerpoint.exe",
                "notepad.exe",
                "notepad++.exe",
                "vs Code.exe"
            });
        }

        private void MonitorFileOperations()
        {
            try
            {
                // 这里可以实现监控文件操作的逻辑
                // 例如通过文件系统钩子或WMI事件
                // 这里仅作为示例
                var recentFiles = GetRecentFiles();
                foreach (var file in recentFiles)
                {
                    if (ContainsSensitiveData(file))
                    {
                        var eventId = $"File_{Path.GetFileName(file)}_{DateTime.Now.Ticks}";
                        _leakageEvents[eventId] = new DataLeakageEvent
                        {
                            Id = eventId,
                            Type = "FileAccess",
                            Severity = "Medium",
                            Description = "检测到敏感数据文件访问",
                            FilePath = file,
                            Timestamp = DateTime.Now,
                            Application = GetCurrentApplication()
                        };

                        _dataManager.AddLog(new LogEntry
                        {
                            Id = Guid.NewGuid().ToString(),
                            Time = DateTime.Now,
                            Type = "DataLeakageFileAccess",
                            Message = "检测到敏感数据文件访问",
                            Details = $"文件: {file}, 应用程序: {GetCurrentApplication()}"
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "DataLeakageFileMonitoringError",
                    Message = "文件监控错误",
                    Details = ex.Message
                });
            }
        }

        private void MonitorNetworkTransmission()
        {
            try
            {
                // 这里可以实现监控网络传输的逻辑
                // 例如通过网络数据包捕获
                // 这里仅作为示例
                var networkPackets = GetRecentNetworkPackets();
                foreach (var packet in networkPackets)
                {
                    if (ContainsSensitiveData(packet))
                    {
                        var eventId = $"Network_{packet.SourceIP}_{DateTime.Now.Ticks}";
                        _leakageEvents[eventId] = new DataLeakageEvent
                        {
                            Id = eventId,
                            Type = "NetworkTransmission",
                            Severity = "High",
                            Description = "检测到敏感数据网络传输",
                            SourceIP = packet.SourceIP,
                            DestinationIP = packet.DestinationIP,
                            Timestamp = DateTime.Now,
                            Application = packet.Application
                        };

                        _dataManager.AddLog(new LogEntry
                        {
                            Id = Guid.NewGuid().ToString(),
                            Time = DateTime.Now,
                            Type = "DataLeakageNetworkTransmission",
                            Message = "检测到敏感数据网络传输",
                            Details = $"源IP: {packet.SourceIP}, 目标IP: {packet.DestinationIP}, 应用程序: {packet.Application}"
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "DataLeakageNetworkMonitoringError",
                    Message = "网络监控错误",
                    Details = ex.Message
                });
            }
        }

        private void MonitorClipboard()
        {
            try
            {
                // 这里可以实现监控剪贴板的逻辑
                // 例如通过Windows API获取剪贴板内容
                // 这里仅作为示例
                string clipboardContent = GetClipboardContent();
                if (!string.IsNullOrEmpty(clipboardContent) && ContainsSensitiveData(clipboardContent))
                {
                    var eventId = $"Clipboard_{DateTime.Now.Ticks}";
                    _leakageEvents[eventId] = new DataLeakageEvent
                    {
                        Id = eventId,
                        Type = "Clipboard",
                        Severity = "Medium",
                        Description = "检测到敏感数据复制到剪贴板",
                        ClipboardContent = clipboardContent.Substring(0, Math.Min(100, clipboardContent.Length)),
                        Timestamp = DateTime.Now,
                        Application = GetCurrentApplication()
                    };

                    _dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "DataLeakageClipboard",
                        Message = "检测到敏感数据复制到剪贴板",
                        Details = $"应用程序: {GetCurrentApplication()}"
                    });
                }
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "DataLeakageClipboardMonitoringError",
                    Message = "剪贴板监控错误",
                    Details = ex.Message
                });
            }
        }

        private void MonitorPrintOperations()
        {
            try
            {
                // 这里可以实现监控打印操作的逻辑
                // 例如通过WMI事件监控打印作业
                // 这里仅作为示例
                var printJobs = GetRecentPrintJobs();
                foreach (var job in printJobs)
                {
                    if (ContainsSensitiveData(job.DocumentName))
                    {
                        var eventId = $"Print_{job.DocumentName}_{DateTime.Now.Ticks}";
                        _leakageEvents[eventId] = new DataLeakageEvent
                        {
                            Id = eventId,
                            Type = "Print",
                            Severity = "Medium",
                            Description = "检测到敏感数据打印",
                            DocumentName = job.DocumentName,
                            PrinterName = job.PrinterName,
                            Timestamp = DateTime.Now,
                            Application = job.Application
                        };

                        _dataManager.AddLog(new LogEntry
                        {
                            Id = Guid.NewGuid().ToString(),
                            Time = DateTime.Now,
                            Type = "DataLeakagePrint",
                            Message = "检测到敏感数据打印",
                            Details = $"文档: {job.DocumentName}, 打印机: {job.PrinterName}, 应用程序: {job.Application}"
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "DataLeakagePrintMonitoringError",
                    Message = "打印监控错误",
                    Details = ex.Message
                });
            }
        }

        private void MonitorEmailSending()
        {
            try
            {
                // 这里可以实现监控邮件发送的逻辑
                // 例如通过MAPI或其他邮件API
                // 这里仅作为示例
                var emails = GetRecentSentEmails();
                foreach (var email in emails)
                {
                    if (ContainsSensitiveData(email.Body) || email.Attachments.Any(ContainsSensitiveData))
                    {
                        var eventId = $"Email_{email.Subject}_{DateTime.Now.Ticks}";
                        _leakageEvents[eventId] = new DataLeakageEvent
                        {
                            Id = eventId,
                            Type = "Email",
                            Severity = "High",
                            Description = "检测到敏感数据通过邮件发送",
                            EmailSubject = email.Subject,
                            Recipients = string.Join(", ", email.Recipients),
                            Timestamp = DateTime.Now,
                            Application = email.Application
                        };

                        _dataManager.AddLog(new LogEntry
                        {
                            Id = Guid.NewGuid().ToString(),
                            Time = DateTime.Now,
                            Type = "DataLeakageEmail",
                            Message = "检测到敏感数据通过邮件发送",
                            Details = $"主题: {email.Subject}, 收件人: {string.Join(", ", email.Recipients)}, 应用程序: {email.Application}"
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "DataLeakageEmailMonitoringError",
                    Message = "邮件监控错误",
                    Details = ex.Message
                });
            }
        }

        private void MonitorCloudStorageUploads()
        {
            try
            {
                // 这里可以实现监控云存储上传的逻辑
                // 例如通过监控文件系统操作或应用程序API
                // 这里仅作为示例
                var uploads = GetRecentCloudUploads();
                foreach (var upload in uploads)
                {
                    if (ContainsSensitiveData(upload.FilePath))
                    {
                        var eventId = $"Cloud_{Path.GetFileName(upload.FilePath)}_{DateTime.Now.Ticks}";
                        _leakageEvents[eventId] = new DataLeakageEvent
                        {
                            Id = eventId,
                            Type = "CloudStorage",
                            Severity = "High",
                            Description = "检测到敏感数据上传到云存储",
                            FilePath = upload.FilePath,
                            CloudService = upload.CloudService,
                            Timestamp = DateTime.Now,
                            Application = upload.Application
                        };

                        _dataManager.AddLog(new LogEntry
                        {
                            Id = Guid.NewGuid().ToString(),
                            Time = DateTime.Now,
                            Type = "DataLeakageCloudStorage",
                            Message = "检测到敏感数据上传到云存储",
                            Details = $"文件: {upload.FilePath}, 云服务: {upload.CloudService}, 应用程序: {upload.Application}"
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "DataLeakageCloudStorageMonitoringError",
                    Message = "云存储监控错误",
                    Details = ex.Message
                });
            }
        }

        public bool ContainsSensitiveData(string content)
        {
            foreach (var pattern in _sensitiveDataPatterns)
            {
                if (Regex.IsMatch(content, pattern))
                {
                    return true;
                }
            }
            return false;
        }

        private bool CheckFileForSensitiveData(string filePath)
        {
            try
            {
                if (File.Exists(filePath))
                {
                    string content = File.ReadAllText(filePath);
                    return ContainsSensitiveData(content);
                }
                return false;
            }
            catch
            {
                return false;
            }
        }

        private bool ContainsSensitiveData(NetworkPacket packet)
        {
            if (packet?.Payload == null || packet.Payload.Length == 0)
                return false;
            try
            {
                var content = Encoding.UTF8.GetString(packet.Payload);
                return ContainsSensitiveData(content);
            }
            catch { return false; }
        }

        private List<string> GetRecentFiles()
        {
            var recentFiles = new List<string>();
            try
            {
                // 使用WMI获取最近访问的文件
                using var searcher = new System.Management.ManagementObjectSearcher(
                    "SELECT * FROM Win32_Process WHERE SessionId = 0");
                
                // 获取最近访问的文件
                foreach (var dir in _protectedDirectories)
                {
                    if (Directory.Exists(dir))
                    {
                        try
                        {
                            var files = Directory.GetFiles(dir, "*.*", SearchOption.TopDirectoryOnly)
                                .OrderByDescending(f => File.GetLastAccessTime(f))
                                .Take(10);
                            recentFiles.AddRange(files);
                        }
                        catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "DataLeakageProtection.cs 捕获异常", ex.Message); }
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "DataLeakageProtection.cs 捕获异常", ex.Message); }
            return recentFiles;
        }

        private List<NetworkPacket> GetRecentNetworkPackets()
        {
            var packets = new List<NetworkPacket>();
            try
            {
                var properties = IPGlobalProperties.GetIPGlobalProperties();
                var connections = properties.GetActiveTcpConnections()
                    .Where(c => c.State == TcpState.Established)
                    .Take(20);
                
                foreach (var conn in connections)
                {
                    packets.Add(new NetworkPacket
                    {
                        Id = Guid.NewGuid().ToString(),
                        SourceIP = conn.LocalEndPoint.Address.ToString(),
                        DestinationIP = conn.RemoteEndPoint.Address.ToString(),
                        SourceEndPoint = conn.LocalEndPoint,
                        DestinationEndPoint = conn.RemoteEndPoint,
                        Protocol = "TCP",
                        Timestamp = DateTime.Now,
                        Application = GetProcessNameByPort(conn.LocalEndPoint.Port)
                    });
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "DataLeakageProtection.cs 捕获异常", ex.Message); }
            return packets;
        }

        private string GetProcessNameByPort(int port)
        {
            try
            {
                var processes = Process.GetProcesses();
                foreach (var process in processes)
                {
                    try
                    {
                        // 使用netstat获取进程与端口的关联
                        using var searcher = new System.Management.ManagementObjectSearcher(
                            $"SELECT * FROM Win32_Process");
                        // 简化处理，返回当前活动进程
                    }
                    catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "DataLeakageProtection.cs 捕获异常", ex.Message); }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "DataLeakageProtection.cs 捕获异常", ex.Message); }
            return "Unknown";
        }

        [DllImport("user32.dll")]
        private static extern bool OpenClipboard(IntPtr hWndNewOwner);
        [DllImport("user32.dll")]
        private static extern bool CloseClipboard();
        [DllImport("user32.dll")]
        private static extern IntPtr GetClipboardData(uint uFormat);
        [DllImport("user32.dll")]
        private static extern bool IsClipboardFormatAvailable(uint format);
        [DllImport("kernel32.dll")]
        private static extern IntPtr GlobalLock(IntPtr hMem);
        [DllImport("kernel32.dll")]
        private static extern bool GlobalUnlock(IntPtr hMem);
        [DllImport("kernel32.dll")]
        private static extern int GlobalSize(IntPtr hMem);
        private const uint CF_UNICODETEXT = 13;

        private string GetClipboardContent()
        {
            try
            {
                if (!IsClipboardFormatAvailable(CF_UNICODETEXT))
                    return string.Empty;
                
                if (!OpenClipboard(IntPtr.Zero))
                    return string.Empty;
                
                try
                {
                    var handle = GetClipboardData(CF_UNICODETEXT);
                    if (handle == IntPtr.Zero)
                        return string.Empty;
                    
                    var pointer = GlobalLock(handle);
                    if (pointer == IntPtr.Zero)
                        return string.Empty;
                    
                    var size = GlobalSize(handle);
                    var buffer = new byte[size];
                    Marshal.Copy(pointer, buffer, 0, size);
                    GlobalUnlock(handle);
                    
                    return Encoding.Unicode.GetString(buffer).TrimEnd('\0');
                }
                finally
                {
                    CloseClipboard();
                }
            }
            catch { return string.Empty; }
        }

        private List<PrintJob> GetRecentPrintJobs()
        {
            var jobs = new List<PrintJob>();
            try
            {
                using var searcher = new System.Management.ManagementObjectSearcher(
                    "SELECT * FROM Win32_PrintJob");
                foreach (var obj in searcher.Get())
                {
                    jobs.Add(new PrintJob
                    {
                        DocumentName = obj["Name"]?.ToString() ?? "Unknown",
                        PrinterName = obj["PrinterName"]?.ToString() ?? "Unknown",
                        Application = "System",
                        Timestamp = DateTime.Now
                    });
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "DataLeakageProtection.cs 捕获异常", ex.Message); }
            return jobs;
        }

        private List<Email> GetRecentSentEmails()
        {
            // 邮件监控需要特定权限和MAPI支持，返回空列表避免隐私问题
            return new List<Email>();
        }

        private List<CloudUpload> GetRecentCloudUploads()
        {
            var uploads = new List<CloudUpload>();
            try
            {
                // 监控常见云存储文件夹
                var cloudFolders = new[]
                {
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "OneDrive"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Dropbox"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Google Drive"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "iCloudDrive")
                };
                
                foreach (var folder in cloudFolders)
                {
                    if (Directory.Exists(folder))
                    {
                        try
                        {
                            var recentFiles = Directory.GetFiles(folder, "*.*", SearchOption.AllDirectories)
                                .Where(f => File.GetLastWriteTime(f) > DateTime.Now.AddMinutes(-5))
                                .Take(10);
                            
                            foreach (var file in recentFiles)
                            {
                                uploads.Add(new CloudUpload
                                {
                                    FilePath = file,
                                    CloudService = Path.GetFileName(folder),
                                    Application = "CloudSync",
                                    Timestamp = File.GetLastWriteTime(file)
                                });
                            }
                        }
                        catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "DataLeakageProtection.cs 捕获异常", ex.Message); }
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "DataLeakageProtection.cs 捕获异常", ex.Message); }
            return uploads;
        }

        private string GetCurrentApplication()
        {
            try
            {
                var foregroundWindow = GetForegroundWindow();
                var processId = 0;
                GetWindowThreadProcessId(foregroundWindow, out processId);
                var process = Process.GetProcessById(processId);
                return process.ProcessName;
            }
            catch { return "Unknown"; }
        }

        [DllImport("user32.dll")]
        private static extern IntPtr GetForegroundWindow();
        [DllImport("user32.dll")]
        private static extern int GetWindowThreadProcessId(IntPtr hWnd, out int processId);

        private void CleanupOldLeakageEvents()
        {
            // 清理过期的泄露事件
            if (_leakageEvents.Count > _maxLeakageEvents)
            {
                var keysToRemove = _leakageEvents.Keys.Take(_leakageEvents.Count - _maxLeakageEvents).ToList();
                foreach (var key in keysToRemove)
                {
                    _leakageEvents.Remove(key);
                }
            }
        }

        public List<DataLeakageEvent> GetLeakageEvents()
        {
            return _leakageEvents.Values.ToList();
        }

        public List<DataProtectionRule> GetProtectionRules()
        {
            return _protectionRules.Values.ToList();
        }

        public void AddSensitiveDataPattern(string pattern)
        {
            if (!_sensitiveDataPatterns.Contains(pattern))
            {
                _sensitiveDataPatterns.Add(pattern);
            }
        }

        public void RemoveSensitiveDataPattern(string pattern)
        {
            _sensitiveDataPatterns.Remove(pattern);
        }

        public void AddProtectedDirectory(string directory)
        {
            if (!_protectedDirectories.Contains(directory))
            {
                _protectedDirectories.Add(directory);
            }
        }

        public void RemoveProtectedDirectory(string directory)
        {
            _protectedDirectories.Remove(directory);
        }

        public void AddAllowedApplication(string application)
        {
            if (!_allowedApplications.Contains(application))
            {
                _allowedApplications.Add(application);
            }
        }

        public void RemoveAllowedApplication(string application)
        {
            _allowedApplications.Remove(application);
        }

        public void SetMonitoringInterval(int interval)
        {
            _monitoringInterval = interval;
        }

        public void EnableFileMonitoring(bool enable)
        {
            _enableFileMonitoring = enable;
        }

        public void EnableNetworkMonitoring(bool enable)
        {
            _enableNetworkMonitoring = enable;
        }

        public void EnableClipboardMonitoring(bool enable)
        {
            _enableClipboardMonitoring = enable;
        }

        public void EnablePrinterMonitoring(bool enable)
        {
            _enablePrinterMonitoring = enable;
        }

        public void EnableEmailMonitoring(bool enable)
        {
            _enableEmailMonitoring = enable;
        }

        public void EnableCloudStorageMonitoring(bool enable)
        {
            _enableCloudStorageMonitoring = enable;
        }

        public void EnableRealTimeProtection(bool enable)
        {
            _enableRealTimeProtection = enable;
        }

        public void SetMaxLeakageEvents(int max)
        {
            _maxLeakageEvents = max;
        }
    }

    public class DataLeakageEvent
    {
        public string Id { get; set; }
        public string Type { get; set; }
        public string Severity { get; set; }
        public string Description { get; set; }
        public string FilePath { get; set; }
        public string SourceIP { get; set; }
        public string DestinationIP { get; set; }
        public string ClipboardContent { get; set; }
        public string DocumentName { get; set; }
        public string PrinterName { get; set; }
        public string EmailSubject { get; set; }
        public string Recipients { get; set; }
        public string CloudService { get; set; }
        public string Application { get; set; }
        public DateTime Timestamp { get; set; }
        public bool IsBlocked { get; set; }
        public string ActionTaken { get; set; }
    }

    public class DataProtectionRule
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public string Severity { get; set; }
        public bool Enabled { get; set; }
        public DateTime CreatedDate { get; set; } = DateTime.Now;
        public DateTime LastModifiedDate { get; set; } = DateTime.Now;
    }

    public class NetworkPacket
    {
        public string Id { get; set; }
        public string SourceIP { get; set; }
        public string DestinationIP { get; set; }
        public IPEndPoint SourceEndPoint { get; set; }
        public IPEndPoint DestinationEndPoint { get; set; }
        public string Protocol { get; set; }
        public int Length { get; set; }
        public byte[] Payload { get; set; }
        public string Application { get; set; }
        public DateTime Timestamp { get; set; }
    }

    public class PrintJob
    {
        public string DocumentName { get; set; }
        public string PrinterName { get; set; }
        public string Application { get; set; }
        public DateTime Timestamp { get; set; }
    }

    public class Email
    {
        public string Subject { get; set; }
        public string Body { get; set; }
        public List<string> Recipients { get; set; } = new List<string>();
        public List<string> Attachments { get; set; } = new List<string>();
        public string Application { get; set; }
        public DateTime Timestamp { get; set; }
    }

    public class CloudUpload
    {
        public string FilePath { get; set; }
        public string CloudService { get; set; }
        public string Application { get; set; }
        public DateTime Timestamp { get; set; }
    }
}