using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Security.Cryptography;
using FireAntivirus.Data;
using FireAntivirus.Engine;
using System.Linq;

namespace FireAntivirus.Services
{
    public class FileMonitor : IMonitor
    {
        private Thread _monitorThread;
        private bool _isRunning;
        private readonly DataManager _dataManager;
        private readonly AntivirusEngine _antivirusEngine;
        private List<FileSystemWatcher> _fileWatchers;
        private HashSet<string> _monitoredExtensions;
        private HashSet<string> _protectedDirectories;
        private HashSet<string> _recentlyScannedFiles;
        private Dictionary<string, FileIntegrityInfo> _fileIntegrityMap;
        private Dictionary<string, FileOperationInfo> _fileOperationTrack;
        private object _scanLock;
        private Timer _integrityCheckTimer;

        public FileMonitor(DataManager dataManager, AntivirusEngine antivirusEngine)
        {
            _dataManager = dataManager;
            _antivirusEngine = antivirusEngine;
            _fileWatchers = new List<FileSystemWatcher>();
            _recentlyScannedFiles = new HashSet<string>();
            _fileIntegrityMap = new Dictionary<string, FileIntegrityInfo>();
            _fileOperationTrack = new Dictionary<string, FileOperationInfo>();
            _scanLock = new object();
            InitializeMonitoredExtensions();
            InitializeProtectedDirectories();
        }

        private void InitializeMonitoredExtensions()
        {
            // 监控的文件扩展名
            _monitoredExtensions = new HashSet<string>
            {
                ".exe", ".dll", ".sys", ".com", ".bat", ".cmd", ".ps1", ".js", ".vbs", ".wsf",
                ".html", ".htm", ".xml", ".txt", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
                ".pdf", ".zip", ".rar", ".7z", ".tar", ".gz", ".iso", ".img",
                ".ini", ".cfg", ".config", ".reg", ".msi", ".msp", ".mst", ".tmp", ".scr"
            };
        }

        private void InitializeProtectedDirectories()
        {
            // 保护的目录
            _protectedDirectories = new HashSet<string>
            {
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + "\\AppData\\Roaming",
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + "\\AppData\\Local",
                Environment.GetFolderPath(Environment.SpecialFolder.Startup),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),
                "C:\\Windows",
                "C:\\Windows\\System32",
                "C:\\Windows\\SysWOW64"
            };
        }

        public void Start()
        {
            if (_isRunning)
                return;

            _isRunning = true;
            _monitorThread = new Thread(MonitorFiles);
            _monitorThread.IsBackground = true;
            _monitorThread.Start();

            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "FileMonitorStart",
                Message = "文件监控已启动",
                Details = "开始监控系统文件，包括文件创建、修改、删除和重命名"
            });
        }

        public void Stop()
        {
            _isRunning = false;
            if (_monitorThread != null && _monitorThread.IsAlive)
            {
                _monitorThread.Join(2000);
            }

            CleanupWatchers();
            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "FileMonitorStop",
                Message = "文件监控已停止",
                Details = string.Empty
            });
        }

        private void MonitorFiles()
        {
            try
            {
                SetupFileWatchers();

                // 启动定期清理最近扫描文件列表的线程
                Thread cleanupThread = new Thread(CleanupRecentlyScannedFiles);
                cleanupThread.IsBackground = true;
                cleanupThread.Start();

                while (_isRunning)
                {
                    Thread.Sleep(1000);
                }
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "FileMonitorError",
                    Message = "文件监控错误",
                    Details = ex.Message
                });
            }
            finally
            {
                CleanupWatchers();
            }
        }

        private void SetupFileWatchers()
        {
            try
            {
                // 监控所有保护目录
                foreach (string directory in _protectedDirectories)
                {
                    if (Directory.Exists(directory))
                    {
                        // 对于系统目录，不监控子目录，减少系统负载
                        bool includeSubdirectories = !directory.StartsWith("C:\\Windows") && 
                                                   !directory.Equals(Environment.GetFolderPath(Environment.SpecialFolder.System));
                        SetupDirectoryWatcher(directory, includeSubdirectories);
                    }
                }

                // 也监控用户目录
                string userDirectory = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                if (Directory.Exists(userDirectory))
                {
                    // 用户目录只监控特定子目录
                    SetupDirectoryWatcher(userDirectory, false);
                    
                    // 监控用户的桌面、文档等关键目录
                    string[] userSubDirs = {
                        Path.Combine(userDirectory, "Desktop"),
                        Path.Combine(userDirectory, "Documents"),
                        Path.Combine(userDirectory, "Downloads")
                    };
                    
                    foreach (string subDir in userSubDirs)
                    {
                        if (Directory.Exists(subDir))
                        {
                            SetupDirectoryWatcher(subDir, true);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "FileWatcherSetupError",
                    Message = "文件监控设置错误",
                    Details = ex.Message
                });
            }
        }

        private void SetupDirectoryWatcher(string directoryPath, bool includeSubdirectories)
        {
            try
            {
                FileSystemWatcher watcher = new FileSystemWatcher();
                watcher.Path = directoryPath;
                watcher.IncludeSubdirectories = includeSubdirectories;
                watcher.NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.CreationTime;
                watcher.Filter = "*.*";

                watcher.Created += new FileSystemEventHandler(OnFileCreated);
                watcher.Changed += new FileSystemEventHandler(OnFileChanged);
                watcher.Deleted += new FileSystemEventHandler(OnFileDeleted);
                watcher.Renamed += new RenamedEventHandler(OnFileRenamed);

                watcher.EnableRaisingEvents = true;
                _fileWatchers.Add(watcher);

                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "FileWatcherStarted",
                    Message = "文件监控已启动",
                    Details = $"监控目录: {directoryPath}, 包含子目录: {includeSubdirectories}"
                });
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "DirectoryWatcherError",
                    Message = "目录监控错误",
                    Details = $"目录: {directoryPath}, 错误: {ex.Message}"
                });
            }
        }

        private void CleanupWatchers()
        {
            foreach (var watcher in _fileWatchers)
            {
                try
                {
                    watcher.EnableRaisingEvents = false;
                    watcher.Dispose();
                }
                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "FileMonitor.cs 捕获异常", ex.Message); }
            }
            _fileWatchers.Clear();
        }

        private void CleanupRecentlyScannedFiles()
        {
            while (_isRunning)
            {
                Thread.Sleep(60000); // 每分钟清理一次
                lock (_scanLock)
                {
                    _recentlyScannedFiles.Clear();
                }
            }
        }

        private void OnFileCreated(object sender, FileSystemEventArgs e)
        {
            try
            {
                // 只记录重要文件的创建事件
                string extension = Path.GetExtension(e.FullPath).ToLower();
                if (_monitoredExtensions.Contains(extension))
                {
                    _dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "FileCreated",
                        Message = "文件创建",
                        Details = $"文件: {e.FullPath}"
                    });
                }
                ScanFile(e.FullPath);
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "FileCreationError",
                    Message = "文件创建处理错误",
                    Details = ex.Message
                });
            }
        }

        private void OnFileChanged(object sender, FileSystemEventArgs e)
        {
            try
            {
                // 只记录重要文件的修改事件
                string extension = Path.GetExtension(e.FullPath).ToLower();
                if (_monitoredExtensions.Contains(extension))
                {
                    _dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "FileChanged",
                        Message = "文件修改",
                        Details = $"文件: {e.FullPath}"
                    });
                }
                ScanFile(e.FullPath);
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "FileChangeError",
                    Message = "文件修改处理错误",
                    Details = ex.Message
                });
            }
        }

        private void OnFileDeleted(object sender, FileSystemEventArgs e)
        {
            try
            {
                // 只记录重要文件的删除事件
                string extension = Path.GetExtension(e.FullPath).ToLower();
                if (_monitoredExtensions.Contains(extension))
                {
                    _dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "FileDeleted",
                        Message = "文件删除",
                        Details = $"文件: {e.FullPath}"
                    });
                }
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "FileDeletionError",
                    Message = "文件删除处理错误",
                    Details = ex.Message
                });
            }
        }

        private void OnFileRenamed(object sender, RenamedEventArgs e)
        {
            try
            {
                // 只记录重要文件的重命名事件
                string extension = Path.GetExtension(e.FullPath).ToLower();
                if (_monitoredExtensions.Contains(extension))
                {
                    _dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "FileRenamed",
                        Message = "文件重命名",
                        Details = $"旧文件: {e.OldFullPath}, 新文件: {e.FullPath}"
                    });
                }
                ScanFile(e.FullPath);
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "FileRenameError",
                    Message = "文件重命名处理错误",
                    Details = ex.Message
                });
            }
        }

        private void ScanFile(string filePath)
        {
            try
            {
                // 防抖：避免重复扫描同一文件
                lock (_scanLock)
                {
                    if (_recentlyScannedFiles.Contains(filePath))
                    {
                        return;
                    }
                    _recentlyScannedFiles.Add(filePath);
                }

                if (!File.Exists(filePath))
                    return;

                // 检查文件大小，避免扫描过大的文件
                FileInfo fileInfo = new FileInfo(filePath);
                if (fileInfo.Length > 50 * 1024 * 1024) // 50MB
                {
                    // 只记录可执行文件的跳过事件
                    string extension = Path.GetExtension(filePath).ToLower();
                    if (extension == ".exe" || extension == ".dll")
                    {
                        _dataManager.AddLog(new LogEntry
                        {
                            Id = Guid.NewGuid().ToString(),
                            Time = DateTime.Now,
                            Type = "LargeFileSkipped",
                            Message = "跳过大型文件",
                            Details = $"文件: {filePath}, 大小: {fileInfo.Length / 1024 / 1024}MB"
                        });
                    }
                    return;
                }

                // 检查文件扩展名，优先扫描可执行文件
                string fileExtension = Path.GetExtension(filePath).ToLower();
                bool isMonitored = _monitoredExtensions.Contains(fileExtension);
                
                if (isMonitored)
                {
                    // 只记录可执行文件的扫描事件
                    if (fileExtension == ".exe" || fileExtension == ".dll")
                    {
                        _dataManager.AddLog(new LogEntry
                        {
                            Id = Guid.NewGuid().ToString(),
                            Time = DateTime.Now,
                            Type = "FileScanning",
                            Message = "正在扫描文件",
                            Details = $"文件: {filePath}, 扩展名: {fileExtension}"
                        });
                    }
                    
                    var result = _antivirusEngine.ScanFile(filePath);
                    
                    if (result.IsInfected)
                    {
                        _dataManager.AddLog(new LogEntry
                        {
                            Id = Guid.NewGuid().ToString(),
                            Time = DateTime.Now,
                            Type = "MaliciousFileDetected",
                            Message = "发现恶意文件",
                            Details = $"文件: {filePath}, 威胁: {result.ThreatName}, 置信度: {result.Confidence:P}"
                        });
                        
                        // 尝试隔离恶意文件
                        TryQuarantineFile(filePath, result.ThreatName);
                    }
                    else if (result.Confidence > 0.7)
                    {
                        _dataManager.AddLog(new LogEntry
                        {
                            Id = Guid.NewGuid().ToString(),
                            Time = DateTime.Now,
                            Type = "SuspiciousFileDetected",
                            Message = "发现可疑文件",
                            Details = $"文件: {filePath}, 置信度: {result.Confidence:P}"
                        });
                    }
                    // 不再记录安全文件的日志，减少日志量
                }
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "FileScanError",
                    Message = "文件扫描错误",
                    Details = $"文件: {filePath}, 错误: {ex.Message}"
                });
            }
        }

        private void TryQuarantineFile(string filePath, string threatName)
        {
            try
            {
                // 创建隔离目录
                string quarantineDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "FireAntivirus", "Quarantine");
                Directory.CreateDirectory(quarantineDir);
                
                // 生成隔离文件名
                string fileName = Path.GetFileName(filePath);
                string quarantinePath = Path.Combine(quarantineDir, $"{DateTime.Now.Ticks}_{fileName}");
                
                // 移动文件到隔离区
                File.Move(filePath, quarantinePath);
                
                // 记录隔离操作
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "FileQuarantined",
                    Message = "文件已隔离",
                    Details = $"原文件: {filePath}, 隔离位置: {quarantinePath}, 威胁: {threatName}"
                });
                
                // 触发通知
                try
                {
                    NotificationService.Instance.ShowNotification(
                        "恶意文件隔离",
                        $"检测到恶意文件已被隔离:\n原位置: {filePath}\n威胁: {threatName}",
                        NotificationType.Error
                    );
                }
                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "FileMonitor.cs 捕获异常", ex.Message); }
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "QuarantineError",
                    Message = "文件隔离失败",
                    Details = $"文件: {filePath}, 错误: {ex.Message}"
                });
            }
        }

        // 扫描指定目录
        public void ScanDirectory(string directoryPath)
        {
            try
            {
                if (!Directory.Exists(directoryPath))
                {
                    _dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "DirectoryNotFound",
                        Message = "目录不存在",
                        Details = $"目录: {directoryPath}"
                    });
                    return;
                }

                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "DirectoryScanning",
                    Message = "正在扫描目录",
                    Details = $"目录: {directoryPath}"
                });

                // 递归扫描目录
                RecursiveScanDirectory(directoryPath);
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "DirectoryScanError",
                    Message = "目录扫描错误",
                    Details = $"目录: {directoryPath}, 错误: {ex.Message}"
                });
            }
        }

        private void RecursiveScanDirectory(string directoryPath)
        {
            try
            {
                // 扫描文件
                string[] files = Directory.GetFiles(directoryPath);
                foreach (string file in files)
                {
                    ScanFile(file);
                }

                // 递归扫描子目录
                string[] directories = Directory.GetDirectories(directoryPath);
                foreach (string directory in directories)
                {
                    RecursiveScanDirectory(directory);
                }
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "RecursiveScanError",
                    Message = "递归扫描错误",
                    Details = $"目录: {directoryPath}, 错误: {ex.Message}"
                });
            }
        }

        // 扫描系统关键目录
        public void ScanSystemDirectories()
        {
            try
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "SystemScanStart",
                    Message = "开始扫描系统目录",
                    Details = "扫描所有系统关键目录"
                });

                foreach (string directory in _protectedDirectories)
                {
                    if (Directory.Exists(directory))
                    {
                        ScanDirectory(directory);
                    }
                }

                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "SystemScanComplete",
                    Message = "系统目录扫描完成",
                    Details = "已扫描所有系统关键目录"
                });
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "SystemScanError",
                    Message = "系统目录扫描错误",
                    Details = ex.Message
                });
            }
        }

        // 文件完整性信息结构
        public class FileIntegrityInfo
        {
            public string FilePath { get; set; }
            public string Sha256Hash { get; set; }
            public long FileSize { get; set; }
            public DateTime LastModified { get; set; }
            public DateTime CheckTime { get; set; }
            public bool IsTrusted { get; set; }
            public string DigitalSignature { get; set; }
        }

        // 文件操作跟踪信息
        public class FileOperationInfo
        {
            public string FilePath { get; set; }
            public List<FileOperation> RecentOperations { get; set; } = new List<FileOperation>();
            public DateTime FirstOperationTime { get; set; }
            public DateTime LastOperationTime { get; set; }
            public int OperationCount { get; set; }
        }

        // 文件操作类型
        public enum FileOperationType
        {
            Create,
            Modify,
            Delete,
            Rename
        }

        // 文件操作记录
        public class FileOperation
        {
            public FileOperationType OperationType { get; set; }
            public DateTime OperationTime { get; set; }
            public string OldFilePath { get; set; }
            public string NewFilePath { get; set; }
            public string ProcessName { get; set; }
            public int ProcessId { get; set; }
        }

        // 计算文件SHA256哈希
        private string CalculateFileHash(string filePath)
        {
            try
            {
                using (var sha256 = SHA256.Create())
                using (var fileStream = File.OpenRead(filePath))
                {
                    byte[] hash = sha256.ComputeHash(fileStream);
                    return BitConverter.ToString(hash).Replace("-", "").ToLower();
                }
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "HashCalculationError",
                    Message = "文件哈希计算错误",
                    Details = $"文件: {filePath}, 错误: {ex.Message}"
                });
                return null;
            }
        }

        // 验证文件完整性
        private bool VerifyFileIntegrity(string filePath)
        {
            try
            {
                if (!File.Exists(filePath))
                    return false;

                var fileInfo = new FileInfo(filePath);
                string currentHash = CalculateFileHash(filePath);
                
                if (_fileIntegrityMap.ContainsKey(filePath))
                {
                    var storedInfo = _fileIntegrityMap[filePath];
                    
                    // 检查文件是否被修改
                    if (storedInfo.Sha256Hash != currentHash || 
                        storedInfo.FileSize != fileInfo.Length ||
                        storedInfo.LastModified != fileInfo.LastWriteTime)
                    {
                        _dataManager.AddLog(new LogEntry
                        {
                            Id = Guid.NewGuid().ToString(),
                            Time = DateTime.Now,
                            Type = "FileModified",
                            Message = "文件完整性验证失败",
                            Details = $"文件: {filePath}, 原哈希: {storedInfo.Sha256Hash}, 新哈希: {currentHash}"
                        });
                        return false;
                    }
                    return true;
                }
                else
                {
                    // 第一次记录文件完整性信息
                    var integrityInfo = new FileIntegrityInfo
                    {
                        FilePath = filePath,
                        Sha256Hash = currentHash,
                        FileSize = fileInfo.Length,
                        LastModified = fileInfo.LastWriteTime,
                        CheckTime = DateTime.Now,
                        IsTrusted = false,
                        DigitalSignature = ""
                    };
                    
                    _fileIntegrityMap[filePath] = integrityInfo;
                    return true;
                }
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "IntegrityCheckError",
                    Message = "文件完整性检查错误",
                    Details = $"文件: {filePath}, 错误: {ex.Message}"
                });
                return false;
            }
        }

        // 检测异常文件操作模式
        private bool DetectSuspiciousFileOperations(string filePath, FileOperationType operationType)
        {
            try
            {
                var currentProcess = System.Diagnostics.Process.GetCurrentProcess();
                
                if (!_fileOperationTrack.ContainsKey(filePath))
                {
                    _fileOperationTrack[filePath] = new FileOperationInfo
                    {
                        FilePath = filePath,
                        FirstOperationTime = DateTime.Now,
                        LastOperationTime = DateTime.Now,
                        OperationCount = 0
                    };
                }

                var operationInfo = _fileOperationTrack[filePath];
                
                // 记录新的操作
                var operation = new FileOperation
                {
                    OperationType = operationType,
                    OperationTime = DateTime.Now,
                    OldFilePath = filePath,
                    NewFilePath = filePath,
                    ProcessName = currentProcess.ProcessName,
                    ProcessId = currentProcess.Id
                };

                operationInfo.RecentOperations.Add(operation);
                operationInfo.LastOperationTime = DateTime.Now;
                operationInfo.OperationCount++;

                // 清理老旧记录（只保留最近30分钟的操作）
                operationInfo.RecentOperations = operationInfo.RecentOperations
                    .Where(op => (DateTime.Now - op.OperationTime).TotalMinutes <= 30)
                    .ToList();

                // 检测可疑模式
                var recentOps = operationInfo.RecentOperations.OrderBy(op => op.OperationTime).ToList();
                
                // 1. 短时间内多次操作（可能的加密攻击）
                if (recentOps.Count >= 5)
                {
                    var firstOp = recentOps[0];
                    var lastOp = recentOps[recentOps.Count - 1];
                    if ((lastOp.OperationTime - firstOp.OperationTime).TotalSeconds < 10)
                    {
                        _dataManager.AddLog(new LogEntry
                        {
                            Id = Guid.NewGuid().ToString(),
                            Time = DateTime.Now,
                            Type = "SuspiciousFileOperation",
                            Message = "检测到可疑文件操作模式",
                            Details = $"文件: {filePath}, 模式: 频繁操作, 数量: {recentOps.Count}次/10秒"
                        });
                        return true;
                    }
                }

                // 2. 特定路径的异常操作（系统文件被未知进程修改）
                if (filePath.StartsWith("C:\\Windows") && 
                    operationType == FileOperationType.Modify &&
                    !currentProcess.ProcessName.ToLower().Contains("svchost") &&
                    !currentProcess.ProcessName.ToLower().Contains("explorer"))
                {
                    _dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "SystemFileModified",
                        Message = "系统文件被未知进程修改",
                        Details = $"文件: {filePath}, 进程: {currentProcess.ProcessName}({currentProcess.Id})"
                    });
                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "OperationDetectionError",
                    Message = "文件操作检测错误",
                    Details = $"文件: {filePath}, 错误: {ex.Message}"
                });
                return false;
            }
        }

        // 增强的扫描逻辑 - 包含完整性检查
        private void EnhancedFileScan(string filePath, FileOperationType operationType = FileOperationType.Modify)
        {
            try
            {
                // 防抖检查
                lock (_scanLock)
                {
                    if (_recentlyScannedFiles.Contains(filePath))
                    {
                        return;
                    }
                    _recentlyScannedFiles.Add(filePath);
                }

                if (!File.Exists(filePath))
                    return;

                FileInfo fileInfo = new FileInfo(filePath);
                
                // 跳过过大文件
                if (fileInfo.Length > 50 * 1024 * 1024)
                    return;

                string extension = Path.GetExtension(filePath).ToLower();
                bool isMonitored = _monitoredExtensions.Contains(extension);

                if (isMonitored)
                {
                    // 1. 执行文件完整性验证
                    bool integrityOk = VerifyFileIntegrity(filePath);
                    
                    // 2. 检测可疑文件操作模式
                    bool suspiciousOperation = DetectSuspiciousFileOperations(filePath, operationType);
                    
                    // 3. 执行病毒扫描
                    var result = _antivirusEngine.ScanFile(filePath);
                    
                    // 综合威胁评估
                    double threatScore = result.Confidence;
                    if (!integrityOk) threatScore += 0.2;
                    if (suspiciousOperation) threatScore += 0.3;

                    if (result.IsInfected || threatScore > 0.8)
                    {
                        string threatType = result.IsInfected ? "恶意文件" : "高度可疑文件";
                        _dataManager.AddLog(new LogEntry
                        {
                            Id = Guid.NewGuid().ToString(),
                            Time = DateTime.Now,
                            Type = "EnhancedThreatDetected",
                            Message = threatType,
                            Details = $"文件: {filePath}, 威胁: {result.ThreatName}, 得分: {threatScore:F2}, 完整性: {integrityOk}, 可疑操作: {suspiciousOperation}"
                        });
                        
                        TryQuarantineFile(filePath, $"{result.ThreatName} (增强检测)");
                    }
                    else if (threatScore > 0.6 && !integrityOk)
                    {
                        _dataManager.AddLog(new LogEntry
                        {
                            Id = Guid.NewGuid().ToString(),
                            Time = DateTime.Now,
                            Type = "SuspiciousFileModified",
                            Message = "可疑文件被修改",
                            Details = $"文件: {filePath}, 完整性验证失败, 操作: {operationType}"
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
                    Type = "EnhancedScanError",
                    Message = "增强文件扫描错误",
                    Details = $"文件: {filePath}, 错误: {ex.Message}"
                });
            }
        }

        // 启动增强的文件监控
        public void EnhancedStart()
        {
            if (_isRunning)
                return;

            _isRunning = true;
            InitializeIntegrityMonitoring(); // 启动完整性监控
            _monitorThread = new Thread(EnhancedMonitorFiles);
            _monitorThread.IsBackground = true;
            _monitorThread.Start();

            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "EnhancedFileMonitorStart",
                Message = "增强文件监控已启动",
                Details = "启动文件完整性监控和异常操作检测功能"
            });
        }

        // 增强的文件监控线程
        private void EnhancedMonitorFiles()
        {
            try
            {
                SetupEnhancedFileWatchers();

                // 启动定期清理线程
                Thread cleanupThread = new Thread(CleanupRecentlyScannedFiles);
                cleanupThread.IsBackground = true;
                cleanupThread.Start();

                while (_isRunning)
                {
                    Thread.Sleep(1000);
                }
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "EnhancedFileMonitorError",
                    Message = "增强文件监控错误",
                    Details = ex.Message
                });
            }
            finally
            {
                CleanupWatchers();
                _integrityCheckTimer?.Dispose();
            }
        }

        // 设置增强的文件监控器
        private void SetupEnhancedFileWatchers()
        {
            try
            {
                // 监控所有保护目录
                foreach (string directory in _protectedDirectories)
                {
                    if (Directory.Exists(directory))
                    {
                        bool includeSubdirectories = !directory.StartsWith("C:\\Windows");
                        SetupEnhancedDirectoryWatcher(directory, includeSubdirectories);
                    }
                }

                // 监控用户目录
                string userDirectory = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                if (Directory.Exists(userDirectory))
                {
                    SetupEnhancedDirectoryWatcher(userDirectory, false);
                    
                    string[] userSubDirs = {
                        Path.Combine(userDirectory, "Desktop"),
                        Path.Combine(userDirectory, "Documents"),
                        Path.Combine(userDirectory, "Downloads")
                    };
                    
                    foreach (string subDir in userSubDirs)
                    {
                        if (Directory.Exists(subDir))
                        {
                            SetupEnhancedDirectoryWatcher(subDir, true);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "EnhancedFileWatcherSetupError",
                    Message = "增强文件监控设置错误",
                    Details = ex.Message
                });
            }
        }

        private void SetupEnhancedDirectoryWatcher(string directoryPath, bool includeSubdirectories)
        {
            try
            {
                FileSystemWatcher watcher = new FileSystemWatcher();
                watcher.Path = directoryPath;
                watcher.IncludeSubdirectories = includeSubdirectories;
                watcher.NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.CreationTime;
                watcher.Filter = "*.*";

                watcher.Created += EnhancedOnFileCreated;
                watcher.Changed += EnhancedOnFileChanged;
                watcher.Deleted += OnFileDeleted;
                watcher.Renamed += EnhancedOnFileRenamed;

                watcher.EnableRaisingEvents = true;
                _fileWatchers.Add(watcher);

                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "EnhancedFileWatcherStarted",
                    Message = "增强文件监控已启动",
                    Details = $"监控目录: {directoryPath}, 包含子目录: {includeSubdirectories}"
                });
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "EnhancedDirectoryWatcherError",
                    Message = "增强目录监控错误",
                    Details = $"目录: {directoryPath}, 错误: {ex.Message}"
                });
            }
        }

        // 增强的文件事件处理器
        private void EnhancedOnFileCreated(object sender, FileSystemEventArgs e)
        {
            EnhancedFileScan(e.FullPath, FileOperationType.Create);
        }

        private void EnhancedOnFileChanged(object sender, FileSystemEventArgs e)
        {
            EnhancedFileScan(e.FullPath, FileOperationType.Modify);
        }

        private void EnhancedOnFileRenamed(object sender, RenamedEventArgs e)
        {
            EnhancedFileScan(e.FullPath, FileOperationType.Rename);
        }

        // 定期完整性检查
        private void InitializeIntegrityMonitoring()
        {
            _integrityCheckTimer = new Timer(CheckSystemIntegrity, null, 
                TimeSpan.FromMinutes(5), // 5分钟后开始
                TimeSpan.FromHours(1));   // 每小时检查一次
        }

        private void CheckSystemIntegrity(object state)
        {
            try
            {
                foreach (var keyFile in _fileIntegrityMap.Keys.ToList())
                {
                    if (File.Exists(keyFile))
                    {
                        bool integrityOk = VerifyFileIntegrity(keyFile);
                        if (!integrityOk)
                        {
                            // 关键文件被修改，执行紧急扫描
                            EnhancedFileScan(keyFile, FileOperationType.Modify);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "IntegrityMonitorError",
                    Message = "完整性监控错误",
                    Details = ex.Message
                });
            }
        }
    }
}
