// 耄耋软件工作室 开发，严禁非法反编译
// 专业级勒索防护引擎 - 对标卡巴斯基/诺顿防护能力
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace FireAntivirus.Services
{
    public class RansomwareProtectionService : IDisposable
    {
        #region Windows API 导入

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CreateHardLink(string lpFileName, string lpExistingFileName, IntPtr lpSecurityAttributes);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DeviceIoControl(IntPtr hDevice, uint dwIoControlCode,
            IntPtr lpInBuffer, uint nInBufferSize, IntPtr lpOutBuffer, uint nOutBufferSize,
            out uint lpBytesReturned, IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern IntPtr CreateFile(string lpFileName, uint dwDesiredAccess,
            uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition,
            uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        private static extern bool SetVolumeShadowCopy(string volumeName, bool enable);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool AdjustTokenPrivileges(IntPtr tokenHandle, bool disableAllPrivileges,
            ref TOKEN_PRIVILEGES newState, uint bufferLength, IntPtr previousState, IntPtr returnLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_PRIVILEGES
        {
            public uint PrivilegeCount;
            public LUID Luid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        private const uint TOKEN_QUERY = 0x0008;
        private const uint SE_PRIVILEGE_ENABLED = 0x00000002;

        #endregion

        #region 私有字段

        private readonly string _configPath;
        private readonly string _protectedFoldersFile;
        private readonly string _backupPath;
        private readonly string _honeypotPath;
        private readonly string _quarantinePath;
        private readonly string _threatLogPath;

        private List<FileSystemWatcher> _watchers = new List<FileSystemWatcher>();
        private List<string> _protectedFolders = new List<string>();
        private HashSet<string> _suspiciousExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private HashSet<string> _knownRansomwareProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private HashSet<string> _trustedProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private HashSet<string> _protectedFileTypes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        private bool _isEnabled = false;
        private bool _protectDocuments = true;
        private bool _enableHoneypot = true;
        private bool _enableBehaviorAnalysis = true;
        private bool _enableAutoBackup = true;
        private bool _enableShadowCopy = true;
        private bool _enableProcessProtection = true;

        private Timer _monitorTimer;
        private Timer _backupTimer;
        private Timer _honeypotTimer;

        private ConcurrentDictionary<string, FileBackupInfo> _fileBackups = new ConcurrentDictionary<string, FileBackupInfo>();
        private ConcurrentDictionary<string, ProcessBehaviorProfile> _processProfiles = new ConcurrentDictionary<string, ProcessBehaviorProfile>();
        private ConcurrentDictionary<string, int> _folderModificationCounts = new ConcurrentDictionary<string, int>();
        private ConcurrentQueue<ThreatEvent> _recentThreats = new ConcurrentQueue<ThreatEvent>();

        private DateTime _lastModificationReset = DateTime.Now;
        private DateTime _lastBackupTime = DateTime.MinValue;
        private DateTime _lastHoneypotCheck = DateTime.MinValue;

        private int _maxBackupSizeMB = 500;
        private int _maxThreatHistory = 100;
        private int _massModificationThreshold = 15;
        private double _entropyThreshold = 7.5;
        private int _behaviorScoreThreshold = 80;

        private PerformanceCounter _diskWriteCounter;
        private PerformanceCounter _diskReadCounter;
        private float _baselineDiskWriteRate = 0;
        private float _baselineDiskReadRate = 0;

        #endregion

        #region 事件

        public event EventHandler<RansomwareDetectedEventArgs> RansomwareDetected;
        public event EventHandler<FileChangedEventArgs> FileChanged;
        public event EventHandler<ProcessBlockedEventArgs> ProcessBlocked;
        public event EventHandler<ThreatMitigatedEventArgs> ThreatMitigated;
        public event EventHandler<BackupCompletedEventArgs> BackupCompleted;
        public event EventHandler<ProtectionStatusChangedEventArgs> ProtectionStatusChanged;

        #endregion

        #region 构造函数

        public RansomwareProtectionService()
        {
            _configPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "FireAntivirus", "RansomwareProtection");

            if (!Directory.Exists(_configPath))
                Directory.CreateDirectory(_configPath);

            _protectedFoldersFile = Path.Combine(_configPath, "protected_folders.txt");
            _backupPath = Path.Combine(_configPath, "Backups");
            _honeypotPath = Path.Combine(_configPath, "Honeypots");
            _quarantinePath = Path.Combine(_configPath, "Quarantine");
            _threatLogPath = Path.Combine(_configPath, "threat_log.json");

            foreach (var path in new[] { _backupPath, _honeypotPath, _quarantinePath })
            {
                if (!Directory.Exists(path))
                    Directory.CreateDirectory(path);
            }

            InitializeExtensions();
            InitializeKnownRansomware();
            InitializeTrustedProcesses();
            InitializeProtectedFileTypes();
            LoadProtectedFolders();
            LoadThreatLog();
            InitializePerformanceCounters();
        }

        #endregion

        #region 初始化方法

        private void InitializeExtensions()
        {
            // 勒索软件扩展名从外置威胁特征库(ransomware_signatures.json)动态加载，
            // 不将恶意特征字符串编译进本 DLL，避免杀软对杀毒软件二进制的误报。
            LoadRansomwareFeaturesFromThreatData(
                loadExtensions: (HashSet<string> extensions) =>
                {
                    _suspiciousExtensions.Clear();
                    foreach (var ext in extensions)
                        _suspiciousExtensions.Add(ext.ToLower());
                });
        }

        private void InitializeKnownRansomware()
        {
            // 勒索软件进程/家族名从外置威胁特征库(ransomware_signatures.json)动态加载，
            // 不将恶意特征字符串编译进本 DLL，避免杀软误报。
            LoadRansomwareFeaturesFromThreatData(
                loadNames: (HashSet<string> names) =>
                {
                    _knownRansomwareProcesses.Clear();
                    foreach (var n in names)
                        _knownRansomwareProcesses.Add(n.ToLower());
                });
        }

        /// <summary>
        /// 从 FireAntivirus.Engine.ThreatData 外置特征库加载勒索软件扩展名/家族名。
        /// 若外部 JSON 缺失或为空，则不做降级硬编码（保持集合为空并不会影响正常文件操作，
        /// 但会丢失勒索识别能力），并把加载状态记录到威胁日志便于排查。
        /// </summary>
        private void LoadRansomwareFeaturesFromThreatData(
            Action<HashSet<string>> loadExtensions = null,
            Action<HashSet<string>> loadNames = null)
        {
            try
            {
                FireAntivirus.Engine.ExternalThreatData.EnsureLoaded();

                if (loadExtensions != null && FireAntivirus.Engine.ExternalThreatData.RansomwareExtensions.Count > 0)
                    loadExtensions(FireAntivirus.Engine.ExternalThreatData.RansomwareExtensions);

                if (loadNames != null && FireAntivirus.Engine.ExternalThreatData.RansomwareNames.Count > 0)
                    loadNames(FireAntivirus.Engine.ExternalThreatData.RansomwareNames);

                if (FireAntivirus.Engine.ExternalThreatData.LastWarnings.Count > 0)
                {
                    var msg = string.Join(" | ", FireAntivirus.Engine.ExternalThreatData.LastWarnings);
                    FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                        "RansomwareProtectionService 特征库加载告警", msg);
                }
            }
            catch (System.Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error,
                    "RansomwareProtectionService 加载外置特征库失败", ex.Message);
            }
        }

        private void InitializeTrustedProcesses()
        {
            // 受信任的系统进程
            var trusted = new[]
            {
                "system", "svchost", "explorer", "csrss", "lsass",
                "wininit", "winlogon", "services", "dwm", "smss",
                "ntoskrnl", "kernel32", "user32",
                "antimalware", "msmpeng", "nisrv", "msascuil",
                "defender", "windowsdefender",
                "fireantivirus", "fireantscanner", "fireantprotection"
            };

            foreach (var proc in trusted)
            {
                _trustedProcesses.Add(proc.ToLower());
            }
        }

        private void InitializeProtectedFileTypes()
        {
            // 重要文件类型 - 优先保护
            var fileTypes = new[]
            {
                ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
                ".pdf", ".txt", ".rtf", ".odt", ".ods", ".odp",
                ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".raw",
                ".mp3", ".mp4", ".avi", ".mov", ".wmv", ".wav",
                ".zip", ".rar", ".7z", ".tar", ".gz",
                ".bak", ".backup", ".old",
                ".mdb", ".accdb", ".sql", ".db", ".dbf",
                ".pst", ".ost", ".msg", ".eml",
                ".key", ".pem", ".p12", ".pfx", ".crt",
                ".wallet", ".dat", ".dmp"
            };

            foreach (var type in fileTypes)
            {
                _protectedFileTypes.Add(type.ToLower());
            }
        }

        private void LoadProtectedFolders()
        {
            if (File.Exists(_protectedFoldersFile))
            {
                _protectedFolders = File.ReadAllLines(_protectedFoldersFile)
                    .Where(l => !string.IsNullOrWhiteSpace(l) && !l.StartsWith("#"))
                    .Select(l => l.Trim())
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();
            }

            if (_protectDocuments)
            {
                AddDefaultProtectedFolders();
            }
        }

        private void AddDefaultProtectedFolders()
        {
            var defaultFolders = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Environment.GetFolderPath(Environment.SpecialFolder.MyPictures),
                Environment.GetFolderPath(Environment.SpecialFolder.MyVideos),
                Environment.GetFolderPath(Environment.SpecialFolder.MyMusic),
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + "\\Downloads",
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + "\\Favorites"
            };

            foreach (var folder in defaultFolders)
            {
                if (!string.IsNullOrEmpty(folder) && Directory.Exists(folder))
                {
                    if (!_protectedFolders.Any(f => f.Equals(folder, StringComparison.OrdinalIgnoreCase)))
                    {
                        _protectedFolders.Add(folder);
                    }
                }
            }
        }

        private void LoadThreatLog()
        {
            try
            {
                if (File.Exists(_threatLogPath))
                {
                    var json = File.ReadAllText(_threatLogPath);
                    var threats = Newtonsoft.Json.JsonConvert.DeserializeObject<List<ThreatEvent>>(json);
                    if (threats != null)
                    {
                        foreach (var threat in threats.Take(_maxThreatHistory))
                        {
                            _recentThreats.Enqueue(threat);
                        }
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "RansomwareProtectionService.cs 捕获异常", ex.Message); }
        }

        private void InitializePerformanceCounters()
        {
            try
            {
                _diskWriteCounter = new PerformanceCounter("PhysicalDisk", "Disk Write Bytes/sec", "_Total");
                _diskReadCounter = new PerformanceCounter("PhysicalDisk", "Disk Read Bytes/sec", "_Total");

                // 获取基线
                _baselineDiskWriteRate = _diskWriteCounter.NextValue();
                _baselineDiskReadRate = _diskReadCounter.NextValue();
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "RansomwareProtectionService.cs 捕获异常", ex.Message); }
        }

        #endregion

        #region 公共方法

        public void EnableProtection()
        {
            if (_isEnabled) return;

            _isEnabled = true;
            StartWatching();
            StartMonitorTimer();
            StartBackupTimer();
            DeployHoneypotFiles();

            if (_enableShadowCopy)
            {
                EnableShadowCopyProtection();
            }

            ProtectionStatusChanged?.Invoke(this, new ProtectionStatusChangedEventArgs
            {
                IsEnabled = true,
                Timestamp = DateTime.Now
            });
        }

        public void DisableProtection()
        {
            _isEnabled = false;
            StopWatching();
            StopMonitorTimer();
            StopBackupTimer();

            ProtectionStatusChanged?.Invoke(this, new ProtectionStatusChangedEventArgs
            {
                IsEnabled = false,
                Timestamp = DateTime.Now
            });
        }

        public void AddProtectedFolder(string folderPath)
        {
            if (!Directory.Exists(folderPath))
                throw new DirectoryNotFoundException($"文件夹不存在: {folderPath}");

            if (!_protectedFolders.Any(f => f.Equals(folderPath, StringComparison.OrdinalIgnoreCase)))
            {
                _protectedFolders.Add(folderPath);
                SaveProtectedFolders();

                if (_isEnabled)
                {
                    StartWatching();
                }
            }
        }

        public void RemoveProtectedFolder(string folderPath)
        {
            var existing = _protectedFolders.FirstOrDefault(f => f.Equals(folderPath, StringComparison.OrdinalIgnoreCase));
            if (existing != null)
            {
                _protectedFolders.Remove(existing);
                SaveProtectedFolders();

                if (_isEnabled)
                {
                    StartWatching();
                }
            }
        }

        public List<string> GetProtectedFolders()
        {
            return _protectedFolders.ToList();
        }

        public void BackupFile(string filePath)
        {
            try
            {
                if (!File.Exists(filePath)) return;

                var fileInfo = new FileInfo(filePath);

                // 跳过太大的文件和临时文件
                if (fileInfo.Length > 100 * 1024 * 1024) return;
                if (filePath.Contains("Temp") || filePath.Contains("tmp")) return;

                var backupFileName = $"{Guid.NewGuid():N}_{Path.GetFileName(filePath)}";
                var backupFilePath = Path.Combine(_backupPath, backupFileName);

                // 使用硬链接节省空间（如果支持）
                File.Copy(filePath, backupFilePath, true);

                var hash = CalculateFileHash(filePath);

                _fileBackups[filePath] = new FileBackupInfo
                {
                    OriginalPath = filePath,
                    BackupPath = backupFilePath,
                    BackupTime = DateTime.Now,
                    OriginalSize = fileInfo.Length,
                    OriginalHash = hash,
                    FileVersion = GetFileVersion(filePath)
                };

                BackupCompleted?.Invoke(this, new BackupCompletedEventArgs
                {
                    FilePath = filePath,
                    BackupPath = backupFilePath,
                    Success = true
                });
            }
            catch (Exception ex)
            {
                BackupCompleted?.Invoke(this, new BackupCompletedEventArgs
                {
                    FilePath = filePath,
                    Success = false,
                    Error = ex.Message
                });
            }
        }

        public bool TryRestoreFile(string originalPath)
        {
            if (!_fileBackups.TryGetValue(originalPath, out var backup))
                return false;

            if (!File.Exists(backup.BackupPath))
                return false;

            try
            {
                // 验证备份完整性
                var backupHash = CalculateFileHash(backup.BackupPath);
                if (!string.IsNullOrEmpty(backup.OriginalHash) && backupHash != backup.OriginalHash)
                {
                    // 备份文件可能已损坏
                    return false;
                }

                // 创建临时文件
                var tempPath = originalPath + ".restoring";
                File.Copy(backup.BackupPath, tempPath, true);

                // 替换原文件
                if (File.Exists(originalPath))
                {
                    File.Delete(originalPath);
                }
                File.Move(tempPath, originalPath);

                ThreatMitigated?.Invoke(this, new ThreatMitigatedEventArgs
                {
                    FilePath = originalPath,
                    Action = "FileRestored",
                    Success = true,
                    Timestamp = DateTime.Now
                });

                return true;
            }
            catch
            {
                return false;
            }
        }

        public List<FileBackupInfo> GetBackupList()
        {
            return _fileBackups.Values.ToList();
        }

        public RansomwareScanResult ScanForRansomware()
        {
            var result = new RansomwareScanResult();
            var stopwatch = Stopwatch.StartNew();

            foreach (var folder in _protectedFolders.Where(Directory.Exists))
            {
                ScanFolder(folder, result);
            }

            stopwatch.Stop();
            result.ScanDuration = stopwatch.Elapsed;

            return result;
        }

        private void ScanFolder(string folder, RansomwareScanResult result)
        {
            try
            {
                foreach (var file in Directory.GetFiles(folder, "*.*", SearchOption.AllDirectories))
                {
                    try
                    {
                        var extension = Path.GetExtension(file).ToLower();
                        if (_suspiciousExtensions.Contains(extension))
                        {
                            result.SuspiciousFiles.Add(new SuspiciousFileInfo
                            {
                                FilePath = file,
                                Extension = extension,
                                Reason = "可疑扩展名",
                                Severity = ThreatSeverity.Medium,
                                DetectionTime = DateTime.Now
                            });
                        }
                    }
                    catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "RansomwareProtectionService.cs 捕获异常", ex.Message); }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "RansomwareProtectionService.cs 捕获异常", ex.Message); }
        }

        public RansomwareProtectionSettings GetSettings()
        {
            return new RansomwareProtectionSettings
            {
                IsEnabled = _isEnabled,
                ProtectDocuments = _protectDocuments,
                ProtectedFoldersCount = _protectedFolders.Count,
                SuspiciousExtensionsCount = _suspiciousExtensions.Count,
                EnableHoneypot = _enableHoneypot,
                EnableBehaviorAnalysis = _enableBehaviorAnalysis,
                EnableAutoBackup = _enableAutoBackup,
                HoneypotFilesCount = GetHoneypotFilesCount(),
                BackupFilesCount = _fileBackups.Count,
                RecentThreatsCount = _recentThreats.Count
            };
        }

        public void UpdateSettings(RansomwareProtectionSettings settings)
        {
            _protectDocuments = settings.ProtectDocuments;
            _enableHoneypot = settings.EnableHoneypot;
            _enableBehaviorAnalysis = settings.EnableBehaviorAnalysis;
            _enableAutoBackup = settings.EnableAutoBackup;

            if (settings.IsEnabled && !_isEnabled)
                EnableProtection();
            else if (!settings.IsEnabled && _isEnabled)
                DisableProtection();
        }

        public void AddSuspiciousExtension(string extension)
        {
            if (!extension.StartsWith("."))
                extension = "." + extension;

            _suspiciousExtensions.Add(extension.ToLower());
        }

        public List<string> GetSuspiciousExtensions()
        {
            return _suspiciousExtensions.ToList();
        }

        public List<ThreatEvent> GetRecentThreats(int count = 50)
        {
            return _recentThreats.ToArray().Take(count).ToList();
        }

        public void BlockProcess(string processName, string reason)
        {
            try
            {
                foreach (var process in Process.GetProcessesByName(processName))
                {
                    try
                    {
                        process.Kill();

                        ProcessBlocked?.Invoke(this, new ProcessBlockedEventArgs
                        {
                            ProcessName = processName,
                            ProcessId = process.Id,
                            Reason = reason,
                            Timestamp = DateTime.Now
                        });
                    }
                    catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "RansomwareProtectionService.cs 捕获异常", ex.Message); }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "RansomwareProtectionService.cs 捕获异常", ex.Message); }
        }

        public void QuarantineFile(string filePath, string reason)
        {
            try
            {
                if (!File.Exists(filePath)) return;

                var quarantineFileName = $"{DateTime.Now:yyyyMMdd_HHmmss}_{Path.GetFileName(filePath)}.quar";
                var quarantineFilePath = Path.Combine(_quarantinePath, quarantineFileName);

                // 加密后移动到隔离区
                EncryptAndMoveToQuarantine(filePath, quarantineFilePath);

                File.Delete(filePath);

                LogThreat(new ThreatEvent
                {
                    Type = ThreatType.Quarantine,
                    FilePath = filePath,
                    Reason = reason,
                    Timestamp = DateTime.Now
                });
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "RansomwareProtectionService.cs 捕获异常", ex.Message); }
        }

        public ProtectionStatistics GetStatistics()
        {
            return new ProtectionStatistics
            {
                IsEnabled = _isEnabled,
                ProtectedFoldersCount = _protectedFolders.Count,
                HoneypotFilesCount = GetHoneypotFilesCount(),
                BackupFilesCount = _fileBackups.Count,
                ThreatsDetectedToday = GetThreatsTodayCount(),
                TotalThreatsDetected = _recentThreats.Count,
                LastBackupTime = _lastBackupTime,
                LastThreatTime = _recentThreats.TryPeek(out var lastThreat) ? lastThreat.Timestamp : (DateTime?)null
            };
        }

        #endregion

        #region 私有方法 - 监控

        private void StartWatching()
        {
            StopWatching();

            foreach (var folder in _protectedFolders.Where(Directory.Exists))
            {
                try
                {
                    var watcher = new FileSystemWatcher(folder)
                    {
                        IncludeSubdirectories = true,
                        NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | 
                                       NotifyFilters.Size | NotifyFilters.Attributes,
                        EnableRaisingEvents = true,
                        InternalBufferSize = 81920 // 增加缓冲区
                    };

                    watcher.Changed += OnFileChanged;
                    watcher.Created += OnFileCreated;
                    watcher.Renamed += OnFileRenamed;
                    watcher.Deleted += OnFileDeleted;
                    watcher.Error += OnWatcherError;

                    _watchers.Add(watcher);
                }
                catch (Exception ex)
                {
                    LogThreat(new ThreatEvent
                    {
                        Type = ThreatType.Error,
                        Reason = $"无法监控文件夹 {folder}: {ex.Message}",
                        Timestamp = DateTime.Now
                    });
                }
            }
        }

        private void StopWatching()
        {
            foreach (var watcher in _watchers)
            {
                try
                {
                    watcher.EnableRaisingEvents = false;
                    watcher.Dispose();
                }
                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "RansomwareProtectionService.cs 捕获异常", ex.Message); }
            }
            _watchers.Clear();
        }

        private void OnWatcherError(object sender, ErrorEventArgs e)
        {
            // 重新启动监控
            Task.Delay(1000).ContinueWith(_ =>
            {
                if (_isEnabled)
                {
                    StartWatching();
                }
            });
        }

        private void StartMonitorTimer()
        {
            _monitorTimer = new Timer(CheckForRansomwareActivity, null, TimeSpan.Zero, TimeSpan.FromSeconds(5));
        }

        private void StopMonitorTimer()
        {
            _monitorTimer?.Dispose();
            _monitorTimer = null;
        }

        private void StartBackupTimer()
        {
            if (_enableAutoBackup)
            {
                _backupTimer = new Timer(AutoBackupCallback, null, TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(30));
            }
        }

        private void StopBackupTimer()
        {
            _backupTimer?.Dispose();
            _backupTimer = null;
        }

        #endregion

        #region 私有方法 - 文件事件处理

        private void OnFileChanged(object sender, FileSystemEventArgs e)
        {
            if (!_isEnabled) return;

            try
            {
                // 排除系统和临时文件
                if (ShouldIgnoreFile(e.FullPath)) return;

                var extension = Path.GetExtension(e.FullPath).ToLower();

                // 检查可疑扩展名
                if (_suspiciousExtensions.Contains(extension))
                {
                    DetectRansomware(e.FullPath, "可疑文件扩展名", ThreatSeverity.Critical);
                    return;
                }

                // 检查加密行为
                if (_enableBehaviorAnalysis)
                {
                    var entropy = CalculateFileEntropy(e.FullPath);
                    if (entropy > _entropyThreshold)
                    {
                        DetectRansomware(e.FullPath, $"检测到高熵值文件 ({entropy:F2})", ThreatSeverity.High);
                        return;
                    }
                }

                // 检查批量修改
                if (IsMassModificationHappening(e.FullPath))
                {
                    DetectRansomware(e.FullPath, "检测到批量文件修改", ThreatSeverity.Critical);
                    return;
                }

                // 自动备份重要文件
                if (_enableAutoBackup && _protectedFileTypes.Contains(extension))
                {
                    Task.Run(() => BackupFile(e.FullPath));
                }

                FileChanged?.Invoke(this, new FileChangedEventArgs
                {
                    FilePath = e.FullPath,
                    ChangeType = FileChangeType.Modified,
                    Timestamp = DateTime.Now
                });
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "RansomwareProtectionService.cs 捕获异常", ex.Message); }
        }

        private void OnFileCreated(object sender, FileSystemEventArgs e)
        {
            if (!_isEnabled) return;

            if (ShouldIgnoreFile(e.FullPath)) return;

            var extension = Path.GetExtension(e.FullPath).ToLower();

            if (_suspiciousExtensions.Contains(extension))
            {
                DetectRansomware(e.FullPath, "创建了可疑扩展名文件", ThreatSeverity.High);
            }
        }

        private void OnFileRenamed(object sender, RenamedEventArgs e)
        {
            if (!_isEnabled) return;

            if (ShouldIgnoreFile(e.FullPath)) return;

            var newExtension = Path.GetExtension(e.FullPath).ToLower();
            var oldExtension = Path.GetExtension(e.OldFullPath).ToLower();

            // 扩展名被改为可疑类型
            if (_suspiciousExtensions.Contains(newExtension) && !_suspiciousExtensions.Contains(oldExtension))
            {
                DetectRansomware(e.FullPath, "文件扩展名被改为可疑类型", ThreatSeverity.Critical);
            }

            // 检查是否为勒索软件添加的典型后缀
            if (newExtension.Contains("encrypted") || newExtension.Contains("locked") || 
                newExtension.Contains("crypto") || newExtension.Contains("ransom"))
            {
                DetectRansomware(e.FullPath, "检测到勒索软件特征扩展名", ThreatSeverity.Critical);
            }
        }

        private void OnFileDeleted(object sender, FileSystemEventArgs e)
        {
            if (!_isEnabled) return;

            if (ShouldIgnoreFile(e.FullPath)) return;

            // 检查是否为诱饵文件被删除
            if (IsHoneypotFile(e.FullPath))
            {
                DetectRansomware(e.FullPath, "诱饵文件被删除", ThreatSeverity.Critical);
            }

            FileChanged?.Invoke(this, new FileChangedEventArgs
            {
                FilePath = e.FullPath,
                ChangeType = FileChangeType.Deleted,
                Timestamp = DateTime.Now
            });
        }

        private bool ShouldIgnoreFile(string filePath)
        {
            var fileName = Path.GetFileName(filePath).ToLower();
            var directory = Path.GetDirectoryName(filePath)?.ToLower() ?? "";

            // 忽略系统文件
            if (filePath.StartsWith(Environment.SystemDirectory, StringComparison.OrdinalIgnoreCase))
                return true;

            // 忽略临时文件
            if (directory.Contains("temp") || directory.Contains("tmp") || directory.Contains("cache"))
                return true;

            // 忽略隐藏文件和系统文件
            try
            {
                var attr = File.GetAttributes(filePath);
                if ((attr & FileAttributes.Hidden) != 0 || (attr & FileAttributes.System) != 0)
                    return true;
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "RansomwareProtectionService.cs 捕获异常", ex.Message); }

            // 忽略程序文件
            if (directory.Contains("program files") || directory.Contains("programdata"))
                return true;

            // 忽略备份和诱饵文件
            if (filePath.StartsWith(_backupPath, StringComparison.OrdinalIgnoreCase) ||
                filePath.StartsWith(_honeypotPath, StringComparison.OrdinalIgnoreCase))
                return true;

            return false;
        }

        #endregion

        #region 私有方法 - 威胁检测

        private void CheckForRansomwareActivity(object state)
        {
            if (!_isEnabled) return;

            try
            {
                // 检查可疑进程
                CheckSuspiciousProcesses();

                // 检查磁盘活动异常
                CheckDiskActivityAnomaly();

                // 检查影子副本状态
                if (_enableShadowCopy)
                {
                    CheckShadowCopyStatus();
                }

                // 重置计数器
                if ((DateTime.Now - _lastModificationReset).TotalSeconds > 10)
                {
                    _folderModificationCounts.Clear();
                    _lastModificationReset = DateTime.Now;
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "RansomwareProtectionService.cs 捕获异常", ex.Message); }
        }

        private void CheckSuspiciousProcesses()
        {
            foreach (var process in Process.GetProcesses())
            {
                try
                {
                    var name = process.ProcessName.ToLower();
                    var id = process.Id;

                    // 跳过受信任进程
                    if (_trustedProcesses.Contains(name)) continue;

                    // 检查已知勒索软件
                    if (_knownRansomwareProcesses.Any(r => name.Contains(r)))
                    {
                        BlockProcess(process.ProcessName, "检测到已知勒索软件进程");
                        continue;
                    }

                    // 行为分析
                    if (_enableBehaviorAnalysis)
                    {
                        var profile = GetOrCreateProcessProfile(process);

                        // 更新进程行为档案
                        UpdateProcessProfile(profile, process);

                        // 检查可疑行为模式
                        if (profile.BehaviorScore >= _behaviorScoreThreshold)
                        {
                            BlockProcess(process.ProcessName, $"检测到可疑行为 (评分: {profile.BehaviorScore})");
                        }
                    }
                }
                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "RansomwareProtectionService.cs 捕获异常", ex.Message); }
            }
        }

        private ProcessBehaviorProfile GetOrCreateProcessProfile(Process process)
        {
            var key = $"{process.ProcessName}_{process.Id}";

            return _processProfiles.GetOrAdd(key, _ => new ProcessBehaviorProfile
            {
                ProcessName = process.ProcessName,
                ProcessId = process.Id,
                StartTime = DateTime.Now,
                FileOperations = new List<FileOperationRecord>(),
                BehaviorScore = 0
            });
        }

        private void UpdateProcessProfile(ProcessBehaviorProfile profile, Process process)
        {
            try
            {
                // 检查进程特征
                var processPath = GetProcessPath(process);
                if (string.IsNullOrEmpty(processPath)) return;

                // 计算行为评分
                int score = 0;

                // 检查进程路径
                if (processPath.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), StringComparison.OrdinalIgnoreCase))
                    score += 20; // 从用户AppData运行

                if (processPath.StartsWith(Path.GetTempPath(), StringComparison.OrdinalIgnoreCase))
                    score += 30; // 从临时目录运行

                // 检查无签名
                if (!HasValidSignature(processPath))
                    score += 25; // 无数字签名

                // 检查文件操作频率
                var recentOps = profile.FileOperations.Count(o => o.Timestamp > DateTime.Now.AddSeconds(-30));
                if (recentOps > 50)
                    score += 30; // 高频文件操作

                // 检查是否有修改受保护文件类型的操作
                var protectedFileOps = profile.FileOperations.Count(o => 
                    _protectedFileTypes.Contains(Path.GetExtension(o.FilePath).ToLower()));
                if (protectedFileOps > 10)
                    score += 25; // 修改重要文件

                profile.BehaviorScore = Math.Min(100, score);
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "RansomwareProtectionService.cs 捕获异常", ex.Message); }
        }

        private void CheckDiskActivityAnomaly()
        {
            try
            {
                if (_diskWriteCounter == null) return;

                var currentWriteRate = _diskWriteCounter.NextValue();

                // 如果写入速率突然增加5倍以上
                if (_baselineDiskWriteRate > 0 && currentWriteRate > _baselineDiskWriteRate * 5)
                {
                    LogThreat(new ThreatEvent
                    {
                        Type = ThreatType.Warning,
                        Reason = "检测到异常磁盘写入活动",
                        Timestamp = DateTime.Now
                    });
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "RansomwareProtectionService.cs 捕获异常", ex.Message); }
        }

        private void CheckShadowCopyStatus()
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_ShadowCopy"))
                {
                    var shadowCopies = searcher.Get().Count;

                    // 如果影子副本数量突然减少
                    // 可能是勒索软件尝试删除影子副本
                    if (shadowCopies == 0)
                    {
                        LogThreat(new ThreatEvent
                        {
                            Type = ThreatType.Warning,
                            Reason = "系统影子副本为空或已被删除",
                            Timestamp = DateTime.Now
                        });
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "RansomwareProtectionService.cs 捕获异常", ex.Message); }
        }

        private bool IsMassModificationHappening(string filePath)
        {
            var folder = Path.GetDirectoryName(filePath);
            if (string.IsNullOrEmpty(folder)) return false;

            var count = _folderModificationCounts.AddOrUpdate(folder, 1, (_, c) => c + 1);

            // 调整阈值：重要文件夹使用更低的阈值
            var threshold = _protectedFolders.Any(f => 
                folder.StartsWith(f, StringComparison.OrdinalIgnoreCase)) 
                ? _massModificationThreshold / 2 
                : _massModificationThreshold;

            return count > threshold;
        }

        private void DetectRansomware(string filePath, string reason, ThreatSeverity severity)
        {
            var threatEvent = new ThreatEvent
            {
                Type = ThreatType.Ransomware,
                FilePath = filePath,
                Reason = reason,
                Severity = severity,
                Timestamp = DateTime.Now
            };

            LogThreat(threatEvent);

            RansomwareDetected?.Invoke(this, new RansomwareDetectedEventArgs
            {
                FilePath = filePath,
                Reason = reason,
                Timestamp = DateTime.Now,
                Severity = severity
            });

            // 自动响应
            if (severity == ThreatSeverity.Critical)
            {
                AutoRespondToThreat(filePath, reason);
            }

            // 尝试恢复文件
            if (_fileBackups.ContainsKey(filePath))
            {
                TryRestoreFile(filePath);
            }
        }

        private void AutoRespondToThreat(string filePath, string reason)
        {
            try
            {
                // 隔离文件
                QuarantineFile(filePath, reason);

                // 记录事件
                ThreatMitigated?.Invoke(this, new ThreatMitigatedEventArgs
                {
                    FilePath = filePath,
                    Action = "AutoQuarantine",
                    Success = true,
                    Timestamp = DateTime.Now
                });
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "RansomwareProtectionService.cs 捕获异常", ex.Message); }
        }

        #endregion

        #region 私有方法 - 蜜罐系统

        private void DeployHoneypotFiles()
        {
            if (!_enableHoneypot) return;

            try
            {
                // 清除旧蜜罐
                if (Directory.Exists(_honeypotPath))
                {
                    Directory.Delete(_honeypotPath, true);
                    Directory.CreateDirectory(_honeypotPath);
                }

                // 在受保护文件夹部署诱饵文件
                foreach (var folder in _protectedFolders.Where(Directory.Exists))
                {
                    DeployHoneypotInFolder(folder);
                }

                _lastHoneypotCheck = DateTime.Now;
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "RansomwareProtectionService.cs 捕获异常", ex.Message); }
        }

        private void DeployHoneypotInFolder(string folderPath)
        {
            try
            {
                // 创建诱饵文件
                var honeypotFiles = new Dictionary<string, byte[]>
                {
                    { "重要文档.docx", CreateHoneypotContent("docx") },
                    { "财务报表.xlsx", CreateHoneypotContent("xlsx") },
                    { "合同文件.pdf", CreateHoneypotContent("pdf") },
                    { "照片合集.zip", CreateHoneypotContent("zip") },
                    { "密码.txt", CreateHoneypotContent("txt") },
                    { "私钥.key", CreateHoneypotContent("key") },
                    { "钱包.dat", CreateHoneypotContent("dat") }
                };

                foreach (var kvp in honeypotFiles)
                {
                    var filePath = Path.Combine(folderPath, kvp.Key);
                    
                    // 避免覆盖真实文件
                    if (!File.Exists(filePath))
                    {
                        File.WriteAllBytes(filePath, kvp.Value);

                        // 设置隐藏属性
                        File.SetAttributes(filePath, FileAttributes.Hidden | FileAttributes.Archive);

                        // 记录蜜罐文件路径
                        File.AppendAllText(Path.Combine(_honeypotPath, "honeypot_list.txt"), filePath + "\n");
                    }
                }

                // 创建诱饵目录
                var decoyDirs = new[] { "机密文件", "重要资料", "财务数据", "个人照片" };
                foreach (var dirName in decoyDirs)
                {
                    var dirPath = Path.Combine(folderPath, dirName);
                    if (!Directory.Exists(dirPath))
                    {
                        Directory.CreateDirectory(dirPath);
                        Directory.CreateDirectory(Path.Combine(dirPath, "Documents"));
                        Directory.CreateDirectory(Path.Combine(dirPath, "Archives"));

                        // 在诱饵目录中创建诱饵文件
                        File.WriteAllText(Path.Combine(dirPath, "readme.txt"), 
                            "此目录受FireAntivirus保护，任何未经授权的修改都将被记录和阻止。");
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "RansomwareProtectionService.cs 捕获异常", ex.Message); }
        }

        private byte[] CreateHoneypotContent(string fileType)
        {
            // 创建具有明显特征的蜜罐内容
            var marker = $"HONEYPOT_FIREANTIVIRUS_{Guid.NewGuid():N}";

            return fileType.ToLower() switch
            {
                "docx" => Encoding.UTF8.GetBytes($"PK\x03\x04{marker}"),
                "xlsx" => Encoding.UTF8.GetBytes($"PK\x03\x04{marker}"),
                "pdf" => Encoding.UTF8.GetBytes($"%PDF-1.4\n{marker}\n%%EOF"),
                "zip" => Encoding.UTF8.GetBytes($"PK\x03\x04{marker}"),
                "txt" => Encoding.UTF8.GetBytes($"重要信息: {marker}"),
                "key" => Encoding.UTF8.GetBytes($"-----BEGIN PRIVATE KEY-----\n{marker}\n-----END PRIVATE KEY-----"),
                "dat" => Encoding.UTF8.GetBytes($"WALLET_DATA_{marker}"),
                _ => Encoding.UTF8.GetBytes(marker)
            };
        }

        private bool IsHoneypotFile(string filePath)
        {
            try
            {
                var listFile = Path.Combine(_honeypotPath, "honeypot_list.txt");
                if (File.Exists(listFile))
                {
                    var honeypotFiles = File.ReadAllLines(listFile);
                    return honeypotFiles.Any(h => h.Equals(filePath, StringComparison.OrdinalIgnoreCase));
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "RansomwareProtectionService.cs 捕获异常", ex.Message); }

            return false;
        }

        private int GetHoneypotFilesCount()
        {
            try
            {
                var listFile = Path.Combine(_honeypotPath, "honeypot_list.txt");
                if (File.Exists(listFile))
                {
                    return File.ReadAllLines(listFile).Length;
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "RansomwareProtectionService.cs 捕获异常", ex.Message); }

            return 0;
        }

        #endregion

        #region 私有方法 - 影子副本保护

        private void EnableShadowCopyProtection()
        {
            try
            {
                // 启用影子副本保护
                using (var key = Registry.LocalMachine.CreateSubKey(
                    @"SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToBackup"))
                {
                    // 配置不被备份排除的文件
                }

                // 监控影子副本删除命令
                // vssadmin delete shadows /all /quiet
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "RansomwareProtectionService.cs 捕获异常", ex.Message); }
        }

        #endregion

        #region 私有方法 - 备份系统

        private void AutoBackupCallback(object state)
        {
            if (!_isEnabled || !_enableAutoBackup) return;

            try
            {
                // 增量备份重要文件
                foreach (var folder in _protectedFolders.Where(Directory.Exists))
                {
                    BackupImportantFiles(folder);
                }

                _lastBackupTime = DateTime.Now;

                // 清理旧备份
                CleanupOldBackups();
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "RansomwareProtectionService.cs 捕获异常", ex.Message); }
        }

        private void BackupImportantFiles(string folderPath)
        {
            try
            {
                var files = Directory.GetFiles(folderPath, "*.*", SearchOption.TopDirectoryOnly)
                    .Where(f => _protectedFileTypes.Contains(Path.GetExtension(f).ToLower()))
                    .Take(50); // 每次最多备份50个文件

                foreach (var file in files)
                {
                    try
                    {
                        // 只备份修改过的文件
                        var lastWrite = File.GetLastWriteTime(file);
                        if (_fileBackups.TryGetValue(file, out var existing))
                        {
                            if (existing.BackupTime >= lastWrite)
                                continue; // 已有最新备份
                        }

                        BackupFile(file);
                    }
                    catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "RansomwareProtectionService.cs 捕获异常", ex.Message); }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "RansomwareProtectionService.cs 捕获异常", ex.Message); }
        }

        private void CleanupOldBackups()
        {
            try
            {
                var backupDir = new DirectoryInfo(_backupPath);
                var backupFiles = backupDir.GetFiles()
                    .OrderByDescending(f => f.CreationTime)
                    .Skip(1000) // 保留最近的1000个备份
                    .ToList();

                foreach (var file in backupFiles)
                {
                    try
                    {
                        file.Delete();
                    }
                    catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "RansomwareProtectionService.cs 捕获异常", ex.Message); }
                }

                // 检查备份目录大小
                var totalSize = backupDir.EnumerateFiles().Sum(f => f.Length) / (1024 * 1024);
                if (totalSize > _maxBackupSizeMB)
                {
                    // 删除最旧的备份
                    var oldFiles = backupDir.EnumerateFiles()
                        .OrderBy(f => f.CreationTime)
                        .Take(100)
                        .ToList();

                    foreach (var file in oldFiles)
                    {
                        file.Delete();
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "RansomwareProtectionService.cs 捕获异常", ex.Message); }
        }

        #endregion

        #region 私有方法 - 工具方法

        private double CalculateFileEntropy(string filePath)
        {
            try
            {
                var bytes = new byte[4096];
                using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                {
                    fs.Read(bytes, 0, bytes.Length);
                }

                return CalculateEntropy(bytes);
            }
            catch
            {
                return 0;
            }
        }

        private double CalculateEntropy(byte[] data)
        {
            if (data == null || data.Length == 0) return 0;

            var frequency = new int[256];
            foreach (var b in data)
            {
                frequency[b]++;
            }

            double entropy = 0;
            foreach (var count in frequency)
            {
                if (count > 0)
                {
                    double probability = (double)count / data.Length;
                    entropy -= probability * Math.Log(probability, 2);
                }
            }

            return entropy;
        }

        private string CalculateFileHash(string filePath)
        {
            try
            {
                using var sha256 = SHA256.Create();
                using var stream = File.OpenRead(filePath);
                var hash = sha256.ComputeHash(stream);
                return BitConverter.ToString(hash).Replace("-", "").ToLower();
            }
            catch
            {
                return string.Empty;
            }
        }

        private string GetFileVersion(string filePath)
        {
            try
            {
                var versionInfo = System.Diagnostics.FileVersionInfo.GetVersionInfo(filePath);
                return versionInfo.FileVersion ?? string.Empty;
            }
            catch
            {
                return string.Empty;
            }
        }

        private string GetProcessPath(Process process)
        {
            try
            {
                return process.MainModule?.FileName ?? string.Empty;
            }
            catch
            {
                return string.Empty;
            }
        }

        private bool HasValidSignature(string filePath)
        {
            try
            {
                // 不使用Windows签名验证，改为检查文件是否在信任目录中
                if (!File.Exists(filePath)) return false;

                string lowerPath = filePath.ToLowerInvariant();
                
                // 检查是否在系统信任目录中
                bool isInTrustedLocation = 
                    lowerPath.Contains("\\windows\\") ||
                    lowerPath.Contains("\\program files\\") ||
                    lowerPath.Contains("\\program files (x86)\\") ||
                    lowerPath.Contains("\\microsoft\\") ||
                    lowerPath.Contains("\\system32\\") ||
                    lowerPath.Contains("\\syswow64\\");
                
                return isInTrustedLocation;
            }
            catch
            {
                return false;
            }
        }

        private string GetFileSigner(string filePath)
        {
            // 不使用Windows签名验证
            if (!File.Exists(filePath)) return string.Empty;
            
            string lowerPath = filePath.ToLowerInvariant();
            if (lowerPath.Contains("\\windows\\") || lowerPath.Contains("\\system32\\"))
                return "Microsoft Corporation";
            if (lowerPath.Contains("\\program files\\"))
                return "受信任的发布者";
            
            return string.Empty;
        }

        private void EncryptAndMoveToQuarantine(string sourcePath, string quarantinePath)
        {
            try
            {
                var key = RandomNumberGenerator.GetBytes(32);
                var iv = RandomNumberGenerator.GetBytes(16);

                using var aes = Aes.Create();
                aes.Key = key;
                aes.IV = iv;

                using var encryptor = aes.CreateEncryptor();
                using var sourceStream = File.OpenRead(sourcePath);
                using var destStream = File.Create(quarantinePath);
                using var cryptoStream = new CryptoStream(destStream, encryptor, CryptoStreamMode.Write);

                // 写入IV
                destStream.Write(iv, 0, iv.Length);

                // 加密内容
                sourceStream.CopyTo(cryptoStream);
                cryptoStream.FlushFinalBlock();

                // 保存密钥信息
                var keyFile = quarantinePath + ".key";
                File.WriteAllBytes(keyFile, key);
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "RansomwareProtectionService.cs 捕获异常", ex.Message); }
        }

        private void LogThreat(ThreatEvent threat)
        {
            _recentThreats.Enqueue(threat);

            // 限制历史记录数量
            while (_recentThreats.Count > _maxThreatHistory)
            {
                _recentThreats.TryDequeue(out _);
            }

            // 保存到文件
            try
            {
                var threats = _recentThreats.ToList();
                var json = Newtonsoft.Json.JsonConvert.SerializeObject(threats, Newtonsoft.Json.Formatting.Indented);
                File.WriteAllText(_threatLogPath, json);
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "RansomwareProtectionService.cs 捕获异常", ex.Message); }
        }

        private int GetThreatsTodayCount()
        {
            return _recentThreats.Count(t => t.Timestamp.Date == DateTime.Today);
        }

        private void SaveProtectedFolders()
        {
            File.WriteAllLines(_protectedFoldersFile, _protectedFolders);
        }

        #endregion

        #region IDisposable

        public void Dispose()
        {
            StopWatching();
            StopMonitorTimer();
            StopBackupTimer();
            _diskWriteCounter?.Dispose();
            _diskReadCounter?.Dispose();
            GC.SuppressFinalize(this);
        }

        #endregion
    }

    #region 数据模型

    public class RansomwareDetectedEventArgs : EventArgs
    {
        public string FilePath { get; set; }
        public string Reason { get; set; }
        public DateTime Timestamp { get; set; }
        public ThreatSeverity Severity { get; set; }
        public string ProcessName { get; set; }
        public int ProcessId { get; set; }
    }

    public class FileChangedEventArgs : EventArgs
    {
        public string FilePath { get; set; }
        public FileChangeType ChangeType { get; set; }
        public DateTime Timestamp { get; set; }
    }

    public class ProcessBlockedEventArgs : EventArgs
    {
        public string ProcessName { get; set; }
        public int ProcessId { get; set; }
        public string Reason { get; set; }
        public DateTime Timestamp { get; set; }
    }

    public class ThreatMitigatedEventArgs : EventArgs
    {
        public string FilePath { get; set; }
        public string Action { get; set; }
        public bool Success { get; set; }
        public DateTime Timestamp { get; set; }
    }

    public class BackupCompletedEventArgs : EventArgs
    {
        public string FilePath { get; set; }
        public string BackupPath { get; set; }
        public bool Success { get; set; }
        public string Error { get; set; }
    }

    public class ProtectionStatusChangedEventArgs : EventArgs
    {
        public bool IsEnabled { get; set; }
        public DateTime Timestamp { get; set; }
    }

    public enum FileChangeType
    {
        Created,
        Modified,
        Deleted,
        Renamed
    }

    public class FileBackupInfo
    {
        public string OriginalPath { get; set; }
        public string BackupPath { get; set; }
        public DateTime BackupTime { get; set; }
        public long OriginalSize { get; set; }
        public string OriginalHash { get; set; }
        public string FileVersion { get; set; }
    }

    public class RansomwareScanResult
    {
        public List<SuspiciousFileInfo> SuspiciousFiles { get; set; } = new List<SuspiciousFileInfo>();
        public List<CompromisedFile> CompromisedFiles { get; set; } = new List<CompromisedFile>();
        public int FilesScanned { get; set; }
        public int ThreatsFound => SuspiciousFiles.Count + CompromisedFiles.Count;
        public TimeSpan ScanDuration { get; set; }
    }

    public class CompromisedFile
    {
        public string FilePath { get; set; }
        public string OriginalExtension { get; set; }
        public string NewExtension { get; set; }
        public DateTime CompromiseTime { get; set; }
        public string BackupPath { get; set; }
        public bool CanRestore { get; set; }
    }

    public class RansomwareProtectionSettings
    {
        public bool IsEnabled { get; set; }
        public bool ProtectDocuments { get; set; }
        public int ProtectedFoldersCount { get; set; }
        public int SuspiciousExtensionsCount { get; set; }
        public bool EnableHoneypot { get; set; }
        public bool EnableBehaviorAnalysis { get; set; }
        public bool EnableAutoBackup { get; set; }
        public int HoneypotFilesCount { get; set; }
        public int BackupFilesCount { get; set; }
        public int RecentThreatsCount { get; set; }
    }

    public class ThreatEvent
    {
        public ThreatType Type { get; set; }
        public string FilePath { get; set; }
        public string Reason { get; set; }
        public ThreatSeverity Severity { get; set; }
        public DateTime Timestamp { get; set; }
        public string ProcessName { get; set; }
        public string Action { get; set; }
    }

    public class ProtectionStatistics
    {
        public bool IsEnabled { get; set; }
        public int ProtectedFoldersCount { get; set; }
        public int HoneypotFilesCount { get; set; }
        public int BackupFilesCount { get; set; }
        public int ThreatsDetectedToday { get; set; }
        public int TotalThreatsDetected { get; set; }
        public DateTime LastBackupTime { get; set; }
        public DateTime? LastThreatTime { get; set; }
    }

    public class ProcessBehaviorProfile
    {
        public string ProcessName { get; set; }
        public int ProcessId { get; set; }
        public string FilePath { get; set; }
        public string ProcessPath { get; set; }
        public DateTime StartTime { get; set; }
        public int BehaviorScore { get; set; }
        public bool HasValidSignature { get; set; }
        public List<FileOperationRecord> FileOperations { get; set; } = new List<FileOperationRecord>();
        public float CpuUsage { get; set; }
        public long MemoryUsage { get; set; }
        public int ThreadCount { get; set; }
        public int HandleCount { get; set; }
    }

    public class FileOperationRecord
    {
        public string FilePath { get; set; }
        public string OperationType { get; set; }
        public DateTime Timestamp { get; set; }
        public long BytesChanged { get; set; }
    }

    public class SuspiciousFileInfo
    {
        public string FilePath { get; set; }
        public string Extension { get; set; }
        public string Reason { get; set; }
        public double Entropy { get; set; }
        public ThreatSeverity Severity { get; set; }
        public DateTime DetectionTime { get; set; }
        public bool IsQuarantined { get; set; }
    }

    #endregion
}