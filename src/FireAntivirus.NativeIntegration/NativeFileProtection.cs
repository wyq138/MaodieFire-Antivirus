// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace FireAntivirus.NativeIntegration
{
    /// <summary>
    /// 文件保护模块的C#封装
    /// </summary>
    public class NativeFileProtection : IDisposable
    {
        #region 私有字段
        private readonly NativeSecurityCoreWrapper _core;
        private FileSystemWatcher _watcher;
        private bool _isMonitoring;
        private readonly object _lockObject = new object();
        private readonly HashSet<string> _protectedPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _blockedExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private bool _disposed;
        #endregion

        #region 事件
        public event EventHandler<FileThreatEventArgs> FileThreatDetected;
        public event EventHandler<FileChangeEventArgs> FileCreated;
        public event EventHandler<FileChangeEventArgs> FileModified;
        public event EventHandler<FileChangeEventArgs> FileDeleted;
        public event EventHandler<FileChangeEventArgs> FileRenamed;
        #endregion

        #region 构造函数
        public NativeFileProtection(NativeSecurityCoreWrapper core)
        {
            _core = core ?? throw new ArgumentNullException(nameof(core));
            InitializeDefaultProtection();
        }

        ~NativeFileProtection()
        {
            Dispose(false);
        }
        #endregion

        #region 公共属性
        public bool IsEnabled
        {
            get => _core.FileProtectionEnabled;
            set => _core.FileProtectionEnabled = value;
        }

        public bool IsMonitoring
        {
            get => _isMonitoring;
        }

        public IReadOnlyList<string> ProtectedPaths
        {
            get
            {
                lock (_protectedPaths)
                {
                    return _protectedPaths.ToList().AsReadOnly();
                }
            }
        }

        public IReadOnlyList<string> BlockedExtensions
        {
            get
            {
                lock (_blockedExtensions)
                {
                    return _blockedExtensions.ToList().AsReadOnly();
                }
            }
        }
        #endregion

        #region 公共方法

        /// <summary>
        /// 开始文件监控
        /// </summary>
        public void StartMonitoring()
        {
            lock (_lockObject)
            {
                if (_isMonitoring)
                    return;

                try
                {
                    _watcher = new FileSystemWatcher
                    {
                        NotifyFilter = NotifyFilters.FileName |
                                       NotifyFilters.DirectoryName |
                                       NotifyFilters.LastWrite |
                                       NotifyFilters.Size,
                        IncludeSubdirectories = true,
                        EnableRaisingEvents = true
                    };

                    _watcher.Created += OnFileCreated;
                    _watcher.Changed += OnFileChanged;
                    _watcher.Deleted += OnFileDeleted;
                    _watcher.Renamed += OnFileRenamed;
                    _watcher.Error += OnWatcherError;

                    _isMonitoring = true;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"启动文件监控失败: {ex.Message}");
                }
            }
        }

        /// <summary>
        /// 停止文件监控
        /// </summary>
        public void StopMonitoring()
        {
            lock (_lockObject)
            {
                if (!_isMonitoring)
                    return;

                try
                {
                    if (_watcher != null)
                    {
                        _watcher.EnableRaisingEvents = false;
                        _watcher.Created -= OnFileCreated;
                        _watcher.Changed -= OnFileChanged;
                        _watcher.Deleted -= OnFileDeleted;
                        _watcher.Renamed -= OnFileRenamed;
                        _watcher.Error -= OnWatcherError;
                        _watcher.Dispose();
                        _watcher = null;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"停止文件监控失败: {ex.Message}");
                }

                _isMonitoring = false;
            }
        }

        /// <summary>
        /// 添加受保护的路径
        /// </summary>
        public void AddProtectedPath(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
                return;

            lock (_protectedPaths)
            {
                _protectedPaths.Add(path);
            }

            // 更新监控器
            UpdateWatcherFilters();
        }

        /// <summary>
        /// 移除受保护的路径
        /// </summary>
        public void RemoveProtectedPath(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
                return;

            lock (_protectedPaths)
            {
                _protectedPaths.Remove(path);
            }

            UpdateWatcherFilters();
        }

        /// <summary>
        /// 添加要阻止的文件扩展名
        /// </summary>
        public void AddBlockedExtension(string extension)
        {
            if (string.IsNullOrWhiteSpace(extension))
                return;

            // 移除前导点
            extension = extension.TrimStart('.');

            lock (_blockedExtensions)
            {
                _blockedExtensions.Add(extension);
            }
        }

        /// <summary>
        /// 移除被阻止的文件扩展名
        /// </summary>
        public void RemoveBlockedExtension(string extension)
        {
            if (string.IsNullOrWhiteSpace(extension))
                return;

            extension = extension.TrimStart('.');

            lock (_blockedExtensions)
            {
                _blockedExtensions.Remove(extension);
            }
        }

        /// <summary>
        /// 扫描指定路径
        /// </summary>
        public async Task<List<FileThreatInfo>> ScanPathAsync(string path, CancellationToken cancellationToken = default)
        {
            return await Task.Run(() =>
            {
                var threats = new List<FileThreatInfo>();

                try
                {
                    if (!Directory.Exists(path))
                        return threats;

                    var files = Directory.GetFiles(path, "*", SearchOption.AllDirectories);

                    foreach (var file in files)
                    {
                        if (cancellationToken.IsCancellationRequested)
                            break;

                        var threat = AnalyzeFile(file);
                        if (threat != null)
                        {
                            threats.Add(threat);
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"扫描路径失败: {ex.Message}");
                }

                return threats;
            }, cancellationToken);
        }

        /// <summary>
        /// 分析指定文件
        /// </summary>
        public FileThreatInfo AnalyzeFile(string filePath)
        {
            var result = new FileThreatInfo
            {
                FilePath = filePath,
                FileName = Path.GetFileName(filePath),
                AnalysisTime = DateTime.Now
            };

            try
            {
                if (!File.Exists(filePath))
                {
                    result.IsThreat = false;
                    return result;
                }

                var fileInfo = new FileInfo(filePath);
                result.FileSize = fileInfo.Length;
                result.CreationTime = fileInfo.CreationTime;
                result.LastWriteTime = fileInfo.LastWriteTime;

                // 检查文件扩展名
                var extension = fileInfo.Extension.TrimStart('.').ToLower();
                lock (_blockedExtensions)
                {
                    if (_blockedExtensions.Contains(extension))
                    {
                        result.IsThreat = true;
                        result.ThreatType = "BlockedExtension";
                        result.ThreatDescription = $"禁止的文件扩展名: {extension}";
                        return result;
                    }
                }

                // 检查可疑扩展名
                var suspiciousExtensions = new[]
                {
                    "exe", "dll", "sys", "scr", "bat", "cmd", "ps1",
                    "vbs", "js", "jse", "wsf", "wsh", "hta", "msi"
                };

                if (suspiciousExtensions.Contains(extension))
                {
                    result.IsSuspicious = true;
                    result.SuspiciousReasons.Add("可执行文件类型");
                }

                // 检查文件名
                var fileName = fileInfo.Name.ToLower();
                var suspiciousPatterns = new[]
                {
                    "malware", "virus", "trojan", "hack", "crack",
                    "keygen", "injector", "loader", "payload"
                };

                if (suspiciousPatterns.Any(p => fileName.Contains(p)))
                {
                    result.IsThreat = true;
                    result.ThreatType = "SuspiciousFileName";
                    result.ThreatDescription = "文件名包含可疑关键词";
                }

                // 检查文件熵值（高熵值表示可能是加壳或加密文件）
                try
                {
                    var entropy = CalculateFileEntropy(filePath);
                    result.Entropy = entropy;

                    if (entropy > 7.5)
                    {
                        result.IsSuspicious = true;
                        result.SuspiciousReasons.Add($"高熵值: {entropy:F2} (可能加壳)");
                    }
                }
                catch
                {
                    // 无法计算熵值
                }

                // 检查文件大小异常
                if (fileInfo.Length == 0)
                {
                    result.IsSuspicious = true;
                    result.SuspiciousReasons.Add("空文件");
                }
                else if (fileInfo.Length < 1024 && suspiciousExtensions.Contains(extension))
                {
                    result.IsSuspicious = true;
                    result.SuspiciousReasons.Add("可执行文件过小");
                }
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
            }

            return result;
        }

        /// <summary>
        /// 删除威胁文件
        /// </summary>
        public bool DeleteThreatFile(string filePath)
        {
            try
            {
                if (File.Exists(filePath))
                {
                    // 先尝试修改文件属性
                    var fileInfo = new FileInfo(filePath);
                    if (fileInfo.IsReadOnly)
                    {
                        fileInfo.IsReadOnly = false;
                    }

                    File.Delete(filePath);
                    return true;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"删除文件失败: {ex.Message}");
            }

            return false;
        }

        /// <summary>
        /// 隔离威胁文件
        /// </summary>
        public bool QuarantineFile(string filePath, string quarantinePath)
        {
            try
            {
                if (!File.Exists(filePath))
                    return false;

                // 创建隔离目录
                Directory.CreateDirectory(quarantinePath);

                var fileName = Path.GetFileName(filePath);
                var quarantineFile = Path.Combine(quarantinePath,
                    $"{DateTime.Now:yyyyMMddHHmmss}_{fileName}");

                // 移动文件
                File.Move(filePath, quarantineFile);

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"隔离文件失败: {ex.Message}");
                return false;
            }
        }

        #endregion

        #region 私有方法
        private void InitializeDefaultProtection()
        {
            // 添加默认受保护的系统路径
            AddProtectedPath(Environment.GetFolderPath(Environment.SpecialFolder.Windows));
            AddProtectedPath(Environment.GetFolderPath(Environment.SpecialFolder.System));
            AddProtectedPath(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
            AddProtectedPath(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86));

            // 添加默认阻止的扩展名
            AddBlockedExtension("exe");
            AddBlockedExtension("dll");
            AddBlockedExtension("sys");
            AddBlockedExtension("scr");
        }

        private void UpdateWatcherFilters()
        {
            lock (_protectedPaths)
            {
                if (_protectedPaths.Count > 0)
                {
                    var paths = _protectedPaths.ToArray();
                    if (paths.Length > 0 && Directory.Exists(paths[0]))
                    {
                        try
                        {
                            _watcher?.Dispose();
                            _watcher = new FileSystemWatcher(paths[0])
                            {
                                NotifyFilter = NotifyFilters.FileName |
                                               NotifyFilters.DirectoryName |
                                               NotifyFilters.LastWrite |
                                               NotifyFilters.Size,
                                IncludeSubdirectories = true,
                                EnableRaisingEvents = _isMonitoring
                            };

                            // 设置扩展名过滤器
                            var extensions = _blockedExtensions.ToArray();
                            if (extensions.Length > 0)
                            {
                                _watcher.Filters.Add("*." + string.Join(".*", extensions.Select(e => "." + e)));
                            }
                        }
                        catch
                        {
                            // 忽略
                        }
                    }
                }
            }
        }

        private void OnFileCreated(object sender, FileSystemEventArgs e)
        {
            Task.Run(() =>
            {
                try
                {
                    // 检查扩展名
                    var extension = Path.GetExtension(e.FullPath).TrimStart('.').ToLower();
                    lock (_blockedExtensions)
                    {
                        if (_blockedExtensions.Contains(extension))
                        {
                            FileThreatDetected?.Invoke(this, new FileThreatEventArgs
                            {
                                FilePath = e.FullPath,
                                ThreatType = "BlockedExtension",
                                Action = FileProtectionAction.Block
                            });

                            // 阻止创建
                            DeleteThreatFile(e.FullPath);
                            return;
                        }
                    }

                    // 分析文件
                    var threat = AnalyzeFile(e.FullPath);
                    if (threat.IsThreat)
                    {
                        FileThreatDetected?.Invoke(this, new FileThreatEventArgs
                        {
                            FilePath = e.FullPath,
                            ThreatType = threat.ThreatType,
                            Description = threat.ThreatDescription,
                            Action = FileProtectionAction.Quarantine
                        });
                    }

                    FileCreated?.Invoke(this, new FileChangeEventArgs
                    {
                        FilePath = e.FullPath,
                        ChangeType = WatcherChangeTypes.Created
                    });
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"处理文件创建事件失败: {ex.Message}");
                }
            });
        }

        private void OnFileChanged(object sender, FileSystemEventArgs e)
        {
            FileModified?.Invoke(this, new FileChangeEventArgs
            {
                FilePath = e.FullPath,
                ChangeType = WatcherChangeTypes.Changed
            });
        }

        private void OnFileDeleted(object sender, FileSystemEventArgs e)
        {
            FileDeleted?.Invoke(this, new FileChangeEventArgs
            {
                FilePath = e.FullPath,
                ChangeType = WatcherChangeTypes.Deleted
            });
        }

        private void OnFileRenamed(object sender, RenamedEventArgs e)
        {
            FileRenamed?.Invoke(this, new FileChangeEventArgs
            {
                FilePath = e.FullPath,
                OldFilePath = e.OldFullPath,
                ChangeType = WatcherChangeTypes.Renamed
            });
        }

        private void OnWatcherError(object sender, ErrorEventArgs e)
        {
            Console.WriteLine($"文件监控错误: {e.GetException().Message}");
        }

        private double CalculateFileEntropy(string filePath)
        {
            try
            {
                var bytes = File.ReadAllBytes(filePath);
                if (bytes.Length == 0)
                    return 0;

                // 计算字节频率
                var frequency = new int[256];
                foreach (var b in bytes)
                {
                    frequency[b]++;
                }

                // 计算熵
                double entropy = 0;
                foreach (var count in frequency)
                {
                    if (count > 0)
                    {
                        var probability = (double)count / bytes.Length;
                        entropy -= probability * Math.Log(probability, 2);
                    }
                }

                return entropy;
            }
            catch
            {
                return 0;
            }
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
    public enum FileProtectionAction
    {
        Allow,
        Block,
        Quarantine,
        Delete
    }

    public class FileThreatInfo
    {
        public string FilePath { get; set; }
        public string FileName { get; set; }
        public long FileSize { get; set; }
        public DateTime CreationTime { get; set; }
        public DateTime LastWriteTime { get; set; }
        public DateTime AnalysisTime { get; set; }
        public bool IsThreat { get; set; }
        public bool IsSuspicious { get; set; }
        public string ThreatType { get; set; }
        public string ThreatDescription { get; set; }
        public List<string> SuspiciousReasons { get; set; } = new List<string>();
        public double Entropy { get; set; }
        public string Error { get; set; }
    }

    public class FileThreatEventArgs : EventArgs
    {
        public string FilePath { get; set; }
        public string ThreatType { get; set; }
        public string Description { get; set; }
        public FileProtectionAction Action { get; set; }
    }

    public class FileChangeEventArgs : EventArgs
    {
        public string FilePath { get; set; }
        public string OldFilePath { get; set; }
        public WatcherChangeTypes ChangeType { get; set; }
    }
    #endregion
}
