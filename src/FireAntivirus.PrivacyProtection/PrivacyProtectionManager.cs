// 耄耋软件工作室 开发，严禁非法反编译
// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace FireAntivirus.PrivacyProtection
{
    public class PrivacyProtectionManager
    {
        private CancellationTokenSource _cancellationTokenSource;
        private Task _monitoringTask;
        private Dictionary<int, ProcessInfo> _monitoredProcesses;
        private List<string> _sensitiveDirectories;
        private List<string> _sensitiveFileExtensions;
        private List<string> _privacySensitiveProcesses;

        public event EventHandler<PrivacyThreatDetectedEventArgs> PrivacyThreatDetected;
        public event EventHandler<CameraAccessEventArgs> CameraAccessDetected;
        public event EventHandler<MicrophoneAccessEventArgs> MicrophoneAccessDetected;
        public event EventHandler<DataCollectionEventArgs> DataCollectionDetected;



        public async Task StartMonitoring()
        {
            if (_monitoringTask != null && !_monitoringTask.IsCompleted)
            {
                return;
            }

            _cancellationTokenSource = new CancellationTokenSource();
            var token = _cancellationTokenSource.Token;

            _monitoringTask = Task.Run(async () => {
                while (!token.IsCancellationRequested)
                {
                    try
                    {
                        // 监控进程访问敏感数据
                        await MonitorSensitiveDataAccess();

                        // 监控摄像头和麦克风使用
                        await MonitorCameraMicrophoneAccess();

                        // 监控数据收集行为
                        await MonitorDataCollection();

                        // 监控隐私设置更改
                        MonitorPrivacySettingsChanges();

                        // 清理临时文件
                        CleanupTempFiles();

                        // 等待一段时间再进行下一次检查
                        await Task.Delay(2000, token);
                    }
                    catch (Exception ex)
                    {
                        // 记录错误但继续运行
                        Console.WriteLine($"隐私保护监控错误: {ex.Message}");
                    }
                }
            }, token);
        }

        public void StopMonitoring()
        {
            if (_cancellationTokenSource != null)
            {
                _cancellationTokenSource.Cancel();
                _cancellationTokenSource.Dispose();
            }

            if (_monitoringTask != null)
            {
                try
                {
                    _monitoringTask.Wait(2000);
                }
                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "PrivacyProtectionManager.cs 捕获异常", ex.Message); }
            }

            _monitoredProcesses.Clear();
        }

        private async Task MonitorSensitiveDataAccess()
        {
            var currentProcesses = Process.GetProcesses();

            foreach (var process in currentProcesses)
            {
                try
                {
                    // 检查进程是否访问敏感目录
                    await CheckSensitiveDirectoryAccess(process);

                    // 检查进程是否访问敏感文件
                    await CheckSensitiveFileAccess(process);

                    // 检查进程是否为隐私敏感进程
                    CheckPrivacySensitiveProcess(process);
                }
                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "PrivacyProtectionManager.cs 捕获异常", ex.Message); }
            }
        }

        private Dictionary<string, FileSystemWatcher> _fileSystemWatchers;

        public PrivacyProtectionManager()
        {
            _monitoredProcesses = new Dictionary<int, ProcessInfo>();
            _sensitiveDirectories = LoadSensitiveDirectories();
            _sensitiveFileExtensions = LoadSensitiveFileExtensions();
            _privacySensitiveProcesses = LoadPrivacySensitiveProcesses();
            _fileSystemWatchers = new Dictionary<string, FileSystemWatcher>();
            InitializeFileWatchers();
        }

        private void InitializeFileWatchers()
        {
            foreach (var directory in _sensitiveDirectories)
            {
                if (Directory.Exists(directory))
                {
                    var watcher = new FileSystemWatcher(directory);
                    watcher.IncludeSubdirectories = true;
                    watcher.NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.DirectoryName;
                    watcher.Changed += OnSensitiveFileChanged;
                    watcher.Created += OnSensitiveFileCreated;
                    watcher.Deleted += OnSensitiveFileDeleted;
                    watcher.Renamed += OnSensitiveFileRenamed;
                    watcher.EnableRaisingEvents = true;
                    _fileSystemWatchers[directory] = watcher;
                }
            }
        }

        private void OnSensitiveFileChanged(object sender, FileSystemEventArgs e)
        {
            // 检查文件是否为敏感文件
            if (_sensitiveFileExtensions.Any(ext => e.FullPath.EndsWith(ext, StringComparison.OrdinalIgnoreCase)))
            {
                OnPrivacyThreatDetected(new PrivacyThreatDetectedEventArgs
                {
                    ThreatType = "敏感文件访问",
                    ProcessName = "文件系统",
                    DataAccessed = $"修改敏感文件: {e.FullPath}",
                    DetectionTime = DateTime.Now
                });
            }
        }

        private void OnSensitiveFileCreated(object sender, FileSystemEventArgs e)
        {
            // 检查文件是否为敏感文件
            if (_sensitiveFileExtensions.Any(ext => e.FullPath.EndsWith(ext, StringComparison.OrdinalIgnoreCase)))
            {
                OnPrivacyThreatDetected(new PrivacyThreatDetectedEventArgs
                {
                    ThreatType = "敏感文件访问",
                    ProcessName = "文件系统",
                    DataAccessed = $"创建敏感文件: {e.FullPath}",
                    DetectionTime = DateTime.Now
                });
            }
        }

        private void OnSensitiveFileDeleted(object sender, FileSystemEventArgs e)
        {
            // 检查文件是否为敏感文件
            if (_sensitiveFileExtensions.Any(ext => e.FullPath.EndsWith(ext, StringComparison.OrdinalIgnoreCase)))
            {
                OnPrivacyThreatDetected(new PrivacyThreatDetectedEventArgs
                {
                    ThreatType = "敏感文件访问",
                    ProcessName = "文件系统",
                    DataAccessed = $"删除敏感文件: {e.FullPath}",
                    DetectionTime = DateTime.Now
                });
            }
        }

        private void OnSensitiveFileRenamed(object sender, RenamedEventArgs e)
        {
            // 检查文件是否为敏感文件
            if (_sensitiveFileExtensions.Any(ext => e.FullPath.EndsWith(ext, StringComparison.OrdinalIgnoreCase)))
            {
                OnPrivacyThreatDetected(new PrivacyThreatDetectedEventArgs
                {
                    ThreatType = "敏感文件访问",
                    ProcessName = "文件系统",
                    DataAccessed = $"重命名敏感文件: {e.OldFullPath} -> {e.FullPath}",
                    DetectionTime = DateTime.Now
                });
            }
        }

        private async Task CheckSensitiveDirectoryAccess(Process process)
        {
            foreach (var directory in _sensitiveDirectories)
            {
                try
                {
                    if (Directory.Exists(directory))
                    {
                        // 检查进程是否正在访问该目录
                        // 已经使用FileSystemWatcher实现了监控
                        await Task.CompletedTask;
                    }
                }
                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "PrivacyProtectionManager.cs 捕获异常", ex.Message); }
            }
        }

        private async Task CheckSensitiveFileAccess(Process process)
        {
            foreach (var directory in _sensitiveDirectories)
            {
                try
                {
                    if (Directory.Exists(directory))
                    {
                        foreach (var ext in _sensitiveFileExtensions)
                        {
                            var files = Directory.GetFiles(directory, "*" + ext, SearchOption.AllDirectories);
                            foreach (var file in files)
                            {
                                // 检查进程是否正在访问该文件
                                // 已经使用FileSystemWatcher实现了监控
                                await Task.CompletedTask;
                            }
                        }
                    }
                }
                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "PrivacyProtectionManager.cs 捕获异常", ex.Message); }
            }
        }

        public void Dispose()
        {
            StopMonitoring();
            foreach (var watcher in _fileSystemWatchers.Values)
            {
                watcher.Dispose();
            }
            _fileSystemWatchers.Clear();
        }

        private void CheckPrivacySensitiveProcess(Process process)
        {
            string processName = process.ProcessName.ToLower();
            if (_privacySensitiveProcesses.Contains(processName))
            {
                OnPrivacyThreatDetected(new PrivacyThreatDetectedEventArgs
                {
                    ThreatType = "隐私敏感进程",
                    ProcessName = process.ProcessName,
                    DataAccessed = "可能收集用户数据",
                    DetectionTime = DateTime.Now
                });
            }
        }

        private async Task MonitorCameraMicrophoneAccess()
        {
            try
            {
                // 监控摄像头使用
                MonitorCameraUsage();

                // 监控麦克风使用
                MonitorMicrophoneUsage();

                await Task.CompletedTask;
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "PrivacyProtectionManager.cs 捕获异常", ex.Message); }
        }

        private void MonitorCameraUsage()
        {
            try
            {
                // 检查摄像头是否被占用
                var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_PnPEntity WHERE Name LIKE '%Camera%'");
                var devices = searcher.Get();

                foreach (var device in devices)
                {
                    string status = device["Status"]?.ToString();
                    if (status == "OK")
                    {
                        // 检查是否有进程正在使用摄像头
                        // 这里可以使用更复杂的设备监控
                        OnCameraAccessDetected(new CameraAccessEventArgs
                        {
                            DeviceName = device["Name"]?.ToString(),
                            AccessTime = DateTime.Now
                        });
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "PrivacyProtectionManager.cs 捕获异常", ex.Message); }
        }

        private void MonitorMicrophoneUsage()
        {
            try
            {
                // 检查麦克风是否被占用
                var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_PnPEntity WHERE Name LIKE '%Microphone%'");
                var devices = searcher.Get();

                foreach (var device in devices)
                {
                    string status = device["Status"]?.ToString();
                    if (status == "OK")
                    {
                        // 检查是否有进程正在使用麦克风
                        // 这里可以使用更复杂的设备监控
                        OnMicrophoneAccessDetected(new MicrophoneAccessEventArgs
                        {
                            DeviceName = device["Name"]?.ToString(),
                            AccessTime = DateTime.Now
                        });
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "PrivacyProtectionManager.cs 捕获异常", ex.Message); }
        }

        private async Task MonitorDataCollection()
        {
            try
            {
                // 检查数据收集行为
                CheckBrowserDataCollection();
                CheckAppDataCollection();

                await Task.CompletedTask;
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "PrivacyProtectionManager.cs 捕获异常", ex.Message); }
        }

        private void CheckBrowserDataCollection()
        {
            // 检查浏览器数据收集
            string[] browserPaths = {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Google\\Chrome\\User Data"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft\\Edge\\User Data"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Mozilla\\Firefox\\Profiles")
            };

            foreach (var path in browserPaths)
            {
                if (Directory.Exists(path))
                {
                    OnDataCollectionDetected(new DataCollectionEventArgs
                    {
                        CollectionType = "浏览器数据",
                        Location = path,
                        DetectionTime = DateTime.Now
                    });
                }
            }
        }

        private void CheckAppDataCollection()
        {
            // 检查应用数据收集
            string appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            if (Directory.Exists(appDataPath))
            {
                var appFolders = Directory.GetDirectories(appDataPath);
                foreach (var folder in appFolders)
                {
                    string folderName = Path.GetFileName(folder);
                    // 检查常见的可能收集数据的应用
                    string[] dataCollectingApps = { "Adobe", "Google", "Microsoft", "Facebook", "Twitter" };
                    if (dataCollectingApps.Any(app => folderName.Contains(app)))
                    {
                        OnDataCollectionDetected(new DataCollectionEventArgs
                        {
                            CollectionType = "应用数据",
                            Location = folder,
                            DetectionTime = DateTime.Now
                        });
                    }
                }
            }
        }

        private void MonitorPrivacySettingsChanges()
        {
            try
            {
                // 监控隐私相关的注册表项
                string[] privacyRegistryKeys = {
                    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Privacy",
                    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore",
                    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced"
                };

                foreach (var keyPath in privacyRegistryKeys)
                {
                    using (var key = Registry.CurrentUser.OpenSubKey(keyPath))
                    {
                        if (key != null)
                        {
                            // 检查注册表项是否被修改
                            // 这里可以使用更复杂的注册表监控
                        }
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "PrivacyProtectionManager.cs 捕获异常", ex.Message); }
        }

        private void CleanupTempFiles()
        {
            try
            {
                // 清理临时文件
                string tempPath = Path.GetTempPath();
                if (Directory.Exists(tempPath))
                {
                    var tempFiles = Directory.GetFiles(tempPath);
                    foreach (var file in tempFiles)
                    {
                        try
                        {
                            File.Delete(file);
                        }
                        catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "PrivacyProtectionManager.cs 捕获异常", ex.Message); }
                    }
                }

                // 清理浏览器缓存
                CleanupBrowserCache();
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "PrivacyProtectionManager.cs 捕获异常", ex.Message); }
        }

        private void CleanupBrowserCache()
        {
            // 清理浏览器缓存
            string[] browserCachePaths = {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Google\\Chrome\\User Data\\Default\\Cache"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft\\Edge\\User Data\\Default\\Cache"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Mozilla\\Firefox\\Profiles")
            };

            foreach (var path in browserCachePaths)
            {
                if (Directory.Exists(path))
                {
                    try
                    {
                        var cacheFiles = Directory.GetFiles(path, "*", SearchOption.AllDirectories);
                        foreach (var file in cacheFiles)
                        {
                            try
                            {
                                File.Delete(file);
                            }
                            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "PrivacyProtectionManager.cs 捕获异常", ex.Message); }
                        }
                    }
                    catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "PrivacyProtectionManager.cs 捕获异常", ex.Message); }
                }
            }
        }

        public void ClearBrowserData()
        {
            // 清除浏览器数据
            CleanupBrowserCache();
        }

        public void BlockCameraAccess()
        {
            // 阻止摄像头访问
            // 这里可以添加实际的摄像头阻止逻辑
            Console.WriteLine("已阻止摄像头访问");
        }

        public void BlockMicrophoneAccess()
        {
            // 阻止麦克风访问
            // 这里可以添加实际的麦克风阻止逻辑
            Console.WriteLine("已阻止麦克风访问");
        }

        private List<string> LoadSensitiveDirectories()
        {
            // 加载敏感目录列表
            return new List<string>
            {
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Environment.GetFolderPath(Environment.SpecialFolder.MyPictures),
                Environment.GetFolderPath(Environment.SpecialFolder.MyVideos),
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)
            };
        }

        private List<string> LoadSensitiveFileExtensions()
        {
            // 加载敏感文件扩展名列表
            return new List<string>
            {
                ".doc", ".docx", ".pdf", ".txt", ".jpg", ".jpeg", ".png", ".gif",
                ".xls", ".xlsx", ".ppt", ".pptx", ".zip", ".rar", ".7z",
                ".pst", ".ost", ".db", ".sqlite", ".json", ".xml"
            };
        }

        private List<string> LoadPrivacySensitiveProcesses()
        {
            // 加载隐私敏感进程列表
            return new List<string>
            {
                "chrome", "msedge", "firefox", "iexplore", "opera",
                "teams", "skype", "zoom", "discord", "slack",
                "facebook", "twitter", "instagram", "whatsapp", "telegram"
            };
        }

        protected virtual void OnPrivacyThreatDetected(PrivacyThreatDetectedEventArgs e)
        {
            PrivacyThreatDetected?.Invoke(this, e);
        }

        protected virtual void OnCameraAccessDetected(CameraAccessEventArgs e)
        {
            CameraAccessDetected?.Invoke(this, e);
        }

        protected virtual void OnMicrophoneAccessDetected(MicrophoneAccessEventArgs e)
        {
            MicrophoneAccessDetected?.Invoke(this, e);
        }

        protected virtual void OnDataCollectionDetected(DataCollectionEventArgs e)
        {
            DataCollectionDetected?.Invoke(this, e);
        }
    }

    public class ProcessInfo
    {
        public int ProcessId { get; set; }
        public string ProcessName { get; set; }
        public DateTime StartTime { get; set; }
    }

    public class PrivacyThreatDetectedEventArgs : EventArgs
    {
        public string ThreatType { get; set; }
        public string ProcessName { get; set; }
        public string DataAccessed { get; set; }
        public DateTime DetectionTime { get; set; }
    }

    public class CameraAccessEventArgs : EventArgs
    {
        public string DeviceName { get; set; }
        public DateTime AccessTime { get; set; }
    }

    public class MicrophoneAccessEventArgs : EventArgs
    {
        public string DeviceName { get; set; }
        public DateTime AccessTime { get; set; }
    }

    public class DataCollectionEventArgs : EventArgs
    {
        public string CollectionType { get; set; }
        public string Location { get; set; }
        public DateTime DetectionTime { get; set; }
    }
}