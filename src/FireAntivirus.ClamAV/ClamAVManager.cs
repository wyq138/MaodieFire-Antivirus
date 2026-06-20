using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using FireAntivirus.Data;

namespace FireAntivirus.ClamAV
{
    public class ClamAVManager : IDisposable
    {
        public bool IsInitialized { get; private set; } = true;
        private DataManager _dataManager;
        private string _clamAVPath;
        private string _virusDatabasePath;
        private string _clamscanPath;
        private string _freshclamPath;
        private string _freshclamConfPath;
        private bool _isInitialized;
        private Timer _autoUpdateTimer;
        private int _autoUpdateIntervalHours = 4;

        public bool IsAvailable => _isInitialized && File.Exists(_clamscanPath);
        public string ClamAVPath => _clamAVPath;
        public string DatabasePath => _virusDatabasePath;
        public int AutoUpdateIntervalHours 
        { 
            get => _autoUpdateIntervalHours;
            set 
            {
                _autoUpdateIntervalHours = value;
                if (_autoUpdateTimer != null)
                {
                    StartAutoUpdate();
                }
            }
        }

        public event Action<string> OnUpdateProgress;
        public event Action<bool, string> OnUpdateComplete;

        public ClamAVManager(DataManager dataManager)
        {
            _dataManager = dataManager;
            InitializePaths();
        }

        private void InitializePaths()
        {
            try
            {
                string baseDir = AppDomain.CurrentDomain.BaseDirectory;
                if (string.IsNullOrEmpty(baseDir))
                {
                    baseDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
                }
                
                string[] possiblePaths = new string[]
                {
                    Path.Combine(baseDir, "ClamAV"),
                    Path.Combine(baseDir, "clamav"),
                    Path.Combine(baseDir, "FireAntivirus.ClamAV", "ClamAV"),
                    Path.Combine(baseDir, "..", "ClamAV"),
                    Path.Combine(baseDir, "..", "clamav"),
                    Path.Combine(Directory.GetCurrentDirectory(), "ClamAV"),
                    Path.Combine(Directory.GetCurrentDirectory(), "clamav")
                };
                
                foreach (var path in possiblePaths)
                {
                    string fullPath = Path.GetFullPath(path);
                    if (Directory.Exists(fullPath) && File.Exists(Path.Combine(fullPath, "clamscan.exe")))
                    {
                        _clamAVPath = fullPath;
                        _virusDatabasePath = Path.Combine(_clamAVPath, "db");
                        _clamscanPath = Path.Combine(_clamAVPath, "clamscan.exe");
                        _freshclamPath = Path.Combine(_clamAVPath, "freshclam.exe");
                        _freshclamConfPath = Path.Combine(_clamAVPath, "freshclam.conf");
                        
                        Directory.CreateDirectory(_virusDatabasePath);
                        
                        _isInitialized = true;
                        _dataManager?.LogInfo($"ClamAV 初始化成功: {_clamAVPath}");
                        return;
                    }
                }

                string defaultPath = Path.Combine(baseDir, "ClamAV");
                _clamAVPath = defaultPath;
                _virusDatabasePath = Path.Combine(_clamAVPath, "db");
                _clamscanPath = Path.Combine(_clamAVPath, "clamscan.exe");
                _freshclamPath = Path.Combine(_clamAVPath, "freshclam.exe");
                _freshclamConfPath = Path.Combine(_clamAVPath, "freshclam.conf");
                
                Directory.CreateDirectory(_virusDatabasePath);
                _isInitialized = Directory.Exists(defaultPath) && File.Exists(_clamscanPath);
                
                if (!_isInitialized)
                {
                    _dataManager?.LogWarning("ClamAV 未找到，使用备用扫描引擎");
                }
                else
                {
                    _dataManager?.LogInfo($"ClamAV 初始化成功: {_clamAVPath}");
                }
            }
            catch (Exception ex)
            {
                _isInitialized = false;
                _dataManager?.LogError($"ClamAV 初始化错误: {ex.Message}");
            }
        }

        public string GetVirusDatabaseVersion()
        {
            try
            {
                var cvdFiles = new[] { "daily.cvd", "main.cvd", "bytecode.cvd" };
                DateTime latestUpdate = DateTime.MinValue;

                foreach (var cvd in cvdFiles)
                {
                    var file = Path.Combine(_virusDatabasePath, cvd);
                    if (File.Exists(file))
                    {
                        var lastWrite = File.GetLastWriteTime(file);
                        if (lastWrite > latestUpdate)
                            latestUpdate = lastWrite;
                    }
                }

                return latestUpdate != DateTime.MinValue 
                    ? latestUpdate.ToString("yyyy-MM-dd HH:mm") 
                    : "未安装";
            }
            catch
            {
                return "未知";
            }
        }

        public bool IsDatabaseUpToDate()
        {
            try
            {
                var cvdFiles = new[] { "daily.cvd", "main.cvd", "bytecode.cvd" };
                DateTime latestUpdate = DateTime.MinValue;

                foreach (var cvd in cvdFiles)
                {
                    var file = Path.Combine(_virusDatabasePath, cvd);
                    if (File.Exists(file))
                    {
                        var lastWrite = File.GetLastWriteTime(file);
                        if (lastWrite > latestUpdate)
                            latestUpdate = lastWrite;
                    }
                }

                if (latestUpdate == DateTime.MinValue) return false;
                
                var daysSinceUpdate = (DateTime.Now - latestUpdate).TotalDays;
                return daysSinceUpdate < 1; // 1天内算最新
            }
            catch
            {
                return false;
            }
        }

        public bool HasDatabaseFiles()
        {
            if (!Directory.Exists(_virusDatabasePath)) return false;
            
            var files = Directory.GetFiles(_virusDatabasePath, "*.cvd");
            return files.Length >= 3; // main.cvd, daily.cvd, bytecode.cvd
        }

        public void StartAutoUpdate()
        {
            StopAutoUpdate();
            
            // 立即执行一次更新检查
            Task.Run(() => UpdateDatabaseAsync());
            
            // 启动定时器
            _autoUpdateTimer = new Timer(
                callback: _ => Task.Run(() => UpdateDatabaseAsync()),
                state: null,
                dueTime: TimeSpan.FromHours(_autoUpdateIntervalHours),
                period: TimeSpan.FromHours(_autoUpdateIntervalHours)
            );
            
            _dataManager?.LogInfo($"病毒库自动更新已启动，间隔: {_autoUpdateIntervalHours}小时");
        }

        public void StopAutoUpdate()
        {
            _autoUpdateTimer?.Dispose();
            _autoUpdateTimer = null;
        }

        public async Task<bool> UpdateDatabaseAsync()
        {
            if (!File.Exists(_freshclamPath))
            {
                _dataManager?.LogError("freshclam.exe 不存在");
                OnUpdateComplete?.Invoke(false, "freshclam.exe 不存在");
                return false;
            }

            if (!File.Exists(_freshclamConfPath))
            {
                _dataManager?.LogError("freshclam.conf 配置文件不存在");
                OnUpdateComplete?.Invoke(false, "freshclam.conf 配置文件不存在");
                return false;
            }

            OnUpdateProgress?.Invoke("正在检查病毒库更新...");

            try
            {
                var startInfo = new ProcessStartInfo
                {
                    FileName = _freshclamPath,
                    Arguments = $"--config-file=\"{_freshclamConfPath}\"",
                    WorkingDirectory = _clamAVPath,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };

                using var process = Process.Start(startInfo);
                if (process == null)
                {
                    OnUpdateComplete?.Invoke(false, "无法启动更新进程");
                    return false;
                }

                // 异步读取输出
                var outputBuilder = new System.Text.StringBuilder();
                process.OutputDataReceived += (s, e) =>
                {
                    if (!string.IsNullOrEmpty(e.Data))
                    {
                        outputBuilder.AppendLine(e.Data);
                        OnUpdateProgress?.Invoke(e.Data);
                    }
                };
                process.ErrorDataReceived += (s, e) =>
                {
                    if (!string.IsNullOrEmpty(e.Data))
                    {
                        outputBuilder.AppendLine($"[ERROR] {e.Data}");
                    }
                };
                process.BeginOutputReadLine();
                process.BeginErrorReadLine();

                await process.WaitForExitAsync();

                bool success = process.ExitCode == 0;
                string message = success ? "病毒库更新成功" : $"病毒库更新失败，退出码: {process.ExitCode}";
                
                _dataManager?.LogInfo(message);
                OnUpdateComplete?.Invoke(success, message);
                
                return success;
            }
            catch (Exception ex)
            {
                _dataManager?.LogError($"病毒库更新错误: {ex.Message}");
                OnUpdateComplete?.Invoke(false, ex.Message);
                return false;
            }
        }

        public ScanResult ScanFile(string filePath)
        {
            var result = new ScanResult
            {
                FilePath = filePath,
                IsInfected = false,
                ThreatName = "",
                ScanTime = DateTime.Now
            };

            if (!File.Exists(filePath))
            {
                result.Error = "文件不存在";
                return result;
            }

            if (!IsAvailable)
            {
                result.Error = "ClamAV 不可用";
                return result;
            }

            if (!HasDatabaseFiles())
            {
                result.Error = "病毒库未安装，请先更新病毒库";
                return result;
            }

            try
            {
                var startInfo = new ProcessStartInfo
                {
                    FileName = _clamscanPath,
                    Arguments = $"--database=\"{_virusDatabasePath}\" --no-summary \"{filePath}\"",
                    WorkingDirectory = _clamAVPath,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };

                using var process = Process.Start(startInfo);
                if (process == null)
                {
                    result.Error = "无法启动扫描进程";
                    return result;
                }

                var output = process.StandardOutput.ReadToEnd();
                process.WaitForExit(60000);

                if (output.Contains("FOUND"))
                {
                    result.IsInfected = true;
                    var lines = output.Split('\n');
                    foreach (var line in lines)
                    {
                        if (line.Contains("FOUND"))
                        {
                            var parts = line.Split(':');
                            if (parts.Length > 1)
                            {
                                result.ThreatName = parts[parts.Length - 1].Replace("FOUND", "").Trim();
                            }
                        }
                    }
                }

                result.RawOutput = output;
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
            }

            return result;
        }

        public List<ScanResult> ScanDirectory(string directoryPath, Action<int, string> progressCallback = null, CancellationToken cancellationToken = default)
        {
            var results = new List<ScanResult>();

            if (!Directory.Exists(directoryPath))
            {
                results.Add(new ScanResult { FilePath = directoryPath, Error = "目录不存在" });
                return results;
            }

            if (!IsAvailable)
            {
                results.Add(new ScanResult { FilePath = directoryPath, Error = "ClamAV 不可用" });
                return results;
            }

            if (!HasDatabaseFiles())
            {
                results.Add(new ScanResult { FilePath = directoryPath, Error = "病毒库未安装" });
                return results;
            }

            try
            {
                var files = Directory.GetFiles(directoryPath, "*.*", SearchOption.AllDirectories)
                    .Where(f => !f.Contains("\\$") && !f.Contains("\\System Volume Information\\") && !f.Contains("\\Windows\\WinSxS\\"))
                    .ToList();

                int totalFiles = files.Count;
                int scannedFiles = 0;

                foreach (var file in files)
                {
                    if (cancellationToken.IsCancellationRequested)
                        break;

                    scannedFiles++;
                    progressCallback?.Invoke(scannedFiles * 100 / totalFiles, file);

                    var result = ScanFile(file);
                    results.Add(result);

                    if (result.IsInfected)
                    {
                        progressCallback?.Invoke(-1, $"发现威胁: {result.ThreatName} in {file}");
                    }
                }
            }
            catch (Exception ex)
            {
                results.Add(new ScanResult { FilePath = directoryPath, Error = ex.Message });
            }

            return results;
        }

        public void Dispose()
        {
            StopAutoUpdate();
        }
    }

    public class ScanResult
    {
        public string FilePath { get; set; }
        public bool IsInfected { get; set; }
        public string ThreatName { get; set; }
        public string Error { get; set; }
        public string RawOutput { get; set; }
        public DateTime ScanTime { get; set; }
    }
}

