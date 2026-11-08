using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.IO.Compression;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using FireAntivirus.Data;
using FireAntivirus.Engine;

namespace FireAntivirus.Services
{
    public class ClamAVEngine
    {
        private DataManager _dataManager;
        private AntivirusEngine _antivirusEngine;
        private string _clamAVPath;
        private string _virusDatabasePath;
        private string _clamscanPath;
        private string _freshclamPath;
        private bool _isInitialized;
        private Timer _autoUpdateTimer;

        public bool IsAvailable => _isInitialized && File.Exists(_clamscanPath);
        public string DatabasePath => _virusDatabasePath;

        public ClamAVEngine(DataManager dataManager, AntivirusEngine antivirusEngine)
        {
            _dataManager = dataManager;
            _antivirusEngine = antivirusEngine;
            InitializePaths();
        }

        private void InitializePaths()
        {
            try
            {
                string baseDir = AppDomain.CurrentDomain.BaseDirectory;
                if (string.IsNullOrEmpty(baseDir))
                {
                    baseDir = Path.GetDirectoryName(System.Reflection.Assembly.GetEntryAssembly()?.Location ?? System.Reflection.Assembly.GetExecutingAssembly().Location);
                }
                
                string[] possibleClamAVPaths = new string[]
                {
                    Path.Combine(baseDir, "ClamAV"),
                    Path.Combine(baseDir, "clamav"),
                    Path.Combine(baseDir, "FireAntivirus.ClamAV", "ClamAV"),
                    Path.Combine(baseDir, "..", "ClamAV"),
                    Path.Combine(baseDir, "..", "clamav"),
                };

                foreach (var clamPath in possibleClamAVPaths)
                {
                    string fullPath = Path.GetFullPath(clamPath);
                    string dbPath = Path.Combine(fullPath, "db");
                    string altDbPath = Path.Combine(fullPath, "database");
                    string clamscanExe = Path.Combine(fullPath, "clamscan.exe");

                    bool hasDb = (Directory.Exists(dbPath) && 
                                 (File.Exists(Path.Combine(dbPath, "main.cvd")) || 
                                  File.Exists(Path.Combine(dbPath, "daily.cvd")))) ||
                                (Directory.Exists(altDbPath) && 
                                 (File.Exists(Path.Combine(altDbPath, "main.cvd")) || 
                                  File.Exists(Path.Combine(altDbPath, "daily.cvd"))));

                    if (Directory.Exists(fullPath) || hasDb)
                    {
                        _clamAVPath = fullPath;
                        _virusDatabasePath = Directory.Exists(dbPath) ? dbPath : altDbPath;
                        
                        if (!Directory.Exists(_virusDatabasePath))
                        {
                            _virusDatabasePath = dbPath;
                            Directory.CreateDirectory(_virusDatabasePath);
                        }

                        _clamscanPath = clamscanExe;
                        _freshclamPath = Path.Combine(fullPath, "freshclam.exe");
                        _isInitialized = true;
                        
                        _dataManager?.LogInfo($"ClamAV 路径: {_clamAVPath}");
                        _dataManager?.LogInfo($"病毒库路径: {_virusDatabasePath}");
                        _dataManager?.LogInfo($"clamscan.exe 存在: {File.Exists(_clamscanPath)}");
                        _dataManager?.LogInfo($"病毒库文件存在: {hasDb}");
                        return;
                    }
                }

                _clamAVPath = Path.Combine(baseDir, "ClamAV");
                _virusDatabasePath = Path.Combine(_clamAVPath, "db");
                _clamscanPath = Path.Combine(_clamAVPath, "clamscan.exe");
                _freshclamPath = Path.Combine(_clamAVPath, "freshclam.exe");
                
                Directory.CreateDirectory(_virusDatabasePath);
                _isInitialized = true;
                
                _dataManager?.LogInfo($"ClamAV 使用默认路径: {_clamAVPath}");
                _dataManager?.LogInfo($"病毒库路径: {_virusDatabasePath}");
            }
            catch (Exception ex)
            {
                _isInitialized = false;
                _dataManager?.LogError($"ClamAV 初始化失败: {ex.Message}");
            }
        }

        public bool UpdateVirusDatabase()
        {
            try
            {
                // 方式1: 使用 freshclam.exe
                if (File.Exists(_freshclamPath))
                {
                    EnsureFreshclamConfig();
                    return RunFreshclam();
                }
                
                // 方式2: 从官网下载
                return DownloadFromOfficial();
            }
            catch (Exception ex)
            {
                _dataManager?.LogError($"更新病毒库失败: {ex.Message}");
                return false;
            }
        }

        private void EnsureFreshclamConfig()
        {
            string configPath = System.IO.Path.Combine(_clamAVPath, "freshclam.conf");
            if (!System.IO.File.Exists(configPath))
            {
                try
                {
                    string config = $"DatabaseDirectory {_virusDatabasePath}\n" +
                                    "DNSDatabaseInfo current.cvd.clamav.net\n" +
                                    "DatabaseMirror database.clamav.net\n" +
                                    "ConnectTimeout 30\n" +
                                    "ReceiveTimeout 0\n" +
                                    "TestDatabases yes\n" +
                                    "ScriptedUpdates yes\n" +
                                    "CompressLocalDatabase no\n";
                    System.IO.File.WriteAllText(configPath, config);
                    _dataManager?.LogInfo("Created freshclam.conf");
                }
                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ClamAVEngine.cs 捕获异常", ex.Message); }
            }
        }

        private bool RunFreshclam()
        {
            try
            {
                string configPath = System.IO.Path.Combine(_clamAVPath, "freshclam.conf");
                EnsureFreshclamConfig();
                var processInfo = new ProcessStartInfo
                {
                    FileName = _freshclamPath,
                    Arguments = string.Format("--config-file=\"{0}\"", configPath),
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    WorkingDirectory = _clamAVPath
                };

                using (var process = Process.Start(processInfo))
                {
                    if (process == null) return false;
                    string output = process.StandardOutput.ReadToEnd();
                    string error = process.StandardError.ReadToEnd();
                    process.WaitForExit(120000);
                    if (process.ExitCode == 0)
                    {
                        _dataManager?.LogInfo("Virus database updated successfully");
                        return true;
                    }
                    else
                    {
                        _dataManager?.LogWarning($"freshclam exit code: {process.ExitCode}");
                        return false;
                    }
                }
            }
            catch
            {
                return false;
            }
        }

        private bool DownloadFromOfficial()
        {
            try
            {
                string[] cvdFiles = { "daily.cvd", "main.cvd", "bytecode.cvd" };
                string baseUrl = "https://database.clamav.net/";

                using (var client = new System.Net.Http.HttpClient { Timeout = TimeSpan.FromMinutes(10) })
                {
                    client.DefaultRequestHeaders.Add("User-Agent", "ClamAV/1.0");
                    foreach (var file in cvdFiles)
                    {
                        string url = baseUrl + file;
                        string destPath = Path.Combine(_virusDatabasePath, file);

                        try
                        {
                            var bytes = client.GetByteArrayAsync(url).GetAwaiter().GetResult();
                            File.WriteAllBytes(destPath, bytes);
                            _dataManager?.LogInfo($"下载病毒库: {file}");
                        }
                        catch (Exception ex)
                        {
                            _dataManager?.LogWarning($"下载 {file} 失败: {ex.Message}");
                        }
                    }
                }

                return true;
            }
            catch
            {
                return false;
            }
        }

        public string GetDatabaseVersion()
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
                    : "未知";
            }
            catch
            {
                return "未知";
            }
        }

        public bool Initialize()
        {
            return _isInitialized;
        }

        public string GetClamAVVersion()
        {
            try
            {
                if (!File.Exists(_clamscanPath))
                    return "未安装";

                var startInfo = new ProcessStartInfo
                {
                    FileName = _clamscanPath,
                    Arguments = "--version",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    WorkingDirectory = _clamAVPath
                };

                using (var process = Process.Start(startInfo))
                {
                    if (process == null) return "未知";
                    string output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit(10000);
                    
                    if (!string.IsNullOrEmpty(output))
                    {
                        var lines = output.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
                        if (lines.Length > 0)
                        {
                            return lines[0].Trim();
                        }
                    }
                    return "未知";
                }
            }
            catch
            {
                return "未知";
            }
        }

        public int GetVirusDatabaseCount()
        {
            try
            {
                if (!Directory.Exists(_virusDatabasePath))
                    return 0;

                int count = 0;
                var cvdFiles = Directory.GetFiles(_virusDatabasePath, "*.cvd");
                count += cvdFiles.Length;

                var cldFiles = Directory.GetFiles(_virusDatabasePath, "*.cld");
                count += cldFiles.Length;

                return count;
            }
            catch
            {
                return 0;
            }
        }

        public void ScheduleVirusDatabaseUpdate()
        {
            try
            {
                StopVirusDatabaseUpdateSchedule();

                _autoUpdateTimer = new Timer(async (state) =>
                {
                    try
                    {
                        await Task.Run(() => UpdateVirusDatabase());
                    }
                    catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ClamAVEngine.cs 捕获异常", ex.Message); }
                }, null, TimeSpan.FromHours(1), TimeSpan.FromHours(1));

                _dataManager?.LogInfo("病毒库自动更新计划已启动，间隔: 1小时");
            }
            catch (Exception ex)
            {
                _dataManager?.LogError($"启动病毒库自动更新计划失败: {ex.Message}");
            }
        }

        public void StopVirusDatabaseUpdateSchedule()
        {
            try
            {
                if (_autoUpdateTimer != null)
                {
                    _autoUpdateTimer.Dispose();
                    _autoUpdateTimer = null;
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ClamAVEngine.cs 捕获异常", ex.Message); }
        }
    }
}