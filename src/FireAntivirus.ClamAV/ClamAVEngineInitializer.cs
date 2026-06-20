using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using FireAntivirus.Data;

namespace FireAntivirus.ClamAV
{
    public class ClamAVEngineInitializer
    {
        private DataManager _dataManager;
        private string _enginePath;
        private string _databasePath;
        private bool _isInitialized;

        public ClamAVEngineInitializer(DataManager dataManager)
        {
            _dataManager = dataManager;
            InitializeEnginePath();
        }

        private void InitializeEnginePath()
        {
            try
            {
                string appDirectory = AppDomain.CurrentDomain.BaseDirectory;
                if (string.IsNullOrEmpty(appDirectory))
                {
                    appDirectory = Path.GetDirectoryName(Assembly.GetEntryAssembly()?.Location ?? Assembly.GetExecutingAssembly().Location);
                }
                
                string[] possiblePaths = new string[]
                {
                    Path.Combine(appDirectory, "ClamAV"),
                    Path.Combine(appDirectory, "clamav"),
                    Path.Combine(appDirectory, "FireAntivirus.ClamAV", "ClamAV"),
                    Path.Combine(appDirectory, "..", "ClamAV"),
                    Path.Combine(appDirectory, "..", "clamav"),
                };

                foreach (var clamPath in possiblePaths)
                {
                    string clamAvOutputPath = Path.GetFullPath(clamPath);
                    
                    if (Directory.Exists(clamAvOutputPath))
                    {
                        string dbPath = Path.Combine(clamAvOutputPath, "db");
                        string altDbPath = Path.Combine(clamAvOutputPath, "database");
                        
                        bool hasDb = (Directory.Exists(dbPath) && Directory.GetFiles(dbPath, "*.cvd").Length > 0) ||
                                     (Directory.Exists(altDbPath) && Directory.GetFiles(altDbPath, "*.cvd").Length > 0);
                        bool hasClamscan = File.Exists(Path.Combine(clamAvOutputPath, "clamscan.exe"));
                        
                        if (hasDb || hasClamscan)
                        {
                            _enginePath = clamAvOutputPath;
                            _databasePath = Directory.Exists(dbPath) ? dbPath : altDbPath;
                            
                            if (!Directory.Exists(_databasePath))
                            {
                                _databasePath = dbPath;
                                Directory.CreateDirectory(_databasePath);
                            }
                            
                            _isInitialized = true;
                            
                            _dataManager?.LogInfo($"ClamAV引擎路径初始化成功: {_enginePath}");
                            
                            ValidateEngineComponents();
                            return;
                        }
                    }
                }

                string defaultPath = Path.Combine(appDirectory, "ClamAV");
                _enginePath = defaultPath;
                _databasePath = Path.Combine(defaultPath, "db");
                Directory.CreateDirectory(_databasePath);
                _isInitialized = true;
                _dataManager?.LogInfo($"ClamAV 使用默认路径: {_enginePath}");
            }
            catch (Exception ex)
            {
                _isInitialized = false;
                _dataManager?.LogError($"ClamAV引擎路径初始化失败: {ex.Message}");
            }
        }

        private void CopyEngineToOutput(string outputPath)
        {
            try
            {
                if (!Directory.Exists(outputPath))
                {
                    Directory.CreateDirectory(outputPath);
                }

                // 复制所有ClamAV文件
                foreach (string file in Directory.GetFiles(_enginePath))
                {
                    string destFile = Path.Combine(outputPath, Path.GetFileName(file));
                    File.Copy(file, destFile, true);
                }

                // 复制数据库目录
                string destDbPath = Path.Combine(outputPath, "db");
                if (!Directory.Exists(destDbPath))
                {
                    Directory.CreateDirectory(destDbPath);
                }

                if (Directory.Exists(_databasePath))
                {
                    foreach (string file in Directory.GetFiles(_databasePath))
                    {
                        string destFile = Path.Combine(destDbPath, Path.GetFileName(file));
                        File.Copy(file, destFile, true);
                    }
                }

                _dataManager?.LogInfo($"ClamAV引擎文件已复制到输出目录: {outputPath}");
            }
            catch (Exception ex)
            {
                _dataManager?.LogWarning($"ClamAV引擎文件复制失败: {ex.Message}");
            }
        }

        private void ValidateEngineComponents()
        {
            if (!_isInitialized) return;

            try
            {
                // 检查核心文件
                string[] requiredFiles = {
                    Path.Combine(_enginePath, "freshclam.exe"),
                    Path.Combine(_enginePath, "freshclam.conf"),
                    Path.Combine(_enginePath, "libclamav.dll")
                };

                foreach (string file in requiredFiles)
                {
                    if (!File.Exists(file))
                    {
                        _isInitialized = false;
                        _dataManager?.LogError($"ClamAV引擎文件缺失: {Path.GetFileName(file)}");
                        return;
                    }
                }

                // 检查病毒库文件
                string[] databaseFiles = {
                    Path.Combine(_databasePath, "main.cvd"),
                    Path.Combine(_databasePath, "daily.cvd"),
                    Path.Combine(_databasePath, "bytecode.cvd")
                };

                int validDbFiles = 0;
                foreach (string dbFile in databaseFiles)
                {
                    if (File.Exists(dbFile) && new FileInfo(dbFile).Length > 0)
                    {
                        validDbFiles++;
                        _dataManager?.LogInfo($"病毒库文件验证通过: {Path.GetFileName(dbFile)}");
                    }
                }

                if (validDbFiles < 2)
                {
                    _dataManager?.LogWarning("病毒库文件不完整，需要更新");
                    // 不标记为初始化失败，因为可以后续更新
                }

                _dataManager?.LogInfo("ClamAV引擎组件验证完成");
            }
            catch (Exception ex)
            {
                _isInitialized = false;
                _dataManager?.LogError($"ClamAV引擎组件验证失败: {ex.Message}");
            }
        }

        public bool TestEngine()
        {
            if (!_isInitialized)
            {
                _dataManager?.LogError("ClamAV引擎未初始化");
                return false;
            }

            try
            {
                string clamScanPath = Path.Combine(_enginePath, "freshclam.exe");
                
                // 测试freshclam执行
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = clamScanPath,
                    Arguments = "--version",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true
                };

                using (Process process = Process.Start(psi))
                {
                    if (process != null)
                    {
                        string output = process.StandardOutput.ReadToEnd();
                        process.WaitForExit(5000); // 5秒超时
                        
                        if (process.ExitCode == 0 && output.Contains("ClamAV"))
                        {
                            _dataManager?.LogInfo($"ClamAV引擎测试成功: {output.Trim()}");
                            return true;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _dataManager?.LogError($"ClamAV引擎测试失败: {ex.Message}");
            }

            return false;
        }

        public bool UpdateVirusDatabase()
        {
            if (!_isInitialized) return false;

            try
            {
                string freshclamPath = Path.Combine(_enginePath, "freshclam.exe");
                string configPath = Path.Combine(_enginePath, "freshclam.conf");

                if (!File.Exists(freshclamPath) || !File.Exists(configPath))
                {
                    _dataManager?.LogError("ClamAV更新工具不存在");
                    return false;
                }

                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = freshclamPath,
                    Arguments = $"--config-file=\"{configPath}\" --datadir=\"{_databasePath}\"",
                    WorkingDirectory = _enginePath,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };

                using (Process process = Process.Start(psi))
                {
                    if (process == null)
                    {
                        _dataManager?.LogError("无法启动病毒库更新进程");
                        return false;
                    }

                    string output = process.StandardOutput.ReadToEnd();
                    string error = process.StandardError.ReadToEnd();
                    process.WaitForExit(120000); // 2分钟超时

                    if (process.ExitCode == 0)
                    {
                        _dataManager?.LogInfo("ClamAV病毒库更新成功");
                        return true;
                    }
                    else
                    {
                        _dataManager?.LogWarning($"ClamAV病毒库更新失败: {error}");
                        return false;
                    }
                }
            }
            catch (Exception ex)
            {
                _dataManager?.LogError($"病毒库更新异常: {ex.Message}");
                return false;
            }
        }

        public string GetEngineInfo()
        {
            if (!_isInitialized) return "引擎未初始化";

            try
            {
                string info = $"ClamAV引擎路径: {_enginePath}\n";
                info += $"数据库路径: {_databasePath}\n";

                // 检查病毒库文件版本
                if (Directory.Exists(_databasePath))
                {
                    var files = Directory.GetFiles(_databasePath, "*.cvd");
                    info += $"病毒库文件数量: {files.Length}\n";

                    foreach (string file in files)
                    {
                        var fileInfo = new FileInfo(file);
                        info += $"{Path.GetFileName(file)} - 大小: {fileInfo.Length / 1024 / 1024}MB, 更新时间: {fileInfo.LastWriteTime}\n";
                    }
                }

                return info;
            }
            catch
            {
                return "获取引擎信息失败";
            }
        }

        public bool IsInitialized => _isInitialized;
        public string EnginePath => _enginePath;
        public string DatabasePath => _databasePath;
    }
}