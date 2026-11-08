using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Enumeration;
using System.Linq;
using System.Management;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Text.RegularExpressions;
using FireAntivirus.Common;
using FireAntivirus.Data;

namespace FireAntivirus.RansomwareProtection
{
    public class RansomwareProtectionManager
    {
        private DataManager _dataManager;
        private List<ProtectedFile> _protectedFiles;
        private List<RansomwareDetection> _detections;
        private List<string> _protectedDirectories;
        private bool _isEnabled;

        public RansomwareProtectionManager(DataManager dataManager)
        {
            _dataManager = dataManager;
            _protectedFiles = new List<ProtectedFile>();
            _detections = new List<RansomwareDetection>();
            _protectedDirectories = new List<string>();
            _isEnabled = true;
            InitializeProtection();
        }

        private void InitializeProtection()
        {
            LoadProtectedDirectories();
            LoadProtectedFiles();
        }

        private void LoadProtectedDirectories()
        {
            // 加载需要保护的目录
            _protectedDirectories.Add(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments));
            _protectedDirectories.Add(Environment.GetFolderPath(Environment.SpecialFolder.Desktop));
            _protectedDirectories.Add(Environment.GetFolderPath(Environment.SpecialFolder.MyPictures));
            _protectedDirectories.Add(Environment.GetFolderPath(Environment.SpecialFolder.MyMusic));
            _protectedDirectories.Add(Environment.GetFolderPath(Environment.SpecialFolder.MyVideos));
        }

        private void LoadProtectedFiles()
        {
            // 加载受保护的文件（监控所有文件，不只是前10个）
            foreach (var directory in _protectedDirectories)
            {
                if (Directory.Exists(directory))
                {
                    try
                    {
                        // 监控常见文档类型
                        var extensions = new[] { "*.doc", "*.docx", "*.xls", "*.xlsx", "*.ppt", "*.pptx", 
                            "*.pdf", "*.txt", "*.jpg", "*.jpeg", "*.png", "*.mp3", "*.mp4", "*.zip", "*.rar" };
                        
                        foreach (var ext in extensions)
                        {
                            var files = Directory.GetFiles(directory, ext, SearchOption.TopDirectoryOnly);
                            foreach (var file in files)
                            {
                                _protectedFiles.Add(new ProtectedFile
                                {
                                    FilePath = file,
                                    LastModified = File.GetLastWriteTime(file),
                                    FileSize = new FileInfo(file).Length
                                });
                            }
                        }
                    }
                    catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "RansomwareProtectionManager.cs 捕获异常", ex.Message); }
                }
            }
        }

        public void StartProtection()
        {
            _isEnabled = true;
            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "RansomwareProtectionStarted",
                Message = "勒索软件防护已启动"
            });
        }

        public void StopProtection()
        {
            _isEnabled = false;
            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "RansomwareProtectionStopped",
                Message = "勒索软件防护已停止"
            });
        }

        public bool IsEnabled()
        {
            return _isEnabled;
        }

        public void AddProtectedDirectory(string directory)
        {
            if (!_protectedDirectories.Contains(directory) && Directory.Exists(directory))
            {
                _protectedDirectories.Add(directory);
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "ProtectedDirectoryAdded",
                    Message = "已添加受保护目录",
                    Details = $"目录: {directory}"
                });
            }
        }

        public void RemoveProtectedDirectory(string directory)
        {
            if (_protectedDirectories.Contains(directory))
            {
                _protectedDirectories.Remove(directory);
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "ProtectedDirectoryRemoved",
                    Message = "已移除受保护目录",
                    Details = $"目录: {directory}"
                });
            }
        }

        public List<string> GetProtectedDirectories()
        {
            return _protectedDirectories;
        }

        public RansomwareDetectionResult DetectRansomwareActivity()
        {
            var result = new RansomwareDetectionResult
            {
                Timestamp = DateTime.Now,
                IsRansomwareDetected = false
            };

            if (!_isEnabled)
            {
                result.Message = "勒索软件防护已禁用";
                return result;
            }

            try
            {
                // 检测可疑的文件操作模式
                var suspiciousActivities = DetectSuspiciousFileActivities();
                if (suspiciousActivities.Count > 0)
                {
                    result.IsRansomwareDetected = true;
                    result.Detections = suspiciousActivities;
                    result.Message = $"检测到 {suspiciousActivities.Count} 个可疑活动";

                    // 记录检测结果
                    foreach (var detection in suspiciousActivities)
                    {
                        _detections.Add(detection);
                        _dataManager.AddLog(new LogEntry
                        {
                            Id = Guid.NewGuid().ToString(),
                            Time = DateTime.Now,
                            Type = "RansomwareDetected",
                            Message = "检测到勒索软件活动",
                            Details = $"类型: {detection.DetectionType}, 进程: {detection.ProcessName}, 文件: {detection.AffectedFile}"
                        });
                    }
                }
                else
                {
                    result.Message = "未检测到勒索软件活动";
                }
            }
            catch (Exception ex)
            {
                result.Message = $"检测过程中发生错误: {ex.Message}";
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "RansomwareDetectionError",
                    Message = "勒索软件检测错误",
                    Details = $"错误: {ex.Message}"
                });
            }

            return result;
        }

        private List<RansomwareDetection> DetectSuspiciousFileActivities()
        {
            var detections = new List<RansomwareDetection>();
            
            // 检测文件加密行为
            foreach (var protectedFile in _protectedFiles)
            {
                try
                {
                    if (File.Exists(protectedFile.FilePath))
                    {
                        var currentInfo = new FileInfo(protectedFile.FilePath);
                        var currentSize = currentInfo.Length;
                        var currentModified = currentInfo.LastWriteTime;

                        // 检测文件大小和修改时间的异常变化
                        var timeDiff = (currentModified - protectedFile.LastModified).TotalSeconds;
                        
                        if (currentSize != protectedFile.FileSize && Math.Abs(timeDiff) < 5)
                        {
                            // 获取访问该文件的进程
                            var processName = GetProcessUsingFile(protectedFile.FilePath);
                            
                            // 检查是否是勒索软件特征
                            if (IsRansomwareExtension(protectedFile.FilePath) || 
                                currentSize > protectedFile.FileSize * 1.5 || 
                                currentSize < protectedFile.FileSize * 0.5)
                            {
                                detections.Add(new RansomwareDetection
                                {
                                    Id = Guid.NewGuid().ToString(),
                                    DetectionType = RansomwareDetectionType.FileEncryption,
                                    ProcessName = processName,
                                    AffectedFile = protectedFile.FilePath,
                                    Timestamp = DateTime.Now
                                });
                            }
                        }
                    }
                }
                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "RansomwareProtectionManager.cs 捕获异常", ex.Message); }
            }

            // 检测大量文件重命名（常见勒索软件行为）
            var recentRenames = DetectMassFileRenames();
            detections.AddRange(recentRenames);

            return detections;
        }

        private string GetProcessUsingFile(string filePath)
        {
            try
            {
                // 使用WMI查询正在使用该文件的进程
                using var searcher = new ManagementObjectSearcher(
                    $"SELECT * FROM Win32_Process");
                
                foreach (var obj in searcher.Get())
                {
                    var cmdLine = obj["CommandLine"]?.ToString() ?? "";
                    if (cmdLine.Contains(filePath, StringComparison.OrdinalIgnoreCase))
                    {
                        return obj["Name"]?.ToString() ?? "unknown";
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "RansomwareProtectionManager.cs 捕获异常", ex.Message); }
            return "unknown";
        }

        private bool IsRansomwareExtension(string filePath)
        {
            // 常见勒索软件加密后的扩展名
            var ransomwareExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                ".encrypted", ".locked", ".crypto", ".cerber", ".locky", ".zepto",
                ".odin", ".shit", ".rdmk", ".zzz", ".xxx", ".yyy", ".zzz",
                ".aaa", ".abc", ".xxx", ".micro", ".cry", "._rsa", ".encrypted",
                ".enc", ".crjoker", ".LeChiffre", ".keybtc@inbox_com", ".0x5bm",
                ".r5a", ".r16m01x05", ".paymrkt", ".explore", ".nesa", ".shadow",
                ".codnat", ".codnat1", ".daghines", ".duhust", ".kasp", ".MRCR1"
            };

            var ext = Path.GetExtension(filePath);
            return ransomwareExtensions.Contains(ext);
        }

        private List<RansomwareDetection> DetectMassFileRenames()
        {
            var detections = new List<RansomwareDetection>();
            
            try
            {
                // 使用WMI监控文件系统活动
                using var searcher = new ManagementObjectSearcher(
                    "SELECT * FROM Win32_Process WHERE Name LIKE '%.exe'");
                
                // 检查可疑进程
                var suspiciousProcessNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                {
                    "vssadmin", "bcdedit", "wbadmin", "wmic", "powershell", "cmd"
                };

                foreach (var obj in searcher.Get())
                {
                    var processName = obj["Name"]?.ToString() ?? "";
                    var cmdLine = obj["CommandLine"]?.ToString()?.ToLower() ?? "";
                    
                    // 检测删除卷影副本的命令
                    if (cmdLine.Contains("delete shadows") || 
                        cmdLine.Contains("shadowcopy delete") ||
                        cmdLine.Contains("recoveryenabled no"))
                    {
                        detections.Add(new RansomwareDetection
                        {
                            Id = Guid.NewGuid().ToString(),
                            DetectionType = RansomwareDetectionType.ShadowCopyDeletion,
                            ProcessName = processName,
                            AffectedFile = "ShadowCopy",
                            Timestamp = DateTime.Now
                        });
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "RansomwareProtectionManager.cs 捕获异常", ex.Message); }
            
            return detections;
        }

        public bool BlockProcess(string processName)
        {
            try
            {
                // 终止所有匹配的进程
                var processes = Process.GetProcessesByName(Path.GetFileNameWithoutExtension(processName));
                var terminated = false;
                
                foreach (var process in processes)
                {
                    try
                    {
                        if (!FireAntivirus.Common.TrustedProcessGuard.CanTerminate(process))
                        {
                            FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info, "RansomwareProtectionManager", $"进程受保护，已跳过查杀: {processName} PID: {process.Id}");
                            continue;
                        }
                        process.Kill();
                        terminated = true;
                    }
                    catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "RansomwareProtectionManager.cs 捕获异常", ex.Message); }
                }
                
                if (terminated)
                {
                    _dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "ProcessBlocked",
                        Message = "进程已被阻止",
                        Details = $"进程: {processName}"
                    });
                }
                
                return terminated;
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "ProcessBlockError",
                    Message = "进程阻止错误",
                    Details = $"进程: {processName}, 错误: {ex.Message}"
                });
                return false;
            }
        }

        public bool RestoreFile(string filePath)
        {
            try
            {
                // 检查是否有备份
                var backupPath = GetBackupPath(filePath);
                
                if (File.Exists(backupPath))
                {
                    // 恢复文件
                    File.Copy(backupPath, filePath, true);
                    
                    _dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "FileRestored",
                        Message = "文件已恢复",
                        Details = $"文件: {filePath}, 备份: {backupPath}"
                    });
                    return true;
                }
                
                // 尝试使用卷影副本恢复
                if (RestoreFromShadowCopy(filePath))
                {
                    _dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "FileRestoredFromShadowCopy",
                        Message = "文件已从卷影副本恢复",
                        Details = $"文件: {filePath}"
                    });
                    return true;
                }
                
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "FileRestoreFailed",
                    Message = "无法恢复文件",
                    Details = $"文件: {filePath}, 没有可用的备份"
                });
                return false;
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "FileRestoreError",
                    Message = "文件恢复错误",
                    Details = $"文件: {filePath}, 错误: {ex.Message}"
                });
                return false;
            }
        }

        private string GetBackupPath(string filePath)
        {
            // 检查备份目录
            var backupDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "FireAntivirus", "Backups", "RansomwareProtection");
            
            if (!Directory.Exists(backupDir))
                return null;
            
            // 计算文件哈希作为备份名
            var fileName = Path.GetFileName(filePath);
            return Path.Combine(backupDir, fileName);
        }

        private bool RestoreFromShadowCopy(string filePath)
        {
            try
            {
                // 使用vssadmin列出卷影副本的设备路径，真实从中复制文件恢复
                var psi = new ProcessStartInfo
                {
                    FileName = "vssadmin",
                    Arguments = "list shadows",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                };

                using var process = Process.Start(psi);
                var output = process?.StandardOutput.ReadToEnd() ?? "";

                // 解析所有卷影卷设备路径（\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN）
                var matches = System.Text.RegularExpressions.Regex.Matches(
                    output, @"\\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy\d+");
                if (matches.Count == 0)
                {
                    _dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "ShadowCopyRestore",
                        Message = "未找到可用卷影副本，无法从卷影恢复",
                        Details = $"文件: {filePath}"
                    });
                    return false;
                }

                // 相对路径从卷影卷根尝试还原（卷影副本保存的是整卷视图）
                string relative = filePath;
                var root = Path.GetPathRoot(filePath) ?? "";
                if (!string.IsNullOrEmpty(root) && filePath.StartsWith(root, StringComparison.OrdinalIgnoreCase))
                    relative = filePath.Substring(root.Length).TrimStart('\\', '/');

                foreach (Match m in matches)
                {
                    string shadowFile = m.Value.TrimEnd('\\') + "\\" + relative;
                    try
                    {
                        if (File.Exists(shadowFile))
                        {
                            Directory.CreateDirectory(Path.GetDirectoryName(filePath));
                            File.Copy(shadowFile, filePath, overwrite: true);
                            _dataManager.AddLog(new LogEntry
                            {
                                Id = Guid.NewGuid().ToString(),
                                Time = DateTime.Now,
                                Type = "ShadowCopyRestored",
                                Message = "已从卷影副本恢复文件",
                                Details = $"文件: {filePath} <- {m.Value}"
                            });
                            return true;
                        }
                    }
                    catch { /* 该卷影中不存在此文件，尝试下一个 */ }
                }

                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "ShadowCopyRestore",
                    Message = "卷影副本中未找到该文件的可用版本",
                    Details = $"文件: {filePath}"
                });
                return false;
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "RansomwareProtectionManager.cs 捕获异常", ex.Message); }
            
            return false;
        }

        public List<RansomwareDetection> GetDetections()
        {
            return _detections;
        }
    }
}