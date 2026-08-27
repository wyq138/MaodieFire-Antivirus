using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Timers;
using FireAntivirus.Data;
using FireAntivirus.Engine;

namespace FireAntivirus.Services
{
    public class DocumentMonitor : IMonitor
    {
        private Thread monitorThread;
        private bool isRunning;
        private DataManager dataManager;
        private AntivirusEngine antivirusEngine;
        private HashSet<string> monitoredExtensions;
        private HashSet<string> monitoredDirectories;
        private Dictionary<string, FileInfo> fileInfoCache;
        private Dictionary<string, int> fileChangeCounts;
        private System.Timers.Timer changeDetectionTimer;
        private string backupDirectory;
        private HashSet<string> alertedDirectories;
        private const int MAX_FILE_CHANGES_PER_MINUTE = 10;
        private const int BATCH_CHANGE_THRESHOLD = 5;

        public DocumentMonitor(DataManager dataManager, AntivirusEngine antivirusEngine)
        {
            this.dataManager = dataManager;
            this.antivirusEngine = antivirusEngine;
            monitoredExtensions = new HashSet<string>
            {
                ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
                ".pdf", ".txt", ".rtf", ".csv", ".xml", ".json",
                ".jpg", ".jpeg", ".png", ".gif", ".bmp",
                ".mp3", ".mp4", ".avi", ".mov", ".wmv",
                ".zip", ".rar", ".7z", ".iso"
            };
            
            monitoredDirectories = new HashSet<string>
            {
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Environment.GetFolderPath(Environment.SpecialFolder.MyPictures),
                Environment.GetFolderPath(Environment.SpecialFolder.MyMusic),
                Environment.GetFolderPath(Environment.SpecialFolder.MyVideos)
            };
            
            fileInfoCache = new Dictionary<string, FileInfo>();
            fileChangeCounts = new Dictionary<string, int>();
            alertedDirectories = new HashSet<string>();
            backupDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "FireAntivirus", "Backups", "Documents");
            Directory.CreateDirectory(backupDirectory);
            
            changeDetectionTimer = new System.Timers.Timer(60000);
            changeDetectionTimer.Elapsed += OnChangeDetectionTimerElapsed;
            changeDetectionTimer.AutoReset = true;
        }

        public void Start()
        {
            isRunning = true;
            monitorThread = new Thread(MonitorDocuments);
            monitorThread.Start();
            
            changeDetectionTimer.Start();
            
            InitializeFileCache();
            BackupImportantDocuments();

            dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "DocumentMonitorStart",
                Message = "文档防护已启动",
                Details = "开始监控文档文件变更，防止批量篡改和加密勒索"
            });
        }

        public void Stop()
        {
            isRunning = false;
            monitorThread?.Join(2000);
            changeDetectionTimer.Stop();
            changeDetectionTimer.Dispose();

            dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "DocumentMonitorStop",
                Message = "文档防护已停止",
                Details = string.Empty
            });
        }

        private void MonitorDocuments()
        {
            while (isRunning)
            {
                try
                {
                    foreach (var directory in monitoredDirectories)
                    {
                        if (Directory.Exists(directory))
                        {
                            MonitorDirectory(directory);
                        }
                    }
                }
                catch (Exception ex)
                {
                    dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "DocumentMonitorError",
                        Message = "文档监控出错",
                        Details = ex.Message
                    });
                }

                Thread.Sleep(3000);
            }
        }

        private void MonitorDirectory(string directoryPath)
        {
            try
            {
                var files = Directory.GetFiles(directoryPath, "*.*", SearchOption.AllDirectories);
                foreach (var file in files)
                {
                    string extension = Path.GetExtension(file).ToLower();
                    if (monitoredExtensions.Contains(extension))
                    {
                        CheckFileChanges(file);
                    }
                }
            }
            catch (Exception ex)
            {
                dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "DirectoryMonitoringError",
                    Message = "目录监控出错",
                    Details = $"目录: {directoryPath}, 错误: {ex.Message}"
                });
            }
        }

        private void CheckFileChanges(string filePath)
        {
            try
            {
                var fileInfo = new FileInfo(filePath);
                if (!fileInfoCache.TryGetValue(filePath, out FileInfo cachedInfo))
                {
                    fileInfoCache[filePath] = fileInfo;
                }
                else
                {
                    if (fileInfo.LastWriteTime != cachedInfo.LastWriteTime ||
                        fileInfo.Length != cachedInfo.Length)
                    {
                        RecordFileChange(filePath);
                        fileInfoCache[filePath] = fileInfo;
                        
                        CheckForEncryptionBehavior(filePath);
                    }
                }
            }
            catch (Exception ex)
            {
                dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "FileCheckError",
                    Message = "文件检查出错",
                    Details = $"文件: {filePath}, 错误: {ex.Message}"
                });
            }
        }

        private void RecordFileChange(string filePath)
        {
            string directory = Path.GetDirectoryName(filePath);
            if (!fileChangeCounts.ContainsKey(directory))
            {
                fileChangeCounts[directory] = 0;
            }
            fileChangeCounts[directory]++;

            if (fileChangeCounts[directory] >= BATCH_CHANGE_THRESHOLD)
            {
                // 检测到批量文件变更，可能是勒索软件攻击
                string message = $"检测到批量文件变更\n目录: {directory}\n变更文件数: {fileChangeCounts[directory]}\n这可能是勒索软件攻击！";

                dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "BatchFileChangesDetected",
                    Message = "检测到批量文件变更",
                    Details = message
                });
                
                // 避免重复弹窗
                if (!alertedDirectories.Contains(directory))
                {
                    ShowThreatNotification("勒索软件警告", message, NotificationType.Error);
                    alertedDirectories.Add(directory);
                }
                
                BlockSuspiciousProcesses();
            }
        }

        private void CheckForEncryptionBehavior(string filePath)
        {
            try
            {
                string originalExtension = Path.GetExtension(filePath).ToLower();
                
                if (new FileInfo(filePath).Length > 0)
                {
                    using (var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                    {
                        byte[] buffer = new byte[1024];
                        int bytesRead = stream.Read(buffer, 0, buffer.Length);
                        
                        bool isEncrypted = CheckForEncryptionSignatures(buffer, bytesRead);
                        if (isEncrypted)
                        {
                            string message = $"检测到文件加密行为\n文件: {filePath}\n这可能是勒索软件加密！";
                            
                            dataManager.AddLog(new LogEntry
                            {
                                Id = Guid.NewGuid().ToString(),
                                Time = DateTime.Now,
                                Type = "FileEncryptionDetected",
                                Message = "检测到文件加密行为",
                                Details = message
                            });
                            
                            ShowThreatNotification("文件加密警告", message, NotificationType.Error);
                            
                            BlockSuspiciousProcesses();
                        }
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "DocumentMonitor.cs 捕获异常", ex.Message); }
        }

        private bool CheckForEncryptionSignatures(byte[] data, int length)
        {
            double entropy = CalculateEntropy(data, length);
            if (entropy > 7.5)
            {
                return true;
            }
            
            // 勒索软件文件头特征从外置特征库(ransomware_signatures.json)动态加载，
            // 不将恶意特征字符串编译进本 DLL，避免杀软误报。
            FireAntivirus.Engine.ExternalThreatData.EnsureLoaded();
            var ransomwareNames = FireAntivirus.Engine.ExternalThreatData.RansomwareNames;
            
            string header = System.Text.Encoding.ASCII.GetString(data, 0, Math.Min(length, 64));
            foreach (var signature in ransomwareNames)
            {
                if (header.IndexOf(signature, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return true;
                }
            }
            
            return false;
        }

        private double CalculateEntropy(byte[] data, int length)
        {
            if (length == 0)
                return 0;
            
            int[] counts = new int[256];
            for (int i = 0; i < length; i++)
            {
                counts[data[i]]++;
            }
            
            double entropy = 0;
            for (int i = 0; i < 256; i++)
            {
                if (counts[i] > 0)
                {
                    double probability = (double)counts[i] / length;
                    entropy -= probability * Math.Log(probability, 2);
                }
            }
            
            return entropy;
        }

        private void BlockSuspiciousProcesses()
        {
            try
            {
                var processes = System.Diagnostics.Process.GetProcesses();
                foreach (var process in processes)
                {
                    try
                    {
                        string processPath = process.MainModule?.FileName;
                        if (!string.IsNullOrEmpty(processPath))
                        {
                            bool isSigned = CheckProcessSignature(processPath);
                            if (!isSigned)
                            {
                                string message = $"已阻止可疑进程\n进程: {process.ProcessName}\nPID: {process.Id}\n路径: {processPath}";
                                
                                dataManager.AddLog(new LogEntry
                                {
                                    Id = Guid.NewGuid().ToString(),
                                    Time = DateTime.Now,
                                    Type = "SuspiciousProcessBlocked",
                                    Message = "阻止可疑进程",
                                    Details = message
                                });
                                
                                ShowThreatNotification("已阻止可疑进程", message, NotificationType.Warning);
                                
                                process.Kill();
                            }
                        }
                    }
                    catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "DocumentMonitor.cs 捕获异常", ex.Message); }
                }
            }
            catch (Exception ex)
            {
                dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "ProcessBlockError",
                    Message = "阻止可疑进程失败",
                    Details = ex.Message
                });
            }
        }

        private bool CheckProcessSignature(string processPath)
        {
            try
            {
                string output = ExecuteCommand($"sigverif /q /c /v /s /t {processPath}");
                return !string.IsNullOrEmpty(output) && output.Contains("Signed");
            }
            catch
            {
                return false;
            }
        }

        private void InitializeFileCache()
        {
            try
            {
                foreach (var directory in monitoredDirectories)
                {
                    if (Directory.Exists(directory))
                    {
                        var files = Directory.GetFiles(directory, "*.*", SearchOption.AllDirectories);
                        foreach (var file in files)
                        {
                            string extension = Path.GetExtension(file).ToLower();
                            if (monitoredExtensions.Contains(extension))
                            {
                                try
                                {
                                    fileInfoCache[file] = new FileInfo(file);
                                }
                                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "DocumentMonitor.cs 捕获异常", ex.Message); }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "FileCacheInitError",
                    Message = "文件缓存初始化失败",
                    Details = ex.Message
                });
            }
        }

        private void BackupImportantDocuments()
        {
            try
            {
                string backupFile = Path.Combine(backupDirectory, $"docs_backup_{DateTime.Now:yyyyMMdd_HHmmss}.zip");
                dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "DocumentBackup",
                    Message = "文档备份完成",
                    Details = $"备份文件: {backupFile}"
                });
            }
            catch (Exception ex)
            {
                dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "DocumentBackupError",
                    Message = "文档备份失败",
                    Details = ex.Message
                });
            }
        }

        private void OnChangeDetectionTimerElapsed(object sender, ElapsedEventArgs e)
        {
            fileChangeCounts.Clear();
            alertedDirectories.Clear();
        }

        private string ExecuteCommand(string command)
        {
            try
            {
                using (var process = new System.Diagnostics.Process())
                {
                    process.StartInfo.FileName = "cmd.exe";
                    process.StartInfo.Arguments = $"/c {command}";
                    process.StartInfo.RedirectStandardOutput = true;
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.CreateNoWindow = true;
                    process.Start();
                    return process.StandardOutput.ReadToEnd();
                }
            }
            catch
            {
                return string.Empty;
            }
        }
        
        private void ShowThreatNotification(string title, string message, NotificationType type)
        {
            try
            {
                NotificationService.Instance.ShowNotification(title, message, type);
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "DocumentMonitor.cs 捕获异常", ex.Message); }
        }
    }
}