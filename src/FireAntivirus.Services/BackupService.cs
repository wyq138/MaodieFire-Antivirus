using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using FireAntivirus.Data;
using FireAntivirus.Common.Notification;

namespace FireAntivirus.Services
{
    public class BackupService : IMonitor
    {
        private Thread _monitorThread;
        private bool _isRunning;
        private DataManager _dataManager;
        private List<BackupTask> _backupTasks;
        private string _backupDirectory;

        public BackupService(DataManager dataManager)
        {
            _dataManager = dataManager;
            _backupTasks = new List<BackupTask>();
            _backupDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "FireAntivirus", "Backups");
            Directory.CreateDirectory(_backupDirectory);
            LoadBackupTasks();
        }

        public void Start()
        {
            _isRunning = true;
            _monitorThread = new Thread(MonitorBackups);
            _monitorThread.Start();

            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "BackupServiceStart",
                Message = "备份服务已启动",
                Details = "开始监控备份任务"
            });
        }

        public void Stop()
        {
            _isRunning = false;
            _monitorThread?.Join(2000);

            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "BackupServiceStop",
                Message = "备份服务已停止",
                Details = string.Empty
            });
        }

        private void MonitorBackups()
        {
            while (_isRunning)
            {
                try
                {
                    CheckBackupTasks();
                }
                catch (Exception ex)
                {
                    _dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "BackupServiceError",
                        Message = "备份服务错误",
                        Details = ex.Message
                    });
                }

                Thread.Sleep(60000); // 每分钟检查一次
            }
        }

        private void CheckBackupTasks()
        {
            foreach (var task in _backupTasks)
            {
                if (task.Enabled && IsTimeToRun(task))
                {
                    RunBackup(task);
                }
            }
        }

        private bool IsTimeToRun(BackupTask task)
        {
            // 检查是否到了执行时间
            // 简化实现，实际应该根据任务的调度计划来判断
            return true;
        }

        public void RunBackup(BackupTask task)
        {
            try
            {
                string backupPath = Path.Combine(_backupDirectory, $"{task.Name}_{DateTime.Now:yyyyMMdd_HHmmss}");
                Directory.CreateDirectory(backupPath);

                // 执行备份
                foreach (string sourcePath in task.SourcePaths)
                {
                    if (Directory.Exists(sourcePath))
                    {
                        BackupDirectory(sourcePath, backupPath);
                    }
                    else if (File.Exists(sourcePath))
                    {
                        BackupFile(sourcePath, backupPath);
                    }
                }

                // 更新任务状态
                task.LastRun = DateTime.Now;
                task.Status = "成功";
                SaveBackupTasks();

                NotificationService.Instance.ShowNotification(
                    "备份完成",
                    $"备份任务 '{task.Name}' 已成功完成",
                    NotificationType.Info
                );

                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "BackupCompleted",
                    Message = "备份任务已完成",
                    Details = $"任务名称: {task.Name}, 备份路径: {backupPath}"
                });
            }
            catch (Exception ex)
            {
                task.Status = "失败: " + ex.Message;
                SaveBackupTasks();

                NotificationService.Instance.ShowNotification(
                    "备份失败",
                    $"备份任务 '{task.Name}' 执行失败: {ex.Message}",
                    NotificationType.Error
                );

                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "BackupFailed",
                    Message = "备份任务执行失败",
                    Details = $"任务名称: {task.Name}, 错误: {ex.Message}"
                });
            }
        }

        private void BackupDirectory(string sourceDir, string targetDir)
        {
            // 创建目标目录
            string targetPath = Path.Combine(targetDir, Path.GetFileName(sourceDir));
            Directory.CreateDirectory(targetPath);

            // 复制文件
            string[] files = Directory.GetFiles(sourceDir);
            foreach (string file in files)
            {
                string fileName = Path.GetFileName(file);
                string destFile = Path.Combine(targetPath, fileName);
                File.Copy(file, destFile, true);
            }

            // 递归复制子目录
            string[] subDirs = Directory.GetDirectories(sourceDir);
            foreach (string subDir in subDirs)
            {
                BackupDirectory(subDir, targetPath);
            }
        }

        private void BackupFile(string sourceFile, string targetDir)
        {
            string fileName = Path.GetFileName(sourceFile);
            string destFile = Path.Combine(targetDir, fileName);
            File.Copy(sourceFile, destFile, true);
        }

        public void CreateBackupTask(string name, List<string> sourcePaths, string schedule)
        {
            var task = new BackupTask
            {
                Id = Guid.NewGuid().ToString(),
                Name = name,
                SourcePaths = sourcePaths,
                Schedule = schedule,
                Enabled = true,
                CreatedAt = DateTime.Now,
                LastRun = null,
                Status = "就绪"
            };

            _backupTasks.Add(task);
            SaveBackupTasks();

            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "BackupTaskCreated",
                Message = "备份任务已创建",
                Details = $"任务名称: {name}, 源路径数: {sourcePaths.Count}"
            });
        }

        public void RestoreBackup(string backupPath, string targetPath)
        {
            try
            {
                if (Directory.Exists(backupPath))
                {
                    // 恢复文件
                    RestoreDirectory(backupPath, targetPath);

                    NotificationService.Instance.ShowNotification(
                        "恢复完成",
                        "备份已成功恢复",
                        NotificationType.Info
                    );

                    _dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "RestoreCompleted",
                        Message = "备份恢复已完成",
                        Details = $"备份路径: {backupPath}, 目标路径: {targetPath}"
                    });
                }
            }
            catch (Exception ex)
            {
                NotificationService.Instance.ShowNotification(
                    "恢复失败",
                    $"备份恢复失败: {ex.Message}",
                    NotificationType.Error
                );

                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "RestoreFailed",
                    Message = "备份恢复失败",
                    Details = $"错误: {ex.Message}"
                });
            }
        }

        private void RestoreDirectory(string sourceDir, string targetDir)
        {
            // 创建目标目录
            Directory.CreateDirectory(targetDir);

            // 复制文件
            string[] files = Directory.GetFiles(sourceDir);
            foreach (string file in files)
            {
                string fileName = Path.GetFileName(file);
                string destFile = Path.Combine(targetDir, fileName);
                File.Copy(file, destFile, true);
            }

            // 递归复制子目录
            string[] subDirs = Directory.GetDirectories(sourceDir);
            foreach (string subDir in subDirs)
            {
                string subDirName = Path.GetFileName(subDir);
                string destSubDir = Path.Combine(targetDir, subDirName);
                RestoreDirectory(subDir, destSubDir);
            }
        }

        private void LoadBackupTasks()
        {
            // 从文件或数据库加载备份任务
            try
            {
                string tasksFile = Path.Combine(_backupDirectory, "backup_tasks.json");
                if (File.Exists(tasksFile))
                {
                    string content = File.ReadAllText(tasksFile);
                    _backupTasks = Newtonsoft.Json.JsonConvert.DeserializeObject<List<BackupTask>>(content) ?? new List<BackupTask>();
                }
            }
            catch { }
        }

        private void SaveBackupTasks()
        {
            // 保存备份任务到文件或数据库
            try
            {
                string tasksFile = Path.Combine(_backupDirectory, "backup_tasks.json");
                string content = Newtonsoft.Json.JsonConvert.SerializeObject(_backupTasks);
                File.WriteAllText(tasksFile, content);
            }
            catch { }
        }
    }

    public class BackupTask
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public List<string> SourcePaths { get; set; }
        public string Schedule { get; set; }
        public bool Enabled { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime? LastRun { get; set; }
        public string Status { get; set; }

        public BackupTask()
        {
            SourcePaths = new List<string>();
        }
    }
}
