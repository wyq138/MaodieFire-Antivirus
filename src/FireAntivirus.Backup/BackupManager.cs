using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using FireAntivirus.Common;
using FireAntivirus.Data;

namespace FireAntivirus.Backup
{
    public class BackupManager
    {
        private DataManager _dataManager;
        private string _backupRoot;
        private List<BackupEntry> _backupEntries;

        public BackupManager(DataManager dataManager)
        {
            _dataManager = dataManager;
            _backupRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "FireAntivirus", "Backups");
            _backupEntries = new List<BackupEntry>();
            InitializeBackup();
        }

        private void InitializeBackup()
        {
            Directory.CreateDirectory(_backupRoot);
            LoadBackups();
        }

        private void LoadBackups()
        {
            // 从备份目录加载真实的备份文件
            if (!Directory.Exists(_backupRoot))
            {
                Directory.CreateDirectory(_backupRoot);
                return;
            }

            try
            {
                var backupFiles = Directory.GetFiles(_backupRoot, "*.zip");
                foreach (var file in backupFiles)
                {
                    try
                    {
                        var fileInfo = new FileInfo(file);
                        _backupEntries.Add(new BackupEntry
                        {
                            Id = Guid.NewGuid().ToString(),
                            Name = Path.GetFileNameWithoutExtension(file),
                            Description = "用户备份",
                            Path = file,
                            Size = fileInfo.Length,
                            CreatedAt = fileInfo.CreationTime,
                            Type = BackupType.Custom
                        });
                    }
                    catch { /* 忽略读取错误的文件 */ }
                }

                // 同时从备份索引文件加载
                string indexFile = Path.Combine(_backupRoot, "backup_index.json");
                if (File.Exists(indexFile))
                {
                    try
                    {
                        var json = File.ReadAllText(indexFile);
                        var entries = Newtonsoft.Json.JsonConvert.DeserializeObject<List<BackupEntry>>(json);
                        if (entries != null)
                        {
                            foreach (var entry in entries)
                            {
                                if (!_backupEntries.Any(e => e.Path == entry.Path))
                                {
                                    _backupEntries.Add(entry);
                                }
                            }
                        }
                    }
                    catch { /* 忽略索引文件解析错误 */ }
                }
            }
            catch { /* 忽略目录读取错误 */ }
        }

        public BackupResult CreateBackup(string name, string description, List<string> includePaths, BackupType type)
        {
            try
            {
                string backupFileName = $"{name.Replace(' ', '_')}_{DateTime.Now.ToString("yyyyMMdd_HHmmss")}.zip";
                string backupPath = Path.Combine(_backupRoot, backupFileName);

                // 创建备份文件
                using (var zipFile = ZipFile.Open(backupPath, ZipArchiveMode.Create))
                {
                    foreach (string path in includePaths)
                    {
                        if (Directory.Exists(path))
                        {
                            // 备份目录
                            foreach (string file in Directory.GetFiles(path, "*.*", SearchOption.AllDirectories))
                            {
                                string relativePath = Path.GetRelativePath(path, file);
                                zipFile.CreateEntryFromFile(file, relativePath);
                            }
                        }
                        else if (File.Exists(path))
                        {
                            // 备份单个文件
                            string fileName = Path.GetFileName(path);
                            zipFile.CreateEntryFromFile(path, fileName);
                        }
                    }
                }

                // 获取备份文件大小
                long size = new FileInfo(backupPath).Length;

                // 创建备份条目
                var backupEntry = new BackupEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Name = name,
                    Description = description,
                    Path = backupPath,
                    Size = size,
                    CreatedAt = DateTime.Now,
                    Type = type
                };

                _backupEntries.Add(backupEntry);
                SaveBackups();

                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "BackupCreated",
                    Message = "备份已创建",
                    Details = $"名称: {name}, 类型: {type}, 大小: {size / (1024 * 1024):F2}MB"
                });

                return new BackupResult
                {
                    Success = true,
                    Message = "备份创建成功",
                    BackupEntry = backupEntry
                };
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "BackupError",
                    Message = "备份创建错误",
                    Details = $"错误: {ex.Message}"
                });

                return new BackupResult
                {
                    Success = false,
                    Message = $"备份创建失败: {ex.Message}"
                };
            }
        }

        public BackupResult RestoreBackup(string backupId, string restorePath)
        {
            try
            {
                var backupEntry = _backupEntries.FirstOrDefault(e => e.Id == backupId);
                if (backupEntry == null)
                {
                    return new BackupResult
                    {
                        Success = false,
                        Message = "备份不存在"
                    };
                }

                if (!File.Exists(backupEntry.Path))
                {
                    return new BackupResult
                    {
                        Success = false,
                        Message = "备份文件不存在"
                    };
                }

                // 创建恢复目录
                Directory.CreateDirectory(restorePath);

                // 解压备份文件
                ZipFile.ExtractToDirectory(backupEntry.Path, restorePath);

                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "BackupRestored",
                    Message = "备份已恢复",
                    Details = $"名称: {backupEntry.Name}, 恢复路径: {restorePath}"
                });

                return new BackupResult
                {
                    Success = true,
                    Message = "备份恢复成功",
                    BackupEntry = backupEntry
                };
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "RestoreError",
                    Message = "备份恢复错误",
                    Details = $"错误: {ex.Message}"
                });

                return new BackupResult
                {
                    Success = false,
                    Message = $"备份恢复失败: {ex.Message}"
                };
            }
        }

        public void DeleteBackup(string backupId)
        {
            var backupEntry = _backupEntries.FirstOrDefault(e => e.Id == backupId);
            if (backupEntry != null)
            {
                try
                {
                    if (File.Exists(backupEntry.Path))
                    {
                        File.Delete(backupEntry.Path);
                    }

                    _backupEntries.Remove(backupEntry);
                    SaveBackups();

                    _dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "BackupDeleted",
                        Message = "备份已删除",
                        Details = $"名称: {backupEntry.Name}"
                    });
                }
                catch (Exception ex)
                {
                    _dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "DeleteBackupError",
                        Message = "备份删除错误",
                        Details = $"名称: {backupEntry.Name}, 错误: {ex.Message}"
                    });
                }
            }
        }

        public List<BackupEntry> GetBackups()
        {
            return _backupEntries;
        }

        public BackupEntry GetBackup(string backupId)
        {
            return _backupEntries.FirstOrDefault(e => e.Id == backupId);
        }

        private void SaveBackups()
        {
            // 模拟保存备份条目到文件
            string backupFile = Path.Combine(_backupRoot, "backups.json");
            // 实际实现中应该序列化备份条目到文件
        }
    }
}