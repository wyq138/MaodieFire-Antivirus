using FireAntivirus.Common;
using FireAntivirus.Data;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;

namespace FireAntivirus.Services
{
    public class BackupRestore
    {
        private readonly string _backupDirectory;
        private readonly string _tempDirectory;
        private readonly int _maxBackups;
        private readonly int _backupTimeoutMs;
        private readonly FireAntivirus.Data.DataManager _dataManager;

        public BackupRestore(FireAntivirus.Data.DataManager dataManager, string? backupDirectory = null, string? tempDirectory = null, int maxBackups = 10, int backupTimeoutMs = 300000) // 5 minutes
        {
            _dataManager = dataManager;
            _backupDirectory = backupDirectory ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "FireAntivirus", "Backups");
            _tempDirectory = tempDirectory ?? Path.GetTempPath();
            _maxBackups = maxBackups;
            _backupTimeoutMs = backupTimeoutMs;

            if (!Directory.Exists(_backupDirectory))
            {
                Directory.CreateDirectory(_backupDirectory);
            }
        }

        public async Task<BackupResult> CreateBackupAsync(BackupOptions options)
        {
            var result = new BackupResult
            {
                BackupId = Guid.NewGuid().ToString(),
                StartTime = DateTime.UtcNow,
                Options = options
            };

            try
            {
                var backupPath = Path.Combine(_backupDirectory, $"backup_{result.BackupId}");
                Directory.CreateDirectory(backupPath);

                if (options.IncludeConfiguration)
                {
                    await BackupConfigurationAsync(backupPath, result);
                }

                if (options.IncludeDefinitions)
                {
                    await BackupDefinitionsAsync(backupPath, result);
                }

                if (options.IncludeLogs)
                {
                    await BackupLogsAsync(backupPath, result);
                }

                if (options.IncludeQuarantine)
                {
                    await BackupQuarantineAsync(backupPath, result);
                }

                if (options.IncludeSystemSettings)
                {
                    await BackupSystemSettingsAsync(backupPath, result);
                }

                // 创建备份元数据
                await CreateBackupMetadataAsync(backupPath, result);

                // 清理旧备份
                await CleanupOldBackupsAsync();

                result.Success = true;
                result.Message = "Backup created successfully";
                result.BackupPath = backupPath;
                result.BackupSize = CalculateDirectorySize(backupPath);
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new FireAntivirus.Data.LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "BackupError",
                    Message = "创建备份失败",
                    Details = ex.Message
                });
                result.Success = false;
                result.ErrorMessage = ex.Message;
            }
            finally
            {
                result.EndTime = DateTime.UtcNow;
                result.Duration = result.EndTime - result.StartTime;
            }

            return result;
        }

        public async Task<RestoreResult> RestoreBackupAsync(string backupId, RestoreOptions options)
        {
            var result = new RestoreResult
            {
                BackupId = backupId,
                StartTime = DateTime.UtcNow,
                Options = options
            };

            try
            {
                var backupPath = Path.Combine(_backupDirectory, $"backup_{backupId}");
                if (!Directory.Exists(backupPath))
                {
                    result.Success = false;
                    result.ErrorMessage = "Backup not found";
                    return result;
                }

                // 读取备份元数据
                var metadata = await ReadBackupMetadataAsync(backupPath);
                result.BackupMetadata = metadata;

                if (options.RestoreConfiguration)
                {
                    await RestoreConfigurationAsync(backupPath, result);
                }

                if (options.RestoreDefinitions)
                {
                    await RestoreDefinitionsAsync(backupPath, result);
                }

                if (options.RestoreLogs)
                {
                    await RestoreLogsAsync(backupPath, result);
                }

                if (options.RestoreQuarantine)
                {
                    await RestoreQuarantineAsync(backupPath, result);
                }

                if (options.RestoreSystemSettings)
                {
                    await RestoreSystemSettingsAsync(backupPath, result);
                }

                result.Success = true;
                result.Message = "Backup restored successfully";
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new FireAntivirus.Data.LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "RestoreError",
                    Message = "恢复备份失败",
                    Details = ex.Message
                });
                result.Success = false;
                result.ErrorMessage = ex.Message;
            }
            finally
            {
                result.EndTime = DateTime.UtcNow;
                result.Duration = result.EndTime - result.StartTime;
            }

            return result;
        }

        public async Task<BackupInfoResult> GetBackupInfoAsync(string backupId)
        {
            var result = new BackupInfoResult
            {
                BackupId = backupId
            };

            try
            {
                var backupPath = Path.Combine(_backupDirectory, $"backup_{backupId}");
                if (!Directory.Exists(backupPath))
                {
                    result.Success = false;
                    result.ErrorMessage = "Backup not found";
                    return result;
                }

                // 读取备份元数据
                var metadata = await ReadBackupMetadataAsync(backupPath);
                result.Metadata = metadata ?? new BackupMetadata();

                // 计算备份大小
                result.BackupSize = CalculateDirectorySize(backupPath);

                // 检查备份内容
                result.ContainsConfiguration = File.Exists(Path.Combine(backupPath, "configuration.zip"));
                result.ContainsDefinitions = File.Exists(Path.Combine(backupPath, "definitions.zip"));
                result.ContainsLogs = File.Exists(Path.Combine(backupPath, "logs.zip"));
                result.ContainsQuarantine = File.Exists(Path.Combine(backupPath, "quarantine.zip"));
                result.ContainsSystemSettings = File.Exists(Path.Combine(backupPath, "systemsettings.zip"));

                result.Success = true;
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new FireAntivirus.Data.LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "BackupError",
                    Message = "获取备份信息失败",
                    Details = $"Get backup info error: {ex.Message}"
                });
                result.Success = false;
                result.ErrorMessage = ex.Message;
            }

            return result;
        }

        public async Task<List<BackupInfo>> GetAllBackupsAsync()
        {
            var backups = new List<BackupInfo>();

            try
            {
                var backupDirectories = Directory.GetDirectories(_backupDirectory, "backup_*");
                foreach (var backupDir in backupDirectories)
                {
                    var backupId = Path.GetFileName(backupDir).Replace("backup_", "");
                    var infoResult = await GetBackupInfoAsync(backupId);
                    if (infoResult.Success && infoResult.Metadata != null)
                    {
                        backups.Add(new BackupInfo
                        {
                            BackupId = backupId,
                            BackupPath = backupDir,
                            BackupSize = infoResult.BackupSize,
                            CreationTime = infoResult.Metadata.CreationTime,
                            ContainsConfiguration = infoResult.ContainsConfiguration,
                            ContainsDefinitions = infoResult.ContainsDefinitions,
                            ContainsLogs = infoResult.ContainsLogs,
                            ContainsQuarantine = infoResult.ContainsQuarantine,
                            ContainsSystemSettings = infoResult.ContainsSystemSettings,
                            Description = infoResult.Metadata.Description
                        });
                    }
                }

                // 按创建时间排序
                backups = backups.OrderByDescending(b => b.CreationTime).ToList();
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new FireAntivirus.Data.LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "BackupError",
                    Message = "获取所有备份失败",
                    Details = $"Get all backups error: {ex.Message}"
                });
            }

            return backups;
        }

        public async Task<DeleteBackupResult> DeleteBackupAsync(string backupId)
        {
            var result = new DeleteBackupResult
            {
                BackupId = backupId,
                StartTime = DateTime.UtcNow
            };

            try
            {
                var backupPath = Path.Combine(_backupDirectory, $"backup_{backupId}");
                if (!Directory.Exists(backupPath))
                {
                    result.Success = false;
                    result.ErrorMessage = "Backup not found";
                    return result;
                }

                Directory.Delete(backupPath, true);
                result.Success = true;
                result.Message = "Backup deleted successfully";
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new FireAntivirus.Data.LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "BackupError",
                    Message = "删除备份失败",
                    Details = $"Delete backup error: {ex.Message}"
                });
                result.Success = false;
                result.ErrorMessage = ex.Message;
            }
            finally
            {
                result.EndTime = DateTime.UtcNow;
                result.Duration = result.EndTime - result.StartTime;
            }

            return result;
        }

        public async Task<BackupValidationResult> ValidateBackupAsync(string backupId)
        {
            var result = new BackupValidationResult
            {
                BackupId = backupId,
                StartTime = DateTime.UtcNow
            };

            try
            {
                var backupPath = Path.Combine(_backupDirectory, $"backup_{backupId}");
                if (!Directory.Exists(backupPath))
                {
                    result.Success = false;
                    result.ErrorMessage = "Backup not found";
                    return result;
                }

                // 检查备份元数据
                var metadata = await ReadBackupMetadataAsync(backupPath);
                if (metadata == null)
                {
                    result.Success = false;
                    result.ErrorMessage = "Invalid backup metadata";
                    return result;
                }

                // 检查备份文件完整性
                var requiredFiles = new List<string>
                {
                    "metadata.json"
                };

                if (metadata.IncludeConfiguration)
                {
                    requiredFiles.Add("configuration.zip");
                }
                if (metadata.IncludeDefinitions)
                {
                    requiredFiles.Add("definitions.zip");
                }
                if (metadata.IncludeLogs)
                {
                    requiredFiles.Add("logs.zip");
                }
                if (metadata.IncludeQuarantine)
                {
                    requiredFiles.Add("quarantine.zip");
                }
                if (metadata.IncludeSystemSettings)
                {
                    requiredFiles.Add("systemsettings.zip");
                }

                var missingFiles = new List<string>();
                foreach (var file in requiredFiles)
                {
                    if (!File.Exists(Path.Combine(backupPath, file)))
                    {
                        missingFiles.Add(file);
                    }
                }

                if (missingFiles.Any())
                {
                    result.Success = false;
                    result.ErrorMessage = $"Missing files: {string.Join(", ", missingFiles)}";
                    result.MissingFiles = missingFiles;
                }
                else
                {
                    result.Success = true;
                    result.Message = "Backup validation successful";
                }
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new FireAntivirus.Data.LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "BackupError",
                    Message = "验证备份失败",
                    Details = $"Backup validation error: {ex.Message}"
                });
                result.Success = false;
                result.ErrorMessage = ex.Message;
            }
            finally
            {
                result.EndTime = DateTime.UtcNow;
                result.Duration = result.EndTime - result.StartTime;
            }

            return result;
        }

        private async Task BackupConfigurationAsync(string backupPath, BackupResult result)
        {
            try
            {
                var configPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "FireAntivirus", "Configuration");
                var backupFilePath = Path.Combine(backupPath, "configuration.zip");
                
                if (Directory.Exists(configPath))
                {
                    await Task.Run(() => ZipFile.CreateFromDirectory(configPath, backupFilePath, CompressionLevel.Optimal, false));
                    result.BackupItems.Add($"Configuration: {configPath}");
                }
                else
                {
                    // 创建空备份文件表示没有配置
                    ZipFile.CreateFromDirectory(Directory.CreateDirectory(Path.Combine(backupPath, "empty_config")).FullName, backupFilePath);
                    result.BackupItems.Add($"Configuration: (empty)");
                }
                
                _dataManager.AddLog(new FireAntivirus.Data.LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "BackupInfo",
                    Message = "配置备份成功",
                    Details = "Configuration backed up successfully"
                });
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new FireAntivirus.Data.LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "BackupError",
                    Message = "备份配置失败",
                    Details = $"Configuration backup error: {ex.Message}"
                });
                result.Warnings.Add($"Failed to backup configuration: {ex.Message}");
            }
        }

        private async Task BackupDefinitionsAsync(string backupPath, BackupResult result)
        {
            try
            {
                var definitionsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "FireAntivirus", "Definitions");
                var backupFilePath = Path.Combine(backupPath, "definitions.zip");
                
                if (Directory.Exists(definitionsPath))
                {
                    await Task.Run(() => ZipFile.CreateFromDirectory(definitionsPath, backupFilePath, CompressionLevel.Optimal, false));
                    result.BackupItems.Add($"Definitions: {definitionsPath}");
                }
                else
                {
                    ZipFile.CreateFromDirectory(Directory.CreateDirectory(Path.Combine(backupPath, "empty_defs")).FullName, backupFilePath);
                    result.BackupItems.Add($"Definitions: (empty)");
                }
                
                _dataManager.AddLog(new FireAntivirus.Data.LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "BackupInfo",
                    Message = "定义备份成功",
                    Details = "Definitions backed up successfully"
                });
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new FireAntivirus.Data.LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "BackupError",
                    Message = "备份定义失败",
                    Details = $"Definitions backup error: {ex.Message}"
                });
                result.Warnings.Add($"Failed to backup definitions: {ex.Message}");
            }
        }

        private async Task BackupLogsAsync(string backupPath, BackupResult result)
        {
            try
            {
                var logsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "FireAntivirus", "Logs");
                var backupFilePath = Path.Combine(backupPath, "logs.zip");
                
                if (Directory.Exists(logsPath))
                {
                    await Task.Run(() => ZipFile.CreateFromDirectory(logsPath, backupFilePath, CompressionLevel.Optimal, false));
                    result.BackupItems.Add($"Logs: {logsPath}");
                }
                else
                {
                    ZipFile.CreateFromDirectory(Directory.CreateDirectory(Path.Combine(backupPath, "empty_logs")).FullName, backupFilePath);
                    result.BackupItems.Add($"Logs: (empty)");
                }
                
                _dataManager.AddLog(new FireAntivirus.Data.LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "BackupInfo",
                    Message = "日志备份成功",
                    Details = "Logs backed up successfully"
                });
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new FireAntivirus.Data.LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "BackupError",
                    Message = "备份日志失败",
                    Details = $"Logs backup error: {ex.Message}"
                });
                result.Warnings.Add($"Failed to backup logs: {ex.Message}");
            }
        }

        private async Task BackupQuarantineAsync(string backupPath, BackupResult result)
        {
            try
            {
                var quarantinePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "FireAntivirus", "Quarantine");
                var backupFilePath = Path.Combine(backupPath, "quarantine.zip");
                
                if (Directory.Exists(quarantinePath))
                {
                    await Task.Run(() => ZipFile.CreateFromDirectory(quarantinePath, backupFilePath, CompressionLevel.Optimal, false));
                    result.BackupItems.Add($"Quarantine: {quarantinePath}");
                }
                else
                {
                    ZipFile.CreateFromDirectory(Directory.CreateDirectory(Path.Combine(backupPath, "empty_quar")).FullName, backupFilePath);
                    result.BackupItems.Add($"Quarantine: (empty)");
                }
                
                _dataManager.AddLog(new FireAntivirus.Data.LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "BackupInfo",
                    Message = "隔离区备份成功",
                    Details = "Quarantine backed up successfully"
                });
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new FireAntivirus.Data.LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "BackupError",
                    Message = "备份隔离区失败",
                    Details = $"Quarantine backup error: {ex.Message}"
                });
                result.Warnings.Add($"Failed to backup quarantine: {ex.Message}");
            }
        }

        private async Task BackupSystemSettingsAsync(string backupPath, BackupResult result)
        {
            try
            {
                var systemSettingsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "FireAntivirus", "SystemSettings");
                var backupFilePath = Path.Combine(backupPath, "systemsettings.zip");
                
                if (Directory.Exists(systemSettingsPath))
                {
                    await Task.Run(() => ZipFile.CreateFromDirectory(systemSettingsPath, backupFilePath, CompressionLevel.Optimal, false));
                    result.BackupItems.Add($"System Settings: {systemSettingsPath}");
                }
                else
                {
                    ZipFile.CreateFromDirectory(Directory.CreateDirectory(Path.Combine(backupPath, "empty_sys")).FullName, backupFilePath);
                    result.BackupItems.Add($"System Settings: (empty)");
                }
                
                _dataManager.AddLog(new FireAntivirus.Data.LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "BackupInfo",
                    Message = "系统设置备份成功",
                    Details = "System settings backed up successfully"
                });
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new FireAntivirus.Data.LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "BackupError",
                    Message = "备份系统设置失败",
                    Details = $"System settings backup error: {ex.Message}"
                });
                result.Warnings.Add($"Failed to backup system settings: {ex.Message}");
            }
        }

        private async Task CreateBackupMetadataAsync(string backupPath, BackupResult result)
        {
            try
            {
                var metadata = new BackupMetadata
                {
                    BackupId = result.BackupId,
                    CreationTime = DateTime.UtcNow,
                    Description = result.Options.Description,
                    IncludeConfiguration = result.Options.IncludeConfiguration,
                    IncludeDefinitions = result.Options.IncludeDefinitions,
                    IncludeLogs = result.Options.IncludeLogs,
                    IncludeQuarantine = result.Options.IncludeQuarantine,
                    IncludeSystemSettings = result.Options.IncludeSystemSettings,
                    BackupSize = result.BackupSize,
                    Duration = result.Duration
                };

                var metadataPath = Path.Combine(backupPath, "metadata.json");
                var json = JsonSerializer.Serialize(metadata, new JsonSerializerOptions { WriteIndented = true });
                await File.WriteAllTextAsync(metadataPath, json);
                
                result.Metadata = metadata;
                _dataManager.AddLog(new FireAntivirus.Data.LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "BackupInfo",
                    Message = "备份元数据创建成功",
                    Details = "Backup metadata created successfully"
                });
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new FireAntivirus.Data.LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "BackupError",
                    Message = "创建备份元数据失败",
                    Details = $"Create backup metadata error: {ex.Message}"
                });
                result.Warnings.Add($"Failed to create backup metadata: {ex.Message}");
            }
        }

        private async Task<BackupMetadata?> ReadBackupMetadataAsync(string backupPath)
        {
            try
            {
                var metadataPath = Path.Combine(backupPath, "metadata.json");
                if (!File.Exists(metadataPath))
                {
                    return null;
                }

                var json = await File.ReadAllTextAsync(metadataPath);
                return JsonSerializer.Deserialize<BackupMetadata>(json);
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new FireAntivirus.Data.LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "BackupError",
                    Message = "读取备份元数据失败",
                    Details = $"Read backup metadata error: {ex.Message}"
                });
                return null;
            }
        }

        private async Task RestoreConfigurationAsync(string backupPath, RestoreResult result)
        {
            try
            {
                var configPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "FireAntivirus", "Configuration");
                var backupFilePath = Path.Combine(backupPath, "configuration.zip");
                
                if (File.Exists(backupFilePath))
                {
                    if (Directory.Exists(configPath))
                        Directory.Delete(configPath, true);
                    Directory.CreateDirectory(configPath);
                    
                    await Task.Run(() => ZipFile.ExtractToDirectory(backupFilePath, configPath));
                    result.RestoredItems.Add($"Configuration: {configPath}");
                }
                
                _dataManager.AddLog(new FireAntivirus.Data.LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "BackupInfo",
                    Message = "配置恢复成功",
                    Details = "Configuration restored successfully"
                });
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new FireAntivirus.Data.LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "BackupError",
                    Message = "恢复配置失败",
                    Details = $"Configuration restore error: {ex.Message}"
                });
                result.Warnings.Add($"Failed to restore configuration: {ex.Message}");
            }
        }

        private async Task RestoreDefinitionsAsync(string backupPath, RestoreResult result)
        {
            try
            {
                var definitionsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "FireAntivirus", "Definitions");
                var backupFilePath = Path.Combine(backupPath, "definitions.zip");
                
                if (File.Exists(backupFilePath))
                {
                    if (Directory.Exists(definitionsPath))
                        Directory.Delete(definitionsPath, true);
                    Directory.CreateDirectory(definitionsPath);
                    
                    await Task.Run(() => ZipFile.ExtractToDirectory(backupFilePath, definitionsPath));
                    result.RestoredItems.Add($"Definitions: {definitionsPath}");
                }
                
                _dataManager.AddLog(new FireAntivirus.Data.LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "BackupInfo",
                    Message = "定义恢复成功",
                    Details = "Definitions restored successfully"
                });
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new FireAntivirus.Data.LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "BackupError",
                    Message = "恢复定义失败",
                    Details = $"Definitions restore error: {ex.Message}"
                });
                result.Warnings.Add($"Failed to restore definitions: {ex.Message}");
            }
        }

        private async Task RestoreLogsAsync(string backupPath, RestoreResult result)
        {
            try
            {
                var logsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "FireAntivirus", "Logs");
                var backupFilePath = Path.Combine(backupPath, "logs.zip");
                
                if (File.Exists(backupFilePath))
                {
                    if (Directory.Exists(logsPath))
                        Directory.Delete(logsPath, true);
                    Directory.CreateDirectory(logsPath);
                    
                    await Task.Run(() => ZipFile.ExtractToDirectory(backupFilePath, logsPath));
                    result.RestoredItems.Add($"Logs: {logsPath}");
                }
                
                _dataManager.AddLog(new FireAntivirus.Data.LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "BackupInfo",
                    Message = "日志恢复成功",
                    Details = "Logs restored successfully"
                });
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new FireAntivirus.Data.LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "BackupError",
                    Message = "恢复日志失败",
                    Details = $"Logs restore error: {ex.Message}"
                });
                result.Warnings.Add($"Failed to restore logs: {ex.Message}");
            }
        }

        private async Task RestoreQuarantineAsync(string backupPath, RestoreResult result)
        {
            try
            {
                var quarantinePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "FireAntivirus", "Quarantine");
                var backupFilePath = Path.Combine(backupPath, "quarantine.zip");
                
                if (File.Exists(backupFilePath))
                {
                    if (Directory.Exists(quarantinePath))
                        Directory.Delete(quarantinePath, true);
                    Directory.CreateDirectory(quarantinePath);
                    
                    await Task.Run(() => ZipFile.ExtractToDirectory(backupFilePath, quarantinePath));
                    result.RestoredItems.Add($"Quarantine: {quarantinePath}");
                }
                
                _dataManager.AddLog(new FireAntivirus.Data.LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "BackupInfo",
                    Message = "隔离区恢复成功",
                    Details = "Quarantine restored successfully"
                });
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new FireAntivirus.Data.LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "BackupError",
                    Message = "恢复隔离区失败",
                    Details = $"Quarantine restore error: {ex.Message}"
                });
                result.Warnings.Add($"Failed to restore quarantine: {ex.Message}");
            }
        }

        private async Task RestoreSystemSettingsAsync(string backupPath, RestoreResult result)
        {
            try
            {
                var systemSettingsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "FireAntivirus", "SystemSettings");
                var backupFilePath = Path.Combine(backupPath, "systemsettings.zip");
                
                if (File.Exists(backupFilePath))
                {
                    if (Directory.Exists(systemSettingsPath))
                        Directory.Delete(systemSettingsPath, true);
                    Directory.CreateDirectory(systemSettingsPath);
                    
                    await Task.Run(() => ZipFile.ExtractToDirectory(backupFilePath, systemSettingsPath));
                    result.RestoredItems.Add($"System Settings: {systemSettingsPath}");
                }
                
                _dataManager.AddLog(new FireAntivirus.Data.LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "BackupInfo",
                    Message = "系统设置恢复成功",
                    Details = "System settings restored successfully"
                });
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new FireAntivirus.Data.LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "BackupError",
                    Message = "恢复系统设置失败",
                    Details = $"System settings restore error: {ex.Message}"
                });
                result.Warnings.Add($"Failed to restore system settings: {ex.Message}");
            }
        }

        private async Task CleanupOldBackupsAsync()
        {
            try
            {
                var backups = await GetAllBackupsAsync();
                if (backups.Count > _maxBackups)
                {
                    var backupsToDelete = backups.OrderBy(b => b.CreationTime).Take(backups.Count - _maxBackups).ToList();
                    foreach (var backup in backupsToDelete)
                    {
                        await DeleteBackupAsync(backup.BackupId);
                    }
                }
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new FireAntivirus.Data.LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "BackupError",
                    Message = "清理旧备份失败",
                    Details = $"Cleanup old backups error: {ex.Message}"
                });
            }
        }

        private long CalculateDirectorySize(string path)
        {
            try
            {
                var directory = new DirectoryInfo(path);
                return directory.EnumerateFiles("*.*", SearchOption.AllDirectories).Sum(file => file.Length);
            }
            catch
            {
                return 0;
            }
        }
    }
}
