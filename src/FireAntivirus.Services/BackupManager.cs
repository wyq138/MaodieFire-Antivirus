using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Threading;
using System.IO.Compression;

namespace FireAntivirus.Services
{
    public class BackupManager
    {
        private string _backupStoragePath;
        private bool _enabled;
        private object _backupLock = new object();

        public event EventHandler<BackupEventArgs> BackupEvent;

        public BackupManager(string backupStoragePath = null)
        {
            _backupStoragePath = backupStoragePath ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "FireAntivirus", "Backups");
            _enabled = true;

            InitializeBackupStorage();
        }

        private void InitializeBackupStorage()
        {
            try
            {
                if (!Directory.Exists(_backupStoragePath))
                {
                    Directory.CreateDirectory(_backupStoragePath);
                }
            }
            catch (Exception ex)
            {
                RaiseBackupEvent(new BackupEventArgs(BackupEventType.Error, "Failed to initialize backup storage: " + ex.Message));
            }
        }

        public async Task<BackupResult> CreateBackupAsync(BackupOptions options, CancellationToken cancellationToken = default)
        {
            var result = new BackupResult();
            try
            {
                RaiseBackupEvent(new BackupEventArgs(BackupEventType.BackupStarted, "Starting backup process..."));

                // 生成备份文件名
                string backupId = Guid.NewGuid().ToString();
                string backupFileName = $"backup_{DateTime.Now:yyyyMMdd_HHmmss}_{backupId}.zip";
                string backupFilePath = Path.Combine(_backupStoragePath, backupFileName);

                // 创建备份文件
                using (var archive = ZipFile.Open(backupFilePath, ZipArchiveMode.Create))
                {
                    // 备份用户数据
                    if (options.IncludeDocuments)
                    {
                        await BackupFolderAsync(archive, Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "Documents", cancellationToken);
                    }

                    if (options.IncludePictures)
                    {
                        await BackupFolderAsync(archive, Environment.GetFolderPath(Environment.SpecialFolder.MyPictures), "Pictures", cancellationToken);
                    }

                    if (options.IncludeVideos)
                    {
                        await BackupFolderAsync(archive, Environment.GetFolderPath(Environment.SpecialFolder.MyVideos), "Videos", cancellationToken);
                    }

                    if (options.IncludeDesktop)
                    {
                        await BackupFolderAsync(archive, Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "Desktop", cancellationToken);
                    }

                    if (options.IncludeFavorites)
                    {
                        await BackupFolderAsync(archive, Environment.GetFolderPath(Environment.SpecialFolder.Favorites), "Favorites", cancellationToken);
                    }

                    // 备份自定义文件夹
                    if (options.CustomFolders != null && options.CustomFolders.Count > 0)
                    {
                        foreach (var folder in options.CustomFolders)
                        {
                            if (cancellationToken.IsCancellationRequested) break;
                            if (Directory.Exists(folder))
                            {
                                string folderName = Path.GetFileName(folder);
                                await BackupFolderAsync(archive, folder, $@"Custom\{folderName}", cancellationToken);
                            }
                        }
                    }

                    // 添加备份元数据
                    var metadata = new
                    {
                        BackupId = backupId,
                        BackupDate = DateTime.Now.ToString("o"),
                        Options = options,
                        SystemInfo = new
                        {
                            OSVersion = Environment.OSVersion.ToString(),
                            MachineName = Environment.MachineName,
                            Username = Environment.UserName
                        }
                    };

                    var metadataEntry = archive.CreateEntry("metadata.json");
                    using (var stream = metadataEntry.Open())
                    using (var writer = new StreamWriter(stream))
                    {
                        writer.Write(Newtonsoft.Json.JsonConvert.SerializeObject(metadata, Newtonsoft.Json.Formatting.Indented));
                    }
                }

                // 计算备份文件大小
                var backupFileInfo = new FileInfo(backupFilePath);
                result.BackupSize = backupFileInfo.Length;
                result.BackupPath = backupFilePath;
                result.BackupId = backupId;
                result.Success = true;

                // 如果启用了加密，加密备份文件
                if (options.EnableEncryption && !string.IsNullOrEmpty(options.EncryptionPassword))
                {
                    await EncryptBackupAsync(backupFilePath, options.EncryptionPassword, cancellationToken);
                }

                RaiseBackupEvent(new BackupEventArgs(BackupEventType.BackupCompleted, $"Backup created successfully. Size: {result.BackupSize / (1024 * 1024):F2} MB"));
            }
            catch (Exception ex)
            {
                RaiseBackupEvent(new BackupEventArgs(BackupEventType.Error, "Backup failed: " + ex.Message));
                result.Success = false;
                result.ErrorMessage = ex.Message;
            }

            return result;
        }

        public async Task<RestoreResult> RestoreBackupAsync(string backupPath, string restorePath, string encryptionPassword = null, CancellationToken cancellationToken = default)
        {
            var result = new RestoreResult();
            try
            {
                RaiseBackupEvent(new BackupEventArgs(BackupEventType.RestoreStarted, "Starting restore process..."));

                string tempPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
                Directory.CreateDirectory(tempPath);

                try
                {
                    string workingPath = backupPath;

                    // 如果备份文件被加密，先解密
                    if (!string.IsNullOrEmpty(encryptionPassword) && backupPath.EndsWith(".encrypted"))
                    {
                        workingPath = Path.Combine(tempPath, Path.GetFileNameWithoutExtension(backupPath));
                        await DecryptBackupAsync(backupPath, workingPath, encryptionPassword, cancellationToken);
                    }

                    // 提取备份文件
                    ZipFile.ExtractToDirectory(workingPath, tempPath);

                    // 读取备份元数据
                    string metadataPath = Path.Combine(tempPath, "metadata.json");
                    if (File.Exists(metadataPath))
                    {
                        var metadataContent = File.ReadAllText(metadataPath);
                        var metadata = Newtonsoft.Json.JsonConvert.DeserializeObject<dynamic>(metadataContent);
                        result.BackupId = metadata?.BackupId?.ToString();
                        result.BackupDate = DateTime.Parse(metadata?.BackupDate?.ToString());
                    }

                    // 恢复文件
                    string[] restoreFolders = { "Documents", "Pictures", "Videos", "Desktop", "Favorites", "Custom" };
                    foreach (var folder in restoreFolders)
                    {
                        if (cancellationToken.IsCancellationRequested) break;
                        string sourceFolder = Path.Combine(tempPath, folder);
                        if (Directory.Exists(sourceFolder))
                        {
                            string targetFolder = Path.Combine(restorePath, folder);
                            if (!Directory.Exists(targetFolder))
                            {
                                Directory.CreateDirectory(targetFolder);
                            }
                            await CopyDirectoryAsync(sourceFolder, targetFolder, cancellationToken);
                            result.RestoredFolders.Add(folder);
                        }
                    }

                    result.Success = true;
                    RaiseBackupEvent(new BackupEventArgs(BackupEventType.RestoreCompleted, "Restore completed successfully."));
                }
                finally
                {
                    // 清理临时文件
                    if (Directory.Exists(tempPath))
                    {
                        Directory.Delete(tempPath, true);
                    }
                }
            }
            catch (Exception ex)
            {
                RaiseBackupEvent(new BackupEventArgs(BackupEventType.Error, "Restore failed: " + ex.Message));
                result.Success = false;
                result.ErrorMessage = ex.Message;
            }

            return result;
        }

        public List<BackupInfo> GetBackups()
        {
            var backups = new List<BackupInfo>();
            try
            {
                if (Directory.Exists(_backupStoragePath))
                {
                    var files = Directory.GetFiles(_backupStoragePath, "backup_*.zip*");
                    foreach (var file in files)
                    {
                        try
                        {
                            var fileInfo = new FileInfo(file);
                            var backupInfo = new BackupInfo
                            {
                                BackupPath = file,
                                BackupSize = fileInfo.Length,
                                CreationDate = fileInfo.CreationTime
                            };

                            // 尝试读取备份元数据
                            string tempPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
                            Directory.CreateDirectory(tempPath);
                            
                            try
                            {
                                string workingPath = file;
                                if (file.EndsWith(".encrypted"))
                                {
                                    // 无法读取加密备份的元数据
                                    backupInfo.IsEncrypted = true;
                                }
                                else
                                {
                                    ZipFile.ExtractToDirectory(file, tempPath);
                                    string metadataPath = Path.Combine(tempPath, "metadata.json");
                                    if (File.Exists(metadataPath))
                                    {
                                        var metadataContent = File.ReadAllText(metadataPath);
                                        var metadata = Newtonsoft.Json.JsonConvert.DeserializeObject<dynamic>(metadataContent);
                                        backupInfo.BackupId = metadata?.BackupId?.ToString();
                                        backupInfo.BackupDate = DateTime.Parse(metadata?.BackupDate?.ToString());
                                    }
                                }
                            }
                            catch
                            {
                                // 忽略元数据读取错误
                            }
                            finally
                            {
                                if (Directory.Exists(tempPath))
                                {
                                    Directory.Delete(tempPath, true);
                                }
                            }

                            backups.Add(backupInfo);
                        }
                        catch
                        {
                            // 忽略单个备份文件的错误
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                RaiseBackupEvent(new BackupEventArgs(BackupEventType.Error, "Failed to get backups: " + ex.Message));
            }
            return backups.OrderByDescending(b => b.CreationDate).ToList();
        }

        public bool DeleteBackup(string backupPath)
        {
            try
            {
                if (File.Exists(backupPath))
                {
                    File.Delete(backupPath);
                    RaiseBackupEvent(new BackupEventArgs(BackupEventType.Info, "Backup deleted successfully: " + backupPath));
                    return true;
                }
                return false;
            }
            catch (Exception ex)
            {
                RaiseBackupEvent(new BackupEventArgs(BackupEventType.Error, "Failed to delete backup: " + ex.Message));
                return false;
            }
        }

        public async Task<bool> ScheduleBackupAsync(BackupOptions options, TimeSpan interval, CancellationToken cancellationToken = default)
        {
            try
            {
                RaiseBackupEvent(new BackupEventArgs(BackupEventType.Info, "Scheduling backup task..."));

                // 这里可以添加定时备份任务的逻辑
                // 例如：使用Task.Delay和循环来实现定时备份

                while (!cancellationToken.IsCancellationRequested)
                {
                    await CreateBackupAsync(options, cancellationToken);
                    await Task.Delay(interval, cancellationToken);
                }

                return true;
            }
            catch (Exception ex)
            {
                RaiseBackupEvent(new BackupEventArgs(BackupEventType.Error, "Failed to schedule backup: " + ex.Message));
                return false;
            }
        }

        private async Task BackupFolderAsync(ZipArchive archive, string sourceFolder, string entryPrefix, CancellationToken cancellationToken = default)
        {
            if (!Directory.Exists(sourceFolder))
                return;

            var files = Directory.GetFiles(sourceFolder, "*", SearchOption.AllDirectories);
            foreach (var file in files)
            {
                if (cancellationToken.IsCancellationRequested) break;
                try
                {
                    string relativePath = Path.GetRelativePath(sourceFolder, file);
                    string entryName = Path.Combine(entryPrefix, relativePath);
                    archive.CreateEntryFromFile(file, entryName);
                }
                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "BackupManager.cs 捕获异常", ex.Message); }
            }
        }

        private async Task CopyDirectoryAsync(string sourceDir, string targetDir, CancellationToken cancellationToken = default)
        {
            if (!Directory.Exists(targetDir))
            {
                Directory.CreateDirectory(targetDir);
            }

            var files = Directory.GetFiles(sourceDir);
            foreach (var file in files)
            {
                if (cancellationToken.IsCancellationRequested) break;
                string fileName = Path.GetFileName(file);
                string targetPath = Path.Combine(targetDir, fileName);
                File.Copy(file, targetPath, true);
            }

            var subDirs = Directory.GetDirectories(sourceDir);
            foreach (var subDir in subDirs)
            {
                if (cancellationToken.IsCancellationRequested) break;
                string dirName = Path.GetFileName(subDir);
                string targetSubDir = Path.Combine(targetDir, dirName);
                await CopyDirectoryAsync(subDir, targetSubDir, cancellationToken);
            }
        }

        private async Task EncryptBackupAsync(string inputPath, string password, CancellationToken cancellationToken = default)
        {
            try
            {
                string outputPath = inputPath + ".encrypted";
                using (var inputStream = File.OpenRead(inputPath))
                using (var outputStream = File.Create(outputPath))
                using (var aes = new AesManaged())
                {
                    // 生成密钥和IV
                    var salt = new byte[16];
                    using (var rng = new RNGCryptoServiceProvider())
                    {
                        rng.GetBytes(salt);
                    }
                    outputStream.Write(salt, 0, salt.Length);

                    var key = new Rfc2898DeriveBytes(password, salt, 10000);
                    aes.Key = key.GetBytes(aes.KeySize / 8);
                    aes.IV = key.GetBytes(aes.BlockSize / 8);

                    // 加密
                    using (var cryptoStream = new CryptoStream(outputStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        await inputStream.CopyToAsync(cryptoStream, 4096, cancellationToken);
                    }
                }

                // 删除原文件
                File.Delete(inputPath);
            }
            catch (Exception ex)
            {
                RaiseBackupEvent(new BackupEventArgs(BackupEventType.Error, "Failed to encrypt backup: " + ex.Message));
                throw;
            }
        }

        private async Task DecryptBackupAsync(string inputPath, string outputPath, string password, CancellationToken cancellationToken = default)
        {
            try
            {
                using (var inputStream = File.OpenRead(inputPath))
                using (var outputStream = File.Create(outputPath))
                using (var aes = new AesManaged())
                {
                    // 读取盐值
                    var salt = new byte[16];
                    await inputStream.ReadAsync(salt, 0, salt.Length, cancellationToken);

                    // 生成密钥和IV
                    var key = new Rfc2898DeriveBytes(password, salt, 10000);
                    aes.Key = key.GetBytes(aes.KeySize / 8);
                    aes.IV = key.GetBytes(aes.BlockSize / 8);

                    // 解密
                    using (var cryptoStream = new CryptoStream(inputStream, aes.CreateDecryptor(), CryptoStreamMode.Read))
                    {
                        await cryptoStream.CopyToAsync(outputStream, 4096, cancellationToken);
                    }
                }
            }
            catch (Exception ex)
            {
                RaiseBackupEvent(new BackupEventArgs(BackupEventType.Error, "Failed to decrypt backup: " + ex.Message));
                throw;
            }
        }

        public void Enable()
        {
            _enabled = true;
            RaiseBackupEvent(new BackupEventArgs(BackupEventType.Info, "Backup manager enabled"));
        }

        public void Disable()
        {
            _enabled = false;
            RaiseBackupEvent(new BackupEventArgs(BackupEventType.Info, "Backup manager disabled"));
        }

        public bool IsEnabled()
        {
            return _enabled;
        }

        public void SetBackupStoragePath(string path)
        {
            _backupStoragePath = path;
            InitializeBackupStorage();
        }

        public string GetBackupStoragePath()
        {
            return _backupStoragePath;
        }

        private void RaiseBackupEvent(BackupEventArgs e)
        {
            BackupEvent?.Invoke(this, e);
        }
    }

    public class BackupEventArgs : EventArgs
    {
        public BackupEventType EventType { get; set; }
        public string Message { get; set; }
        public DateTime Timestamp { get; set; }

        public BackupEventArgs(BackupEventType eventType, string message)
        {
            EventType = eventType;
            Message = message;
            Timestamp = DateTime.Now;
        }
    }

    public enum BackupEventType
    {
        Info,
        Warning,
        Error,
        BackupStarted,
        BackupCompleted,
        RestoreStarted,
        RestoreCompleted,
        BackupDeleted,
        BackupScheduled
    }
}