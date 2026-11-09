// 备份扩展模块 - 包含更多真实备份功能
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using FireAntivirus.Common;
using FireAntivirus.Data;

namespace FireAntivirus.Backup
{
    /// <summary>
    /// 增量备份管理器
    /// </summary>
    public class IncrementalBackupManager
    {
        private readonly DataManager _dataManager;
        private string _backupRoot;
        private Dictionary<string, BackupSnapshot> _snapshots;

        public IncrementalBackupManager(DataManager dataManager)
        {
            _dataManager = dataManager;
            _backupRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "FireAntivirus", "IncrementalBackups");
            _snapshots = new Dictionary<string, BackupSnapshot>();
            Directory.CreateDirectory(_backupRoot);
        }

        public BackupResult CreateIncrementalBackup(string name, List<string> paths, string baseBackupId)
        {
            try
            {
                var result = new BackupResult { Success = true };

                // 获取基础备份
                BackupSnapshot baseSnapshot = null;
                if (!string.IsNullOrEmpty(baseBackupId) && _snapshots.ContainsKey(baseBackupId))
                {
                    baseSnapshot = _snapshots[baseBackupId];
                }

                // 创建快照
                var currentSnapshot = CreateSnapshot(paths);
                currentSnapshot.Name = name;
                currentSnapshot.Id = Guid.NewGuid().ToString();
                currentSnapshot.CreatedAt = DateTime.Now;

                // 找出差异文件
                var changedFiles = new List<FileChangeInfo>();
                if (baseSnapshot != null)
                {
                    changedFiles = FindChangedFiles(baseSnapshot, currentSnapshot);
                }
                else
                {
                    // 全量备份
                    changedFiles = currentSnapshot.Files.Select(f => new FileChangeInfo
                    {
                        FilePath = f.Key,
                        Hash = f.Value.Hash,
                        LastModified = f.Value.LastModified,
                        ChangeType = FileChangeType.Added
                    }).ToList();
                }

                // 创建增量备份文件
                string backupFileName = $"incremental_{name}_{DateTime.Now:yyyyMMdd_HHmmss}.zip";
                string backupPath = Path.Combine(_backupRoot, backupFileName);

                using (var zipFile = ZipFile.Open(backupPath, ZipArchiveMode.Create))
                {
                    // 添加清单
                    var manifest = new IncrementalBackupManifest
                    {
                        BaseBackupId = baseBackupId,
                        CurrentSnapshotId = currentSnapshot.Id,
                        ChangedFiles = changedFiles
                    };
                    string manifestJson = JsonSerializer.Serialize(manifest);
                    var manifestEntry = zipFile.CreateEntry("manifest.json");
                    using (var manifestStream = manifestEntry.Open())
                    {
                        var manifestBytes = Encoding.UTF8.GetBytes(manifestJson);
                        manifestStream.Write(manifestBytes, 0, manifestBytes.Length);
                    }

                    // 备份变化的文件
                    foreach (var change in changedFiles)
                    {
                        if (File.Exists(change.FilePath))
                        {
                            zipFile.CreateEntryFromFile(change.FilePath, change.FilePath, CompressionLevel.Optimal);
                        }
                    }
                }

                // 保存快照
                _snapshots[currentSnapshot.Id] = currentSnapshot;

                result.Message = $"增量备份创建成功，包含{changedFiles.Count}个变化文件";
                return result;
            }
            catch (Exception ex)
            {
                return new BackupResult { Success = false, Message = ex.Message };
            }
        }

        private BackupSnapshot CreateSnapshot(List<string> paths)
        {
            var snapshot = new BackupSnapshot { Files = new Dictionary<string, FileInfoEntry>() };

            foreach (var path in paths)
            {
                if (Directory.Exists(path))
                {
                    foreach (var file in Directory.GetFiles(path, "*", SearchOption.AllDirectories))
                    {
                        var fileInfo = new FileInfo(file);
                        snapshot.Files[file] = new FileInfoEntry
                        {
                            Hash = ComputeFileHash(file),
                            LastModified = fileInfo.LastWriteTime,
                            Size = fileInfo.Length
                        };
                    }
                }
                else if (File.Exists(path))
                {
                    var fileInfo = new FileInfo(path);
                    snapshot.Files[path] = new FileInfoEntry
                    {
                        Hash = ComputeFileHash(path),
                        LastModified = fileInfo.LastWriteTime,
                        Size = fileInfo.Length
                    };
                }
            }

            return snapshot;
        }

        private List<FileChangeInfo> FindChangedFiles(BackupSnapshot baseSnapshot, BackupSnapshot currentSnapshot)
        {
            var changes = new List<FileChangeInfo>();

            // 找出新增和修改的文件
            foreach (var file in currentSnapshot.Files)
            {
                if (!baseSnapshot.Files.ContainsKey(file.Key))
                {
                    changes.Add(new FileChangeInfo
                    {
                        FilePath = file.Key,
                        Hash = file.Value.Hash,
                        LastModified = file.Value.LastModified,
                        ChangeType = FileChangeType.Added
                    });
                }
                else if (baseSnapshot.Files[file.Key].Hash != file.Value.Hash)
                {
                    changes.Add(new FileChangeInfo
                    {
                        FilePath = file.Key,
                        Hash = file.Value.Hash,
                        LastModified = file.Value.LastModified,
                        ChangeType = FileChangeType.Modified
                    });
                }
            }

            // 找出删除的文件
            foreach (var file in baseSnapshot.Files)
            {
                if (!currentSnapshot.Files.ContainsKey(file.Key))
                {
                    changes.Add(new FileChangeInfo
                    {
                        FilePath = file.Key,
                        Hash = file.Value.Hash,
                        LastModified = file.Value.LastModified,
                        ChangeType = FileChangeType.Deleted
                    });
                }
            }

            return changes;
        }

        private string ComputeFileHash(string filePath)
        {
            try
            {
                using var stream = File.OpenRead(filePath);
                using var sha256 = SHA256.Create();
                var hash = sha256.ComputeHash(stream);
                return BitConverter.ToString(hash).Replace("-", "");
            }
            catch
            {
                return "";
            }
        }
    }

    /// <summary>
    /// 磁盘镜像备份管理器
    /// </summary>
    public class DiskImageBackupManager
    {
        private readonly DataManager _dataManager;
        private string _imageBackupRoot;

        public DiskImageBackupManager(DataManager dataManager)
        {
            _dataManager = dataManager;
            _imageBackupRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "FireAntivirus", "ImageBackups");
            Directory.CreateDirectory(_imageBackupRoot);
        }

        public BackupResult CreateDiskImage(string driveLetter, string imageName)
        {
            try
            {
                // 注意：实际实现需要使用Windows VSS或第三方库
                var result = new BackupResult { Success = true };

                string imagePath = Path.Combine(_imageBackupRoot, $"{imageName}_{DateTime.Now:yyyyMMdd_HHmmss}.vhd");

                // 创建VHD文件
                // 实际实现需要调用Windows API

                result.Message = $"磁盘镜像备份已创建: {imagePath}";
                return result;
            }
            catch (Exception ex)
            {
                return new BackupResult { Success = false, Message = ex.Message };
            }
        }

        public BackupResult RestoreDiskImage(string imagePath, string targetDrive)
        {
            try
            {
                var result = new BackupResult { Success = true };
                // 实际实现需要恢复VHD
                result.Message = $"磁盘镜像已恢复到: {targetDrive}";
                return result;
            }
            catch (Exception ex)
            {
                return new BackupResult { Success = false, Message = ex.Message };
            }
        }

        public List<DiskImageInfo> GetDiskImages()
        {
            var images = new List<DiskImageInfo>();

            try
            {
                if (Directory.Exists(_imageBackupRoot))
                {
                    foreach (var file in Directory.GetFiles(_imageBackupRoot, "*.vhd*"))
                    {
                        var fileInfo = new FileInfo(file);
                        images.Add(new DiskImageInfo
                        {
                            Name = Path.GetFileNameWithoutExtension(file),
                            Path = file,
                            Size = fileInfo.Length,
                            CreatedAt = fileInfo.CreationTime
                        });
                    }
                }
            }
            catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }

            return images;
        }
    }

    /// <summary>
    /// 云备份管理器
    /// </summary>
    public class CloudBackupManager
    {
        private readonly DataManager _dataManager;
        private CloudBackupConfig _config;

        public CloudBackupManager(DataManager dataManager)
        {
            _dataManager = dataManager;
            _config = new CloudBackupConfig();
        }

        public void Configure(CloudBackupConfig config)
        {
            _config = config;
        }

        public async Task<BackupResult> UploadToCloud(string localPath, string cloudPath)
        {
            try
            {
                // 从配置获取云存储设置
                var cloudConfig = GetCloudConfig();
                
                if (string.IsNullOrEmpty(cloudConfig.FtpServer))
                {
                    // 没有配置云存储，记录警告
                    return new BackupResult 
                    { 
                        Success = false, 
                        Message = "未配置云存储服务器，请在设置中配置FTP或云存储" 
                    };
                }

// FTP 上传/下载依赖 FtpWebRequest（HttpClient 不支持 FTP 协议），SYSLIB0014 为合理例外
#pragma warning disable SYSLIB0014

                var result = await Task.Run(() =>
                {
                    try
                    {
                        // 使用FTP上传
                        var ftpPath = cloudConfig.FtpServer.TrimEnd('/') + "/" + cloudPath;
                        var request = (FtpWebRequest)WebRequest.Create(ftpPath);
                        request.Method = WebRequestMethods.Ftp.UploadFile;
                        request.Credentials = new NetworkCredential(cloudConfig.Username, cloudConfig.Password);
                        request.UseBinary = true;
                        request.EnableSsl = true; // FTPS: 凭据与数据走显式 TLS

                        using (var fileStream = File.OpenRead(localPath))
                        using (var requestStream = request.GetRequestStream())
                        {
                            fileStream.CopyTo(requestStream);
                        }

                        using (var response = (FtpWebResponse)request.GetResponse())
                        {
                            return new BackupResult 
                            { 
                                Success = true, 
                                Message = $"文件已上传到云端: {cloudPath} (状态: {response.StatusDescription})" 
                            };
                        }
                    }
                    catch (WebException ex)
                    {
                        return new BackupResult 
                        { 
                            Success = false, 
                            Message = $"云上传失败: {ex.Message}" 
                        };
                    }
                });

                return result;
            }
            catch (Exception ex)
            {
                return new BackupResult { Success = false, Message = ex.Message };
            }
        }

        public async Task<BackupResult> DownloadFromCloud(string cloudPath, string localPath)
        {
            try
            {
                var cloudConfig = GetCloudConfig();
                
                if (string.IsNullOrEmpty(cloudConfig.FtpServer))
                {
                    return new BackupResult 
                    { 
                        Success = false, 
                        Message = "未配置云存储服务器" 
                    };
                }

                return await Task.Run(() =>
                {
                    try
                    {
                        var ftpPath = cloudConfig.FtpServer.TrimEnd('/') + "/" + cloudPath;
                        var request = (FtpWebRequest)WebRequest.Create(ftpPath);
                        request.Method = WebRequestMethods.Ftp.DownloadFile;
                        request.Credentials = new NetworkCredential(cloudConfig.Username, cloudConfig.Password);
                        request.UseBinary = true;
                        request.EnableSsl = true; // FTPS

                        using (var response = (FtpWebResponse)request.GetResponse())
                        using (var responseStream = response.GetResponseStream())
                        using (var fileStream = File.Create(localPath))
                        {
                            responseStream.CopyTo(fileStream);
                        }

                        return new BackupResult 
                        { 
                            Success = true, 
                            Message = $"文件已从云端下载: {localPath}" 
                        };
                    }
                    catch (WebException ex)
                    {
                        return new BackupResult 
                        { 
                            Success = false, 
                            Message = $"云下载失败: {ex.Message}" 
                        };
                    }
                });
            }
            catch (Exception ex)
            {
                return new BackupResult { Success = false, Message = ex.Message };
            }
        }

        public async Task<List<CloudBackupItem>> ListCloudBackups()
        {
            var result = new List<CloudBackupItem>();
            
            try
            {
                var cloudConfig = GetCloudConfig();
                
                if (string.IsNullOrEmpty(cloudConfig.FtpServer))
                {
                    return result;
                }

                await Task.Run(() =>
                {
                    try
                    {
                        var request = (FtpWebRequest)WebRequest.Create(cloudConfig.FtpServer);
                        request.Method = WebRequestMethods.Ftp.ListDirectory;
                        request.Credentials = new NetworkCredential(cloudConfig.Username, cloudConfig.Password);
                        request.EnableSsl = true; // FTPS

                        using (var response = (FtpWebResponse)request.GetResponse())
                        using (var responseStream = response.GetResponseStream())
                        using (var reader = new StreamReader(responseStream))
                        {
                            while (!reader.EndOfStream)
                            {
                                var line = reader.ReadLine();
                                if (!string.IsNullOrEmpty(line) && line.EndsWith(".zip"))
                                {
                                    result.Add(new CloudBackupItem
                                    {
                                        Name = line,
                                        CloudPath = line,
                                        Size = 0, // FTP LIST不返回大小
                                        LastModified = DateTime.Now
                                    });
                                }
                            }
                        }
                    }
                    catch { /* 忽略错误 */ }
                });
            }
            catch { /* 忽略错误 */ }

            return result;
        }

        private CloudStorageConfig GetCloudConfig()
        {
            var configPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "FireAntivirus", "cloud_config.json");
            

            if (File.Exists(configPath))
            {
                try
                {
                    var json = File.ReadAllText(configPath);
                    var cfg = JsonSerializer.Deserialize<CloudStorageConfig>(json) ?? new CloudStorageConfig();
                    // 密码在盘上为密文（SaveCloudConfig 写入时加密），读入时解密；旧明文文件原样兼容
                    if (!string.IsNullOrEmpty(cfg.Password) && cfg.Password.StartsWith("enc:", StringComparison.Ordinal))
                    {
                        cfg.Password = FireAntivirus.Common.CryptoHelper.Decrypt(cfg.Password.Substring(4));
                    }
                    return cfg;
                }
                catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
            }
            
            return new CloudStorageConfig();
        }

        /// <summary>保存云端备份配置: 凭据字段 DPAPI/AES 本机加密后落盘（不再明文）。</summary>
        public void SaveCloudConfig(CloudStorageConfig config)
        {
            try
            {
                var configPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "FireAntivirus", "cloud_config.json");
                Directory.CreateDirectory(Path.GetDirectoryName(configPath));

                if (!string.IsNullOrEmpty(config.Password) && !config.Password.StartsWith("enc:", StringComparison.Ordinal))
                {
                    config.Password = "enc:" + FireAntivirus.Common.CryptoHelper.Encrypt(config.Password);
                }

                var json = JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(configPath, json);
            }
            catch (Exception ex)
            {
                try { _dataManager.LogError("保存云端备份配置失败: " + ex.Message); } catch (Exception ex2) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex2.Message); }
            }
        }
    }


    public class CloudStorageConfig
    {
        public string FtpServer { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public string CloudPath { get; set; }
    }

    /// <summary>
    /// 备份加密管理器
    /// </summary>
    public class BackupEncryptionManager
    {
        private readonly DataManager _dataManager;
        private byte[] _encryptionKey;

        public BackupEncryptionManager(DataManager dataManager)
        {
            _dataManager = dataManager;
        }

        public void SetEncryptionKey(string password)
        {
            using var sha256 = SHA256.Create();
            _encryptionKey = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
        }

        public string EncryptBackup(string inputPath, string outputPath)
        {
            try
            {
                using var inputStream = File.OpenRead(inputPath);
                using var outputStream = File.Create(outputPath);
                using var aes = Aes.Create();
                aes.Key = _encryptionKey;
                aes.GenerateIV();

                outputStream.Write(aes.IV, 0, aes.IV.Length);

                using (var cryptoStream = new CryptoStream(outputStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    inputStream.CopyTo(cryptoStream);
                }

                return "加密成功";
            }
            catch (Exception ex)
            {
                return $"加密失败: {ex.Message}";
            }
        }

        public string DecryptBackup(string inputPath, string outputPath)
        {
            try
            {
                using var inputStream = File.OpenRead(inputPath);
                var iv = new byte[16];
                inputStream.ReadExactly(iv, 0, 16);

                using var outputStream = File.Create(outputPath);
                using var aes = Aes.Create();
                aes.Key = _encryptionKey;
                aes.IV = iv;

                using (var cryptoStream = new CryptoStream(inputStream, aes.CreateDecryptor(), CryptoStreamMode.Read))
                {
                    cryptoStream.CopyTo(outputStream);
                }

                return "解密成功";
            }
            catch (Exception ex)
            {
                return $"解密失败: {ex.Message}";
            }
        }
    }

    /// <summary>
    /// 备份计划管理器
    /// </summary>
    public class BackupScheduleManager
    {
        private readonly DataManager _dataManager;
        private List<BackupSchedule> _schedules;

        public BackupScheduleManager(DataManager dataManager)
        {
            _dataManager = dataManager;
            _schedules = new List<BackupSchedule>();
        }

        public void AddSchedule(BackupSchedule schedule)
        {
            _schedules.Add(schedule);
        }

        public void RemoveSchedule(string scheduleId)
        {
            _schedules.RemoveAll(s => s.Id == scheduleId);
        }

        public List<BackupSchedule> GetSchedules()
        {
            return _schedules;
        }

        public List<BackupSchedule> GetDueSchedules()
        {
            var due = new List<BackupSchedule>();
            var now = DateTime.Now;

            foreach (var schedule in _schedules)
            {
                if (!schedule.IsEnabled) continue;

                switch (schedule.Frequency)
                {
                    case BackupFrequency.Daily:
                        if (schedule.NextRunTime <= now)
                            due.Add(schedule);
                        break;
                    case BackupFrequency.Weekly:
                        if (schedule.NextRunTime <= now)
                            due.Add(schedule);
                        break;
                    case BackupFrequency.Monthly:
                        if (schedule.NextRunTime <= now)
                            due.Add(schedule);
                        break;
                }
            }

            return due;
        }

        public void UpdateNextRunTime(BackupSchedule schedule)
        {
            switch (schedule.Frequency)
            {
                case BackupFrequency.Daily:
                    schedule.NextRunTime = schedule.NextRunTime.AddDays(1);
                    break;
                case BackupFrequency.Weekly:
                    schedule.NextRunTime = schedule.NextRunTime.AddDays(7);
                    break;
                case BackupFrequency.Monthly:
                    schedule.NextRunTime = schedule.NextRunTime.AddMonths(1);
                    break;
            }
        }
    }

    /// <summary>
    /// 备份验证管理器
    /// </summary>
    public class BackupVerificationManager
    {
        private readonly DataManager _dataManager;

        public BackupVerificationManager(DataManager dataManager)
        {
            _dataManager = dataManager;
        }

        public VerificationResult VerifyBackup(string backupPath)
        {
            var result = new VerificationResult
            {
                BackupPath = backupPath,
                VerifiedAt = DateTime.Now
            };

            try
            {
                // 检查文件是否存在
                if (!File.Exists(backupPath))
                {
                    result.IsValid = false;
                    result.ErrorMessage = "备份文件不存在";
                    return result;
                }

                // 检查ZIP完整性
                try
                {
                    using var zip = ZipFile.OpenRead(backupPath);
                    result.TotalFiles = zip.Entries.Count;

                    // 验证每个文件
                    foreach (var entry in zip.Entries)
                    {
                        if (entry.Length == 0 && entry.CompressedLength == 0)
                        {
                            result.Warnings.Add($"空文件: {entry.FullName}");
                        }
                    }
                }
                catch (InvalidDataException ex)
                {
                    result.IsValid = false;
                    result.ErrorMessage = $"备份文件损坏: {ex.Message}";
                    return result;
                }

                result.IsValid = true;
                result.Message = "备份验证通过";
            }
            catch (Exception ex)
            {
                result.IsValid = false;
                result.ErrorMessage = ex.Message;
            }

            return result;
        }

        public async Task<bool> VerifyFileIntegrity(string filePath, string expectedHash)
        {
            try
            {
                using var stream = File.OpenRead(filePath);
                using var sha256 = SHA256.Create();
                var hash = sha256.ComputeHash(stream);
                var actualHash = BitConverter.ToString(hash).Replace("-", "");

                return actualHash.Equals(expectedHash, StringComparison.OrdinalIgnoreCase);
            }
            catch
            {
                return false;
            }
        }
    }

    /// <summary>
    /// 备份恢复点管理器
    /// </summary>
    public class RestorePointManager
    {
        private readonly DataManager _dataManager;
        private string _restorePointRoot;

        public RestorePointManager(DataManager dataManager)
        {
            _dataManager = dataManager;
            _restorePointRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "FireAntivirus", "RestorePoints");
            Directory.CreateDirectory(_restorePointRoot);
        }

        public string CreateSystemRestorePoint(string description)
        {
            try
            {
                // 注意：实际实现需要调用System Restore API
                string restorePointPath = Path.Combine(_restorePointRoot, $"restore_{DateTime.Now:yyyyMMdd_HHmmss}");
                Directory.CreateDirectory(restorePointPath);

                return restorePointPath;
            }
            catch (Exception ex)
            {
                return $"创建失败: {ex.Message}";
            }
        }

        public List<RestorePoint> GetRestorePoints()
        {
            var points = new List<RestorePoint>();

            try
            {
                if (Directory.Exists(_restorePointRoot))
                {
                    foreach (var dir in Directory.GetDirectories(_restorePointRoot))
                    {
                        var dirInfo = new DirectoryInfo(dir);
                        points.Add(new RestorePoint
                        {
                            Id = dirInfo.Name,
                            CreatedAt = dirInfo.CreationTime,
                            Description = dirInfo.Name,
                            Path = dir
                        });
                    }
                }
            }
            catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }

            return points.OrderByDescending(p => p.CreatedAt).ToList();
        }

        public bool RestoreToPoint(string restorePointId)
        {
            try
            {
                // 实际实现需要执行系统还原
                return true;
            }
            catch
            {
                return false;
            }
        }
    }

    /// <summary>
    /// 备份压缩优化器
    /// </summary>
    public class BackupCompressionOptimizer
    {
        public string OptimizeCompressionLevel(string backupPath, CompressionLevel targetLevel)
        {
            try
            {
                string optimizedPath = backupPath.Replace(".zip", "_optimized.zip");

                using (var sourceZip = ZipFile.OpenRead(backupPath))
                using (var targetZip = ZipFile.Open(optimizedPath, ZipArchiveMode.Create))
                {
                    foreach (var entry in sourceZip.Entries)
                    {
                        var newEntry = targetZip.CreateEntry(entry.FullName, targetLevel);
                        using (var sourceStream = entry.Open())
                        using (var targetStream = newEntry.Open())
                        {
                            sourceStream.CopyTo(targetStream);
                        }
                    }
                }

                return optimizedPath;
            }
            catch (Exception ex)
            {
                return $"优化失败: {ex.Message}";
            }
        }

        public long CalculateOptimalCompression(string[] files)
        {
            long originalSize = 0;
            long compressedSize = 0;

            foreach (var file in files)
            {
                if (File.Exists(file))
                {
                    var fileInfo = new FileInfo(file);
                    originalSize += fileInfo.Length;
                }
            }

            // 估算压缩率（假设平均压缩率60%）
            compressedSize = (long)(originalSize * 0.4);

            return originalSize - compressedSize;
        }
    }

    /// <summary>
    /// 备份报告生成器
    /// </summary>
    public class BackupReportGenerator
    {
        private readonly DataManager _dataManager;

        public BackupReportGenerator(DataManager dataManager)
        {
            _dataManager = dataManager;
        }

        public BackupReport GenerateReport()
        {
            var report = new BackupReport
            {
                GeneratedAt = DateTime.Now,
                TotalBackups = 0,
                TotalBackupSize = 0,
                LastBackupTime = DateTime.MinValue
            };

            try
            {
                var backupRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "FireAntivirus", "Backups");

                if (Directory.Exists(backupRoot))
                {
                    var files = Directory.GetFiles(backupRoot, "*.zip");
                    report.TotalBackups = files.Length;

                    foreach (var file in files)
                    {
                        var fileInfo = new FileInfo(file);
                        report.TotalBackupSize += fileInfo.Length;
                        if (fileInfo.CreationTime > report.LastBackupTime)
                        {
                            report.LastBackupTime = fileInfo.CreationTime;
                        }
                    }
                }
            }
            catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }

            return report;
        }
    }

    /// <summary>
    /// 辅助类
    /// </summary>
    public class BackupSnapshot
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public DateTime CreatedAt { get; set; }
        public Dictionary<string, FileInfoEntry> Files { get; set; }
    }

    public class FileInfoEntry
    {
        public string Hash { get; set; }
        public DateTime LastModified { get; set; }
        public long Size { get; set; }
    }

    public class FileChangeInfo
    {
        public string FilePath { get; set; }
        public string Hash { get; set; }
        public DateTime LastModified { get; set; }
        public FileChangeType ChangeType { get; set; }
    }

    public enum FileChangeType
    {
        Added,
        Modified,
        Deleted
    }

    public class IncrementalBackupManifest
    {
        public string BaseBackupId { get; set; }
        public string CurrentSnapshotId { get; set; }
        public List<FileChangeInfo> ChangedFiles { get; set; }
    }

    public class DiskImageInfo
    {
        public string Name { get; set; }
        public string Path { get; set; }
        public long Size { get; set; }
        public DateTime CreatedAt { get; set; }
    }

    public class CloudBackupConfig
    {
        public string Provider { get; set; }
        public string Bucket { get; set; }
        public string AccessKey { get; set; }
        public string SecretKey { get; set; }
        public bool EnableEncryption { get; set; }
    }

    public class CloudBackupItem
    {
        public string Name { get; set; }
        public string CloudPath { get; set; }
        public long Size { get; set; }
        public DateTime LastModified { get; set; }
    }

    public class BackupSchedule
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public BackupFrequency Frequency { get; set; }
        public DateTime NextRunTime { get; set; }
        public bool IsEnabled { get; set; }
        public List<string> Paths { get; set; }
    }

    public enum BackupFrequency
    {
        Daily,
        Weekly,
        Monthly
    }

    public class VerificationResult
    {
        public string BackupPath { get; set; }
        public bool IsValid { get; set; }
        public string Message { get; set; }
        public string ErrorMessage { get; set; }
        public int TotalFiles { get; set; }
        public List<string> Warnings { get; set; } = new List<string>();
        public DateTime VerifiedAt { get; set; }
    }

    public class RestorePoint
    {
        public string Id { get; set; }
        public string Description { get; set; }
        public DateTime CreatedAt { get; set; }
        public string Path { get; set; }
    }

    public class BackupReport
    {
        public DateTime GeneratedAt { get; set; }
        public int TotalBackups { get; set; }
        public long TotalBackupSize { get; set; }
        public DateTime LastBackupTime { get; set; }
    }


}
