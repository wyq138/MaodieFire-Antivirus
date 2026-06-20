using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using FireAntivirus.Data;
using FireAntivirus.Engine;

namespace FireAntivirus.Services
{
    public class VirusDatabaseManager
    {
        private DataManager dataManager;
        private AntivirusEngine antivirusEngine;
        private bool isUpdating;

        public VirusDatabaseManager(DataManager dataManager, AntivirusEngine antivirusEngine)
        {
            this.dataManager = dataManager;
            this.antivirusEngine = antivirusEngine;
            this.isUpdating = false;
        }

        public bool UpdateVirusDatabase()
        {
            if (isUpdating)
            {
                dataManager.LogWarning("病毒库更新正在进行中");
                return false;
            }

            isUpdating = true;
            bool success = false;

            try
            {
                dataManager.LogInfo("开始更新病毒库");

                // 1. 更新本地病毒库
                success = UpdateLocalDatabase();

                // 2. 尝试更新ClamAV病毒库（如果可用）
                TryUpdateClamAVDatabase();

                // 3. 清理旧的病毒库文件
                CleanupOldDatabase();

                if (success)
                {
                    dataManager.LogInfo("病毒库更新成功");
                }
                else
                {
                    dataManager.LogWarning("病毒库更新失败");
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"病毒库更新异常: {ex.Message}");
            }
            finally
            {
                isUpdating = false;
            }

            return success;
        }

        private bool UpdateLocalDatabase()
        {
            try
            {
                string[] databaseUrls = {
                    // ClamAV官方病毒库（主要源）- 仅下载CVD签名文件
                    "https://database.clamav.net/main.cvd",
                    "https://database.clamav.net/daily.cvd",
                    "https://database.clamav.net/bytecode.cvd",
                    
                    // ClamAV官方备用源
                    "https://clamav.net/downloads/signatures/main.cvd",
                    "https://clamav.net/downloads/signatures/daily.cvd", 
                    "https://clamav.net/downloads/signatures/bytecode.cvd"
                };

                string databasePath = Path.Combine(dataManager.GetDataDirectory(), "Database");
                if (!Directory.Exists(databasePath))
                {
                    Directory.CreateDirectory(databasePath);
                }

                int successCount = 0;
                foreach (string url in databaseUrls)
                {
                    try
                    {
                        string fileName = Path.GetFileName(url);
                        string localPath = Path.Combine(databasePath, fileName);

                        using (WebClient client = new WebClient())
                        {
                            client.Headers.Add("User-Agent", "FireAntivirus/1.0");
                            client.DownloadFile(url, localPath);
                            dataManager.LogInfo($"成功下载病毒库文件: {fileName}");
                            successCount++;
                        }

                        // 验证下载的文件
                        if (File.Exists(localPath) && new FileInfo(localPath).Length > 0)
                        {
                            dataManager.LogInfo($"病毒库文件验证成功: {fileName}");
                        }
                        else
                        {
                            dataManager.LogWarning($"病毒库文件验证失败: {fileName}");
                            File.Delete(localPath);
                        }
                    }
                    catch (Exception ex)
                    {
                        dataManager.LogWarning($"下载病毒库失败 {url}: {ex.Message}");
                        continue;
                    }
                }

                // 即使部分下载失败，只要有至少一个病毒库文件成功下载，就返回成功
                return successCount > 0;
            }
            catch (Exception ex)
            {
                dataManager.LogError($"更新本地病毒库失败: {ex.Message}");
                return false;
            }
        }

        private void TryUpdateClamAVDatabase()
        {
            try
            {
                string freshclamPath = FindFreshclamPath();
                string baseDir = AppDomain.CurrentDomain.BaseDirectory;
                string clamavDir = Path.Combine(baseDir, "ClamAV");
                
                if (!Directory.Exists(clamavDir))
                {
                    clamavDir = Path.GetDirectoryName(freshclamPath) ?? Path.Combine(baseDir, "ClamAV");
                }
                
                string dbPath = Path.Combine(clamavDir, "db");
                if (!Directory.Exists(dbPath))
                {
                    Directory.CreateDirectory(dbPath);
                }

                string configPath = Path.Combine(clamavDir, "freshclam.conf");

                if (!File.Exists(configPath))
                {
                    string config = $"DatabaseDirectory {dbPath}\n" +
                                    "DNSDatabaseInfo current.cvd.clamav.net\n" +
                                    "DatabaseMirror database.clamav.net\n" +
                                    "ConnectTimeout 30\nReceiveTimeout 0\n" +
                                    "TestDatabases yes\nScriptedUpdates yes\nCompressLocalDatabase no\n";
                    File.WriteAllText(configPath, config);
                }

                if (!string.IsNullOrEmpty(freshclamPath) && File.Exists(freshclamPath))
                {
                    ProcessStartInfo psi = new ProcessStartInfo
                    {
                        FileName = freshclamPath,
                        Arguments = $"--config-file=\"{configPath}\"",
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        WorkingDirectory = clamavDir
                    };

                    using (Process process = Process.Start(psi))
                    {
                        string output = process.StandardOutput.ReadToEnd();
                        string error = process.StandardError.ReadToEnd();
                        process.WaitForExit(120000);

                        if (process.ExitCode == 0)
                        {
                            dataManager.LogInfo("ClamAV病毒库更新成功");
                        }
                        else
                        {
                            dataManager.LogWarning($"ClamAV病毒库更新失败: {error}");
                            DownloadClamAVDatabaseDirectly(dbPath);
                        }
                    }
                }
                else
                {
                    DownloadClamAVDatabaseDirectly(dbPath);
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"更新ClamAV病毒库失败: {ex.Message}");
            }
        }

        private void DownloadClamAVDatabaseDirectly(string dbPath)
        {
            try
            {
                if (!Directory.Exists(dbPath))
                {
                    Directory.CreateDirectory(dbPath);
                }

                string[] cvdFiles = { "main.cvd", "daily.cvd", "bytecode.cvd" };
                string[] urls = {
                    "https://database.clamav.net/main.cvd",
                    "https://database.clamav.net/daily.cvd",
                    "https://database.clamav.net/bytecode.cvd",
                };

                for (int i = 0; i < cvdFiles.Length; i++)
                {
                    string localPath = Path.Combine(dbPath, cvdFiles[i]);
                    if (File.Exists(localPath) && new FileInfo(localPath).Length > 0)
                    {
                        var lastWrite = File.GetLastWriteTime(localPath);
                        if ((DateTime.Now - lastWrite).TotalDays < 1)
                        {
                            dataManager.LogInfo($"病毒库文件已是最新: {cvdFiles[i]}");
                            continue;
                        }
                    }

                    try
                    {
                        using (WebClient client = new WebClient())
                        {
                            client.Headers.Add("User-Agent", "FireAntivirus/1.0");
                            client.DownloadFile(urls[i], localPath);
                            if (File.Exists(localPath) && new FileInfo(localPath).Length > 0)
                            {
                                dataManager.LogInfo($"成功下载病毒库文件: {cvdFiles[i]}");
                            }
                            else
                            {
                                dataManager.LogWarning($"病毒库文件下载验证失败: {cvdFiles[i]}");
                                if (File.Exists(localPath)) File.Delete(localPath);
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        dataManager.LogWarning($"下载病毒库文件失败 {cvdFiles[i]}: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"直接下载病毒库失败: {ex.Message}");
            }
        }

        private string FindClamScanPath()
        {
            try
            {
                string[] possiblePaths = {
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "ClamAV", "clamscan.exe"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "ClamAV", "clamscan.exe"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "ClamAV", "clamscan.exe"),
                    Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ClamAV", "clamscan.exe"),
                    "clamscan.exe"
                };

                foreach (string path in possiblePaths)
                {
                    if (File.Exists(path))
                    {
                        return path;
                    }
                }

                return null;
            }
            catch
            {
                return null;
            }
        }

        private string FindFreshclamPath()
        {
            try
            {
                string[] possiblePaths = {
                    Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ClamAV", "freshclam.exe"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "ClamAV", "freshclam.exe"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "ClamAV", "freshclam.exe"),
                    "freshclam.exe"
                };

                foreach (string path in possiblePaths)
                {
                    if (File.Exists(path))
                    {
                        return path;
                    }
                }

                return null;
            }
            catch
            {
                return null;
            }
        }

        private void CleanupOldDatabase()
        {
            try
            {
                string databasePath = Path.Combine(dataManager.GetDataDirectory(), "Database");
                if (!Directory.Exists(databasePath))
                    return;

                string[] oldFiles = Directory.GetFiles(databasePath, "*.old");
                foreach (string oldFile in oldFiles)
                {
                    try
                    {
                        File.Delete(oldFile);
                        dataManager.LogInfo($"已清理旧病毒库文件: {oldFile}");
                    }
                    catch
                    {
                    }
                }

                // 清理超过30天的病毒库文件
                DateTime cutoffDate = DateTime.Now.AddDays(-30);
                string[] allFiles = Directory.GetFiles(databasePath);
                foreach (string file in allFiles)
                {
                    try
                    {
                        FileInfo fileInfo = new FileInfo(file);
                        if (fileInfo.LastWriteTime < cutoffDate)
                        {
                            File.Delete(file);
                            dataManager.LogInfo($"已清理过期病毒库文件: {file}");
                        }
                    }
                    catch
                    {
                    }
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"清理旧病毒库失败: {ex.Message}");
            }
        }

        public bool IsDatabaseUpToDate()
        {
            try
            {
                string databasePath = Path.Combine(dataManager.GetDataDirectory(), "Database");
                if (!Directory.Exists(databasePath))
                    return false;

                string[] requiredFiles = { "main.cvd", "daily.cvd", "bytecode.cvd", "signatures.txt" };
                int validFiles = 0;

                foreach (string file in requiredFiles)
                {
                    string filePath = Path.Combine(databasePath, file);
                    if (File.Exists(filePath))
                    {
                        FileInfo fileInfo = new FileInfo(filePath);
                        if (fileInfo.Length > 0 && fileInfo.LastWriteTime > DateTime.Now.AddDays(-7))
                        {
                            validFiles++;
                        }
                    }
                }

                return validFiles >= 2;
            }
            catch
            {
                return false;
            }
        }

        public long GetDatabaseSize()
        {
            try
            {
                string databasePath = Path.Combine(dataManager.GetDataDirectory(), "Database");
                if (!Directory.Exists(databasePath))
                    return 0;

                long totalSize = 0;
                string[] files = Directory.GetFiles(databasePath, "*.*", SearchOption.AllDirectories);
                foreach (string file in files)
                {
                    try
                    {
                        FileInfo fileInfo = new FileInfo(file);
                        totalSize += fileInfo.Length;
                    }
                    catch
                    {
                    }
                }

                return totalSize;
            }
            catch
            {
                return 0;
            }
        }

        public void VerifyDatabaseIntegrity()
        {
            try
            {
                string databasePath = Path.Combine(dataManager.GetDataDirectory(), "Database");
                if (!Directory.Exists(databasePath))
                    return;

                string[] files = Directory.GetFiles(databasePath);
                foreach (string file in files)
                {
                    try
                    {
                        FileInfo fileInfo = new FileInfo(file);
                        if (fileInfo.Length == 0)
                        {
                            dataManager.LogWarning($"病毒库文件为空: {file}");
                            File.Delete(file);
                        }
                        else
                        {
                            dataManager.LogInfo($"病毒库文件验证成功: {file}, 大小: {fileInfo.Length / (1024 * 1024)} MB");
                        }
                    }
                    catch (Exception ex)
                    {
                        dataManager.LogError($"验证病毒库文件失败 {file}: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"验证病毒库完整性失败: {ex.Message}");
            }
        }

        public void ExportDatabaseInfo()
        {
            try
            {
                string databasePath = Path.Combine(dataManager.GetDataDirectory(), "Database");
                if (!Directory.Exists(databasePath))
                    return;

                string infoPath = Path.Combine(dataManager.GetDataDirectory(), "database_info.json");
                StringBuilder info = new StringBuilder();

                info.AppendLine("{");
                info.AppendLine("  \"timestamp\": \"" + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "\"");
                info.AppendLine("  ,\"files\": [");

                string[] files = Directory.GetFiles(databasePath);
                for (int i = 0; i < files.Length; i++)
                {
                    try
                    {
                        FileInfo fileInfo = new FileInfo(files[i]);
                        info.AppendLine("    {");
                        info.AppendLine("      \"name\": \"" + Path.GetFileName(files[i]) + "\"");
                        info.AppendLine("      ,\"size\": " + fileInfo.Length);
                        info.AppendLine("      ,\"modified\": \"" + fileInfo.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss") + "\"");
                        info.AppendLine("    }" + (i < files.Length - 1 ? "," : ""));
                    }
                    catch
                    {
                    }
                }

                info.AppendLine("  ]");
                info.AppendLine("}");

                File.WriteAllText(infoPath, info.ToString());
                dataManager.LogInfo($"已导出病毒库信息: {infoPath}");
            }
            catch (Exception ex)
            {
                dataManager.LogError($"导出病毒库信息失败: {ex.Message}");
            }
        }

        public void ImportDatabase(string importPath)
        {
            try
            {
                if (!Directory.Exists(importPath))
                {
                    dataManager.LogError($"导入路径不存在: {importPath}");
                    return;
                }

                string databasePath = Path.Combine(dataManager.GetDataDirectory(), "Database");
                if (!Directory.Exists(databasePath))
                {
                    Directory.CreateDirectory(databasePath);
                }

                string[] files = Directory.GetFiles(importPath);
                foreach (string file in files)
                {
                    try
                    {
                        string fileName = Path.GetFileName(file);
                        string destination = Path.Combine(databasePath, fileName);
                        File.Copy(file, destination, true);
                        dataManager.LogInfo($"成功导入病毒库文件: {fileName}");
                    }
                    catch (Exception ex)
                    {
                        dataManager.LogError($"导入病毒库文件失败 {file}: {ex.Message}");
                    }
                }

                dataManager.LogInfo($"病毒库导入完成，共导入 {files.Length} 个文件");
            }
            catch (Exception ex)
            {
                dataManager.LogError($"导入病毒库失败: {ex.Message}");
            }
        }

        public void BackupDatabase()
        {
            try
            {
                string databasePath = Path.Combine(dataManager.GetDataDirectory(), "Database");
                if (!Directory.Exists(databasePath))
                    return;

                string backupPath = Path.Combine(dataManager.GetDataDirectory(), "Backups", "Database", DateTime.Now.ToString("yyyyMMdd_HHmmss"));
                Directory.CreateDirectory(backupPath);

                string[] files = Directory.GetFiles(databasePath);
                foreach (string file in files)
                {
                    try
                    {
                        string fileName = Path.GetFileName(file);
                        string destination = Path.Combine(backupPath, fileName);
                        File.Copy(file, destination);
                        dataManager.LogInfo($"成功备份病毒库文件: {fileName}");
                    }
                    catch (Exception ex)
                    {
                        dataManager.LogError($"备份病毒库文件失败 {file}: {ex.Message}");
                    }
                }

                dataManager.LogInfo($"病毒库备份完成，共备份 {files.Length} 个文件");
            }
            catch (Exception ex)
            {
                dataManager.LogError($"备份病毒库失败: {ex.Message}");
            }
        }

        public void RestoreDatabase(string backupPath)
        {
            try
            {
                if (!Directory.Exists(backupPath))
                {
                    dataManager.LogError($"备份路径不存在: {backupPath}");
                    return;
                }

                string databasePath = Path.Combine(dataManager.GetDataDirectory(), "Database");
                if (!Directory.Exists(databasePath))
                {
                    Directory.CreateDirectory(databasePath);
                }

                string[] files = Directory.GetFiles(backupPath);
                foreach (string file in files)
                {
                    try
                    {
                        string fileName = Path.GetFileName(file);
                        string destination = Path.Combine(databasePath, fileName);
                        File.Copy(file, destination, true);
                        dataManager.LogInfo($"成功恢复病毒库文件: {fileName}");
                    }
                    catch (Exception ex)
                    {
                        dataManager.LogError($"恢复病毒库文件失败 {file}: {ex.Message}");
                    }
                }

                dataManager.LogInfo($"病毒库恢复完成，共恢复 {files.Length} 个文件");
            }
            catch (Exception ex)
            {
                dataManager.LogError($"恢复病毒库失败: {ex.Message}");
            }
        }
    }



    public class OnlineVirusScanner
    {
        private DataManager dataManager;

        public OnlineVirusScanner(DataManager dataManager)
        {
            this.dataManager = dataManager;
        }

        public ScanResult ScanFileOnline(string filePath)
        {
            var result = new ScanResult
            {
                FilePath = filePath,
                IsInfected = false,
                Confidence = 0.0,
                DetectionTime = DateTime.Now
            };

            try
            {
                if (!File.Exists(filePath))
                {
                    dataManager.LogError($"文件不存在: {filePath}");
                    return result;
                }

                // 计算文件哈希
                string fileHash = CalculateFileHash(filePath);
                if (string.IsNullOrEmpty(fileHash))
                {
                    dataManager.LogError($"计算文件哈希失败: {filePath}");
                    return result;
                }

                // 查询在线病毒库
                bool isMalicious = QueryOnlineDatabase(fileHash);
                if (isMalicious)
                {
                    result.IsInfected = true;
                    result.Confidence = 0.9;
                    result.ThreatName = "Online Detection";
                    result.ThreatType = "Virus";
                    result.AdditionalInfo = "Online virus database detection";
                    dataManager.LogWarning($"在线病毒库检测到威胁: {filePath}");
                }
                else
                {
                    result.IsInfected = false;
                    result.Confidence = 0.8;
                    dataManager.LogInfo($"在线病毒库扫描完成，文件安全: {filePath}");
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"在线扫描异常 {filePath}: {ex.Message}");
            }

            return result;
        }

        private string CalculateFileHash(string filePath)
        {
            try
            {
                using (System.Security.Cryptography.MD5 md5 = System.Security.Cryptography.MD5.Create())
                {
                    using (FileStream stream = File.OpenRead(filePath))
                    {
                        byte[] hash = md5.ComputeHash(stream);
                        return BitConverter.ToString(hash).Replace("-", "").ToLower();
                    }
                }
            }
            catch
            {
                return null;
            }
        }

        private bool QueryOnlineDatabase(string fileHash)
        {
            try
            {
                // 实现与多个在线病毒库的API调用
                // 1. VirusTotal API
                if (QueryVirusTotal(fileHash))
                {
                    return true;
                }
                
                // 2. MetaDefender API
                if (QueryMetaDefender(fileHash))
                {
                    return true;
                }
                
                // 3. Hybrid Analysis API
                if (QueryHybridAnalysis(fileHash))
                {
                    return true;
                }
                
                // 4. 本地缓存查询
                if (QueryLocalCache(fileHash))
                {
                    return true;
                }
                
                return false;
            }
            catch
            {
                return false;
            }
        }
        
        private bool QueryVirusTotal(string fileHash)
        {
            try
            {
                // 使用公开API（有限制）或用户配置的API密钥
                string apiKey = GetConfig("virustotal_api_key", "");
                if (string.IsNullOrEmpty(apiKey))
                {
                    dataManager.LogInfo("VirusTotal API密钥未配置，跳过在线查询");
                    return false;
                }
                
                string url = $"https://www.virustotal.com/api/v3/files/{fileHash}";
                
                using (WebClient client = new WebClient())
                {
                    client.Headers.Add("x-apikey", apiKey);
                    client.Headers.Add("User-Agent", "FireAntivirus/1.0");
                    
                    string response = client.DownloadString(url);
                    // 简单的响应解析
                    return response.IndexOf("malicious", StringComparison.OrdinalIgnoreCase) >= 0 &&
                           response.IndexOf("true", StringComparison.OrdinalIgnoreCase) >= 0;
                }
            }
            catch (Exception ex)
            {
                dataManager.LogWarning($"VirusTotal查询失败: {ex.Message}");
                return false;
            }
        }
        
        private bool QueryMetaDefender(string fileHash)
        {
            try
            {
                // 优先使用本地缓存或免费服务
                string apiKey = GetConfig("metadefender_api_key", "");
                if (string.IsNullOrEmpty(apiKey))
                {
                    // 使用免费的文件哈希查询服务（限制使用）
                    return QueryFreeHashService(fileHash, "metadefender");
                }
                
                string url = $"https://api.metadefender.com/v4/hash/{fileHash}";
                
                using (WebClient client = new WebClient())
                {
                    client.Headers.Add("apikey", apiKey);
                    client.Headers.Add("User-Agent", "FireAntivirus/1.0");
                    
                    string response = client.DownloadString(url);
                    // 简单的响应解析
                    return response.IndexOf("threat_found", StringComparison.OrdinalIgnoreCase) >= 0 &&
                           response.IndexOf("true", StringComparison.OrdinalIgnoreCase) >= 0;
                }
            }
            catch (Exception ex)
            {
                dataManager.LogWarning($"MetaDefender查询失败: {ex.Message}");
                return false;
            }
        }
        
        private bool QueryHybridAnalysis(string fileHash)
        {
            try
            {
                string apiKey = GetConfig("hybridanalysis_api_key", "");
                if (string.IsNullOrEmpty(apiKey))
                {
                    dataManager.LogInfo("Hybrid Analysis API密钥未配置，跳过在线查询");
                    return false;
                }
                
                string url = "https://www.hybrid-analysis.com/api/v2/search/hash";
                
                using (WebClient client = new WebClient())
                {
                    client.Headers.Add("api-key", apiKey);
                    client.Headers.Add("User-Agent", "Falcon Sandbox");
                    client.Headers.Add("Content-Type", "application/json");
                    
                    string json = $"{{\"hash\": \"{fileHash}\"}}";
                    string response = client.UploadString(url, json);
                    // 改进响应解析安全
                    return response.IndexOf("verdict", StringComparison.OrdinalIgnoreCase) >= 0 &&
                           response.IndexOf("malicious", StringComparison.OrdinalIgnoreCase) >= 0;
                }
            }
            catch (Exception ex)
            {
                dataManager.LogWarning($"Hybrid Analysis查询失败: {ex.Message}");
                return false;
            }
        }
        
        private bool QueryLocalCache(string fileHash)
        {
            try
            {
                string cachePath = Path.Combine(dataManager.GetDataDirectory(), "Database", "hash_cache.txt");
                if (!File.Exists(cachePath))
                {
                    return false;
                }
                
                string[] lines = File.ReadAllLines(cachePath);
                foreach (string line in lines)
                {
                    string[] parts = line.Split('|');
                    if (parts.Length >= 2 && parts[0].Trim().Equals(fileHash, StringComparison.OrdinalIgnoreCase))
                    {
                        return parts[1].Trim().Equals("malicious", StringComparison.OrdinalIgnoreCase);
                    }
                }
                
                return false;
            }
            catch
            {
                return false;
            }
        }

        private string GetConfig(string key, string defaultValue)
        {
            try
            {
                string configPath = Path.Combine(dataManager.GetDataDirectory(), "config.json");
                if (!File.Exists(configPath))
                    return defaultValue;

                string configContent = File.ReadAllText(configPath);
                // 简单解析JSON（实际项目中应使用JSON解析器）
                int startIndex = configContent.IndexOf($"\"{key}\":");
                if (startIndex >= 0)
                {
                    startIndex += key.Length + 3; // 移动到值位置
                    int endIndex = configContent.IndexOf("\"", startIndex + 1);
                    if (endIndex > startIndex)
                    {
                        return configContent.Substring(startIndex, endIndex - startIndex);
                    }
                }
                return defaultValue;
            }
            catch
            {
                return defaultValue;
            }
        }

        private bool QueryFreeHashService(string fileHash, string serviceName)
        {
            try
            {
                // 使用公开可用的MD5哈希查询服务（有频率限制）
                string url = $"https://md5calc.com/hash/{fileHash}/info.json";
                
                using (WebClient client = new WebClient())
                {
                    client.Headers.Add("User-Agent", "FireAntivirus/1.0");
                    // WebClient does not support Timeout in .NET Core
                    
                    string response = client.DownloadString(url);
                    // 检查是否有已知威胁信息
                    return response.IndexOf("malicious", StringComparison.OrdinalIgnoreCase) >= 0 ||
                           response.IndexOf("threat", StringComparison.OrdinalIgnoreCase) >= 0 ||
                           response.IndexOf("virus", StringComparison.OrdinalIgnoreCase) >= 0;
                }
            }
            catch (Exception ex)
            {
                dataManager.LogInfo($"免费哈希服务查询失败 ({serviceName}): {ex.Message}");
                return false;
            }
        }
        
        private async Task DownloadDatabaseFileAsync(string url, string savePath)
        {
            try
            {
                using (WebClient client = new WebClient())
                {
                    client.Headers.Add("User-Agent", "FireAntivirus Database Updater");
                    await client.DownloadFileTaskAsync(url, savePath);
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"数据库文件下载失败: {ex.Message}");
                throw;
            }
        }
    }
}
