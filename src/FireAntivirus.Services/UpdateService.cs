using System;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace FireAntivirus.Services
{
    public class UpdateService
    {
        private static readonly string[] UpdateServerUrls = new string[]
        {
            "https://update.fireantivirus.com",
            "https://api.fireantivirus.com/update",
            "https://raw.githubusercontent.com/fireantivirus/updates/main"
        };
        
        private const string CurrentVersion = "1.0.2.0";
        private const string UpdateCheckInterval = "24:00:00";

        public static event EventHandler<UpdateAvailableEventArgs> UpdateAvailable;
        public static event EventHandler<UpdateProgressEventArgs> UpdateProgress;
        public static event EventHandler<UpdateCompletedEventArgs> UpdateCompleted;

        public static async Task CheckForUpdatesAsync()
        {
            try
            {
                var latestVersion = await GetLatestVersionAsync();
                if (IsNewerVersion(latestVersion, CurrentVersion))
                {
                    var updateInfo = await GetUpdateInfoAsync(latestVersion);
                    UpdateAvailable?.Invoke(null, new UpdateAvailableEventArgs
                    {
                        Version = latestVersion,
                        UpdateInfo = updateInfo
                    });
                }
            }
            catch (Exception ex)
            {
                // 记录错误但不影响主程序
                Console.WriteLine($"检查更新时出错: {ex.Message}");
            }
        }

        public static async Task DownloadAndInstallUpdateAsync(string version)
        {
            try
            {
                bool downloadSuccess = false;
                string tempPath = Path.Combine(Path.GetTempPath(), "FireAntivirusSetup.exe");
                
                foreach (string serverUrl in UpdateServerUrls)
                {
                    try
                    {
                        var downloadUrl = $"{serverUrl}/updates/{version}/FireAntivirusSetup.exe";
                        var checksumPath = $"{serverUrl}/updates/{version}/checksum.txt";

                        // 下载更新包
                        await DownloadFileAsync(downloadUrl, tempPath);

                        // 验证文件完整性
                        if (await VerifyFileIntegrityAsync(tempPath, checksumPath))
                        {
                            downloadSuccess = true;
                            // 启动安装程序
                            StartInstallation(tempPath);
                            break;
                        }
                    }
                    catch
                    {
                        continue; // 尝试下一个服务器
                    }
                }
                
                if (!downloadSuccess)
                {
                    throw new Exception("所有更新服务器连接失败，无法下载更新包");
                }
            }
            catch (Exception ex)
            {
                UpdateCompleted?.Invoke(null, new UpdateCompletedEventArgs
                {
                    Success = false,
                    ErrorMessage = ex.Message
                });
            }
        }

        // HttpClient 线程安全共享（替代已过时的 WebClient）
        private static readonly System.Net.Http.HttpClient _http = new System.Net.Http.HttpClient
        {
            Timeout = TimeSpan.FromMinutes(10)
        };

        static UpdateService()
        {
            try { _http.DefaultRequestHeaders.Add("User-Agent", "FireAntivirus Update Client"); } catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
        }

        private static async Task<string> GetLatestVersionAsync()
        {
            foreach (string serverUrl in UpdateServerUrls)
            {
                try
                {
                    string version = await _http.GetStringAsync($"{serverUrl}/latest-version.txt");
                    if (!string.IsNullOrWhiteSpace(version))
                    {
                        return version.Trim();
                    }
                }
                catch
                {
                    continue; // 尝试下一个服务器
                }
            }

            // 如果所有服务器都连接失败，返回当前版本
            return CurrentVersion;
        }

        private static async Task<string> GetUpdateInfoAsync(string version)
        {
            foreach (string serverUrl in UpdateServerUrls)
            {
                try
                {
                    string info = await _http.GetStringAsync($"{serverUrl}/updates/{version}/release-notes.txt");
                    if (!string.IsNullOrWhiteSpace(info))
                    {
                        return info;
                    }
                }
                catch
                {
                    continue; // 尝试下一个服务器
                }
            }

            return "有新版本可用";
        }

        private static async Task DownloadFileAsync(string url, string savePath)
        {
            using (var resp = await _http.GetAsync(url, System.Net.Http.HttpCompletionOption.ResponseHeadersRead))
            {
                resp.EnsureSuccessStatusCode();
                long total = resp.Content.Headers.ContentLength ?? -1;
                long received = 0;
                using (var src = await resp.Content.ReadAsStreamAsync())
                using (var dst = File.Create(savePath))
                {
                    var buffer = new byte[81920];
                    int read;
                    while ((read = await src.ReadAsync(buffer, 0, buffer.Length)) > 0)
                    {
                        await dst.WriteAsync(buffer, 0, read);
                        received += read;
                        UpdateProgress?.Invoke(null, new UpdateProgressEventArgs
                        {
                            ProgressPercentage = total > 0 ? (int)(received * 100 / total) : 0,
                            BytesReceived = received,
                            TotalBytesToReceive = total
                        });
                    }
                }
            }
        }

        private static async Task<bool> VerifyFileIntegrityAsync(string filePath, string checksumUrl)
        {
            try
            {
                var expectedChecksum = (await _http.GetStringAsync(checksumUrl)).Trim();

                using (var md5 = MD5.Create())
                {
                    using (var stream = File.OpenRead(filePath))
                    {
                        var hash = md5.ComputeHash(stream);
                        var actualChecksum = BitConverter.ToString(hash).Replace("-", "").ToLower();
                        return actualChecksum == expectedChecksum;
                    }
                }
            }
            catch
            {
                return false;
            }
        }

        private static void StartInstallation(string setupPath)
        {
            try
            {
                System.Diagnostics.Process.Start(setupPath, "/silent /norestart");
                UpdateCompleted?.Invoke(null, new UpdateCompletedEventArgs
                {
                    Success = true
                });
            }
            catch (Exception ex)
            {
                UpdateCompleted?.Invoke(null, new UpdateCompletedEventArgs
                {
                    Success = false,
                    ErrorMessage = ex.Message
                });
            }
        }

        private static bool IsNewerVersion(string latestVersion, string currentVersion)
        {
            try
            {
                var latest = Version.Parse(latestVersion);
                var current = Version.Parse(currentVersion);
                return latest > current;
            }
            catch
            {
                return false;
            }
        }

        public static bool IsAutoUpdateEnabled()
        {
            try
            {
                var configPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "FireAntivirus", "config.json");

                if (File.Exists(configPath))
                {
                    var configContent = File.ReadAllText(configPath);
                    return configContent.Contains("\"autoUpdate\":true") || !configContent.Contains("autoUpdate");
                }
                return true; // 默认启用
            }
            catch
            {
                return true;
            }
        }

        public static TimeSpan GetUpdateCheckInterval()
        {
            try
            {
                return TimeSpan.Parse(UpdateCheckInterval);
            }
            catch
            {
                return TimeSpan.FromHours(24);
            }
        }

        public static bool IsThreatIntelligenceSyncEnabled()
        {
            try
            {
                var configPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "FireAntivirus", "config.json");

                if (File.Exists(configPath))
                {
                    var configContent = File.ReadAllText(configPath);
                    return configContent.Contains("threatIntelligenceSync:true") || !configContent.Contains("threatIntelligenceSync");
                }
                return true; // 默认启用
            }
            catch
            {
                return true;
            }
        }

        public static async Task SyncThreatIntelligenceAsync()
        {
            bool syncSuccess = false;
            string savePath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "FireAntivirus", "threat-intelligence.json");

            // 确保目录存在
            Directory.CreateDirectory(Path.GetDirectoryName(savePath));

            foreach (string serverUrl in UpdateServerUrls)
            {
                try
                {
                    var threatIntelligenceUrl = $"{serverUrl}/threat-intelligence/latest.json";
                    var checksumUrl = $"{serverUrl}/threat-intelligence/latest.checksum";

                    // 下载威胁情报
                    await DownloadFileAsync(threatIntelligenceUrl, savePath);

                    // 验证文件完整性
                    if (await VerifyFileIntegrityAsync(savePath, checksumUrl))
                    {
                        Console.WriteLine($"威胁情报同步成功，来源: {serverUrl}");
                        syncSuccess = true;
                        break;
                    }
                    else
                    {
                        throw new Exception("威胁情报文件完整性验证失败");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"威胁情报同步失败，服务器 {serverUrl}: {ex.Message}");
                    continue; // 尝试下一个服务器
                }
            }

            if (!syncSuccess)
            {
                throw new Exception("所有威胁情报服务器同步失败");
            }
        }

        public static bool IsUpdateAvailable()
        {
            try
            {
                var latestVersion = GetLatestVersion();
                return IsNewerVersion(latestVersion, CurrentVersion);
            }
            catch
            {
                return false;
            }
        }

        public static string GetLatestVersion()
        {
            foreach (string serverUrl in UpdateServerUrls)
            {
                try
                {
                    string version = _http.GetStringAsync($"{serverUrl}/latest-version.txt").GetAwaiter().GetResult().Trim();
                    if (!string.IsNullOrWhiteSpace(version))
                    {
                        return version;
                    }
                }
                catch
                {
                    continue; // 尝试下一个服务器
                }
            }

            return CurrentVersion;
        }

        public static string GetCurrentVersion()
        {
            return CurrentVersion;
        }

        public static async Task DownloadAndInstallUpdateAsync()
        {
            var latestVersion = await GetLatestVersionAsync();
            await DownloadAndInstallUpdateAsync(latestVersion);
        }

        public static async Task DownloadThreatIntelligenceAsync()
        {
            await SyncThreatIntelligenceAsync();
        }
    }

    public class UpdateAvailableEventArgs : EventArgs
    {
        public string Version { get; set; }
        public string UpdateInfo { get; set; }
    }

    public class UpdateProgressEventArgs : EventArgs
    {
        public int ProgressPercentage { get; set; }
        public long BytesReceived { get; set; }
        public long TotalBytesToReceive { get; set; }
    }

    public class UpdateCompletedEventArgs : EventArgs
    {
        public bool Success { get; set; }
        public string ErrorMessage { get; set; }
    }
}
