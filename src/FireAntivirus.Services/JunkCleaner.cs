using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using FireAntivirus.Data;
using FireAntivirus.Engine;

namespace FireAntivirus.Services
{
    public class JunkCleaner
    {
        private DataManager dataManager;
        private AntivirusEngine antivirusEngine;

        public JunkCleaner(DataManager dataManager, AntivirusEngine antivirusEngine)
        {
            this.dataManager = dataManager;
            this.antivirusEngine = antivirusEngine;
        }

        public List<JunkItem> ScanJunkFiles()
        {
            List<JunkItem> junkItems = new List<JunkItem>();

            try
            {
                junkItems.AddRange(ScanTemporaryFiles());
                junkItems.AddRange(ScanBrowserCache());
                junkItems.AddRange(ScanRecycleBin());
                junkItems.AddRange(ScanWindowsCache());
                junkItems.AddRange(ScanApplicationCache());
                junkItems.AddRange(ScanWindowsUpdateCache());
                junkItems.AddRange(ScanPrefetchFiles());
                junkItems.AddRange(ScanLogFiles());
                junkItems.AddRange(ScanThumbnailCache());
                junkItems.AddRange(ScanOldFiles());

                dataManager.LogInfo($"垃圾文件扫描完成，发现 {junkItems.Count} 个垃圾文件");
            }
            catch (Exception ex)
            {
                dataManager.LogError($"垃圾文件扫描失败: {ex.Message}");
            }

            return junkItems;
        }

        private List<JunkItem> ScanTemporaryFiles()
        {
            List<JunkItem> items = new List<JunkItem>();

            try
            {
                string[] tempPaths = {
                    Path.GetTempPath(),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "AppData", "Local", "Temp")
                };

                foreach (string tempPath in tempPaths)
                {
                    if (Directory.Exists(tempPath))
                    {
                        ScanDirectory(tempPath, items, "临时文件", JunkType.TemporaryFiles);
                    }
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"扫描临时文件失败: {ex.Message}");
            }

            return items;
        }

        private List<JunkItem> ScanBrowserCache()
        {
            List<JunkItem> items = new List<JunkItem>();

            try
            {
                string[] browserCachePaths = {
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Google", "Chrome", "User Data", "Default", "Cache"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Google", "Chrome", "User Data", "Default", "Code Cache"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Google", "Chrome", "User Data", "Default", "GPUCache"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "Edge", "User Data", "Default", "Cache"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Mozilla", "Firefox", "Profiles"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "360se", "data", "cache"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Tencent", "QQBrowser", "User Data", "Default", "Cache"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SogouExplorer", "Cache")
                };

                foreach (string cachePath in browserCachePaths)
                {
                    if (Directory.Exists(cachePath))
                    {
                        ScanDirectory(cachePath, items, "浏览器缓存", JunkType.BrowserCache);
                    }
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"扫描浏览器缓存失败: {ex.Message}");
            }

            return items;
        }

        private List<JunkItem> ScanRecycleBin()
        {
            List<JunkItem> items = new List<JunkItem>();

            try
            {
                string[] driveLetters = Environment.GetLogicalDrives();
                foreach (string drive in driveLetters)
                {
                    string recycleBinPath = drive + "$Recycle.Bin";
                    if (Directory.Exists(recycleBinPath))
                    {
                        ScanDirectory(recycleBinPath, items, "回收站", JunkType.RecycleBin);
                    }
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"扫描回收站失败: {ex.Message}");
            }

            return items;
        }

        private List<JunkItem> ScanWindowsCache()
        {
            List<JunkItem> items = new List<JunkItem>();

            try
            {
                string[] windowsCachePaths = {
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SoftwareDistribution", "Download"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SoftwareDistribution", "Download", "XXXX"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "Windows", "INetCache"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "Windows", "History"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "Windows", "WebCache"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "Windows", "INetCookies"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "Windows", "INetCache")
                };

                foreach (string cachePath in windowsCachePaths)
                {
                    if (Directory.Exists(cachePath))
                    {
                        ScanDirectory(cachePath, items, "Windows缓存", JunkType.WindowsCache);
                    }
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"扫描Windows缓存失败: {ex.Message}");
            }

            return items;
        }

        private List<JunkItem> ScanApplicationCache()
        {
            List<JunkItem> items = new List<JunkItem>();

            try
            {
                string appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                if (Directory.Exists(appDataPath))
                {
                    string[] cacheDirectories = Directory.GetDirectories(appDataPath, "*", SearchOption.TopDirectoryOnly);
                    foreach (string cacheDir in cacheDirectories)
                    {
                        if (cacheDir.ToLower().Contains("cache") || 
                            cacheDir.ToLower().Contains("temp") ||
                            cacheDir.ToLower().Contains("log") ||
                            cacheDir.ToLower().Contains("cache2"))
                        {
                            ScanDirectory(cacheDir, items, "应用缓存", JunkType.ApplicationCache);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"扫描应用缓存失败: {ex.Message}");
            }

            return items;
        }

        private List<JunkItem> ScanWindowsUpdateCache()
        {
            List<JunkItem> items = new List<JunkItem>();

            try
            {
                string[] updateCachePaths = {
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SoftwareDistribution", "Download"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SoftwareDistribution", "Download", "XXXX"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SoftwareDistribution", "Download", "XXXX")
                };

                foreach (string cachePath in updateCachePaths)
                {
                    if (Directory.Exists(cachePath))
                    {
                        ScanDirectory(cachePath, items, "Windows更新缓存", JunkType.WindowsUpdateCache);
                    }
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"扫描Windows更新缓存失败: {ex.Message}");
            }

            return items;
        }

        private List<JunkItem> ScanPrefetchFiles()
        {
            List<JunkItem> items = new List<JunkItem>();

            try
            {
                string prefetchPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");
                if (Directory.Exists(prefetchPath))
                {
                    string[] prefetchFiles = Directory.GetFiles(prefetchPath, "*.pf");
                    foreach (string file in prefetchFiles)
                    {
                        try
                        {
                            FileInfo fileInfo = new FileInfo(file);
                            items.Add(new JunkItem
                            {
                                Path = file,
                                Size = fileInfo.Length,
                                Type = JunkType.PrefetchFiles,
                                Description = "Prefetch文件",
                                CreatedDate = fileInfo.CreationTime,
                                ModifiedDate = fileInfo.LastWriteTime
                            });
                        }
                        catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
                    }
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"扫描Prefetch文件失败: {ex.Message}");
            }

            return items;
        }

        private List<JunkItem> ScanLogFiles()
        {
            List<JunkItem> items = new List<JunkItem>();

            try
            {
                string[] logPaths = {
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Logs"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Debug"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Minidump"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "Windows", "WER"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "Windows", "ErrorReporting")
                };

                foreach (string logPath in logPaths)
                {
                    if (Directory.Exists(logPath))
                    {
                        ScanDirectory(logPath, items, "日志文件", JunkType.LogFiles);
                    }
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"扫描日志文件失败: {ex.Message}");
            }

            return items;
        }

        private List<JunkItem> ScanThumbnailCache()
        {
            List<JunkItem> items = new List<JunkItem>();

            try
            {
                string[] thumbnailPaths = {
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "Windows", "Explorer"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "Windows", "Explorer", "ThumbnailCache")
                };

                foreach (string thumbnailPath in thumbnailPaths)
                {
                    if (Directory.Exists(thumbnailPath))
                    {
                        ScanDirectory(thumbnailPath, items, "缩略图缓存", JunkType.ThumbnailCache);
                    }
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"扫描缩略图缓存失败: {ex.Message}");
            }

            return items;
        }

        private List<JunkItem> ScanOldFiles()
        {
            List<JunkItem> items = new List<JunkItem>();

            try
            {
                string tempPath = Path.GetTempPath();
                if (Directory.Exists(tempPath))
                {
                    DateTime cutoffDate = DateTime.Now.AddDays(-7);
                    string[] oldFiles = Directory.GetFiles(tempPath, "*.*", SearchOption.AllDirectories);

                    foreach (string file in oldFiles)
                    {
                        try
                        {
                            FileInfo fileInfo = new FileInfo(file);
                            if (fileInfo.LastWriteTime < cutoffDate)
                            {
                                items.Add(new JunkItem
                                {
                                    Path = file,
                                    Size = fileInfo.Length,
                                    Type = JunkType.OldFiles,
                                    Description = "超过7天的临时文件",
                                    CreatedDate = fileInfo.CreationTime,
                                    ModifiedDate = fileInfo.LastWriteTime
                                });
                            }
                        }
                        catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
                    }
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"扫描旧文件失败: {ex.Message}");
            }

            return items;
        }

        private void ScanDirectory(string directoryPath, List<JunkItem> items, string description, JunkType type)
        {
            try
            {
                string[] files = Directory.GetFiles(directoryPath, "*.*", SearchOption.AllDirectories);
                foreach (string file in files)
                {
                    try
                    {
                        FileInfo fileInfo = new FileInfo(file);
                        items.Add(new JunkItem
                        {
                            Path = file,
                            Size = fileInfo.Length,
                            Type = type,
                            Description = description,
                            CreatedDate = fileInfo.CreationTime,
                            ModifiedDate = fileInfo.LastWriteTime
                        });
                    }
                    catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"扫描目录失败 {directoryPath}: {ex.Message}");
            }
        }

        public JunkCleanResult CleanJunkFiles(List<JunkItem> junkItems)
        {
            JunkCleanResult result = new JunkCleanResult
            {
                TotalSize = 0,
                CleanedSize = 0,
                CleanedFiles = 0,
                FailedFiles = 0,
                StartTime = DateTime.Now,
                EndTime = DateTime.Now
            };

            try
            {
                foreach (var item in junkItems)
                {
                    try
                    {
                        if (File.Exists(item.Path))
                        {
                            result.TotalSize += item.Size;
                            File.Delete(item.Path);
                            result.CleanedSize += item.Size;
                            result.CleanedFiles++;
                        }
                        else if (Directory.Exists(item.Path))
                        {
                            result.TotalSize += item.Size;
                            Directory.Delete(item.Path, true);
                            result.CleanedSize += item.Size;
                            result.CleanedFiles++;
                        }
                    }
                    catch
                    {
                        result.FailedFiles++;
                    }
                }

                result.EndTime = DateTime.Now;
                dataManager.LogInfo($"垃圾清理完成: 清理了 {result.CleanedFiles} 个文件，释放 {FormatSize(result.CleanedSize)} 空间");
            }
            catch (Exception ex)
            {
                dataManager.LogError($"垃圾清理失败: {ex.Message}");
            }

            return result;
        }

        public JunkCleanResult CleanAllJunk()
        {
            List<JunkItem> junkItems = ScanJunkFiles();
            return CleanJunkFiles(junkItems);
        }

        public long CalculateTotalJunkSize()
        {
            List<JunkItem> junkItems = ScanJunkFiles();
            return junkItems.Sum(item => item.Size);
        }

        public Dictionary<JunkType, long> GetJunkSizeByType()
        {
            List<JunkItem> junkItems = ScanJunkFiles();
            return junkItems.GroupBy(item => item.Type)
                .ToDictionary(g => g.Key, g => g.Sum(item => item.Size));
        }

        private string FormatSize(long bytes)
        {
            string[] sizes = { "B", "KB", "MB", "GB", "TB" };
            int order = 0;
            double size = bytes;

            while (size >= 1024 && order < sizes.Length - 1)
            {
                order++;
                size /= 1024;
            }

            return $"{size:0.##} {sizes[order]}";
        }

        public List<JunkItem> GetJunkFilesByType(JunkType type)
        {
            List<JunkItem> allJunkItems = ScanJunkFiles();
            return allJunkItems.Where(item => item.Type == type).ToList();
        }
    }

    public class JunkItem
    {
        public string Path { get; set; }
        public long Size { get; set; }
        public JunkType Type { get; set; }
        public string Description { get; set; }
        public DateTime CreatedDate { get; set; }
        public DateTime ModifiedDate { get; set; }
    }

    public class JunkCleanResult
    {
        public long TotalSize { get; set; }
        public long CleanedSize { get; set; }
        public int CleanedFiles { get; set; }
        public int FailedFiles { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public TimeSpan Duration => EndTime - StartTime;
    }

    public enum JunkType
    {
        TemporaryFiles,
        BrowserCache,
        RecycleBin,
        WindowsCache,
        ApplicationCache,
        WindowsUpdateCache,
        PrefetchFiles,
        LogFiles,
        ThumbnailCache,
        OldFiles
    }
}