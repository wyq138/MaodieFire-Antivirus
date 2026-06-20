using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using FireAntivirus.Data;
using FireAntivirus.Engine;

namespace FireAntivirus.Services
{
    public class FileShredder
    {
        private DataManager dataManager;
        private AntivirusEngine antivirusEngine;
        private int overwritePasses;
        private bool verifyDeletion;
        private bool deleteEmptyFolders;

        public FileShredder(DataManager dataManager, AntivirusEngine antivirusEngine)
        {
            this.dataManager = dataManager;
            this.antivirusEngine = antivirusEngine;
            this.overwritePasses = 3;
            this.verifyDeletion = true;
            this.deleteEmptyFolders = true;
        }

        public bool ShredFile(string filePath)
        {
            try
            {
                if (!File.Exists(filePath))
                {
                    LogError($"文件不存在: {filePath}");
                    return false;
                }

                LogInfo($"开始粉碎文件: {filePath}");

                FileInfo fileInfo = new FileInfo(filePath);
                long fileSize = fileInfo.Length;

                OverwriteFile(filePath, overwritePasses);

                if (verifyDeletion)
                {
                    if (!VerifyFileDeletion(filePath))
                    {
                        LogWarning($"文件删除验证失败: {filePath}");
                        return false;
                    }
                }

                LogInfo($"文件粉碎成功: {filePath}");
                return true;
            }
            catch (Exception ex)
            {
                LogError($"粉碎文件失败 {filePath}: " + ex.Message);
                return false;
            }
        }

        public bool ShredDirectory(string directoryPath, bool recursive = true)
        {
            try
            {
                if (!Directory.Exists(directoryPath))
                {
                    LogError($"目录不存在: {directoryPath}");
                    return false;
                }

                LogInfo($"开始粉碎目录: {directoryPath}");

                int filesShredded = 0;
                int directoriesDeleted = 0;

                if (recursive)
                {
                    string[] subDirectories = Directory.GetDirectories(directoryPath, "*", SearchOption.AllDirectories);
                    foreach (string subDir in subDirectories)
                    {
                        string[] files = Directory.GetFiles(subDir);
                        foreach (string file in files)
                        {
                            if (ShredFile(file))
                            {
                                filesShredded++;
                            }
                        }
                    }
                }

                string[] rootFiles = Directory.GetFiles(directoryPath);
                foreach (string file in rootFiles)
                {
                    if (ShredFile(file))
                    {
                        filesShredded++;
                    }
                }

                if (deleteEmptyFolders)
                {
                    if (recursive)
                    {
                        string[] allDirectories = Directory.GetDirectories(directoryPath, "*", SearchOption.AllDirectories);
                        Array.Reverse(allDirectories);
                        foreach (string dir in allDirectories)
                        {
                            try
                            {
                                if (Directory.GetFiles(dir).Length == 0 && Directory.GetDirectories(dir).Length == 0)
                                {
                                    Directory.Delete(dir);
                                    directoriesDeleted++;
                                }
                            }
                            catch
                            {
                            }
                        }
                    }

                    try
                    {
                        if (Directory.GetFiles(directoryPath).Length == 0 && Directory.GetDirectories(directoryPath).Length == 0)
                        {
                            Directory.Delete(directoryPath);
                            directoriesDeleted++;
                        }
                    }
                    catch
                    {
                    }
                }

                LogInfo($"目录粉碎完成: {directoryPath}, 文件数: {filesShredded}, 目录数: {directoriesDeleted}");
                return true;
            }
            catch (Exception ex)
            {
                LogError($"粉碎目录失败 {directoryPath}: " + ex.Message);
                return false;
            }
        }

        private void OverwriteFile(string filePath, int passes)
        {
            try
            {
                FileInfo fileInfo = new FileInfo(filePath);
                long fileSize = fileInfo.Length;

                using (FileStream fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Write, FileShare.None))
                {
                    for (int pass = 1; pass <= passes; pass++)
                    {
                        fileStream.Seek(0, SeekOrigin.Begin);

                        byte[] overwritePattern = GetOverwritePattern(pass, (int)fileSize);

                        int bytesWritten = 0;
                        while (bytesWritten < fileSize)
                        {
                            int bytesToWrite = (int)Math.Min(overwritePattern.Length, fileSize - bytesWritten);
                            fileStream.Write(overwritePattern, 0, bytesToWrite);
                            bytesWritten += bytesToWrite;
                        }

                        fileStream.Flush();
                        LogInfo($"覆盖完成 (第 {pass} 轮): {filePath}");
                    }
                }

                File.SetAttributes(filePath, FileAttributes.Normal);
                File.Delete(filePath);
            }
            catch (Exception ex)
            {
                LogError($"覆盖文件失败 {filePath}: " + ex.Message);
                throw;
            }
        }

        private byte[] GetOverwritePattern(int pass, int size)
        {
            switch (pass % 3)
            {
                case 1:
                    return new byte[size];
                case 2:
                    byte[] ones = new byte[size];
                    for (int i = 0; i < size; i++)
                    {
                        ones[i] = 0xFF;
                    }
                    return ones;
                default:
                    using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
                    {
                        byte[] randomBytes = new byte[size];
                        rng.GetBytes(randomBytes);
                        return randomBytes;
                    }
            }
        }

        private bool VerifyFileDeletion(string filePath)
        {
            try
            {
                if (File.Exists(filePath))
                {
                    LogError($"文件仍然存在: {filePath}");
                    return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                LogError($"验证文件删除失败 {filePath}: " + ex.Message);
                return false;
            }
        }

        public bool ShredRecycleBin()
        {
            try
            {
                LogInfo("开始粉碎回收站");

                string recycleBinPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "$Recycle.Bin");

                if (!Directory.Exists(recycleBinPath))
                {
                    LogWarning("回收站路径不存在");
                    return false;
                }

                return ShredDirectory(recycleBinPath, true);
            }
            catch (Exception ex)
            {
                LogError("粉碎回收站失败: " + ex.Message);
                return false;
            }
        }

        public bool ShredTemporaryFiles()
        {
            try
            {
                LogInfo("开始粉碎临时文件");

                List<string> tempDirectories = new List<string>
                {
                    Path.GetTempPath(),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp")
                };

                int successCount = 0;
                foreach (string tempDir in tempDirectories)
                {
                    if (Directory.Exists(tempDir))
                    {
                        if (ShredDirectory(tempDir, true))
                        {
                            successCount++;
                        }
                    }
                }

                LogInfo($"临时文件粉碎完成: {successCount}/{tempDirectories.Count}");
                return successCount > 0;
            }
            catch (Exception ex)
            {
                LogError("粉碎临时文件失败: " + ex.Message);
                return false;
            }
        }

        public bool ShredBrowserCache()
        {
            try
            {
                LogInfo("开始粉碎浏览器缓存");

                string[] browserCachePaths = {
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Google", "Chrome", "User Data", "Default", "Cache"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "Edge", "User Data", "Default", "Cache"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Mozilla", "Firefox", "Profiles")
                };

                int successCount = 0;
                foreach (string cachePath in browserCachePaths)
                {
                    if (Directory.Exists(cachePath))
                    {
                        if (ShredDirectory(cachePath, true))
                        {
                            successCount++;
                        }
                    }
                }

                LogInfo($"浏览器缓存粉碎完成: {successCount}/{browserCachePaths.Length}");
                return successCount > 0;
            }
            catch (Exception ex)
            {
                LogError("粉碎浏览器缓存失败: " + ex.Message);
                return false;
            }
        }

        public long CalculateShredSize(string path)
        {
            try
            {
                if (File.Exists(path))
                {
                    return new FileInfo(path).Length;
                }
                else if (Directory.Exists(path))
                {
                    return CalculateDirectorySize(path);
                }
                return 0;
            }
            catch (Exception ex)
            {
                LogError($"计算粉碎大小失败 {path}: " + ex.Message);
                return 0;
            }
        }

        private long CalculateDirectorySize(string directoryPath)
        {
            long totalSize = 0;

            try
            {
                string[] files = Directory.GetFiles(directoryPath, "*", SearchOption.AllDirectories);
                foreach (string file in files)
                {
                    try
                    {
                        totalSize += new FileInfo(file).Length;
                    }
                    catch
                    {
                    }
                }
            }
            catch
            {
            }

            return totalSize;
        }

        public void SetOverwritePasses(int passes)
        {
            if (passes < 1 || passes > 35)
            {
                throw new ArgumentException("覆盖次数必须在1到35之间");
            }
            overwritePasses = passes;
        }

        public void SetVerifyDeletion(bool verify)
        {
            verifyDeletion = verify;
        }

        public void SetDeleteEmptyFolders(bool delete)
        {
            deleteEmptyFolders = delete;
        }

        public int GetOverwritePasses()
        {
            return overwritePasses;
        }

        public bool GetVerifyDeletion()
        {
            return verifyDeletion;
        }

        public bool GetDeleteEmptyFolders()
        {
            return deleteEmptyFolders;
        }

        private void LogInfo(string message)
        {
            dataManager.LogInfo("[文件粉碎] " + message);
        }

        private void LogWarning(string message)
        {
            dataManager.LogWarning("[文件粉碎] " + message);
        }

        private void LogError(string message)
        {
            dataManager.LogError("[文件粉碎] " + message);
        }
    }

    public class ShredResult
    {
        public bool Success { get; set; }
        public string Path { get; set; }
        public long Size { get; set; }
        public int FilesShredded { get; set; }
        public int DirectoriesDeleted { get; set; }
        public TimeSpan Duration { get; set; }
        public string ErrorMessage { get; set; }
    }
}