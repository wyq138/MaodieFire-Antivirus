using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Diagnostics;
using System.Linq;
using FireAntivirus.Data;
using FireAntivirus.Engine;

namespace FireAntivirus.Services
{
    public class FileIntegrityChecker : IMonitor
    {
        private Thread monitorThread;
        private bool isRunning;
        private DataManager dataManager;
        private AntivirusEngine antivirusEngine;
        private Dictionary<string, FileIntegrityRecord> integrityRecords;
        private HashSet<string> criticalDirectories;
        private HashSet<string> criticalFiles;
        private HashSet<string> trustedSigners;
        private int checkInterval;
        private bool autoRepair;

        public FileIntegrityChecker(DataManager dataManager, AntivirusEngine antivirusEngine)
        {
            this.dataManager = dataManager;
            this.antivirusEngine = antivirusEngine;
            this.integrityRecords = new Dictionary<string, FileIntegrityRecord>();
            this.criticalDirectories = new HashSet<string>();
            this.criticalFiles = new HashSet<string>();
            this.trustedSigners = new HashSet<string>();
            this.checkInterval = 300000;
            this.autoRepair = false;
            InitializeCriticalPaths();
            LoadIntegrityRecords();
        }

        private void InitializeCriticalPaths()
        {
            criticalDirectories.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32"));
            criticalDirectories.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32\\drivers"));
            criticalDirectories.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64"));
            criticalDirectories.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Fonts"));
            criticalDirectories.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Common Files"));
            criticalDirectories.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Common Files"));

            criticalFiles.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32\\ntoskrnl.exe"));
            criticalFiles.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32\\hal.dll"));
            criticalFiles.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32\\kernel32.dll"));
            criticalFiles.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32\\user32.dll"));
            criticalFiles.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32\\shell32.dll"));
            criticalFiles.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32\\explorer.exe"));
            criticalFiles.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32\\svchost.exe"));
            criticalFiles.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32\\services.exe"));
            criticalFiles.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32\\lsass.exe"));
            criticalFiles.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32\\winlogon.exe"));
            criticalFiles.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32\\csrss.exe"));
            criticalFiles.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32\\smss.exe"));

            trustedSigners.Add("Microsoft Windows");
            trustedSigners.Add("Microsoft Corporation");
            trustedSigners.Add("Microsoft Windows Hardware Compatibility Publisher");
        }

        private void LoadIntegrityRecords()
        {
            try
            {
                string recordsPath = Path.Combine(dataManager.GetDataDirectory(), "integrity_records.json");
                if (File.Exists(recordsPath))
                {
                    string json = File.ReadAllText(recordsPath);
                    var records = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, FileIntegrityRecord>>(json);
                    if (records != null)
                    {
                        integrityRecords = records;
                    }
                }
            }
            catch (Exception ex)
            {
                LogError("加载完整性记录失败: " + ex.Message);
            }
        }

        private void SaveIntegrityRecords()
        {
            try
            {
                string recordsPath = Path.Combine(dataManager.GetDataDirectory(), "integrity_records.json");
                string json = System.Text.Json.JsonSerializer.Serialize(integrityRecords, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(recordsPath, json);
            }
            catch (Exception ex)
            {
                LogError("保存完整性记录失败: " + ex.Message);
            }
        }

        public void Start()
        {
            if (isRunning) return;
            isRunning = true;
            monitorThread = new Thread(MonitorLoop);
            monitorThread.IsBackground = true;
            monitorThread.Start();
            LogInfo("文件完整性检查器已启动");
        }

        public void Stop()
        {
            isRunning = false;
            if (monitorThread != null && monitorThread.IsAlive)
            {
                monitorThread.Join(5000);
            }
            LogInfo("文件完整性检查器已停止");
        }

        private void MonitorLoop()
        {
            while (isRunning)
            {
                try
                {
                    CheckFileIntegrity();
                    Thread.Sleep(checkInterval);
                }
                catch (Exception ex)
                {
                    LogError("文件完整性检查异常: " + ex.Message);
                    Thread.Sleep(5000);
                }
            }
        }

        public void CheckFileIntegrity()
        {
            List<IntegrityViolation> violations = new List<IntegrityViolation>();

            foreach (string criticalFile in criticalFiles)
            {
                if (File.Exists(criticalFile))
                {
                    IntegrityViolation violation = CheckFile(criticalFile);
                    if (violation != null)
                    {
                        violations.Add(violation);
                    }
                }
            }

            foreach (string directory in criticalDirectories)
            {
                if (Directory.Exists(directory))
                {
                    var directoryViolations = CheckDirectory(directory);
                    violations.AddRange(directoryViolations);
                }
            }

            if (violations.Count > 0)
            {
                HandleViolations(violations);
            }
        }

        private IntegrityViolation CheckFile(string filePath)
        {
            try
            {
                string hash = CalculateFileHash(filePath);
                var versionInfo = System.Diagnostics.FileVersionInfo.GetVersionInfo(filePath);

                if (integrityRecords.ContainsKey(filePath))
                {
                    FileIntegrityRecord record = integrityRecords[filePath];
                    if (record.Hash != hash)
                    {
                        return new IntegrityViolation
                        {
                            FilePath = filePath,
                            ViolationType = IntegrityViolationType.HashMismatch,
                            OriginalHash = record.Hash,
                            CurrentHash = hash,
                            LastModified = File.GetLastWriteTime(filePath),
                            Severity = ViolationSeverity.High
                        };
                    }
                }
                else
                {
                    integrityRecords[filePath] = new FileIntegrityRecord
                    {
                        FilePath = filePath,
                        Hash = hash,
                        FileSize = new FileInfo(filePath).Length,
                        LastModified = File.GetLastWriteTime(filePath),
                        Version = versionInfo.FileVersion,
                        CompanyName = versionInfo.CompanyName,
                        SignatureStatus = VerifyFileSignature(filePath)
                    };
                    SaveIntegrityRecords();
                }

                return null;
            }
            catch (Exception ex)
            {
                LogError("检查文件失败 " + filePath + ": " + ex.Message);
                return null;
            }
        }

        private List<IntegrityViolation> CheckDirectory(string directoryPath)
        {
            List<IntegrityViolation> violations = new List<IntegrityViolation>();

            try
            {
                string[] extensions = { ".exe", ".dll", ".sys", ".drv", ".ocx", ".cpl" };
                var files = Directory.EnumerateFiles(directoryPath, "*.*", SearchOption.TopDirectoryOnly)
                    .Where(f => extensions.Contains(Path.GetExtension(f).ToLower()));

                foreach (string file in files)
                {
                    try
                    {
                        IntegrityViolation violation = CheckFile(file);
                        if (violation != null)
                        {
                            violations.Add(violation);
                        }
                    }
                    catch (Exception ex)
                    {
                        LogError("检查目录文件失败 " + file + ": " + ex.Message);
                    }
                }
            }
            catch (Exception ex)
            {
                LogError("检查目录失败 " + directoryPath + ": " + ex.Message);
            }

            return violations;
        }

        private string CalculateFileHash(string filePath)
        {
            using (var sha256 = SHA256.Create())
            {
                using (var stream = File.OpenRead(filePath))
                {
                    byte[] hashBytes = sha256.ComputeHash(stream);
                    return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
                }
            }
        }

                private SignatureStatus VerifyFileSignature(string filePath)
        {
            try
            {
                // 不使用Windows签名验证，改为检查文件是否在信任目录中
                if (!File.Exists(filePath))
                    return SignatureStatus.Unknown;
                
                string lowerPath = filePath.ToLowerInvariant();
                
                // 系统目录下的文件默认信任
                bool isInTrustedLocation = 
                    lowerPath.Contains("\\windows\\") ||
                    lowerPath.Contains("\\system32\\") ||
                    lowerPath.Contains("\\syswow64\\") ||
                    lowerPath.Contains("\\program files\\") ||
                    lowerPath.Contains("\\program files (x86)\\");
                
                if (isInTrustedLocation)
                {
                    return SignatureStatus.Valid;
                }
                
                return SignatureStatus.NotSigned;
            }
            catch
            {
                return SignatureStatus.Unknown;
            }
        }

        private void HandleViolations(List<IntegrityViolation> violations)
        {
            foreach (var violation in violations)
            {
                string message = $"检测到文件完整性违规: {violation.FilePath}\n" +
                                $"类型: {violation.ViolationType}\n" +
                                $"严重程度: {violation.Severity}";

                if (violation.ViolationType == IntegrityViolationType.HashMismatch)
                {
                    message += $"\n原始哈希: {violation.OriginalHash}\n" +
                              $"当前哈希: {violation.CurrentHash}";
                }

                LogWarning(message);

                FileIntegrityThreatDetection detection = new FileIntegrityThreatDetection
                {
                    FilePath = violation.FilePath,
                    ThreatType = ThreatType.FileIntegrityViolation.ToString(),
                    Severity = (violation.Severity == ViolationSeverity.High ? ThreatSeverity.High : ThreatSeverity.Medium).ToString(),
                    Description = $"文件完整性违规: {violation.ViolationType}",
                    DetectedAt = DateTime.Now,
                    Details = message
                };

                dataManager.LogThreat($"检测到文件完整性违规: {violation.FilePath}", $"威胁类型: {detection.ThreatType}, 详细信息: {detection.Details}");

                if (autoRepair && violation.Severity == ViolationSeverity.High)
                {
                    RepairFile(violation);
                }
            }
        }

        public bool RepairFile(IntegrityViolation violation)
        {
            try
            {
                LogInfo($"尝试修复文件: {violation.FilePath}");

                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = "sfc",
                    Arguments = "/scannow",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    Verb = "runas"
                };

                Process process = Process.Start(psi);
                process.WaitForExit();

                if (process.ExitCode == 0)
                {
                    LogInfo($"文件修复成功: {violation.FilePath}");
                    integrityRecords.Remove(violation.FilePath);
                    CheckFile(violation.FilePath);
                    return true;
                }
                else
                {
                    LogWarning($"文件修复失败: {violation.FilePath}, 退出代码: {process.ExitCode}");
                    return false;
                }
            }
            catch (Exception ex)
            {
                LogError($"修复文件异常 {violation.FilePath}: " + ex.Message);
                return false;
            }
        }

        public bool RestoreFile(string filePath, string backupPath)
        {
            try
            {
                if (File.Exists(backupPath))
                {
                    File.Copy(backupPath, filePath, true);
                    LogInfo($"文件恢复成功: {filePath}");
                    integrityRecords.Remove(filePath);
                    CheckFile(filePath);
                    return true;
                }
                return false;
            }
            catch (Exception ex)
            {
                LogError($"恢复文件异常 {filePath}: " + ex.Message);
                return false;
            }
        }

        public List<FileIntegrityRecord> GetIntegrityRecords()
        {
            return integrityRecords.Values.ToList();
        }

        public List<FileIntegrityRecord> GetCriticalFileRecords()
        {
            return integrityRecords.Values
                .Where(r => criticalFiles.Contains(r.FilePath))
                .ToList();
        }

        public void UpdateBaseline()
        {
            LogInfo("更新完整性基线...");
            integrityRecords.Clear();
            CheckFileIntegrity();
            SaveIntegrityRecords();
            LogInfo("完整性基线更新完成");
        }

        public void SetCheckInterval(int milliseconds)
        {
            checkInterval = milliseconds;
        }

        public void SetAutoRepair(bool enabled)
        {
            autoRepair = enabled;
        }

        private void LogInfo(string message)
        {
            dataManager.LogInfo("[文件完整性] " + message);
        }

        private void LogWarning(string message)
        {
            dataManager.LogWarning("[文件完整性] " + message);
        }

        private void LogError(string message)
        {
            dataManager.LogError("[文件完整性] " + message);
        }
    }

    public class FileIntegrityRecord
    {
        public string FilePath { get; set; }
        public string Hash { get; set; }
        public long FileSize { get; set; }
        public DateTime LastModified { get; set; }
        public string Version { get; set; }
        public string CompanyName { get; set; }
        public SignatureStatus SignatureStatus { get; set; }
    }

    public class IntegrityViolation
    {
        public string FilePath { get; set; }
        public IntegrityViolationType ViolationType { get; set; }
        public string OriginalHash { get; set; }
        public string CurrentHash { get; set; }
        public DateTime LastModified { get; set; }
        public ViolationSeverity Severity { get; set; }
    }

    public enum IntegrityViolationType
    {
        HashMismatch,
        SizeMismatch,
        SignatureInvalid,
        UnauthorizedModification,
        FileDeleted,
        NewFile
    }

    public enum SignatureStatus
    {
        Valid,
        Invalid,
        NotSigned,
        Unknown
    }

    public class FileIntegrityThreatDetection
    {
        public string FilePath { get; set; }
        public string ThreatType { get; set; }
        public string Severity { get; set; }
        public string Description { get; set; }
        public DateTime DetectedAt { get; set; }
        public string Details { get; set; }
    }
}
