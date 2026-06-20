// 抖音用户 耄耋杀毒软件 开发，严禁非法反编译
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace FireAntivirus.Engine.Analyzers.Recovery
{
    /// <summary>
    /// 恢复分析器 - 系统恢复和修复分析
    /// </summary>
    public class RecoveryAnalyzer
    {
        private readonly List<RecoveryPoint> _recoveryPoints;
        private readonly List<SystemBackup> _systemBackups;

        public RecoveryAnalyzer()
        {
            _recoveryPoints = new List<RecoveryPoint>();
            _systemBackups = new List<SystemBackup>();
        }

        public RecoveryResult Analyze()
        {
            var result = new RecoveryResult
            {
                RecoveryPoints = new List<RecoveryPointInfo>(),
                Backups = new List<BackupInfo>(),
                Warnings = new List<string>()
            };

            try
            {
                // 检查系统还原点
                CheckSystemRestorePoints(result);

                // 检查Windows备份
                CheckWindowsBackup(result);

                // 检查启动修复
                CheckStartupRepair(result);

                // 检查系统文件完整性
                CheckSystemIntegrity(result);

                if (result.RecoveryPoints.Count == 0)
                {
                    result.Warnings.Add("未找到系统还原点");
                }
            }
            catch (Exception ex)
            {
                result.Warnings.Add($"恢复分析错误: {ex.Message}");
            }

            return result;
        }

        private void CheckSystemRestorePoints(RecoveryResult result)
        {
            try
            {
                // 使用vssadmin列出卷影副本
                var psi = new ProcessStartInfo
                {
                    FileName = "vssadmin",
                    Arguments = "list shadows",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                };

                using var process = Process.Start(psi);
                if (process != null)
                {
                    var output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();

                    // 解析输出
                    var lines = output.Split('\n');
                    RecoveryPointInfo currentPoint = null;

                    foreach (var line in lines)
                    {
                        var trimmed = line.Trim();

                        if (trimmed.StartsWith("卷影副本 ID"))
                        {
                            if (currentPoint != null)
                                result.RecoveryPoints.Add(currentPoint);

                            currentPoint = new RecoveryPointInfo
                            {
                                ID = trimmed.Split(':').Last().Trim()
                            };
                        }
                        else if (currentPoint != null)
                        {
                            if (trimmed.StartsWith("卷影副本创建时间"))
                            {
                                currentPoint.CreationTime = trimmed.Split(':').Last().Trim();
                            }
                            else if (trimmed.StartsWith("卷影副本卷名"))
                            {
                                currentPoint.Volume = trimmed.Split(':').Last().Trim();
                            }
                        }
                    }

                    if (currentPoint != null)
                        result.RecoveryPoints.Add(currentPoint);
                }
            }
            catch { }
        }

        private void CheckWindowsBackup(RecoveryResult result)
        {
            try
            {
                // 检查Windows Server Backup
                using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsBackup");
                if (key != null)
                {
                    result.BackupEnabled = true;

                    var lastBackup = key.GetValue("LastBackupTime");
                    if (lastBackup != null)
                    {
                        result.LastBackupTime = DateTime.FromFileTime(Convert.ToInt64(lastBackup));
                    }
                }
            }
            catch { }
        }

        private void CheckStartupRepair(RecoveryResult result)
        {
            try
            {
                // 检查启动修复
                var bootSdiPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Boot", "PCAT", "boot.sdi");
                result.StartupRepairAvailable = File.Exists(bootSdiPath);

                // 检查恢复分区
                using var searcher = new System.Management.ManagementObjectSearcher("SELECT * FROM Win32_DiskPartition");
                foreach (var obj in searcher.Get())
                {
                    var type = obj["Type"]?.ToString() ?? "";
                    if (type.Contains("Recovery") || type.Contains("GPT:System"))
                    {
                        result.HasRecoveryPartition = true;
                        break;
                    }
                }
            }
            catch { }
        }

        private void CheckSystemIntegrity(RecoveryResult result)
        {
            try
            {
                // 检查系统文件
                var systemFiles = new[]
                {
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "ntoskrnl.exe"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "kernel32.dll"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "ntdll.dll"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "user32.dll")
                };

                result.SystemFileStatus = new Dictionary<string, bool>();
                foreach (var file in systemFiles)
                {
                    result.SystemFileStatus[Path.GetFileName(file)] = File.Exists(file);
                }
            }
            catch { }
        }

        public bool CreateRestorePoint(string description)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "powershell",
                    Arguments = $"-Command \"Checkpoint-Computer -Description '{description}' -RestorePointType 'MODIFY_SETTINGS'\"",
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var process = Process.Start(psi);
                process?.WaitForExit();
                return true;
            }
            catch
            {
                return false;
            }
        }

        public bool RestoreSystem(string restorePointId)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "rstrui.exe",
                    Arguments = $"/restore",
                    UseShellExecute = true
                };

                Process.Start(psi);
                return true;
            }
            catch
            {
                return false;
            }
        }
    }

    public class RecoveryResult
    {
        public List<RecoveryPointInfo> RecoveryPoints { get; set; }
        public List<BackupInfo> Backups { get; set; }
        public List<string> Warnings { get; set; }
        public bool BackupEnabled { get; set; }
        public DateTime? LastBackupTime { get; set; }
        public bool StartupRepairAvailable { get; set; }
        public bool HasRecoveryPartition { get; set; }
        public Dictionary<string, bool> SystemFileStatus { get; set; }
    }

    public class RecoveryPointInfo
    {
        public string ID { get; set; }
        public string CreationTime { get; set; }
        public string Volume { get; set; }
        public string Description { get; set; }
    }

    public class BackupInfo
    {
        public string Path { get; set; }
        public DateTime CreationTime { get; set; }
        public long Size { get; set; }
    }

    public class RecoveryPoint
    {
        public string ID { get; set; }
        public DateTime CreatedTime { get; set; }
        public string Description { get; set; }
        public string Type { get; set; }
    }

    public class SystemBackup
    {
        public string Path { get; set; }
        public DateTime CreatedTime { get; set; }
        public long SizeBytes { get; set; }
    }
}
