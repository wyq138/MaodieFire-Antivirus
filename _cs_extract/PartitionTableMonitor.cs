using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;
using FireAntivirus.Data;
using FireAntivirus.Engine;

namespace FireAntivirus.Services
{
    public class PartitionTableMonitor : IMonitor
    {
        private Thread monitorThread;
        private bool isRunning;
        private DataManager dataManager;
        private AntivirusEngine antivirusEngine;
        private Dictionary<string, PartitionTableRecord> partitionTableRecords;
        private Dictionary<string, string> mbrHashes;
        private Dictionary<string, string> gptHashes;
        private List<PhysicalDisk> physicalDisks;
        private int checkInterval;
        private bool enableMBRMonitoring;
        private bool enableGPTMonitoring;
        private bool enableBootSectorMonitoring;

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern IntPtr CreateFile(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadFile(
            IntPtr hFile,
            byte[] lpBuffer,
            uint nNumberOfBytesToRead,
            out uint lpNumberOfBytesRead,
            IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        private const uint GENERIC_READ = 0x80000000;
        private const uint FILE_SHARE_READ = 0x00000001;
        private const uint FILE_SHARE_WRITE = 0x00000002;
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_ATTRIBUTE_NORMAL = 0x80;
        private const int INVALID_HANDLE_VALUE = -1;

        public PartitionTableMonitor(DataManager dataManager, AntivirusEngine antivirusEngine)
        {
            this.dataManager = dataManager;
            this.antivirusEngine = antivirusEngine;
            this.partitionTableRecords = new Dictionary<string, PartitionTableRecord>();
            this.mbrHashes = new Dictionary<string, string>();
            this.gptHashes = new Dictionary<string, string>();
            this.physicalDisks = new List<PhysicalDisk>();
            this.checkInterval = 60000;
            this.enableMBRMonitoring = true;
            this.enableGPTMonitoring = true;
            this.enableBootSectorMonitoring = true;
            InitializePhysicalDisks();
            LoadPartitionTableRecords();
        }

        private void InitializePhysicalDisks()
        {
            try
            {
                physicalDisks.Clear();

                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_DiskDrive"))
                {
                    var disks = searcher.Get();

                    foreach (ManagementObject disk in disks)
                    {
                        PhysicalDisk physicalDisk = new PhysicalDisk
                        {
                            DeviceID = disk["DeviceID"]?.ToString(),
                            Model = disk["Model"]?.ToString(),
                            Size = Convert.ToInt64(disk["Size"]),
                            Partitions = Convert.ToInt32(disk["Partitions"]),
                            Index = Convert.ToInt32(disk["Index"]),
                            InterfaceType = disk["InterfaceType"]?.ToString()
                        };

                        physicalDisks.Add(physicalDisk);
                    }
                }

                LogInfo($"检测到 {physicalDisks.Count} 个物理磁盘");
            }
            catch (Exception ex)
            {
                LogError("初始化物理磁盘失败: " + ex.Message);
            }
        }

        private void LoadPartitionTableRecords()
        {
            try
            {
                string recordsPath = Path.Combine(dataManager.GetDataDirectory(), "partition_table_records.json");
                if (File.Exists(recordsPath))
                {
                    string json = File.ReadAllText(recordsPath);
                    var records = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, PartitionTableRecord>>(json);
                    if (records != null)
                    {
                        partitionTableRecords = records;
                    }
                }
            }
            catch (Exception ex)
            {
                LogError("加载分区表记录失败: " + ex.Message);
            }
        }

        private void SavePartitionTableRecords()
        {
            try
            {
                string recordsPath = Path.Combine(dataManager.GetDataDirectory(), "partition_table_records.json");
                string json = System.Text.Json.JsonSerializer.Serialize(partitionTableRecords, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(recordsPath, json);
            }
            catch (Exception ex)
            {
                LogError("保存分区表记录失败: " + ex.Message);
            }
        }

        public void Start()
        {
            if (isRunning) return;
            isRunning = true;
            monitorThread = new Thread(MonitorLoop);
            monitorThread.IsBackground = true;
            monitorThread.Start();
            LogInfo("分区表监控已启动");
        }

        public void Stop()
        {
            isRunning = false;
            if (monitorThread != null && monitorThread.IsAlive)
            {
                monitorThread.Join(5000);
            }
            LogInfo("分区表监控已停止");
        }

        private void MonitorLoop()
        {
            while (isRunning)
            {
                try
                {
                    CheckPartitionTables();
                    if (enableMBRMonitoring)
                    {
                        CheckMBR();
                    }
                    if (enableGPTMonitoring)
                    {
                        CheckGPT();
                    }
                    if (enableBootSectorMonitoring)
                    {
                        CheckBootSector();
                    }
                    Thread.Sleep(checkInterval);
                }
                catch (Exception ex)
                {
                    LogError("分区表监控异常: " + ex.Message);
                    Thread.Sleep(5000);
                }
            }
        }

        public void CheckPartitionTables()
        {
            try
            {
                InitializePhysicalDisks();

                foreach (var disk in physicalDisks)
                {
                    string diskKey = disk.DeviceID;

                    if (partitionTableRecords.ContainsKey(diskKey))
                    {
                        PartitionTableRecord record = partitionTableRecords[diskKey];

                        if (record.Partitions != disk.Partitions)
                        {
                            HandlePartitionTableChange(disk, record);
                        }
                    }
                    else
                    {
                        PartitionTableRecord newRecord = new PartitionTableRecord
                        {
                            DeviceID = disk.DeviceID,
                            Model = disk.Model,
                            Size = disk.Size,
                            Partitions = disk.Partitions,
                            Index = disk.Index,
                            InterfaceType = disk.InterfaceType,
                            LastChecked = DateTime.Now
                        };

                        partitionTableRecords[diskKey] = newRecord;
                        SavePartitionTableRecords();
                        LogInfo($"添加分区表记录: {disk.DeviceID}");
                    }
                }
            }
            catch (Exception ex)
            {
                LogError("检查分区表失败: " + ex.Message);
            }
        }

        private void HandlePartitionTableChange(PhysicalDisk disk, PartitionTableRecord record)
        {
            string message = $"检测到分区表更改\n磁盘: {disk.DeviceID}\n原分区数: {record.Partitions}\n新分区数: {disk.Partitions}\n这可能是恶意攻击！";

            LogWarning(message);

            PartitionThreatDetection detection = new PartitionThreatDetection
            {
                FilePath = disk.DeviceID,
                ThreatType = ThreatType.PartitionTableModification.ToString(),
                Severity = ThreatSeverity.High.ToString(),
                Description = "分区表被修改",
                DetectedAt = DateTime.Now,
                Details = message
            };
            dataManager.LogThreat($"检测到分区表修改: {disk.DeviceID}", $"威胁类型: {detection.ThreatType}, 详细信息: {detection.Details}");
            
            // 弹窗警告
            ShowThreatNotification("分区表修改警告", message, NotificationType.Error);

            record.Partitions = disk.Partitions;
            record.LastChecked = DateTime.Now;
            SavePartitionTableRecords();
        }

        public void CheckMBR()
        {
            try
            {
                foreach (var disk in physicalDisks)
                {
                    if (disk.InterfaceType == "USB") continue;

                    string mbrHash = ReadMBR(disk.Index);
                    if (string.IsNullOrEmpty(mbrHash)) continue;

                    string diskKey = $"MBR-{disk.Index}";

                    if (mbrHashes.ContainsKey(diskKey))
                    {
                        string oldHash = mbrHashes[diskKey];
                        if (oldHash != mbrHash)
                        {
                            HandleMBRChange(disk, oldHash, mbrHash);
                        }
                    }
                    else
                    {
                        mbrHashes[diskKey] = mbrHash;
                        LogInfo($"记录MBR哈希: {disk.DeviceID}");
                    }
                }
            }
            catch (Exception ex)
            {
                LogError("检查MBR失败: " + ex.Message);
            }
        }

        private string ReadMBR(int diskIndex)
        {
            try
            {
                string devicePath = $"\\\\.\\PhysicalDrive{diskIndex}";
                IntPtr handle = CreateFile(devicePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);

                if (handle.ToInt32() == INVALID_HANDLE_VALUE)
                {
                    return null;
                }

                try
                {
                    byte[] buffer = new byte[512];
                    uint bytesRead;

                    if (ReadFile(handle, buffer, 512, out bytesRead, IntPtr.Zero))
                    {
                        if (bytesRead == 512)
                        {
                            using (SHA256 sha256 = SHA256.Create())
                            {
                                byte[] hashBytes = sha256.ComputeHash(buffer);
                                return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
                            }
                        }
                    }
                }
                finally
                {
                    CloseHandle(handle);
                }
            }
            catch (Exception ex)
            {
                LogError($"读取MBR失败 (磁盘 {diskIndex}): " + ex.Message);
            }

            return null;
        }

        private void HandleMBRChange(PhysicalDisk disk, string oldHash, string newHash)
        {
            string message = $"检测到MBR更改\n磁盘: {disk.DeviceID}\n这可能是Bootkit感染！";

            LogWarning(message);

            PartitionThreatDetection detection = new PartitionThreatDetection
            {
                FilePath = disk.DeviceID,
                ThreatType = ThreatType.MBRModification.ToString(),
                Severity = ThreatSeverity.Critical.ToString(),
                Description = "MBR被修改，可能存在Bootkit感染",
                DetectedAt = DateTime.Now,
                Details = message
            };
            dataManager.LogThreat($"检测到MBR修改: {disk.DeviceID}", $"威胁类型: {detection.ThreatType}, 详细信息: {detection.Details}");
            
            // 弹窗警告
            ShowThreatNotification("MBR修改警告", message, NotificationType.Error);

            mbrHashes[$"MBR-{disk.Index}"] = newHash;
        }

        public void CheckGPT()
        {
            try
            {
                foreach (var disk in physicalDisks)
                {
                    if (disk.InterfaceType == "USB") continue;

                    string gptHash = ReadGPT(disk.Index);
                    if (string.IsNullOrEmpty(gptHash)) continue;

                    string diskKey = $"GPT-{disk.Index}";

                    if (gptHashes.ContainsKey(diskKey))
                    {
                        string oldHash = gptHashes[diskKey];
                        if (oldHash != gptHash)
                        {
                            HandleGPTChange(disk, oldHash, gptHash);
                        }
                    }
                    else
                    {
                        gptHashes[diskKey] = gptHash;
                        LogInfo($"记录GPT哈希: {disk.DeviceID}");
                    }
                }
            }
            catch (Exception ex)
            {
                LogError("检查GPT失败: " + ex.Message);
            }
        }

        private string ReadGPT(int diskIndex)
        {
            try
            {
                string devicePath = $"\\\\.\\PhysicalDrive{diskIndex}";
                IntPtr handle = CreateFile(devicePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);

                if (handle.ToInt32() == INVALID_HANDLE_VALUE)
                {
                    return null;
                }

                try
                {
                    byte[] buffer = new byte[512];
                    uint bytesRead;

                    if (ReadFile(handle, buffer, 512, out bytesRead, IntPtr.Zero))
                    {
                        if (bytesRead == 512)
                        {
                            if (buffer[510] == 0x55 && buffer[511] == 0xAA)
                            {
                                if (buffer[0] == 0xEB && buffer[1] == 0x3C && buffer[2] == 0x90)
                                {
                                    return null;
                                }

                                byte[] gptHeader = new byte[512];
                                if (ReadFile(handle, gptHeader, 512, out bytesRead, IntPtr.Zero))
                                {
                                    if (bytesRead == 512)
                                    {
                                        using (SHA256 sha256 = SHA256.Create())
                                        {
                                            byte[] hashBytes = sha256.ComputeHash(gptHeader);
                                            return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                finally
                {
                    CloseHandle(handle);
                }
            }
            catch (Exception ex)
            {
                LogError($"读取GPT失败 (磁盘 {diskIndex}): " + ex.Message);
            }

            return null;
        }

        private void HandleGPTChange(PhysicalDisk disk, string oldHash, string newHash)
        {
            string message = $"检测到GPT更改\n磁盘: {disk.DeviceID}\n这可能是Bootkit感染！";

            LogWarning(message);

            PartitionThreatDetection detection = new PartitionThreatDetection
            {
                FilePath = disk.DeviceID,
                ThreatType = ThreatType.GPTModification.ToString(),
                Severity = ThreatSeverity.Critical.ToString(),
                Description = "GPT被修改，可能存在Bootkit感染",
                DetectedAt = DateTime.Now,
                Details = message
            };
            dataManager.LogThreat($"检测到GPT修改: {disk.DeviceID}", $"威胁类型: {detection.ThreatType}, 详细信息: {detection.Details}");
            
            // 弹窗警告
            ShowThreatNotification("GPT修改警告", message, NotificationType.Error);

            gptHashes[$"GPT-{disk.Index}"] = newHash;
        }

        public void CheckBootSector()
        {
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_LogicalDisk WHERE DriveType=3"))
                {
                    var drives = searcher.Get();

                    foreach (ManagementObject drive in drives)
                    {
                        string driveLetter = drive["DeviceID"]?.ToString();
                        if (string.IsNullOrEmpty(driveLetter)) continue;

                        CheckBootSector(driveLetter);
                    }
                }
            }
            catch (Exception ex)
            {
                LogError("检查引导扇区失败: " + ex.Message);
            }
        }

        private void CheckBootSector(string driveLetter)
        {
            try
            {
                string devicePath = $"\\\\.\\{driveLetter.TrimEnd('\\')}";
                IntPtr handle = CreateFile(devicePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);

                if (handle.ToInt32() == INVALID_HANDLE_VALUE)
                {
                    return;
                }

                try
                {
                    byte[] buffer = new byte[512];
                    uint bytesRead;

                    if (ReadFile(handle, buffer, 512, out bytesRead, IntPtr.Zero))
                    {
                        if (bytesRead == 512)
                        {
                            using (SHA256 sha256 = SHA256.Create())
                            {
                                byte[] hashBytes = sha256.ComputeHash(buffer);
                                string newHash = BitConverter.ToString(hashBytes).Replace("-", "").ToLower();

                                string driveKey = $"BOOT-{driveLetter}";

                                if (partitionTableRecords.ContainsKey(driveKey))
                                {
                                    string oldHash = partitionTableRecords[driveKey].BootSectorHash;
                                    if (!string.IsNullOrEmpty(oldHash) && oldHash != newHash)
                                    {
                                        HandleBootSectorChange(driveLetter, oldHash, newHash);
                                    }
                                }
                                else
                                {
                                    PartitionTableRecord record = new PartitionTableRecord
                                    {
                                        DeviceID = driveLetter,
                                        BootSectorHash = newHash,
                                        LastChecked = DateTime.Now
                                    };
                                    partitionTableRecords[driveKey] = record;
                                    SavePartitionTableRecords();
                                }
                            }
                        }
                    }
                }
                finally
                {
                    CloseHandle(handle);
                }
            }
            catch (Exception ex)
            {
                LogError($"检查引导扇区失败 ({driveLetter}): " + ex.Message);
            }
        }

        private void HandleBootSectorChange(string driveLetter, string oldHash, string newHash)
        {
            string message = $"检测到引导扇区更改\n驱动器: {driveLetter}\n这可能是Bootkit感染！";

            LogWarning(message);

            PartitionThreatDetection detection = new PartitionThreatDetection
            {
                FilePath = driveLetter,
                ThreatType = ThreatType.BootSectorModification.ToString(),
                Severity = ThreatSeverity.Critical.ToString(),
                Description = "引导扇区被修改，可能存在Bootkit感染",
                DetectedAt = DateTime.Now,
                Details = message
            };
            dataManager.LogThreat($"检测到引导扇区修改: {driveLetter}", $"威胁类型: {detection.ThreatType}, 详细信息: {detection.Details}");
            
            // 弹窗警告
            ShowThreatNotification("引导扇区修改警告", message, NotificationType.Error);

            string driveKey = $"BOOT-{driveLetter}";
            if (partitionTableRecords.ContainsKey(driveKey))
            {
                partitionTableRecords[driveKey].BootSectorHash = newHash;
                partitionTableRecords[driveKey].LastChecked = DateTime.Now;
                SavePartitionTableRecords();
            }
        }

        public List<PhysicalDisk> GetPhysicalDisks()
        {
            return new List<PhysicalDisk>(physicalDisks);
        }

        public Dictionary<string, PartitionTableRecord> GetPartitionTableRecords()
        {
            return new Dictionary<string, PartitionTableRecord>(partitionTableRecords);
        }

        public void UpdateBaseline()
        {
            LogInfo("更新分区表基线...");
            partitionTableRecords.Clear();
            mbrHashes.Clear();
            gptHashes.Clear();
            CheckPartitionTables();
            CheckMBR();
            CheckGPT();
            CheckBootSector();
            SavePartitionTableRecords();
            LogInfo("分区表基线更新完成");
        }

        public void SetCheckInterval(int milliseconds)
        {
            checkInterval = milliseconds;
        }

        public void SetMBRMonitoring(bool enabled)
        {
            enableMBRMonitoring = enabled;
        }

        public void SetGPTMonitoring(bool enabled)
        {
            enableGPTMonitoring = enabled;
        }

        public void SetBootSectorMonitoring(bool enabled)
        {
            enableBootSectorMonitoring = enabled;
        }

        private void LogInfo(string message)
        {
            dataManager.LogInfo("[分区表监控] " + message);
        }

        private void LogWarning(string message)
        {
            dataManager.LogWarning("[分区表监控] " + message);
        }

        private void LogError(string message)
        {
            dataManager.LogError("[分区表监控] " + message);
        }
        
        private void ShowThreatNotification(string title, string message, NotificationType type)
        {
            try
            {
                NotificationService.Instance.ShowNotification(title, message, type);
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "PartitionTableMonitor.cs 捕获异常", ex.Message); }
        }
    }

    public class PhysicalDisk
    {
        public string DeviceID { get; set; }
        public string Model { get; set; }
        public long Size { get; set; }
        public int Partitions { get; set; }
        public int Index { get; set; }
        public string InterfaceType { get; set; }
    }

    public class PartitionTableRecord
    {
        public string DeviceID { get; set; }
        public string Model { get; set; }
        public long Size { get; set; }
        public int Partitions { get; set; }
        public int Index { get; set; }
        public string InterfaceType { get; set; }
        public string BootSectorHash { get; set; }
        public DateTime LastChecked { get; set; }
    }

    public class PartitionThreatDetection
    {
        public string FilePath { get; set; }
        public string ThreatType { get; set; }
        public string Severity { get; set; }
        public string Description { get; set; }
        public DateTime DetectedAt { get; set; }
        public string Details { get; set; }
    }
}
