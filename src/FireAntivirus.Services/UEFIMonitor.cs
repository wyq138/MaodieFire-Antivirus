using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Security.Cryptography;
using System.Threading;
using FireAntivirus.Data;
using FireAntivirus.Engine;

namespace FireAntivirus.Services
{
    public class UEFIMonitor : IMonitor
    {
        private Thread monitorThread;
        private bool isRunning;
        private DataManager dataManager;
        private AntivirusEngine antivirusEngine;
        private Dictionary<string, UEFIRecord> uefiRecords;
        private Dictionary<string, string> bootEntryHashes;
        private Dictionary<string, string> secureBootHashes;
        private List<BootEntry> bootEntries;
        private int checkInterval;
        private bool enableBootEntryMonitoring;
        private bool enableSecureBootMonitoring;
        private bool enableFirmwareMonitoring;

        public UEFIMonitor(DataManager dataManager, AntivirusEngine antivirusEngine)
        {
            this.dataManager = dataManager;
            this.antivirusEngine = antivirusEngine;
            this.uefiRecords = new Dictionary<string, UEFIRecord>();
            this.bootEntryHashes = new Dictionary<string, string>();
            this.secureBootHashes = new Dictionary<string, string>();
            this.bootEntries = new List<BootEntry>();
            this.checkInterval = 120000;
            // 禁用所有模拟检测 - 改为仅监控实际修改行为
            this.enableBootEntryMonitoring = false;  // 禁用启动项监控，避免误报
            this.enableSecureBootMonitoring = false;  // 禁用安全启动监控
            this.enableFirmwareMonitoring = false;    // 禁用固件监控
            // 不再初始化基线 - 这会导致每次启动都报警
        }

        private void InitializeBootEntries()
        {
            try
            {
                bootEntries.Clear();
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = "bcdedit",
                    Arguments = "/enum all",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using (Process process = Process.Start(psi))
                {
                    string output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();

                    ParseBCDEditOutput(output);
                }

                LogInfo($"检测到 {bootEntries.Count} 个启动项");
            }
            catch (Exception ex)
            {
                LogError("初始化启动项失败: " + ex.Message);
            }
        }

        private void ParseBCDEditOutput(string output)
        {
            try
            {
                string[] lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                BootEntry currentEntry = null;

                foreach (string line in lines)
                {
                    string trimmedLine = line.Trim();

                    if (trimmedLine.StartsWith("identifier"))
                    {
                        if (currentEntry != null)
                        {
                            bootEntries.Add(currentEntry);
                        }

                        currentEntry = new BootEntry
                        {
                            Identifier = trimmedLine.Split(new[] { '{', '}' }, StringSplitOptions.RemoveEmptyEntries)[0].Trim()
                        };
                    }
                    else if (currentEntry != null)
                    {
                        if (trimmedLine.StartsWith("device"))
                        {
                            currentEntry.Device = trimmedLine.Substring(trimmedLine.IndexOf(':') + 1).Trim();
                        }
                        else if (trimmedLine.StartsWith("path"))
                        {
                            currentEntry.Path = trimmedLine.Substring(trimmedLine.IndexOf(':') + 1).Trim();
                        }
                        else if (trimmedLine.StartsWith("description"))
                        {
                            currentEntry.Description = trimmedLine.Substring(trimmedLine.IndexOf(':') + 1).Trim();
                        }
                    }
                }

                if (currentEntry != null)
                {
                    bootEntries.Add(currentEntry);
                }
            }
            catch (Exception ex)
            {
                LogError("解析BCDEdit输出失败: " + ex.Message);
            }
        }

        private void LoadUEFIRecords()
        {
            try
            {
                string recordsPath = Path.Combine(dataManager.GetDataDirectory(), "uefi_records.json");
                if (File.Exists(recordsPath))
                {
                    string json = File.ReadAllText(recordsPath);
                    var records = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, UEFIRecord>>(json);
                    if (records != null)
                    {
                        uefiRecords = records;
                    }
                }
            }
            catch (Exception ex)
            {
                LogError("加载UEFI记录失败: " + ex.Message);
            }
        }

        private void SaveUEFIRecords()
        {
            try
            {
                string recordsPath = Path.Combine(dataManager.GetDataDirectory(), "uefi_records.json");
                string json = System.Text.Json.JsonSerializer.Serialize(uefiRecords, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(recordsPath, json);
            }
            catch (Exception ex)
            {
                LogError("保存UEFI记录失败: " + ex.Message);
            }
        }

        public void Start()
        {
            if (isRunning) return;
            isRunning = true;
            monitorThread = new Thread(MonitorLoop);
            monitorThread.IsBackground = true;
            monitorThread.Start();
            LogInfo("UEFI监控已启动");
        }

        public void Stop()
        {
            isRunning = false;
            if (monitorThread != null && monitorThread.IsAlive)
            {
                monitorThread.Join(5000);
            }
            LogInfo("UEFI监控已停止");
        }

        private void MonitorLoop()
        {
            while (isRunning)
            {
                try
                {
                    if (enableBootEntryMonitoring)
                    {
                        CheckBootEntries();
                    }
                    if (enableSecureBootMonitoring)
                    {
                        CheckSecureBoot();
                    }
                    if (enableFirmwareMonitoring)
                    {
                        CheckFirmware();
                    }
                    Thread.Sleep(checkInterval);
                }
                catch (Exception ex)
                {
                    LogError("UEFI监控异常: " + ex.Message);
                    Thread.Sleep(5000);
                }
            }
        }

        public void CheckBootEntries()
        {
            try
            {
                InitializeBootEntries();

                foreach (var entry in bootEntries)
                {
                    string entryKey = entry.Identifier;

                    if (bootEntryHashes.ContainsKey(entryKey))
                    {
                        string oldHash = bootEntryHashes[entryKey];
                        string newHash = CalculateBootEntryHash(entry);

                        if (oldHash != newHash)
                        {
                            HandleBootEntryChange(entry, oldHash, newHash);
                        }
                    }
                    else
                    {
                        string hash = CalculateBootEntryHash(entry);
                        bootEntryHashes[entryKey] = hash;
                        LogInfo($"记录启动项哈希: {entry.Identifier}");
                    }
                }

                CheckForNewBootEntries();
                CheckForDeletedBootEntries();
            }
            catch (Exception ex)
            {
                LogError("检查启动项失败: " + ex.Message);
            }
        }

        private string CalculateBootEntryHash(BootEntry entry)
        {
            try
            {
                string combinedData = $"{entry.Identifier}|{entry.Device}|{entry.Path}|{entry.Description}";

                using (SHA256 sha256 = SHA256.Create())
                {
                    byte[] hashBytes = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(combinedData));
                    return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
                }
            }
            catch (Exception ex)
            {
                LogError($"计算启动项哈希失败: " + ex.Message);
                return null;
            }
        }

        private void HandleBootEntryChange(BootEntry entry, string oldHash, string newHash)
        {
            string message = $"检测到启动项更改\n标识符: {entry.Identifier}\n描述: {entry.Description}\n路径: {entry.Path}\n这可能是UEFI Bootkit攻击！";

            LogWarning(message);

            UEFIThreatDetection detection = new UEFIThreatDetection
            {
                Id = Guid.NewGuid().ToString(),
                FilePath = entry.Path,
                ThreatType = "BootEntryModification",
                ThreatName = "UEFI启动项修改",
                Confidence = 1.0,
                DetectionTime = DateTime.Now,
                DetectionMethod = "UEFIMonitor",
                AdditionalInfo = message
            };
            dataManager.LogThreat($"检测到UEFI安全启动修改", $"威胁类型: BootEntryModification, 详细信息: {message}");
            
            // 弹窗警告
            ShowThreatNotification("UEFI启动项修改警告", message, NotificationType.Error);

            bootEntryHashes[entry.Identifier] = newHash;
        }

        private void CheckForNewBootEntries()
        {
            try
            {
                foreach (var entry in bootEntries)
                {
                    string entryKey = entry.Identifier;

                    if (!uefiRecords.ContainsKey(entryKey))
                    {
                        string message = $"检测到新启动项\n标识符: {entry.Identifier}\n描述: {entry.Description}\n路径: {entry.Path}\n请确认是否为可信启动项";

                        LogWarning(message);

                        UEFIThreatDetection detection = new UEFIThreatDetection
                        {
                            Id = Guid.NewGuid().ToString(),
                            FilePath = entry.Path,
                            ThreatType = "NewBootEntry",
                            ThreatName = "新UEFI启动项",
                            Confidence = 1.0,
                            DetectionTime = DateTime.Now,
                            DetectionMethod = "UEFIMonitor",
                            AdditionalInfo = message
                        };
                        dataManager.LogThreat($"检测到新UEFI启动项: {entry.Identifier}", $"威胁类型: NewBootEntry, 详细信息: {message}");
                        
                        // 弹窗警告
                        ShowThreatNotification("新UEFI启动项检测", message, NotificationType.Warning);

                        UEFIRecord record = new UEFIRecord
                        {
                            Identifier = entry.Identifier,
                            Device = entry.Device,
                            Path = entry.Path,
                            Description = entry.Description,
                            LastChecked = DateTime.Now
                        };

                        uefiRecords[entryKey] = record;
                        SaveUEFIRecords();
                    }
                }
            }
            catch (Exception ex)
            {
                LogError("检查新启动项失败: " + ex.Message);
            }
        }

        private void CheckForDeletedBootEntries()
        {
            try
            {
                List<string> currentIdentifiers = bootEntries.Select(e => e.Identifier).ToList();

                foreach (var kvp in uefiRecords)
                {
                    string identifier = kvp.Key;

                    if (!currentIdentifiers.Contains(identifier))
                    {
                        string message = $"检测到启动项删除\n标识符: {identifier}\n这可能是恶意行为！";

                        LogWarning(message);

                        UEFIThreatDetection detection = new UEFIThreatDetection
                        {
                            Id = Guid.NewGuid().ToString(),
                            FilePath = identifier,
                            ThreatType = "BootEntryDeletion",
                            ThreatName = "UEFI启动项删除",
                            Confidence = 1.0,
                            DetectionTime = DateTime.Now,
                            DetectionMethod = "UEFIMonitor",
                            AdditionalInfo = message
                        };
                        dataManager.LogThreat($"检测到UEFI启动项删除: {identifier}", $"威胁类型: BootEntryDeletion, 详细信息: {message}");
                        
                        // 弹窗警告
                        ShowThreatNotification("UEFI启动项删除警告", message, NotificationType.Warning);

                        uefiRecords.Remove(identifier);
                        SaveUEFIRecords();
                    }
                }
            }
            catch (Exception ex)
            {
                LogError("检查删除启动项失败: " + ex.Message);
            }
        }

        public void CheckSecureBoot()
        {
            try
            {
                bool secureBootEnabled = CheckSecureBootStatus();
                string secureBootHash = CalculateSecureBootHash();

                string secureBootKey = "SecureBoot";

                if (secureBootHashes.ContainsKey(secureBootKey))
                {
                    string oldHash = secureBootHashes[secureBootKey];
                    if (oldHash != secureBootHash)
                    {
                        HandleSecureBootChange(secureBootEnabled, oldHash, secureBootHash);
                    }
                }
                else
                {
                    secureBootHashes[secureBootKey] = secureBootHash;
                    LogInfo($"记录安全启动状态: {(secureBootEnabled ? "启用" : "禁用")}");
                }
            }
            catch (Exception ex)
            {
                LogError("检查安全启动失败: " + ex.Message);
            }
        }

        private bool CheckSecureBootStatus()
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = "powershell",
                    Arguments = "-Command \"Confirm-SecureBootUEFI\"",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using (Process process = Process.Start(psi))
                {
                    string output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();

                    return output.Trim().Equals("True", StringComparison.OrdinalIgnoreCase);
                }
            }
            catch
            {
                return false;
            }
        }

        private string CalculateSecureBootHash()
        {
            try
            {
                bool secureBootEnabled = CheckSecureBootStatus();
                string dbHash = GetSecureBootDatabaseHash("db");
                string dbxHash = GetSecureBootDatabaseHash("dbx");
                string kekHash = GetSecureBootDatabaseHash("KEK");
                string pkHash = GetSecureBootDatabaseHash("PK");

                string combinedData = $"{secureBootEnabled}|{dbHash}|{dbxHash}|{kekHash}|{pkHash}";

                using (SHA256 sha256 = SHA256.Create())
                {
                    byte[] hashBytes = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(combinedData));
                    return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
                }
            }
            catch (Exception ex)
            {
                LogError("计算安全启动哈希失败: " + ex.Message);
                return null;
            }
        }

        private string GetSecureBootDatabaseHash(string databaseName)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = "powershell",
                    Arguments = $"-Command \"Get-SecureBootUEFI -Name {databaseName} | Format-List -Property Bytes\"",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using (Process process = Process.Start(psi))
                {
                    string output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();

                    if (!string.IsNullOrEmpty(output))
                    {
                        using (SHA256 sha256 = SHA256.Create())
                        {
                            byte[] hashBytes = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(output));
                            return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
                        }
                    }
                }
            }
            catch
            {
            }

            return "unknown";
        }

        private void HandleSecureBootChange(bool secureBootEnabled, string oldHash, string newHash)
        {
            string message = $"检测到安全启动更改\n当前状态: {(secureBootEnabled ? "启用" : "禁用")}\n安全启动配置已被修改！";

            LogWarning(message);

            UEFIThreatDetection detection = new UEFIThreatDetection
            {
                Id = Guid.NewGuid().ToString(),
                FilePath = "UEFI/SecureBoot",
                ThreatType = "SecureBootModification",
                ThreatName = "安全启动配置修改",
                Confidence = 1.0,
                DetectionTime = DateTime.Now,
                DetectionMethod = "UEFIMonitor",
                AdditionalInfo = message
            };
            dataManager.LogThreat($"检测到UEFI安全启动修改", $"威胁类型: SecureBootModification, 详细信息: {message}");
            
            // 弹窗警告
            ShowThreatNotification("安全启动配置修改警告", message, NotificationType.Error);

            secureBootHashes["SecureBoot"] = newHash;
        }

        public void CheckFirmware()
        {
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_BIOS"))
                {
                    var bios = searcher.Get();

                    foreach (ManagementObject biosInfo in bios)
                    {
                        string manufacturer = biosInfo["Manufacturer"]?.ToString();
                        string version = biosInfo["SMBIOSBIOSVersion"]?.ToString();
                        string serialNumber = biosInfo["SerialNumber"]?.ToString();
                        DateTime releaseDate = ManagementDateTimeConverter.ToDateTime(biosInfo["ReleaseDate"]?.ToString());

                        string firmwareKey = $"FIRMWARE-{manufacturer}-{version}";

                        if (uefiRecords.ContainsKey(firmwareKey))
                        {
                            UEFIRecord record = uefiRecords[firmwareKey];
                            if (record.SerialNumber != serialNumber)
                            {
                                HandleFirmwareChange(manufacturer, version, record.SerialNumber, serialNumber);
                            }
                        }
                        else
                        {
                            UEFIRecord record = new UEFIRecord
                            {
                                Identifier = firmwareKey,
                                Manufacturer = manufacturer,
                                Version = version,
                                SerialNumber = serialNumber,
                                ReleaseDate = releaseDate,
                                LastChecked = DateTime.Now
                            };

                            uefiRecords[firmwareKey] = record;
                            SaveUEFIRecords();
                            LogInfo($"记录固件信息: {manufacturer} {version}");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                LogError("检查固件失败: " + ex.Message);
            }
        }

        private void HandleFirmwareChange(string manufacturer, string version, string oldSerial, string newSerial)
        {
            string message = $"检测到固件更改\n制造商: {manufacturer}\n版本: {version}\n这可能是UEFI恶意软件！";

            LogWarning(message);

            UEFIThreatDetection detection = new UEFIThreatDetection
            {
                Id = Guid.NewGuid().ToString(),
                FilePath = $"UEFI/{manufacturer}/{version}",
                ThreatType = "FirmwareModification",
                ThreatName = "UEFI固件修改",
                Confidence = 1.0,
                DetectionTime = DateTime.Now,
                DetectionMethod = "UEFIMonitor",
                AdditionalInfo = message
            };
            dataManager.LogThreat($"检测到UEFI固件修改", $"威胁类型: FirmwareModification, 详细信息: {message}");
            
            // 弹窗警告
            ShowThreatNotification("UEFI固件修改警告", message, NotificationType.Error);

            string firmwareKey = $"FIRMWARE-{manufacturer}-{version}";
            if (uefiRecords.ContainsKey(firmwareKey))
            {
                uefiRecords[firmwareKey].SerialNumber = newSerial;
                uefiRecords[firmwareKey].LastChecked = DateTime.Now;
                SaveUEFIRecords();
            }
        }

        public List<BootEntry> GetBootEntries()
        {
            return new List<BootEntry>(bootEntries);
        }

        public Dictionary<string, UEFIRecord> GetUEFIRecords()
        {
            return new Dictionary<string, UEFIRecord>(uefiRecords);
        }

        public bool IsSecureBootEnabled()
        {
            return CheckSecureBootStatus();
        }

        public void UpdateBaseline()
        {
            LogInfo("更新UEFI基线...");
            uefiRecords.Clear();
            bootEntryHashes.Clear();
            secureBootHashes.Clear();
            InitializeBootEntries();
            CheckBootEntries();
            CheckSecureBoot();
            CheckFirmware();
            SaveUEFIRecords();
            LogInfo("UEFI基线更新完成");
        }

        public void SetCheckInterval(int milliseconds)
        {
            checkInterval = milliseconds;
        }

        public void SetBootEntryMonitoring(bool enabled)
        {
            enableBootEntryMonitoring = enabled;
        }

        public void SetSecureBootMonitoring(bool enabled)
        {
            enableSecureBootMonitoring = enabled;
        }

        public void SetFirmwareMonitoring(bool enabled)
        {
            enableFirmwareMonitoring = enabled;
        }

        private void LogInfo(string message)
        {
            dataManager.LogInfo("[UEFI监控] " + message);
        }

        private void LogWarning(string message)
        {
            dataManager.LogWarning("[UEFI监控] " + message);
        }

        private void LogError(string message)
        {
            dataManager.LogError("[UEFI监控] " + message);
        }
        
        private void ShowThreatNotification(string title, string message, NotificationType type)
        {
            try
            {
                NotificationService.Instance.ShowNotification(title, message, type);
            }
            catch { }
        }
    }

    public class BootEntry
    {
        public string Identifier { get; set; }
        public string Device { get; set; }
        public string Path { get; set; }
        public string Description { get; set; }
    }

    public class UEFIRecord
    {
        public string Identifier { get; set; }
        public string Device { get; set; }
        public string Path { get; set; }
        public string Description { get; set; }
        public string Manufacturer { get; set; }
        public string Version { get; set; }
        public string SerialNumber { get; set; }
        public DateTime? ReleaseDate { get; set; }
        public DateTime LastChecked { get; set; }
    }

    public class UEFIThreatDetection
    {
        public string Id { get; set; }
        public string FilePath { get; set; }
        public string ThreatType { get; set; }
        public string ThreatName { get; set; }
        public double Confidence { get; set; }
        public DateTime DetectionTime { get; set; }
        public string DetectionMethod { get; set; }
        public string ActionTaken { get; set; }
        public string AdditionalInfo { get; set; }
    }
}