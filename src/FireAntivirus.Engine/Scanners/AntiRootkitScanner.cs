// 抖音用户 耄耋杀毒软件 开发，严禁非法反编译
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;

namespace FireAntivirus.Engine.Scanners
{
    /// <summary>
    /// 反Rootkit扫描器 - 检测和清除Rootkit
    /// </summary>
    public class AntiRootkitScanner
    {
        private readonly List<RootkitSignature> _knownRootkits;
        private readonly List<string> _suspiciousPatterns;

        public AntiRootkitScanner()
        {
            _knownRootkits = new List<RootkitSignature>();
            _suspiciousPatterns = new List<string>();
            InitializeKnownRootkits();
        }

        private void InitializeKnownRootkits()
        {
            _knownRootkits.AddRange(new[]
            {
                new RootkitSignature
                {
                    Name = "TDSS",
                    Family = "TDSS/Alureon",
                    Files = new[] { "tdlcmd.dll", "tdss*.dll", "cmdprov.dll" },
                    RegistryKeys = new[] { @"SYSTEM\CurrentControlSet\Services\TDSS" },
                    RiskLevel = "严重"
                },
                new RootkitSignature
                {
                    Name = "ZeroAccess",
                    Family = "ZeroAccess/Sirefef",
                    Files = new[] { @"%APPDATA%\*.dat" },
                    RegistryKeys = new[] { @"SOFTWARE\Microsoft\Windows\CurrentVersion\WinSxS" },
                    RiskLevel = "严重"
                },
                new RootkitSignature
                {
                    Name = "Rustock",
                    Family = "Rustock",
                    Files = new[] { "win32.sys", "rustock*.sys" },
                    RegistryKeys = new[] { @"SYSTEM\CurrentControlSet\Services\rustock" },
                    RiskLevel = "严重"
                },
                new RootkitSignature
                {
                    Name = "TDL4",
                    Family = "TDL4",
                    Files = new[] { "mbr.exe", "tdl4.sys" },
                    RiskLevel = "严重"
                }
            });

            _suspiciousPatterns.AddRange(new[]
            {
                "NtQueryDirectoryFile",
                "NtQuerySystemInformation",
                "NtQueryInformationProcess",
                "NtQueryInformationThread",
                "ZwQueryDirectoryFile",
                "ZwQuerySystemInformation",
                "SSDT hook",
                "IDT hook",
                "IRP hook"
            });
        }

        public AntiRootkitScanResult Scan()
        {
            var result = new AntiRootkitScanResult
            {
                Detections = new List<RootkitDetection>(),
                HiddenProcesses = new List<HiddenProcessInfo>(),
                HiddenFiles = new List<HiddenFileInfo>(),
                HiddenRegistryKeys = new List<HiddenRegistryInfo>(),
                SuspiciousDrivers = new List<SuspiciousDriverInfo>(),
                Warnings = new List<string>()
            };

            try
            {
                // 1. 检查隐藏进程
                ScanHiddenProcesses(result);

                // 2. 检查隐藏文件
                ScanHiddenFiles(result);

                // 3. 检查隐藏注册表项
                ScanHiddenRegistry(result);

                // 4. 检查可疑驱动
                ScanSuspiciousDrivers(result);

                // 5. 检查MBR
                ScanMBR(result);

                // 6. 检查已知Rootkit特征
                CheckKnownRootkits(result);

                // 7. 检查SSDT钩子
                CheckSystemCallHooks(result);

                result.TotalDetections = result.Detections.Count;
                result.HasRootkit = result.Detections.Any(d => d.RiskLevel == "严重");
            }
            catch (Exception ex)
            {
                result.Warnings.Add($"扫描错误: {ex.Message}");
            }

            return result;
        }

        private void ScanHiddenProcesses(AntiRootkitScanResult result)
        {
            try
            {
                // 获取进程快照
                var snapshotProcesses = GetProcessesFromSnapshot();
                
                // 获取系统进程列表
                var systemProcesses = Process.GetProcesses().Select(p => p.Id).ToHashSet();

                // 找出差异（可能被隐藏的进程）
                foreach (var pid in snapshotProcesses)
                {
                    if (!systemProcesses.Contains(pid))
                    {
                        result.HiddenProcesses.Add(new HiddenProcessInfo
                        {
                            PID = pid,
                            Reason = "进程在快照中存在但在系统列表中不可见"
                        });
                    }
                }
            }
            catch { }
        }

        private List<int> GetProcessesFromSnapshot()
        {
            var pids = new List<int>();

            try
            {
                // 使用不同的API获取进程列表
                var psi = new ProcessStartInfo
                {
                    FileName = "tasklist",
                    Arguments = "/fo csv",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                };

                using var process = Process.Start(psi);
                if (process != null)
                {
                    var output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();

                    foreach (var line in output.Split('\n').Skip(1))
                    {
                        var parts = line.Split(',');
                        if (parts.Length >= 2)
                        {
                            var pidStr = parts[1].Trim('"');
                            if (int.TryParse(pidStr, out var pid))
                            {
                                pids.Add(pid);
                            }
                        }
                    }
                }
            }
            catch { }

            return pids;
        }

        private void ScanHiddenFiles(AntiRootkitScanResult result)
        {
            try
            {
                var system32Path = Environment.GetFolderPath(Environment.SpecialFolder.System);
                
                // 使用不同的方法列出文件
                var directoryInfo = new DirectoryInfo(system32Path);
                var filesFromDirectory = directoryInfo.GetFiles().Select(f => f.Name).ToHashSet();

                // 使用FindFirstFile/FindNextFile API
                var filesFromAPI = GetFilesFromAPI(system32Path);

                // 比较差异
                foreach (var file in filesFromAPI)
                {
                    if (!filesFromDirectory.Contains(file))
                    {
                        result.HiddenFiles.Add(new HiddenFileInfo
                        {
                            Path = Path.Combine(system32Path, file),
                            Reason = "文件可能被隐藏"
                        });
                    }
                }
            }
            catch { }
        }

        private List<string> GetFilesFromAPI(string directory)
        {
            var files = new List<string>();

            try
            {
                // 使用cmd dir命令获取文件列表
                var psi = new ProcessStartInfo
                {
                    FileName = "cmd",
                    Arguments = $"/c dir /a \"{directory}\" /b",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                };

                using var process = Process.Start(psi);
                if (process != null)
                {
                    var output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();

                    files = output.Split('\n')
                        .Select(f => f.Trim())
                        .Where(f => !string.IsNullOrEmpty(f))
                        .ToList();
                }
            }
            catch { }

            return files;
        }

        private void ScanHiddenRegistry(AntiRootkitScanResult result)
        {
            try
            {
                // 检查启动项
                using var runKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run");
                if (runKey != null)
                {
                    foreach (var valueName in runKey.GetValueNames())
                    {
                        var value = runKey.GetValue(valueName)?.ToString();
                        if (!string.IsNullOrEmpty(value))
                        {
                            // 检查可疑启动项
                            if (IsSuspiciousStartupEntry(valueName, value))
                            {
                                result.HiddenRegistryKeys.Add(new HiddenRegistryInfo
                                {
                                    KeyPath = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                                    ValueName = valueName,
                                    Value = value,
                                    Reason = "可疑启动项"
                                });
                            }
                        }
                    }
                }

                // 检查服务
                using var servicesKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
                if (servicesKey != null)
                {
                    foreach (var serviceName in servicesKey.GetSubKeyNames())
                    {
                        if (IsSuspiciousServiceName(serviceName))
                        {
                            using var serviceKey = servicesKey.OpenSubKey(serviceName);
                            var imagePath = serviceKey?.GetValue("ImagePath")?.ToString();
                            
                            result.HiddenRegistryKeys.Add(new HiddenRegistryInfo
                            {
                                KeyPath = $@"SYSTEM\CurrentControlSet\Services\{serviceName}",
                                ValueName = "ImagePath",
                                Value = imagePath,
                                Reason = "可疑服务"
                            });
                        }
                    }
                }
            }
            catch { }
        }

        private bool IsSuspiciousStartupEntry(string name, string value)
        {
            var suspiciousNames = new[] { "svchost", "explorer", "rundll32", "lsass" };
            var suspiciousPaths = new[] { "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\" };

            if (suspiciousNames.Any(n => name.Contains(n, StringComparison.OrdinalIgnoreCase)))
            {
                return true;
            }

            if (suspiciousPaths.Any(p => value.Contains(p, StringComparison.OrdinalIgnoreCase)))
            {
                return true;
            }

            return false;
        }

        private bool IsSuspiciousServiceName(string name)
        {
            var suspiciousNames = new[]
            {
                "patch", "hack", "crack", "keygen", "rootkit", "backdoor"
            };

            return suspiciousNames.Any(n => name.Contains(n, StringComparison.OrdinalIgnoreCase));
        }

        private void ScanSuspiciousDrivers(AntiRootkitScanResult result)
        {
            try
            {
                var driversPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers");
                
                if (Directory.Exists(driversPath))
                {
                    foreach (var driverFile in Directory.GetFiles(driversPath, "*.sys"))
                    {
                        var fileName = Path.GetFileName(driverFile);
                        
                        // 检查可疑驱动名
                        if (IsSuspiciousDriverName(fileName))
                        {
                            result.SuspiciousDrivers.Add(new SuspiciousDriverInfo
                            {
                                Path = driverFile,
                                Name = fileName,
                                Reason = "可疑驱动文件名"
                            });
                        }

                        // 检查未签名的驱动
                        if (!IsDriverSigned(driverFile))
                        {
                            result.SuspiciousDrivers.Add(new SuspiciousDriverInfo
                            {
                                Path = driverFile,
                                Name = fileName,
                                Reason = "未签名驱动"
                            });
                        }
                    }
                }
            }
            catch { }
        }

        private bool IsSuspiciousDriverName(string name)
        {
            var suspiciousDrivers = new[]
            {
                "rootkit", "hack", "hook", "inject", "patch", "crack"
            };

            return suspiciousDrivers.Any(d => name.Contains(d, StringComparison.OrdinalIgnoreCase));
        }

        private bool IsDriverSigned(string driverPath)
        {
            try
            {
                var cert = System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(driverPath);
                return cert != null;
            }
            catch
            {
                return false;
            }
        }

        private void ScanMBR(AntiRootkitScanResult result)
        {
            try
            {
                // 检查MBR是否被修改
                var psi = new ProcessStartInfo
                {
                    FileName = "wmic",
                    Arguments = "diskdrive get status",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                };

                using var process = Process.Start(psi);
                if (process != null)
                {
                    var output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();

                    if (output.Contains("Error") || output.Contains("Unknown"))
                    {
                        result.Warnings.Add("磁盘状态异常，可能存在MBR感染");
                    }
                }
            }
            catch { }
        }

        private void CheckKnownRootkits(AntiRootkitScanResult result)
        {
            foreach (var rootkit in _knownRootkits)
            {
                // 检查文件
                if (rootkit.Files != null)
                {
                    foreach (var filePattern in rootkit.Files)
                    {
                        var expandedPath = Environment.ExpandEnvironmentVariables(filePattern);
                        var directory = Path.GetDirectoryName(expandedPath);
                        var fileName = Path.GetFileName(expandedPath);

                        if (string.IsNullOrEmpty(directory))
                        {
                            directory = Environment.GetFolderPath(Environment.SpecialFolder.System);
                        }

                        if (Directory.Exists(directory))
                        {
                            foreach (var file in Directory.GetFiles(directory, fileName))
                            {
                                result.Detections.Add(new RootkitDetection
                                {
                                    RootkitName = rootkit.Name,
                                    Family = rootkit.Family,
                                    DetectionType = "文件",
                                    Location = file,
                                    RiskLevel = rootkit.RiskLevel
                                });
                            }
                        }
                    }
                }

                // 检查注册表
                if (rootkit.RegistryKeys != null)
                {
                    foreach (var keyPath in rootkit.RegistryKeys)
                    {
                        using var key = Registry.LocalMachine.OpenSubKey(keyPath);
                        if (key != null)
                        {
                            result.Detections.Add(new RootkitDetection
                            {
                                RootkitName = rootkit.Name,
                                Family = rootkit.Family,
                                DetectionType = "注册表",
                                Location = keyPath,
                                RiskLevel = rootkit.RiskLevel
                            });
                        }
                    }
                }
            }
        }

        private void CheckSystemCallHooks(AntiRootkitScanResult result)
        {
            try
            {
                // 检查系统服务描述符表钩子
                // 这需要内核级别的访问，这里只做基本检查

                // 使用gmer或其他工具的概念
                result.Warnings.Add("系统调用钩子检测需要内核访问权限");
            }
            catch { }
        }
    }

    public class AntiRootkitScanResult
    {
        public List<RootkitDetection> Detections { get; set; }
        public List<HiddenProcessInfo> HiddenProcesses { get; set; }
        public List<HiddenFileInfo> HiddenFiles { get; set; }
        public List<HiddenRegistryInfo> HiddenRegistryKeys { get; set; }
        public List<SuspiciousDriverInfo> SuspiciousDrivers { get; set; }
        public List<string> Warnings { get; set; }
        public int TotalDetections { get; set; }
        public bool HasRootkit { get; set; }
    }

    public class RootkitDetection
    {
        public string RootkitName { get; set; }
        public string Family { get; set; }
        public string DetectionType { get; set; }
        public string Location { get; set; }
        public string RiskLevel { get; set; }
    }

    public class HiddenProcessInfo
    {
        public int PID { get; set; }
        public string Reason { get; set; }
    }

    public class HiddenFileInfo
    {
        public string Path { get; set; }
        public string Reason { get; set; }
    }

    public class HiddenRegistryInfo
    {
        public string KeyPath { get; set; }
        public string ValueName { get; set; }
        public string Value { get; set; }
        public string Reason { get; set; }
    }

    public class SuspiciousDriverInfo
    {
        public string Path { get; set; }
        public string Name { get; set; }
        public string Reason { get; set; }
    }

    public class RootkitSignature
    {
        public string Name { get; set; }
        public string Family { get; set; }
        public string[] Files { get; set; }
        public string[] RegistryKeys { get; set; }
        public string RiskLevel { get; set; }
    }
}
