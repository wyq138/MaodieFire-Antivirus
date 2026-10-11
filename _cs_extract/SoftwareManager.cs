using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using Microsoft.Win32;
using FireAntivirus.Data;
using FireAntivirus.Engine;

namespace FireAntivirus.Services
{
    public class SoftwareManager
    {
        private DataManager dataManager;
        private AntivirusEngine antivirusEngine;

        public SoftwareManager(DataManager dataManager, AntivirusEngine antivirusEngine)
        {
            this.dataManager = dataManager;
            this.antivirusEngine = antivirusEngine;
        }

        public List<SoftwareInfo> GetInstalledSoftware()
        {
            List<SoftwareInfo> softwareList = new List<SoftwareInfo>();

            try
            {
                softwareList.AddRange(GetRegistrySoftware());
                softwareList.AddRange(GetWmiSoftware());
                softwareList.AddRange(GetProgramFilesSoftware());

                dataManager.LogInfo($"成功获取 {softwareList.Count} 个已安装软件");
            }
            catch (Exception ex)
            {
                dataManager.LogError($"获取已安装软件失败: {ex.Message}");
            }

            return softwareList;
        }

        private List<SoftwareInfo> GetRegistrySoftware()
        {
            List<SoftwareInfo> softwareList = new List<SoftwareInfo>();

            try
            {
                string[] registryPaths = {
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                    @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
                };

                foreach (string registryPath in registryPaths)
                {
                    try
                    {
                        using (RegistryKey key = Registry.LocalMachine.OpenSubKey(registryPath))
                        {
                            if (key != null)
                            {
                                foreach (string subKeyName in key.GetSubKeyNames())
                                {
                                    try
                                    {
                                        using (RegistryKey subKey = key.OpenSubKey(subKeyName))
                                        {
                                            if (subKey != null)
                                            {
                                                object displayName = subKey.GetValue("DisplayName");
                                                object displayVersion = subKey.GetValue("DisplayVersion");
                                                object publisher = subKey.GetValue("Publisher");
                                                object installDate = subKey.GetValue("InstallDate");
                                                object installLocation = subKey.GetValue("InstallLocation");
                                                object uninstallString = subKey.GetValue("UninstallString");

                                                if (displayName != null)
                                                {
                                                    SoftwareInfo software = new SoftwareInfo
                                                    {
                                                        Name = displayName.ToString(),
                                                        Version = displayVersion?.ToString() ?? "Unknown",
                                                        Publisher = publisher?.ToString() ?? "Unknown",
                                                        InstallDate = ParseInstallDate(installDate?.ToString()),
                                                        InstallLocation = installLocation?.ToString() ?? "",
                                                        UninstallString = uninstallString?.ToString() ?? "",
                                                        Source = "Registry"
                                                    };

                                                    softwareList.Add(software);
                                                }
                                            }
                                        }
                                    }
                                    catch
                                    {
                                    }
                                }
                            }
                        }
                    }
                    catch
                    {
                    }
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"从注册表获取软件失败: {ex.Message}");
            }

            return softwareList;
        }

        private List<SoftwareInfo> GetWmiSoftware()
        {
            List<SoftwareInfo> softwareList = new List<SoftwareInfo>();

            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Product"))
                {
                    foreach (ManagementObject product in searcher.Get())
                    {
                        try
                        {
                            string name = product["Name"]?.ToString();
                            string version = product["Version"]?.ToString();
                            string vendor = product["Vendor"]?.ToString();
                            string installDate = product["InstallDate"]?.ToString();
                            string installLocation = product["InstallLocation"]?.ToString();

                            if (!string.IsNullOrEmpty(name))
                            {
                                SoftwareInfo software = new SoftwareInfo
                                {
                                    Name = name,
                                    Version = version ?? "Unknown",
                                    Publisher = vendor ?? "Unknown",
                                    InstallDate = ParseInstallDate(installDate),
                                    InstallLocation = installLocation ?? "",
                                    Source = "WMI"
                                };

                                softwareList.Add(software);
                            }
                        }
                        catch
                        {
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"从WMI获取软件失败: {ex.Message}");
            }

            return softwareList;
        }

        private List<SoftwareInfo> GetProgramFilesSoftware()
        {
            List<SoftwareInfo> softwareList = new List<SoftwareInfo>();

            try
            {
                string[] programFilesPaths = {
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)
                };

                foreach (string programFilesPath in programFilesPaths)
                {
                    if (Directory.Exists(programFilesPath))
                    {
                        try
                        {
                            foreach (string directory in Directory.GetDirectories(programFilesPath))
                            {
                                try
                                {
                                    string directoryName = Path.GetFileName(directory);
                                    if (directoryName.StartsWith("Microsoft") || directoryName.StartsWith("Windows"))
                                        continue;

                                    SoftwareInfo software = new SoftwareInfo
                                    {
                                        Name = directoryName,
                                        Version = "Unknown",
                                        Publisher = "Unknown",
                                        InstallDate = null,
                                        InstallLocation = directory,
                                        Source = "ProgramFiles"
                                    };

                                    softwareList.Add(software);
                                }
                                catch
                                {
                                }
                            }
                        }
                        catch
                        {
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"从Program Files获取软件失败: {ex.Message}");
            }

            return softwareList;
        }

        public bool UninstallSoftware(SoftwareInfo software)
        {
            try
            {
                if (!string.IsNullOrEmpty(software.UninstallString))
                {
                    string uninstallCommand = software.UninstallString;
                    if (uninstallCommand.StartsWith("\""))
                    {
                        int endQuoteIndex = uninstallCommand.IndexOf("\"", 1);
                        if (endQuoteIndex > 0)
                        {
                            string uninstallPath = uninstallCommand.Substring(1, endQuoteIndex - 1);
                            string arguments = uninstallCommand.Substring(endQuoteIndex + 1).Trim();

                            ProcessStartInfo startInfo = new ProcessStartInfo
                            {
                                FileName = uninstallPath,
                                Arguments = arguments + " /SILENT /NORESTART",
                                Verb = "runas",
                                UseShellExecute = true
                            };

                            using (Process process = Process.Start(startInfo))
                            {
                                process.WaitForExit();
                                return process.ExitCode == 0;
                            }
                        }
                    }
                    else
                    {
                        ProcessStartInfo startInfo = new ProcessStartInfo
                        {
                            FileName = "cmd.exe",
                            Arguments = $"/c {uninstallCommand} /SILENT /NORESTART",
                            Verb = "runas",
                            UseShellExecute = true
                        };

                        using (Process process = Process.Start(startInfo))
                        {
                            process.WaitForExit();
                            return process.ExitCode == 0;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"卸载软件失败: {ex.Message}");
            }

            return false;
        }

        public List<SoftwareInfo> GetOutdatedSoftware()
        {
            List<SoftwareInfo> outdatedSoftware = new List<SoftwareInfo>();
            List<SoftwareInfo> allSoftware = GetInstalledSoftware();

            foreach (var software in allSoftware)
            {
                try
                {
                    if (IsSoftwareOutdated(software))
                    {
                        outdatedSoftware.Add(software);
                    }
                }
                catch
                {
                }
            }

            return outdatedSoftware;
        }

        private bool IsSoftwareOutdated(SoftwareInfo software)
        {
            // 这里可以实现检查软件是否过期的逻辑
            // 例如通过版本号比较或在线检查
            // 这里仅作为示例
            return false;
        }

        public List<SoftwareInfo> GetSoftwareByPublisher(string publisher)
        {
            List<SoftwareInfo> softwareList = GetInstalledSoftware();
            return softwareList.Where(s => s.Publisher.Contains(publisher, StringComparison.OrdinalIgnoreCase)).ToList();
        }

        public List<SoftwareInfo> GetSoftwareByName(string name)
        {
            List<SoftwareInfo> softwareList = GetInstalledSoftware();
            return softwareList.Where(s => s.Name.Contains(name, StringComparison.OrdinalIgnoreCase)).ToList();
        }

        public long GetSoftwareSize(SoftwareInfo software)
        {
            try
            {
                if (!string.IsNullOrEmpty(software.InstallLocation) && Directory.Exists(software.InstallLocation))
                {
                    return GetDirectorySize(software.InstallLocation);
                }
            }
            catch
            {
            }

            return 0;
        }

        private long GetDirectorySize(string path)
        {
            long size = 0;
            try
            {
                foreach (string file in Directory.GetFiles(path, "*.*", SearchOption.AllDirectories))
                {
                    try
                    {
                        size += new FileInfo(file).Length;
                    }
                    catch
                    {
                    }
                }
            }
            catch
            {
            }
            return size;
        }

        public bool IsSoftwareSafe(SoftwareInfo software)
        {
            try
            {
                if (!string.IsNullOrEmpty(software.InstallLocation))
                {
                    return antivirusEngine.ScanDirectory(software.InstallLocation).Count == 0;
                }
            }
            catch
            {
            }

            return true;
        }

        public List<SoftwareInfo> GetUnsafeSoftware()
        {
            List<SoftwareInfo> unsafeSoftware = new List<SoftwareInfo>();
            List<SoftwareInfo> allSoftware = GetInstalledSoftware();

            foreach (var software in allSoftware)
            {
                try
                {
                    if (!IsSoftwareSafe(software))
                    {
                        unsafeSoftware.Add(software);
                    }
                }
                catch
                {
                }
            }

            return unsafeSoftware;
        }

        public List<SoftwareInfo> GetUpdatableSoftware()
        {
            List<SoftwareInfo> updatableSoftware = new List<SoftwareInfo>();
            List<SoftwareInfo> allSoftware = GetInstalledSoftware();

            foreach (var software in allSoftware)
            {
                try
                {
                    if (!string.IsNullOrEmpty(software.InstallLocation) && Directory.Exists(software.InstallLocation))
                    {
                        string updateFile = Path.Combine(software.InstallLocation, "update.exe");
                        string setupFile = Path.Combine(software.InstallLocation, "setup.exe");

                        if (File.Exists(updateFile) || File.Exists(setupFile))
                        {
                            updatableSoftware.Add(software);
                        }
                    }
                }
                catch
                {
                }
            }

            return updatableSoftware;
        }

        private DateTime? ParseInstallDate(string installDate)
        {
            if (string.IsNullOrEmpty(installDate))
                return null;

            try
            {
                if (installDate.Length == 8)
                {
                    int year = int.Parse(installDate.Substring(0, 4));
                    int month = int.Parse(installDate.Substring(4, 2));
                    int day = int.Parse(installDate.Substring(6, 2));
                    return new DateTime(year, month, day);
                }
                else if (DateTime.TryParse(installDate, out DateTime date))
                {
                    return date;
                }
            }
            catch
            {
            }

            return null;
        }
    }

    public class SoftwareInfo
    {
        public string Name { get; set; }
        public string Version { get; set; }
        public string Publisher { get; set; }
        public DateTime? InstallDate { get; set; }
        public string InstallLocation { get; set; }
        public string UninstallString { get; set; }
        public string Source { get; set; }
        public long Size { get; set; }
    }

    public static class ManagementDateTimeConverter
    {
        public static DateTime ToDateTime(string dmtfDate)
        {
            try
            {
                if (string.IsNullOrEmpty(dmtfDate))
                    return DateTime.MinValue;

                int year = int.Parse(dmtfDate.Substring(0, 4));
                int month = int.Parse(dmtfDate.Substring(4, 2));
                int day = int.Parse(dmtfDate.Substring(6, 2));
                int hour = int.Parse(dmtfDate.Substring(8, 2));
                int minute = int.Parse(dmtfDate.Substring(10, 2));
                int second = int.Parse(dmtfDate.Substring(12, 2));

                return new DateTime(year, month, day, hour, minute, second, DateTimeKind.Utc).ToLocalTime();
            }
            catch
            {
                return DateTime.MinValue;
            }
        }
    }
}
