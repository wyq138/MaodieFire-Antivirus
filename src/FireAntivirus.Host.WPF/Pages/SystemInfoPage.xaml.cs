// 抖音用户 耄耋杀毒软件 开发，严禁非法反编译
using System;
using System.Collections.Generic;
using System.Management;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using FireAntivirus.Common.Localization;

using FireAntivirus.Host.WPF;

namespace FireAntivirus.Host.WPF.Pages
{
    /// <summary>
    /// 系统信息页面 - 从WinForms转换
    /// </summary>
    public partial class SystemInfoPage : Page, IThemed
    {
        private Theme currentTheme = Theme.Light;
        private DispatcherTimer updateTimer;
        private System.Threading.CancellationTokenSource _cts = new();
        private bool _isLoaded = false;
        private LanguageManager _languageManager = LanguageManager.Instance;

        // 缓存机制
        private static Dictionary<string, object> infoCache = new Dictionary<string, object>();
        private static Dictionary<string, DateTime> cacheTimestamps = new Dictionary<string, DateTime>();
        private const int CACHE_DURATION_SECONDS = 30;

        public SystemInfoPage()
        {
            try
            {
                InitializeComponent();
                
                // 订阅语言变更事件
                _languageManager.LanguageChanged += (sender, e) => UpdateLanguage();
                
                // 页面加载时自动加载数据
                Loaded += (s, e) =>

                // 页面卸载时停止后台任务
                Unloaded += (s, e) =>
                {
                    _isLoaded = false;
                    _cts?.Cancel();
                    updateTimer?.Stop();
                };
                {
                    LoadSystemInfo();
                    InitializeTimer();
                    updateTimer.Start();
                };
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error initializing SystemInfoPage: {ex.Message}");
            }
        }

        private void InitializeTimer()
        {
            updateTimer = new DispatcherTimer();
            updateTimer.Interval = TimeSpan.FromSeconds(10);
            updateTimer.Tick += UpdateTimer_Tick;
        }

        private void UpdateTimer_Tick(object sender, EventArgs e)
        {
            UpdateDynamicInfo();
        }

        private void LoadSystemInfo()
        {
            _isLoaded = true;
            Task.Run(async () =>
            {
                try
                {
                    var osInfo = await Task.Run(() => GetOSInfo());
                    var cpuInfo = await Task.Run(() => GetCPUInfo());
                    var memoryInfo = await Task.Run(() => GetMemoryInfo());
                    var diskInfo = await Task.Run(() => GetDiskInfo());
                    var systemInfo = await Task.Run(() => GetSystemInfo());

                                        if (!_cts.Token.IsCancellationRequested) Dispatcher.BeginInvoke(new Action(() =>
                    {
                        try
                        {
                            // 更新操作系统信息
                            OSNameLabel.Text = osInfo[0];
                            OSVersionLabel.Text = osInfo[1];
                            OSArchLabel.Text = osInfo[2];
                            OSInstallDateLabel.Text = osInfo[3];
                            OSSystemDirLabel.Text = osInfo[4];

                            // 更新处理器信息
                            CPUNameLabel.Text = cpuInfo[0];
                            CPUManufacturerLabel.Text = cpuInfo[1];
                            CPUCoresLabel.Text = cpuInfo[2];
                            CPULogicalLabel.Text = cpuInfo[3];
                            CPUSpeedLabel.Text = cpuInfo[4];

                            // 更新内存信息
                            MemoryTotalLabel.Text = memoryInfo[0];
                            MemoryAvailableLabel.Text = memoryInfo[1];
                            MemoryUsageLabel.Text = memoryInfo[2];
                            MemoryVisibleLabel.Text = memoryInfo[3];
                            MemoryFreeLabel.Text = memoryInfo[4];

                            // 更新磁盘信息
                            Disk1Label.Text = diskInfo.Length > 0 ? diskInfo[0] : "无数据";
                            Disk2Label.Text = diskInfo.Length > 1 ? diskInfo[1] : "无数据";
                            Disk3Label.Text = diskInfo.Length > 2 ? diskInfo[2] : "无数据";
                            Disk4Label.Text = diskInfo.Length > 3 ? diskInfo[3] : "无数据";
                            Disk5Label.Text = diskInfo.Length > 4 ? diskInfo[4] : "";

                            // 更新系统信息
                            SystemManufacturerLabel.Text = systemInfo[0];
                            SystemModelLabel.Text = systemInfo[1];
                            SystemMemoryLabel.Text = systemInfo[2];
                            SystemBootTimeLabel.Text = systemInfo[3];
                            SystemComputerNameLabel.Text = systemInfo[4];
                        }
                        catch { }
                    }));
                }
                catch { }
            });
        }

        private void UpdateDynamicInfo()
        {
            Task.Run(() =>
            {
                try
                {
                    var memoryInfo = GetMemoryInfo();
                    var diskInfo = GetDiskInfo();

                                        if (!_cts.Token.IsCancellationRequested) Dispatcher.BeginInvoke(new Action(() =>
                    {
                        // 更新内存信息
                        MemoryTotalLabel.Text = memoryInfo[0];
                        MemoryAvailableLabel.Text = memoryInfo[1];
                        MemoryUsageLabel.Text = memoryInfo[2];
                        MemoryVisibleLabel.Text = memoryInfo[3];
                        MemoryFreeLabel.Text = memoryInfo[4];

                        // 更新磁盘信息
                        Disk1Label.Text = diskInfo.Length > 0 ? diskInfo[0] : "无数据";
                        Disk2Label.Text = diskInfo.Length > 1 ? diskInfo[1] : "无数据";
                        Disk3Label.Text = diskInfo.Length > 2 ? diskInfo[2] : "无数据";
                        Disk4Label.Text = diskInfo.Length > 3 ? diskInfo[3] : "无数据";
                    }));
                }
                catch { }
            });
        }

        private bool IsCacheValid(string key)
        {
            if (!cacheTimestamps.ContainsKey(key))
                return false;
            return (DateTime.Now - cacheTimestamps[key]).TotalSeconds < CACHE_DURATION_SECONDS;
        }

        private void UpdateCache(string key, object value)
        {
            infoCache[key] = value;
            cacheTimestamps[key] = DateTime.Now;
        }

        private string[] GetOSInfo()
        {
            const string cacheKey = "OSInfo";
            if (IsCacheValid(cacheKey))
                return (string[])infoCache[cacheKey];

            try
            {
                ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT Caption, Version, BuildNumber, OSArchitecture, InstallDate, SystemDirectory FROM Win32_OperatingSystem");
                foreach (ManagementObject os in searcher.Get())
                {
                    var result = new string[]
                    {
                        $"操作系统: {os["Caption"]?.ToString() ?? "未知"}",
                        $"版本: {os["Version"]?.ToString() ?? "未知"} (Build {os["BuildNumber"]?.ToString() ?? "未知"})",
                        $"架构: {os["OSArchitecture"]?.ToString() ?? "未知"}",
                        $"安装日期: {GetInstallDate(os)}",
                        $"系统目录: {os["SystemDirectory"]?.ToString() ?? "未知"}"
                    };
                    UpdateCache(cacheKey, result);
                    return result;
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"GetOSInfo error: {ex.Message}");
            }

            var defaultResult = new string[]
            {
                "操作系统: 未知",
                "版本: 未知",
                "架构: 未知",
                "安装日期: 未知",
                "系统目录: 未知"
            };
            UpdateCache(cacheKey, defaultResult);
            return defaultResult;
        }

        private string GetInstallDate(ManagementObject os)
        {
            try
            {
                var installDate = os["InstallDate"]?.ToString();
                if (!string.IsNullOrEmpty(installDate))
                {
                    return ManagementDateTimeConverter.ToDateTime(installDate).ToString("yyyy-MM-dd HH:mm:ss");
                }
                return "未知";
            }
            catch
            {
                return "未知";
            }
        }

        private string[] GetCPUInfo()
        {
            const string cacheKey = "CPUInfo";
            if (IsCacheValid(cacheKey))
                return (string[])infoCache[cacheKey];

            try
            {
                ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT Name, Manufacturer, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed FROM Win32_Processor");
                foreach (ManagementObject cpu in searcher.Get())
                {
                    var result = new string[]
                    {
                        $"处理器: {cpu["Name"]?.ToString() ?? "未知"}",
                        $"制造商: {cpu["Manufacturer"]?.ToString() ?? "未知"}",
                        $"核心数: {cpu["NumberOfCores"]?.ToString() ?? "未知"}",
                        $"逻辑处理器: {cpu["NumberOfLogicalProcessors"]?.ToString() ?? "未知"}",
                        $"最大时钟速度: {cpu["MaxClockSpeed"]?.ToString() ?? "未知"} MHz"
                    };
                    UpdateCache(cacheKey, result);
                    return result;
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"GetCPUInfo error: {ex.Message}");
            }

            var defaultResult = new string[]
            {
                "处理器: 未知",
                "制造商: 未知",
                "核心数: 未知",
                "逻辑处理器: 未知",
                "最大时钟速度: 未知"
            };
            UpdateCache(cacheKey, defaultResult);
            return defaultResult;
        }

        private string[] GetMemoryInfo()
        {
            try
            {
                ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystem");
                ulong totalPhysicalMemory = 0;
                foreach (ManagementObject computer in searcher.Get())
                {
                    totalPhysicalMemory = (ulong)(computer["TotalPhysicalMemory"] ?? 0);
                    break;
                }

                ulong freePhysicalMemory = 0;
                ulong totalVisibleMemorySize = 0;
                searcher = new ManagementObjectSearcher("SELECT * FROM Win32_OperatingSystem");
                foreach (ManagementObject os in searcher.Get())
                {
                    freePhysicalMemory = (ulong)(os["FreePhysicalMemory"] ?? 0);
                    totalVisibleMemorySize = (ulong)(os["TotalVisibleMemorySize"] ?? 0);
                    break;
                }

                double totalMemoryGB = totalPhysicalMemory / (1024.0 * 1024.0 * 1024.0);
                double availableMemoryGB = freePhysicalMemory / (1024.0 * 1024.0);
                int usagePercent = totalVisibleMemorySize > 0 ? (int)((totalVisibleMemorySize - freePhysicalMemory) * 100 / totalVisibleMemorySize) : 0;

                return new string[]
                {
                    $"物理内存: {Math.Round(totalMemoryGB, 2)} GB",
                    $"可用内存: {Math.Round(availableMemoryGB, 2)} GB",
                    $"内存使用率: {usagePercent}%",
                    $"总可见内存: {totalVisibleMemorySize / (1024 * 1024)} MB",
                    $"可用物理内存: {freePhysicalMemory / 1024} MB"
                };
            }
            catch
            {
                return new string[]
                {
                    "物理内存: 未知",
                    "可用内存: 未知",
                    "内存使用率: 未知",
                    "总可见内存: 未知",
                    "可用物理内存: 未知"
                };
            }
        }

        private string[] GetDiskInfo()
        {
            const string cacheKey = "DiskInfo";
            if (IsCacheValid(cacheKey))
                return (string[])infoCache[cacheKey];

            try
            {
                ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_LogicalDisk WHERE DriveType=3");
                var diskInfo = new List<string>();
                int diskCount = 0;

                foreach (ManagementObject disk in searcher.Get())
                {
                    if (diskCount >= 4) break;

                    string driveLetter = disk["DeviceID"]?.ToString() ?? "未知";
                    ulong size = (ulong)(disk["Size"] ?? 0);
                    ulong freeSpace = (ulong)(disk["FreeSpace"] ?? 0);
                    double sizeGB = size / (1024.0 * 1024.0 * 1024.0);
                    double freeSpaceGB = freeSpace / (1024.0 * 1024.0 * 1024.0);
                    int usagePercent = size > 0 ? (int)((size - freeSpace) * 100 / size) : 0;

                    diskInfo.Add($"{driveLetter}: {Math.Round(freeSpaceGB, 2)} GB / {Math.Round(sizeGB, 2)} GB ({usagePercent}%)");
                    diskCount++;
                }

                while (diskInfo.Count < 5)
                {
                    diskInfo.Add("无数据");
                }

                var result = diskInfo.ToArray();
                UpdateCache(cacheKey, result);
                return result;
            }
            catch
            {
                var result = new string[]
                {
                    "磁盘1: 未知",
                    "磁盘2: 未知",
                    "磁盘3: 未知",
                    "磁盘4: 未知",
                    ""
                };
                UpdateCache(cacheKey, result);
                return result;
            }
        }

        private string[] GetSystemInfo()
        {
            const string cacheKey = "SystemInfo";
            if (IsCacheValid(cacheKey))
                return (string[])infoCache[cacheKey];

            try
            {
                ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystem");
                string manufacturer = "未知";
                string model = "未知";
                string totalPhysicalMemory = "未知";

                foreach (ManagementObject computer in searcher.Get())
                {
                    manufacturer = computer["Manufacturer"]?.ToString() ?? "未知";
                    model = computer["Model"]?.ToString() ?? "未知";
                    ulong memory = (ulong)(computer["TotalPhysicalMemory"] ?? 0);
                    totalPhysicalMemory = $"{Math.Round(memory / (1024.0 * 1024.0 * 1024.0), 2)} GB";
                    break;
                }

                searcher = new ManagementObjectSearcher("SELECT * FROM Win32_OperatingSystem");
                string lastBootUpTime = "未知";
                foreach (ManagementObject os in searcher.Get())
                {
                    lastBootUpTime = ManagementDateTimeConverter.ToDateTime(os["LastBootUpTime"]?.ToString() ?? "").ToString("yyyy-MM-dd HH:mm:ss");
                    break;
                }

                var result = new string[]
                {
                    $"制造商: {manufacturer}",
                    $"型号: {model}",
                    $"总物理内存: {totalPhysicalMemory}",
                    $"上次启动时间: {lastBootUpTime}",
                    $"计算机名: {Environment.MachineName}"
                };
                UpdateCache(cacheKey, result);
                return result;
            }
            catch
            {
                var result = new string[]
                {
                    "制造商: 未知",
                    "型号: 未知",
                    "总物理内存: 未知",
                    "上次启动时间: 未知",
                    "计算机名: 未知"
                };
                UpdateCache(cacheKey, result);
                return result;
            }
        }

        public void ApplyTheme(Theme theme)
        {
            currentTheme = theme;
            UpdateTheme();
        }

        private void UpdateTheme()
        {
            if (currentTheme == Theme.Dark)
            {
                MainGrid.Background = new SolidColorBrush(Color.FromRgb(30, 30, 30));
            }
            else
            {
                MainGrid.Background = new SolidColorBrush(Colors.White);
            }
        }

        private void UpdateLanguage()
        {
            try
            {
                TitleText.Text = _languageManager.GetString("SystemInfo", "系统信息");
            }
            catch { }
        }
    }
}
