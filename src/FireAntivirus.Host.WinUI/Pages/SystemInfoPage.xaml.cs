// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Collections.Generic;
using System.Management;
using System.Threading.Tasks;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace FireAntivirus.Host.WinUI.Pages
{
    public sealed partial class SystemInfoPage : Page
    {
        public SystemInfoPage()
        {
            InitializeComponent();
            LoadSystemInfo();
        }

        private void LoadSystemInfo()
        {
            _ = LoadAsync();
        }

        private async Task LoadAsync()
        {
            var os = await Task.Run(GetOSInfo);
            var cpu = await Task.Run(GetCPUInfo);
            var mem = await Task.Run(GetMemoryInfo);
            var disk = await Task.Run(GetDiskInfo);
            var sys = await Task.Run(GetSystemInfo);

            DispatcherQueue.TryEnqueue(() =>
            {
                try
                {
                    OSNameLabel.Text = os[0]; OSVersionLabel.Text = os[1]; OSArchLabel.Text = os[2];
                    OSInstallDateLabel.Text = os[3]; OSSystemDirLabel.Text = os[4];
                    CPUNameLabel.Text = cpu[0]; CPUManufacturerLabel.Text = cpu[1]; CPUCoresLabel.Text = cpu[2];
                    CPULogicalLabel.Text = cpu[3]; CPUSpeedLabel.Text = cpu[4];
                    MemoryTotalLabel.Text = mem[0]; MemoryAvailableLabel.Text = mem[1]; MemoryUsageLabel.Text = mem[2];
                    MemoryVisibleLabel.Text = mem[3]; MemoryFreeLabel.Text = mem[4];
                    Disk1Label.Text = disk.Length > 0 ? disk[0] : "无数据";
                    Disk2Label.Text = disk.Length > 1 ? disk[1] : "无数据";
                    Disk3Label.Text = disk.Length > 2 ? disk[2] : "无数据";
                    Disk4Label.Text = disk.Length > 3 ? disk[3] : "无数据";
                    Disk5Label.Text = disk.Length > 4 ? disk[4] : "";
                    SystemManufacturerLabel.Text = sys[0]; SystemModelLabel.Text = sys[1];
                    SystemMemoryLabel.Text = sys[2]; SystemBootTimeLabel.Text = sys[3]; SystemComputerNameLabel.Text = sys[4];
                }
                catch (Exception ex)
                {
                    FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "系统信息更新失败: " + ex.Message);
                }
            });
        }

        private static string[] GetOSInfo()
        {
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT Caption,Version,BuildNumber,OSArchitecture,InstallDate,SystemDirectory FROM Win32_OperatingSystem");
                foreach (ManagementObject os in searcher.Get())
                {
                    return new[]
                    {
                        "操作系统: " + os["Caption"], "版本: " + os["Version"] + " (Build " + os["BuildNumber"] + ")",
                        "架构: " + os["OSArchitecture"], "安装日期: " + ToDate(os["InstallDate"]),
                        "系统目录: " + os["SystemDirectory"]
                    };
                }
            }
            catch { /* WMI 不可用 */ }
            return new[] { "操作系统: 未知", "版本: 未知", "架构: 未知", "安装日期: 未知", "系统目录: 未知" };
        }

        private static string ToDate(object wmiDate)
        {
            try { return wmiDate == null ? "未知" : ManagementDateTimeConverter.ToDateTime(wmiDate.ToString()).ToString("yyyy-MM-dd HH:mm:ss"); }
            catch { return "未知"; }
        }

        private static string[] GetCPUInfo()
        {
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT Name,Manufacturer,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed FROM Win32_Processor");
                foreach (ManagementObject cpu in searcher.Get())
                {
                    return new[]
                    {
                        "处理器: " + cpu["Name"], "制造商: " + cpu["Manufacturer"],
                        "核心数: " + cpu["NumberOfCores"], "逻辑处理器: " + cpu["NumberOfLogicalProcessors"],
                        "最大时钟速度: " + cpu["MaxClockSpeed"] + " MHz"
                    };
                }
            }
            catch { /* WMI 不可用 */ }
            return new[] { "处理器: 未知", "制造商: 未知", "核心数: 未知", "逻辑处理器: 未知", "最大时钟速度: 未知" };
        }

        private static string[] GetMemoryInfo()
        {
            try
            {
                ulong total = 0, free = 0, visible = 0;
                using (var cs = new ManagementObjectSearcher("SELECT TotalPhysicalMemory FROM Win32_ComputerSystem"))
                    foreach (ManagementObject o in cs.Get()) { total = (ulong)(o["TotalPhysicalMemory"] ?? 0); break; }
                using (var os = new ManagementObjectSearcher("SELECT FreePhysicalMemory,TotalVisibleMemorySize FROM Win32_OperatingSystem"))
                    foreach (ManagementObject o in os.Get()) { free = (ulong)(o["FreePhysicalMemory"] ?? 0); visible = (ulong)(o["TotalVisibleMemorySize"] ?? 0); break; }
                int pct = visible > 0 ? (int)((visible - free) * 100 / visible) : 0;
                return new[]
                {
                    "物理内存: " + Math.Round(total / (1024.0 * 1024 * 1024), 2) + " GB",
                    "可用内存: " + Math.Round(free / 1024.0 / 1024, 2) + " GB",
                    "内存使用率: " + pct + "%",
                    "总可见内存: " + visible / (1024 * 1024) + " MB",
                    "可用物理内存: " + free / 1024 + " MB"
                };
            }
            catch { return new[] { "物理内存: 未知", "可用内存: 未知", "内存使用率: 未知", "总可见内存: 未知", "可用物理内存: 未知" }; }
        }

        private static string[] GetDiskInfo()
        {
            var list = new List<string>();
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_LogicalDisk WHERE DriveType=3");
                foreach (ManagementObject disk in searcher.Get())
                {
                    if (list.Count >= 4) break;
                    string letter = disk["DeviceID"]?.ToString() ?? "未知";
                    ulong size = (ulong)(disk["Size"] ?? 0), free = (ulong)(disk["FreeSpace"] ?? 0);
                    list.Add($"{letter}: {Math.Round(free / (1024.0 * 1024 * 1024), 2)} GB / {Math.Round(size / (1024.0 * 1024 * 1024), 2)} GB ({Math.Round(size > 0 ? (size - free) * 100.0 / size : 0, 0)}%)");
                }
            }
            catch { /* WMI 不可用 */ }
            while (list.Count < 5) list.Add("无数据");
            return list.ToArray();
        }

        private static string[] GetSystemInfo()
        {
            try
            {
                string mfr = "未知", model = "未知", mem = "未知", boot = "未知";
                using (var cs = new ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystem"))
                    foreach (ManagementObject o in cs.Get())
                    {
                        mfr = o["Manufacturer"]?.ToString() ?? "未知"; model = o["Model"]?.ToString() ?? "未知";
                        mem = Math.Round((ulong)(o["TotalPhysicalMemory"] ?? 0) / (1024.0 * 1024 * 1024), 2) + " GB"; break;
                    }
                using (var os = new ManagementObjectSearcher("SELECT LastBootUpTime FROM Win32_OperatingSystem"))
                    foreach (ManagementObject o in os.Get()) { boot = ToDate(o["LastBootUpTime"]); break; }
                return new[] { "制造商: " + mfr, "型号: " + model, "总物理内存: " + mem, "上次启动时间: " + boot, "计算机名: " + Environment.MachineName };
            }
            catch { return new[] { "制造商: 未知", "型号: 未知", "总物理内存: 未知", "上次启动时间: 未知", "计算机名: " + Environment.MachineName }; }
        }

        private void Refresh_Click(object sender, RoutedEventArgs e) => LoadSystemInfo();
    }
}