// 系统信息：真实读取操作系统/CPU/内存/磁盘数据
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.Win32;

namespace FireAntivirus.Host.WinUI.Pages
{
    public sealed partial class SysInfoPage : Page
    {
        public SysInfoPage()
        {
            InitializeComponent();
            _ = LoadInfoAsync();
        }

        private async Task LoadInfoAsync()
        {
            try
            {
                // 系统信息收集（CPU 注册表查询 / 磁盘枚举 / ClamAV 库文件查询）可能耗时，放后台线程
                var items = await Task.Run(() =>
                {
                    var list = new System.Collections.Generic.List<(string K, string V)>();
                    void Add(string key, string value) => list.Add((key, value ?? "--"));

                    Add("操作系统", GetOsName());
                    Add("系统版本", Environment.OSVersion.VersionString);
                    Add("处理器", GetCpuName());
                    Add("处理器核心", $"{Environment.ProcessorCount} 逻辑核心");
                    Add("内存", GetMemoryInfo());
                    Add("当前用户", Environment.UserName);
                    Add("计算机名", Environment.MachineName);
                    Add("系统目录", Environment.SystemDirectory);
                    Add("已运行时间", TimeSpan.FromMilliseconds(Environment.TickCount64).ToString(@"d\.hh\:mm\:ss"));
                    Add("磁盘分区", GetDrives());

                    // 杀毒软件自身状态
                    var rt = RealTimeProtection.Instance;
                    Add("实时防护", rt.FileGuardEnabled ? $"开启（监控 {rt.WatcherCount} 个目录）" : "关闭");
                    Add("ClamAV 病毒库", GetClamAvDbInfo());
                    return list;
                });

                foreach (var (k, v) in items)
                    Add(k, v);
            }
            catch (Exception ex)
            {
                Add("加载失败", ex.Message);
            }
        }

        private void Add(string key, string value)
        {
            var grid = new Grid { ColumnSpacing = 12 };
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(120) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            grid.Children.Add(new TextBlock { Text = key, Opacity = 0.6, VerticalAlignment = VerticalAlignment.Top });
            var val = new TextBlock { Text = value ?? "--", TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true };
            Grid.SetColumn(val, 1);
            grid.Children.Add(val);
            InfoPanel.Children.Add(grid);
        }

        private static string GetOsName()
        {
            try
            {
                var productName = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion")?.GetValue("ProductName")?.ToString();
                var displayVersion = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion")?.GetValue("DisplayVersion")?.ToString();
                return string.IsNullOrEmpty(productName) ? Environment.OSVersion.ToString()
                    : $"{productName} {displayVersion} ({(Environment.Is64BitOperatingSystem ? "64 位" : "32 位")})";
            }
            catch { return Environment.OSVersion.ToString(); }
        }

        private static string GetCpuName()
        {
            try
            {
                return Registry.LocalMachine.OpenSubKey(
                    @"HARDWARE\DESCRIPTION\System\CentralProcessor\0")?.GetValue("ProcessorNameString")?.ToString() ?? "--";
            }
            catch { return "--"; }
        }

        private static string GetMemoryInfo()
        {
            try
            {
                var status = new MEMORYSTATUSEX { dwLength = (uint)Marshal.SizeOf<MEMORYSTATUSEX>() };
                if (GlobalMemoryStatusEx(ref status))
                {
                    double totalGB = status.ullTotalPhys / 1024.0 / 1024 / 1024;
                    double availGB = status.ullAvailPhys / 1024.0 / 1024 / 1024;
                    return $"{totalGB:F1} GB 总量，可用 {availGB:F1} GB";
                }
            }
            catch { }
            return "--";
        }

        private static string GetDrives()
        {
            var parts = new List<string>();
            foreach (var d in System.IO.DriveInfo.GetDrives())
            {
                try
                {
                    if (!d.IsReady || d.DriveType != System.IO.DriveType.Fixed) continue;
                    double total = d.TotalSize / 1024.0 / 1024 / 1024;
                    double free = d.AvailableFreeSpace / 1024.0 / 1024 / 1024;
                    parts.Add($"{d.Name.TrimEnd('\\')} {free:F0}/{total:F0} GB");
                }
                catch { }
            }
            return parts.Count > 0 ? string.Join("；", parts) : "--";
        }

        private static string GetClamAvDbInfo()
        {
            try
            {
                string[] candidates =
                {
                    System.IO.Path.Combine(AppContext.BaseDirectory, "ClamAV", "db"),
                    System.IO.Path.Combine(AppContext.BaseDirectory, "FireAntivirus.ClamAV", "ClamAV", "db"),
                };
                foreach (var db in candidates)
                {
                    var daily = System.IO.Path.Combine(db, "daily.cvd");
                    if (System.IO.File.Exists(daily))
                        return $"已就绪，daily.cvd 更新于 {System.IO.File.GetLastWriteTime(daily):yyyy-MM-dd HH:mm}";
                }
                return "未找到病毒库文件";
            }
            catch { return "--"; }
        }

        // GlobalMemoryStatusEx P/Invoke
        [StructLayout(LayoutKind.Sequential)]
        private struct MEMORYSTATUSEX
        {
            public uint dwLength;
            public uint dwMemoryLoad;
            public ulong ullTotalPhys;
            public ulong ullAvailPhys;
            public ulong ullTotalPageFile;
            public ulong ullAvailPageFile;
            public ulong ullTotalVirtual;
            public ulong ullAvailVirtual;
            public ulong ullAvailExtendedVirtual;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX lpBuffer);
    }
}
