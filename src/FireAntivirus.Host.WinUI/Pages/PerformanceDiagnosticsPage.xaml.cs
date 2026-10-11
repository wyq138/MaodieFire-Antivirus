// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Diagnostics.Contracts;
using System.Runtime.InteropServices;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace FireAntivirus.Host.WinUI.Pages
{
    public sealed class DiagRow
    {
        public string Name { get; set; } = "";
        public string Result { get; set; } = "";
    }

    public sealed partial class PerformanceDiagnosticsPage : Page
    {
        private readonly ObservableCollection<DiagRow> _diag = new();
        private readonly PerformanceCounter _cpu, _mem;

        public PerformanceDiagnosticsPage()
        {
            InitializeComponent();
            DiagList.ItemsSource = _diag;
            _cpu = new PerformanceCounter("Processor", "% Processor Time", "_Total");
            _mem = new PerformanceCounter("Memory", "% Committed Bytes In Use");
            _ = _cpu.NextValue();
            _ = _mem.NextValue();
            var timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
            timer.Tick += (s, e) => UpdateLive();
            timer.Start();
            RunDiagnostics();
        }

        private static string Fmt(long bytes)
        {
            string[] suf = { "B", "KB", "MB", "GB" };
            double v = bytes; int i = 0;
            while (v >= 1024 && i < suf.Length - 1) { v /= 1024; i++; }
            return $"{v:F1} {suf[i]}";
        }

        private void UpdateLive()
        {
            double cpu = 0, mem = 0;
            try { cpu = _cpu.NextValue(); } catch { }
            try { mem = _mem.NextValue(); } catch { }
            var up = DateTime.Now - Process.GetCurrentProcess().StartTime;
            DispatcherQueue.TryEnqueue(() =>
            {
                CpuText.Text = $"{Math.Min(cpu, 100):F0}%";
                MemText.Text = $"{Math.Min(mem, 100):F0}%";
                UpText.Text = $"{(int)up.TotalHours}时{(int)up.Minutes}分";
            });
        }

        private void RunDiagnostics()
        {
            _diag.Clear();
            try
            {
                var gcMem = System.GC.GetTotalMemory(false);
                _diag.Add(new DiagRow { Name = "托管内存使用", Result = Fmt(gcMem) });
                _diag.Add(new DiagRow { Name = "系统物理内存", Result = Fmt((long)(Environment.WorkingSet + GC.GetTotalMemory(false))) });
                _diag.Add(new DiagRow { Name = "当前进程句柄", Result = Process.GetCurrentProcess().HandleCount + " 个" });
                _diag.Add(new DiagRow { Name = "当前线程数", Result = Process.GetCurrentProcess().Threads.Count + " 个" });
                _diag.Add(new DiagRow { Name = "逻辑处理器", Result = Environment.ProcessorCount + " 核" });
                _diag.Add(new DiagRow { Name = "已用内存", Result = GetMemoryStatus() });
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "性能诊断失败: " + ex.Message);
                _diag.Add(new DiagRow { Name = "诊断", Result = "部分数据不可用" });
            }
        }

        private static string GetMemoryStatus()
        {
            MEMORYSTATUSEX ms = new MEMORYSTATUSEX { dwLength = (uint)Marshal.SizeOf<MEMORYSTATUSEX>() };
            if (GlobalMemoryStatusEx(ref ms))
                return $"{Fmt((long)ms.ullTotalPhys)} 已用 {Fmt((long)(ms.ullTotalPhys - ms.ullAvailPhys))}";
            return "--";
        }

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

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX lpBuffer);

        private void Diagnose_Click(object sender, RoutedEventArgs e) => RunDiagnostics();
    }
}