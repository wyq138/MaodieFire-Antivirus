// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Diagnostics;
using System.IO;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace FireAntivirus.Host.WinUI.Pages
{
    public sealed partial class SystemOptimizerPage : Page
    {
        private readonly PerformanceCounter _cpu, _mem;

        public SystemOptimizerPage()
        {
            InitializeComponent();
            try
            {
                _cpu = new PerformanceCounter("Processor", "% Processor Time", "_Total");
                _mem = new PerformanceCounter("Memory", "% Committed Bytes In Use");
                _ = _cpu.NextValue();
                _ = _mem.NextValue();
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "优化器性能计数器初始化失败: " + ex.Message);
            }
            var timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
            timer.Tick += (s, e) => RefreshDynamicInfo();
            timer.Start();
            RefreshDynamicInfo();
        }

        private void RefreshDynamicInfo()
        {
            double cpu = 0, mem = 0;
            try { cpu = _cpu?.NextValue() ?? 0; } catch (Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "CPU采样失败: " + ex.Message); }
            try { mem = _mem?.NextValue() ?? 0; } catch (Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "内存采样失败: " + ex.Message); }
            long reclaim = EstimateReclaimable();
            DispatcherQueue.TryEnqueue(() =>
            {
                CpuUsage.Text = $"CPU: {Math.Min(cpu, 100):F1}%";
                CpuProgress.Value = Math.Min(cpu, 100);
                MemoryUsage.Text = $"内存: {Math.Min(mem, 100):F1}%";
                MemoryProgress.Value = Math.Min(mem, 100);
                EstimatedSpace.Text = "预计可释放: " + Fmt(reclaim);
            });
        }

        private static long EstimateReclaimable()
        {
            long reclaim = 0;
            string temp = Path.GetTempPath();
            try { foreach (var f in Directory.EnumerateFiles(temp, "*", SearchOption.TopDirectoryOnly)) { try { reclaim += new FileInfo(f).Length; } catch { } } } catch { }
            return Math.Max(reclaim, 16 * 1024 * 1024);
        }

        private static string Fmt(long bytes)
        {
            string[] suf = { "B", "KB", "MB", "GB" };
            double v = bytes; int i = 0;
            while (v >= 1024 && i < suf.Length - 1) { v /= 1024; i++; }
            return $"{v:F0} {suf[i]}";
        }

        private long CleanTemp()
        {
            long freed = 0;
            string temp = Path.GetTempPath();
            try
            {
                foreach (var f in Directory.EnumerateFiles(temp, "*", SearchOption.TopDirectoryOnly))
                {
                    try { var fi = new FileInfo(f); var len = fi.Length; fi.Delete(); freed += len; } catch { }
                }
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "清理临时文件失败: " + ex.Message);
            }
            return freed;
        }

        private void Optimize_Click(object sender, RoutedEventArgs e)
        {
            long freed = 0;
            try { freed = CleanTemp(); } catch (Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "一键优化失败: " + ex.Message); }
            _ = new ContentDialog
            {
                Title = "优化完成",
                Content = "系统优化完成！已释放 " + Fmt(freed) + " 空间。",
                CloseButtonText = "确定", XamlRoot = XamlRoot
            }.ShowAsync();
            RefreshDynamicInfo();
        }
    }
}