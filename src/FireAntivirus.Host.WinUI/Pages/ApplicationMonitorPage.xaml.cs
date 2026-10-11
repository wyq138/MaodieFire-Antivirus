// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace FireAntivirus.Host.WinUI.Pages
{
    public sealed class ProcessInfo
    {
        public string ProcessName { get; set; } = "";
        public int PID { get; set; }
        public string CPU { get; set; } = "0%";
        public string Memory { get; set; } = "0 B";
        public string Status { get; set; } = "运行中";
        public string Path { get; set; } = "--";
        public Process Underlying { get; set; }
    }

    public sealed partial class ApplicationMonitorPage : Page
    {
        private readonly ObservableCollection<ProcessInfo> _procs = new();
        private readonly System.Collections.Generic.Dictionary<int, TimeSpan> _cpuHistory = new();
        private DateTime _lastCpuCheck = DateTime.Now;
        private DispatcherTimer? _timer;

        public ApplicationMonitorPage()
        {
            InitializeComponent();
            ProcessGrid.ItemsSource = _procs;
            DetailPanel.Visibility = Visibility.Collapsed;
            _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
            _timer.Tick += (s, e) => { LoadCpuAndMemory(); LoadProcesses(); };
            _timer.Start();
            LoadProcesses();
        }

        private static string Fmt(long bytes)
        {
            string[] suf = { "B", "KB", "MB", "GB" };
            double v = bytes; int i = 0;
            while (v >= 1024 && i < suf.Length - 1) { v /= 1024; i++; }
            return $"{v:F1} {suf[i]}";
        }

        private void LoadCpuAndMemory()
        {
            try
            {
                using var cpu = new PerformanceCounter("Processor", "% Processor Time", "_Total");
                _ = cpu.NextValue();
                var c1 = cpu.NextValue();
                DispatcherQueue.TryEnqueue(() =>
                {
                    CpuUsageText.Text = $"{Math.Min(c1, 100):F0}%";
                    CpuBar.Value = Math.Min(c1, 100);
                });
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "CPU采样失败: " + ex.Message);
            }
            try
            {
                using var mem = new PerformanceCounter("Memory", "% Committed Bytes In Use");
                var m1 = mem.NextValue();
                DispatcherQueue.TryEnqueue(() =>
                {
                    MemoryUsageText.Text = $"{Math.Min(m1, 100):F0}%";
                    MemoryBar.Value = Math.Min(m1, 100);
                });
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "内存采样失败: " + ex.Message);
            }
        }

        private void LoadProcesses()
        {
            var now = DateTime.Now;
            var list = new System.Collections.Generic.List<ProcessInfo>();
            try
            {
                foreach (var p in Process.GetProcesses())
                {
                    try
                    {
                        string cpu = "0%";
                        try
                        {
                            var total = p.TotalProcessorTime;
                            if (_cpuHistory.TryGetValue(p.Id, out var prev))
                            {
                                var elapsedMs = (now - _lastCpuCheck).TotalMilliseconds;
                                if (elapsedMs > 0)
                                {
                                    var pct = ((total - prev).TotalMilliseconds / elapsedMs) * 100 / Environment.ProcessorCount;
                                    cpu = $"{Math.Min(pct, 100):F1}%";
                                }
                            }
                            _cpuHistory[p.Id] = total;
                        }
                        catch { /* 无权限读取 */ }

                        list.Add(new ProcessInfo
                        {
                            ProcessName = p.ProcessName,
                            PID = p.Id,
                            CPU = cpu,
                            Memory = Fmt(p.WorkingSet64),
                            Status = TryResponding(p),
                            Path = TryPath(p),
                            Underlying = p
                        });
                    }
                    catch { /* 进程已退出 */ }
                }
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "进程枚举失败: " + ex.Message);
            }
            _lastCpuCheck = now;

            DispatcherQueue.TryEnqueue(() =>
            {
                _procs.Clear();
                foreach (var row in list.OrderBy(r => r.Memory)) _procs.Add(row);
            });
        }

        private static string TryResponding(Process p)
        {
            try { return p.Responding ? "运行中" : "无响应"; } catch { return "运行中"; }
        }

        private static string TryPath(Process p)
        {
            try { return p.MainModule?.FileName ?? "--"; } catch { return "--"; }
        }

        private void ProcessGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (ProcessGrid.SelectedItem is ProcessInfo info)
            {
                DetailPanel.Visibility = Visibility.Visible;
                DetailProcessName.Text = "进程名: " + info.ProcessName;
                DetailProcessPath.Text = "路径: " + info.Path;
                DetailProcessUser.Text = "状态: " + info.Status;
                DetailProcessThreads.Text = "PID: " + info.PID;
                DetailProcessHandles.Text = "内存: " + info.Memory;
            }
        }

        private void Refresh_Click(object sender, RoutedEventArgs e) => LoadProcesses();

        private void EndProcess_Click(object sender, RoutedEventArgs e)
        {
            if (ProcessGrid.SelectedItem is not ProcessInfo info || info.Underlying == null) return;
            try
            {
                using (var p = Process.GetProcessById(info.PID))
                {
                    if (!FireAntivirus.Common.TrustedProcessGuard.CanTerminate(p))
                    {
                        _ = new ContentDialog
                        {
                            Title = "提示",
                            Content = "该进程为受保护的系统进程，无法结束。",
                            CloseButtonText = "确定", XamlRoot = XamlRoot
                        }.ShowAsync();
                        return;
                    }
                    p.Kill();
                }
                _ = new ContentDialog
                {
                    Title = "成功", Content = "进程已结束。", CloseButtonText = "确定", XamlRoot = XamlRoot
                }.ShowAsync();
                LoadProcesses();
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "结束进程失败: " + ex.Message);
                _ = new ContentDialog
                {
                    Title = "错误", Content = "无法结束进程: " + ex.Message, CloseButtonText = "确定", XamlRoot = XamlRoot
                }.ShowAsync();
            }
        }
    }
}