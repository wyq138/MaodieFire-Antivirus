// 耄耋软件工作室 开发
// 内核事件监控器 —— 实时防护事件的统一汇聚点，每条拦截/检测行为两路并发可见：
//   1) 右下角威胁处置窗（ThreatDealWindow）：威胁名/位置/等级 + 隔离/删除/忽略按钮，操作真实接 QuarantineStore
//   2) 全局拦截计数（ThreatStats）：实时防护页实时刷新数量
// 事件源：内核驱动管道（IOCTL 0x805 轮询）+ RTPPlus 用户态各模块（进程/文件/注册表/网络/行为）
using System;
using System.Threading;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;

namespace FireAntivirus.Host.WinUI
{
    public static class KernelEventMonitor
    {
        private static bool _channelHooked;
        private static bool _rtpHooked;

        /// <summary>
        /// 全局实时拦截统计（跨页面共享，Interlocked 保证并发安全；实时防护页订阅 StatsChanged 实时刷新数量）。
        /// </summary>
        public static class ThreatStats
        {
            private static int _kernel;
            private static int _rtp;
            private static int _total;

            /// <summary>内核层拦截数（进程/注册表/注入/磁盘/句柄剥离）。</summary>
            public static int Kernel => _kernel;
            /// <summary>用户态旁路拦截数（RTPPlus 各模块）。</summary>
            public static int Rtp => _rtp;
            /// <summary>总拦截数。</summary>
            public static int Total => _total;

            /// <summary>计数变化事件（可能从后台线程触发，订阅方自行切 UI 线程）。</summary>
            public static event Action StatsChanged;

            internal static void RecordKernel()
            {
                Interlocked.Increment(ref _kernel);
                Interlocked.Increment(ref _total);
                try { StatsChanged?.Invoke(); } catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
            }

            internal static void RecordRtp()
            {
                Interlocked.Increment(ref _rtp);
                Interlocked.Increment(ref _total);
                try { StatsChanged?.Invoke(); } catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
            }
        }

        /// <summary>
        /// 启动统一事件监控：系统 Toast 注册 + 驱动轮询 + RTPPlus 订阅。
        /// </summary>
        public static void Start(Window mainWindow)
        {
            var queue = mainWindow.DispatcherQueue;

            // 系统 Toast：AUMID 注册（失败则 Toast 通道不可用，浮层/计数不受影响）

            // 1. 内核事件：异步 IOCTL 微过滤通道（驱动 pending IRP，事件入队即推送；
//    驱动不支持异步时通道内部自动降级为 400ms 同步拉取，不影响功能）
            if (!_channelHooked)
            {
                _channelHooked = true;
                FireAntivirus.Engine.Kernel.AsyncIoctlChannel.EventsReceived += events =>
                {
                    queue.TryEnqueue(() =>
                    {
                        foreach (var e in events)
                            ShowKernelEvent(mainWindow, queue, e);
                    });
                };
                FireAntivirus.Engine.Kernel.AsyncIoctlChannel.Start();
            }

            // 2. RTPPlus 用户态模块威胁事件（进程/文件/注册表/网络/行为）
            HookRtpEvents(mainWindow, queue);
        }

        /// <summary>内核事件 → 系统右下角 Toast（Windows 通知中心，主窗口隐藏/最小化仍可见）+ 计数。</summary>
        private static void ShowKernelEvent(Window mainWindow, DispatcherQueue queue, FireAntivirus.Engine.Kernel.KernelEvent e)
        {
            ThreatStats.RecordKernel();

            string source = string.IsNullOrEmpty(e.Source) ? $"PID {e.Pid}" : e.Source;
            string title = $"内核防护 · {e.TypeName}";

            // 威胁处置主通道：独立处置窗口（隔离/忽略/打开位置，被占用时提供重启清除/结束占用进程两方案）
            ThreatDealWindow.Show(source, title + "（" + e.Detail + "）", e.Severity,
                canQuarantine: !string.IsNullOrEmpty(source) && System.IO.File.Exists(source));
        }

        /// <summary>RTPPlus 用户态事件 → 系统右下角 Toast + 计数。</summary>
        private static void ShowRtpEvent(Window mainWindow, DispatcherQueue queue, string module, string detail, string severity)
        {
            ThreatStats.RecordRtp();

            string title = $"{module} · 实时拦截";

            // 威胁处置主通道：独立处置窗口
            ThreatDealWindow.Show(detail, title, severity,
                canQuarantine: !string.IsNullOrEmpty(detail) && System.IO.File.Exists(detail));
        }

        private static void HookRtpEvents(Window mainWindow, DispatcherQueue queue)
        {
            if (_rtpHooked) return;
            _rtpHooked = true;

            FireAntivirus.RealTimeProtectionPlus.RealTimeProtectionPlusManager.ThreatDetected +=
                (module, detail, severity) => ShowRtpEvent(mainWindow, queue, module, detail, severity);
        }
    }
}