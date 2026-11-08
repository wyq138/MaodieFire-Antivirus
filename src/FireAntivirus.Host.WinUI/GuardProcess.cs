// 耄耋软件工作室 开发
// 双进程互拉守护：
//   主实例启动守护子进程（本程序 --guard <主PID>），守护循环监控主进程；
//   主进程被病毒杀掉且无用户退出标记 → 守护立即拉起新主实例后退出（新主实例会拉起新的守护）；
//   主进程侧定时检查守护子进程存活，守护被杀 → 重新拉起——互拉闭环，谁死了都有人拉。
//   用户主动退出（托盘"退出"写 exit_flag.dat）→ 守护尊重退出，整组安静下线。
//   另有系统计划任务（WatchdogGuard）作为第三层保险。
using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace FireAntivirus.Host.WinUI
{
    internal static class GuardProcess
    {
        private static Process _guard;
        private static int _mainPid;
        private static string _exePath;
        private static volatile bool _stopRequested;

        /// <summary>
        /// 用户主动退出：停止守护与互拉循环（先于写退出标记执行，物理封死 3 秒竞态拉起窗口）。
        /// </summary>
        public static void StopGuard()
        {
            _stopRequested = true;
            try
            {
                foreach (var p in Process.GetProcessesByName("FireAntivirusWatchman"))
                    try { p.Kill(); } catch { }
            }
            catch { }
            try
            {
                if (_guard != null && !_guard.HasExited)
                    _guard.Kill();
            }
            catch { }
        }

        /// <summary>
        /// 守护进程使用独立文件名（FireAntivirusWatchman.exe）：病毒按映像名批量杀
        /// （taskkill /IM FireAntivirus.Host.WinUI.exe）杀不到守护——保证两个进程必有一个持续存活。
        /// </summary>
        private static string WatchmanPath()
        {
            string dir = Path.GetDirectoryName(_exePath) ?? AppContext.BaseDirectory;
            return Path.Combine(dir, "FireAntivirusWatchman.exe");
        }

        /// <summary>确保 FireAntivirusWatchman.exe 与主程序同版本：结束旧版守护（旧逻辑会用旧退出标记路径，
        /// 把用户正常退出误判为被杀而误拉）后强制覆盖复制。</summary>
        private static bool EnsureWatchmanCopy()
        {
            try
            {
                var watchman = WatchmanPath();
                // 结束旧版守护进程（防止其以旧标记路径误判、误拉）
                try
                {
                    foreach (var p in Process.GetProcessesByName("FireAntivirusWatchman"))
                        try { p.Kill(); } catch { }
                }
                catch { }
                Thread.Sleep(200);
                File.Copy(_exePath, watchman, overwrite: true);
                return true;
            }
            catch (IOException)
            {
                // 目标占用且清理失败：现有文件仍是可用守护，降级使用
                return File.Exists(WatchmanPath());
            }
            catch
            {
                return File.Exists(WatchmanPath());
            }
        }

        /// <summary>主实例侧：拉起守护子进程（独立 watchman.exe --guard 模式）。</summary>
        public static void StartGuard()
        {
            try
            {
                _exePath = Process.GetCurrentProcess().MainModule?.FileName ?? "";
                if (string.IsNullOrEmpty(_exePath)) return;

                _mainPid = Environment.ProcessId;
                if (!EnsureWatchmanCopy())
                {
                    FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error,
                        "守护进程文件准备失败，降级为主程序自守护");
                }
                var guardExe = File.Exists(WatchmanPath()) ? WatchmanPath() : _exePath;
                _guard = Process.Start(new ProcessStartInfo(guardExe, "--guard " + _mainPid)
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                });
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error,
                    "守护子进程拉起失败: " + ex.Message);
            }
        }

        /// <summary>主实例侧：3 秒级确认守护存活，被杀立即重拉（互拉闭环的主侧）。</summary>
        public static void MonitorGuardLoop()
        {
            while (true)
            {
                Thread.Sleep(TimeSpan.FromSeconds(3));
                try
                {
                    if (_stopRequested || WatchdogGuard.IsUserExitMarked()) return; // 用户已退出，停止互拉
                    if (_guard == null || _guard.HasExited) StartGuard();
                }
                catch
                {
                    if (_stopRequested) return;
                    try { StartGuard(); } catch { }
                }
            }
        }

        /// <summary>守护模式入口（--guard 进程的主循环，阻塞直至守护结束）。</summary>
        public static void RunGuard(int mainPid)
        {
            while (true)
            {
                Thread.Sleep(3000);

                // 用户主动退出（托盘"退出"写标记）→ 整组安静下线
                if (WatchdogGuard.IsUserExitMarked()) return;

                Process main = null;
                try { main = Process.GetProcessById(mainPid); } catch { }

                if (main == null || main.HasExited)
                {
                    // 主进程被杀且用户没有主动退出 → 静默拉起新主实例：
                    // 防护与托盘常驻后台继续跑，但不弹主窗口打扰用户（--silent 模式）
                    try
                    {
                        string exe = Path.Combine(AppContext.BaseDirectory, "FireAntivirus.Host.WinUI.exe");
                        if (!File.Exists(exe))
                            exe = Process.GetCurrentProcess().MainModule?.FileName ?? "";
                        if (!string.IsNullOrEmpty(exe))
                        {
                            FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                                "看门狗: 检测到主进程被终止，正在后台静默恢复（托盘常驻，不弹窗口）");
                            Process.Start(new ProcessStartInfo(exe, "--silent") { UseShellExecute = false });
                        }
                    }
                    catch (Exception ex)
                    {
                        FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error,
                            "看门狗拉起主进程失败: " + ex.Message);
                    }
                    return; // 守护使命完成（新主实例自带新守护）
                }
            }
        }
    }
}