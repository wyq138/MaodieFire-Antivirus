// 耄耋软件工作室 开发
// 看门狗守护（软件被病毒/恶意软件杀死后自恢复）：
//   主实例持有命名 Mutex —— 进程被杀时内核自动释放该 Mutex；
//   三层恢复体系：
//     1) 守护子进程 FireAntivirusWatchman.exe（独立文件名，病毒按名批量杀杀不到）3 秒级监控主进程，
//        主进程被杀且无用户退出标记 → 静默拉起新主实例（--silent，托盘常驻不弹窗口）
//     2) 主实例 3 秒级确认守护存活，守护被杀 → 重新拉起（互拉闭环）
//     3) 系统计划任务 FireAntivirusWatchdog 每分钟兜底拉起（--watchdog，前两层同时失效时）
//   用户主动退出（托盘"退出"）：写 exit_flag（固定 ProgramData 路径）+ 禁用计划任务，
//   守护/计划任务/恢复实例三层全部尊重退出标记，整组安静下线。
using System;
using System.Diagnostics;
using System.IO;
using System.Threading;

namespace FireAntivirus.Host.WinUI
{
    internal static class WatchdogGuard
    {
        private const string MutexName = "FireAntivirus.Main.Instance";
        private const string TaskName = "FireAntivirusWatchdog";

        private static Mutex _mainLock;

        /// <summary>
        /// 退出标记放在固定的全 ASCII 稳定路径（ProgramData），主实例/守护/计划任务恢复实例
        /// 三方面读取的必须是同一路径——放在 BaseDirectory 会随进程启动方式漂移导致标记失效。
        /// </summary>
        private static string ExitFlagPath
        {
            get
            {
                try
                {
                    var dir = Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                        "FireAntivirus");
                    Directory.CreateDirectory(dir);
                    return Path.Combine(dir, "exit_flag.dat");
                }
                catch
                {
                    return Path.Combine(AppContext.BaseDirectory, "exit_flag.dat");
                }
            }
        }

        /// <summary>主实例是否存活（命名 Mutex 已被持有）。</summary>
        public static bool HasMainInstance() => Mutex.TryOpenExisting(MutexName, out _);

        /// <summary>用户是否已标记主动退出（守护/计划任务/恢复实例启动前都必须检查）。</summary>
        public static bool IsUserExitMarked() => File.Exists(ExitFlagPath);

        /// <summary>
        /// 占据主实例身份（非阻塞）。返回 false = 竞态中已有其他实例抢先成为主实例，调用方应立即退出；
        /// 前持有者被病毒杀掉时 Mutex 为 abandoned 状态，此处捕获后即完成接管（自恢复）。
        /// </summary>
        public static bool AcquireMainLock()
        {
            _mainLock = new Mutex(false, MutexName, out var createdNew);
            if (createdNew) return true; // 全新 Mutex：我们是第一个主实例
            try
            {
                if (_mainLock.WaitOne(0)) return true; // 无人持有：抢占成功
            }
            catch (AbandonedMutexException)
            {
                return true; // 前持有者被杀（abandoned）：Mutex 归我们，接管成功
            }
            // 持有人还活着：竞态落败
            _mainLock.Dispose();
            _mainLock = null;
            return false;
        }

        /// <summary>
        /// 用户主动退出标记：写 exit_flag（固定稳定路径）+ 禁用看门狗计划任务（双保险），
        /// 确保守护/计划任务/恢复实例三层全部停止恢复。
        /// </summary>
        public static void MarkUserExit()
        {
            try
            {
                File.WriteAllText(ExitFlagPath, DateTime.Now.ToString("O"));
                Run("schtasks", "/change /tn \"" + TaskName + "\" /disable");
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info,
                    "看门狗: 用户主动退出已标记（exit_flag=" + ExitFlagPath + " + 计划任务已禁用）");
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error,
                    "看门狗退出标记失败: " + ex.Message);
            }
        }

        /// <summary>主实例启动：清除退出标记并重新启用看门狗计划任务。</summary>
        public static void ClearUserExitMark()
        {
            try
            {
                if (File.Exists(ExitFlagPath)) File.Delete(ExitFlagPath);
                Run("schtasks", "/change /tn \"" + TaskName + "\" /enable");
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info,
                    "看门狗: 主实例启动，退出标记已清除（计划任务重新启用）");
            }
            catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
        }

        /// <summary>
        /// 确保看门狗计划任务存在。应用以管理员运行，schtasks 可直接注册 HIGHEST 权限任务；
        /// 任务由系统调度，不依赖任何常驻进程，病毒杀掉应用也无法阻止恢复。
        /// 设置页关闭自恢复时：任务不存在则不注册，存在则禁用。
        /// </summary>
        public static void EnsureScheduledTask()
        {
            try
            {
                // 用户在设置页关闭了自恢复：不注册，且把已存在的任务禁用
                if (!SettingsStore.Current.WatchdogEnabled)
                {
                    Run("schtasks", "/change /tn \"" + TaskName + "\" /disable");
                    return;
                }

                string exe = Process.GetCurrentProcess().MainModule?.FileName ?? "";
                if (string.IsNullOrEmpty(exe)) return;

                var query = Run("schtasks", "/query /tn \"" + TaskName + "\"");
                if (query.exitCode == 0) return; // 已注册

                string args = "/create /f /tn \"" + TaskName + "\" " +
                              "/tr \"\\\"" + exe + "\\\" --watchdog\" " +
                              "/sc minute /mo 1 /rl HIGHEST";
                var create = Run("schtasks", args);

                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info,
                    $"看门狗计划任务注册: exit={create.exitCode} {create.output}");
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error,
                    "看门狗计划任务注册失败: " + ex.Message);
            }
        }

        /// <summary>设置页开关即时生效：enable/disable 计划任务（不删除，便于随时恢复）。</summary>
        public static void ApplyWatchdogSetting(bool enabled)
        {
            try
            {
                if (enabled)
                {
                    EnsureScheduledTask();
                    Run("schtasks", "/change /tn \"" + TaskName + "\" /enable");
                }
                else
                {
                    Run("schtasks", "/change /tn \"" + TaskName + "\" /disable");
                }
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                    "看门狗开关切换失败: " + ex.Message);
            }
        }

        private static (int exitCode, string output) Run(string file, string arguments)
        {
            var psi = new ProcessStartInfo
            {
                FileName = file,
                Arguments = arguments,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using var p = Process.Start(psi);
            if (p == null) return (-1, "process start failed");
            string output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
            p.WaitForExit(10000);
            return (p.ExitCode, output);
        }
    }
}