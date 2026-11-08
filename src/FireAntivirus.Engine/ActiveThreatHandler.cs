// 活动威胁处置器（照搬 XIGUASecurity 10x 的 active_threat 真实机制）：
//   场景：病毒源文件被活动进程占用，直接删除/隔离返回"拒绝访问"。
//   方案一"重启时清除"：MoveFileExW(MOVEFILE_DELAY_UNTIL_REBOOT)（管理员直接生效，无 UAC），
//                       失败回退写 HKLM\...\Session Manager\PendingFileRenameOperations（同一底层机制）。
//   方案二"不重启清除"：Windows Restart Manager 定位占用文件的全部进程 → 终止 → 等句柄释放后重试删除。
// 全部为真实 Win32 调用，失败如实返回错误，不假装成功。
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;

namespace FireAntivirus.Engine
{
    public static class ActiveThreatHandler
    {
        // ---------------- 方案一：重启时清除 ----------------

        private const uint MOVEFILE_DELAY_UNTIL_REBOOT = 0x4;

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, uint dwFlags);

        /// <summary>标记文件为"下次重启时删除"（被占用文件的可靠清除方式）。</summary>
        public static bool ScheduleDeleteOnReboot(string filePath, out string error)
        {
            error = null;
            try
            {
                string abs = Path.GetFullPath(filePath);
                if (!File.Exists(abs)) { error = "文件不存在"; return false; }

                // 方案 A：MoveFileEx（管理员运行直接生效，不弹 UAC）
                if (MoveFileEx(abs, null, MOVEFILE_DELAY_UNTIL_REBOOT))
                {
                    FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info,
                        $"已标记重启删除(MoveFileEx): {abs}");
                    return true;
                }

                int win32 = Marshal.GetLastWin32Error();

                // 方案 B：回退写 PendingFileRenameOperations（\??\ 前缀 NT 路径，空目标=删除）
                try
                {
                    string ntPath = @"\??\" + abs;
                    using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                        @"SYSTEM\CurrentControlSet\Control\Session Manager", writable: true);
                    if (key == null) { error = $"MoveFileEx 失败(错误码 {win32})，且无法打开 Session Manager 注册表键（需管理员）"; return false; }

                    var existing = key.GetValue("PendingFileRenameOperations") as string[] ?? Array.Empty<string>();
                    var updated = new List<string>(existing) { ntPath, "" };
                    key.SetValue("PendingFileRenameOperations", updated.ToArray(),
                        Microsoft.Win32.RegistryValueKind.MultiString);

                    FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info,
                        $"已标记重启删除(PendingFileRenameOperations): {abs}");
                    return true;
                }
                catch (Exception ex)
                {
                    error = $"MoveFileEx 失败(错误码 {win32})，注册表回退失败: {ex.Message}（需管理员权限）";
                    return false;
                }
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
        }

        // ---------------- 方案二：Restart Manager 解锁并删除 ----------------

        [StructLayout(LayoutKind.Sequential)]
        private struct RM_UNIQUE_PROCESS
        {
            public int dwProcessId;
            public System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct RM_PROCESS_INFO
        {
            public RM_UNIQUE_PROCESS Process;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string strAppName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string strServiceShortName;
            public int ApplicationType;
            public uint AppStatus;
            public uint TSSessionId;
            [MarshalAs(UnmanagedType.Bool)] public bool bRestartable;
        }

        [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
        private static extern int RmStartSession(out uint pSessionHandle, int dwSessionFlags, string strSessionKey);

        [DllImport("rstrtmgr.dll")]
        private static extern int RmEndSession(uint pSessionHandle);

        [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
        private static extern int RmRegisterResources(
            uint pSessionHandle, uint nFiles, string[] rgsFilenames,
            uint nApplications, RM_UNIQUE_PROCESS[] rgApplications,
            uint nServices, string[] rgsServiceNames);

        [DllImport("rstrtmgr.dll")]
        private static extern int RmGetList(
            uint dwSessionHandle, out uint pnProcInfoNeeded, ref uint pnProcInfo,
            [In, Out] RM_PROCESS_INFO[] rgAffectedApps, ref uint lpdwRebootReasons);

        private const int ERROR_SUCCESS = 0;
        private const int ERROR_MORE_DATA = 234;

        /// <summary>用 Restart Manager 查出占用该文件的进程 PID 列表（真实系统 API）。</summary>
        public static List<int> FindLockingProcesses(string filePath)
        {
            var pids = new List<int>();
            uint session = 0;
            try
            {
                string key = Guid.NewGuid().ToString("N"); // 长度必须 32
                if (RmStartSession(out session, 0, key) != ERROR_SUCCESS) return pids;

                string[] files = { Path.GetFullPath(filePath) };
                if (RmRegisterResources(session, 1, files, 0, null, 0, null) != ERROR_SUCCESS) return pids;

                uint needed = 0, count = 0, reasons = 0;
                int rc = RmGetList(session, out needed, ref count, null, ref reasons);
                if (rc == ERROR_MORE_DATA && needed > 0)
                {
                    count = needed;
                    var infos = new RM_PROCESS_INFO[needed];
                    rc = RmGetList(session, out needed, ref count, infos, ref reasons);
                    if (rc == ERROR_SUCCESS)
                    {
                        for (int i = 0; i < count; i++)
                        {
                            if (infos[i].Process.dwProcessId > 0 && !pids.Contains(infos[i].Process.dwProcessId))
                                pids.Add(infos[i].Process.dwProcessId);
                        }
                    }
                }
            }
            catch { }
            finally
            {
                if (session != 0) try { RmEndSession(session); } catch { }
            }
            return pids;
        }

        /// <summary>
        /// 不重启清除：结束占用进程 → 等待句柄释放 → 重试删除（最多 10 次 / 5 秒）。
        /// 返回实际删除结果；失败如实返回错误（如系统关键进程不可终止）。
        /// </summary>
        public static bool KillLocksAndDelete(string filePath, out string error)
        {
            error = null;
            try
            {
                string abs = Path.GetFullPath(filePath);
                if (!File.Exists(abs)) { error = "文件不存在"; return false; }

                int self = Environment.ProcessId;
                var pids = FindLockingProcesses(abs);
                foreach (var pid in pids)
                {
                    if (pid == self || pid <= 4) continue; // 跳过自身与系统进程
                    try
                    {
                        using var p = Process.GetProcessById(pid);
                        p.Kill();
                        p.WaitForExit(3000);
                        FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info,
                            $"已终止占用进程 PID={pid} ({p.ProcessName})，目标: {abs}");
                    }
                    catch (Exception ex)
                    {
                        FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                            $"终止占用进程 PID={pid} 失败: {ex.Message}");
                    }
                }

                // 等待句柄释放后重试删除
                for (int i = 0; i < 10; i++)
                {
                    try
                    {
                        if (!File.Exists(abs)) return true;
                        File.Delete(abs);
                        if (!File.Exists(abs)) return true;
                    }
                    catch { }
                    Thread.Sleep(500);
                }

                error = "占用进程已终止但文件仍被锁定（可能为系统保护文件或子进程仍持有句柄）";
                return false;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
        }
    }
}