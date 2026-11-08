// 句柄访问掩码审计（真实系统级实现，非静态特征猜测）：
//   1) NtQuerySystemInformation(SystemHandleInformation) 枚举全系统句柄表；
//   2) 对每个"访问掩码含危险位"的句柄，DuplicateHandle 到本进程后 GetProcessId 解析目标进程；
//   3) 审计受保护进程（lsass/csrss/winlogon/services/smss/wininit/杀软自身）被谁、以什么权限打开；
//   4) 解码 PROCESS_* 访问掩码，按 ATT&CK 语义分级（VM_WRITE+CREATE_THREAD=注入，VM_READ LSASS=凭据窃取）；
//   5) 输出 JSON 审计报告（ProgramData\FireAntivirus\Logs\HandleAudit），供处置与取证。
// 权限不足时如实置 AccessDenied，不伪造结果。
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

namespace FireAntivirus.Engine.Analyzers
{
    public enum HandleRisk { Low = 0, Medium = 1, High = 2, Critical = 3 }

    public sealed class HandleAuditEntry
    {
        public int OwnerPid { get; set; }
        public string OwnerName { get; set; }
        public int TargetPid { get; set; }
        public string TargetName { get; set; }
        public uint AccessMask { get; set; }
        public string Access { get; set; }
        public ushort HandleValue { get; set; }
        public HandleRisk Risk { get; set; }
        public string Technique { get; set; }
        public string Detail { get; set; }
    }

    public sealed class HandleAuditReport
    {
        public DateTime ScanTime { get; set; }
        public int ProtectedProcessCount { get; set; }
        public int TotalHandles { get; set; }
        public int ScannedOwners { get; set; }
        public bool AccessDenied { get; set; }
        public List<HandleAuditEntry> Findings { get; set; } = new List<HandleAuditEntry>();
        public string Summary { get; set; }
    }

    public static class HandleAccessAudit
    {
        /// <summary>设置开关（关闭后周期审计与 LSASS 专项检查均停止）。</summary>
        public static bool Enabled { get; set; } = true;

        public static DateTime LastScanUtc { get; private set; }
        public static HandleAuditReport LastReport { get; private set; }
        public static event Action<HandleAuditEntry> Finding;

        // 受保护进程（凭据/会话/安全核心）
        private static readonly string[] ProtectedProcessNames =
        {
            "lsass", "csrss", "winlogon", "services", "smss", "wininit", "lsaiso", "MsMpEng",
            "MpDefenderCoreService", "NisSrv", "SecurityHealthService", "SgrmBroker"
        };

        // 自身进程名（自我保护：谁在打开我们）
        private static readonly HashSet<string> SelfNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "FireAntivirus", "FireAntivirus.Host.WinUI"
        };

        // 合法的句柄持有者（系统内核/安全软件内部互访），避免把系统自身行为当攻击
        private static readonly HashSet<string> TrustedOwners = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "system", "smss", "csrss", "wininit", "services", "lsass", "winlogon", "lsaiso",
            "MsMpEng", "MpDefenderCoreService", "NisSrv", "SecurityHealthService", "SgrmBroker",
            "svchost", "explorer"
        };

        // 跨扫描去重：同一持有者以同一掩码打开同一目标，10 分钟内只报一次（周期审计会反复看到同一句柄）
        private static readonly Dictionary<string, DateTime> Reported =
            new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        private static readonly object _reportLock = new object();

        private static bool ShouldReport(string fingerprint)
        {
            lock (_reportLock)
            {
                var now = DateTime.UtcNow;
                if (Reported.TryGetValue(fingerprint, out var last) && now - last < TimeSpan.FromMinutes(10))
                    return false;

                Reported[fingerprint] = now;
                if (Reported.Count > 5000)
                {
                    var cutoff = now - TimeSpan.FromMinutes(10);
                    foreach (var key in Reported.Where(kv => kv.Value < cutoff).Select(kv => kv.Key).ToList())
                        Reported.Remove(key);
                }
                return true;
            }
        }

        private const uint PROCESS_CREATE_THREAD = 0x0002;
        private const uint PROCESS_VM_OPERATION = 0x0008;
        private const uint PROCESS_VM_READ = 0x0010;
        private const uint PROCESS_VM_WRITE = 0x0020;
        private const uint PROCESS_DUP_HANDLE = 0x0040;
        private const uint PROCESS_CREATE_PROCESS = 0x0080;
        private const uint PROCESS_SET_INFORMATION = 0x0200;
        private const uint PROCESS_SUSPEND_RESUME = 0x0800;

        private const uint DangerousMask =
            PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
            PROCESS_DUP_HANDLE | PROCESS_CREATE_PROCESS | PROCESS_SET_INFORMATION | PROCESS_SUSPEND_RESUME;

        private const int SystemHandleInformation = 16;
        private const int STATUS_INFO_LENGTH_MISMATCH = unchecked((int)0xC0000004);
        private const uint PROCESS_DUP_HANDLE_ACCESS = 0x0040;

        [StructLayout(LayoutKind.Sequential)]
        private struct SYSTEM_HANDLE_ENTRY
        {
            public int OwnerPid;
            public byte ObjectTypeIndex;
            public byte HandleAttributes;
            public short HandleValue;
            public IntPtr Object;
            public uint GrantedAccess;
        }

        [DllImport("ntdll.dll")]
        private static extern int NtQuerySystemInformation(int infoClass, IntPtr info, int infoLength, out int returnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DuplicateHandle(IntPtr srcProcess, IntPtr srcHandle,
            IntPtr dstProcess, out IntPtr dstHandle, uint access, bool inherit, uint options);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern int GetProcessId(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        /// <summary>
        /// 全量审计受保护进程句柄。extraTargets 用于追加目标（如额外业务进程）。
        /// 报告同时写入 JSON 并触发 Finding 事件（仅 High/Critical）。
        /// </summary>
        public static HandleAuditReport Scan(IEnumerable<int> extraTargets = null)
        {
            var report = new HandleAuditReport { ScanTime = DateTime.Now };
            if (!Enabled) return report;

            try
            {
                var targets = CollectProtectedTargets(extraTargets);
                report.ProtectedProcessCount = targets.Count;
                if (targets.Count == 0) { report.Summary = "未发现受保护进程"; return report; }

                var entries = EnumerateHandles();
                report.TotalHandles = entries.Count;
                if (entries.Count == 0)
                {
                    report.Summary = "句柄表枚举为空（权限不足或被拦截）";
                    report.AccessDenied = true;
                    return report;
                }

                IntPtr self = Process.GetCurrentProcess().Handle;
                int selfPid = Environment.ProcessId;
                var targetPids = new HashSet<int>(targets.Keys);
                var findings = new List<HandleAuditEntry>();
                var seenOwnerTargets = new HashSet<(int Owner, int Target)>();

                // 按持有进程分组，每个 owner 只 OpenProcess 一次
                foreach (var group in entries.GroupBy(e => e.OwnerPid))
                {
                    int ownerPid = group.Key;
                    if (ownerPid <= 4 || ownerPid == selfPid) continue;

                    string ownerName;
                    try { ownerName = Process.GetProcessById(ownerPid).ProcessName; }
                    catch { continue; }

                    if (TrustedOwners.Contains(ownerName)) continue;

                    IntPtr owner = OpenProcess(PROCESS_DUP_HANDLE_ACCESS, false, ownerPid);
                    if (owner == IntPtr.Zero) { report.AccessDenied = true; continue; }
                    report.ScannedOwners++;

                    try
                    {
                        foreach (var e in group)
                        {
                            if ((e.GrantedAccess & DangerousMask) == 0) continue;

                            IntPtr srcHandle = new IntPtr(e.HandleValue);
                            if (!DuplicateHandle(owner, srcHandle, self, out var dup,
                                    0x1000 /*PROCESS_QUERY_LIMITED_INFORMATION*/, false, 0))
                                continue;

                            try
                            {
                                int targetPid = GetProcessId(dup);
                                if (targetPid == 0 || !targetPids.Contains(targetPid)) continue;
                                if (!seenOwnerTargets.Add((ownerPid, targetPid))) continue;

                                string fingerprint = $"{ownerPid}|{targetPid}|{e.GrantedAccess:X8}";
                                if (!ShouldReport(fingerprint)) continue;

                                var (risk, technique) = Classify(e.GrantedAccess, targetPid, targetPids);
                                if (risk < HandleRisk.Medium) continue;

                                var finding = new HandleAuditEntry
                                {
                                    OwnerPid = ownerPid,
                                    OwnerName = ownerName,
                                    TargetPid = targetPid,
                                    TargetName = targets[targetPid],
                                    AccessMask = e.GrantedAccess,
                                    Access = DescribeAccess(e.GrantedAccess),
                                    HandleValue = unchecked((ushort)e.HandleValue),
                                    Risk = risk,
                                    Technique = technique,
                                    Detail = $"{ownerName} (PID {ownerPid}) 以 {DescribeAccess(e.GrantedAccess)} 打开 {targets[targetPid]} (PID {targetPid})"
                                };
                                findings.Add(finding);

                                if (risk >= HandleRisk.High)
                                {
                                    try { Finding?.Invoke(finding); } catch { }
                                }
                            }
                            finally { CloseHandle(dup); }
                        }
                    }
                    finally { CloseHandle(owner); }
                }

                findings = findings
                    .OrderByDescending(f => f.Risk)
                    .ThenBy(f => f.OwnerPid)
                    .ToList();
                report.Findings = findings;
                report.Summary = $"审计 {report.ScannedOwners} 个进程持有者 / {report.TotalHandles} 个句柄，" +
                                 $"发现 {findings.Count} 条危险句柄访问" +
                                 (report.AccessDenied ? "（部分进程权限不足，已跳过）" : "");

                LastScanUtc = DateTime.UtcNow;
                LastReport = report;
            }
            catch (Exception ex)
            {
                report.AccessDenied = true;
                report.Summary = "句柄审计失败: " + ex.Message;
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                    "句柄访问掩码审计失败: " + ex.Message);
            }
            return report;
        }

        /// <summary>LSASS 专项（凭据访问检测入口，复用全量审计结果）。</summary>
        public static List<HandleAuditEntry> ScanLsass()
        {
            var report = Scan();
            return report.Findings
                .Where(f => string.Equals(f.TargetName, "lsass", StringComparison.OrdinalIgnoreCase)
                            && (f.AccessMask & (PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD)) != 0)
                .ToList();
        }

        private static List<SYSTEM_HANDLE_ENTRY> EnumerateHandles()
        {
            var result = new List<SYSTEM_HANDLE_ENTRY>();
            int length = 0x10000;
            IntPtr buffer = IntPtr.Zero;
            try
            {
                while (true)
                {
                    buffer = Marshal.AllocHGlobal(length);
                    int status = NtQuerySystemInformation(SystemHandleInformation, buffer, length, out int returnLength);
                    if (status == 0)
                    {
                        int count = Marshal.ReadInt32(buffer);
                        int entrySize = Marshal.SizeOf<SYSTEM_HANDLE_ENTRY>();
                        for (int i = 0; i < count; i++)
                        {
                            IntPtr ptr = IntPtr.Add(buffer, 4 + i * entrySize);
                            result.Add(Marshal.PtrToStructure<SYSTEM_HANDLE_ENTRY>(ptr));
                        }
                        break;
                    }
                    if (status == STATUS_INFO_LENGTH_MISMATCH)
                    {
                        Marshal.FreeHGlobal(buffer);
                        buffer = IntPtr.Zero;
                        length = returnLength > 0 ? returnLength : length * 2;
                        continue;
                    }
                    break;
                }
            }
            catch { }
            finally
            {
                if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
            }
            return result;
        }

        private static Dictionary<int, string> CollectProtectedTargets(IEnumerable<int> extraTargets)
        {
            var map = new Dictionary<int, string>();
            foreach (var name in ProtectedProcessNames)
            {
                foreach (var p in Process.GetProcessesByName(name))
                {
                    try { map[p.Id] = p.ProcessName.ToLowerInvariant(); } catch { }
                }
            }

            // 自身进程（自我保护审计）
            foreach (var p in Process.GetProcesses())
            {
                try
                {
                    if (SelfNames.Contains(p.ProcessName)) map[p.Id] = "FireAntivirus";
                }
                catch { }
                finally { p.Dispose(); }
            }

            if (extraTargets != null)
            {
                foreach (int pid in extraTargets)
                {
                    if (pid <= 0 || map.ContainsKey(pid)) continue;
                    try { map[pid] = Process.GetProcessById(pid).ProcessName.ToLowerInvariant(); } catch { }
                }
            }
            return map;
        }

        private static (HandleRisk Risk, string Technique) Classify(uint mask, int targetPid, HashSet<int> protectedPids)
        {
            bool isLsass = protectedPids.Contains(targetPid) &&
                           SafeName(targetPid).Equals("lsass", StringComparison.OrdinalIgnoreCase);

            bool inject = (mask & PROCESS_VM_WRITE) != 0 && (mask & (PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION)) != 0;
            if (inject) return (HandleRisk.Critical, "T1055");

            if ((mask & PROCESS_VM_WRITE) != 0) return (HandleRisk.Critical, isLsass ? "T1003.001" : "T1055");
            if (isLsass && (mask & PROCESS_VM_READ) != 0) return (HandleRisk.Critical, "T1003.001");
            if ((mask & PROCESS_DUP_HANDLE) != 0) return (HandleRisk.High, "T1134");
            if ((mask & PROCESS_CREATE_THREAD) != 0) return (HandleRisk.High, "T1055");
            if ((mask & PROCESS_CREATE_PROCESS) != 0) return (HandleRisk.High, "T1055");
            if ((mask & PROCESS_VM_READ) != 0) return (HandleRisk.High, "T1057");
            if ((mask & (PROCESS_SET_INFORMATION | PROCESS_SUSPEND_RESUME)) != 0) return (HandleRisk.Medium, "T1562");
            return (HandleRisk.Low, "");
        }

        private static string SafeName(int pid)
        {
            try { return Process.GetProcessById(pid).ProcessName; } catch { return ""; }
        }

        public static string DescribeAccess(uint mask)
        {
            var parts = new List<string>();
            if ((mask & PROCESS_CREATE_THREAD) != 0) parts.Add("CREATE_THREAD");
            if ((mask & PROCESS_VM_OPERATION) != 0) parts.Add("VM_OPERATION");
            if ((mask & PROCESS_VM_READ) != 0) parts.Add("VM_READ");
            if ((mask & PROCESS_VM_WRITE) != 0) parts.Add("VM_WRITE");
            if ((mask & PROCESS_DUP_HANDLE) != 0) parts.Add("DUP_HANDLE");
            if ((mask & PROCESS_CREATE_PROCESS) != 0) parts.Add("CREATE_PROCESS");
            if ((mask & PROCESS_SET_INFORMATION) != 0) parts.Add("SET_INFORMATION");
            if ((mask & PROCESS_SUSPEND_RESUME) != 0) parts.Add("SUSPEND_RESUME");
            if (parts.Count == 0)
            {
                if ((mask & 0x1000) != 0) parts.Add("QUERY_LIMITED_INFORMATION");
                if ((mask & 0x0400) != 0) parts.Add("QUERY_INFORMATION");
                if (parts.Count == 0) parts.Add("0x" + mask.ToString("X8"));
            }
            return string.Join("|", parts);
        }

        /// <summary>写出 JSON 审计报告，返回文件路径（失败返回 null）。</summary>
        public static string WriteReport(HandleAuditReport report, string directory = null)
        {
            if (report == null) return null;
            try
            {
                directory ??= Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "FireAntivirus", "Logs", "HandleAudit");
                Directory.CreateDirectory(directory);
                string path = Path.Combine(directory, $"handle_audit_{report.ScanTime:yyyyMMdd_HHmmss}.json");
                File.WriteAllText(path, JsonSerializer.Serialize(report,
                    new JsonSerializerOptions { WriteIndented = true }));
                return path;
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                    "句柄审计报告写入失败: " + ex.Message);
                return null;
            }
        }

        /// <summary>
        /// 处置：终止危险句柄持有进程。系统/安全核心进程与白名单永不终止，返回 false。
        /// （句柄本身无法跨进程关闭，需内核；用户态正确处置是终止持有者或由驱动拦截。）
        /// </summary>
        public static bool TerminateHolder(HandleAuditEntry finding, out string message)
        {
            message = "";
            if (finding == null) { message = "无效的审计条目"; return false; }

            string owner = finding.OwnerName ?? "";
            if (TrustedOwners.Contains(owner) || SelfNames.Contains(owner))
            {
                message = $"拒绝终止系统/安全进程: {owner} (PID {finding.OwnerPid})";
                return false;
            }

            try
            {
                using var p = Process.GetProcessById(finding.OwnerPid);
                p.Kill();
                message = $"已终止危险句柄持有进程 {owner} (PID {finding.OwnerPid})";
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info, message);
                return true;
            }
            catch (Exception ex)
            {
                message = $"终止失败（可能权限不足或进程已退出）: {ex.Message}";
                return false;
            }
        }
    }
}