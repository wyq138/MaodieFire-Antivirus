// Rootkit 检测工具 —— 全部基于真实系统机制：
//   1) ntdll 内联 Hook 检测  : 内存中 ntdll .text 节与磁盘副本逐字节比对（用户态 rootkit/API 钩子手法）
//   2) 隐藏进程检测          : NtQuerySystemInformation 底层枚举 vs Win32 枚举差集（DKOM 隐藏迹象）
//   3) 可疑内核驱动扫描      : EnumDeviceDrivers 枚举 + 非常规路径/驱动目录外加载检测
//   4) 持久化植入检查        : IFEO Debugger 劫持 / AppInit_DLLs / SafeBoot 服务注入 / Winlogon 篡改 / hosts 劫持
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace FireAntivirus.Engine.Scanners
{
    public class RootkitFinding
    {
        public string Category { get; set; }
        public string Name { get; set; }
        public string Detail { get; set; }
        public string Severity { get; set; }   // High / Medium / Low
    }

    public class RootkitScanResult
    {
        public List<RootkitFinding> Findings { get; } = new List<RootkitFinding>();
        public int ModulesScanned { get; set; }
        public int ProcessesScanned { get; set; }
        public DateTime ScanTime { get; set; } = DateTime.Now;
        public bool IsClean => Findings.Count == 0;
    }

    public static class RootkitDetector
    {
        /// <summary>执行完整 Rootkit 扫描。</summary>
        public static RootkitScanResult ScanAll()
        {
            var result = new RootkitScanResult();

            result.Findings.AddRange(CheckNtdllHooks());
            result.Findings.AddRange(CheckHiddenProcesses(result));
            result.Findings.AddRange(CheckSuspiciousDrivers(result));
            result.Findings.AddRange(CheckPersistenceImplants());

            return result;
        }

        // ============================================================
        // 1. ntdll 内联 Hook 检测：内存 .text 节 vs 磁盘副本比对
        // ============================================================
        public static List<RootkitFinding> CheckNtdllHooks()
        {
            var findings = new List<RootkitFinding>();

            try
            {
                var diskNtdll = Path.Combine(Environment.SystemDirectory, "ntdll.dll");
                if (!File.Exists(diskNtdll)) return findings;

                // 定位内存中 ntdll 模块基址
                IntPtr ntdllBase = GetModuleHandle("ntdll.dll");
                if (ntdllBase == IntPtr.Zero) return findings;

                // 解析内存模块 PE 头 → .text 节（绕过受保护内存的手法：直接解析结构）
                int peOffset = Marshal.ReadInt32(ntdllBase, 0x3C);
                IntPtr peHeader = IntPtr.Add(ntdllBase, peOffset);
                ushort numberOfSections = (ushort)Marshal.ReadInt16(peHeader, 6);
                ushort optionalHeaderSize = (ushort)Marshal.ReadInt16(peHeader, 20);
                IntPtr sectionTable = IntPtr.Add(peHeader, 24 + optionalHeaderSize);

                IntPtr textVa = IntPtr.Zero;
                int textSize = 0;

                for (int i = 0; i < numberOfSections; i++)
                {
                    IntPtr sec = IntPtr.Add(sectionTable, i * 40);
                    var nameBytes = new byte[8];
                    Marshal.Copy(sec, nameBytes, 0, 8);
                    var name = Encoding.ASCII.GetString(nameBytes).TrimEnd('\0');

                    if (name == ".text")
                    {
                        textVa = IntPtr.Add(ntdllBase, Marshal.ReadInt32(sec, 12));   // VirtualAddress
                        textSize = Marshal.ReadInt32(sec, 8);                          // VirtualSize
                        break;
                    }
                }

                if (textVa == IntPtr.Zero || textSize <= 0) return findings;

                // 读取内存中的 .text 节
                var memoryText = new byte[textSize];
                Marshal.Copy(textVa, memoryText, 0, textSize);

                // 读取磁盘副本的对应节（重定位基址不影响 .text 相对内容比对：
                // 逐字节比对时跳过因 ASLR/重定位导致的合理差异区域——按 16 字节块比对，
                // 单块内差异字节 <=2 视为正常填充差异，整块不同才计为 hook 疑点）
                var diskBytes = File.ReadAllBytes(diskNtdll);
                var diskPe = BitConverter.ToInt32(diskBytes, 0x3C);
                ushort diskSections = BitConverter.ToUInt16(diskBytes, diskPe + 6);
                ushort diskOptSize = BitConverter.ToUInt16(diskBytes, diskPe + 16);
                int diskSectionTable = diskPe + 24 + diskOptSize;

                int diskTextOffset = -1, diskTextSize = 0;
                for (int i = 0; i < diskSections; i++)
                {
                    int sec = diskSectionTable + i * 40;
                    var name = Encoding.ASCII.GetString(diskBytes, sec, 8).TrimEnd('\0');
                    if (name == ".text")
                    {
                        diskTextOffset = BitConverter.ToInt32(diskBytes, sec + 20);  // PointerToRawData
                        diskTextSize = BitConverter.ToInt32(diskBytes, sec + 8);     // VirtualSize
                        break;
                    }
                }

                if (diskTextOffset < 0 || diskTextSize <= 0) return findings;

                int compareLen = Math.Min(textSize, diskTextSize);
                int suspiciousBlocks = 0;
                for (int block = 0; block < compareLen; block += 16)
                {
                    int len = Math.Min(16, compareLen - block);
                    int diff = 0;
                    for (int i = 0; i < len; i++)
                    {
                        if (memoryText[block + i] != diskBytes[diskTextOffset + block + i]) diff++;
                    }
                    if (diff >= 3) suspiciousBlocks++;
                }

                // 大量整块差异 = 内联 hook 补丁（jmp 地址改写等），少量差异属正常（重定位）
                if (suspiciousBlocks > 8)
                {
                    findings.Add(new RootkitFinding
                    {
                        Category = "ntdll 完整性",
                        Name = $"检测到 {suspiciousBlocks} 个代码块被改写",
                        Detail = $"内存中 ntdll.dll 的 .text 代码节与磁盘副本存在大面积差异，" +
                                 "符合用户态 API Hook（内联补丁）特征。常见于 API 监控类 rootkit/注入框架。",
                        Severity = "High"
                    });
                }
            }
            catch
            {
                // 权限不足等场景静默跳过
            }

            return findings;
        }

        // ============================================================
        // 2. 隐藏进程检测：底层系统调用枚举 vs Win32 枚举 差集
        // ============================================================
        public static List<RootkitFinding> CheckHiddenProcesses(RootkitScanResult result)
        {
            var findings = new List<RootkitFinding>();

            try
            {
                // 底层：NtQuerySystemInformation(SystemProcessInformation)
                var lowLevelPids = new HashSet<int>();
                IntPtr buffer = IntPtr.Zero;
                try
                {
                    int length = 0;
                    NtQuerySystemInformation(5 /*SystemProcessInformation*/, IntPtr.Zero, 0, ref length);
                    if (length > 0)
                    {
                        buffer = Marshal.AllocHGlobal(length);
                        if (NtQuerySystemInformation(5, buffer, length, ref length) == 0)
                        {
                            // SYSTEM_PROCESS_INFORMATION: NextEntryOffset 在 +0，UniqueProcessId 在 x64 +8/x86 +4
                            IntPtr current = buffer;
                            while (true)
                            {
                                int nextOffset = Marshal.ReadInt32(current, 0);
                                IntPtr pidPtr = Marshal.ReadIntPtr(current, IntPtr.Size == 8 ? 8 : 4);
                                lowLevelPids.Add((int)pidPtr.ToInt64());

                                if (nextOffset <= 0) break;
                                current = IntPtr.Add(current, nextOffset);
                            }
                        }
                    }
                }
                finally
                {
                    if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
                }

                // Win32 层枚举
                var win32Pids = System.Diagnostics.Process.GetProcesses()
                    .Select(p => { try { return p.Id; } catch { return -1; } })
                    .ToHashSet();

                result.ProcessesScanned = lowLevelPids.Count;

                // 底层枚举到但 Win32 枚举不到 = 疑似从工具层隐藏的进程
                var hidden = lowLevelPids.Where(pid => pid > 4 && !win32Pids.Contains(pid)).ToList();

                if (hidden.Count > 0)
                {
                    // 过滤保护进程（我们的服务/系统 4 号进程等）——仅提示无法打开的
                    var suspicious = hidden.Where(pid =>
                    {
                        try
                        {
                            var p = System.Diagnostics.Process.GetProcessById(pid);
                            return false; // 能通过 GetProcessById 打开说明只是快照时差
                        }
                        catch
                        {
                            return true;  // 真正"看不见"的进程
                        }
                    }).ToList();

                    if (suspicious.Count > 0)
                    {
                        findings.Add(new RootkitFinding
                        {
                            Category = "隐藏进程",
                            Name = $"发现 {suspicious.Count} 个无法通过常规 API 访问的进程",
                            Detail = $"PID: {string.Join(", ", suspicious)} —— " +
                                     "内核枚举可见但 Win32 层无法访问，符合 DKOM 链表摘除类隐藏迹象（少数受保护进程亦会命中，请结合上下文判断）。",
                            Severity = "Medium"
                        });
                    }
                }
            }
            catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }

            return findings;
        }

        // ============================================================
        // 3. 可疑内核驱动扫描：常规驱动目录外加载 / 目录缺失
        // ============================================================
        public static List<RootkitFinding> CheckSuspiciousDrivers(RootkitScanResult result)
        {
            var findings = new List<RootkitFinding>();

            try
            {
                IntPtr[] drivers = new IntPtr[1024];
                int needed;
                if (!EnumDeviceDrivers(drivers, drivers.Length * IntPtr.Size, out needed))
                    return findings;

                int count = Math.Min(needed / IntPtr.Size, drivers.Length);
                var driversRoot = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                    "System32", "drivers").ToLowerInvariant();

                int legitInWinDir = 0;
                var suspects = new List<string>();

                for (int i = 0; i < count; i++)
                {
                    var sb = new StringBuilder(1024);
                    if (GetDeviceDriverFileName(drivers[i], sb, sb.Capacity, out _) == 0) continue;

                    var path = sb.ToString();
                    // \SystemRoot\ 前缀转换为真实路径
                    if (path.StartsWith("\\SystemRoot\\", StringComparison.OrdinalIgnoreCase))
                        path = Path.Combine(
                            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                            path.Substring("\\SystemRoot\\".Length));
                    if (path.StartsWith("\\??\\", StringComparison.OrdinalIgnoreCase))
                        path = path.Substring(4);

                    var lower = path.ToLowerInvariant();
                    if (lower.Contains(driversRoot) || lower.Contains("\\winsxs\\"))
                    {
                        legitInWinDir++;
                        continue;
                    }

                    // 驱动目录之外加载的内核模块（合法软件也会命中，如杀软/虚拟机驱动，作为可疑提示）
                    suspects.Add(path);
                }

                result.ModulesScanned = count;

                if (suspects.Count > 0)
                {
                    findings.Add(new RootkitFinding
                    {
                        Category = "内核驱动",
                        Name = $"发现 {suspects.Count} 个非常规位置加载的内核驱动",
                        Detail = "以下驱动不在 System32\\drivers 或 WinSxS 目录中（合法杀软/虚拟机驱动属正常，未知来源需警惕）:\n" +
                                 string.Join("\n", suspects.Take(10)),
                        Severity = "Low"
                    });
                }
            }
            catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }

            return findings;
        }

        // ============================================================
        // 4. 持久化植入检查：IFEO / AppInit_DLLs / SafeBoot / Winlogon / hosts
        // ============================================================
        public static List<RootkitFinding> CheckPersistenceImplants()
        {
            var findings = new List<RootkitFinding>();

            try
            {
                using var hklm = Microsoft.Win32.RegistryKey
                    .OpenBaseKey(Microsoft.Win32.RegistryHive.LocalMachine, Microsoft.Win32.RegistryView.Registry64);

                // 4.1 IFEO Debugger 劫持
                using var ifeo = hklm.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options");
                if (ifeo != null)
                {
                    foreach (var sub in ifeo.GetSubKeyNames())
                    {
                        try
                        {
                            using var k = ifeo.OpenSubKey(sub);
                            var debugger = k?.GetValue("Debugger") as string;
                            if (!string.IsNullOrWhiteSpace(debugger))
                            {
                                findings.Add(new RootkitFinding
                                {
                                    Category = "持久化植入",
                                    Name = $"IFEO 劫持: {sub}",
                                    Detail = $"镜像劫持 Debugger 指向: {debugger} —— 任何进程 {sub} 启动时都会被重定向，恶意软件常用此手法。",
                                    Severity = "High"
                                });
                            }
                        }
                        catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
                    }
                }

                // 4.2 AppInit_DLLs
                using var appInit = hklm.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows");
                var appInitDlls = appInit?.GetValue("AppInit_DLLs") as string;
                if (!string.IsNullOrWhiteSpace(appInitDlls))
                {
                    findings.Add(new RootkitFinding
                    {
                        Category = "持久化植入",
                        Name = "AppInit_DLLs 非空",
                        Detail = $"值: {appInitDlls} —— 该键会向所有 GUI 进程注入 DLL，恶意软件常用作全局注入点。",
                        Severity = "Medium"
                    });
                }

                // 4.3 SafeBoot 服务注入（安全模式自启动）
                foreach (var mode in new[] { "Minimal", "Network" })
                {
                    using var safeBoot = hklm.OpenSubKey($@"SYSTEM\CurrentControlSet\Control\SafeBoot\{mode}");
                    if (safeBoot == null) continue;
                    foreach (var sub in safeBoot.GetSubKeyNames())
                    {
                        // 常见系统驱动白名单（rstr/tap/vds 等前缀略过），仅报可疑命名
                        if (sub.Length > 40 || sub.Contains("{") || sub.ToLowerInvariant().StartsWith("fireantivirus"))
                            continue;
                        if (IsUnusualSafeBootEntry(sub))
                        {
                            findings.Add(new RootkitFinding
                            {
                                Category = "持久化植入",
                                Name = $"SafeBoot 注入: {sub}",
                                Detail = $"服务 '{sub}' 注册在安全模式({mode})启动列表，恶意软件借安全模式免杀常用手法。",
                                Severity = "Medium"
                            });
                        }
                    }
                }

                // 4.4 Winlogon Shell / Userinit 篡改
                using var winlogon = hklm.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon");
                var shell = winlogon?.GetValue("Shell") as string;
                if (shell != null && !shell.Trim().Equals("explorer.exe", StringComparison.OrdinalIgnoreCase))
                {
                    findings.Add(new RootkitFinding
                    {
                        Category = "持久化植入",
                        Name = "Winlogon Shell 被篡改",
                        Detail = $"Shell = {shell} —— 系统外壳被替换。",
                        Severity = "High"
                    });
                }
                var userinit = winlogon?.GetValue("Userinit") as string;
                if (userinit != null &&
                    !userinit.Replace("\"", "").Trim().EndsWith("userinit.exe,", StringComparison.OrdinalIgnoreCase) &&
                    userinit.Split(',').Length > 2)
                {
                    findings.Add(new RootkitFinding
                    {
                        Category = "持久化植入",
                        Name = "Winlogon Userinit 追加项",
                        Detail = $"Userinit = {userinit} —— 登录时额外启动了非标准程序。",
                        Severity = "High"
                    });
                }

                // 4.5 hosts 劫持
                var hostsPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "etc", "hosts");
                if (File.Exists(hostsPath))
                {
                    var lines = File.ReadAllLines(hostsPath)
                        .Where(l => l.Trim().Length > 0 && !l.Trim().StartsWith("#"))
                        .ToList();
                    if (lines.Count > 20)
                    {
                        findings.Add(new RootkitFinding
                        {
                            Category = "持久化植入",
                            Name = $"hosts 文件异常（{lines.Count} 条有效记录）",
                            Detail = "hosts 重定向条目异常偏多，可能存在域名劫持。\n前几条: " +
                                     string.Join(" | ", lines.Take(5)),
                            Severity = "Medium"
                        });
                    }
                }
            }
            catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }

            return findings;
        }

        private static bool IsUnusualSafeBootEntry(string name)
        {
            // 已知正常的安全模式服务（微软组件常见前缀）
            var knownPrefixes = new[]
            {
                "afd", "classpnp", "disk", "dm", "file", "fltmgr", "hook", "kbd", "lanman",
                "moun", "mount", "mrxsmb", "ms", "mup", "ndis", "net", "nt", "partmgr", "pci",
                "ras", "rdp", "sac", "smb", "srv", "tcpip", "vga", "vol", "vmbus", "win",
                "ws2", "sam", "svc", "crypt", "event", "plugplay", "power", "prof", "batt",
                "sermouse", "vds", "iscsi", "storahci", "stornvme", "swenum", "umbus", "usb",
                "hid", "kd", "nsi", "wpdupfltr", "acpi", "intelide", "atapi", "cdrom", "flt"
            };
            var lower = name.ToLowerInvariant();
            return !knownPrefixes.Any(lower.StartsWith);
        }

        // ============================================================
        // P/Invoke
        // ============================================================
        [DllImport("ntdll.dll")]
        private static extern int NtQuerySystemInformation(int infoClass, IntPtr buffer, int length, ref int returnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string moduleName);

        [DllImport("psapi.dll", SetLastError = true)]
        private static extern bool EnumDeviceDrivers(IntPtr[] drivers, int arraySize, out int bytesNeeded);

        [DllImport("psapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int GetDeviceDriverFileName(IntPtr imageBase, StringBuilder fileName, int fileNameLength, out int returnLength);
    }
}