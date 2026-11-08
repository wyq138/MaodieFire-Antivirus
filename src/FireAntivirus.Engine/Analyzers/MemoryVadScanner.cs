// VAD 树隐匿内存剥离：
//   VirtualQueryEx 遍历目标进程虚拟地址描述符（VAD），筛出 MEM_PRIVATE + 可执行 + 已提交的匿名内存，
//   ReadProcessMemory 剥离内容后做熵 / PE 头 / shellcode 签名 / 敏感字符串分析；
//   High 级可疑区可 dump 到 ProgramData\FireAntivirus\MemoryDumps 供取证。
//   权限不足（系统进程）如实返回错误，不伪造结果。
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace FireAntivirus.Engine.Analyzers
{
    public sealed class VadFinding
    {
        public int Pid { get; set; }
        public string ProcessName { get; set; }
        public long BaseAddress { get; set; }
        public long Size { get; set; }
        public uint Protect { get; set; }
        public double Entropy { get; set; }
        public bool LooksLikePe { get; set; }
        public int Score { get; set; }
        public List<string> Reasons { get; set; } = new List<string>();
    }

    public sealed class VadScanReport
    {
        public int Pid { get; set; }
        public string ProcessName { get; set; }
        public int ScannedRegions { get; set; }
        public List<VadFinding> Findings { get; set; } = new List<VadFinding>();
        public string Error { get; set; }
        public bool AccessDenied { get; set; }
    }

    public static class MemoryVadScanner
    {
        public static bool Enabled { get; set; } = true;
        public static int MinRegionSize { get; set; } = 4096;
        public static int MaxRegionSize { get; set; } = 64 * 1024 * 1024;
        public static int MaxReadBytesPerRegion { get; set; } = 4 * 1024 * 1024;
        public static string DumpDirectory { get; set; } = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "FireAntivirus", "MemoryDumps");

        private const uint PROCESS_QUERY_INFORMATION = 0x0400;
        private const uint PROCESS_VM_READ = 0x0010;
        private const uint MEM_COMMIT = 0x1000;
        private const uint MEM_PRIVATE = 0x20000;
        private const uint PAGE_GUARD = 0x100;
        private const uint PAGE_NOACCESS = 0x01;
        private const uint EXECUTABLE = 0x10 | 0x20 | 0x40 | 0x80;

        [StructLayout(LayoutKind.Sequential)]
        private struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr VirtualQueryEx(IntPtr process, IntPtr address,
            out MEMORY_BASIC_INFORMATION info, UIntPtr length);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(IntPtr process, IntPtr baseAddress,
            byte[] buffer, UIntPtr size, out UIntPtr bytesRead);

        public static VadScanReport ScanProcess(int pid)
        {
            var report = new VadScanReport { Pid = pid };
            if (!Enabled || pid <= 0) return report;

            try
            {
                using var process = System.Diagnostics.Process.GetProcessById(pid);
                report.ProcessName = process.ProcessName;
            }
            catch (Exception ex)
            {
                report.Error = "进程不存在或已退出: " + ex.Message;
                return report;
            }

            IntPtr handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
            if (handle == IntPtr.Zero)
            {
                report.AccessDenied = true;
                report.Error = $"OpenProcess 失败（权限不足，Win32={Marshal.GetLastWin32Error()}）";
                return report;
            }

            try
            {
                long address = 0;
                const long maxUserAddress = 0x7FFFFFFF0000L;
                var info = new MEMORY_BASIC_INFORMATION();
                int guard = 0;

                while (address < maxUserAddress && guard++ < 400000)
                {
                    if (VirtualQueryEx(handle, new IntPtr(address), out info, (UIntPtr)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>()) == IntPtr.Zero)
                        break;

                    long regionSize = info.RegionSize.ToInt64();
                    if (regionSize <= 0) break;

                    bool executable = info.State == MEM_COMMIT
                                      && (info.Protect & EXECUTABLE) != 0
                                      && (info.Protect & (PAGE_GUARD | PAGE_NOACCESS)) == 0;
                    bool privateMemory = info.Type == MEM_PRIVATE;

                    if (executable && privateMemory && regionSize >= MinRegionSize && regionSize <= MaxRegionSize)
                    {
                        report.ScannedRegions++;
                        var finding = AnalyzeRegion(handle, pid, report.ProcessName,
                            info.BaseAddress.ToInt64(), regionSize, info.Protect);
                        if (finding != null && finding.Score >= 50) report.Findings.Add(finding);
                    }

                    long next = info.BaseAddress.ToInt64() + regionSize;
                    if (next <= address) break;
                    address = next;
                }

                report.Findings = report.Findings.OrderByDescending(f => f.Score).ToList();
            }
            catch (Exception ex)
            {
                report.Error = ex.Message;
            }
            finally
            {
                CloseHandle(handle);
            }
            return report;
        }

        public static List<VadScanReport> ScanProcesses(IEnumerable<int> pids, int maxProcesses = 30)
        {
            var reports = new List<VadScanReport>();
            if (!Enabled || pids == null) return reports;
            foreach (int pid in pids.Where(p => p > 0).Distinct().Take(maxProcesses))
            {
                try { reports.Add(ScanProcess(pid)); } catch { }
            }
            return reports;
        }

        private static VadFinding AnalyzeRegion(IntPtr handle, int pid, string processName,
            long baseAddress, long regionSize, uint protect)
        {
            int readSize = (int)Math.Min(regionSize, MaxReadBytesPerRegion);
            var buffer = new byte[readSize];
            if (!ReadProcessMemory(handle, new IntPtr(baseAddress), buffer,
                    (UIntPtr)(uint)readSize, out UIntPtr read))
                return null;

            int actual = (int)read.ToUInt64();
            if (actual < 64) return null;

            var finding = new VadFinding
            {
                Pid = pid,
                ProcessName = processName,
                BaseAddress = baseAddress,
                Size = regionSize,
                Protect = protect,
                Entropy = Entropy(buffer, actual),
                Score = 40,
                Reasons = { "MEM_PRIVATE 匿名可执行内存（无文件支撑）" }
            };

            if (buffer[0] == 'M' && buffer[1] == 'Z')
            {
                finding.LooksLikePe = true;
                int peOffset = actual > 0x40 ? BitConverter.ToInt32(buffer, 0x3C) : -1;
                bool hasPeHeader = peOffset > 0 && peOffset + 4 <= actual
                                   && buffer[peOffset] == 'P' && buffer[peOffset + 1] == 'E';
                finding.Score = hasPeHeader ? 85 : 70;
                finding.Reasons.Add(hasPeHeader ? "匿名内存中存在完整 PE 头（反射加载/手动映射）" : "匿名内存中存在 MZ 头");
            }

            if (finding.Entropy >= 7.5)
            {
                finding.Score += 10;
                finding.Reasons.Add($"高熵 {finding.Entropy:F2}（加密/编码载荷）");
            }

            if (Contains(buffer, actual, new byte[] { 0xFC, 0x48, 0x83, 0xE4, 0xF0 }))
            {
                finding.Score += 20;
                finding.Reasons.Add("Metasploit x64 shellcode 特征 (fc 48 83 e4 f0)");
            }
            if (Contains(buffer, actual, new byte[] { 0xFC, 0xE8 }))
            {
                finding.Score += 10;
                finding.Reasons.Add("x86 shellcode 常见入口 (fc e8)");
            }

            string text = Encoding.ASCII.GetString(buffer, 0, actual).ToLowerInvariant();
            foreach (var marker in new[] { "virtualalloc", "winexec", "createremotethread", "getprocaddress", "loadlibrary", "cmd.exe", "powershell", "http://", "https://" })
            {
                if (text.Contains(marker)) { finding.Score += 8; finding.Reasons.Add("敏感字符串: " + marker); }
            }

            finding.Score = Math.Clamp(finding.Score, 0, 100);
            return finding;
        }

        public static bool DumpRegion(int pid, long baseAddress, long size, out string outputPath, out string error)
        {
            outputPath = "";
            error = "";
            try
            {
                Directory.CreateDirectory(DumpDirectory);
                outputPath = Path.Combine(DumpDirectory, $"pid{pid}_{baseAddress:X}_{size:X}.bin");

                using var process = System.Diagnostics.Process.GetProcessById(pid);
                IntPtr handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
                if (handle == IntPtr.Zero) { error = "OpenProcess 失败（需要管理员权限）"; outputPath = ""; return false; }
                try
                {
                    int readSize = (int)Math.Min(size, MaxReadBytesPerRegion);
                    var buffer = new byte[readSize];
                    if (!ReadProcessMemory(handle, new IntPtr(baseAddress), buffer, (UIntPtr)(uint)readSize, out UIntPtr read))
                    {
                        error = $"ReadProcessMemory 失败（Win32={Marshal.GetLastWin32Error()}）";
                        outputPath = "";
                        return false;
                    }
                    File.WriteAllBytes(outputPath, buffer.Take((int)read.ToUInt64()).ToArray());
                    return true;
                }
                finally { CloseHandle(handle); }
            }
            catch (Exception ex)
            {
                error = ex.Message;
                outputPath = "";
                return false;
            }
        }

        private static double Entropy(byte[] data, int length)
        {
            if (length <= 0) return 0;
            var counts = new int[256];
            for (int i = 0; i < length; i++) counts[data[i]]++;
            double entropy = 0;
            for (int i = 0; i < 256; i++)
            {
                if (counts[i] == 0) continue;
                double p = (double)counts[i] / length;
                entropy -= p * Math.Log2(p);
            }
            return entropy;
        }

        private static bool Contains(byte[] haystack, int length, byte[] needle)
        {
            for (int i = 0; i + needle.Length <= length; i++)
            {
                bool match = true;
                for (int j = 0; j < needle.Length; j++)
                {
                    if (haystack[i + j] != needle[j]) { match = false; break; }
                }
                if (match) return true;
            }
            return false;
        }
    }
}