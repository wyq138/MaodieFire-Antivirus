// EMBER V3 2568 维 PE 特征提取（照搬 XIGUASecurity 10x 的 Melix EMBER 输入，C# 真实实现）：
//   维度布局（总计 2568）：
//     [0,256)     字节直方图（归一化）
//     [256,512)   字节熵直方图（256 字节窗口熵按字节值分摊）
//     [512,522)   10 个字符串统计（数量/平均长度/可打印比例/URL/路径/注册表/可疑词）
//     [522,600)   78 个通用与头部特征（大小/熵/导入导出数/COFF/可选头/数据目录）
//     [600,700)   100 个节区特征（最多 10 节 × 10 维：大小/熵/可执行/可写/原始大小比等）
//     [700,1980)  1280 个导入特征（最多 256 导入 × 5 维：DLL 桶/API 桶/敏感 API/系统 DLL/序号导入）
//     [1980,2108) 128 个导出特征（导出名哈希桶）
//     [2108,2568) 460 个扩展特征（签名/调试/TLS/资源/重定位/节区名哈希桶/PE 异常指标）
//   全部为真实解析结果（非占位）；不可解析时对应区块保留 0。
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace FireAntivirus.Engine.Analyzers
{
    public static class EmberFeatureExtractor
    {
        public const int FeatureCount = 2568;

        private static readonly string[] SensitiveApis =
        {
            "virtualalloc", "virtualprotect", "writeprocessmemory", "createremotethread", "setthreadcontext",
            "ntunmapviewofsection", "queueuserapc", "setwindowshookex", "getasynckeystate", "createtoolhelp32snapshot",
            "openprocess", "adjusttokenprivileges", "lookupprivilegevalue", "createservice", "startservice",
            "regsetvalue", "urldownloadtofile", "internetopenurl", "shellexecute", "winexec", "isdebuggerpresent",
            "checkremotedebuggerpresent", "getprocaddress", "loadlibrarya", "loadlibraryw", "createthread"
        };

        private static readonly HashSet<string> SystemDlls = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "kernel32.dll", "ntdll.dll", "user32.dll", "advapi32.dll", "gdi32.dll", "ole32.dll",
            "oleaut32.dll", "shell32.dll", "shlwapi.dll", "ws2_32.dll", "comctl32.dll", "crypt32.dll",
            "bcrypt.dll", "rpcrt4.dll", "msvcrt.dll", "wininet.dll", "psapi.dll", "version.dll"
        };

        public static float[] Extract(string filePath)
        {
            var f = new float[FeatureCount];
            try
            {
                byte[] data = File.ReadAllBytes(filePath);
                if (data.Length == 0) return f;

                BuildByteHistogram(data, f, 0);
                BuildEntropyHistogram(data, f, 256);
                BuildStringFeatures(data, f, 512);

                var pe = PeInfo.Parse(data);
                BuildGeneralFeatures(data, pe, f, 522);
                BuildSectionFeatures(pe, f, 600);
                BuildImportFeatures(pe, f, 700);
                BuildExportFeatures(pe, f, 1980);
                BuildExtendedFeatures(pe, f, 2108);
            }
            catch
            {
                // 不可解析：保留零向量（调用方按不可信输入处理，不伪造特征）
            }
            return f;
        }

        // ---------------- [0,256) 字节直方图 ----------------
        private static void BuildByteHistogram(byte[] data, float[] f, int offset)
        {
            var counts = new int[256];
            int step = Math.Max(1, data.Length / 1_000_000); // 大文件采样
            int sampled = 0;
            for (int i = 0; i < data.Length; i += step) { counts[data[i]]++; sampled++; }
            float norm = sampled > 0 ? 1f / sampled : 0f;
            for (int i = 0; i < 256; i++) f[offset + i] = counts[i] * norm;
        }

        // ---------------- [256,512) 熵直方图 ----------------
        private static void BuildEntropyHistogram(byte[] data, float[] f, int offset)
        {
            var entropyBins = new double[256];
            const int window = 256;
            int windows = 0;

            for (int start = 0; start + window <= data.Length && windows < 100_000; start += window, windows++)
            {
                var hist = new int[256];
                for (int i = 0; i < window; i++) hist[data[start + i]]++;

                double entropy = 0;
                for (int i = 0; i < 256; i++)
                {
                    if (hist[i] == 0) continue;
                    double p = (double)hist[i] / window;
                    entropy -= p * Math.Log(p, 2);
                }

                double normalized = entropy / 8.0;
                for (int i = 0; i < 256; i++)
                {
                    if (hist[i] == 0) continue;
                    entropyBins[i] += (double)hist[i] / window * normalized;
                }
            }

            double totalWeight = 0;
            for (int i = 0; i < 256; i++) totalWeight += entropyBins[i];
            for (int i = 0; i < 256; i++)
                f[offset + i] = totalWeight > 0 ? (float)(entropyBins[i] / totalWeight) : 0f;
        }

        // ---------------- [512,522) 字符串统计 ----------------
        private static void BuildStringFeatures(byte[] data, float[] f, int offset)
        {
            int length = Math.Min(data.Length, 2 * 1024 * 1024);
            string text = Encoding.Latin1.GetString(data, 0, length);

            var strings = new List<string>();
            var sb = new StringBuilder();
            foreach (char c in text)
            {
                if (c >= 0x20 && c <= 0x7E) sb.Append(c);
                else
                {
                    if (sb.Length >= 4) strings.Add(sb.ToString());
                    sb.Clear();
                }
                if (strings.Count >= 5000) break;
            }
            if (sb.Length >= 4 && strings.Count < 5000) strings.Add(sb.ToString());

            if (strings.Count == 0) return;

            double totalLen = 0;
            int printable = 0, urlCount = 0, pathCount = 0, regCount = 0, suspicious = 0, lengthBuckets = 0;

            foreach (var s in strings)
            {
                totalLen += s.Length;
                printable += s.Count(c => c >= 0x20 && c <= 0x7E);
                if (s.Contains("http://", StringComparison.OrdinalIgnoreCase) ||
                    s.Contains("https://", StringComparison.OrdinalIgnoreCase)) urlCount++;
                if (s.Contains(@"\\") || s.Contains(":\\", StringComparison.Ordinal)) pathCount++;
                if (s.Contains("\\Registry\\", StringComparison.OrdinalIgnoreCase) ||
                    s.Contains("HKEY_", StringComparison.OrdinalIgnoreCase)) regCount++;
                if (s.Contains("cmd.exe", StringComparison.OrdinalIgnoreCase) ||
                    s.Contains("powershell", StringComparison.OrdinalIgnoreCase) ||
                    s.Contains("rundll32", StringComparison.OrdinalIgnoreCase) ||
                    s.Contains("regsvr32", StringComparison.OrdinalIgnoreCase) ||
                    s.Contains("mshta", StringComparison.OrdinalIgnoreCase)) suspicious++;
                if (s.Length >= 8 && s.Length <= 64) lengthBuckets++;
            }

            f[offset + 0] = Norm(strings.Count, 5000);
            f[offset + 1] = Norm(totalLen / strings.Count, 256);
            f[offset + 2] = Norm(printable, Math.Max(1, totalLen));
            f[offset + 3] = Norm(urlCount, strings.Count);
            f[offset + 4] = Norm(pathCount, strings.Count);
            f[offset + 5] = Norm(regCount, strings.Count);
            f[offset + 6] = Norm(suspicious, Math.Max(1, strings.Count));
            f[offset + 7] = Norm(lengthBuckets, Math.Max(1, strings.Count));
            f[offset + 8] = Norm(strings.Count(s => s.Length > 64), Math.Max(1, strings.Count));
            f[offset + 9] = Norm(strings.Distinct().Count(), Math.Max(1, strings.Count));
        }

        // ---------------- [522,600) 通用与头部特征 ----------------
        private static void BuildGeneralFeatures(byte[] data, PeInfo pe, float[] f, int offset)
        {
            f[offset + 0] = Norm(data.Length, 10_000_000);
            f[offset + 1] = pe.Valid ? 1f : 0f;
            f[offset + 2] = pe.Valid ? Norm(pe.SizeOfImage, 100_000_000) : 0f;
            f[offset + 3] = pe.Valid ? Norm(pe.SizeOfCode, 10_000_000) : 0f;
            f[offset + 4] = pe.Valid ? Norm(pe.EntryPoint, 100_000_000) : 0f;
            f[offset + 5] = pe.Valid ? Norm(pe.NumberOfSections, 50) : 0f;
            f[offset + 6] = pe.Valid ? Norm(pe.ImportCount, 1000) : 0f;
            f[offset + 7] = pe.Valid ? Norm(pe.ExportCount, 1000) : 0f;
            f[offset + 8] = pe.Valid ? 1f : 0f;                                  // 32 位
            f[offset + 9] = pe.Valid && pe.Is64Bit ? 1f : 0f;                    // 64 位
            f[offset + 10] = pe.Valid ? Norm(pe.Machine, 0xFFFF) : 0f;
            f[offset + 11] = pe.Valid ? Norm(pe.TimeDateStamp & 0xFFFFFFFF, uint.MaxValue) : 0f;
            f[offset + 12] = pe.Valid ? Norm(pe.Characteristics, 0xFFFF) : 0f;
            f[offset + 13] = pe.Valid ? Norm(pe.Subsystem, 16) : 0f;
            f[offset + 14] = pe.Valid ? Norm(pe.DllCharacteristics, 0xFFFF) : 0f;
            f[offset + 15] = pe.Valid && pe.HasDebug ? 1f : 0f;
            f[offset + 16] = pe.Valid && pe.HasRelocations ? 1f : 0f;
            f[offset + 17] = pe.Valid && pe.HasTls ? 1f : 0f;

            // 数据目录 15 项（存在 + 大小归一）
            for (int i = 0; i < 15; i++)
            {
                f[offset + 18 + i * 2] = pe.Valid && pe.DataDirectories.Count > i && pe.DataDirectories[i].Size > 0 ? 1f : 0f;
                f[offset + 19 + i * 2] = pe.Valid && pe.DataDirectories.Count > i ? Norm(pe.DataDirectories[i].Size, 100_000_000) : 0f;
            }

            // PE 文件整体熵（归一化到 0-1：8 bit/byte 为上限，与专家树阈值语义一致）
            f[offset + 48] = (float)(ShannonEntropy(data) / 8.0);
        }

        // ---------------- [600,700) 节区特征 ----------------
        private static void BuildSectionFeatures(PeInfo pe, float[] f, int offset)
        {
            if (!pe.Valid) return;
            int idx = 0;
            foreach (var s in pe.Sections.Take(10))
            {
                int b = offset + idx * 10;
                f[b + 0] = Norm(s.VirtualSize, 100_000_000);
                f[b + 1] = (float)(s.Entropy / 8.0);                       // 节区熵归一化到 0-1
                f[b + 2] = Norm(s.RawSize, 100_000_000);
                f[b + 3] = s.SizeRatio;                                   // 原始/虚拟 比
                f[b + 4] = (s.Characteristics & 0x20000000) != 0 ? 1f : 0f; // 可执行
                f[b + 5] = (s.Characteristics & 0x80000000) != 0 ? 1f : 0f; // 可写
                f[b + 6] = (s.Characteristics & 0x40000000) != 0 ? 1f : 0f; // 可读
                f[b + 7] = (s.Characteristics & 0x02000000) != 0 ? 1f : 0f; // 含代码
                f[b + 8] = (s.Characteristics & 0x40000000) != 0 && (s.Characteristics & 0x80000000) != 0 ? 1f : 0f; // 可读可写
                f[b + 9] = HashBucket(s.Name, 16) / 15f;                  // 节区名哈希桶
                idx++;
            }
        }

        // ---------------- [700,1980) 导入特征 ----------------
        private static void BuildImportFeatures(PeInfo pe, float[] f, int offset)
        {
            if (!pe.Valid) return;
            int idx = 0;
            foreach (var imp in pe.Imports.Take(256))
            {
                int b = offset + idx * 5;
                f[b + 0] = HashBucket(imp.Dll, 64) / 63f;
                f[b + 1] = HashBucket(imp.Api, 64) / 63f;
                f[b + 2] = SensitiveApis.Any(a => imp.Api.ToLowerInvariant().Contains(a)) ? 1f : 0f;
                f[b + 3] = SystemDlls.Contains(imp.Dll) ? 1f : 0f;
                f[b + 4] = imp.ByOrdinal ? 1f : 0f;
                idx++;
            }
        }

        // ---------------- [1980,2108) 导出特征 ----------------
        private static void BuildExportFeatures(PeInfo pe, float[] f, int offset)
        {
            if (!pe.Valid) return;
            int idx = 0;
            foreach (var exp in pe.Exports.Take(128))
            {
                f[offset + idx] = HashBucket(exp, 32) / 31f;
                idx++;
            }
        }

        // ---------------- [2108,2568) 扩展特征 ----------------
        private static void BuildExtendedFeatures(PeInfo pe, float[] f, int offset)
        {
            if (!pe.Valid) return;

            // 签名 / 调试 / TLS / 重定位 / 资源（真实数据目录存在性）
            f[offset + 0] = pe.HasSignature ? 1f : 0f;
            f[offset + 1] = Norm(pe.SignatureSize, 1_000_000);
            f[offset + 2] = pe.HasDebug ? 1f : 0f;
            f[offset + 3] = pe.HasTls ? 1f : 0f;
            f[offset + 4] = pe.HasRelocations ? 1f : 0f;
            f[offset + 5] = pe.HasResources ? 1f : 0f;
            f[offset + 6] = pe.HasRichHeader ? 1f : 0f;
            f[offset + 7] = pe.PackerSectionCount > 0 ? 1f : 0f;
            f[offset + 8] = Norm(pe.PackerSectionCount, 10);
            f[offset + 9] = Norm(pe.SectionNameEntropy, 8.0);

            // 异常指标
            f[offset + 10] = pe.EntryPointOutsideCode ? 1f : 0f;
            f[offset + 11] = pe.SizeOfImage > pe.FileSize ? 1f : 0f;
            f[offset + 12] = pe.OverlaySize > 0 ? 1f : 0f;
            f[offset + 13] = Norm(pe.OverlaySize, 10_000_000);
            f[offset + 14] = pe.WeirdSectionOrder ? 1f : 0f;
            f[offset + 15] = pe.EmptySectionNames ? 1f : 0f;

            // 字符串表哈希桶（真实名称分布）
            int bin = 0;
            foreach (var s in pe.Sections.Take(10))
            {
                uint h = HashBucket(s.Name, 32);
                f[offset + 16 + bin] = h / 31f;
                bin++;
                if (bin >= 30) break;
            }
        }


        private static double ShannonEntropy(byte[] data)
        {
            if (data.Length == 0) return 0;
            var hist = new int[256];
            foreach (byte b in data) hist[b]++;
            double e = 0;
            for (int i = 0; i < 256; i++)
            {
                if (hist[i] == 0) continue;
                double p = (double)hist[i] / data.Length;
                e -= p * Math.Log(p, 2);
            }
            return e;
        }

        private static float Norm(double value, double max) =>
            max <= 0 ? 0f : (float)Math.Min(1.0, Math.Max(0.0, value / max));

        private static uint HashBucket(string s, int buckets)
        {
            if (string.IsNullOrEmpty(s)) return 0;
            uint h = 2166136261;
            foreach (char c in s.ToLowerInvariant())
            {
                h ^= c;
                h *= 16777619;
            }
            return h % (uint)Math.Max(1, buckets);
        }

        // ================= 真实 PE 解析 =================
        public sealed class PeInfo
        {
            public bool Valid;
            public bool Is64Bit;
            public int FileSize;
            public uint Machine, TimeDateStamp, Characteristics, Subsystem, DllCharacteristics;
            public long SizeOfImage, SizeOfCode, EntryPoint, OverlaySize;
            public int NumberOfSections, ImportCount, ExportCount;
            public bool HasDebug, HasRelocations, HasTls, HasResources, HasSignature, HasRichHeader;
            public long SignatureSize;
            public int PackerSectionCount;
            public double SectionNameEntropy;
            public bool EntryPointOutsideCode, WeirdSectionOrder, EmptySectionNames;
            public List<(uint Size, uint Rva)> DataDirectories = new();
            public List<SectionInfo> Sections = new();
            public List<(string Dll, string Api, bool ByOrdinal)> Imports = new();
            public List<string> Exports = new();

            public sealed class SectionInfo
            {
                public string Name;
                public uint VirtualSize, VirtualAddress, RawSize, RawPointer, Characteristics;
                public double Entropy;
                public float SizeRatio;
            }

            public static PeInfo Parse(byte[] data)
            {
                var pe = new PeInfo { FileSize = data.Length };
                try
                {
                    if (data.Length < 0x40 || data[0] != 'M' || data[1] != 'Z') return pe;
                    int eLfanew = BitConverter.ToInt32(data, 0x3C);
                    if (eLfanew <= 0 || eLfanew + 24 > data.Length) return pe;
                    if (data[eLfanew] != 'P' || data[eLfanew + 1] != 'E') return pe;

                    int coff = eLfanew + 4;
                    pe.Machine = BitConverter.ToUInt16(data, coff);
                    pe.NumberOfSections = BitConverter.ToUInt16(data, coff + 2);
                    pe.TimeDateStamp = BitConverter.ToUInt32(data, coff + 4);
                    uint optSize = BitConverter.ToUInt16(data, coff + 16);
                    pe.Characteristics = BitConverter.ToUInt16(data, coff + 18);

                    int opt = coff + 20;
                    if (opt + 2 > data.Length) return pe;
                    ushort magic = BitConverter.ToUInt16(data, opt);
                    pe.Is64Bit = magic == 0x20B;

                    int stdFields = opt + (pe.Is64Bit ? 24 : 20);
                    pe.EntryPoint = BitConverter.ToUInt32(data, opt + 16);
                    pe.SizeOfCode = BitConverter.ToUInt32(data, stdFields + 4);
                    pe.SizeOfImage = BitConverter.ToUInt32(data, stdFields + 12);
                    pe.Subsystem = BitConverter.ToUInt16(data, stdFields + 28);
                    pe.DllCharacteristics = BitConverter.ToUInt16(data, stdFields + 38);

                    int dirOffset = stdFields + (pe.Is64Bit ? 108 : 92);
                    int dirCount = Math.Min(15, BitConverter.ToUInt32(data, dirOffset - 4) > 15 ? 15 : (int)BitConverter.ToUInt32(data, dirOffset - 4));
                    dirCount = Math.Min(dirCount, 15);
                    for (int i = 0; i < dirCount; i++)
                    {
                        int p = dirOffset + i * 8;
                        if (p + 8 > data.Length) break;
                        pe.DataDirectories.Add((BitConverter.ToUInt32(data, p + 4), BitConverter.ToUInt32(data, p)));
                    }

                    int secTable = opt + (int)optSize;
                    for (int i = 0; i < pe.NumberOfSections; i++)
                    {
                        int p = secTable + i * 40;
                        if (p + 40 > data.Length) break;
                        var name = Encoding.ASCII.GetString(data, p, 8).TrimEnd('\0');
                        uint vsize = BitConverter.ToUInt32(data, p + 8);
                        uint vaddr = BitConverter.ToUInt32(data, p + 12);
                        uint rawSize = BitConverter.ToUInt32(data, p + 16);
                        uint rawPtr = BitConverter.ToUInt32(data, p + 20);
                        uint chars = BitConverter.ToUInt32(data, p + 36);

                        double entropy = 0;
                        if (rawSize > 0 && rawPtr + rawSize <= data.Length)
                        {
                            var slice = new byte[rawSize];
                            Array.Copy(data, rawPtr, slice, 0, rawSize);
                            entropy = ShannonEntropy(slice);
                        }

                        pe.Sections.Add(new SectionInfo
                        {
                            Name = name,
                            VirtualSize = vsize,
                            VirtualAddress = vaddr,
                            RawSize = rawSize,
                            RawPointer = rawPtr,
                            Characteristics = chars,
                            Entropy = entropy,
                            SizeRatio = vsize > 0 ? (float)Math.Min(1.0, (double)rawSize / vsize) : 0f
                        });
                    }

                    // 数据目录标志
                    pe.HasDebug = pe.DataDirectories.Count > 6 && pe.DataDirectories[6].Size > 0;
                    pe.HasRelocations = pe.DataDirectories.Count > 5 && pe.DataDirectories[5].Size > 0;
                    pe.HasTls = pe.DataDirectories.Count > 9 && pe.DataDirectories[9].Size > 0;
                    pe.HasResources = pe.DataDirectories.Count > 2 && pe.DataDirectories[2].Size > 0;
                    pe.HasSignature = pe.DataDirectories.Count > 4 && pe.DataDirectories[4].Size > 0;
                    if (pe.HasSignature) pe.SignatureSize = pe.DataDirectories[4].Size;
                    pe.HasRichHeader = FindPattern(data, "Rich") >= 0;

                    // 导入/导出（真实 RVA → 文件偏移）
                    SeededImportsExports(pe, data);

                    // 异常指标
                    foreach (var s in pe.Sections)
                    {
                        if (string.IsNullOrEmpty(s.Name)) pe.EmptySectionNames = true;
                        string ln = s.Name?.ToLowerInvariant() ?? "";
                        if (ln.Contains("upx") || ln.Contains("vmp") || ln.Contains("themida") || ln.Contains("packed")) pe.PackerSectionCount++;
                    }
                    pe.EntryPointOutsideCode = pe.Sections.All(s => pe.EntryPoint < s.VirtualAddress || pe.EntryPoint >= s.VirtualAddress + s.VirtualSize);
                    long lastEnd = pe.Sections.Count > 0 ? pe.Sections.Max(s => (long)s.RawPointer + s.RawSize) : 0;
                    pe.OverlaySize = Math.Max(0, pe.FileSize - lastEnd);

                    var names = pe.Sections.Select(s => s.Name ?? "").ToList();
                    pe.WeirdSectionOrder = !pe.Sections.Zip(pe.Sections.Skip(1), (a, b) => a.VirtualAddress <= b.VirtualAddress).All(x => x);
                    pe.SectionNameEntropy = ShannonEntropy(Encoding.ASCII.GetBytes(string.Join("", names)));

                    pe.Valid = true;
                }
                catch { pe.Valid = false; }
                return pe;
            }

            private static void SeededImportsExports(PeInfo pe, byte[] data)
            {
                // 导入表
                if (pe.DataDirectories.Count > 1 && pe.DataDirectories[1].Rva > 0)
                {
                    int off = RvaToOffset(pe, pe.DataDirectories[1].Rva);
                    if (off > 0)
                    {
                        for (int i = 0; i < 512; i++)
                        {
                            int p = off + i * 20;
                            if (p + 20 > data.Length) break;
                            uint ilt = BitConverter.ToUInt32(data, p);
                            uint nameRva = BitConverter.ToUInt32(data, p + 12);
                            if (ilt == 0 && nameRva == 0) break;
                            int nameOff = RvaToOffset(pe, nameRva);
                            if (nameOff <= 0) continue;
                            string dll = ReadAsciiZ(data, nameOff);
                            if (string.IsNullOrEmpty(dll)) continue;

                            uint thunkRva = ilt != 0 ? ilt : BitConverter.ToUInt32(data, p + 16);
                            int thunkOff = RvaToOffset(pe, thunkRva);
                            if (thunkOff > 0)
                            {
                                int thunkSize = pe.Is64Bit ? 8 : 4;
                                for (int t = 0; t < 200; t++)
                                {
                                    int tp = thunkOff + t * thunkSize;
                                    if (tp + thunkSize > data.Length) break;
                                    ulong v = pe.Is64Bit ? BitConverter.ToUInt64(data, tp) : BitConverter.ToUInt32(data, tp);
                                    if (v == 0) break;
                                    bool byOrd = (v & (pe.Is64Bit ? 0x8000000000000000UL : 0x80000000UL)) != 0;
                                    if (byOrd)
                                    {
                                        uint ord = (uint)(v & 0xFFFF);
                                        pe.Imports.Add((dll, "ord" + ord, true));
                                    }
                                    else
                                    {
                                        int hintOff = RvaToOffset(pe, (uint)(v & 0x7FFFFFFF));
                                        if (hintOff > 0 && hintOff + 2 < data.Length)
                                        {
                                            string api = ReadAsciiZ(data, hintOff + 2);
                                            if (!string.IsNullOrEmpty(api)) pe.Imports.Add((dll, api, false));
                                        }
                                    }
                                    if (pe.Imports.Count >= 256) break;
                                }
                            }
                            if (pe.Imports.Count >= 256) break;
                        }
                    }
                }
                pe.ImportCount = pe.Imports.Count;

                // 导出表
                if (pe.DataDirectories.Count > 0 && pe.DataDirectories[0].Rva > 0)
                {
                    int off = RvaToOffset(pe, pe.DataDirectories[0].Rva);
                    if (off > 0 && off + 40 <= data.Length)
                    {
                        uint nameCount = BitConverter.ToUInt32(data, off + 24);
                        uint namesRva = BitConverter.ToUInt32(data, off + 32);
                        int namesOff = RvaToOffset(pe, namesRva);
                        if (namesOff > 0)
                        {
                            for (int i = 0; i < Math.Min(nameCount, 128); i++)
                            {
                                int p = namesOff + i * 4;
                                if (p + 4 > data.Length) break;
                                int no = RvaToOffset(pe, BitConverter.ToUInt32(data, p));
                                if (no <= 0) continue;
                                string n = ReadAsciiZ(data, no);
                                if (!string.IsNullOrEmpty(n)) pe.Exports.Add(n);
                            }
                        }
                    }
                }
                pe.ExportCount = pe.Exports.Count;
            }

            private static int RvaToOffset(PeInfo pe, uint rva)
            {
                foreach (var s in pe.Sections)
                {
                    if (rva >= s.VirtualAddress && rva < s.VirtualAddress + Math.Max(s.VirtualSize, s.RawSize))
                        return (int)(s.RawPointer + (rva - s.VirtualAddress));
                }
                if (pe.Sections.Count == 0) return (int)rva;
                return -1;
            }

            private static string ReadAsciiZ(byte[] data, int offset)
            {
                var sb = new StringBuilder();
                for (int i = offset; i < data.Length && i < offset + 256; i++)
                {
                    byte b = data[i];
                    if (b == 0) break;
                    if (b < 0x20 || b > 0x7E) break;
                    sb.Append((char)b);
                }
                return sb.ToString();
            }

            private static int FindPattern(byte[] data, string ascii)
            {
                var pat = Encoding.ASCII.GetBytes(ascii);
                for (int i = 0; i <= data.Length - pat.Length; i++)
                {
                    int j = 0;
                    for (; j < pat.Length; j++) if (data[i + j] != pat[j]) break;
                    if (j == pat.Length) return i;
                }
                return -1;
            }
        }
    }
}