using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using FireAntivirus.Common;

namespace FireAntivirus.Engine.Analyzers
{
    /// <summary>
    /// PE 加壳/熵 行为证据分析器。
    /// 角色定位：绝不单独定罪，只产出"打包/变形"类的弱证据（evidence），
    /// 供静态/启发式阶段在"已经命中强信号"时进一步放大置信度，或补充独立弱分。
    /// 这样既提升对"压缩壳+恶意导入"类样本的检出，又不会把合法加壳软件（常带可信签名）误报。
    /// </summary>
    public sealed class PackingAnalyzer
    {
        // ---- PE 解析结果 ----
        private sealed class SectionInfo
        {
            public string Name = "";
            public uint VirtualSize;
            public uint RawSize;
            public int RawPtr;
            public uint Characteristics;
            public double Entropy;      // 基于原始数据的香农熵
        }

        public sealed class PackingEvidence
        {
            public bool IsPacked;                 // 综合判定疑似加壳
            public bool HasTlsCallbacks;          // 存在 TLS 回调（解壳常见）
            public double EpEntropy;              // 入口点所在节的熵
            public double MaxSectionEntropy;      // 全节最大熵
            public string EpSection = "";         // 入口点所在节名
            public string MatchSection = "";      // 命中的已知壳节区名（如有）
            public double Strength;               // 打包证据强度 0..1（弱信号）
            public string Notes = "";             // 供日志/报告使用的中文描述
            public bool IsValid;                  // 是否为可解析的 PE PE32/PE32+
        }

        private const int PE_OFFSET_LOC = 0x3C;
        private const ushort IMAGE_NT_SIGNATURE = 0x4550;      // 'PE\0\0' 低16位'PE'
        private const int PEP32_OPT = 224;
        private const int PEP64_OPT = 240;

        /// <summary>对原始文件字节执行加壳/熵证据提取。</summary>
        public PackingEvidence Analyze(byte[] data)
        {
            var ev = new PackingEvidence { IsValid = false };
            try
            {
                if (data == null || data.Length < 0x40) return ev;
                if (data[0] != 0x4D || data[1] != 0x5A) return ev;   // 非 MZ

                int peOff = BitConverter.ToInt32(data, PE_OFFSET_LOC);
                if (peOff + 4 > data.Length) return ev;
                if (BitConverter.ToUInt16(data, peOff) != IMAGE_NT_SIGNATURE) return ev;

                ushort magic = BitConverter.ToUInt16(data, peOff + 24);
                if (magic != 0x10B && magic != 0x20B) return ev;      // 非 PE32/PE32+
                bool is32 = magic == 0x10B;
                int optSize = is32 ? PEP32_OPT : PEP64_OPT;
                ev.IsValid = true;

                // 数据目录：OptionalHeader 尾部的 DataDirectory[]（16 项，每项 8 字节）
                int dataDirOff = peOff + 24 + optSize;
                uint tlsRva = 0;
                if (dataDirOff + 8 * 9 + 4 <= data.Length)             // TLS 目录是第 9 项
                {
                    tlsRva = BitConverter.ToUInt32(data, dataDirOff + 8 * 9);
                }

                ushort sectionCount = BitConverter.ToUInt16(data, peOff + 6);
                int sectionTable = peOff + 24 + optSize;
                if (sectionCount > 96) sectionCount = 96;              // 防御异常字段

                var order = new List<SectionInfo>();
                var rvaToOffset = new List<(uint rva, uint size, int offset)>();
                for (int i = 0; i < sectionCount; i++)
                {
                    int baseIdx = sectionTable + i * 40;
                    if (baseIdx + 40 > data.Length) break;
                    var sec = new SectionInfo
                    {
                        Name = ReadAscii(data, baseIdx, 8).TrimEnd('\0').Trim(),
                        VirtualSize = BitConverter.ToUInt32(data, baseIdx + 8),
                        RawSize = BitConverter.ToUInt32(data, baseIdx + 16),
                        RawPtr = BitConverter.ToInt32(data, baseIdx + 20),
                        Characteristics = BitConverter.ToUInt32(data, baseIdx + 36)
                    };
                    uint vSize = Math.Max(sec.VirtualSize, sec.RawSize);
                    rvaToOffset.Add((BitConverter.ToUInt32(data, baseIdx + 12), vSize, sec.RawPtr));
                    order.Add(sec);
                }

                int RvaToOffset(int rva)
                {
                    foreach (var s in rvaToOffset)
                        if (rva >= s.rva && rva < s.rva + s.size && s.offset >= 0)
                            return s.offset + (rva - (int)s.rva);
                    return rva;
                }

                // 逐节熵
                double maxEntropy = 0.0;
                foreach (var s in order)
                {
                    s.Entropy = ComputeSectionEntropy(data, s.RawPtr, (int)Math.Min(s.RawSize, (uint)Math.Max(0, data.Length - s.RawPtr)));
                    if (s.Entropy > maxEntropy) maxEntropy = s.Entropy;
                }
                ev.MaxSectionEntropy = maxEntropy;

                // 入口点所在节的熵与名称
                int epRva = BitConverter.ToInt32(data, peOff + 24 + 16);
                int epOff = RvaToOffset(epRva);
                var epSection = order.FirstOrDefault(s => epRva > 0 &&
                              epRva >= 0 && epRva < (long)Math.Max(s.VirtualSize, s.RawSize) &&
                              epOff >= s.RawPtr && epOff < s.RawPtr + (int)s.RawSize);
                if (epSection == null && order.Count > 0)
                {
                    for (int i = order.Count - 1; i >= 0; i--)
                        if (epOff >= order[i].RawPtr && epOff < order[i].RawPtr + (int)order[i].RawSize) { epSection = order[i]; break; }
                }
                if (epSection != null)
                {
                    ev.EpSection = epSection.Name;
                    ev.EpEntropy = epSection.Entropy;
                }

                // TLS 回调
                ev.HasTlsCallbacks = tlsRva > 0;

                // 命中已知壳/恶意节区名（特征外置）：信任 >0.78 才显著
                foreach (var s in order)
                {
                    var feats = FireAntivirus.Engine.Data.EmbeddedThreatDatabase.LookupSection(s.Name.ToUpperInvariant());
                    var strong = feats.Where(f => f.Confidence >= 0.78).OrderByDescending(f => f.Confidence).FirstOrDefault();
                    if (strong != null && ev.MatchSection.Length == 0)
                    {
                        ev.MatchSection = $"{strong.Family}({s.Name})";
                        ev.Notes = strong.Description;
                    }
                }

                // ---- 证据强度综合（全部为"弱信号"，最高约 0.35）----
                double str = 0.0;
                // 入口点落在高熵节 -> 常见于解壳桩
                if (epSection != null)
                {
                    if (ev.EpEntropy > 7.6) str += 0.13;
                    else if (ev.EpEntropy > 7.1) str += 0.07;
                }
                // 任一节高熵 + 压缩比明显（unsual 的 rawSize 远小于 VirtualSize）
                foreach (var s in order)
                {
                    if (s.RawSize == 0) continue;
                    double ratio = (double)Math.Min(s.VirtualSize, s.RawSize) / s.RawSize;
                    if (s.Entropy > 7.4 && ratio < 0.8) { str += 0.08; break; }
                }
                // 高熵且未签名（合法加壳多带签名，这里作为提示而非定罪）
                if (maxEntropy > 7.6 && !HasSignature(data)) str += 0.05;
                // 强壳节区命中 -> 弱加分
                if (ev.MatchSection.Length > 0) str += 0.14;
                // TLS 回调存在（解包加载器常用）
                if (ev.HasTlsCallbacks && maxEntropy > 7.2) str += 0.05;

                ev.Strength = Math.Min(0.35, str);
                ev.IsPacked = ev.Strength >= 0.18 &&
                             (!HasSignature(data));       // 有可信数字签名时不算打包证据
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                    "PackingAnalyzer 解析失败", ex.Message);
            }
            return ev;
        }

        /// <summary>是否为带数字证书（安全目录数据目录存在且非零）的 PE。</summary>
        private static bool HasSignature(byte[] data)
        {
            try
            {
                if (data == null || data.Length < 0x40) return false;
                int peOff = BitConverter.ToInt32(data, PE_OFFSET_LOC);
                ushort magic = data.Length > peOff + 24 + 2 ? BitConverter.ToUInt16(data, peOff + 24) : (ushort)0;
                bool is32 = magic == 0x10B;
                int optSize = is32 ? PEP32_OPT : PEP64_OPT;
                int securityDir = peOff + 24 + optSize + 8 * 4;      // 安全目录是第 4 项
                if (securityDir + 4 > data.Length) return false;
                uint rva = BitConverter.ToUInt32(data, securityDir);
                uint size = BitConverter.ToUInt32(data, securityDir + 4);
                return rva > 0 && size > 8;
            }
            catch { return false; }
        }

        private static double ComputeSectionEntropy(byte[] data, int offset, int length)
        {
            if (data == null || length <= 0 || offset < 0 || offset >= data.Length) return 0.0;
            int n = Math.Min(length, data.Length - offset);
            if (n <= 0) return 0.0;

            long[] freq = new long[256];
            for (int i = 0; i < n; i++) freq[data[offset + i]]++;

            double entropy = 0.0;
            for (int i = 0; i < 256; i++)
            {
                if (freq[i] == 0) continue;
                double p = (double)freq[i] / n;
                entropy -= p * Math.Log(p, 2);
            }
            return entropy;
        }

        private static string ReadAscii(byte[] data, int offset, int maxLen)
        {
            if (offset < 0 || offset >= data.Length) return string.Empty;
            int end = offset;
            int max = Math.Min(data.Length, offset + maxLen);
            while (end < max && data[end] != 0) end++;
            if (end <= offset) return string.Empty;
            var sb = new System.Text.StringBuilder();
            for (int i = offset; i < end; i++) sb.Append((char)data[i]);
            return sb.ToString();
        }
    }
}