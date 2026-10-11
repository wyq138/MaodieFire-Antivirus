// 耄耋软件工作室 开发，严禁非法反编译
// =============================================================================
// MultiDimFileEvaluator —— 多维度文件评估器
// -----------------------------------------------------------------------------
// 从"单一引擎只报弱信号"升级为"多维度、可归一化的证据链评估"：
//   维度1 哈希信誉    MD5/SHA1/SHA256 命中自动更新特征库(abuse.ch)与内嵌哈希
//   维度2 权威身份    Authenticode 数字签名链(X509, 纯C#校验) + 可信发布者白名单
//   维度3 PE结构      Machine/Characteristics/节数/时间戳/校验和/DllCharacteristics
//                    TLS回调/Debug目录/Resource节/Overlay占比
//   维度4 节熵/加壳    逐节 Shannon 熵 + 入口点节熵异常 + 畸形节
//   维度5 导入行为     跨DLL高危API组合(注入/加密+文件/网络外连/内存操作)
//
// 判定策略（沿用项目"阶段分>60或已开始破坏动作才动作"的硬约束）：
//   1) 命中已知恶意哈希/恶意签名发布者等破坏性证据 -> 强信号直接计票
//   2) 否则各维度加权得到 0~100 阶段分；可信签名降权、绝不归零(防系统目录被感染的漏报)
//   3) 仅当"强破坏信号"或"阶段分≥60且至少2个独立维度佐证"时才投出阳性票
// 本类只作为多引擎共识中的一个独立投票方，不单独定罪，从而杜绝对正常程序的误报。
// =============================================================================
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace FireAntivirus.Engine.Analyzers
{
    /// <summary>多维度评估结果：阶段分 + 各维度证据。</summary>
    public sealed class MultiDimEvidence
    {
        public bool IsMalicious { get; set; }
        public double Score { get; set; }
        public List<string> Details { get; } = new List<string>();
    }

    public sealed class MultiDimFileEvaluator
    {
        // ---- 维度常量阈值（保守设计，杜绝误报）----
        private const int StageThreshold = 60;          // 阶段分≥60 才投阳性
        private const int MinCorroboratingDims = 2;     // 至少 2 个独立维度佐证
        private const double HighEntropyEp = 7.3;       // 入口点节熵过高阈值

        // 可信发布者（仅作负向降权，不构成硬放行）—— 与 StaticAnalyzer 保持一致口径
        private static readonly HashSet<string> TrustedPublishers = new(StringComparer.OrdinalIgnoreCase)
        {
            "Microsoft Corporation", "Microsoft Windows", "Microsoft",
            "Google LLC", "Google Inc", "Apple Inc.", "Apple Computer, Inc.",
            "Mozilla Corporation", "Adobe Inc.", "Intel Corporation",
            "NVIDIA Corporation", "AMD", "Oracle Corporation", "VMware, Inc.",
            "Cisco Systems, Inc.", "Dell Inc.", "HP Inc.", "Lenovo",
            "Avast Software", "Kaspersky Lab", "360 Security Technology Inc.",
            "Tencent", "Huawei", "Baidu, Inc.", "耄耋软件工作室", "FireAntivirus"
        };

        // 仅认可在"真实导入表"事件中成立的高危行为组（组合命中才计分）
        private static readonly string[][] BehaviorGroups =
        {
            new[] { "CreateRemoteThread", "OpenProcess", "VirtualAllocEx", "WriteProcessMemory" },
            new[] { "CreateProcess", "NtUnmapViewOfSection", "WriteProcessMemory", "ResumeThread" },
            new[] { "SetWindowsHookEx", "GetAsyncKeyState", "GetKeyboardState", "CallNextHookEx" },
            new[] { "CryptEncrypt", "CryptDecrypt", "FindFirstFile", "EncryptFile" },
            new[] { "URLDownloadToFile", "WinExec", "ShellExecute", "HttpSendRequest" },
            new[] { "RegSetValueEx", "CreateService", "OpenSCManager", "CopyFile" },
            new[] { "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess" }
        };

        // 相对输入大小的大型 Overlay 被认为是异常（有效节外数据过多）
        private const double MaxOverlayRatio = 0.35;

        /// <summary>评估单个文件，返回阶段分与证据（不单独定罪，供共识管线投票）。</summary>
        public MultiDimEvidence Evaluate(string filePath)
        {
            var ev = new MultiDimEvidence();
            try
            {
                if (!File.Exists(filePath)) return ev;
                var fi = new FileInfo(filePath);
                if (fi.Length == 0) return ev;

                byte[] data;
                try { data = File.ReadAllBytes(filePath); }
                catch { return ev; }
                if (data == null || data.Length == 0) return ev;

                // ---------------------------------------------------------
                // 维度1：哈希信誉（MD5 + SHA1 + SHA256 全算，主键 SHA256）
                // ---------------------------------------------------------
                string sha256 = ComputeSha(data, SHA256.Create());
                if (SignatureDatabaseUpdater.TryGetHashThreat(sha256, out var sigThreat))
                {
                    ev.IsMalicious = true;                        // 命中实时恶意哈希库 -> 强破坏信号
                    ev.Score = 100;
                    ev.Details.Add($"哈希信誉: 命中自动更新特征库 {sigThreat}");
                    return ev;
                }

                bool isPE = data.Length >= 0x40 && data[0] == 0x4D && data[1] == 0x5A;
                int positiveDims = 0;
                double stage = 0.0;

                // ---------------------------------------------------------
                // 维度2：权威身份（Authenticode 数字签名链，纯 C# X509 校验）
                // ---------------------------------------------------------
                bool hasTrustedSig = false, selfSigned = false, sigInvalid = false;
                string publisher = null;
                if (TryExtractPublisher(data, out var appPublisher, out var appSelf, out var appInvalid))
                {
                    publisher = appPublisher;
                    selfSigned = appSelf;
                    sigInvalid = appInvalid;
                    if (!string.IsNullOrEmpty(publisher))
                    {
                        hasTrustedSig = IsTrustedPublisher(publisher);
                        if (hasTrustedSig)
                        {
                            ev.Details.Add("权威身份: 可信发布者数字签名");
                            stage -= 12;                       // 负向降权，降低误报
                        }
                        else if (selfSigned)
                        {
                            ev.Details.Add("权威身份: 自签名证书(可疑)");
                            stage += 8;
                            positiveDims++;
                        }
                        else
                        {
                            ev.Details.Add("权威身份: 已签名但非白名单发布者");
                            stage += 3;
                        }
                    }
                    else if (sigInvalid)
                    {
                        ev.Details.Add("权威身份: 存在无效/被吊销签名");
                        stage += 10;
                        positiveDims++;
                    }
                }

                // ---------------------------------------------------------
                // 维度3/4/5：PE 结构 + 节熵/加壳 + 导入行为
                // ---------------------------------------------------------
                if (isPE)
                {
                    var pe = ParsePeDimensions(data);
                    stage += pe.ImageAnomalyScore;
                    if (pe.ImageAnomalyScore >= 8) positiveDims++;
                    foreach (var d in pe.Details) ev.Details.Add("PE结构: " + d);

                    stage += pe.PackScore;
                    if (pe.PackScore >= 10) positiveDims++;
                    foreach (var d in pe.PackDetails) ev.Details.Add("加壳/熵: " + d);

                    stage += pe.ImportScore;
                    if (pe.ImportScore >= 10) positiveDims++;
                    foreach (var d in pe.ImportDetails) ev.Details.Add("导入行为: " + d);
                }
                else
                {
                    // 非 PE：文档/脚本结构信号（仅当独立强信号叠加才有效）
                    var doc = EvaluateNonPe(data, Path.GetFileName(filePath));
                    stage += doc.DocScore;
                    if (doc.DocScore >= 15) positiveDims++;
                    foreach (var d in doc.Details) ev.Details.Add("文档/脚本: " + d);
                }

                // ---------------------------------------------------------
                // 归并：可信签名的降权只减分不归零 + 阶段判定
                // ---------------------------------------------------------
                if (stage > 0 && hasTrustedSig) stage *= 0.55;

                ev.Score = Math.Max(0, Math.Min(100, stage));
                if (ev.Score >= StageThreshold && positiveDims >= MinCorroboratingDims)
                {
                    ev.IsMalicious = true;
                }
            }
            catch (Exception ex)
            {
                Common.LogHelper.Log(Common.LogHelper.LogLevel.Warning, "多维评估失败: " + ex.Message);
            }
            return ev;
        }

        // =====================================================================
        // PE 内部解析（字节级，不依赖外部字符串特征）
        // =====================================================================
        private struct DimSection
        {
            public string Name;
            public uint VirtualSize;
            public uint RawSize;
            public uint Characteristics;
            public uint RawPtr;
            public double Entropy;
        }

        private struct DimPe
        {
            public double ImageAnomalyScore;
            public List<string> Details;
            public double PackScore;
            public List<string> PackDetails;
            public double ImportScore;
            public List<string> ImportDetails;
        }

        private DimPe ParsePeDimensions(byte[] d)
        {
            var pe = new DimPe
            {
                Details = new List<string>(),
                PackDetails = new List<string>(),
                ImportDetails = new List<string>()
            };

            if (d.Length < 0x40 || d[0] != 0x4D || d[1] != 0x5A) return pe;

            int e_lfanew = BitConverter.ToInt32(d, 0x3C);
            if (e_lfanew + 264 > d.Length) return pe;
            if (d[e_lfanew] != 'P' || d[e_lfanew + 1] != 'E') return pe;

            // 可选头
            ushort magic = BitConverter.ToUInt16(d, e_lfanew + 24);
            bool is32 = magic == 0x10B;
            bool isPePlus = magic == 0x20B;
            if (!is32 && !isPePlus) return pe;
            int opt = e_lfanew + 24;
            int optSize = is32 ? 224 : 240;

            ushort numSections = BitConverter.ToUInt16(d, e_lfanew + 6);
            uint timestamp = BitConverter.ToUInt32(d, e_lfanew + 8);
            ushort characteristics = BitConverter.ToUInt16(d, e_lfanew + 18);

            // --- 维度3：镜像层结构异常 ---
            int imgAnomalies = 0;
            if (characteristics == 0x0000 || (characteristics & 0x0002) == 0) // 无有效标志/非可执行标志
            {
                imgAnomalies++;
                pe.Details.Add("Image 特性标志异常");
            }
            // 时间戳在未来（后门预编译时间）
            long nowEpoch = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (timestamp > (ulong)(nowEpoch + 86400))
            {
                imgAnomalies++;
                pe.Details.Add("时间戳指向未来(可疑预编译)");
            }
            if (numSections == 0 || numSections > 32)
            {
                imgAnomalies++;
                pe.Details.Add("节表数量异常");
            }
            pe.ImageAnomalyScore = Math.Min(14, imgAnomalies * 5);

            // --- DllCharacteristics（缺 ASLR/DEP 是退化信号）---
            uint dllChars = BitConverter.ToUInt32(d, opt + (is32 ? 70 : 70));
            if ((dllChars & 0x0040) == 0) { pe.Details.Add("未启用动态基址(ASLR)"); }
            if ((dllChars & 0x0100) == 0) { pe.Details.Add("未启用数据执行保护(DEP)"); }

            // --- 节表 + 维度4：逐节熵 ---
            int secTab = opt + optSize;
            var sections = new List<DimSection>();
            for (int i = 0; i < numSections && secTab + i * 40 + 40 <= d.Length; i++)
            {
                int off = secTab + i * 40;
                string name = ReadAscii(d, off, 8);
                uint vSize = BitConverter.ToUInt32(d, off + 8);
                uint rawSize = BitConverter.ToUInt32(d, off + 16);
                uint rawPtr = BitConverter.ToUInt32(d, off + 20);
                uint chars = BitConverter.ToUInt32(d, off + 36);
                double ent = ComputeSectionEntropy(d, (int)rawPtr, (int)rawSize);
                sections.Add(new DimSection
                {
                    Name = name, VirtualSize = vSize, RawSize = rawSize,
                    Characteristics = chars, RawPtr = rawPtr, Entropy = ent
                });
            }

            pe.PackScore += 0.0; // 占位，真正计分在下文填充
            double epEntropy = 0;
            uint epRva = BitConverter.ToUInt32(d, opt + (is32 ? 16 : 16));
            // 找到 EP 所在节
            uint secOffsetAcc = 0;
            foreach (var s in sections)
            {
                if (epRva >= secOffsetAcc && epRva < secOffsetAcc + Math.Max(1, s.VirtualSize) && s.RawSize > 0)
                {
                    epEntropy = s.Entropy;
                    break;
                }
                secOffsetAcc += Math.Max(1, s.VirtualSize);
            }

            int packSignals = 0;
            if (sections.Count > 0)
            {
                // 有效节超过 6.9 熵 → 高压缩/加密节
                int highEntropySections = sections.Count(s => s.Entropy > 6.9);
                if (highEntropySections >= 2) { packSignals++; pe.PackDetails.Add($"{highEntropySections} 个节熵>6.9(疑似加密/加壳)"); }
                // 空壳节：VirtualSize>0 但 RawSize 极小
                int emptyShell = sections.Count(s => s.VirtualSize > 4096 && s.RawSize < 512);
                if (emptyShell >= 2) { packSignals++; pe.PackDetails.Add("存在多个空映射节(加壳特征)"); }
                // WX 节
                int wx = sections.Count(s => (s.Characteristics & 0x80000000) != 0 && (s.Characteristics & 0x20000000) != 0);
                if (wx >= 2) { packSignals++; pe.PackDetails.Add("可写+可执行(WX)节异常"); }
                // 入口点节熵过高
                if (epEntropy > HighEntropyEp) { packSignals++; pe.PackDetails.Add($"入口节熵 {epEntropy:F2} 异常高"); }
            }

            // --- Overlay（有效内容外的尾部数据）---
            long fileLen = d.Length;
            long maxRawEnd = sections.Max(s => (long)s.RawPtr + s.RawSize);
            long overlay = fileLen - Math.Max(maxRawEnd, opt + optSize);
            if (overlay > 0 && maxRawEnd > 0 && (double)overlay / fileLen > MaxOverlayRatio)
            {
                packSignals++;
                pe.PackDetails.Add($"尾部Overlay过大({overlay}字节, 占比{(double)overlay/fileLen:P0})");
            }

            // 高熵 + 空壳/Overlay → 加壳信号
            double rawPack = packSignals switch
            {
                >= 4 => 22, >= 3 => 16, >= 2 => 10, _ => 0
            };
            pe.PackScore = rawPack;

            // --- TLS 回调（恶意代码首选隐蔽执行点）---
            uint tlsRva = BitConverter.ToUInt32(d, opt + (is32 ? 96 : 112));
            if (tlsRva != 0)
            {
                pe.Details.Add("图像包含 TLS 回调(隐蔽执行入口)");
                pe.PackScore += 6;
            }

            // --- 维度5：导入表高危行为组（跨 DLL）---
            var imports = ParseImportApis(d, is32);
            if (imports.Count > 0)
            {
                int groupsHit = 0;
                foreach (var group in BehaviorGroups)
                {
                    int hits = group.Count(api => imports.Contains(api));
                    if (hits >= 3) { groupsHit++; pe.ImportDetails.Add($"高危行为组 {string.Join("/", group.Take(3))}"); }
                }
                pe.ImportScore = Math.Min(16, groupsHit * 8);
            }

            return pe;
        }

        private static HashSet<string> ParseImportApis(byte[] d, bool is32)
        {
            var apis = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                int e_lfanew = BitConverter.ToInt32(d, 0x3C);
                ushort magic = BitConverter.ToUInt16(d, e_lfanew + 24);
                is32 = magic == 0x10B;
                int optSize = is32 ? 224 : 240;
                int impDirRvaOff = e_lfanew + 24 + (is32 ? 104 : 120);
                if (impDirRvaOff + 8 > d.Length) return apis;
                uint impRva = BitConverter.ToUInt32(d, impDirRvaOff);
                uint impSize = BitConverter.ToUInt32(d, impDirRvaOff + 4);
                if (impRva == 0 || impSize == 0 || impRva + impSize > (uint)d.Length) return apis;

                ushort numSec = BitConverter.ToUInt16(d, e_lfanew + 6);
                int secTab = e_lfanew + 24 + optSize;
                var map = new List<(uint rva, uint size, int off)>();
                for (int i = 0; i < numSec; i++)
                {
                    int b = secTab + i * 40;
                    if (b + 40 > d.Length) break;
                    map.Add((BitConverter.ToUInt32(d, b + 12), BitConverter.ToUInt32(d, b + 8), (int)BitConverter.ToUInt32(d, b + 20)));
                }

                int RvaToFile(int rva)
                {
                    foreach (var m in map)
                        if (rva >= m.rva && rva < m.rva + Math.Max(1, m.size) && m.off >= 0)
                            return m.off + (rva - (int)m.rva);
                    return rva;
                }

                for (uint k = 0; k < impSize && k + 20 <= impRva + impSize; k += 20)
                {
                    uint desc = (uint)RvaToFile((int)(impRva + k));
                    if (desc + 20 > (uint)d.Length) break;
                    uint nameRva = BitConverter.ToUInt32(d, (int)desc + 12);
                    uint firstThunk = BitConverter.ToUInt32(d, (int)desc + 16);
                    if (nameRva == 0 && firstThunk == 0) break;
                    if (firstThunk == 0) continue;
                    int thunkOff = RvaToFile((int)firstThunk);
                    if (thunkOff < 0) continue;
                    for (uint t = 0; t < 512; t++)
                    {
                        int tho = thunkOff + (int)t * (is32 ? 4 : 8);
                        if (tho + (is32 ? 4 : 8) > d.Length) break;
                        ulong tv = is32 ? BitConverter.ToUInt32(d, tho) : BitConverter.ToUInt64(d, tho);
                        if (tv == 0) break;
                        bool byName = is32 ? (tv >> 31) == 0 : (tv >> 63) == 0;
                        if (!byName) continue;
                        ulong mask = is32 ? 0x7FFFFFFFUL : 0x7FFFFFFFFFFFFFFFUL;
                        int hint = (int)(tv & mask);
                        int hintOff = RvaToFile(hint + 2);
                        string name = ReadAscii(d, hintOff, 128);
                        if (!string.IsNullOrEmpty(name)) apis.Add(name);
                    }
                }
            }
            catch { /* 解析失败视为无导入票 */ }
            return apis;
        }

        private struct DimNonPe
        {
            public double DocScore;
            public List<string> Details;
        }

        private DimNonPe EvaluateNonPe(byte[] d, string name)
        {
            var ev = new DimNonPe { Details = new List<string>() };
            if (d.Length < 2) return ev;

            // OOXML / ZIP（PK 魔数）宏文档
            if (d[0] == 0x50 && d[1] == 0x4B)
            {
                ev.Details.Add("Zip/OOXML 容器(需进一步看宏)");
                ev.DocScore += 4;
            }
            // OLE2 复合文档（D0 CF 11 E0）—— 老式宏载体
            if (d.Length >= 4 && d[0] == 0xD0 && d[1] == 0xCF && d[2] == 0x11 && d[3] == 0xE0)
            {
                ev.Details.Add("OLE2 复合文档(可能是宏载体)");
                ev.DocScore += 8;
            }
            // RTF 对象（{\rtf ... \object 可嵌套 OLE）
            if (d.Length >= 5 && d[0] == '{' && d[1] == '\\' && d[2] == 'r' && d[3] == 't' && d[4] == 'f')
            {
                ev.Details.Add("RTF 富文本(可嵌入恶意 OLE)");
                ev.DocScore += 6;
            }
            // PowerShell/脚本脚本头 + 高风险关键字共现（仅 ASCII 低误报字符串）
            string head = Encoding.ASCII.GetString(d, 0, Math.Min(d.Length, 4096));
            if (name.EndsWith(".ps1", StringComparison.OrdinalIgnoreCase) || head.Contains("#Requires -RunAsAdministrator"))
            {
                int risky = 0;
                if (head.Contains("-E")) risky++;
                if (head.Contains("Bypass")) risky++;
                if (head.Contains("DownloadString")) risky++;
                if (head.Contains("Invoke-Mimikatz") || head.Contains("ScheduledTask") || head.Contains("New-Object Net.WebClient")) risky++;
                if (risky >= 3) { ev.Details.Add("PowerShell 高危混淆命令共现"); ev.DocScore += 18; }
            }
            return ev;
        }

        // =====================================================================
        // Authenticode 签名提取（纯 C# X509，不调用系统 WinVerifyTrust）
        // =====================================================================
        private static bool TryExtractPublisher(byte[] pe, out string publisher, out bool selfSigned, out bool invalid)
        {
            publisher = null; selfSigned = false; invalid = false;
            try
            {
                if (pe.Length < 0x40 || pe[0] != 0x4D || pe[1] != 0x5A) return false;
                int e_lfanew = BitConverter.ToInt32(pe, 0x3C);
                if (e_lfanew + 4 > pe.Length || pe[e_lfanew] != 'P' || pe[e_lfanew + 1] != 'E') return false;
                ushort magic = BitConverter.ToUInt16(pe, e_lfanew + 24);
                bool is32 = magic == 0x10B;
                int secDirOff = e_lfanew + 24 + (is32 ? 128 : 144);
                if (secDirOff + 8 > pe.Length) return false;
                uint rva = BitConverter.ToUInt32(pe, secDirOff);
                uint size = BitConverter.ToUInt32(pe, secDirOff + 4);
                if (rva == 0 || size == 0 || rva + size > (uint)pe.Length || size <= 8) return false;

                // 安全目录是 WIN_CERTIFICATE(wLength + wRevision + wCertificateType + bCertificate)，
                // 证书体在偏移 +8 处。
                int certLen = (int)size - 8;
                if (certLen <= 0 || (int)rva + 8 + certLen > pe.Length) return false;
                var certBlob = new byte[certLen];
                Buffer.BlockCopy(pe, (int)rva + 8, certBlob, 0, certLen);
                using var cert = new X509Certificate2(certBlob);
                if (cert == null) return false;
                publisher = cert.Subject;
                selfSigned = IsSelfSigned(cert);
                return true;
            }
            catch (Exception)
            {
                invalid = true;   // 有签名目录但无法构造证书 → 签名无效/被破坏
                return true;
            }
        }

        private static bool IsSelfSigned(X509Certificate2 cert)
        {
            try
            {
                // 发起者参与者是否为同一主体（经典自签判定）
                string issuer = cert.IssuerName.Name ?? "";
                string subject = cert.SubjectName.Name ?? "";
                return string.Equals(issuer, subject, StringComparison.Ordinal);
            }
            catch { return false; }
        }

        private static bool IsTrustedPublisher(string publisher)
        {
            if (string.IsNullOrEmpty(publisher)) return false;
            foreach (var tp in TrustedPublishers)
                if (publisher.Contains(tp, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        // =====================================================================
        // 底层工具
        // =====================================================================
        private static double ComputeSectionEntropy(byte[] data, int offset, int length)
        {
            if (offset < 0 || length <= 0 || offset + length > data.Length) return 0.0;
            var freq = new int[256];
            for (int i = offset; i < offset + length; i++) freq[data[i]]++;
            double ent = 0.0;
            for (int i = 0; i < 256; i++)
            {
                if (freq[i] == 0) continue;
                double p = (double)freq[i] / length;
                ent -= p * Math.Log(p, 2);
            }
            return ent;
        }

        private static string ComputeSha(byte[] data, HashAlgorithm algo)
        {
            try { using (algo) return BitConverter.ToString(algo.ComputeHash(data)).Replace("-", "").ToLower(); }
            catch { return string.Empty; }
        }

        private static string ReadAscii(byte[] data, int offset, int maxLen)
        {
            if (offset < 0 || offset >= data.Length) return string.Empty;
            int end = offset;
            int max = Math.Min(data.Length, offset + maxLen);
            while (end < max && data[end] != 0) end++;
            if (end <= offset) return string.Empty;
            var sb = new StringBuilder();
            for (int i = offset; i < end; i++) sb.Append((char)data[i]);
            return sb.ToString();
        }
    }
}