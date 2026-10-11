using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using FireAntivirus.Common;
using FireAntivirus.Data;

namespace FireAntivirus.Engine.Analyzers
{
    public class StaticAnalyzer
    {
        private DataManager dataManager;
        private Dictionary<string, string> fileHashCache;

        // 专业检测阈值 - 减少误报
        // 提升阈值并采用强信号制，杜绝"普通程序因通用字符串被误报"
        private const double HIGH_RISK_THRESHOLD = 0.9;
        private const double SUSPICIOUS_THRESHOLD = 0.82;

        // 可信发布者白名单（有真实签名且命中白名单的强排除信号）
        private static readonly HashSet<string> TrustedPublishers = new(StringComparer.OrdinalIgnoreCase)
        {
            "Microsoft Corporation", "Microsoft Windows", "Microsoft",
            "Google LLC", "Google Inc", "Apple Inc.", "Apple Computer, Inc.",
            "Mozilla Corporation",
            "Adobe Inc.", "Adobe Systems Incorporated",
            "Intel Corporation", "NVIDIA Corporation", "AMD", "Advanced Micro Devices",
            "Oracle Corporation", "VMware, Inc.",
            "Cisco Systems, Inc.", "Dell Inc.", "HP Inc.", "Hewlett-Packard", "Lenovo",
            "ASUSTeK Computer Inc.",
            "AVG Technologies", "Avast Software", "Kaspersky Lab",
            "Symantec Corporation", "McAfee, Inc.", "Trend Micro, Inc.",
            "Bitdefender", "ESET, spol. s r.o.",
            "360 Security Technology Inc.", "Tencent", "Huawei", "Baidu, Inc.",
            "The Qt Company Ltd.", "GitHub, Inc.", "Git Inc.", "Dropbox, Inc.",
            "Zoom Video Communications, Inc.", "Amazon.com Services LLC", "Amazon Web Services, Inc.",
            "Slack Technologies, Inc.", "Discord Inc.", "Spotify AB", "Valve Corporation",
            "Epic Games, Inc.", "Unity Technologies SF", "Autodesk, Inc.", "Canon Inc.",
            "Citrix Systems, Inc.", "F5 Networks, Inc.", "Fortinet, Inc.", "Palo Alto Networks, Inc.",
            "CrowdStrike, Inc.", "SentinelOne, Inc.", "Avast", "NortonLifeLock Inc.",
            "耄耋软件工作室", "FireAntivirus"
        };

        // 仅在"真实 PE 导入表"层面才认可的高危 API 组合（防止读取/写入文件即被误判）
        private static readonly Dictionary<string, string[]> HighRiskApiPairs = new(StringComparer.OrdinalIgnoreCase)
        {
            // 进程注入：远程线程 + 内存操作 + 开放进程 同时出现才计分
            ["ProcessInjection"] = new[] { "CreateRemoteThread", "OpenProcess", "VirtualAllocEx" },
            ["ProcessHollowing"] = new[] { "CreateProcess", "NtUnmapViewOfSection", "WriteProcessMemory" },
            ["DllInjection"] = new[] { "CreateRemoteThread", "WriteProcessMemory", "LoadLibrary" },
            ["Keylogger"] = new[] { "SetWindowsHookEx", "GetAsyncKeyState", "CallNextHookEx" },
            ["ScreenCapture"] = new[] { "BitBlt", "GetDesktopWindow", "PrintWindow" },
            // 勒索：批量遍历 + 加密 + 删除
            ["RansomCrypto"] = new[] { "CryptEncrypt", "CryptDecrypt", "FindFirstFile" },
            ["ShadowCopyDelete"] = new[] { "vssadmin", "delete", "shadows" },
            // 反调试
            ["AntiDebug"] = new[] { "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess" },
            // 权限持久化
            ["Persistence"] = new[] { "CreateService", "OpenSCManager", "RegSetValueEx" }
        };

        // 恶意进程名/文件名等特征全部外置到 embedded_threats.json，经 EmbeddedThreatDatabase 运行时加载，
        // 不把恶意字符串硬编码进 DLL，避免被病毒引擎误判。

        public StaticAnalyzer()
        {
            dataManager = new DataManager();
            fileHashCache = new Dictionary<string, string>();
        }

        /// <summary>
        /// 核心：仅在真实 PE 结构（导入表）层面解析出 API，再按"高危组合"判断。
        /// 不再对整个文件做 UTF-8 文本子串匹配，从根上消除普通程序因常见字符串被误报的问题。
        /// </summary>
        private (string dll, HashSet<string> apis)[] ParseImportTable(byte[] peData)
        {
            var imports = new List<(string, HashSet<string>)>();
            try
            {
                if (peData == null || peData.Length < 0x40) return imports.ToArray();
                if (peData[0] != 0x4D || peData[1] != 0x5A) return imports.ToArray(); // 非 MZ

                int peOffset = BitConverter.ToInt32(peData, 0x3C);
                if (peOffset + 4 > peData.Length) return imports.ToArray();
                if (peData[peOffset] != 0x50 || peData[peOffset + 1] != 0x45) return imports.ToArray(); // 非 PE

                var peMagic = BitConverter.ToUInt16(peData, peOffset + 24);
                bool is32 = peMagic == 0x010B;
                int optHeaderSize = is32 ? 224 : 240;
                int importDirRvaOffset = peOffset + 24 + (is32 ? 104 : 120);
                if (importDirRvaOffset + 8 > peData.Length) return imports.ToArray();

                uint importRva = BitConverter.ToUInt32(peData, importDirRvaOffset);
                uint importSize = BitConverter.ToUInt32(peData, importDirRvaOffset + 4);
                if (importRva == 0 || importSize == 0 || importRva + importSize > (uint)peData.Length)
                    return imports.ToArray();

                // 节区映射：RVA -> 文件偏移
                ushort sectionCount = BitConverter.ToUInt16(peData, peOffset + 6);
                int sectionTable = peOffset + 24 + optHeaderSize;
                var rvaToOffset = new List<(uint rva, uint size, int offset)>();
                for (int i = 0; i < sectionCount; i++)
                {
                    int baseIdx = sectionTable + i * 40;
                    if (baseIdx + 40 > peData.Length) break;
                    uint virtualAddr = BitConverter.ToUInt32(peData, baseIdx + 12);
                    uint virtualSize = BitConverter.ToUInt32(peData, baseIdx + 8);
                    uint rawPtr = BitConverter.ToUInt32(peData, baseIdx + 20);
                    uint rawSize = BitConverter.ToUInt32(peData, baseIdx + 16);
                    rvaToOffset.Add((virtualAddr, virtualSize, (int)rawPtr));
                }

                int RvaToFile(int rva)
                {
                    foreach (var sec in rvaToOffset)
                    {
                        if (rva >= sec.rva && rva < sec.rva + sec.size && sec.offset >= 0)
                            return sec.offset + (rva - (int)sec.rva);
                    }
                    return rva;
                }

                for (uint d = 0; d < importSize && d + 20 <= importRva + importSize; d += 20)
                {
                    uint descOff = (uint)RvaToFile((int)importRva + (int)d);
                    if (descOff + 20 > (uint)peData.Length) break;
                    uint nameRva = BitConverter.ToUInt32(peData, (int)descOff + 12);
                    uint firstThunkRva = BitConverter.ToUInt32(peData, (int)descOff + 16);
                    if (nameRva == 0 && firstThunkRva == 0) break; // 结束标志

                    if (nameRva == 0) continue;
                    int nameOff = RvaToFile((int)nameRva);
                    int thunkOff = RvaToFile((int)firstThunkRva);
                    if (nameOff <= 0 || thunkOff < 0) continue;

                    // DLL 名
                    string dllName = ReadAscii(peData, nameOff, 256);
                    if (string.IsNullOrEmpty(dllName)) continue;

                    var apis = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    for (uint t = 0; t < 512; t++)
                    {
                        int throne = thunkOff + (int)t * (is32 ? 4 : 8);
                        if (throne + (is32 ? 4 : 8) > peData.Length) break;
                        ulong thunkValue = is32
                            ? BitConverter.ToUInt32(peData, throne)
                            : BitConverter.ToUInt64(peData, throne);
                        if (thunkValue == 0) break;
                        // 通过 IMAGE_THUNK_DATA 最高位判断是否按名称导入
                        bool byName = is32 ? (thunkValue >> 31) == 0 : (thunkValue >> 63) == 0;
                        if (!byName) continue;
                        ulong mask = is32 ? 0x7FFFFFFFUL : 0x7FFFFFFFFFFFFFFFUL;
                        int hint = (int)(thunkValue & mask);
                        int hintOff = RvaToFile(hint + 2); // 跳过 WORD Hint
                        string apiName = ReadAscii(peData, hintOff, 128);
                        if (!string.IsNullOrEmpty(apiName)) apis.Add(apiName);
                    }

                    if (apis.Count > 0) imports.Add((dllName, apis));
                }
                return imports.ToArray();
            }
            catch (Exception ex)
            {
                dataManager.LogError("PE导入表解析失败", ex.Message, "StaticAnalyzer");
                return imports.ToArray();
            }
        }

        /// <summary>收集 PE 各节区名（用于加壳/外包特征判定）。</summary>
        private List<string> CollectSectionNames(byte[] peData)
        {
            var sections = new List<string>();
            try
            {
                if (peData == null || peData.Length < 0x40) return sections;
                if (peData[0] != 0x4D || peData[1] != 0x5A) return sections;
                int peOffset = BitConverter.ToInt32(peData, 0x3C);
                if (peOffset + 4 > peData.Length) return sections;
                if (peData[peOffset] != 0x50 || peData[peOffset + 1] != 0x45) return sections;

                var magic = BitConverter.ToUInt16(peData, peOffset + 24);
                bool is32 = magic == 0x010B;
                int optHeaderSize = is32 ? 224 : 240;
                int sectionTable = peOffset + 24 + optHeaderSize;
                ushort sectionCount = BitConverter.ToUInt16(peData, peOffset + 6);
                for (int i = 0; i < sectionCount; i++)
                {
                    int baseIdx = sectionTable + i * 40;
                    if (baseIdx + 8 > peData.Length) break;
                    string name = ReadAscii(peData, baseIdx, 40).TrimEnd('\0').Trim();
                    if (!string.IsNullOrEmpty(name)) sections.Add(name);
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError("PE节区解析失败", ex.Message, "StaticAnalyzer");
            }
            return sections;
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

        /// <summary>敏感导入集：判定文件是否为可执行 PE 后收集全部导入名。</summary>
        private HashSet<string> CollectImports(string filePath, byte[] fileContent)
        {
            var apis = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var imports = ParseImportTable(fileContent);
            foreach (var (_, set) in imports)
                foreach (var a in set) apis.Add(a);
            return apis;
        }

        public List<ScanResult> AnalyzeFile(string filePath)
        {
            var results = new List<ScanResult>();
            
            if (!File.Exists(filePath))
            {
                return results;
            }

            try
            {
                var fileContent = File.ReadAllBytes(filePath);
                var result = AnalyzeFileCore(filePath, fileContent);
                results.Add(result);

                if (result.IsInfected)
                {
                    dataManager.LogThreat($"静态分析检测到恶意文件: {filePath}", $"评分: {result.Confidence:P}", "StaticAnalyzer");
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"静态分析失败: {filePath}", ex.Message, "StaticAnalyzer");
            }

            return results;
        }

        /// <summary>
        /// 强信号静态判定（零文本子串匹配）：
        ///  1) 已知恶意哈希（特征库/云） -> 直接高危
        ///  2) 可信签名（白名单发布者） -> 直接放行
        ///  3) PE 导入表中出现真实高危 API 组合 -> 加可信的强信号
        ///  4) 已知恶意文件名精确命中 -> 加分
        ///  5) 极高熵 + 无签名（疑似加壳/变形）为弱辅助信号
        ///  阈值设计为"必须多个独立强信号同时成立"才报警，普通程序永不触发。
        /// </summary>
        private ScanResult AnalyzeFileCore(string filePath, byte[] fileContent)
        {
            var result = new ScanResult
            {
                FilePath = filePath,
                IsInfected = false,
                Confidence = 0.0,
                DetectionTime = DateTime.Now,
                DetectionMethod = "Static"
            };

            if (fileContent == null || fileContent.Length == 0) return result;

            try
            {
                // ---- 1) 已知恶意哈希：最权威信号，永远优先于一切"可信"降权，直接认定 ----
                string sha256 = ComputeSha256(fileContent);
                var sigThreat = FireAntivirus.Engine.SignatureDatabaseUpdater.TryGetHashThreat(sha256, out var t) ? t : null;
                if (string.IsNullOrEmpty(sigThreat))
                {
                    var localSig = dataManager.GetSignatureByHash(sha256);
                    if (localSig != null && !string.IsNullOrEmpty(localSig.Name))
                    {
                        sigThreat = localSig.Name;
                    }
                }
                if (!string.IsNullOrEmpty(sigThreat))
                {
                    return MakeHit(filePath, $"已知恶意文件 ({sigThreat})", "Malware", "High", 0.99, "命中已知恶意哈希特征库", sha256);
                }

                // ---- 是否为 PE 可执行文件 ----
                bool isPE = fileContent.Length >= 0x40 && fileContent[0] == 0x4D && fileContent[1] == 0x5A;
                string fileName = Path.GetFileName(filePath);

                // ---- 1.5) 内嵌YARA式规则匹配（多字符串共现，规则要求MinMatches命中才计分） ----
                var (yaraRule, yaraHits) = FireAntivirus.Engine.Data.EmbeddedThreatDatabase.MatchYaraRules(fileContent);
                if (yaraRule != null && yaraRule.Confidence >= 0.9 && yaraHits >= 2)
                {
                    // 家族级强命中：两个及以上独立家族字符串同时出现，直接判定
                    return MakeHit(filePath, $"{yaraRule.Family} 家族样本 ({yaraRule.RuleName})",
                        "Malware", yaraRule.Severity, yaraRule.Confidence,
                        $"内嵌YARA规则命中 {yaraHits}/{yaraRule.Strings.Length}: {yaraRule.Description}", sha256);
                }

                // ---- 1.6) 内嵌已知恶意文件名精确匹配 ----
                var knownFile = FireAntivirus.Engine.Data.EmbeddedThreatDatabase.LookupKnownFile(fileName);
                double embeddedNameScore = knownFile != null ? 0.55 : 0.0;

                // ---- 1.7) 内嵌PE节区特征（加壳/恶意壳） ----
                double sectionScore = 0.0;
                string sectionMatch = null;
                if (isPE)
                {
                    var sectionNames = CollectSectionNames(fileContent);
                    foreach (var sec in sectionNames)
                    {
                        var feats = FireAntivirus.Engine.Data.EmbeddedThreatDatabase.LookupSection(sec);
                        foreach (var feat in feats)
                        {
                            // 恶意/强壳节区 + 未签名 才显著加分；避免合法UPX软告警
                            if (feat.Confidence >= 0.78)
                            {
                                sectionScore = Math.Max(sectionScore, feat.Confidence * 0.72);
                                sectionMatch = $"{feat.Family}({feat.SectionName})";
                            }
                            else
                            {
                                sectionScore = Math.Max(sectionScore, feat.Confidence * 0.4);
                            }
                        }
                    }
                }

                // ---- 2) 可信签名：仅作为"负向降权因子"，绝不构成硬放行 ----
                //     关键：即使文件来自系统目录/有可信签名，若存在强恶意行为信号仍会被判定为威胁，防止系统目录被感染的漏报。
                var peAnalyzer = new FireAntivirus.Engine.PEAnalyzer();
                var peSig = peAnalyzer.Analyze(filePath);
                bool hasTrustedSig = peSig != null && peSig.IsSigned && peSig.IsValidSignature && IsTrustedPublisher(peSig.Publisher);
                double trustDiscount = hasTrustedSig ? 0.55 : 0.0; // 最高可压低约一半风险分，但不归零

                // ---- 真实加壳/熵证据（逐节熵、EP所在节、TLS回调、压缩比）----
                var packEv = isPE ? new PackingAnalyzer().Analyze(fileContent) : new PackingAnalyzer.PackingEvidence { IsPacked = false };

                // ---- 3) 已知恶意文件名精确命中（特征外置） ----
                bool nameHit = FireAntivirus.Engine.Data.EmbeddedThreatDatabase.IsKnownMaliciousName(fileName);
                double nameScore = nameHit ? 0.5 : 0.0;

                // ---- 4) 真实 PE 导入表高危 API 组合（跨 DLL 静态证据） ----
                double apiScore = 0.0;
                int strongApiGroupCount = 0;
                var matchedApis = new List<string>();
                if (isPE)
                {
                    var imports = ParseImportTable(fileContent);
                    var allApis = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    foreach (var (_, set) in imports)
                        foreach (var a in set) allApis.Add(a);

                    foreach (var kv in HighRiskApiPairs)
                    {
                        int count = kv.Value.Count(api => allApis.Contains(api));
                        // 组合内须满足 ≥2 个真实导入，才认为构成了可疑行为
                        if (count >= 2)
                        {
                            matchedApis.Add(kv.Key);
                            strongApiGroupCount++;
                            apiScore += count >= 3 ? 0.34 : 0.2;
                        }
                    }

                    // 叠加内嵌库的 PE 特征 API 组合（更丰富，覆盖注入/键盘记录/凭据转储/提权等）
                    foreach (var feat in FireAntivirus.Engine.Data.EmbeddedThreatDatabase.PeFeatures)
                    {
                        if (feat.ImportApis == null || feat.ImportApis.Length == 0) continue;
                        bool dllOk = string.IsNullOrEmpty(feat.ImportDll);
                        if (!dllOk)
                        {
                            foreach (var (dll, _) in imports)
                            {
                                if (dll.Contains(feat.ImportDll.Replace(".dll", ""), StringComparison.OrdinalIgnoreCase))
                                { dllOk = true; break; }
                            }
                        }
                        if (!dllOk) continue;
                        int hit = feat.ImportApis.Count(api => allApis.Contains(api));
                        if (hit >= feat.MinApiMatches)
                        {
                            if (!matchedApis.Contains(feat.Family))
                            {
                                matchedApis.Add(feat.Family);
                                strongApiGroupCount++;
                            }
                            apiScore += Math.Min(0.4, feat.Confidence * hit / Math.Max(1, feat.ImportApis.Length));
                        }
                    }
                }

                // ---- 5) 极高熵 + 未签名：弱辅助，使用逐节入口熵，仅当与其他强信号叠加才有效 ----
                double entropyScore = (isPE && !hasTrustedSig)
                    ? (packEv.EpEntropy > 7.6 ? 0.1 : packEv.EpEntropy > 7.1 ? 0.05 : 0.0)
                    : 0.0;

                // 打包 + 多个强高危导入族同时成立：仅对"已构成明显风险的打包样本"额外加分，良性加壳软件被可信签名豁免
                double packBonus = (isPE && !hasTrustedSig && packEv.IsPacked && strongApiGroupCount >= 2) ? 0.12 : 0.0;

                double total = Math.Max(nameScore, embeddedNameScore) + Math.Min(apiScore + packBonus, 0.6) + entropyScore + sectionScore;

                // 应用可信签名降权（只减分，不归零，保证恶意强信号仍能覆盖"可信"标签）
                if (hasTrustedSig && total > 0)
                {
                    total = Math.Max(total - trustDiscount, total * 0.45);
                    // 恶意强信号组合≥3组时，即使有可信签名也不允许被完全豁免
                    if (strongApiGroupCount >= 3) total = Math.Max(total, 0.85);
                }

                if (total >= HIGH_RISK_THRESHOLD)
                {
                    string type = matchedApis.FirstOrDefault() ?? (nameHit ? "Trojan" : "Suspicious");
                    string threatName = nameHit ? $"疑似恶意程序 ({fileName})"
                        : matchedApis.Count > 0 ? $"疑似恶意代码 ({string.Join("+", matchedApis)})"
                        : "疑似恶意程序";
                    return MakeHit(filePath, threatName, type, "Medium", Math.Min(0.999, total), $"强信号累积: {string.Join(",", matchedApis)}, 可信签名: {hasTrustedSig}, 文件名命中: {nameHit}", sha256);
                }

                if (total >= SUSPICIOUS_THRESHOLD)
                {
                    result.Confidence = total;
                    result.ThreatName = "静态分析发现可疑程序";
                    result.ThreatType = "Risk";
                    result.Severity = "Low";
                    result.AdditionalInfo = $"可疑信号累积: {total:P}";
                    result.FileHash = HexToBytes(sha256);
                    return result;
                }

                // ---- 干净 ----
                result.Confidence = total;
                result.DetectionMethod = "Clean";
                return result;
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
                result.DetectionMethod = "Error";
                return result;
            }
        }

        private ScanResult MakeHit(string filePath, string name, string type, string severity, double conf, string info, string sha256)
        {
            return new ScanResult
            {
                FilePath = filePath,
                IsInfected = true,
                ThreatName = name,
                ThreatType = type,
                Severity = severity,
                Confidence = conf,
                DetectionTime = DateTime.Now,
                DetectionMethod = "Static",
                AdditionalInfo = info,
                FileHash = HexToBytes(sha256),
                MatchedSignatures = new List<string> { name }
            };
        }

        private string ComputeSha256(byte[] data)
        {
            try { using var sha = System.Security.Cryptography.SHA256.Create(); return BitConverter.ToString(sha.ComputeHash(data)).Replace("-", "").ToLower(); }
            catch { return string.Empty; }
        }

        private byte[] HexToBytes(string hex)
        {
            if (string.IsNullOrEmpty(hex) || hex.Length % 2 != 0) return null;
            var b = new byte[hex.Length / 2];
            for (int i = 0; i < b.Length; i++)
                b[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return b;
        }

        private bool IsTrustedPublisher(string publisher)
        {
            if (string.IsNullOrEmpty(publisher)) return false;
            // 优先查询内嵌可信发布者库（精确+包含匹配，取可信度≥0.6）
            var embedded = FireAntivirus.Engine.Data.EmbeddedThreatDatabase.LookupPublisher(publisher);
            if (embedded != null) return embedded.TrustScore >= 0.6;
            foreach (var tp in TrustedPublishers)
                if (publisher.Contains(tp, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        public List<ScanResult> AnalyzeDirectory(string directoryPath)
        {
            var results = new List<ScanResult>();
            
            if (!Directory.Exists(directoryPath))
            {
                return results;
            }

            try
            {
                var files = Directory.GetFiles(directoryPath, "*.*", SearchOption.AllDirectories);
                foreach (var file in files)
                {
                    try
                    {
                        var fileResults = AnalyzeFile(file);
                        results.AddRange(fileResults);
                    }
                    catch
                    {
                        continue;
                    }
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"目录静态分析失败: {directoryPath}", ex.Message, "StaticAnalyzer");
            }

            return results;
        }

        private string GetFileHash(string filePath)
        {
            if (fileHashCache.TryGetValue(filePath, out string cachedHash))
            {
                return cachedHash;
            }

            string hash = string.Empty;

            try
            {
                using (var md5 = MD5.Create())
                {
                    using (var stream = File.OpenRead(filePath))
                    {
                        byte[] hashBytes = md5.ComputeHash(stream);
                        hash = BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
                    }
                }

                fileHashCache[filePath] = hash;
            }
            catch
            {
                hash = string.Empty;
            }

            return hash;
        }

        private double CalculateEntropy(byte[] data)
        {
            try
            {
                var frequency = new Dictionary<byte, int>();
                foreach (byte b in data)
                {
                    if (frequency.ContainsKey(b))
                    {
                        frequency[b]++;
                    }
                    else
                    {
                        frequency[b] = 1;
                    }
                }

                double entropy = 0.0;
                double totalBytes = data.Length;

                foreach (var pair in frequency)
                {
                    double probability = pair.Value / totalBytes;
                    entropy -= probability * Math.Log(probability, 2);
                }

                return entropy;
            }
            catch
            {
                return 0.0;
            }
        }

        public void ClearCache()
        {
            fileHashCache.Clear();
        }

        public int GetCacheSize()
        {
            return fileHashCache.Count;
        }
    }
}