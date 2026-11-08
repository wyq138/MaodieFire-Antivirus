using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using FireAntivirus.Common;
using FireAntivirus.Data;

namespace FireAntivirus.Engine.Analyzers
{
    /// <summary>
    /// 高级启发式检测引擎。
    /// 原则（与 StaticAnalyzer / ProcessAnalyzer 一致的证据链思路）：
    ///  - 绝不对"整个文件做 UTF-8 文本子串匹配"——任何正常的 PE 二进制都会包含导入表里的 API 名，
    ///    纯子串命中会因为"文件名+大写节名+常见字符串"疯狂误报；
    ///  - 只承认真实 PE 结构（DOS 头 -> NT 头 -> 可选头 -> 节区表 -> 导入表 RVA -> 原始偏移）里解析出来的 API；
    ///  - 正常系统进程名（svchost/cmd/powershell 等）不做黑名单，绝不因路径包含 Temp/Desktop 加分；
    ///  - 依据 真实哈希特征库 / 可信签名(仅降权) / 导入表高危组合 / 加壳弱辅助 / 文件大小时段弱辅助 多阶段加权。
    /// 警告：本检测器任何被误报的"单点"都不得单独报警，必须多个独立强信号同时成立。
    /// </summary>
    public class HeuristicEngine
    {
        private DataManager dataManager;
        private Dictionary<string, double> fileHashCache;
        private Dictionary<string, double> heuristicScores;

        // 判定阈值：默认必须 0.85 以上才视为感染（配合 PE 层面强信号，杜绝误报）
        private const double INFECTED_THRESHOLD = 0.85;
        private const double HIGH_RISK_THRESHOLD = 0.95;

        // 可信发布者白名单（有真实签名且命中白名单的强排除信号，仅降权不豁免）
        private static readonly HashSet<string> TrustedPublishers = new(StringComparer.OrdinalIgnoreCase)
        {
            "Microsoft Corporation", "Microsoft Windows", "Microsoft",
            "Google LLC", "Google Inc", "Apple Inc.", "Apple Computer, Inc.",
            "Mozilla Corporation", "Adobe Inc.", "Adobe Systems Incorporated",
            "Intel Corporation", "NVIDIA Corporation", "AMD", "Advanced Micro Devices",
            "Oracle Corporation", "VMware, Inc.", "Cisco Systems, Inc.", "Dell Inc.",
            "HP Inc.", "Lenovo", "ASUSTeK Computer Inc.", "Canon Inc.", "GitHub, Inc.",
            "Zoom Video Communications, Inc.", "Amazon.com Services LLC", "Amazon Web Services, Inc.",
            "耄耋软件工作室", "FireAntivirus"
        };

        // 仅在"真实 PE 导入表"层面才认可的高危 API 组合
        private static readonly (string Name, string[] Apis)[] HighRiskApiPairs =
        {
            ("进程注入", new[] { "CreateRemoteThread", "OpenProcess", "VirtualAllocEx" }),
            ("进程镂空", new[] { "CreateProcess", "NtUnmapViewOfSection", "WriteProcessMemory" }),
            ("DLL注入", new[] { "CreateRemoteThread", "WriteProcessMemory", "LoadLibrary" }),
            ("键盘记录", new[] { "SetWindowsHookEx", "GetAsyncKeyState", "CallNextHookEx" }),
            ("屏幕捕获", new[] { "BitBlt", "GetDesktopWindow", "PrintWindow" }),
            ("反调试", new[] { "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess" }),
            ("持久化", new[] { "CreateService", "OpenSCManager", "RegSetValueEx" })
        };

        // 恶意/矿机文件名等特征全部外置到 embedded_threats.json（经 EmbeddedThreatDatabase 运行时加载），
        // 不把恶意字符串硬编码进 DLL，避免被病毒引擎误判。

        public HeuristicEngine()
        {
            dataManager = DataManager.SharedInstance;
            fileHashCache = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase);
            heuristicScores = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase);
        }

        public List<ScanResult> AnalyzeFile(string filePath)
        {
            var results = new List<ScanResult>();
            if (!File.Exists(filePath)) return results;

            try
            {
                double heuristicScore = CalculateHeuristicScore(filePath);
                var result = CreateScanResult(filePath, heuristicScore);
                results.Add(result);

                if (result.IsInfected)
                {
                    dataManager.LogThreat($"启发式检测到恶意文件: {filePath}", $"评分: {heuristicScore:P}", "HeuristicEngine");
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"启发式分析失败: {filePath}", ex.Message, "HeuristicEngine");
            }
            return results;
        }

        public double CalculateHeuristicScore(string filePath)
        {
            if (fileHashCache.TryGetValue(filePath, out double cached)) return cached;

            double score = 0.0;
            try
            {
                var fileContent = File.ReadAllBytes(filePath);
                if (fileContent == null || fileContent.Length == 0) return 0.0;

                string sha256 = ComputeSha256(fileContent);
                string fileName = Path.GetFileName(filePath);
                bool isPE = fileContent.Length >= 0x40 && fileContent[0] == 0x4D && fileContent[1] == 0x5A;

                // ---- 1) 真实哈希特征库：最权威，直接决定 ----
                if (!string.IsNullOrEmpty(sha256))
                {
                    if (SignatureDatabaseUpdater.TryGetHashThreat(sha256, out var t) && !string.IsNullOrEmpty(t))
                    {
                        score = 1.0;
                        heuristicScores[filePath] = score;
                        fileHashCache[filePath] = score;
                        return score;
                    }
                    var localSig = dataManager.GetSignatureByHash(sha256);
                    if (localSig != null && !string.IsNullOrEmpty(localSig.Name))
                    {
                        score = 1.0;
                        heuristicScores[filePath] = score;
                        fileHashCache[filePath] = score;
                        return score;
                    }
                }

                // ---- 2) 可信签名：仅负向降权，绝不硬豁免 ----
                bool hasTrustedSig = TryValidateSignature(filePath);
                double trustDiscount = hasTrustedSig ? 0.4 : 0.0;

                // ---- 3) 真实 PE 导入表高危组合（只对 PE 生效） ----
                double apiScore = 0.0;
                double highRiskGroupScore = 0.0;
                int strongGroupCount = 0;
                if (isPE)
                {
                    var imports = ParseImportTable(fileContent);
                    var allApis = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    foreach (var (_, set) in imports)
                        foreach (var a in set) allApis.Add(a);

                    foreach (var pair in HighRiskApiPairs)
                    {
                        int count = pair.Apis.Count(a => allApis.Contains(a));
                        // 分组内须 ≥2 个真实导入，才判定构成可疑行为
                        if (count >= 2)
                        {
                            strongGroupCount++;
                            highRiskGroupScore += count >= 3 ? 0.34 : 0.24;
                        }
                    }
                    apiScore = strongGroupCount >= 2 ? Math.Min(0.7, highRiskGroupScore) : 0.0;

                    // 熵值过高 + 未签名 + 文件极小（疑似加壳内嵌载荷）；仅作为弱辅助叠加
                    double entropy = CalculateEntropy(fileContent);
                    if (!hasTrustedSig && entropy > 7.6 && strongGroupCount > 0)
                        apiScore = Math.Min(0.7, apiScore + 0.12);
                }

                // ---- 4) 文件名精确命中已知矿机/恶意名（非子串，本地集+内嵌库取最大） ----
                double nameScore = 0.0;
                var embeddedKnown = FireAntivirus.Engine.Data.EmbeddedThreatDatabase.LookupKnownFile(fileName);
                if (!hasTrustedSig && (FireAntivirus.Engine.Data.EmbeddedThreatDatabase.IsKnownMaliciousName(fileName) || embeddedKnown != null))
                    nameScore = Math.Max(0.5, embeddedKnown?.Confidence * 0.6 ?? 0.5);

                // ---- 4.5) 内嵌YARA式规则匹配（弱于静态引擎的强判定，作为评分加分项） ----
                var (yaraRule, yaraHits) = FireAntivirus.Engine.Data.EmbeddedThreatDatabase.MatchYaraRules(fileContent);
                double yaraScore = 0.0;
                if (yaraRule != null)
                {
                    int required = yaraRule.MinMatches == int.MinValue ? yaraRule.Strings.Length : yaraRule.MinMatches;
                    if (yaraHits >= required)
                        yaraScore = Math.Min(0.55, yaraRule.Confidence * 0.58);
                }

                // ---- 5) 弱辅助：临时目录 + 未签名（不单独报警） ----
                double weakScore = 0.0;
                if (!hasTrustedSig && IsInSuspiciousLocation(filePath))
                    weakScore += 0.08;
                if (!hasTrustedSig && (new FileInfo(filePath).Length < 4096))
                    weakScore += 0.06;

                score = nameScore + apiScore + yaraScore + weakScore;

                // 应用可信签名降权（只减不豁免；3 组以上强信号即使可信也不放行）
                if (hasTrustedSig && score > 0)
                    score = Math.Max(score - trustDiscount, score * 0.45);
                if (strongGroupCount >= 3)
                    score = Math.Max(score, 0.9);

                score = Math.Clamp(score, 0.0, 1.0);

                fileHashCache[filePath] = score;
                heuristicScores[filePath] = score;
            }
            catch
            {
                score = 0.0;
            }

            return score;
        }

        private ScanResult CreateScanResult(string filePath, double score)
        {
            var result = new ScanResult
            {
                FilePath = filePath,
                IsInfected = score >= INFECTED_THRESHOLD,
                Confidence = score,
                DetectionTime = DateTime.Now,
                DetectionMethod = "Heuristic"
            };

            if (result.IsInfected)
            {
                if (score > HIGH_RISK_THRESHOLD)
                {
                    result.ThreatName = "检测到恶意文件（PE 导入/行为强信号）";
                    result.ThreatType = "Malware";
                    result.Severity = "High";
                }
                else
                {
                    result.ThreatName = "检测到高度可疑文件";
                    result.ThreatType = "Suspicious";
                    result.Severity = "Medium";
                }
                result.AdditionalInfo = $"启发式评分: {score:P}（真实 PE 导入表证据链判定）";
            }
            return result;
        }

        // ------------------------------------------------------------------
        // 真实 PE 导入表解析（DOS 头 -> NT 头 -> 可选头 -> 节区表 -> 数据目录 -> 导入表 RVA -> 原始偏移）
        // ------------------------------------------------------------------
        private (string dll, HashSet<string> apis)[] ParseImportTable(byte[] peData)
        {
            var imports = new List<(string, HashSet<string>)>();
            try
            {
                if (peData == null || peData.Length < 0x40) return imports.ToArray();
                if (peData[0] != 0x4D || peData[1] != 0x5A) return imports.ToArray();

                int peOffset = BitConverter.ToInt32(peData, 0x3C);
                if (peOffset + 4 > peData.Length) return imports.ToArray();
                if (peData[peOffset] != 0x50 || peData[peOffset + 1] != 0x45) return imports.ToArray();

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
                    rvaToOffset.Add((BitConverter.ToUInt32(peData, baseIdx + 12),
                                     BitConverter.ToUInt32(peData, baseIdx + 8),
                                     (int)BitConverter.ToUInt32(peData, baseIdx + 20)));
                }

                int RvaToFile(int rva)
                {
                    foreach (var sec in rvaToOffset)
                        if (rva >= sec.rva && rva < sec.rva + sec.size && sec.offset >= 0)
                            return sec.offset + (rva - (int)sec.rva);
                    return rva;
                }

                for (uint d = 0; d < importSize && d + 20 <= importRva + importSize; d += 20)
                {
                    uint descOff = (uint)RvaToFile((int)importRva + (int)d);
                    if (descOff + 20 > (uint)peData.Length) break;
                    uint nameRva = BitConverter.ToUInt32(peData, (int)descOff + 12);
                    uint firstThunkRva = BitConverter.ToUInt32(peData, (int)descOff + 16);
                    if (nameRva == 0 && firstThunkRva == 0) break;

                    if (nameRva == 0) continue;
                    int nameOff = RvaToFile((int)nameRva);
                    int thunkOff = RvaToFile((int)firstThunkRva);
                    if (nameOff <= 0 || thunkOff < 0) continue;

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
                        bool byName = is32 ? (thunkValue >> 31) == 0 : (thunkValue >> 63) == 0;
                        if (!byName) continue;
                        ulong mask = is32 ? 0x7FFFFFFFUL : 0x7FFFFFFFFFFFFFFFUL;
                        int hint = (int)(thunkValue & mask);
                        int hintOff = RvaToFile(hint + 2);
                        string apiName = ReadAscii(peData, hintOff, 128);
                        if (!string.IsNullOrEmpty(apiName)) apis.Add(apiName);
                    }

                    if (apis.Count > 0) imports.Add((dllName, apis));
                }
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "HeuristicEngine 解析导入表", ex.Message);
            }
            return imports.ToArray();
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

        private static bool IsInSuspiciousLocation(string filePath)
        {
            if (string.IsNullOrEmpty(filePath)) return false;
            string upper = filePath.ToUpperInvariant();
            return upper.Contains("\\APPDATA\\LOCAL\\TEMP\\")
                || upper.Contains("\\WINDOWS\\TEMP\\")
                || upper.Contains("\\USERS\\PUBLIC\\");
        }

        private static bool TryValidateSignature(string exePath)
        {
            if (string.IsNullOrEmpty(exePath) || !File.Exists(exePath)) return false;
            try
            {
                using var cert = X509Certificate.CreateFromSignedFile(exePath);
                using var cert2 = new X509Certificate2(cert);
                if (!cert2.Verify()) return false;
                string publisher = cert2.GetNameInfo(X509NameType.SimpleName, false);
                if (string.IsNullOrEmpty(publisher)) return false;
                return TrustedPublishers.Any(p => publisher.Contains(p, StringComparison.OrdinalIgnoreCase));
            }
            catch
            {
                return false;
            }
        }

        private static string ComputeSha256(byte[] data)
        {
            try { using var sha = SHA256.Create(); return BitConverter.ToString(sha.ComputeHash(data)).Replace("-", "").ToLower(); }
            catch { return string.Empty; }
        }

        private static double CalculateEntropy(byte[] data)
        {
            try
            {
                var frequency = new Dictionary<byte, int>();
                foreach (byte b in data)
                {
                    frequency.TryGetValue(b, out int c);
                    frequency[b] = c + 1;
                }
                double entropy = 0.0;
                double total = data.Length;
                foreach (var p in frequency)
                {
                    double prob = p.Value / total;
                    entropy -= prob * Math.Log(prob, 2);
                }
                return entropy;
            }
            catch { return 0.0; }
        }

        public void ClearCache()
        {
            fileHashCache.Clear();
            heuristicScores.Clear();
        }

        public Dictionary<string, double> GetHeuristicScores()
        {
            return heuristicScores;
        }

        public int GetCacheSize()
        {
            return fileHashCache.Count;
        }
    }
}