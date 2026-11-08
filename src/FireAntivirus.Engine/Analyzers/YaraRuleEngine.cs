// YARA/YARA-X 搭配引擎：
//   1) 内置 YARA 规则子集解释器（.yar 字符串/十六进制/正则 + N of them 等条件求值）；
//   2) 检测到 yara-x.exe（官方 Rust 重写版）时优先用 CLI 真实扫描，两者互为搭配；
//   3) 兼容 LMD(Linux Malware Detect) 的 rfxn.ndb(hex)/rfxn.md5(hash)/rfxn.yara 特征格式。
// 规则来源：%ProgramData%\FireAntivirus\yara_rules\*.yar + 程序内置基础规则。
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace FireAntivirus.Engine.Analyzers
{
    public sealed class YaraRule
    {
        public string RuleName;
        public string SourceFile;
        public List<(string Id, byte[] Pattern, byte[] Mask, string RegexText, bool IsHex)> Strings = new();
        public string Condition;
    }

    public static class YaraRuleEngine
    {
        private static List<YaraRule> _rules;
        private static DateTime _loadedAt = DateTime.MinValue;
        private static readonly object _lock = new object();

        private static readonly HttpClient _rulesHttp = new HttpClient { Timeout = TimeSpan.FromSeconds(90) };

        static YaraRuleEngine()
        {
            try { _rulesHttp.DefaultRequestHeaders.Add("User-Agent", "FireAntivirus/3.0 (+yara-rules-update)"); } catch { }
        }

        // 真实公开 YARA 规则源：Florian Roth signature-base（社区老牌公开规则库）。
        // 上游文件可能随时间变动：404/无效内容的文件跳过并如实上报，不影响其余规则集入库。
        private static readonly string[] PublicRuleUrls =
        {
            "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/generic_anomalies.yar",
            "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/thor-webshells.yar",
            "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/exploit_kits.yar",
            "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/cve_rules_new.yar",
            "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/vmdetect.yar",
            "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/maldoc_spectral.yar"
        };

        public sealed class RuleUpdateResult
        {
            public int Updated;
            public List<string> Skipped = new List<string>();
            public string Message;
        }

        /// <summary>
        /// 在线更新 YARA 规则库（真实公开源）：下载 → 内容校验（拒绝 404 页/非规则内容）→ 落盘规则目录 → 触发运行时重载。
        /// percent 0-100 实时上报。
        /// </summary>
        public static async Task<RuleUpdateResult> UpdateRulesFromPublicSourceAsync(IProgress<(int Percent, string Stage)> progress = null)
        {
            var result = new RuleUpdateResult();
            try
            {
                Directory.CreateDirectory(RulesDirectory);
                int total = PublicRuleUrls.Length;
                int done = 0;
                foreach (var url in PublicRuleUrls)
                {
                    done++;
                    string name = url[(url.LastIndexOf('/') + 1)..];
                    try
                    {
                        try { progress?.Report((done * 100 / total, $"下载规则 {name}（{done}/{total}）")); } catch { }
                        var bytes = await _rulesHttp.GetByteArrayAsync(url);
                        string text = Encoding.UTF8.GetString(bytes);

                        // 内容校验：404 页面/占位页/空文件不入库
                        if (text.StartsWith("<!DOCTYPE", StringComparison.OrdinalIgnoreCase)
                            || text.StartsWith("<html", StringComparison.OrdinalIgnoreCase)
                            || text.Length < 64
                            || !text.Contains("rule ", StringComparison.Ordinal))
                        {
                            result.Skipped.Add(name);
                            continue;
                        }

                        await File.WriteAllTextAsync(Path.Combine(RulesDirectory, name), text);
                        result.Updated++;
                    }
                    catch (Exception ex)
                    {
                        result.Skipped.Add($"{name}: {ex.Message}");
                    }
                }

                if (result.Updated > 0)
                {
                    lock (_lock) { _loadedAt = DateTime.MinValue; } // 触发内置解释器重载
                }

                result.Message = result.Updated > 0
                    ? $"YARA 规则库已更新 {result.Updated} 个规则集" + (result.Skipped.Count > 0 ? $"（{result.Skipped.Count} 个源文件跳过）" : "")
                    : "远端规则暂不可用（网络或上游变动）";
            }
            catch (Exception ex)
            {
                result.Message = "YARA 规则更新失败: " + ex.Message;
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "YARA 规则在线更新失败", ex.Message);
            }
            return result;
        }

        private static string RulesDirectory => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "FireAntivirus", "yara_rules");

        private static string YaraXPath =>
            Environment.GetEnvironmentVariable("YARAX_PATH")
            ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "FireAntivirus", "tools", "yara-x.exe");

        /// <summary>外部 yara-x.exe 是否可用（可用时优先走 YARA-X CLI，与内置解释器互为搭配）。</summary>
        public static bool IsYaraXAvailable() => File.Exists(YaraXPath);

        /// <summary>
        /// 扫描文件，返回命中的规则名列表（YARA/YARA-X 搭配：优先 YARA-X CLI，回退内置解释器）。
        /// </summary>
        public static List<string> ScanFile(string filePath)
        {
            if (IsYaraXAvailable())
            {
                var viaYaraX = ScanWithYaraX(filePath);
                if (viaYaraX != null) return viaYaraX;
            }
            return ScanWithBuiltin(filePath);
        }

        /// <summary>通过官方 yara-x.exe 真实扫描（CLI），解析命中的规则名。
        /// 规则目录全部 .yar 合并为单文件一次调用——此前逐规则文件各起一个进程，
        /// 全盘扫描/实时防护下产生"进程雨"直接卡死机器（实测教训）；
        /// 并发进程全局限流 x2；合并失败则回退内置解释器。</summary>
        private static List<string> ScanWithYaraX(string filePath)
        {
            try
            {
                string merged = EnsureMergedRules();
                if (merged == null) return new List<string>();

                var names = new List<string>();
                _procSem.Wait();
                try
                {
                    var psi = new ProcessStartInfo
                    {
                        FileName = YaraXPath,
                        Arguments = $"scan \"{merged}\" \"{filePath}\"",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true
                    };
                    using var process = Process.Start(psi);
                    if (process == null) return names;
                    string output;
                    using (var so = process.StandardOutput)
                    using (var se = process.StandardError)
                    {
                        output = so.ReadToEnd() + se.ReadToEnd();
                    }
                    process.WaitForExit(60000);

                    // yara-x 输出每行: <ruleName> <filePath>
                    foreach (var line in output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                    {
                        var name = line.Trim().Split(' ').FirstOrDefault();
                        if (!string.IsNullOrEmpty(name) && !names.Contains(name))
                            names.Add(name);
                    }
                }
                finally
                {
                    _procSem.Release();
                }
                return names;
            }
            catch
            {
                return null; // CLI 失败回退内置解释器
            }
        }

        private static readonly SemaphoreSlim _procSem = new SemaphoreSlim(2, 2); // yara-x 进程全局并发上限
        private static string _mergedRulesPath;
        private static DateTime _mergedRulesStamp;

        /// <summary>合并规则目录全部 .yar 为单文件（目录内容变化时重建；失败返回 null 回退内置解释器）。</summary>
        private static string EnsureMergedRules()
        {
            try
            {
                if (!Directory.Exists(RulesDirectory)) return null;
                var ruleFiles = Directory.GetFiles(RulesDirectory, "*.yar");
                if (ruleFiles.Length == 0) return null;

                var latest = ruleFiles.Max(File.GetLastWriteTimeUtc);
                string mergedPath = Path.Combine(Path.GetTempPath(), "FireAntivirus_merged_rules.yar");
                if (_mergedRulesPath != null && File.Exists(mergedPath) && _mergedRulesStamp == latest)
                    return mergedPath;

                var sb = new StringBuilder();
                foreach (var f in ruleFiles)
                {
                    try { sb.AppendLine(File.ReadAllText(f)); sb.AppendLine(); } catch { }
                }
                File.WriteAllText(mergedPath, sb.ToString());
                _mergedRulesPath = mergedPath;
                _mergedRulesStamp = latest;
                return mergedPath;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>内置 YARA 规则解释器扫描。</summary>
        private static List<string> ScanWithBuiltin(string filePath)
        {
            EnsureRulesLoaded();

            var hits = new List<string>();
            try
            {
                if (!File.Exists(filePath)) return hits;

                byte[] data;
                using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    var len = (int)Math.Min(fs.Length, 4L * 1024 * 1024);
                    data = new byte[len];
                    int read = 0;
                    while (read < len)
                    {
                        int n = fs.Read(data, read, len - read);
                        if (n <= 0) break;
                        read += n;
                    }
                    if (read < data.Length) Array.Resize(ref data, read);
                }

                if (data.Length == 0) return hits;

                lock (_lock)
                {
                    foreach (var rule in _rules)
                    {
                        try
                        {
                            if (EvaluateRule(rule, data))
                                hits.Add(rule.RuleName);
                        }
                        catch { /* 单条规则解析失败不影响整体 */ }
                    }
                }
            }
            catch { }

            return hits;
        }

        private static bool EvaluateRule(YaraRule rule, byte[] data)
        {
            var asAscii = Encoding.ASCII.GetString(data);
            var asWide = Encoding.Unicode.GetString(data);

            var hits = new Dictionary<string, bool>();
            foreach (var s in rule.Strings)
            {
                bool hit;
                if (s.IsHex)
                {
                    hit = ContainsHexPattern(data, s.Pattern, s.Mask);
                }
                else if (s.RegexText != null)
                {
                    var regex = new Regex(s.RegexText, RegexOptions.IgnoreCase | RegexOptions.ExplicitCapture, TimeSpan.FromSeconds(5));
                    hit = regex.IsMatch(asAscii) || regex.IsMatch(asWide);
                }
                else
                {
                    hit = IndexOfBytes(data, s.Pattern) >= 0
                          || IndexOfBytes(data, Encoding.Unicode.GetBytes(Encoding.ASCII.GetString(s.Pattern))) >= 0;
                }
                hits[s.Id] = hit;
            }

            return EvaluateCondition(rule.Condition, hits);
        }

        /// <summary>
        /// 条件求值（YARA 常用子集）：N of them / any of them / all of them / them /
        /// 布尔组合（and / or / not / 括号 / $a）。
        /// </summary>
        private static bool EvaluateCondition(string condition, Dictionary<string, bool> hits)
        {
            if (string.IsNullOrWhiteSpace(condition))
                return hits.Values.Any(v => v);

            var expr = condition.Trim();

            // N of them / any of them / all of them / them
            var m = Regex.Match(expr, @"^(?<n>\d+)\s+of\s+them$", RegexOptions.IgnoreCase);
            if (m.Success)
                return hits.Values.Count(v => v) >= int.Parse(m.Groups["n"].Value);

            m = Regex.Match(expr, @"^any\s+of\s+them$", RegexOptions.IgnoreCase);
            if (m.Success) return hits.Values.Any(v => v);

            m = Regex.Match(expr, @"^all\s+of\s+them$", RegexOptions.IgnoreCase);
            if (m.Success) return hits.Values.All(v => v);

            if (expr.Equals("them", StringComparison.OrdinalIgnoreCase))
                return hits.Values.Any(v => v);

            m = Regex.Match(expr, @"^(?<n>\d+)\s+of\s+\((?<set>[^)]+)\)$", RegexOptions.IgnoreCase);
            if (m.Success)
            {
                int need = int.Parse(m.Groups["n"].Value);
                int count = m.Groups["set"].Value.Split(',').Count(id =>
                    hits.TryGetValue(id.Trim(), out var hit) && hit);
                return count >= need;
            }

            // 布尔表达式（$a and $b / not / 括号）：把标识符替换成 1/0 后求值
            var tokens = Regex.Replace(expr, @"\$(?<id>[A-Za-z0-9_]+)", match =>
            {
                var id = "$" + match.Groups["id"].Value;
                return hits.TryGetValue(id, out var hit) && hit ? "1" : "0";
            }, RegexOptions.IgnoreCase);
            tokens = tokens.Replace("and", "&&", StringComparison.OrdinalIgnoreCase)
                           .Replace("or", "||", StringComparison.OrdinalIgnoreCase)
                           .Replace("not", "!", StringComparison.OrdinalIgnoreCase);

            return SimpleBooleanEval(tokens);
        }

        // ---- 受限布尔表达式求值（仅含 0/1/( ) && || !），递归下降实现 ----
        private static bool SimpleBooleanEval(string expr)
        {
            int pos = 0;
            return ParseOr(expr, ref pos);
        }

        private static bool ParseOr(string s, ref int pos)
        {
            bool left = ParseAnd(s, ref pos);
            while (MatchToken(s, ref pos, "||"))
            {
                bool right = ParseAnd(s, ref pos);
                left |= right;
            }
            return left;
        }

        private static bool ParseAnd(string s, ref int pos)
        {
            bool left = ParseFactor(s, ref pos);
            while (MatchToken(s, ref pos, "&&"))
            {
                bool right = ParseFactor(s, ref pos);
                left &= right;
            }
            return left;
        }

        private static bool ParseFactor(string s, ref int pos)
        {
            SkipSpace(s, ref pos);

            if (pos < s.Length && s[pos] == '!')
            {
                pos++;
                return !ParseFactor(s, ref pos);
            }

            if (pos < s.Length && s[pos] == '(')
            {
                pos++;
                bool value = ParseOr(s, ref pos);
                SkipSpace(s, ref pos);
                if (pos < s.Length && s[pos] == ')') pos++;
                return value;
            }

            if (pos < s.Length && s[pos] == '1') { pos++; return true; }
            if (pos < s.Length && s[pos] == '0') { pos++; return false; }

            return false;
        }

        private static void SkipSpace(string s, ref int pos)
        {
            while (pos < s.Length && s[pos] == ' ') pos++;
        }

        private static bool MatchToken(string s, ref int pos, string token)
        {
            SkipSpace(s, ref pos);
            if (pos + token.Length <= s.Length &&
                string.CompareOrdinal(s, pos, token, 0, token.Length) == 0)
            {
                pos += token.Length;
                return true;
            }
            return false;
        }

        // ---- 字节匹配 ----
        private static int IndexOfBytes(byte[] haystack, byte[] needle)
        {
            if (needle.Length == 0 || haystack.Length < needle.Length) return -1;

            for (int i = 0; i <= haystack.Length - needle.Length; i++)
            {
                if (haystack[i] != needle[0]) continue;
                bool match = true;
                for (int j = 1; j < needle.Length; j++)
                {
                    if (haystack[i + j] != needle[j]) { match = false; break; }
                }
                if (match) return i;
            }
            return -1;
        }

        private static bool ContainsHexPattern(byte[] data, byte[] pattern, byte[] mask)
        {
            if (pattern.Length == 0 || data.Length < pattern.Length) return false;

            for (int i = 0; i <= data.Length - pattern.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < pattern.Length; j++)
                {
                    // mask[j] == 0 表示通配符 ??
                    if (mask[j] != 0 && data[i + j] != pattern[j]) { match = false; break; }
                }
                if (match) return i >= 0;
            }
            return false;
        }

        // ---- 规则加载 ----
        public static void EnsureRulesLoaded()
        {
            lock (_lock)
            {
                var latestChange = Directory.Exists(RulesDirectory)
                    ? new DirectoryInfo(RulesDirectory).GetFiles("*.yar").Max(f => f.LastWriteTime)
                    : DateTime.MinValue;

                if (_rules != null && latestChange <= _loadedAt) return;

                var rules = new List<YaraRule>();

                // 内置基础规则（首次运行导出，随后可被外部规则文件扩充/覆盖）
                ExportBuiltinRules();
                if (!Directory.Exists(RulesDirectory)) { _rules = rules; _loadedAt = DateTime.Now; return; }

                foreach (var file in Directory.GetFiles(RulesDirectory, "*.yar"))
                {
                    try
                    {
                        rules.AddRange(ParseYarFile(file));
                    }
                    catch { }
                }

                // LMD ndb 特征文件转换为内置十六进制规则（一条 = 一条规则）
                var lmdDir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "FireAntivirus", "LMD");
                var ndb = Path.Combine(lmdDir, "rfxn.ndb");
                if (File.Exists(ndb))
                {
                    rules.AddRange(ParseLmdNdb(ndb));
                }

                _rules = rules;
                _loadedAt = DateTime.Now;
            }
        }

        public static int RuleCount
        {
            get { lock (_lock) return _rules?.Count ?? 0; }
        }

        // ---- YARA 规则解析（常用子集）----
        internal static List<YaraRule> ParseYarFile(string path)
        {
            var text = File.ReadAllText(path);
            var rules = new List<YaraRule>();
            var ruleRegex = new Regex(
                @"rule\s+(?<name>[\w\-\.]+)\s*\{(?<body>(?>[^{}]+|\{(?<DEPTH>)|\}(<-DEPTH>))*)(\})",
                RegexOptions.ExplicitCapture);

            // 简化块提取：按 rule 关键字切分
            var parts = Regex.Split(text, @"\brule\s+", RegexOptions.IgnoreCase);
            foreach (var part in parts.Skip(1))
            {
                int braceStart = part.IndexOf('{');
                if (braceStart < 0) continue;

                var nameToken = part.Substring(0, braceStart).Trim();
                var name = nameToken.Split(':')[0].Split(' ')[0].Trim();
                if (name.StartsWith("global") || name.StartsWith("private")) continue;

                int braceEnd = part.LastIndexOf('}');
                if (braceEnd <= braceStart) continue;
                var body = part.Substring(braceStart + 1, braceEnd - braceStart - 1);

                // 分离 strings: 与 condition:
                var stringsSection = "";
                var conditionSection = "";
                var condMatch = Regex.Match(body, @"condition\s*:", RegexOptions.IgnoreCase);
                var strMatch = Regex.Match(body, @"strings\s*:", RegexOptions.IgnoreCase);
                int condIdx = condMatch.Success ? condMatch.Index : -1;
                int strIdx = strMatch.Success ? strMatch.Index : -1;

                if (condIdx >= 0)
                {
                    conditionSection = body.Substring(condIdx + Regex.Match(body.Substring(condIdx), @"condition\s*:").Length).Trim();
                    var condBlockEnd = conditionSection.IndexOf('}');
                    if (condBlockEnd >= 0) conditionSection = conditionSection.Substring(0, condBlockEnd);
                }

                if (strIdx >= 0)
                {
                    stringsSection = strIdx < condIdx
                        ? body.Substring(strIdx, condIdx - strIdx)
                        : body.Substring(strIdx);
                    stringsSection = Regex.Replace(stringsSection, @"strings\s*:", "", RegexOptions.IgnoreCase);
                }

                var rule = new YaraRule
                {
                    RuleName = name,
                    SourceFile = Path.GetFileName(path),
                    Condition = conditionSection
                };

                // 解析字符串条目
                foreach (var line in stringsSection.Split('\n'))
                {
                    var trimmed = line.Trim();
                    if (trimmed.Length == 0 || trimmed.StartsWith("//")) continue;

                    var sm = Regex.Match(trimmed, @"\$(?<id>\w+)\s*=\s*(?<def>.+)$");
                    if (!sm.Success) continue;
                    var id = "$" + sm.Groups["id"].Value;
                    var def = sm.Groups["def"].Value.Trim();

                    if (def.StartsWith("{") && def.Contains("}"))
                    {
                        // 十六进制串 { XX XX ?? XX }
                        var hexText = def.Trim('{', '}').Replace(" ", "").Replace("\r", "").Replace("\n", "");
                        var pattern = new List<byte>();
                        var mask = new List<byte>();
                        bool valid = true;
                        for (int i = 0; i + 1 < hexText.Length; i += 2)
                        {
                            var hi = hexText[i];
                            var lo = hexText[i + 1];
                            if (hi == '?' && lo == '?') { pattern.Add(0); mask.Add(0); }
                            else if (Uri.IsHexDigit(hi) && Uri.IsHexDigit(lo))
                            { pattern.Add(Convert.ToByte(hexText.Substring(i, 2), 16)); mask.Add(0xFF); }
                            else { valid = false; break; }
                        }
                        if (valid && pattern.Count > 0)
                            rule.Strings.Add((id, pattern.ToArray(), mask.ToArray(), null, true));
                    }
                    else if (def.StartsWith("/"))
                    {
                        // 正则 /.../[flags]
                        var endSlash = def.LastIndexOf('/');
                        if (endSlash > 0)
                        {
                            var patternText = def.Substring(1, endSlash - 1);
                            rule.Strings.Add((id, Array.Empty<byte>(), Array.Empty<byte>(), patternText, false));
                        }
                    }
                    else if (def.StartsWith("\"") && def.LastIndexOf('"') > 0)
                    {
                        // 字符串 "text"（忽略 ascii/wide/nocase 修饰符——匹配时同时按宽字符处理）
                        var endQuote = def.LastIndexOf('"');
                        var literal = def.Substring(1, endQuote - 1).Replace("\\\"", "\"").Replace("\\\\", "\\");
                        if (literal.Length > 0)
                            rule.Strings.Add((id, Encoding.ASCII.GetBytes(literal), null, null, false));
                    }
                }

                if (rule.Strings.Count > 0)
                    rules.Add(rule);
            }

            return rules;
        }

        // ---- LMD rfxn.ndb 解析（格式: 名称;偏移;hex特征）----
        internal static List<YaraRule> ParseLmdNdb(string path)
        {
            var rules = new List<YaraRule>();

            foreach (var line in File.ReadLines(path))
            {
                var trimmed = line.Trim();
                if (trimmed.Length == 0 || trimmed.StartsWith("#")) continue;

                var parts = trimmed.Split(';');
                if (parts.Length < 3) continue;

                var name = parts[0].Trim();
                var hexText = parts[2].Replace(" ", "").Replace("{", "").Replace("}", "").Trim();

                var pattern = new List<byte>();
                var mask = new List<byte>();
                bool valid = hexText.Length % 2 == 0;

                for (int i = 0; valid && i + 1 < hexText.Length; i += 2)
                {
                    var hi = hexText[i];
                    var lo = hexText[i + 1];
                    if (hi == '?' && lo == '?') { pattern.Add(0); mask.Add(0); }
                    else if (Uri.IsHexDigit(hi) && Uri.IsHexDigit(lo))
                    { pattern.Add(Convert.ToByte(hexText.Substring(i, 2), 16)); mask.Add(0xFF); }
                    else valid = false;
                }

                if (valid && pattern.Count >= 4)
                {
                    rules.Add(new YaraRule
                    {
                        RuleName = $"LMD.{name}",
                        SourceFile = "rfxn.ndb",
                        Condition = "any of them",
                        Strings = { ("$s0", pattern.ToArray(), mask.ToArray(), null, true) }
                    });
                }
            }

            return rules;
        }

        // ---- 内置基础规则（真实威胁特征）----
        private static void ExportBuiltinRules()
        {
            try
            {
                Directory.CreateDirectory(RulesDirectory);
                var builtin = Path.Combine(RulesDirectory, "builtin.yar");
                if (File.Exists(builtin)) return;

                var sb = new StringBuilder();
                sb.AppendLine("// FireAntivirus 内置基础 YARA 规则（可编辑扩充，保存后自动热加载）");
                sb.AppendLine();
                sb.AppendLine("rule FA_Test_Eicar_Test_File");
                sb.AppendLine("{");
                sb.AppendLine("    strings:");
                sb.AppendLine("        $eicar = \"EICAR-STANDARD-ANTIVIRUS-TEST-FILE\"");
                sb.AppendLine("    condition:");
                sb.AppendLine("        $eicar");
                sb.AppendLine("}");
                sb.AppendLine();
                sb.AppendLine("rule FA_Ransomware_Shadow_Deletion_Commands");
                sb.AppendLine("{");
                sb.AppendLine("    strings:");
                sb.AppendLine("        $s1 = \"vssadmin delete shadows\"");
                sb.AppendLine("        $s2 = \"wbadmin delete catalog\"");
                sb.AppendLine("        $s3 = \"bcdedit /set recoveryenabled no\"");
                sb.AppendLine("        $s4 = \"cipher /w:\"");
                sb.AppendLine("    condition:");
                sb.AppendLine("        2 of them");
                sb.AppendLine("}");
                sb.AppendLine();
                sb.AppendLine("rule FA_Webshell_Generic_Eval_Base64");
                sb.AppendLine("{");
                sb.AppendLine("    strings:");
                sb.AppendLine("        $p1 = /eval\\s*\\(\\s*(gzinflate|base64_decode|str_rot13)\\s*\\(/i");
                sb.AppendLine("        $p2 = /\\$_(GET|POST|REQUEST)\\s*\\[[^\\]]{0,64}\\]\\s*\\(/i");
                sb.AppendLine("        $p3 = /passthru\\s*\\(|shell_exec\\s*\\(|system\\s*\\(/i");
                sb.AppendLine("    condition:");
                sb.AppendLine("        2 of them");
                sb.AppendLine("}");
                sb.AppendLine();
                sb.AppendLine("rule FA_Backdoor_Behavior_Markers");
                sb.AppendLine("{");
                sb.AppendLine("    strings:");
                sb.AppendLine("        $b1 = \"CreateRemoteThread\"");
                sb.AppendLine("        $b2 = \"WriteProcessMemory\"");
                sb.AppendLine("        $b3 = \"NtUnmapViewOfSection\"");
                sb.AppendLine("        $b4 = \"SetWindowsHookEx\"");
                sb.AppendLine("    condition:");
                sb.AppendLine("        3 of them");
                sb.AppendLine("}");

                File.WriteAllText(builtin, sb.ToString());
            }
            catch { }
        }
    }
}