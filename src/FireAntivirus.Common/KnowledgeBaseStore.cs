using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;

namespace FireAntivirus.Common
{
    /// <summary>
    /// 嵌入式知识库访问器：每个功能项目都内嵌一份模式规则知识库
    /// （KnowledgeBase/*.rules.json，由 tools/generate_knowledge_base.py 生成）。
    /// 本类提供惰性加载与查询 API，供各模块在需要时读取本项目的规则包。
    /// 规则类型: sp=文本模式, dp=域名模式, rp=注册表路径, hp=十六进制特征。
    /// </summary>
    public static class KnowledgeBaseStore
    {
        private static readonly Dictionary<string, IReadOnlyList<KbRule>> _cache =
            new Dictionary<string, IReadOnlyList<KbRule>>(StringComparer.Ordinal);
        private static readonly object _lock = new object();

        public class KbRule
        {
            public string Id { get; set; }
            public string Type { get; set; }
            public string Pattern { get; set; }
            public string Family { get; set; }
            public int Severity { get; set; }
        }

        /// <summary>加载指定程序集内嵌的知识库（惰性、缓存）。</summary>
        public static IReadOnlyList<KbRule> Load(Assembly assembly)
        {
            if (assembly == null) return Array.Empty<KbRule>();
            lock (_lock)
            {
                if (_cache.TryGetValue(assembly.FullName, out var cached)) return cached;
                var rules = LoadFromAssembly(assembly);
                _cache[assembly.FullName] = rules;
                return rules;
            }
        }

        /// <summary>加载当前调用方程序集的知识库。</summary>
        public static IReadOnlyList<KbRule> LoadCurrent()
        {
            return Load(Assembly.GetCallingAssembly());
        }

        private static IReadOnlyList<KbRule> LoadFromAssembly(Assembly assembly)
        {
            var rules = new List<KbRule>();
            try
            {
                var names = assembly.GetManifestResourceNames()
                    .Where(n => n.EndsWith(".rules.json", StringComparison.OrdinalIgnoreCase));
                foreach (var name in names)
                {
                    using (var stream = assembly.GetManifestResourceStream(name))
                    using (var reader = new StreamReader(stream, Encoding.UTF8))
                    {
                        string line;
                        while ((line = reader.ReadLine()) != null)
                        {
                            var rule = ParseLine(line);
                            if (rule != null) rules.Add(rule);
                        }
                    }
                }
            }
            catch
            {
                // 知识库加载失败不应影响主流程
            }
            return rules;
        }

        private static KbRule ParseLine(string line)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(line) || line[0] != '{') return null;
                int idIdx = line.IndexOf("\"id\":\"", StringComparison.Ordinal);
                int tIdx = line.IndexOf("\"t\":\"", StringComparison.Ordinal);
                int pIdx = line.IndexOf("\"p\":\"", StringComparison.Ordinal);
                int fIdx = line.IndexOf("\"f\":\"", StringComparison.Ordinal);
                int sIdx = line.IndexOf("\"s\":", StringComparison.Ordinal);
                if (tIdx < 0 || pIdx < 0) return null;
                return new KbRule
                {
                    Id = Extract(line, idIdx, "\"id\":\""),
                    Type = Extract(line, tIdx, "\"t\":\""),
                    Pattern = Extract(line, pIdx, "\"p\":\""),
                    Family = fIdx >= 0 ? Extract(line, fIdx, "\"f\":\"") : "Generic",
                    Severity = sIdx >= 0 ? SafeInt(line, sIdx + 4) : 2
                };
            }
            catch { return null; }
        }

        private static string Extract(string s, int idx, string key)
        {
            if (idx < 0) return null;
            int start = idx + key.Length;
            var sb = new StringBuilder();
            for (int i = start; i < s.Length; i++)
            {
                char c = s[i];
                if (c == '\\' && i + 1 < s.Length) { sb.Append(s[i + 1]); i++; continue; }
                if (c == '"') break;
                sb.Append(c);
            }
            return sb.ToString();
        }

        private static int SafeInt(string s, int idx)
        {
            int end = idx;
            while (end < s.Length && end - idx < 2 && char.IsDigit(s[end])) end++;
            return end > idx && int.TryParse(s.Substring(idx, end - idx), out var v) ? v : 2;
        }

        /// <summary>用本程序集知识库的文本模式对内容做匹配，返回命中的家族集合。</summary>
        public static HashSet<string> MatchContent(byte[] content, int minPatternLength = 6)
        {
            var families = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (content == null || content.Length == 0) return families;
            try
            {
                string text = Encoding.UTF8.GetString(content);
                if (text.Count(c => c == '\0') > content.Length / 10) return families; // 二进制内容不匹配文本模式
                foreach (var rule in LoadCurrent())
                {
                    if (rule.Type != "sp" || string.IsNullOrEmpty(rule.Pattern)) continue;
                    if (rule.Pattern.Length < minPatternLength) continue;
                    if (text.IndexOf(rule.Pattern, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        families.Add(rule.Family ?? "Generic");
                    }
                }
            }
            catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
            return families;
        }

        /// <summary>统计信息（诊断用）。</summary>
        public static string GetStats(Assembly assembly)
        {
            var rules = Load(assembly);
            return $"规则数: {rules.Count}, 类型: {string.Join(",", rules.Select(r => r.Type).Distinct())}";
        }
    }
}
