// 耄耋软件工作室 开发，严禁非法反编译
// 威胁特征库数据源：从外置 JSON（ThreatData/embedded_threats.json）运行时加载，
// 不把恶意字符串硬编码进 DLL，避免被病毒引擎误判。
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Newtonsoft.Json;

namespace FireAntivirus.Engine.Data
{
    #region 数据结构

    public class EmbeddedYaraRule
    {
        [JsonProperty("name")] public string RuleName { get; set; }
        [JsonProperty("family")] public string Family { get; set; }
        [JsonProperty("severity")] public string Severity { get; set; }
        [JsonProperty("strings")] public string[] Strings { get; set; }
        [JsonProperty("min")] public int MinMatches { get; set; } = int.MinValue;
        [JsonProperty("confidence")] public double Confidence { get; set; }
        [JsonProperty("desc")] public string Description { get; set; }
    }

    public class EmbeddedPeFeature
    {
        [JsonProperty("family")] public string Family { get; set; }
        [JsonProperty("severity")] public string Severity { get; set; }
        [JsonProperty("section")] public string SectionName { get; set; }
        [JsonProperty("dll")] public string ImportDll { get; set; }
        [JsonProperty("apis")] public string[] ImportApis { get; set; }
        [JsonProperty("min")] public int MinApiMatches { get; set; } = 1;
        [JsonProperty("confidence")] public double Confidence { get; set; }
        [JsonProperty("desc")] public string Description { get; set; }
    }

    public class EmbeddedKnownFile
    {
        [JsonProperty("name")] public string FileName { get; set; }
        [JsonProperty("family")] public string Family { get; set; }
        [JsonProperty("severity")] public string Severity { get; set; }
        [JsonProperty("confidence")] public double Confidence { get; set; }
    }

    public class EmbeddedTrustedPublisher
    {
        public string Publisher { get; set; }
        public double TrustScore { get; set; }
    }

    public class EmbeddedBenignLayout
    {
        public string[] Sections { get; set; }
        public double TrustScore { get; set; }
    }

    internal class EmbeddedThreatDbFile
    {
        [JsonProperty("version")] public int Version { get; set; }
        [JsonProperty("yara_rules")] public List<EmbeddedYaraRule> YaraRules { get; set; }
        [JsonProperty("pe_sections")] public List<EmbeddedPeFeature> PeSections { get; set; }
        [JsonProperty("pe_apis")] public List<EmbeddedPeFeature> PeApis { get; set; }
        [JsonProperty("known_files")] public List<EmbeddedKnownFile> KnownFiles { get; set; }
        [JsonProperty("trusted_publishers")] public List<string> TrustedPublishers { get; set; }
        [JsonProperty("known_malicious_names")] public List<string> KnownMaliciousNames { get; set; }
        [JsonProperty("malicious_process_names")] public List<string> MaliciousProcessNames { get; set; }
        [JsonProperty("suspicious_launch_paths")] public List<string> SuspiciousLaunchPaths { get; set; }
        [JsonProperty("injection_module_patterns")] public List<string> InjectionModulePatterns { get; set; }
        [JsonProperty("attack_command_line_signals")] public List<string> AttackCommandLineSignals { get; set; }
        [JsonProperty("miner_process_names")] public List<string> MinerProcessNames { get; set; }
        [JsonProperty("network_propagation_signals")] public List<string> NetworkPropagationSignals { get; set; }
        [JsonProperty("miner_algorithms")] public List<string> MinerAlgorithms { get; set; }
    }

    #endregion

    /// <summary>
    /// 威胁特征数据库（运行时从外置 JSON 加载）。
    /// 避免将恶意字符串硬编码进 DLL 以防 Defender 误判；加载失败时降级为空库并记录。
    /// </summary>
    public static class EmbeddedThreatDatabase
    {
        public static EmbeddedYaraRule[] YaraRules { get; private set; } = Array.Empty<EmbeddedYaraRule>();
        public static EmbeddedPeFeature[] PeFeatures { get; private set; } = Array.Empty<EmbeddedPeFeature>();
        public static EmbeddedKnownFile[] KnownMaliciousFiles { get; private set; } = Array.Empty<EmbeddedKnownFile>();
        public static EmbeddedTrustedPublisher[] TrustedPublishers { get; private set; } = Array.Empty<EmbeddedTrustedPublisher>();
        public static EmbeddedBenignLayout[] BenignLayouts { get; private set; } = Array.Empty<EmbeddedBenignLayout>();
        public static string[] KnownMaliciousNames { get; private set; } = Array.Empty<string>();
        public static string[] MaliciousProcessNames { get; private set; } = Array.Empty<string>();
        public static string[] SuspiciousLaunchPaths { get; private set; } = Array.Empty<string>();
        public static string[] InjectionModulePatterns { get; private set; } = Array.Empty<string>();
        public static string[] AttackCommandLineSignals { get; private set; } = Array.Empty<string>();
        public static string[] MinerProcessNames { get; private set; } = Array.Empty<string>();
        public static string[] NetworkPropagationSignals { get; private set; } = Array.Empty<string>();
        public static string[] MinerAlgorithms { get; private set; } = Array.Empty<string>();

        public static readonly string[] MaliciousUrlPatterns = Array.Empty<string>();
        public static readonly string[] KnownC2Domains = Array.Empty<string>();
        public static readonly string[] SuspiciousCommandLinePatterns = Array.Empty<string>();
        public static readonly string[] SuspiciousMutexes = Array.Empty<string>();

        public static readonly string[] RansomwareTargetExtensions = new[]
        {
            ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".txt", ".rtf",
            ".odt", ".ods", ".odp", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff",
            ".psd", ".raw", ".mp3", ".mp4", ".avi", ".mkv", ".mov", ".wav", ".flac",
            ".zip", ".rar", ".7z", ".tar", ".gz", ".bak", ".sql", ".mdb", ".dwg",
            ".svg", ".vmx", ".vmdk", ".vdi", ".qcow2", ".cs", ".java", ".php", ".py",
            ".key", ".pem", ".crt", ".pfx", ".kdbx", ".wallet", ".dat", ".hwp",
            ".wps", ".et", ".dps", ".json", ".html", ".c", ".cpp"
        };

        private static bool _loading = false;
        private static bool _loaded = false;
        private static readonly object _lock = new object();
        private static string _loadError = null;

        // 索引缓存
        private static readonly Dictionary<string, EmbeddedKnownFile> _knownFileIndex = new(StringComparer.OrdinalIgnoreCase);
        private static readonly Dictionary<string, EmbeddedTrustedPublisher> _publisherIndex = new(StringComparer.OrdinalIgnoreCase);
        private static readonly Dictionary<string, EmbeddedPeFeature[]> _sectionIndex = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>外部调用方确保加载（幂等）。</summary>
        public static void EnsureLoaded()
        {
            if (_loaded || _loading) return;
            lock (_lock)
            {
                if (_loaded || _loading) return;
                _loading = true;
                try
                {
                    var dirs = new[]
                    {
                        AppDomain.CurrentDomain.BaseDirectory,
                        Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ThreatData")
                    };
                    string path = null;
                    foreach (var d in dirs)
                    {
                        var cand = Path.Combine(d, "embedded_threats.json");
                        if (File.Exists(cand)) { path = cand; break; }
                    }

                    if (path == null)
                    {
                        _loadError = "未找到外置特征库文件 embedded_threats.json";
                        YaraRules = Array.Empty<EmbeddedYaraRule>();
                        PeFeatures = Array.Empty<EmbeddedPeFeature>();
                        KnownMaliciousFiles = Array.Empty<EmbeddedKnownFile>();
                        TrustedPublishers = Array.Empty<EmbeddedTrustedPublisher>();
                        KnownMaliciousNames = Array.Empty<string>();
                        MaliciousProcessNames = Array.Empty<string>();
                        SuspiciousLaunchPaths = Array.Empty<string>();
                        InjectionModulePatterns = Array.Empty<string>();
                        AttackCommandLineSignals = Array.Empty<string>();
                        MinerProcessNames = Array.Empty<string>();
                        NetworkPropagationSignals = Array.Empty<string>();
                        MinerAlgorithms = Array.Empty<string>();
                        return;
                    }

                    var db = JsonConvert.DeserializeObject<EmbeddedThreatDbFile>(File.ReadAllText(path));
                    if (db == null) throw new InvalidDataException("外置特征库解析为空");

                    YaraRules = db.YaraRules?.ToArray() ?? Array.Empty<EmbeddedYaraRule>();
                    var sections = db.PeSections ?? new List<EmbeddedPeFeature>();
                    var apis = db.PeApis ?? new List<EmbeddedPeFeature>();
                    PeFeatures = sections.Concat(apis).ToArray();
                    KnownMaliciousFiles = db.KnownFiles?.ToArray() ?? Array.Empty<EmbeddedKnownFile>();
                    TrustedPublishers = (db.TrustedPublishers ?? new List<string>())
                        .Select(p => new EmbeddedTrustedPublisher { Publisher = p, TrustScore = 0.85 })
                        .ToArray();
                    KnownMaliciousNames = (db.KnownMaliciousNames ?? new List<string>())
                        .Where(n => !string.IsNullOrWhiteSpace(n)).Select(n => n.Trim().ToLowerInvariant()).ToArray();
                    MaliciousProcessNames = (db.MaliciousProcessNames ?? new List<string>())
                        .Where(n => !string.IsNullOrWhiteSpace(n)).Select(n => n.Trim().ToLowerInvariant()).ToArray();
                    SuspiciousLaunchPaths = (db.SuspiciousLaunchPaths ?? new List<string>())
                        .Where(n => !string.IsNullOrWhiteSpace(n)).Select(n => n.Trim().ToLowerInvariant()).ToArray();
                    InjectionModulePatterns = (db.InjectionModulePatterns ?? new List<string>())
                        .Where(n => !string.IsNullOrWhiteSpace(n)).Select(n => n.Trim().ToLowerInvariant()).ToArray();
                    AttackCommandLineSignals = (db.AttackCommandLineSignals ?? new List<string>())
                        .Where(n => !string.IsNullOrWhiteSpace(n)).Select(n => n.Trim().ToLowerInvariant()).ToArray();
                    MinerProcessNames = (db.MinerProcessNames ?? new List<string>())
                        .Where(n => !string.IsNullOrWhiteSpace(n)).Select(n => n.Trim().ToLowerInvariant()).ToArray();
                    NetworkPropagationSignals = (db.NetworkPropagationSignals ?? new List<string>())
                        .Where(n => !string.IsNullOrWhiteSpace(n)).Select(n => n.Trim().ToLowerInvariant()).ToArray();
                    MinerAlgorithms = (db.MinerAlgorithms ?? new List<string>())
                        .Where(n => !string.IsNullOrWhiteSpace(n)).Select(n => n.Trim().ToLowerInvariant()).ToArray();

                    BuildIndex();
                }
                catch (Exception ex)
                {
                    _loadError = ex.Message;
                    FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "EmbeddedThreatDatabase 加载失败", ex.Message);
                }
                finally
                {
                    _loading = false;
                    _loaded = true;
                }
            }
        }

        private static void BuildIndex()
        {
            _knownFileIndex.Clear();
            _publisherIndex.Clear();
            _sectionIndex.Clear();
            foreach (var f in KnownMaliciousFiles)
                if (!string.IsNullOrWhiteSpace(f.FileName)) _knownFileIndex[f.FileName.Trim()] = f;
            foreach (var p in TrustedPublishers)
                if (!string.IsNullOrWhiteSpace(p.Publisher)) _publisherIndex[p.Publisher.Trim()] = p;
            foreach (var g in PeFeatures.Where(f => !string.IsNullOrEmpty(f.SectionName))
                                         .GroupBy(f => f.SectionName, StringComparer.OrdinalIgnoreCase))
                _sectionIndex[g.Key] = g.ToArray();
        }

        public static EmbeddedKnownFile LookupKnownFile(string fileName)
        {
            EnsureLoaded();
            if (string.IsNullOrEmpty(fileName)) return null;
            var name = Path.GetFileName(fileName.Trim());
            return _knownFileIndex.TryGetValue(name, out var f) ? f : null;
        }

        public static EmbeddedTrustedPublisher LookupPublisher(string publisher)
        {
            EnsureLoaded();
            if (string.IsNullOrEmpty(publisher)) return null;
            return _publisherIndex.TryGetValue(publisher.Trim(), out var p) ? p : null;
        }

        public static EmbeddedPeFeature[] LookupSection(string sectionName)
        {
            EnsureLoaded();
            if (string.IsNullOrEmpty(sectionName)) return Array.Empty<EmbeddedPeFeature>();
            return _sectionIndex.TryGetValue(sectionName.Trim(), out var f) ? f : Array.Empty<EmbeddedPeFeature>();
        }

        public static bool IsKnownMaliciousName(string name)
        {
            EnsureLoaded();
            if (string.IsNullOrWhiteSpace(name)) return false;
            var n = Path.GetFileName(name.Trim()).ToLowerInvariant();
            return KnownMaliciousNames.Length > 0 && Array.IndexOf(KnownMaliciousNames, n) >= 0;
        }

        public static bool IsMaliciousProcessName(string name)
        {
            EnsureLoaded();
            if (string.IsNullOrWhiteSpace(name)) return false;
            var n = name.Trim().ToLowerInvariant();
            return MaliciousProcessNames.Length > 0 && Array.IndexOf(MaliciousProcessNames, n) >= 0;
        }

        public static bool IsMinerProcessName(string name)
        {
            EnsureLoaded();
            if (string.IsNullOrWhiteSpace(name)) return false;
            var n = name.Trim().ToLowerInvariant();
            return MinerProcessNames.Length > 0 && Array.IndexOf(MinerProcessNames, n) >= 0;
        }

        public static (EmbeddedYaraRule Rule, int Matches) MatchYaraRules(byte[] fileData, Func<string, EmbeddedYaraRule, bool> customFilter = null)
        {
            EnsureLoaded();
            if (fileData == null || fileData.Length == 0 || YaraRules.Length == 0) return (null, 0);

            string text = Encoding.ASCII.GetString(
                Array.ConvertAll(fileData, b => b >= 32 && b <= 126 ? b : (byte)32)).ToLowerInvariant();
            var textSpan = text.AsMemory();

            EmbeddedYaraRule best = null;
            int bestMatches = 0;
            foreach (var rule in YaraRules)
            {
                if (customFilter != null && !customFilter(rule.RuleName, rule)) continue;
                if (rule.Strings == null || rule.Strings.Length == 0) continue;
                int hits = 0;
                foreach (var s in rule.Strings)
                {
                    if (string.IsNullOrEmpty(s)) continue;
                    if (textSpan.Span.IndexOf(s.ToLowerInvariant().AsSpan(), StringComparison.Ordinal) >= 0)
                        hits++;
                }
                int required = rule.MinMatches == int.MinValue ? rule.Strings.Length : rule.MinMatches;
                if (hits >= required && rule.Confidence > (best?.Confidence ?? 0))
                {
                    best = rule;
                    bestMatches = hits;
                }
            }
            return (best, bestMatches);
        }

        /// <summary>自检：确认外置库是否成功加载。</summary>
        public static (bool Ok, int YaraCount, int PeCount, int KnownFileCount, int PublisherCount, string Error) SelfCheck()
        {
            EnsureLoaded();
            int yara = YaraRules?.Length ?? 0;
            int pe = PeFeatures?.Length ?? 0;
            int kf = KnownMaliciousFiles?.Length ?? 0;
            int pub = TrustedPublishers?.Length ?? 0;

            if (!_loaded || _loadError != null)
                return (false, yara, pe, kf, pub, _loadError ?? "特征库未加载");

            bool ok = yara > 20 && pe > 10 && kf > 30 && pub > 10
                && YaraRules.All(r => !string.IsNullOrEmpty(r.RuleName) && r.Strings != null && r.Strings.Length > 0)
                && KnownMaliciousFiles.All(f => !string.IsNullOrEmpty(f.FileName));

            return (ok, yara, pe, kf, pub, ok ? null : "规则完整性校验失败");
        }
    }
}