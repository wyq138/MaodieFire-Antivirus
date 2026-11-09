using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace FireAntivirus.Engine
{
    /// <summary>
    /// 外置威胁数据装载器。
    /// 所有恶意软件家族字符串均从外部 JSON 加载，不编译进 DLL，
    /// 从根源上消除杀软对引擎二进制的误报，同时保证查杀能力与数据完全一致。
    /// 加载失败不会静默：告警信息通过 LastWarnings 暴露，绝不静默降级导致漏报。
    /// </summary>
    public static class ExternalThreatData
    {
        // JSON 是小驼峰命名(suspiciousProcessNames/commandIndicators 等)，属性是 PascalCase；
        // 必须大小写不敏感，否则所有字段静默反序列化为 null，导致进程防护等模块空库失效（假功能）。
        private static readonly JsonSerializerOptions _jsonOpts = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        };
        private static readonly object _lock = new object();
        private static bool _loaded;
        private static readonly List<string> _warnings = new List<string>();

        /// <summary>
        /// 数据目录：在线更新的运行时库（ProgramData，含 version.json）优先，否则回退出厂库。
        /// </summary>
        private static string DataDir
        {
            get
            {
                try
                {
                    var runtime = Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                        "FireAntivirus", "ThreatData");
                    if (File.Exists(Path.Combine(runtime, "version.json"))) return runtime;
                }
                catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
                return Path.Combine(AppContext.BaseDirectory, "ThreatData");
            }
        }

        public static List<string> LastWarnings => _warnings;

        public static List<SuspiciousProcessEntry> SuspiciousProcesses { get; private set; } = new List<SuspiciousProcessEntry>();
        public static List<MalwareFamilyEntry> MalwareFamilies { get; private set; } = new List<MalwareFamilyEntry>();
        public static HashSet<string> RansomwareExtensions { get; private set; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public static HashSet<string> RansomwareNames { get; private set; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public static List<string> RansomNotes { get; private set; } = new List<string>();

        // ---- 恶意行为指标（命令串 / 漏洞利用名 / 挖矿特征），从 JSON 加载，不编译进 DLL ----
        public static HashSet<string> CommandIndicators { get; private set; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public static HashSet<string> ExploitNames { get; private set; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public static HashSet<string> MiningProtocols { get; private set; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public static HashSet<string> MiningPools { get; private set; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public static HashSet<string> MiningBinaries { get; private set; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        /// <summary>实时防护/进程监控用的可疑进程名集（ThreatData/malicious_indicators.json）。</summary>
        public static HashSet<string> SuspiciousProcessNames { get; private set; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        /// <summary>确保数据已加载（线程安全，幂等）。</summary>
        public static void EnsureLoaded()
        {
            if (_loaded) return;
            lock (_lock)
            {
                if (_loaded) return;
                try
                {
                    LoadSuspiciousProcesses();
                    LoadMalwareFamilies();
                    LoadRansomwareSignatures();
                    LoadMaliciousIndicators();
                    _loaded = true;
                }
                catch (Exception ex)
                {
                    _warnings.Add($"外部威胁数据加载异常: {ex.Message}");
                }
            }
        }

        /// <summary>特征库在线更新落盘后调用：丢弃全部已加载缓存，下次访问按新库重载。</summary>
        public static void Reload()
        {
            lock (_lock)
            {
                _loaded = false;
                SuspiciousProcesses = new List<SuspiciousProcessEntry>();
                MalwareFamilies = new List<MalwareFamilyEntry>();
                RansomwareExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                RansomwareNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                RansomNotes = new List<string>();
                CommandIndicators = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                ExploitNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                MiningProtocols = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                MiningPools = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                MiningBinaries = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                SuspiciousProcessNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                _warnings.Clear();
            }
        }

        private static string Take(string file) => Path.Combine(DataDir, file);

        private static void LoadSuspiciousProcesses()
        {
            var path = Take("suspicious_processes.json");
            if (!File.Exists(path)) { _warnings.Add("suspicious_processes.json 缺失"); return; }
            var list = JsonSerializer.Deserialize<List<SuspiciousProcessEntry>>(File.ReadAllText(path), _jsonOpts);
            if (list != null) SuspiciousProcesses = list;
            else _warnings.Add("suspicious_processes.json 无法解析");
        }

        private static void LoadMalwareFamilies()
        {
            var path = Take("malware_families.json");
            if (!File.Exists(path)) { _warnings.Add("malware_families.json 缺失"); return; }
            var list = JsonSerializer.Deserialize<List<MalwareFamilyEntry>>(File.ReadAllText(path), _jsonOpts);
            if (list != null) MalwareFamilies = list;
            else _warnings.Add("malware_families.json 无法解析");
        }

        private static void LoadRansomwareSignatures()
        {
            var path = Take("ransomware_signatures.json");
            if (!File.Exists(path)) { _warnings.Add("ransomware_signatures.json 缺失"); return; }
            var data = JsonSerializer.Deserialize<RansomwareData>(File.ReadAllText(path));
            if (data == null) { _warnings.Add("ransomware_signatures.json 无法解析"); return; }
            if (data.Extensions != null) foreach (var e in data.Extensions) RansomwareExtensions.Add(e);
            if (data.Names != null) foreach (var n in data.Names) RansomwareNames.Add(n);
            if (data.Notes != null) RansomNotes = new List<string>(data.Notes);
        }

        private static void LoadMaliciousIndicators()
        {
            var path = Take("malicious_indicators.json");
            if (!File.Exists(path)) { _warnings.Add("malicious_indicators.json 缺失"); return; }
            var data = JsonSerializer.Deserialize<MaliciousIndicatorData>(File.ReadAllText(path), _jsonOpts);
            if (data == null) { _warnings.Add("malicious_indicators.json 无法解析"); return; }

            void Add(HashSet<string> set, string[] items)
            {
                if (items == null) return;
                foreach (var i in items) if (!string.IsNullOrWhiteSpace(i)) set.Add(i.Trim());
            }

            Add(CommandIndicators, data.CommandIndicators);
            Add(ExploitNames, data.ExploitNames);
            Add(MiningProtocols, data.MiningProtocols);
            Add(MiningPools, data.MiningPools);
            Add(MiningBinaries, data.MiningBinaries);
            Add(SuspiciousProcessNames, data.SuspiciousProcessNames);
        }
    }

    public class SuspiciousProcessEntry
    {
        public string Name { get; set; }
        public string Threat { get; set; }
    }

    public class MalwareFamilyEntry
    {
        public string Key { get; set; }
        public string Name { get; set; }
        public string Type { get; set; }
        public string[] Patterns { get; set; }
        public string[] FileExtensions { get; set; }
        public string RiskLevel { get; set; }
    }

    public class RansomwareData
    {
        public string[] Extensions { get; set; }
        public string[] Names { get; set; }
        public string[] Notes { get; set; }
    }

    public class MaliciousIndicatorData
    {
        public string[] SuspiciousProcessNames { get; set; }
        public string[] CommandIndicators { get; set; }
        public string[] ExploitNames { get; set; }
        public string[] MiningProtocols { get; set; }
        public string[] MiningPools { get; set; }
        public string[] MiningBinaries { get; set; }
    }
}