// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace FireAntivirus.Engine
{
    /// <summary>
    /// 自动更新病毒特征库。
    /// 从 abuse.ch 开源威胁情报源拉取最新特征，落盘到 ProgramData，
    /// 杜绝"硬编码常见病毒"导致对变种无能为力的老问题——特征随时可在运行时增量更新。
    ///
    /// 数据源（均为开源、无需 API Key）：
    ///  - MalwareBazaar 恶意样本 SHA256：https://bazaar.abuse.ch/export/txt/sha256/recent/
    ///  - URLhaus 恶意 URL：            https://urlhaus.abuse.ch/downloads/csv_recent/
    ///  - Feodo Tracker C2 IP：          https://feodotracker.abuse.ch/downloads/ipblocklist.csv
    ///
    /// 落盘目录：%ProgramData%\FireAntivirus\SignatureDatabase\
    /// </summary>
    public static class SignatureDatabaseUpdater
    {
        // ---- 目录与元数据 ----
        private static readonly string RootDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "FireAntivirus", "SignatureDatabase");

        private const string MetaFile = "signature_meta.json";
        private const string HashesFile = "malware_hashes.json";
        private const string UrlsFile = "malicious_urls.json";
        private const string IpsFile = "malicious_ips.json";

        // ---- 在线数据源 ----
        private const string BazaarHashRecentUrl = "https://bazaar.abuse.ch/export/txt/sha256/recent/";
        private const string UrlhausCsvRecentUrl = "https://urlhaus.abuse.ch/downloads/csv_recent/";
        private const string FeodoIpBlocklistUrl = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv";

        private const string UserAgent = "FireAntivirus/3.0 (+signature-updater)";

        // ---- 内存特征缓存 ----
        private static readonly ConcurrentDictionary<string, string> _hashToThreat =
            new ConcurrentDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private static readonly ConcurrentDictionary<string, byte> _maliciousUrls =
            new ConcurrentDictionary<string, byte>(StringComparer.OrdinalIgnoreCase);
        private static readonly ConcurrentDictionary<string, byte> _maliciousIps =
            new ConcurrentDictionary<string, byte>(StringComparer.OrdinalIgnoreCase);

        private static readonly SemaphoreSlim _updateGate = new SemaphoreSlim(1, 1);
        private static volatile bool _autoRunning;
        private static DateTime _lastUpdate = DateTime.MinValue;
        private static string _lastError = string.Empty;

        private static readonly HttpClient _client = new HttpClient(new HttpClientHandler
        {
            AutomaticDecompression = System.Net.DecompressionMethods.GZip | System.Net.DecompressionMethods.Deflate
        })
        { Timeout = TimeSpan.FromSeconds(45) };

        static SignatureDatabaseUpdater()
        {
            _client.DefaultRequestHeaders.Add("User-Agent", UserAgent);
        }

        /// <summary>上次成功更新时间（本地时间）。</summary>
        public static DateTime LastUpdate => _lastUpdate;

        /// <summary>最后一次更新的错误描述（空表示无错误）。</summary>
        public static string LastError => _lastError;

        /// <summary>已加载恶意哈希数。</summary>
        public static int HashCount => _hashToThreat.Count;

        /// <summary>已加载恶意 URL 数。</summary>
        public static int UrlCount => _maliciousUrls.Count;

        /// <summary>已加载恶意 IP 数。</summary>
        public static int IpCount => _maliciousIps.Count;

        /// <summary>是否已加载（内存缓存非空）。</summary>
        public static bool IsLoaded => _hashToThreat.Count > 0 || _maliciousUrls.Count > 0 || _maliciousIps.Count > 0;

        /// <summary>应用启动时调用：播种内置已知哈希 + 加载已持久化特征 + 启动后台自动更新（不阻塞、绝不抛异常）。</summary>
        public static async Task InitializeAsync()
        {
            try { SeedBuiltinHashes(); LoadPersisted(); } catch { /* 数据损坏时保持空，不崩引擎 */ }

            if (!_autoRunning)
            {
                _ = Task.Run(async () => await RunAutoUpdateLoopAsync());
            }

            // 首次更新（若从未更新过）异步拉取一次，避免长时间空库
            if (_lastUpdate == DateTime.MinValue)
            {
                try { await Task.Run(async () => await UpdateAsync()); } catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SignatureDatabaseUpdater.cs 捕获异常", ex.Message); }
            }
        }

        /// <summary>
        /// 把内置已知恶意哈希（ThreatData/known_hashes.json，含 EICAR 测试样本等）播种进运行时特征库。
        /// 目的：不依赖联网也能确定性命中内置高危样本（如 EICAR），同时联网更新在其基础上增量。
        /// </summary>
        private static void SeedBuiltinHashes()
        {
            try
            {
                var file = Path.Combine(AppContext.BaseDirectory, "ThreatData", "known_hashes.json");
                if (!File.Exists(file)) return;
                var list = JsonSerializer.Deserialize<List<MalwareHashEntry>>(File.ReadAllText(file));
                if (list == null) return;
                foreach (var e in list)
                {
                    if (string.IsNullOrWhiteSpace(e.Sha256)) continue;
                    _hashToThreat.TryAdd(e.Sha256.ToLowerInvariant(), string.IsNullOrEmpty(e.ThreatName) ? "KnownMalware" : e.ThreatName);
                }
            }
            catch { /* 内置库缺失不致命 */ }
        }

        /// <summary>后台自动更新循环：默认每 60 分钟检查一次。</summary>
        public static async Task RunAutoUpdateLoopAsync(TimeSpan? interval = null)
        {
            if (_autoRunning) return;
            _autoRunning = true;

            var sleep = interval ?? TimeSpan.FromMinutes(60);
            while (true)
            {
                try
                {
                    // 距上次更新超过"更新间隔"才真正拉取（源站建议 recent 数据约每小时刷新一次）
                    if (DateTime.Now - _lastUpdate >= sleep)
                    {
                        await UpdateAsync();
                    }
                }
                catch { /* 单次失败不中断循环 */ }

                await Task.Delay(TimeSpan.FromMinutes(5));
            }
        }

        /// <summary>
        /// 手动触发/立即更新一次特征库。
        /// 返回更新统计（成功拉取到的最新条目数），供 UI 展示与"立即更新"按钮调用。
        /// </summary>
        public static async Task<SignatureUpdateResult> UpdateAsync()
        {
            // 串行化：同一时刻只允许一次更新
            if (!await _updateGate.WaitAsync(0)) return new SignatureUpdateResult { Succeeded = false, Error = "已有更新正在进行" };
            try
            {
                var result = new SignatureUpdateResult { Succeeded = false };

                try { result.HashesAdded += await UpdateMalwareBazaarHashesAsync(); } catch (Exception ex) { _lastError = $"MalwareBazaar: {ex.Message}"; }
                try { result.UrlsAdded += await UpdateUrlhausUrlsAsync(); } catch (Exception ex) { _lastError += "| URLhaus: " + ex.Message; }
                try { result.IpsAdded += await UpdateFeodoIpsAsync(); } catch (Exception ex) { _lastError += "| Feodo: " + ex.Message; }

                _lastUpdate = DateTime.Now;
                result.Succeeded = true;
                result.UpdatedAt = _lastUpdate;
                result.TotalHashes = HashCount;
                result.TotalUrls = UrlCount;
                result.TotalIps = IpCount;

                SaveMeta();
                return result;
            }
            catch (Exception ex)
            {
                _lastError = ex.Message;
                return new SignatureUpdateResult { Succeeded = false, Error = ex.Message };
            }
            finally
            {
                _updateGate.Release();
            }
        }

        // ---------------------------------------------------------------- 数据源解析

        private static async Task<int> UpdateMalwareBazaarHashesAsync()
        {
            string text = await _client.GetStringAsync(BazaarHashRecentUrl);
            return AddHashesFromText(text);
        }

        /// <summary>解析 MalwareBazaar 文本并加入内存特征库（可在离线测试中直接调用验证解析逻辑）。</summary>
        public static int AddHashesFromText(string text)
        {
            if (string.IsNullOrEmpty(text)) return 0;
            // recent 导出为按行排列的哈希（兼容 html/txt），提取全部 64 位 hex 作为 SHA256
            var matches = Regex.Matches(text, @"\b[a-fA-F0-9]{64}\b");
            int added = 0;
            foreach (Match m in matches)
            {
                string h = m.Value.ToLowerInvariant();
                if (_hashToThreat.TryAdd(h, "MalwareBazaar.HashHit")) added++;
            }
            SaveHashes();
            return added;
        }

        private static async Task<int> UpdateUrlhausUrlsAsync()
        {
            string text = await _client.GetStringAsync(UrlhausCsvRecentUrl);
            return AddUrlsFromText(text);
        }

        /// <summary>解析 URLhaus CSV 文本并加入内存特征库（可在离线测试中直接调用验证解析逻辑）。</summary>
        public static int AddUrlsFromText(string text)
        {
            if (string.IsNullOrEmpty(text)) return 0;
            // CSV 每一行第二列为 URL，用正则兜底提取所有 http(s) URL
            var urls = Regex.Matches(text, @"https?://[^\s""',]+", RegexOptions.IgnoreCase);
            int added = 0;
            foreach (Match m in urls)
            {
                string u = m.Value;
                if (!_maliciousUrls.ContainsKey(u) && _maliciousUrls.TryAdd(u, 0)) added++;
            }
            SaveUrls();
            return added;
        }

        private static async Task<int> UpdateFeodoIpsAsync()
        {
            string text = await _client.GetStringAsync(FeodoIpBlocklistUrl);
            return AddIpsFromText(text);
        }

        /// <summary>解析 Feodo C2 IP 列表文本并加入内存特征库（可在离线测试中直接调用验证解析逻辑）。</summary>
        public static int AddIpsFromText(string text)
        {
            if (string.IsNullOrEmpty(text)) return 0;
            var ips = Regex.Matches(text, @"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b");
            int added = 0;
            foreach (Match m in ips)
            {
                string ip = m.Value;
                if (!_maliciousIps.ContainsKey(ip) && _maliciousIps.TryAdd(ip, 0)) added++;
            }
            SaveIps();
            return added;
        }

        // ---------------------------------------------------------------- 查询接口（供引擎扫描时调用）

        /// <summary>按文件 SHA256 查询是否命中已更新的特征库。</summary>
        public static bool TryGetHashThreat(string sha256, out string threatName) =>
            _hashToThreat.TryGetValue(sha256, out threatName);

        /// <summary>
        /// 仅在内存注册一条恶意哈希（不写盘、不污染持久化特征库），
        /// 供无杀伤力自检构造"可被引擎检测但无害"的样本，验证检测链路是否达标。
        /// </summary>
        public static void RegisterTestHash(string sha256, string threatName = null)
        {
            if (string.IsNullOrWhiteSpace(sha256)) return;
            _hashToThreat.TryAdd(sha256.ToLowerInvariant(), string.IsNullOrEmpty(threatName) ? "SelfTest.Threat" : threatName);
        }

        /// <summary>移除自检过程注册的测试哈希（仅内存），保持特征库干净。</summary>
        public static void RemoveTestHash(string sha256)
        {
            if (string.IsNullOrWhiteSpace(sha256)) return;
            _hashToThreat.TryRemove(sha256.ToLowerInvariant(), out _);
        }

        /// <summary>仅在内存注册一条恶意 URL（不写盘），供自检验证网页拦截链路达标。</summary>
        public static void RegisterTestUrl(string url)
        {
            if (string.IsNullOrWhiteSpace(url)) return;
            _maliciousUrls.TryAdd(url, 0);
        }

        /// <summary>移除自检注册的测试 URL（仅内存）。</summary>
        public static void RemoveTestUrl(string url)
        {
            if (string.IsNullOrWhiteSpace(url)) return;
            _maliciousUrls.TryRemove(url, out _);
        }

        /// <summary>仅在内存注册一条恶意 IP（不写盘），供自检验证网络连接拦截链路达标。</summary>
        public static void RegisterTestIp(string ip)
        {
            if (string.IsNullOrWhiteSpace(ip)) return;
            _maliciousIps.TryAdd(ip, 0);
        }

        /// <summary>移除自检注册的测试 IP（仅内存）。</summary>
        public static void RemoveTestIp(string ip)
        {
            if (string.IsNullOrWhiteSpace(ip)) return;
            _maliciousIps.TryRemove(ip, out _);
        }

        /// <summary>URL 是否为已收录的恶意 URL（host/完整 URL 均可）。</summary>
        public static bool IsMaliciousUrl(string url)
        {
            if (string.IsNullOrWhiteSpace(url)) return false;
            if (_maliciousUrls.ContainsKey(url)) return true;

            // 解析出 host 后再试一次
            if (Uri.TryCreate(url.StartsWith("http", StringComparison.OrdinalIgnoreCase)
                    ? url : "http://" + url, UriKind.Absolute, out var uri))
            {
                return _maliciousUrls.ContainsKey(uri.Host);
            }
            return false;
        }

        /// <summary>IP 是否为已收录的恶意 C2 地址。</summary>
        public static bool IsMaliciousIp(string ip) =>
            !string.IsNullOrWhiteSpace(ip) && _maliciousIps.ContainsKey(ip);

        // ---------------------------------------------------------------- 持久化

        private static void SaveHashes() =>
            WriteJson(HashesFile, new HashDb { UpdatedAt = DateTime.Now, Hashes = _hashToThreat.Select(kv => new HashEntry { Sha256 = kv.Key, Signature = kv.Value }).ToList() });

        private static void SaveUrls() =>
            WriteJson(UrlsFile, new UrlDb { UpdatedAt = DateTime.Now, Urls = _maliciousUrls.Keys.ToList() });

        private static void SaveIps() =>
            WriteJson(IpsFile, new IpDb { UpdatedAt = DateTime.Now, Ips = _maliciousIps.Keys.ToList() });

        private static void SaveMeta() =>
            WriteJson(MetaFile, new Meta { LastUpdate = _lastUpdate, LastError = _lastError, HashCount = HashCount, UrlCount = UrlCount, IpCount = IpCount });

        private static void WriteJson(string fileName, object data)
        {
            try
            {
                Directory.CreateDirectory(RootDir);
                string tmp = Path.Combine(RootDir, fileName + ".tmp");
                File.WriteAllText(tmp, JsonSerializer.Serialize(data, new JsonSerializerOptions { WriteIndented = true }));
                File.Move(tmp, Path.Combine(RootDir, fileName), overwrite: true);
            }
            catch { /* 磁盘写入失败不致命 */ }
        }

        private static void LoadPersisted()
        {
            Directory.CreateDirectory(RootDir);

            var metaPath = Path.Combine(RootDir, MetaFile);
            if (File.Exists(metaPath))
            {
                try
                {
                    var meta = JsonSerializer.Deserialize<Meta>(File.ReadAllText(metaPath));
                    if (meta != null && meta.LastUpdate != DateTime.MinValue) _lastUpdate = meta.LastUpdate;
                }
                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SignatureDatabaseUpdater.cs 捕获异常", ex.Message); }
            }

            var hashPath = Path.Combine(RootDir, HashesFile);
            if (File.Exists(hashPath))
            {
                try
                {
                    var db = JsonSerializer.Deserialize<HashDb>(File.ReadAllText(hashPath));
                    if (db?.Hashes != null)
                        foreach (var e in db.Hashes)
                            if (!string.IsNullOrEmpty(e.Sha256)) _hashToThreat[e.Sha256] = e.Signature ?? "Unknown";
                }
                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SignatureDatabaseUpdater.cs 捕获异常", ex.Message); }
            }

            var urlPath = Path.Combine(RootDir, UrlsFile);
            if (File.Exists(urlPath))
            {
                try
                {
                    var db = JsonSerializer.Deserialize<UrlDb>(File.ReadAllText(urlPath));
                    if (db?.Urls != null)
                        foreach (var u in db.Urls) if (!string.IsNullOrEmpty(u)) _maliciousUrls[u] = 0;
                }
                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SignatureDatabaseUpdater.cs 捕获异常", ex.Message); }
            }

            var ipPath = Path.Combine(RootDir, IpsFile);
            if (File.Exists(ipPath))
            {
                try
                {
                    var db = JsonSerializer.Deserialize<IpDb>(File.ReadAllText(ipPath));
                    if (db?.Ips != null)
                        foreach (var ip in db.Ips) if (!string.IsNullOrEmpty(ip)) _maliciousIps[ip] = 0;
                }
                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SignatureDatabaseUpdater.cs 捕获异常", ex.Message); }
            }
        }

        // ---------------------------------------------------------------- 数据模型（仅 JSON 持久化用）

        public class SignatureUpdateResult
        {
            public bool Succeeded { get; set; }
            public string Error { get; set; }
            public DateTime UpdatedAt { get; set; }
            public int HashesAdded { get; set; }
            public int UrlsAdded { get; set; }
            public int IpsAdded { get; set; }
            public int TotalHashes { get; set; }
            public int TotalUrls { get; set; }
            public int TotalIps { get; set; }

            public int Total =>
                TotalHashes + TotalUrls + TotalIps;
        }

        private sealed class Meta
        {
            public DateTime LastUpdate { get; set; } = DateTime.MinValue;
            public string LastError { get; set; } = string.Empty;
            public int HashCount { get; set; }
            public int UrlCount { get; set; }
            public int IpCount { get; set; }
        }

        private sealed class HashDb
        {
            public DateTime UpdatedAt { get; set; }
            public List<HashEntry> Hashes { get; set; } = new List<HashEntry>();
        }

        private sealed class HashEntry
        {
            public string Sha256 { get; set; }
            public string Signature { get; set; }
        }

        private sealed class UrlDb
        {
            public DateTime UpdatedAt { get; set; }
            public List<string> Urls { get; set; } = new List<string>();
        }

        private sealed class IpDb
        {
            public DateTime UpdatedAt { get; set; }
            public List<string> Ips { get; set; } = new List<string>();
        }
    }

    /// <summary>提供特征库状态给 UI/自检的只读快照。</summary>
    public class SignatureDatabaseStatus
    {
        public bool IsLoaded { get; set; }
        public int HashCount { get; set; }
        public int UrlCount { get; set; }
        public int IpCount { get; set; }
        public DateTime LastUpdate { get; set; }
        public string LastError { get; set; }
    }
}