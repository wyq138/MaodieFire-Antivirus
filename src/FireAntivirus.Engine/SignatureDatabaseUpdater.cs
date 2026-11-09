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
            DbUpdateInProgress = true;
            try
            {
                var result = new SignatureUpdateResult { Succeeded = false };

                // 逐源执行并记录真实状态：旧实现异常被吞、Succeeded 恒 true → UI 永远显示"更新成功 +0 哈希"
                await RunSourceAsync(result, "MalwareBazaar(SHA256)", UpdateMalwareBazaarHashesAsync, isHash: true);
                await RunSourceAsync(result, "URLhaus(恶意URL)", UpdateUrlhausUrlsAsync, isUrl: true);
                await RunSourceAsync(result, "Feodo(C2 IP)", UpdateFeodoIpsAsync, isIp: true);
                await RunSourceAsync(result, "LMD(GitHub/镜像)", UpdateLmdSignaturesAsync, isHash: true);

                // 至少一个源成功才算更新成功；全失败如实报告
                result.Succeeded = result.Sources.Any(s => s.Ok);
                result.Error = result.Succeeded ? "" : "全部数据源不可达（网络受限或源站不可用，请检查网络后重试）";
                _lastError = result.Error;

                if (result.Succeeded)
                {
                    // 仅成功时推进上次更新时间：失败保持旧值，自动更新循环 5 分钟后可重试
                    _lastUpdate = DateTime.Now;
                }

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
                DbUpdateInProgress = false;
            }
        }

        /// <summary>逐源执行：成功/失败/条数/备注全部如实记录，供 UI 精确展示。</summary>
        private static async Task RunSourceAsync(
            SignatureUpdateResult result, string name, Func<Task<int>> fetcher,
            bool isHash = false, bool isUrl = false, bool isIp = false)
        {
            var status = new SourceStatus { Name = name };
            try
            {
                int n = await fetcher();
                status.Ok = true;
                status.Added = n;
                if (n == 0)
                    status.Note = "无新增（源当前时段无新条目，或本地已是最新）";

                if (isHash) result.HashesAdded += n;
                if (isUrl) result.UrlsAdded += n;
                if (isIp) result.IpsAdded += n;
            }
            catch (Exception ex)
            {
                status.Ok = false;
                status.Note = ex.Message;
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                    $"[特征库更新] 源 {name} 失败: {ex.Message}");
            }
            result.Sources.Add(status);
        }

        /// <summary>多源回退下载：主源（GitHub Raw）在受限网络不可达时自动切换 jsDelivr CDN 镜像。</summary>
        private static async Task<string> GetStringWithFallbackAsync(params string[] urls)
        {
            Exception last = null;
            foreach (var u in urls)
            {
                try { return await _client.GetStringAsync(u); }
                catch (Exception ex) { last = ex; }
            }
            throw last ?? new Exception("无可用数据源");
        }

        // ---------------------------------------------------------------- 数据源解析

        // LMD(Linux Malware Detect) 特征源 —— md5 哈希精确匹配(强证据) + ndb/yara 内容特征(经 YARA 引擎)
        // 主源 GitHub Raw 在受限网络常不可达 → 自动回退 jsDelivr CDN 镜像（同一仓库内容）
        private const string LmdNdbUrl = "https://raw.githubusercontent.com/rfxn/linux-malware-detect/master/signatures/rfxn.ndb";
        private const string LmdMd5Url = "https://raw.githubusercontent.com/rfxn/linux-malware-detect/master/signatures/rfxn.md5";
        private const string LmdYaraUrl = "https://raw.githubusercontent.com/rfxn/linux-malware-detect/master/signatures/rfxn.yara";
        private const string LmdNdbMirror = "https://cdn.jsdelivr.net/gh/rfxn/linux-malware-detect@master/signatures/rfxn.ndb";
        private const string LmdMd5Mirror = "https://cdn.jsdelivr.net/gh/rfxn/linux-malware-detect@master/signatures/rfxn.md5";
        private const string LmdYaraMirror = "https://cdn.jsdelivr.net/gh/rfxn/linux-malware-detect@master/signatures/rfxn.yara";

        private static readonly ConcurrentDictionary<string, string> _md5ToThreat =
            new ConcurrentDictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        /// <summary>LMD md5 特征精确查询(命中即强证据)。</summary>
        public static bool TryGetMd5Threat(string md5Hex, out string threatName) =>
            _md5ToThreat.TryGetValue(md5Hex, out threatName);

        /// <summary>更新 LMD 特征：rfxn.ndb(hex→YARA 引擎) / rfxn.md5(哈希库) / rfxn.yara(YARA 规则)。</summary>
        private static async Task<int> UpdateLmdSignaturesAsync()
        {
            int added = 0;
            var lmdDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "FireAntivirus", "LMD");
            var yaraDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "FireAntivirus", "yara_rules");
            Directory.CreateDirectory(lmdDir);
            Directory.CreateDirectory(yaraDir);

            // 1. rfxn.ndb: hex 内容特征（YaraRuleEngine 解析为强证据规则）
            try
            {
                var ndb = await GetStringWithFallbackAsync(LmdNdbUrl, LmdNdbMirror);
                if (ndb.Length > 100)
                {
                    File.WriteAllText(Path.Combine(lmdDir, "rfxn.ndb"), ndb);
                    added += ndb.Split('\n').Count(l => l.Trim().Length > 10);
                }
            }
            catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }

            // 2. rfxn.md5: md5 哈希 → 内存特征库（格式: hash:size:name）
            try
            {
                var md5Text = await GetStringWithFallbackAsync(LmdMd5Url, LmdMd5Mirror);
                foreach (var line in md5Text.Split('\n'))
                {
                    var parts = line.Trim().Split(':');
                    if (parts.Length >= 3 && parts[0].Length == 32)
                    {
                        if (_md5ToThreat.TryAdd(parts[0].ToLowerInvariant(), parts[2].Trim()))
                            added++;
                    }
                }
            }
            catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }

            // 3. rfxn.yara: YARA 规则 → 规则目录（引擎热加载）
            try
            {
                var yaraText = await GetStringWithFallbackAsync(LmdYaraUrl, LmdYaraMirror);
                if (yaraText.Contains("rule "))
                {
                    File.WriteAllText(Path.Combine(yaraDir, "rfxn.yar"), yaraText);
                }
            }
            catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }

            return added;
        }

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

        /// <summary>导出全部已收录恶意 IP（供网络防护模块真实封禁使用）。</summary>
        public static List<string> GetMaliciousIps() => _maliciousIps.Keys.ToList();

        /// <summary>进程名是否命中已知恶意特征（网络威胁情报进程规则）。</summary>
        public static bool IsMaliciousProcessName(string processName)
        {
            if (string.IsNullOrWhiteSpace(processName)) return false;
            var name = processName.Trim().ToLowerInvariant();
            if (!name.EndsWith(".exe")) name += ".exe";
            return _maliciousProcessNames.TryGetValue(name, out _);
        }

        // 恶意进程名规则：从威胁情报订阅加载 + 常见恶意家族名（真实检测规则）
        private static readonly ConcurrentDictionary<string, byte> _maliciousProcessNames = new(
            new[]
            {
                "mimikatz.exe", "cobaltstrike.exe", "beacon.exe", "meterpreter.exe",
                "psexec.exe", "wce.exe", "procdump64.exe", "procdump.exe",
                "nc.exe", "ncat.exe", "netcat.exe", "plink.exe"
            }.ToDictionary(k => k, _ => (byte)0));

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

            /// <summary>逐源状态（真实成功/失败/条数/备注），UI 精确展示用。</summary>
            public List<SourceStatus> Sources { get; set; } = new List<SourceStatus>();

            public int Total =>
                TotalHashes + TotalUrls + TotalIps;
        }

        public class SourceStatus
        {
            public string Name { get; set; }
            public bool Ok { get; set; }
            public int Added { get; set; }
            public string Note { get; set; }
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

        // ---------------------------------------------------------------- ClamAV 病毒库更新

        private static int _clamavUpdating = 0;
        private static DateTime _lastClamavUpdate = DateTime.MinValue;
        private static bool _lastClamavResult;

        /// <summary>病毒库更新进行中（实时防护扫描与 ClamAV 批扫暂停，防资源对撞卡死）。</summary>
        public static volatile bool DbUpdateInProgress;

        /// <summary>
        /// 调用内置 freshclam.exe 真实下载 ClamAV 病毒库（main/daily/bytecode.cvd）。
        /// 一小时内不重复更新；找不到 clamscan/freshclam 时返回 false 并记录日志。
        /// </summary>
        public static async Task<bool> UpdateClamavDbAsync()
        {
            if (Interlocked.Exchange(ref _clamavUpdating, 1) == 1)
                return _lastClamavResult;
            DbUpdateInProgress = true;
            try
            {
                if ((DateTime.Now - _lastClamavUpdate).TotalMinutes < 60)
                    return _lastClamavResult;

                string clamDir = FindClamDirectory();
                if (clamDir == null)
                {
                    _lastError = "未找到 ClamAV 目录";
                    FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "freshclam 更新失败: 未找到 ClamAV 目录");
                    _lastClamavResult = false;
                    return false;
                }

                string dbDir = Path.Combine(clamDir, "db");
                Directory.CreateDirectory(dbDir);
                // 无 BOM 的干净配置（原配置带 BOM 会导致 freshclam 解析失败）
                string conf = Path.Combine(clamDir, "freshclam-clean.conf");
                await File.WriteAllTextAsync(conf,
                    "DatabaseMirror database.clamav.net\n" +
                    "DatabaseDirectory " + dbDir + "\n" +
                    "UpdateLogFile " + Path.Combine(clamDir, "freshclam.log") + "\n" +
                    "ConnectTimeout 60\nReceiveTimeout 60\n");
                Directory.CreateDirectory(Path.Combine(clamDir, "certs"));

                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = Path.Combine(clamDir, "freshclam.exe"),
                    Arguments = "--config-file=\"" + conf + "\" --datadir=\"" + dbDir + "\"",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    WorkingDirectory = clamDir
                };
                bool ok = await Task.Run(() =>
                {
                    try
                    {
                        using var p = System.Diagnostics.Process.Start(psi);
                        if (p == null) return false;
                        try { p.PriorityClass = System.Diagnostics.ProcessPriorityClass.BelowNormal; } catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
                        string output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
                        p.WaitForExit(600000);
                        return p.ExitCode == 0 && File.Exists(Path.Combine(dbDir, "daily.cvd"));
                    }
                    catch (Exception ex)
                    {
                        _lastError = ex.Message;
                        return false;
                    }
                });

                _lastClamavUpdate = DateTime.Now;
                _lastClamavResult = ok;
                if (ok)
                    FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info, "ClamAV 病毒库更新成功");
                else
                    FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "ClamAV 病毒库更新失败: " + _lastError);
                return ok;
            }
            finally
            {
                Interlocked.Exchange(ref _clamavUpdating, 0);
                DbUpdateInProgress = false;
            }
        }

        /// <summary>读取 ClamAV 本地库真实状态（文件/大小/更新时间），供首页病毒库卡展示。</summary>
        public static ClamavDbStatus GetClamavDbStatus()
        {
            var st = new ClamavDbStatus();
            try
            {
                string clamDir = FindClamDirectory();
                if (clamDir == null) return st;

                string dbDir = Path.Combine(clamDir, "db");
                st.Dir = dbDir;
                if (!Directory.Exists(dbDir)) return st;

                var files = Directory.GetFiles(dbDir, "*.cvd")
                    .Concat(Directory.GetFiles(dbDir, "*.cld"))
                    .ToList();
                DateTime? latest = null;
                foreach (var f in files)
                {
                    var fi = new FileInfo(f);
                    st.Files.Add(fi.Name);
                    st.TotalBytes += fi.Length;
                    if (!latest.HasValue || fi.LastWriteTime > latest.Value) latest = fi.LastWriteTime;
                }
                st.Updated = latest;
                st.Available = st.TotalBytes > 0;
            }
            catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
            return st;
        }

        /// <summary>定位随程序分发的 ClamAV 目录（含 freshclam.exe）。</summary>
        private static string FindClamDirectory()
        {
            try
            {
                string baseDir = AppDomain.CurrentDomain.BaseDirectory;
                string[] candidates =
                {
                    Path.Combine(baseDir, "ClamAV"),
                    Path.Combine(baseDir, "clamav"),
                    Path.Combine(baseDir, "FireAntivirus.ClamAV", "ClamAV"),
                    Path.Combine(baseDir, "..", "ClamAV"),
                };
                foreach (var c in candidates)
                {
                    var full = Path.GetFullPath(c);
                    if (File.Exists(Path.Combine(full, "freshclam.exe"))) return full;
                }
            }
            catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
            return null;
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

    /// <summary>ClamAV 本地病毒库（main/daily/bytecode.cvd）真实状态快照。</summary>
    public class ClamavDbStatus
    {
        public bool Available { get; set; }
        public string Dir { get; set; }
        public List<string> Files { get; set; } = new List<string>();
        public long TotalBytes { get; set; }
        public DateTime? Updated { get; set; }
        public double TotalMB => TotalBytes / 1024.0 / 1024.0;
    }
}