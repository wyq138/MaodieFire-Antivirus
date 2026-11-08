// ssdeep(CTPH) + LSH 模糊哈希聚类：同家族/变种样本按内容相似度归并，
// 扫描命中 ≥ MatchThreshold 直接给出家族标签；确认恶意样本自动入库（越用越准）。
// ssdeep 为真实滚动哈希分块实现，LSH 用 4-gram 分带做候选，再做编辑距离精确比对。
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;

namespace FireAntivirus.Engine.Analyzers
{
    public sealed class FuzzyHash
    {
        public int BlockSize { get; set; }
        public string Hash1 { get; set; } = "";
        public string Hash2 { get; set; } = "";

        public override string ToString() => $"{BlockSize}:{Hash1}:{Hash2}";

        public static FuzzyHash Parse(string value)
        {
            var parts = (value ?? "").Split(':');
            if (parts.Length != 3 || !int.TryParse(parts[0], out int bs)) return null;
            return new FuzzyHash { BlockSize = bs, Hash1 = parts[1], Hash2 = parts[2] };
        }
    }

    public sealed class FuzzyMatch
    {
        public bool Matched { get; set; }
        public int Score { get; set; }
        public string Family { get; set; }
        public string MatchedHash { get; set; }
        public string SamplePath { get; set; }
        public DateTime IndexedUtc { get; set; }
    }

    public static class FuzzyHashCluster
    {
        public const int MinBlockSize = 3;
        private const int SpamSumLength = 64;
        private const uint HashPrime = 0x01000193;
        private const uint HashInit = 0x28021967;
        private const string B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        public static bool Enabled { get; set; } = true;
        public static int MatchThreshold { get; set; } = 85;
        public static string IndexPath { get; set; } = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "FireAntivirus", "Similarity", "fuzzy_index.jsonl");

        private sealed class Entry
        {
            public string Hash { get; set; }
            public string Family { get; set; }
            public string SamplePath { get; set; }
            public long Size { get; set; }
            public DateTime IndexedUtc { get; set; }
        }

        private static readonly object _lock = new object();
        private static readonly Dictionary<string, Entry> _entries = new Dictionary<string, Entry>(StringComparer.Ordinal);
        private static readonly Dictionary<string, List<string>> _bands = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        private static bool _loaded;

        public static int Count { get { lock (_lock) { EnsureLoaded(); return _entries.Count; } } }

        // ---------------------------------------------------------------- ssdeep

        public static FuzzyHash Compute(byte[] data)
        {
            if (data == null || data.Length == 0) return new FuzzyHash { BlockSize = MinBlockSize };

            int blockSize = MinBlockSize;
            while ((long)blockSize * SpamSumLength < data.Length) blockSize *= 2;

            var h1 = new StringBuilder(SpamSumLength);
            var h2 = new StringBuilder(SpamSumLength);
            uint r1 = 0, r2 = 0, r3 = 0, sum1 = HashInit, sum2 = HashInit;
            var window = new byte[7];
            int n = 0;
            uint bs = (uint)blockSize, bs2 = (uint)(blockSize * 2);

            foreach (byte c in data)
            {
                r2 -= r1;
                r2 += 7u * c;
                r1 += c;
                r1 -= window[n % 7];
                window[n % 7] = c;
                n++;
                r3 = ((r3 << 5) & 0xFFFFFFFFu) ^ c;
                uint rolling = r1 + r2 + r3;

                sum1 = (sum1 * HashPrime) & 0xFFFFFFFFu; sum1 ^= c;
                sum2 = (sum2 * HashPrime) & 0xFFFFFFFFu; sum2 ^= c;

                if (rolling % bs == bs - 1)
                {
                    if (h1.Length < SpamSumLength - 1) h1.Append(B64[(int)(sum1 % 64)]);
                    sum1 = HashInit;
                }
                if (rolling % bs2 == bs2 - 1)
                {
                    if (h2.Length < SpamSumLength - 1) h2.Append(B64[(int)(sum2 % 64)]);
                    sum2 = HashInit;
                }
            }

            if (sum1 != HashInit) h1.Append(B64[(int)(sum1 % 64)]);
            if (sum2 != HashInit) h2.Append(B64[(int)(sum2 % 64)]);

            return new FuzzyHash { BlockSize = blockSize, Hash1 = h1.ToString(), Hash2 = h2.ToString() };
        }

        public static int Compare(FuzzyHash a, FuzzyHash b)
        {
            if (a == null || b == null) return 0;
            if (a.BlockSize == b.BlockSize) return ScoreStrings(a.Hash1, b.Hash1);
            if (a.BlockSize == b.BlockSize * 2) return ScoreStrings(a.Hash1, b.Hash2);
            if (b.BlockSize == a.BlockSize * 2) return ScoreStrings(a.Hash2, b.Hash1);
            if (a.BlockSize > b.BlockSize && a.BlockSize % b.BlockSize == 0 && a.BlockSize / b.BlockSize >= 2)
                return ScoreStrings(a.Hash2, b.Hash1);
            if (b.BlockSize > a.BlockSize && b.BlockSize % a.BlockSize == 0 && b.BlockSize / a.BlockSize >= 2)
                return ScoreStrings(a.Hash1, b.Hash2);
            return 0;
        }

        public static int CompareStrings(string left, string right)
        {
            var a = FuzzyHash.Parse(left);
            var b = FuzzyHash.Parse(right);
            return a == null || b == null ? 0 : Compare(a, b);
        }

        private static int ScoreStrings(string a, string b)
        {
            if (string.IsNullOrEmpty(a) || string.IsNullOrEmpty(b)) return 0;
            int distance = Levenshtein(a, b);
            int max = Math.Max(a.Length, b.Length);
            int score = (int)Math.Round((1.0 - (double)distance / max) * 100.0);
            return Math.Clamp(score, 0, 100);
        }

        private static int Levenshtein(string a, string b)
        {
            int n = a.Length, m = b.Length;
            if (n == 0) return m;
            if (m == 0) return n;
            var prev = new int[m + 1];
            var cur = new int[m + 1];
            for (int j = 0; j <= m; j++) prev[j] = j;
            for (int i = 1; i <= n; i++)
            {
                cur[0] = i;
                for (int j = 1; j <= m; j++)
                {
                    int cost = a[i - 1] == b[j - 1] ? 0 : 1;
                    cur[j] = Math.Min(Math.Min(cur[j - 1] + 1, prev[j] + 1), prev[j - 1] + cost);
                }
                var tmp = prev; prev = cur; cur = tmp;
            }
            return prev[m];
        }

        // ---------------------------------------------------------------- 索引与聚类

        public static bool TryMatchFile(string filePath, out FuzzyMatch match)
        {
            match = new FuzzyMatch();
            if (!Enabled || string.IsNullOrEmpty(filePath) || !File.Exists(filePath)) return false;
            try
            {
                var info = new FileInfo(filePath);
                if (info.Length <= 0 || info.Length > 32L * 1024 * 1024) return false;
                var data = File.ReadAllBytes(filePath);
                return TryMatch(data, out match);
            }
            catch { return false; }
        }

        public static bool TryMatch(byte[] data, out FuzzyMatch match)
        {
            match = new FuzzyMatch();
            if (!Enabled || data == null || data.Length < 128) return false;

            try
            {
                var hash = Compute(data);
                if (hash.Hash1.Length < 8) return false;

                lock (_lock)
                {
                    EnsureLoaded();
                    if (_entries.Count == 0) return false;

                    int bestScore = 0;
                    Entry best = null;
                    foreach (var candidate in Candidates(hash))
                    {
                        if (!_entries.TryGetValue(candidate, out var entry)) continue;
                        var parsed = FuzzyHash.Parse(entry.Hash);
                        int score = Compare(hash, parsed);
                        if (score > bestScore) { bestScore = score; best = entry; }
                        if (bestScore >= 99) break;
                    }

                    if (best == null || bestScore < MatchThreshold) return false;
                    match = new FuzzyMatch
                    {
                        Matched = true,
                        Score = bestScore,
                        Family = best.Family,
                        MatchedHash = best.Hash,
                        SamplePath = best.SamplePath,
                        IndexedUtc = best.IndexedUtc
                    };
                    return true;
                }
            }
            catch { return false; }
        }

        public static bool IndexFile(string filePath, string family, out string error)
        {
            error = "";
            try
            {
                if (!Enabled || string.IsNullOrEmpty(filePath) || !File.Exists(filePath)) return false;
                var info = new FileInfo(filePath);
                if (info.Length <= 0 || info.Length > 32L * 1024 * 1024) { error = "文件过大或为空"; return false; }
                var data = File.ReadAllBytes(filePath);
                return Index(data, family, filePath, out error);
            }
            catch (Exception ex) { error = ex.Message; return false; }
        }

        public static bool Index(byte[] data, string family, string samplePath, out string error)
        {
            error = "";
            try
            {
                if (!Enabled || data == null || data.Length < 128) { error = "样本过小"; return false; }
                var hash = Compute(data);
                if (hash.Hash1.Length < 8) { error = "哈希过短"; return false; }
                var key = hash.ToString();

                lock (_lock)
                {
                    EnsureLoaded();
                    if (_entries.ContainsKey(key)) return true;
                    if (_entries.Count >= 20000) { error = "索引已达上限 20000"; return false; }

                    var entry = new Entry
                    {
                        Hash = key,
                        Family = string.IsNullOrWhiteSpace(family) ? "Unknown" : family,
                        SamplePath = samplePath,
                        Size = data.Length,
                        IndexedUtc = DateTime.UtcNow
                    };
                    _entries[key] = entry;
                    foreach (var band in Bands(hash)) BandAdd(band, key);
                    AppendToDisk(entry);
                    return true;
                }
            }
            catch (Exception ex) { error = ex.Message; return false; }
        }

        private static IEnumerable<string> Bands(FuzzyHash hash)
        {
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var part in new[] { hash.Hash1, hash.Hash2 })
            {
                for (int i = 0; i + 4 <= part.Length; i += 1)
                {
                    string band = "b" + part.Substring(i, 4);
                    if (seen.Add(band)) yield return band;
                }
            }
        }

        private static IEnumerable<string> Candidates(FuzzyHash hash)
        {
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var band in Bands(hash))
            {
                if (!_bands.TryGetValue(band, out var list)) continue;
                foreach (var key in list)
                    if (seen.Count < 2000 && seen.Add(key)) yield return key;
            }
        }

        private static void BandAdd(string band, string key)
        {
            if (!_bands.TryGetValue(band, out var list))
            {
                list = new List<string>(4);
                _bands[band] = list;
            }
            if (!list.Contains(key)) list.Add(key);
        }

        private static void EnsureLoaded()
        {
            if (_loaded) return;
            _loaded = true;
            try
            {
                if (!File.Exists(IndexPath)) return;
                foreach (var line in File.ReadLines(IndexPath))
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    var entry = JsonSerializer.Deserialize<Entry>(line,
                        new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                    if (entry?.Hash == null) continue;
                    _entries[entry.Hash] = entry;
                    var parsed = FuzzyHash.Parse(entry.Hash);
                    if (parsed != null)
                        foreach (var band in Bands(parsed)) BandAdd(band, entry.Hash);
                    if (_entries.Count >= 20000) break;
                }
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info,
                    $"模糊哈希聚类索引已加载: {_entries.Count} 条（{IndexPath}）");
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                    "模糊哈希索引加载失败: " + ex.Message);
            }
        }

        private static void AppendToDisk(Entry entry)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(IndexPath) ?? ".");
                File.AppendAllText(IndexPath, JsonSerializer.Serialize(entry) + Environment.NewLine, Encoding.UTF8);
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                    "模糊哈希索引写入失败: " + ex.Message);
            }
        }

        public static void Reload()
        {
            lock (_lock)
            {
                _entries.Clear();
                _bands.Clear();
                _loaded = false;
                EnsureLoaded();
            }
        }
    }
}