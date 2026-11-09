// 清白哈希记忆库（白名单优先架构的核心层，对标大厂"已知好"优先判定）：
//   1) 曾被弱证据怀疑但最终放行的文件（同源刷票拦截/签名否决/系统目录豁免）——哈希入库，永久放行
//   2) 用户在威胁处置窗点"忽略"——视为信任该文件，哈希入库
//   命中即秒过（Clean-Whitelisted），误报只可能发生第一次。
//   强证据（特征/ClamAV/YARA/云权威确认）在 ScanFile 中位于白名单检查之后仍可翻案——
//   即"已知好"挡启发式误报，"已知坏"特征优先级最高，两者不冲突。
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;

namespace FireAntivirus.Engine
{
    public static class WhitelistStore
    {
        private const int MaxEntries = 100_000;      // 防膨胀上限
        private const int SaveBatch = 32;            // 每累计 N 条落盘一次（全盘扫描下避免逐条写盘）

        private static readonly ConcurrentDictionary<string, DateTime> _knownGood = new(StringComparer.OrdinalIgnoreCase);
        private static readonly object _saveLock = new object();
        private static int _dirtyCount;
        private static bool _loaded;

        private static string StorePath => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "FireAntivirus", "whitelist_hashes.json");

        private static void EnsureLoaded()
        {
            if (_loaded) return;
            try
            {
                if (File.Exists(StorePath))
                {
                    var doc = JsonSerializer.Deserialize<Dictionary<string, DateTime>>(File.ReadAllText(StorePath));
                    if (doc != null)
                    {
                        foreach (var kv in doc)
                            _knownGood[kv.Key] = kv.Value;
                    }
                }
            }
            catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
            _loaded = true;
        }

        /// <summary>哈希是否在清白库中。</summary>
        public static bool IsKnownGood(string sha256)
        {
            if (string.IsNullOrEmpty(sha256)) return false;
            EnsureLoaded();
            return _knownGood.ContainsKey(sha256);
        }

        /// <summary>哈希入清白库（弱证据放行/用户忽略）。</summary>
        public static void Remember(string sha256)
        {
            if (string.IsNullOrEmpty(sha256)) return;
            EnsureLoaded();
            if (_knownGood.Count >= MaxEntries && !_knownGood.ContainsKey(sha256)) return;
            if (!_knownGood.TryAdd(sha256, DateTime.Now)) return;

            // 批量落盘：每 SaveBatch 条写一次，避免全盘扫描期间的写盘风暴
            if (System.Threading.Interlocked.Increment(ref _dirtyCount) >= SaveBatch)
            {
                System.Threading.Interlocked.Exchange(ref _dirtyCount, 0);
                Persist();
            }
        }

        /// <summary>按文件路径入清白库（用户"忽略"操作）。</summary>
        public static void RememberFile(string filePath)
        {
            try
            {
                if (!File.Exists(filePath)) return;
                using var sha = SHA256.Create();
                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
                var hash = Convert.ToHexString(sha.ComputeHash(fs)).Replace("-", "");
                Remember(hash);
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info,
                    $"用户忽略威胁，文件哈希已入清白库: {filePath}");
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                    "清白库入库失败", filePath + ": " + ex.Message);
            }
        }

        /// <summary>强制落盘（进程退出/设置页可调用）。</summary>
        public static void Persist()
        {
            lock (_saveLock)
            {
                try
                {
                    EnsureLoaded();
                    Directory.CreateDirectory(Path.GetDirectoryName(StorePath));
                    File.WriteAllText(StorePath,
                        JsonSerializer.Serialize(new Dictionary<string, DateTime>(_knownGood),
                            new JsonSerializerOptions { WriteIndented = false }));
                }
                catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
            }
        }

        /// <summary>清空（调试/重置用）。</summary>
        public static void Clear()
        {
            _knownGood.Clear();
            Persist();
        }
    }
}