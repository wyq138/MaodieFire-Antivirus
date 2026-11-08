// ClamAV 批量池扫描器（进程雨卡死的终局修复）：
//   旧实现 ScanWithClamAV 对每个文件 spawn clamscan.exe —— clamscan 每次启动都要加载全套
//   CVD 病毒库（500-600MB/进程），4 路并发扫描 = 同时 4+ 个 600MB 进程，直接内存爆炸（2026-11-06 实测）。
//   批量池模式：文件入队 → 攒批(≤40 文件) → 全软件同一时刻最多 1 个 clamscan 进程批扫整批
//   → 命中文件经 ThreatConfirmed 事件由宿主弹处置窗/自动隔离。
//   代价：ClamAV 确认从"即时"变"延迟数秒"——检出率不变，内存占用从 N×600MB 降到 1×600MB 峰值。
//   ClamAV 进程模型天然使用最新病毒库：freshclam 更新完成无需重载引擎。
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace FireAntivirus.Engine
{
    public static class ClamAVBatchScanner
    {
        private const int MaxBatch = 40;                 // 单批文件数
        private const int MaxArgChars = 24000;           // 命令行长度保护（Windows 上限 32K）
        private const int BatchIdleDelayMs = 400;        // 队列空轮询间隔
        private const int BatchGapMs = 1500;             // 批间隔：让 clamscan 内存回落

        private static readonly ConcurrentQueue<string> _queue = new ConcurrentQueue<string>();
        private static readonly SemaphoreSlim _gate = new SemaphoreSlim(1, 1);
        private static Task _worker;
        private static int _pending;

        /// <summary>ClamAV 批扫确认命中（宿主订阅：弹处置窗 / Critical·High 自动隔离）。</summary>
        public static event Action<ScanResult> ThreatConfirmed;

        /// <summary>当前待批扫文件数（诊断用）。</summary>
        public static int PendingCount => Volatile.Read(ref _pending);

        /// <summary>文件入批扫队列（ScanFile 主链调用；ClamAV 结果异步回流）。</summary>
        public static void Enqueue(string filePath)
        {
            if (string.IsNullOrEmpty(filePath)) return;
            Interlocked.Increment(ref _pending);
            _queue.Enqueue(filePath);
            EnsureWorker();
        }

        private static void EnsureWorker()
        {
            var w = _worker;
            if (w != null && !w.IsCompleted) return;
            _worker = Task.Run(WorkerLoopAsync);
        }

        private static async Task WorkerLoopAsync()
        {
            while (true)
            {
                if (Volatile.Read(ref _pending) == 0 && _queue.IsEmpty)
                {
                    _worker = null;
                    return; // 队列空退出，下次 Enqueue 重新拉起
                }

                if (SignatureDatabaseUpdater.DbUpdateInProgress)
                {
                    await Task.Delay(2000); // 病毒库更新中：暂停批扫，防下载解压与批扫抢资源
                    continue;
                }

                var batch = DrainBatch();
                if (batch.Count == 0)
                {
                    await Task.Delay(BatchIdleDelayMs);
                    continue;
                }

                await ScanBatchAsync(batch);
                await Task.Delay(BatchGapMs);
            }
        }

        private static List<string> DrainBatch()
        {
            var list = new List<string>();
            int argLen = 0;
            while (list.Count < MaxBatch && _queue.TryDequeue(out var f))
            {
                Interlocked.Decrement(ref _pending);
                if (string.IsNullOrEmpty(f) || !File.Exists(f)) continue;
                argLen += f.Length + 4;
                list.Add(f);
                if (argLen >= MaxArgChars) break;
            }
            return list;
        }

        private static async Task ScanBatchAsync(List<string> batch)
        {
            string clamscan = FindClamScan();
            if (string.IsNullOrEmpty(clamscan)) return; // 未分发 ClamAV：队列自然丢弃，引擎其余层照常工作

            string dbPath = Path.Combine(Path.GetDirectoryName(clamscan), "db");
            if (!Directory.Exists(dbPath))
                dbPath = Path.Combine(Path.GetDirectoryName(clamscan), "database");

            var psi = new ProcessStartInfo
            {
                FileName = clamscan,
                Arguments = $"--database=\"{dbPath}\" --no-summary {string.Join(" ", batch.Select(Quote))}",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                WorkingDirectory = Path.GetDirectoryName(clamscan)
            };

            await _gate.WaitAsync();
            try
            {
                using var p = Process.Start(psi);
                if (p == null) return;
                try { p.PriorityClass = ProcessPriorityClass.BelowNormal; } catch { }
                string output;
                using (var so = p.StandardOutput)
                using (var se = p.StandardError)
                {
                    output = so.ReadToEnd() + se.ReadToEnd();
                }
                p.WaitForExit(120000);

                // clamscan 输出: <路径>: <威胁名> FOUND
                foreach (var line in output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    int idx = line.LastIndexOf("FOUND", StringComparison.Ordinal);
                    if (idx <= 0) continue;

                    string head = line.Substring(0, idx).Trim();
                    int colon = head.LastIndexOf(':');
                    if (colon < 0) continue;
                    string path = head.Substring(0, colon).Trim();
                    string threat = head.Substring(colon + 1).Trim();

                    if (string.IsNullOrEmpty(threat)) continue;

                    ThreatConfirmed?.Invoke(new ScanResult
                    {
                        FilePath = path,
                        IsInfected = true,
                        ThreatName = threat,
                        ThreatType = "Virus",
                        Severity = "High",
                        Confidence = 1.0,
                        DetectionMethod = "ClamAV-Batch",
                        DetectionTime = DateTime.Now,
                        AdditionalInfo = $"ClamAV 批量池确认（单进程批扫，内存友好）"
                    });
                }
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                    "ClamAV 批扫失败: " + ex.Message);
            }
            finally
            {
                _gate.Release();
            }
        }

        private static string Quote(string p) => "\"" + p + "\"";

        /// <summary>定位随程序分发的 clamscan.exe（与 freshclam 同目录约定）。</summary>
        private static string FindClamScan()
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
                    if (File.Exists(Path.Combine(full, "clamscan.exe"))) return Path.Combine(full, "clamscan.exe");
                }
            }
            catch { }
            return null;
        }
    }
}