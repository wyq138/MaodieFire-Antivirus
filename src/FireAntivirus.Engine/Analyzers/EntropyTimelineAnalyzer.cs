// 文件 I/O 熵变时序分析（勒索防护升级）：
//   对文档类文件维护"基线熵 → 当前熵"的时间序列（30 秒滑动窗口），只读尾部 64KB 计算香农熵。
//   判定：窗口内 ≥6 个文件从低熵(<5.0)跃升到高熵(>=7.5)，或 ≥3 个文件跃迁且窗口内观测文件数 ≥10。
//   排除压缩/媒体/安装包/PE（它们本来就高熵），首次观测即高熵的文件不参与（已加密基线不可用）。
//   输出可疑 PID 集合，供链级阻断。
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace FireAntivirus.Engine.Analyzers
{
    public sealed class EntropyAnomaly
    {
        public bool Detected { get; set; }
        public int Score { get; set; }
        public double WindowSeconds { get; set; }
        public List<string> Reasons { get; set; } = new List<string>();
        public List<string> Files { get; set; } = new List<string>();
        public List<int> SuspectPids { get; set; } = new List<int>();
        public int WriteRate { get; set; }
    }

    public static class EntropyTimelineAnalyzer
    {
        public static bool Enabled { get; set; } = true;
        public static double LowBaseline { get; set; } = 5.0;
        public static double HighEntropy { get; set; } = 7.5;
        public static int MinEscalations { get; set; } = 6;
        public static int WindowSeconds { get; set; } = 30;
        public static int MinDistinctFiles { get; set; } = 10;
        public static int MaxTrackedFiles { get; set; } = 20000;

        private sealed class State
        {
            public double Baseline;
            public double Last;
            public long LastSize;
            public string Extension = "";
            public DateTime LastUtc;
            public bool BaselineValid;
            public DateTime? EscalatedUtc;
        }

        private sealed class Escalation
        {
            public string Path;
            public int Pid;
            public DateTime Utc;
            public double From;
            public double To;
        }

        private static readonly object _lock = new object();
        private static readonly Dictionary<string, State> _states =
            new Dictionary<string, State>(StringComparer.OrdinalIgnoreCase);
        private static readonly List<Escalation> _escalations = new List<Escalation>();
        private static readonly Dictionary<string, DateTime> _observedWindow =
            new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);

        // 只对"正常情况低熵"的文档类判定（压缩/媒体/安装包/PE 天然高熵，纳入会大量误报）
        private static readonly HashSet<string> WatchedExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".txt", ".rtf", ".csv",
            ".jpg", ".jpeg", ".png", ".bmp", ".tif", ".tiff", ".psd", ".ai", ".dwg",
            ".db", ".sqlite", ".mdb", ".accdb", ".sql", ".bak", ".mdf", ".ldf",
            ".mp3", ".wav", ".flac", ".aac", ".mp4", ".avi", ".mov", ".mkv",
            ".eml", ".msg", ".pst", ".ost", ".one", ".vsd", ".vsdx", ".odt", ".ods"
        };

        /// <summary>文件写入事件入口。返回当前窗口的熵变异常（未触发时 Detected=false）。</summary>
        public static EntropyAnomaly Observe(string filePath, int pid = 0)
        {
            var anomaly = new EntropyAnomaly { WindowSeconds = WindowSeconds };
            if (!Enabled || string.IsNullOrEmpty(filePath)) return anomaly;

            try
            {
                string ext = Path.GetExtension(filePath) ?? "";
                if (!WatchedExtensions.Contains(ext)) return anomaly;

                var info = new FileInfo(filePath);
                if (!info.Exists || info.Length <= 0 || info.Length > 512L * 1024 * 1024) return anomaly;

                double entropy = TailEntropy(filePath);
                var now = DateTime.UtcNow;

                lock (_lock)
                {
                    if (_states.Count > MaxTrackedFiles)
                        foreach (var key in _states.OrderBy(kv => kv.Value.LastUtc)
                                                  .Take(_states.Count - MaxTrackedFiles)
                                                  .Select(kv => kv.Key).ToList())
                            _states.Remove(key);

                    if (!_states.TryGetValue(filePath, out var state))
                    {
                        state = new State
                        {
                            Baseline = entropy,
                            Last = entropy,
                            LastSize = info.Length,
                            Extension = ext,
                            LastUtc = now,
                            BaselineValid = entropy < HighEntropy
                        };
                        _states[filePath] = state;
                    }
                    else
                    {
                        bool extensionChanged = !string.Equals(state.Extension, ext, StringComparison.OrdinalIgnoreCase);
                        bool escalated = state.BaselineValid
                                         && state.Baseline < LowBaseline
                                         && entropy >= HighEntropy
                                         && entropy - state.Baseline >= 2.0
                                         && (state.EscalatedUtc == null || (now - state.EscalatedUtc.Value).TotalSeconds > WindowSeconds);

                        if (escalated)
                        {
                            state.EscalatedUtc = now;
                            _escalations.Add(new Escalation
                            {
                                Path = filePath,
                                Pid = pid,
                                Utc = now,
                                From = state.Baseline,
                                To = entropy
                            });
                        }

                        if (extensionChanged && entropy >= HighEntropy)
                            anomaly.Reasons.Add($"文件扩展名被改且内容高熵: {Path.GetFileName(filePath)}");

                        state.Last = entropy;
                        state.LastSize = info.Length;
                        state.Extension = ext;
                        state.LastUtc = now;
                    }

                    _observedWindow[filePath] = now;
                    var cutoff = now.AddSeconds(-WindowSeconds);
                    _escalations.RemoveAll(e => e.Utc < cutoff);
                    foreach (var key in _observedWindow.Where(kv => kv.Value < cutoff).Select(kv => kv.Key).ToList())
                        _observedWindow.Remove(key);

                    int distinctEscalated = _escalations.Select(e => e.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count();
                    int distinctObserved = _observedWindow.Count;
                    anomaly.WriteRate = distinctObserved;

                    if (distinctEscalated >= MinEscalations)
                    {
                        anomaly.Detected = true;
                        anomaly.Score = Math.Min(100, 70 + distinctEscalated * 3);
                        anomaly.Reasons.Add($"{WindowSeconds}s 内 {distinctEscalated} 个文档从低熵跃升到高熵（疑似批量加密）");
                    }
                    else if (distinctEscalated >= 3 && distinctObserved >= MinDistinctFiles)
                    {
                        anomaly.Detected = true;
                        anomaly.Score = 75;
                        anomaly.Reasons.Add($"{WindowSeconds}s 内 {distinctEscalated} 个文档熵跃迁，写入 {distinctObserved} 个文件（疑似勒索加密）");
                    }

                    if (anomaly.Detected)
                    {
                        anomaly.Files = _escalations.OrderByDescending(e => e.Utc)
                                                    .Select(e => e.Path).Distinct(StringComparer.OrdinalIgnoreCase)
                                                    .Take(20).ToList();
                        anomaly.SuspectPids = _escalations.Where(e => e.Pid > 0)
                                                          .GroupBy(e => e.Pid)
                                                          .OrderByDescending(g => g.Count())
                                                          .Select(g => g.Key).Take(10).ToList();
                    }
                }
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                    "熵变时序分析失败: " + ex.Message);
            }
            return anomaly;
        }

        public static void Reset()
        {
            lock (_lock)
            {
                _states.Clear();
                _escalations.Clear();
                _observedWindow.Clear();
            }
        }

        private static double TailEntropy(string filePath)
        {
            const int sampleSize = 64 * 1024;
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            long readFrom = Math.Max(0, fs.Length - sampleSize);
            fs.Seek(readFrom, SeekOrigin.Begin);
            var buffer = new byte[Math.Min(sampleSize, fs.Length)];
            int read = 0;
            while (read < buffer.Length)
            {
                int n = fs.Read(buffer, read, buffer.Length - read);
                if (n <= 0) break;
                read += n;
            }
            if (read == 0) return 0;

            var counts = new int[256];
            for (int i = 0; i < read; i++) counts[buffer[i]]++;
            double entropy = 0;
            for (int i = 0; i < 256; i++)
            {
                if (counts[i] == 0) continue;
                double p = (double)counts[i] / read;
                entropy -= p * Math.Log2(p);
            }
            return entropy;
        }
    }
}