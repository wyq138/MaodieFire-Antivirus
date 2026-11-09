// EDR 检测时间线：所有检测点（引擎/实时防护/句柄审计/血缘/熵时序/VAD/污点/ASR）统一写 JSONL，
//   支持按时间窗口查询、严重度/来源/技术统计，供调查视图与取证使用；16MB 滚动、保留 5 份。
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;

namespace FireAntivirus.Engine.Analyzers
{
    public sealed class TimelineEvent
    {
        public DateTime Utc { get; set; }
        public string Source { get; set; } = "";
        public string Category { get; set; } = "";
        public string Severity { get; set; } = "";
        public string Technique { get; set; } = "";
        public int Pid { get; set; }
        public string Process { get; set; } = "";
        public string Target { get; set; } = "";
        public string Detail { get; set; } = "";
    }

    public sealed class TimelineStats
    {
        public DateTime FromUtc { get; set; }
        public DateTime ToUtc { get; set; }
        public int Total { get; set; }
        public Dictionary<string, int> BySeverity { get; set; } = new Dictionary<string, int>();
        public Dictionary<string, int> BySource { get; set; } = new Dictionary<string, int>();
        public Dictionary<string, int> ByTechnique { get; set; } = new Dictionary<string, int>();
    }

    public static class DetectionTimeline
    {
        public static bool Enabled { get; set; } = true;
        public static string DirectoryPath { get; set; } = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "FireAntivirus", "Logs", "Timeline");
        public static long MaxFileBytes { get; set; } = 16L * 1024 * 1024;
        public static int KeepFiles { get; set; } = 5;

        private static readonly object _lock = new object();
        private static long _lastSizeCheck;

        public static string CurrentFile => Path.Combine(DirectoryPath,
            $"timeline_{DateTime.UtcNow:yyyyMMdd}.jsonl");

        public static void Record(string source, string category, string severity, string technique,
            int pid, string process, string target, string detail)
        {
            if (!Enabled) return;
            Record(new TimelineEvent
            {
                Utc = DateTime.UtcNow,
                Source = source ?? "",
                Category = category ?? "",
                Severity = severity ?? "",
                Technique = technique ?? "",
                Pid = pid,
                Process = process ?? "",
                Target = target ?? "",
                Detail = detail ?? ""
            });
        }

        public static void Record(TimelineEvent evt)
        {
            if (!Enabled || evt == null) return;
            try
            {
                lock (_lock)
                {
                    Directory.CreateDirectory(DirectoryPath);
                    evt.Utc = evt.Utc == default ? DateTime.UtcNow : evt.Utc;
                    File.AppendAllText(CurrentFile, JsonSerializer.Serialize(evt) + Environment.NewLine, Encoding.UTF8);
                    RotateIfNeeded();
                }
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                    "EDR 时间线写入失败: " + ex.Message);
            }
        }

        public static List<TimelineEvent> Query(DateTime? fromUtc = null, DateTime? toUtc = null, int max = 500)
        {
            var result = new List<TimelineEvent>();
            try
            {
                if (!Directory.Exists(DirectoryPath)) return result;
                DateTime from = fromUtc ?? DateTime.UtcNow.AddHours(-24);
                DateTime to = toUtc ?? DateTime.UtcNow;

                foreach (var file in Directory.EnumerateFiles(DirectoryPath, "timeline_*.jsonl")
                                              .OrderByDescending(f => f))
                {
                    foreach (var line in File.ReadLines(file))
                    {
                        if (string.IsNullOrWhiteSpace(line)) continue;
                        TimelineEvent evt;
                        try { evt = JsonSerializer.Deserialize<TimelineEvent>(line,
                            new JsonSerializerOptions { PropertyNameCaseInsensitive = true }); }
                        catch { continue; }
                        if (evt == null || evt.Utc < from || evt.Utc > to) continue;
                        result.Add(evt);
                    }
                    if (result.Count >= max * 4) break;
                }
                return result.OrderByDescending(e => e.Utc).Take(max).ToList();
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                    "EDR 时间线查询失败: " + ex.Message);
                return result;
            }
        }

        public static TimelineStats Stats(TimeSpan window)
        {
            var to = DateTime.UtcNow;
            var from = to - window;
            var events = Query(from, to, 5000);
            var stats = new TimelineStats { FromUtc = from, ToUtc = to, Total = events.Count };

            stats.BySeverity = events.GroupBy(e => string.IsNullOrEmpty(e.Severity) ? "Unknown" : e.Severity)
                                     .ToDictionary(g => g.Key, g => g.Count());
            stats.BySource = events.GroupBy(e => string.IsNullOrEmpty(e.Source) ? "Unknown" : e.Source)
                                   .ToDictionary(g => g.Key, g => g.Count());
            stats.ByTechnique = events.Where(e => !string.IsNullOrEmpty(e.Technique))
                                      .GroupBy(e => e.Technique)
                                      .ToDictionary(g => g.Key, g => g.Count());
            return stats;
        }

        private static void RotateIfNeeded()
        {
            try
            {
                string current = CurrentFile;
                if (!File.Exists(current)) return;
                long size = new FileInfo(current).Length;
                if (size < MaxFileBytes) return;

                string rotated = Path.Combine(DirectoryPath,
                    $"timeline_{DateTime.UtcNow:yyyyMMdd_HHmmss}.jsonl");
                File.Move(current, rotated, overwrite: true);

                foreach (var old in Directory.EnumerateFiles(DirectoryPath, "timeline_*.jsonl")
                                              .OrderByDescending(f => f).Skip(KeepFiles).ToList())
                    try { File.Delete(old); } catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
            }
            catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
        }

        public static string Export(DateTime? fromUtc, DateTime? toUtc, string outputPath)
        {
            try
            {
                var events = Query(fromUtc, toUtc, 10000);
                Directory.CreateDirectory(Path.GetDirectoryName(outputPath) ?? ".");
                File.WriteAllText(outputPath, JsonSerializer.Serialize(events,
                    new JsonSerializerOptions { WriteIndented = true }), Encoding.UTF8);
                return outputPath;
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                    "EDR 时间线导出失败: " + ex.Message);
                return null;
            }
        }
    }
}