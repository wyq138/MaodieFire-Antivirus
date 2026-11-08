// 内存 YARA 扫描：把 VAD 剥离出的匿名可执行内存落盘取证后，用现有 YARA 规则引擎真实扫描；
//   命中规则名直接回报（与文件扫描同一套规则库），用于无文件/反射加载/内存马检出。
//   dump 保留在 MemoryDumps（取证），单进程最多 8 个区域、每区 ≤4MB 上限。
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace FireAntivirus.Engine.Analyzers
{
    public sealed class MemoryYaraHit
    {
        public long BaseAddress { get; set; }
        public long Size { get; set; }
        public int RegionScore { get; set; }
        public List<string> Rules { get; set; } = new List<string>();
        public string DumpPath { get; set; } = "";
    }

    public sealed class MemoryYaraResult
    {
        public int Pid { get; set; }
        public string ProcessName { get; set; } = "";
        public List<MemoryYaraHit> Hits { get; set; } = new List<MemoryYaraHit>();
        public int ScannedRegions { get; set; }
        public string Error { get; set; } = "";
    }

    public static class MemoryYaraScanner
    {
        public static bool Enabled { get; set; } = true;
        public static int MinRegionScore { get; set; } = 60;
        public static int MaxRegionsPerProcess { get; set; } = 8;

        public static MemoryYaraResult ScanProcess(int pid)
        {
            var result = new MemoryYaraResult { Pid = pid };
            if (!Enabled || pid <= 0) return result;

            try
            {
                var vad = MemoryVadScanner.ScanProcess(pid);
                result.ProcessName = vad.ProcessName;
                result.Error = vad.Error;

                var candidates = vad.Findings
                    .Where(f => f.Score >= MinRegionScore)
                    .OrderByDescending(f => f.Score)
                    .Take(MaxRegionsPerProcess)
                    .ToList();

                foreach (var region in candidates)
                {
                    result.ScannedRegions++;
                    if (!MemoryVadScanner.DumpRegion(pid, region.BaseAddress, region.Size,
                            out string dumpPath, out string dumpError))
                    {
                        continue;
                    }

                    List<string> rules;
                    try { rules = YaraRuleEngine.ScanFile(dumpPath) ?? new List<string>(); }
                    catch { rules = new List<string>(); }

                    if (rules.Count > 0)
                    {
                        result.Hits.Add(new MemoryYaraHit
                        {
                            BaseAddress = region.BaseAddress,
                            Size = region.Size,
                            RegionScore = region.Score,
                            Rules = rules.Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
                            DumpPath = dumpPath
                        });
                    }
                }

                if (result.Hits.Count > 0)
                {
                    FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                        $"[内存YARA] PID {pid} {result.ProcessName}: {result.Hits.Count} 个区域命中 " +
                        string.Join(",", result.Hits.SelectMany(h => h.Rules).Distinct().Take(6)));
                }
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
            }
            return result;
        }
    }
}