// 沙箱反沙箱对抗（Anti-Evasion / Anti-Sandbox）：
//   恶意样本检测到沙箱/虚拟机/调试器时会"装死"或改变行为，导致沙箱行为判定失效（假阴性）。
//   本模块做三件事（全部真实字节级特征，非占位）：
//   1) 静态识别样本里的沙箱/虚拟机/调试器/硬件指纹/延时规避/环境枚举痕迹并加权评分；
//   2) 判定运行时策略：常规沙箱 / 加固沙箱（隐藏 Sandboxie 痕迹、保护沙箱进程、独立用户配置单元）；
//   3) 把"反分析规避"本身作为一条 IOA 证据交给沙箱评分（T1497.001），避免样本装死就白跑。
// 注：不把未知样本放到真实主机上裸跑——那是真感染；强反沙箱样本仍进加固沙箱，结果标注可信度。
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace FireAntivirus.Engine.Sandbox
{
    public enum SandboxEvasionLevel { None = 0, Weak = 1, Strong = 2 }

    public enum SandboxRunDecision
    {
        NormalSandbox = 0,
        HardenedSandbox = 1
    }

    public sealed class SandboxEvasionFinding
    {
        public string Category { get; set; }
        public string Marker { get; set; }
        public int Weight { get; set; }
    }

    public sealed class SandboxEvasionResult
    {
        public string FilePath { get; set; }
        public int Score { get; set; }
        public SandboxEvasionLevel Level { get; set; }
        public SandboxRunDecision Decision { get; set; }
        public List<SandboxEvasionFinding> Findings { get; set; } = new List<SandboxEvasionFinding>();
        public string Summary { get; set; }
    }

    public static class SandboxEvasionGuard
    {
        /// <summary>设置开关（关闭后不识别反沙箱特征、不做加固配置）。</summary>
        public static bool Enabled { get; set; } = true;

        private const int MaxScanBytes = 4 * 1024 * 1024;

        private sealed class MarkerGroup
        {
            public string Category;
            public int Weight;          // 组内命中一次的基础权重
            public int MaxHits;         // 组内最多计分的命中数（防同一组刷分）
            public string[] Markers;
        }

        // 特征库：字符串以 ASCII/Latin1 方式在文件头 4MB 内匹配（PE 字符串/导入名/资源/脚本均覆盖）
        private static readonly MarkerGroup[] Groups =
        {
            new MarkerGroup { Category = "Sandboxie 痕迹", Weight = 35, MaxHits = 2,
                Markers = new[] { "sbiedll", "sandboxie", "sbieCtrl", "sbierpcss", "sandboxiedcomlaunch", "sbieini", "autosandbox" } },
            new MarkerGroup { Category = "虚拟机痕迹", Weight = 30, MaxHits = 2,
                Markers = new[] { "vmware", "vbox", "virtualbox", "vmtoolsd", "vmsrvc", "vmusrvc", "qemu", "xen", "hyper-v", "parallels", "prl_", "vboxservice" } },
            new MarkerGroup { Category = "反调试 API", Weight = 25, MaxHits = 2,
                Markers = new[] { "isdebuggerpresent", "checkremotedebugger", "ntqueryinformationprocess", "processdebugport", "beingdebugged", "ntglobalflag", "outputdebugstring", "debugactiveprocess" } },
            new MarkerGroup { Category = "时间差/延时规避", Weight = 20, MaxHits = 2,
                Markers = new[] { "gettickcount", "queryperformancecounter", "timegettime", "rdtsc", "cpuid", "gettickcount64" } },
            new MarkerGroup { Category = "硬件指纹枚举", Weight = 25, MaxHits = 2,
                Markers = new[] { "win32_diskdrive", "win32_bios", "win32_computersystem", "win32_baseboard", "serialnumber", "macaddress", "volumeserialnumber", "idvd" } },
            new MarkerGroup { Category = "环境枚举", Weight = 15, MaxHits = 2,
                Markers = new[] { "getcomputername", "getusername", "wtsquerysessioninformation", "getsystemmetrics", "enumwindows", "findwindow", "enumprocesses" } },
            new MarkerGroup { Category = "沙箱主机名/用户名", Weight = 30, MaxHits = 2,
                Markers = new[] { "sandbox", "malware", "cuckoo", "analysis", "virus", "sample", "testpc", "john", "wdagutilityaccount" } },
            new MarkerGroup { Category = "分析工具痕迹", Weight = 35, MaxHits = 2,
                Markers = new[] { "x64dbg", "ollydbg", "windbg", "ida64", "idaq", "procmon", "processhacker", "wireshark", "fiddler", "cheatengine" } }
        };

        /// <summary>静态分析：返回反沙箱评分与运行时策略。文件不可读时返回 None（不臆断）。</summary>
        public static SandboxEvasionResult Analyze(string filePath)
        {
            var result = new SandboxEvasionResult { FilePath = filePath };
            if (!Enabled || string.IsNullOrEmpty(filePath) || !File.Exists(filePath)) return result;

            try
            {
                byte[] data;
                using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    int len = (int)Math.Min(fs.Length, MaxScanBytes);
                    data = new byte[len];
                    int read = 0;
                    while (read < len)
                    {
                        int n = fs.Read(data, read, len - read);
                        if (n <= 0) break;
                        read += n;
                    }
                    if (read < len) Array.Resize(ref data, read);
                }
                if (data.Length == 0) return result;

                string text = Encoding.Latin1.GetString(data).ToLowerInvariant();

                int score = 0;
                foreach (var group in Groups)
                {
                    int hits = 0;
                    foreach (var marker in group.Markers)
                    {
                        if (hits >= group.MaxHits) break;
                        if (text.Contains(marker, StringComparison.Ordinal))
                        {
                            hits++;
                            result.Findings.Add(new SandboxEvasionFinding
                            {
                                Category = group.Category,
                                Marker = marker,
                                Weight = group.Weight
                            });
                        }
                    }
                    score += hits * group.Weight;
                }

                result.Score = Math.Min(100, score);
                result.Level = result.Score >= 60 ? SandboxEvasionLevel.Strong
                             : result.Score >= 25 ? SandboxEvasionLevel.Weak
                             : SandboxEvasionLevel.None;
                result.Decision = result.Level == SandboxEvasionLevel.None
                    ? SandboxRunDecision.NormalSandbox
                    : SandboxRunDecision.HardenedSandbox;

                result.Summary = result.Level == SandboxEvasionLevel.None
                    ? "未发现反沙箱/反虚拟机特征"
                    : $"检测到 {result.Findings.Count} 项反分析特征（评分 {result.Score}，{result.Level}）→ " +
                      (result.Decision == SandboxRunDecision.HardenedSandbox ? "启用加固沙箱" : "常规沙箱");

                if (result.Level != SandboxEvasionLevel.None)
                {
                    FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                        $"[SandboxEvasion] {Path.GetFileName(filePath)}: {result.Summary}");
                }
            }
            catch (Exception ex)
            {
                result.Summary = "反沙箱分析失败: " + ex.Message;
            }
            return result;
        }

        /// <summary>
        /// Sandboxie 加固配置（真实存在的 SbieIni 键）：
        ///   隐藏沙箱进程/窗口、保护沙箱进程、独立用户配置单元、禁用沙箱控制 UI 常驻。
        /// </summary>
        public static (string Key, string Value)[] HardeningSettings() => new[]
        {
            ("HideSbieProcesses", "y"),
            ("ProtectSbie", "y"),
            ("SeparateUserHive", "y"),
            ("UseSbieCtrl", "n"),
        };

        /// <summary>把加固配置写入 AUTOSandBox（同步，调用方应在后台线程执行）。</summary>
        public static void ApplyHardening(out string message)
        {
            message = "";
            try
            {
                SandboxProvisioner.ApplyExtraSettings(HardeningSettings());
                message = "沙箱加固配置已应用（隐藏/保护 Sandboxie、独立用户配置单元）";
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info, message);
            }
            catch (Exception ex)
            {
                message = "沙箱加固配置失败: " + ex.Message;
            }
        }

        /// <summary>把反沙箱命中转成沙箱行为证据（供 IoaRules 计分，T1497.001）。</summary>
        public static IEnumerable<string> ToBehaviorEvidence(SandboxEvasionResult result)
        {
            if (result == null || result.Level == SandboxEvasionLevel.None) yield break;
            foreach (var f in result.Findings.Take(4))
                yield return "evasion:" + f.Marker;
            yield return "evasion:sandbox-artifact";
        }
    }
}