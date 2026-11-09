// 防御规避检测（C# 实现）：
//   基于进程命令行/目标路径对 MITRE ATT&CK 防御规避技术做特征匹配并给出严重度：
//   T1490 删除卷影副本 / T1070.001 清除事件日志 / T1562.001 禁用 Defender /
//   T1562.006 AMSI 绕过 / T1562.009 SafeBoot 操纵 / T1564.001 隐藏文件属性 / T1027 编码混淆命令。
//   由实时防护的进程创建事件驱动（RTPPlus OnProcessCreated），命中经统一威胁链弹出处置窗口。
using System;
using System.Collections.Generic;
using System.Linq;

namespace FireAntivirus.Engine.Analyzers
{
    public sealed class EvasionDetection
    {
        public bool Detected { get; set; }
        public string Technique { get; set; }   // ATT&CK 编号
        public string Detail { get; set; }
        public string Severity { get; set; } = "High";
    }

    public static class DefenseEvasionMonitor
    {
        private sealed class EvasionRule
        {
            public string Technique;
            public string Name;
            public string Severity;
            public string[] Keys;
        }

        private static readonly List<EvasionRule> Rules = new List<EvasionRule>
        {
            new EvasionRule { Technique = "T1490", Name = "删除卷影副本（勒索前置）", Severity = "High",
                Keys = new[] { "vssadmin delete shadows", "wmic shadowcopy delete", "vssadmin.exe delete", "diskshadow" } },
            new EvasionRule { Technique = "T1490", Name = "禁用系统恢复", Severity = "High",
                Keys = new[] { "recoveryenabled no", "bcdedit /set {default} recoveryenabled no", "bcdedit /set bootstatuspolicy" } },
            new EvasionRule { Technique = "T1070.001", Name = "清除事件日志", Severity = "High",
                Keys = new[] { "wevtutil cl ", "wevtutil.exe cl", "cleareventlog", "clear-eventlog" } },
            new EvasionRule { Technique = "T1070.002", Name = "清除最近历史/使用痕迹", Severity = "Medium",
                Keys = new[] { "del /f /q %appdata%", "del /f /q %localappdata%", "rd /s /q %temp%", "erase /f /q" } },
            new EvasionRule { Technique = "T1562.001", Name = "禁用/篡改 Defender", Severity = "High",
                Keys = new[] { "disablerealtimemonitoring", "set-mppreference", "mpcmdrun -removedefinitions", "defender\\exclusions" } },
            new EvasionRule { Technique = "T1562.004", Name = "禁用防火墙", Severity = "Medium",
                Keys = new[] { "netsh advfirewall set allprofiles state off", "netsh firewall set opmode disable" } },
            new EvasionRule { Technique = "T1562.006", Name = "AMSI 绕过", Severity = "High",
                Keys = new[] { "amsiutils", "amsiinitfailed", "[ref].assembly.gettype", "amsi.dll" } },
            new EvasionRule { Technique = "T1562.009", Name = "SafeBoot 操纵", Severity = "Critical",
                Keys = new[] { "safeboot minimal", "safeboot network", "safebootalternateshell", "\\safeboot\\" } },
            new EvasionRule { Technique = "T1564.001", Name = "隐藏文件属性", Severity = "Medium",
                Keys = new[] { "attrib +h", "attrib +s +h", "attrib -r +s +h" } },
            new EvasionRule { Technique = "T1027", Name = "编码/混淆命令", Severity = "Medium",
                Keys = new[] { "-encodedcommand", "-enc ", "frombase64string", "base64 " } },
            new EvasionRule { Technique = "T1140", Name = "解码执行", Severity = "Medium",
                Keys = new[] { "certutil -decode", "certutil -urlcache", "bitsadmin /transfer" } },
            new EvasionRule { Technique = "T1218", Name = "LOLBin 代理执行", Severity = "Medium",
                Keys = new[] { "mshta javascript:", "regsvr32 /s /u /i:http", "rundll32 javascript:", "installutil /logfile=" } },
        };

        /// <summary>设置开关（关闭后不再产生任何检测结果）。</summary>
        public static bool Enabled { get; set; } = true;

        // 去重：同技术同进程 10 分钟内只报一次（旧实现 HashSet 永不清理，同名进程第二次起永远静默）
        private static readonly Dictionary<string, DateTime> Reported =
            new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        private static readonly object _reportLock = new object();

        private static bool ShouldReport(string fingerprint)
        {
            lock (_reportLock)
            {
                var now = DateTime.UtcNow;
                if (Reported.TryGetValue(fingerprint, out var last) && now - last < TimeSpan.FromMinutes(10))
                    return false;

                Reported[fingerprint] = now;
                if (Reported.Count > 5000)
                {
                    var cutoff = now - TimeSpan.FromMinutes(10);
                    foreach (var key in Reported.Where(kv => kv.Value < cutoff).Select(kv => kv.Key).ToList())
                        Reported.Remove(key);
                }
                return true;
            }
        }

        /// <summary>分析进程命令行/路径是否命中防御规避技术。</summary>
        public static EvasionDetection Analyze(string processName, int pid, string commandLine)
        {
            var result = new EvasionDetection();
            if (!Enabled) return result;
            try
            {
                string cmd = (commandLine ?? "").ToLowerInvariant();
                string name = (processName ?? "").ToLowerInvariant();
                string target = name + " " + cmd;

                foreach (var rule in Rules)
                {
                    foreach (var key in rule.Keys)
                    {
                        if (!target.Contains(key.ToLowerInvariant())) continue;

                        string fingerprint = rule.Technique + "|" + name;
                        if (!ShouldReport(fingerprint)) continue;

                        result.Detected = true;
                        result.Technique = rule.Technique;
                        result.Severity = rule.Severity;
                        result.Detail = $"{rule.Name}（{rule.Technique}）: {processName} (PID {pid}) · {Trim(cmd)}";
                        return result;
                    }
                }
            }
            catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
            return result;
        }

        private static string Trim(string s) => s.Length <= 240 ? s : s.Substring(0, 240) + "...";
    }
}