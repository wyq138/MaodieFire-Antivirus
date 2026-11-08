// 凭据访问防护（照搬 XIGUASecurity 10x credential_access.rs，C# 实现）：
//   1) 命令行特征检测（MITRE ATT&CK）：
//      T1003.001 LSASS 内存转储 / T1003.002 SAM 导出 / T1003.003 NTDS.dit
//      T1555.004 凭据管理器枚举 / T1552.004 DPAPI 主密钥 / T1110 暴力破解 / Mimikatz 特征
//   2) LSASS 句柄级检测：委托 HandleAccessAudit（全系统句柄表枚举 + 访问掩码解码），
//      找出"非 lsass 进程以 VM_READ/VM_WRITE/CREATE_THREAD 打开 LSASS"——凭据窃取前兆。
// 两条链路共享 10 分钟去重窗口，避免周期扫描反复弹窗。
using System;
using System.Collections.Generic;
using System.Linq;

namespace FireAntivirus.Engine.Analyzers
{
    public sealed class CredentialDetection
    {
        public bool Detected { get; set; }
        public string Technique { get; set; }
        public string Detail { get; set; }
        public string Severity { get; set; } = "High";
        public int Pid { get; set; }
        public string ProcessName { get; set; }
    }

    public static class CredentialAccessMonitor
    {
        /// <summary>设置开关（关闭后命令行检测与 LSASS 句柄审计均不再产生结果）。</summary>
        public static bool Enabled { get; set; } = true;

        private sealed class CredRule
        {
            public string Technique;
            public string Name;
            public string Severity;
            public string[] Keys;
        }

        private static readonly List<CredRule> Rules = new List<CredRule>
        {
            new CredRule { Technique = "T1003.001", Name = "LSASS 内存转储", Severity = "Critical",
                Keys = new[] { "procdump -ma lsass", "procdump64 -ma lsass", "comsvcs.dll minidump", "out-minidump", "lsass.dmp", "rundll32 comsvcs" } },
            new CredRule { Technique = "T1003.002", Name = "SAM 注册表导出", Severity = "High",
                Keys = new[] { "reg save hklm\\sam", "reg save hklm\\system", "reg save hklm\\security", "reg export hklm\\sam" } },
            new CredRule { Technique = "T1003.003", Name = "NTDS.dit 访问", Severity = "Critical",
                Keys = new[] { "ntds.dit", "ntdsutil", "esentutl /p" } },
            new CredRule { Technique = "T1555.004", Name = "Windows 凭据管理器枚举", Severity = "High",
                Keys = new[] { "cmdkey /list", "vaultcmd", "vaultcli" } },
            new CredRule { Technique = "T1552.004", Name = "DPAPI 主密钥导出", Severity = "High",
                Keys = new[] { "dpapi::masterkey", "protect\\credhist", "\\microsoft\\protect\\" } },
            new CredRule { Technique = "T1110", Name = "暴力破解工具", Severity = "Medium",
                Keys = new[] { "hydra", "medusa", "brutespray", "ncrack", "crowbar" } },
            new CredRule { Technique = "T1003", Name = "Mimikatz/凭据窃取特征", Severity = "Critical",
                Keys = new[] { "sekurlsa", "logonpasswords", "lsadump", "mimikatz", "privilege::debug" } },
        };

        // 去重：同技术同进程 10 分钟内只报一次
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

        /// <summary>命令行特征分析（进程创建事件驱动）。</summary>
        public static CredentialDetection Analyze(string processName, int pid, string commandLine)
        {
            var result = new CredentialDetection { Pid = pid, ProcessName = processName };
            if (!Enabled) return result;
            try
            {
                string target = ((processName ?? "") + " " + (commandLine ?? "")).ToLowerInvariant();
                foreach (var rule in Rules)
                {
                    foreach (var key in rule.Keys)
                    {
                        if (!target.Contains(key.ToLowerInvariant())) continue;
                        string fingerprint = rule.Technique + "|" + (processName ?? "");
                        if (!ShouldReport(fingerprint)) continue;

                        result.Detected = true;
                        result.Technique = rule.Technique;
                        result.Severity = rule.Severity;
                        result.Detail = $"{rule.Name}（{rule.Technique}）: {processName} (PID {pid}) · {Trim(commandLine ?? "")}";
                        return result;
                    }
                }
            }
            catch { }
            return result;
        }

        /// <summary>
        /// LSASS 句柄级检测（委托全量句柄审计，含访问掩码解码与风险分级）。
        /// 权限不足时审计报告置 AccessDenied 并返回空列表（如实降级，不伪造）。
        /// </summary>
        public static List<CredentialDetection> ScanLsassHandles()
        {
            var detections = new List<CredentialDetection>();
            if (!Enabled) return detections;

            try
            {
                foreach (var finding in HandleAccessAudit.ScanLsass())
                {
                    if (!ShouldReport("lsass-handle|" + finding.OwnerPid)) continue;

                    detections.Add(new CredentialDetection
                    {
                        Detected = true,
                        Technique = finding.Technique,
                        Severity = finding.Risk >= HandleRisk.Critical ? "Critical" : "High",
                        Pid = finding.OwnerPid,
                        ProcessName = finding.OwnerName,
                        Detail = finding.Detail + $"（访问掩码 0x{finding.AccessMask:X8}）"
                    });
                }
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                    "LSASS 句柄审计失败（可能权限不足）: " + ex.Message);
            }
            return detections;
        }

        private static string Trim(string s) => s.Length <= 240 ? s : s.Substring(0, 240) + "...";
    }
}