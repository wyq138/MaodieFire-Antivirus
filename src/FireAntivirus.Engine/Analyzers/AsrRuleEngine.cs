// ASR（Attack Surface Reduction）规则集 —— 对齐 Microsoft Defender ASR 的核心阻断项：
//   Office 子进程、编码/下载脚本、凭据转储、LOLBin 远程载荷、WMI 持久化、mshta/rundll32 无文件、
//   可移动盘执行、PsExec 风格服务、脚本宿主落地可执行内容。
//   引擎输入 = 进程血缘（祖先链）+ 命令行；命中即真实动作（阻断 = 链级终止，否则告警）。
//   与 LOLBins 链规则互补：LOLBins 看"链路 + 命令行"，ASR 看"单点策略 + 父链上下文"。
using System;
using System.Collections.Generic;
using System.Linq;

namespace FireAntivirus.Engine.Analyzers
{
    public sealed class AsrHit
    {
        public bool Hit { get; set; }
        public string RuleId { get; set; } = "";
        public string Name { get; set; } = "";
        public string Technique { get; set; } = "";
        public string Severity { get; set; } = "High";
        public int Score { get; set; }
        public bool Block { get; set; }
        public string Detail { get; set; } = "";
    }

    public static class AsrRuleEngine
    {
        public static bool Enabled { get; set; } = true;
        public static bool BlockEnabled { get; set; } = true;

        private sealed class AsrRule
        {
            public string Id { get; set; }
            public string Name { get; set; }
            public string Technique { get; set; }
            public string Severity { get; set; }
            public int Score { get; set; }
            public bool Block { get; set; }
            public string[] Children { get; set; } = Array.Empty<string>();
            public string[] Parents { get; set; } = Array.Empty<string>();
            public string[] CmdMarkers { get; set; } = Array.Empty<string>();
            public bool RequireCmd { get; set; }
        }

        private static readonly List<AsrRule> Rules = new List<AsrRule>
        {
            new AsrRule { Id = "ASR-OFFICE-CHILD", Name = "阻止 Office 应用创建子进程", Technique = "T1566/T1204",
                Severity = "Critical", Score = 90, Block = true,
                Parents = new[] { "winword", "excel", "powerpnt", "outlook", "wps", "et", "wpp" },
                Children = new[] { "cmd", "powershell", "pwsh", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "certutil", "bitsadmin" } },

            new AsrRule { Id = "ASR-SCRIPT-ENCODED", Name = "阻止编码/隐藏 PowerShell 执行", Technique = "T1059.001/T1027",
                Severity = "Critical", Score = 88, Block = true, RequireCmd = true,
                Children = new[] { "powershell", "pwsh" },
                CmdMarkers = new[] { "-enc ", "-encodedcommand", "-windowstyle hidden", "-w hidden", "-nop -w hidden" } },

            new AsrRule { Id = "ASR-SCRIPT-DOWNLOAD", Name = "阻止脚本下载并执行", Technique = "T1105/T1059",
                Severity = "Critical", Score = 86, Block = true, RequireCmd = true,
                Children = new[] { "powershell", "pwsh" },
                CmdMarkers = new[] { "downloadstring", "downloadfile", "invoke-webrequest", "start-bitstransfer", "iex(", "iex ", "invoke-expression" } },

            new AsrRule { Id = "ASR-CREDENTIAL-DUMP", Name = "阻止凭据转储工具", Technique = "T1003.001",
                Severity = "Critical", Score = 95, Block = true, RequireCmd = true,
                Children = new[] { "procdump", "procdump64", "rundll32" },
                CmdMarkers = new[] { "lsass", "comsvcs.dll minidump", "minidump", "sekurlsa", "logonpasswords" } },

            new AsrRule { Id = "ASR-LOLBIN-REMOTE", Name = "阻止 LOLBin 加载远程载荷", Technique = "T1218",
                Severity = "Critical", Score = 88, Block = true, RequireCmd = true,
                Children = new[] { "certutil", "bitsadmin", "mshta", "regsvr32", "rundll32", "installutil", "msbuild" },
                CmdMarkers = new[] { "http://", "https://", "ftp://", "urlcache", "-decode", "scrobj.dll", "/i:http",
                                     "javascript:", "vbscript:", "/transfer", "-urlcache" } },

            new AsrRule { Id = "ASR-WMI-PERSIST", Name = "阻止 WMI 创建进程/事件订阅", Technique = "T1047/T1546.003",
                Severity = "High", Score = 78, Block = true, RequireCmd = true,
                Children = new[] { "wmic", "powershell", "pwsh" },
                CmdMarkers = new[] { "process call create", "__eventfilter", "commandlineeventconsumer", "/node:" } },

            new AsrRule { Id = "ASR-PSEXEC-SERVICE", Name = "阻止 PsExec 风格远程服务执行", Technique = "T1569.002",
                Severity = "High", Score = 80, Block = true, RequireCmd = true,
                Children = new[] { "psexec", "psexec64", "paexec", "smbexec" },
                CmdMarkers = new[] { "\\\\", "-s ", "-accepteula" } },

            new AsrRule { Id = "ASR-SCRIPT-DROP-EXE", Name = "阻止脚本宿主落地可执行内容", Technique = "T1027/T1105",
                Severity = "High", Score = 75, Block = false, RequireCmd = true,
                Children = new[] { "certutil", "bitsadmin", "expand", "extrac32" },
                CmdMarkers = new[] { ".exe", ".dll", ".scr", "-f -decode", "-decodehex" } },

            new AsrRule { Id = "ASR-USB-EXEC", Name = "阻止从可移动/网络路径执行", Technique = "T1091/T1059",
                Severity = "Medium", Score = 60, Block = false,
                Children = new[] { "*" },
                CmdMarkers = new string[0] },

            new AsrRule { Id = "ASR-LNK-SPAWN", Name = "阻止未签名快捷方式拉起解释器", Technique = "T1204.001",
                Severity = "High", Score = 72, Block = false,
                Parents = new[] { "explorer" },
                Children = new[] { "cmd", "powershell", "wscript", "mshta" } }
        };

        /// <summary>对单个进程做 ASR 评估（pid + 命令行 + 血缘祖先由调用方传入）。</summary>
        public static AsrHit Evaluate(string processName, string commandLine, IReadOnlyList<ProcessNode> ancestors)
        {
            var hit = new AsrHit();
            if (!Enabled || string.IsNullOrEmpty(processName)) return hit;

            string cmd = (commandLine ?? "").ToLowerInvariant();
            var lines = ancestors ?? Array.Empty<ProcessNode>();

            foreach (var rule in Rules)
            {
                bool childMatch = rule.Children.Any(c => NameMatches(processName, c));
                if (!childMatch) continue;

                if (rule.Parents.Length > 0)
                {
                    bool parentMatch = rule.Parents.Any(p => lines.Any(a => NameMatches(a.Name, p)));
                    if (!parentMatch) continue;
                }

                if (rule.RequireCmd && !rule.CmdMarkers.Any(m => cmd.Contains(m))) continue;

                // 可移动盘/网络共享执行：按可执行扩展名 + 路径特征判定
                if (rule.Id == "ASR-USB-EXEC")
                {
                    string path = lines.FirstOrDefault(a => a.Pid > 0)?.Path ?? "";
                    bool removable = path.StartsWith(@"\\?\Volume", StringComparison.OrdinalIgnoreCase)
                                     || System.Text.RegularExpressions.Regex.IsMatch(path, @"^[D-Zd-z]:\\", System.Text.RegularExpressions.RegexOptions.None)
                                     || path.StartsWith(@"\\", StringComparison.Ordinal);
                    bool executable = path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
                                      || path.EndsWith(".scr", StringComparison.OrdinalIgnoreCase)
                                      || path.EndsWith(".bat", StringComparison.OrdinalIgnoreCase)
                                      || path.EndsWith(".cmd", StringComparison.OrdinalIgnoreCase)
                                      || path.EndsWith(".ps1", StringComparison.OrdinalIgnoreCase);
                    if (!removable || !executable) continue;
                }

                hit.Hit = true;
                hit.RuleId = rule.Id;
                hit.Name = rule.Name;
                hit.Technique = rule.Technique;
                hit.Severity = rule.Severity;
                hit.Score = rule.Score;
                hit.Block = rule.Block && BlockEnabled;
                hit.Detail = $"{rule.Name}（{rule.Id} / {rule.Technique}）: {processName} {Trim(cmd)}";
                return hit;
            }
            return hit;
        }

        private static string Trim(string value) => value.Length <= 200 ? value : value.Substring(0, 200) + "...";

        private static bool NameMatches(string name, string pattern)
        {
            if (string.IsNullOrEmpty(name) || string.IsNullOrEmpty(pattern)) return false;
            if (pattern == "*") return true;
            string baseName = System.IO.Path.GetFileNameWithoutExtension(name);
            string patternBase = System.IO.Path.GetFileNameWithoutExtension(pattern);
            return string.Equals(baseName, patternBase, StringComparison.OrdinalIgnoreCase);
        }
    }
}