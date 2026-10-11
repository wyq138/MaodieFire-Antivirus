using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using FireAntivirus.Common;

namespace FireAntivirus.Engine.Analyzers
{
    /// <summary>
    /// 提权链检测：分析进程命令行/文件内容中的权限提升证据。
    /// 提权是多数攻击的第二步——获得初始访问后立即提权。
    /// 证据链：UAC 绕过 + Token 操纵 + 服务创建 + 已知提权工具。
    /// </summary>
    public sealed class PrivilegeEscalationAnalyzer
    {
        // UAC 绕过技术
        private static readonly string[] UacBypassPatterns =
        {
            "fodhelper.exe", "computerdefaults.exe", "sdclt.exe", "eventvwr.exe",
            "slui.exe", "AppInfo", "autoelevate", "CMSTPLUA", "WSReset.exe",
            "consent.exe", "winver.exe", "bypass", "uac"
        };

        // Token 操纵
        private static readonly string[] TokenManipulationApis =
        {
            "OpenProcessToken", "DuplicateToken", "DuplicateTokenEx",
            "SetTokenInformation", "AdjustTokenPrivileges", "GetTokenInformation",
            "ImpersonateLoggedOnUser", "CreateProcessAsUser",
            "NtSetInformationProcess", "ZwSetInformationProcess",
            "SeBackupPrivilege", "SeDebugPrivilege", "SeTakeOwnershipPrivilege",
            "SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege"
        };

        // 服务创建/劫持
        private static readonly string[] ServiceAbusePatterns =
        {
            "CreateService", "OpenSCManager", "StartService", "ChangeServiceConfig",
            "sc.exe create", "sc config", "schtasks /create", "schtasks /change",
            "New-Service", "Set-Service", "reg add HKLM\\SYSTEM\\CurrentControlSet\\Services"
        };

        // 已知提权工具/漏洞利用名
        private static readonly string[] KnownElevationTools =
        {
            "juicy", "potato", "rotten", "sweet", "lonely", "muscle",
            "PrintSpoofer", "SharpUp", "PowerUp", "BeRoot", "WinPEAS",
            "Seatbelt", "Sherlock", "Watson", "MS16-", "MS17-", "CVE-"
        };

        // 命名管道/模拟
        private static readonly string[] NamedPipePatterns =
        {
            @"\\.\pipe\", "CreateNamedPipe", "ConnectNamedPipe",
            "impersonate", "ImpersonateNamedPipeClient",
            "RpcImpersonateClient", "CoImpersonateClient"
        };

        public sealed class PrivEscEvidence
        {
            public bool HasUacBypass;               // UAC 绕过
            public bool HasTokenManipulation;        // Token 操纵
            public bool HasServiceAbuse;             // 服务滥用
            public bool HasKnownTool;               // 已知提权工具
            public bool HasPipeImpersonation;        // 管道模拟
            public int ChainCount;                   // 独立证据数 0..5
            public double Strength;                  // 证据强度 0..1
            public string Notes = "";
        }

        public PrivEscEvidence Analyze(string content)
        {
            var ev = new PrivEscEvidence();
            if (string.IsNullOrWhiteSpace(content)) return ev;

            try
            {
                ev.HasUacBypass = UacBypassPatterns.Any(p => content.Contains(p, StringComparison.OrdinalIgnoreCase));
                ev.HasTokenManipulation = TokenManipulationApis.Any(a => content.Contains(a, StringComparison.OrdinalIgnoreCase));
                ev.HasServiceAbuse = ServiceAbusePatterns.Any(s => content.Contains(s, StringComparison.OrdinalIgnoreCase));
                ev.HasKnownTool = KnownElevationTools.Any(t => content.Contains(t, StringComparison.OrdinalIgnoreCase));
                ev.HasPipeImpersonation = NamedPipePatterns.Any(p => content.Contains(p, StringComparison.OrdinalIgnoreCase));

                ev.ChainCount = (ev.HasUacBypass ? 1 : 0) + (ev.HasTokenManipulation ? 1 : 0) +
                                (ev.HasServiceAbuse ? 1 : 0) + (ev.HasKnownTool ? 1 : 0) +
                                (ev.HasPipeImpersonation ? 1 : 0);

                if (ev.ChainCount >= 4) { ev.Strength = 0.80; ev.Notes = "提权证据链完整（UAC+Token+服务+工具+管道）"; }
                else if (ev.ChainCount >= 3) { ev.Strength = 0.50; ev.Notes = "提权证据部分匹配"; }
                else if (ev.ChainCount >= 2) { ev.Strength = 0.20; ev.Notes = "提权初始线索"; }
            }
            catch (Exception ex)
            {
                LogHelper.Log(LogHelper.LogLevel.Warning, "PrivilegeEscalationAnalyzer 失败", ex.Message);
            }
            return ev;
        }
    }
}