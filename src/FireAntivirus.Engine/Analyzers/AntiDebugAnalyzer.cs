using System;
using System.Collections.Generic;
using System.Linq;
using FireAntivirus.Common;
using FireAntivirus.Engine.Strings;

namespace FireAntivirus.Engine.Analyzers
{
    /// <summary>
    /// 反调试/反虚拟机检测：分析 PE 导入表或文件字符串中是否存在反分析技术。
    /// 恶意软件常通过这些手段规避沙箱和调试器，正常软件极少使用。
    /// 证据链：至少 3 种不同类别反调试手法才构成显著信号。
    /// </summary>
    public sealed class AntiDebugAnalyzer
    {
        // 反调试 API（真实导入表匹配）
        private static readonly string[] AntiDebugApis =
        {
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
            "NtSetInformationThread", "OutputDebugString", "GetThreadContext",
            "ZwQueryInformationProcess", "NtClose", "NtRaiseException",
            "RtlAdjustPrivilege", "RtlSetProcessIsCritical"
        };

        // 反虚拟机检测
        private static readonly string[] AntiVmPatterns =
        {
            "vbox", "vmware", "virtualbox", "qemu", "xen", "hyper-v",
            "VBoxGuest", "VBoxMouse", "VBoxVideo", "VBoxService",
            "VMAdditions", "VMwareTools", "VMwareUser", "VMwareTray",
            "vmtoolsd", "vmmouse", "vm3dmp", "vmscsi", "vmsrvc",
            "hgfs", "prl_", "Parallels", "VirtIO", "Virtio"
        };

        // 反沙箱（时间检测/延迟执行）
        private static readonly string[] AntiSandboxPatterns =
        {
            "Sleep", "NtDelayExecution", "GetTickCount", "QueryPerformanceCounter",
            "timeGetTime", "GetSystemTime", "GetLocalTime", "NtQuerySystemTime",
            "rdtsc", "__rdtsc", "CPUID"
        };

        // 调试器字符串检测
        private static readonly string[] DebuggerStrings =
        {
            "ollydbg", "x64dbg", "x32dbg", "idag", "idaw", "idaq", "windbg",
            "immunity", "ProcessHacker", "ProcessExplorer", "Cheat Engine",
            "debugger", "debug", "anti-debug", "antidebug"
        };

        public sealed class AntiDebugEvidence
        {
            public bool HasDebugApi;                // 反调试 API
            public bool HasAntiVm;                   // 反虚拟机
            public bool HasAntiSandbox;              // 反沙箱
            public bool HasDebuggerString;           // 调试器字符串检测
            public int CategoryCount;                // 独立类别数 0..4
            public double Strength;                  // 证据强度 0..1
            public string Notes = "";
        }

        /// <summary>
        /// 分析文本内容中的反调试/反 VM 证据。
        /// </summary>
        public AntiDebugEvidence Analyze(string content)
        {
            var ev = new AntiDebugEvidence();
            if (string.IsNullOrWhiteSpace(content)) return ev;

            try
            {
                ev.HasDebugApi = AntiDebugApis.Any(a => content.Contains(a, StringComparison.OrdinalIgnoreCase));
                ev.HasAntiVm = AntiVmPatterns.Any(p => content.Contains(p, StringComparison.OrdinalIgnoreCase));
                ev.HasAntiSandbox = AntiSandboxPatterns.Any(p => content.Contains(p, StringComparison.OrdinalIgnoreCase));
                ev.HasDebuggerString = DebuggerStrings.Any(d => content.Contains(d, StringComparison.OrdinalIgnoreCase));

                ev.CategoryCount = (ev.HasDebugApi ? 1 : 0) + (ev.HasAntiVm ? 1 : 0) +
                                   (ev.HasAntiSandbox ? 1 : 0) + (ev.HasDebuggerString ? 1 : 0);

                // 至少 3 类不同反分析手段才构成显著信号
                if (ev.CategoryCount >= 4) { ev.Strength = 0.75; ev.Notes = "全面反分析保护（API+VM+沙箱+字符串）"; }
                else if (ev.CategoryCount >= 3) { ev.Strength = 0.50; ev.Notes = "多重反分析保护"; }
                else if (ev.CategoryCount >= 2) { ev.Strength = 0.20; ev.Notes = "部分反分析特征"; }
            }
            catch (Exception ex)
            {
                LogHelper.Log(LogHelper.LogLevel.Warning, "AntiDebugAnalyzer 失败", ex.Message);
            }
            return ev;
        }
    }
}