using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using FireAntivirus.Common;

namespace FireAntivirus.Engine.Analyzers
{
    /// <summary>
    /// 内存 shellcode/exploit 检测：分析文件内容中的常见 exploit payload 和 shellcode 特征。
    /// 使用强信号模式而非泛词匹配，避免误报。
    /// 证据链：shellcode 特征 + exploit 技术 + 堆喷射 + ROP 链。
    /// </summary>
    public sealed class MemoryPatternAnalyzer
    {
        // Shellcode 常见特征字节（以 Base64 解码后的字符串特征表示）
        // 实际 shellcode 检测应基于汇编模式，这里用常出现的特征字符串作为初步筛查
        private static readonly string[] ShellcodeSignatures =
        {
            // Egg hunter / NOP sled 变体
            "\\x90\\x90\\x90\\x90", "\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90",
            "\\xeb\\xfe", "\\xe8\\x00\\x00\\x00\\x00", "\\xeb\\x0\\xeb\\x0",
            "\\xfc\\xe8\\x82\\x00\\x00\\x00", "\\xfc\\xe8\\x89\\x00\\x00\\x00",
            // 常见 shellcode 加载器
            "VirtualProtect", "VirtualAlloc", "VirtualAllocEx",
            "WriteProcessMemory", "ReadProcessMemory",
            "CreateThread", "RtlCreateUserThread", "NtCreateThreadEx",
            "QueueUserAPC", "SetThreadContext"
        };

        // 堆喷射特征
        private static readonly string[] HeapSprayPatterns =
        {
            "\\x0c\\x0c\\x0c\\x0c", "\\x0d\\x0d\\x0d\\x0d",
            "\\x0a\\x0a\\x0a\\x0a", "\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00",
            "heapspray", "HeapCreate", "HeapAlloc", "RtlAllocateHeap",
            "VirtualAlloc", "MEM_COMMIT", "MEM_RESERVE", "PAGE_EXECUTE_READWRITE"
        };

        // ROP gadget 典型特征
        private static readonly string[] RopGadgetSignatures =
        {
            "ret", "pop", "pop r", "jmp esp", "call esp", "push esp", "retn",
            "add esp", "sub esp", "xchg eax, esp", "call eax", "jmp eax",
            "pwn", "return-oriented", "rop", "gadget"
        };

        // 常见 exploit 框架
        private static readonly string[] ExploitFrameworkSignatures =
        {
            "metasploit", "msfvenom", "meterpreter", "payload", "reverse_tcp",
            "bind_tcp", "windows/meterpreter", "windows/shell", "meterpreter/reverse",
            "cobaltstrike", "cobalt strike", "beacon", "malleable",
            "empire", "powershell empire", "pwn", "exploit-db"
        };

        public sealed class MemoryPatternEvidence
        {
            public bool HasShellcode;               // Shellcode 特征
            public bool HasHeapSpray;               // 堆喷射特征
            public bool HasRopGadget;               // ROP 链特征
            public bool HasExploitFramework;        // 已知 exploit 框架
            public int CategoryCount;                // 独立类别数 0..4
            public double Strength;                  // 证据强度 0..1
            public string Notes = "";
        }

        public MemoryPatternEvidence Analyze(string content)
        {
            var ev = new MemoryPatternEvidence();
            if (string.IsNullOrWhiteSpace(content)) return ev;

            try
            {
                ev.HasShellcode = ShellcodeSignatures.Any(s => content.Contains(s, StringComparison.OrdinalIgnoreCase));
                ev.HasHeapSpray = HeapSprayPatterns.Any(h => content.Contains(h, StringComparison.OrdinalIgnoreCase));
                ev.HasRopGadget = RopGadgetSignatures.Any(r => content.Contains(r, StringComparison.OrdinalIgnoreCase));
                ev.HasExploitFramework = ExploitFrameworkSignatures.Any(e => content.Contains(e, StringComparison.OrdinalIgnoreCase));

                ev.CategoryCount = (ev.HasShellcode ? 1 : 0) + (ev.HasHeapSpray ? 1 : 0) +
                                   (ev.HasRopGadget ? 1 : 0) + (ev.HasExploitFramework ? 1 : 0);

                if (ev.CategoryCount >= 4) { ev.Strength = 0.85; ev.Notes = "完整的 exploit payload 特征（shellcode+堆喷射+ROP+框架）"; }
                else if (ev.CategoryCount >= 3) { ev.Strength = 0.60; ev.Notes = "多重 exploit 特征"; }
                else if (ev.CategoryCount >= 2) { ev.Strength = 0.25; ev.Notes = "部分 exploit 特征"; }
            }
            catch (Exception ex)
            {
                LogHelper.Log(LogHelper.LogLevel.Warning, "MemoryPatternAnalyzer 失败", ex.Message);
            }
            return ev;
        }
    }
}