// AMSI 集成（照搬 XIGUASecurity 10x amsi_protection.rs，C# 版）：
//   1) 动态调用系统 amsi.dll 的 AmsiInitialize/AmsiScanBuffer 扫描脚本/命令内容（真实杀毒接口）；
//   2) 检测 AMSI bypass：检查本进程 amsi.dll 中 AmsiScanBuffer 首字节是否被内存补丁（E9 JMP/C3 RET 等）；
//   3) 供脚本检测层（ScriptMacroAnalyzer）作为强证据源使用。
using System;
using System.Runtime.InteropServices;

namespace FireAntivirus.Engine.Analyzers
{
    public enum AmsiVerdict
    {
        Clean = 0,          // AMSI_RESULT_CLEAN
        NotDetected = 1,    // 尚未识别
        BlockedByAdmin = 2,
        Detected = 32768,
        Error = -1
    }

    public static class AmsiScanner
    {
        private const uint AMSI_RESULT_CLEAN = 0;
        private const uint AMSI_RESULT_NOT_DETECTED = 1;
        private const uint AMSI_RESULT_BLOCKED_BY_ADMIN = 2;
        private const uint AMSI_RESULT_DETECTED = 32768;

        [DllImport("amsi.dll", CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern int AmsiInitialize(string appName, out IntPtr amsiContext);

        [DllImport("amsi.dll", SetLastError = false)]
        private static extern int AmsiScanBuffer(
            IntPtr amsiContext, byte[] buffer, uint length, IntPtr contentName,
            IntPtr amsiSession, out uint result);

        [DllImport("amsi.dll", SetLastError = false)]
        private static extern void AmsiUninitialize(IntPtr amsiContext);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string moduleName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr module, string procName);

        private static readonly object _lock = new object();
        private static IntPtr _context = IntPtr.Zero;
        private static bool _initTried;
        private static bool _available;
        private static bool _bypassChecked;
        private static bool _bypassDetected;

        /// <summary>设置开关（关闭后 ScanContent 直接返回 NotDetected，不产生任何票）。</summary>
        public static bool Enabled { get; set; } = true;

        public static bool IsAvailable
        {
            get { lock (_lock) { EnsureInit(); return _available; } }
        }

        /// <summary>本进程 amsi.dll 的 AmsiScanBuffer 是否被内存补丁（AMSI bypass 迹象）。</summary>
        public static bool IsAmsiBypassedInSelf
        {
            get { lock (_lock) { CheckBypass(); return _bypassDetected; } }
        }

        private static void EnsureInit()
        {
            if (_initTried) return;
            _initTried = true;
            try
            {
                int hr = AmsiInitialize("FireAntivirus", out _context);
                _available = hr == 0 && _context != IntPtr.Zero;
                if (!_available)
                    FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                        $"AMSI 初始化失败 hr={hr}（可能被安全策略禁用）");
                else
                    FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info, "AMSI 已初始化");
            }
            catch (Exception ex)
            {
                _available = false;
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                    "AMSI 不可用: " + ex.Message);
            }
        }

        /// <summary>用系统 AMSI 引擎扫描脚本/命令内容（真实扫描，返回 AMSI 判定）。</summary>
        public static AmsiVerdict ScanContent(string content, string contentName = "FireAntivirus.Script")
        {
            if (!Enabled || string.IsNullOrEmpty(content)) return AmsiVerdict.NotDetected;
            lock (_lock)
            {
                EnsureInit();
                if (!_available) return AmsiVerdict.Error;

                try
                {
                    byte[] buffer = System.Text.Encoding.UTF8.GetBytes(content);
                    // 内容名通过 IntPtr 传递（可空）；session 允许为 0
                    IntPtr namePtr = IntPtr.Zero;
                    try { namePtr = Marshal.StringToHGlobalUni(contentName ?? ""); } catch { }

                    try
                    {
                        int hr = AmsiScanBuffer(_context, buffer, (uint)buffer.Length, namePtr, IntPtr.Zero, out uint result);
                        if (hr != 0) return AmsiVerdict.Error;
                        return result switch
                        {
                            AMSI_RESULT_DETECTED => AmsiVerdict.Detected,
                            AMSI_RESULT_BLOCKED_BY_ADMIN => AmsiVerdict.BlockedByAdmin,
                            AMSI_RESULT_CLEAN => AmsiVerdict.Clean,
                            AMSI_RESULT_NOT_DETECTED => AmsiVerdict.NotDetected,
                            _ => AmsiVerdict.NotDetected
                        };
                    }
                    finally
                    {
                        if (namePtr != IntPtr.Zero) Marshal.FreeHGlobal(namePtr);
                    }
                }
                catch (Exception ex)
                {
                    FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                        "AMSI 扫描异常: " + ex.Message);
                    return AmsiVerdict.Error;
                }
            }
        }

        /// <summary>
        /// AMSI bypass 检测：AmsiScanBuffer 正常序言不应为 JMP(0xE9)/RET(0xC3)/jmp rax(0xFF 0xE0)。
        /// 出现补丁首字节通常意味着 AMSI 已被恶意代码绕过（防御规避 T1562.001）。
        /// </summary>
        private static void CheckBypass()
        {
            if (_bypassChecked) return;
            _bypassChecked = true;
            try
            {
                IntPtr module = GetModuleHandle("amsi.dll");
                if (module == IntPtr.Zero) return; // 未加载则无 bypass 判断意义
                IntPtr fn = GetProcAddress(module, "AmsiScanBuffer");
                if (fn == IntPtr.Zero) return;

                byte b0 = Marshal.ReadByte(fn);
                byte b1 = Marshal.ReadByte(fn + 1);
                if (b0 == 0xE9 || b0 == 0xC3 || (b0 == 0xFF && b1 == 0xE0))
                {
                    _bypassDetected = true;
                    FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                        $"[AMSI] 检测到 AmsiScanBuffer 内存补丁（首字节 0x{b0:X2} 0x{b1:X2}）——疑似 AMSI bypass");
                }
            }
            catch { }
        }
    }
}