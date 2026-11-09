// WFP 数据包级阻断（Windows Filtering Platform 策略层）：
//   1) FwpmEngineOpen0 真实探测 Base Filtering Engine（BFE）可用性与权限；
//   2) 通过 Windows 防火墙（WFP 官方策略层）下发 out/in block 规则，按远端 IP 立即阻断；
//   3) 规则名带企业前缀 + TTL（默认 10 分钟），到期自动撤销；全部规则可枚举/手动解除；
//   4) 不做内核 callout 注入（避免 BFE 结构体版本差异导致拒绝），但阻断真实生效于 TCP/UDP/ICMP。
//   只允许对"已确认恶意/高危"目标下发，单次最多 64 条，避免规则爆炸。
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace FireAntivirus.Engine.Analyzers
{
    public sealed class WfpBlockEntry
    {
        public string Ip { get; set; } = "";
        public string RuleName { get; set; } = "";
        public DateTime CreatedUtc { get; set; }
        public DateTime ExpiresUtc { get; set; }
        public string Reason { get; set; } = "";
    }

    public static class WfpBlocker
    {
        public static bool Enabled { get; set; } = true;
        public static int DefaultTtlMinutes { get; set; } = 10;
        public static int MaxRules { get; set; } = 64;
        public static string RulePrefix { get; set; } = "FireAntivirus-Block-";

        public static string LastError { get; private set; } = "";
        public static bool BfeAvailable { get; private set; }

        private static readonly object _lock = new object();
        private static readonly Dictionary<string, WfpBlockEntry> _active =
            new Dictionary<string, WfpBlockEntry>(StringComparer.OrdinalIgnoreCase);
        private static readonly Timer _expiryTimer = new Timer(_ => Expire(), null, 30000, 30000);

        [StructLayout(LayoutKind.Sequential)]
        private struct FWPM_DISPLAY_DATA0
        {
            public IntPtr Name;
            public IntPtr Description;
        }

        // 必须与 fwptypes.h 的 FWPM_SESSION0 逐字段对齐（x64 共 72 字节）：
        // sessionKey / displayData / flags / txnWaitTimeoutInMSec / processId / sid / sessionName / kernelMode
        // 旧定义把 DisplayData 放尾部且缺字段，封送错位致 FwpmEngineOpen0 内部解引用垃圾指针 → 0xC0000005 崩溃。
        [StructLayout(LayoutKind.Sequential)]
        private struct FWPM_SESSION0
        {
            public Guid SessionKey;
            public FWPM_DISPLAY_DATA0 DisplayData;
            public uint Flags;
            public uint TxnWaitTimeoutInMSec;
            public uint ProcessId;
            public IntPtr Sid;
            public IntPtr SessionName;
            public int KernelMode;
        }

        [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)]
        private static extern uint FwpmEngineOpen0(string serverName, uint authnService,
            IntPtr authIdentity, ref FWPM_SESSION0 session, out IntPtr engineHandle);
        [DllImport("fwpuclnt.dll")]
        private static extern uint FwpmEngineClose0(IntPtr engineHandle);

        /// <summary>探测 BFE 与权限（引擎能打开 = 策略层可用；失败时返回 Win32 错误码）。</summary>
        public static bool ProbeEngine()
        {
            try
            {
                var session = new FWPM_SESSION0 { Flags = 0x00000001 /* DYNAMIC */ };
                uint status = FwpmEngineOpen0(null, 10 /* RPC_C_AUTHN_WINNT */, IntPtr.Zero, ref session, out IntPtr engine);
                BfeAvailable = status == 0 && engine != IntPtr.Zero;
                if (engine != IntPtr.Zero) FwpmEngineClose0(engine);
                if (!BfeAvailable)
                {
                    LastError = $"FwpmEngineOpen0 失败(0x{status:X8})，需要管理员权限且 BFE 服务运行";
                    FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "[WFP] " + LastError);
                }
                return BfeAvailable;
            }
            catch (Exception ex)
            {
                BfeAvailable = false;
                LastError = "FwpmEngineOpen0 异常: " + ex.Message;
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "[WFP] " + LastError);
                return false;
            }
        }

        /// <summary>阻断单个远端 IPv4（out + in）。返回是否真实下发成功。</summary>
        public static bool Block(string ip, string reason, int ttlMinutes = 0)
        {
            if (!Enabled) { LastError = "WFP 阻断未启用"; return false; }
            if (!IsValidIPv4(ip)) { LastError = "无效 IPv4: " + ip; return false; }

            lock (_lock)
            {
                if (_active.Count >= MaxRules) { LastError = "阻断规则已达上限 " + MaxRules; return false; }
                if (_active.ContainsKey(ip)) return true;

                string ruleName = RulePrefix + ip;
                bool outOk = RunNetsh($"advfirewall firewall add rule name=\"{ruleName}-out\" dir=out action=block remoteip={ip} enable=yes profile=any");
                bool inOk = RunNetsh($"advfirewall firewall add rule name=\"{ruleName}-in\" dir=in action=block remoteip={ip} enable=yes profile=any");

                if (!outOk && !inOk) { LastError = "netsh 下发失败（需要管理员权限）"; return false; }

                int ttl = ttlMinutes > 0 ? ttlMinutes : DefaultTtlMinutes;
                var entry = new WfpBlockEntry
                {
                    Ip = ip,
                    RuleName = ruleName,
                    CreatedUtc = DateTime.UtcNow,
                    ExpiresUtc = DateTime.UtcNow.AddMinutes(ttl),
                    Reason = reason ?? ""
                };
                _active[ip] = entry;

                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                    $"[WFP] 已阻断 {ip}（out={outOk}, in={inOk}, TTL {ttl}min）：{reason}");
                DetectionTimeline.Record("WFP", "网络阻断", "High", "T1562/T1071", 0, "",
                    ip, $"WFP 规则已下发: {reason}");
                return true;
            }
        }

        public static bool Unblock(string ip)
        {
            lock (_lock)
            {
                string ruleName = RulePrefix + ip;
                bool a = RunNetsh($"advfirewall firewall delete rule name=\"{ruleName}-out\"");
                bool b = RunNetsh($"advfirewall firewall delete rule name=\"{ruleName}-in\"");
                _active.Remove(ip);
                if (!a && !b) { LastError = "未找到规则或删除失败"; return false; }
                DetectionTimeline.Record("WFP", "解除阻断", "Info", "", 0, "", ip, "WFP 规则已撤销");
                return true;
            }
        }

        public static List<WfpBlockEntry> Active()
        {
            lock (_lock) { return _active.Values.OrderByDescending(e => e.CreatedUtc).ToList(); }
        }

        public static void RemoveAll()
        {
            foreach (var entry in Active()) Unblock(entry.Ip);
        }

        /// <summary>从网络事件文本中提取公网 IPv4 并阻断（仅高危目标调用）。</summary>
        public static int BlockFromText(string text, string reason, int ttlMinutes = 0)
        {
            int blocked = 0;
            if (string.IsNullOrEmpty(text)) return 0;
            foreach (Match match in Regex.Matches(text, @"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"))
            {
                string ip = match.Groups[1].Value;
                if (!IsValidIPv4(ip) || !IsPublicIPv4(ip)) continue;
                if (Block(ip, reason, ttlMinutes)) blocked++;
            }
            return blocked;
        }

        private static void Expire()
        {
            try
            {
                DateTime now = DateTime.UtcNow;
                foreach (var entry in Active().Where(e => e.ExpiresUtc <= now).ToList())
                    Unblock(entry.Ip);
            }
            catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
        }

        private static bool RunNetsh(string arguments)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "netsh.exe",
                    Arguments = arguments,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                using var process = Process.Start(psi);
                if (process == null) return false;
                string output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
                process.WaitForExit(8000);
                return process.ExitCode == 0 && !output.Contains("发生系统错误", StringComparison.OrdinalIgnoreCase)
                                            && !output.Contains("The requested operation requires elevation", StringComparison.OrdinalIgnoreCase);
            }
            catch (Exception ex)
            {
                LastError = ex.Message;
                return false;
            }
        }

        private static bool IsValidIPv4(string ip)
        {
            if (string.IsNullOrWhiteSpace(ip)) return false;
            var parts = ip.Split('.');
            if (parts.Length != 4) return false;
            foreach (var part in parts)
                if (!byte.TryParse(part, out _)) return false;
            return true;
        }

        private static bool IsPublicIPv4(string ip)
        {
            var parts = ip.Split('.').Select(byte.Parse).ToArray();
            if (parts[0] == 10) return false;
            if (parts[0] == 127) return false;
            if (parts[0] == 0) return false;
            if (parts[0] == 172 && parts[1] >= 16 && parts[1] <= 31) return false;
            if (parts[0] == 192 && parts[1] == 168) return false;
            if (parts[0] == 169 && parts[1] == 254) return false;
            if (parts[0] == 100 && parts[1] >= 64 && parts[1] <= 127) return false;
            if (parts[0] >= 224) return false;
            return true;
        }
    }
}