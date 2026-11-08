using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace FireAntivirus.Common
{
    /// <summary>
    /// 中央防误杀守护：任何自动/手动查杀动作在执行 Process.Kill 之前必须调用
    /// TrustedProcessGuard.CanTerminate，确保不会误杀正常系统进程。
    /// 三层防线：
    ///   1. 受保护系统进程名（绝对禁止终止，不做任何例外）；
    ///   2. Windows 系统目录 + 系统进程名组合豁免；
    ///   3. Authenticode 签名验证（WinVerifyTrust），微软/Windows/受信任发布者签名的进程一律豁免。
    /// </summary>
    public static class TrustedProcessGuard
    {
        /// <summary>绝对不允许终止的系统关键进程名（小写、不含扩展名）。</summary>
        private static readonly HashSet<string> ProtectedSystemProcessNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "system", "idle", "smss", "csrss", "wininit", "winlogon", "services", "lsass",
            "svchost", "dwm", "explorer", "conhost", "runtimebroker", "taskhostw", "taskhost",
            "dllhost", "sihost", "ctfmon", "audiodg", "spoolsv", "searchindexer", "searchapp",
            "searchhost", "fontdrvhost", "wmiprvse", "msmpeng", "nisdrv", "nissrv", "wdfmgr",
            "securityhealthservice", "securityhealthsystray", "dashost", "edservice", "sgrmbroker",
            "smartscreen", "wermgr", "werfault", "perfmon", "mmc", "cmd", "conhost", "openconsole",
            "powershell", "pwsh", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "schtasks",
            "taskkill", "tasklist", "wusa", "dism", "sfc", "trustedinstaller", "tiworker",
            "mscorsvw", "ngen", "vssvc", "wbengine", "memcompression", "registry", "lsaiso",
            "sihost", "shellexperiencehost", "startmenuexperiencehost", "textinputhost",
            "applicationframehost", "lockapp", "logonui", "userinit", "dwm.exe", "kbdhook",
            "everything", "explorer", "notepad", "notepad++", "mspaint", "winver", "calc",
            "chrome", "msedge", "firefox", "code", "devenv", "clion64", "idea64", "pycharm64",
            "windowsdefender", "msoia", "winword", "excel", "powerpnt", "outlook", "onenote",
            "teams", "onedrive", "nvcontainer", "nvdisplay.container", "nvsphelper64",
            "amdow", "amdrsserv", "radeonsettings", "nvidia web helper", "steam", "steamwebhelper",
            "qq", "wechat", "wechatappex", "weixin", "dingtalk", "feishu", "wps", "wpscloudsvr",
            "baidunetdisk", "thunder", "cloudmusic", "kugou", "iqiyi", "potplayer", "vlc",
            "telegram", "discord", "slack", "zoom", "钉钉", "企业微信",
            "clamscan", "clamd", "freshclam", "fireantivirus", "fireantivirus.service",
            "fireantivirus.servicehost", "fireantivirus.launcher", "selftestharness"
        };

        /// <summary>受信任的发布者证书主体关键词（签名验证通过后仍需匹配其一）。</summary>
        private static readonly string[] TrustedPublisherKeywords = new string[]
        {
            "microsoft", "windows", "google", "apple", "intel", "nvidia", "amd",
            "adobe", "mozilla", "tencent", "alibaba", "baidu", "huawei", "samsung",
            "canonical", "oracle", "dotnet foundation", "github", "gitkraken",
            "衡量", "耄耋", "fireantivirus"
        };

        /// <summary>Windows 系统目录（含 SysWOW64）。</summary>
        private static readonly string[] SystemDirectories = BuildSystemDirectories();

        private static string[] BuildSystemDirectories()
        {
            var dirs = new List<string>
            {
                Environment.GetFolderPath(Environment.SpecialFolder.System),      // System32
                Environment.GetFolderPath(Environment.SpecialFolder.SystemX86),   // SysWOW64
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "WinSxS"),
                Environment.GetFolderPath(Environment.SpecialFolder.Windows)
            };
            return dirs.Where(d => !string.IsNullOrEmpty(d)).Select(NormalizePath).Distinct().ToArray();
        }

        private static string NormalizePath(string path)
        {
            try
            {
                return Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                          .ToLowerInvariant();
            }
            catch
            {
                return (path ?? string.Empty).ToLowerInvariant();
            }
        }

        /// <summary>判断某进程是否为受保护、禁止终止的系统进程。</summary>
        public static bool IsProtectedProcess(int processId)
        {
            try
            {
                using (var p = Process.GetProcessById(processId))
                {
                    return IsProtectedProcess(p);
                }
            }
            catch
            {
                // 进程已退出或无法访问：按受保护处理，宁可放过不可错杀
                return true;
            }
        }

        /// <summary>判断某进程是否为受保护、禁止终止的系统进程。</summary>
        public static bool IsProtectedProcess(Process process)
        {
            if (process == null) return true;
            try
            {
                return IsProtectedProcess(process.Id, SafeGetProcessName(process), SafeGetProcessPath(process));
            }
            catch
            {
                return true;
            }
        }

        /// <summary>按 名称+路径 判断是否受保护（供已知进程信息的调用方使用）。</summary>
        public static bool IsProtectedProcess(int processId, string processName, string processPath)
        {
            try
            {
                if (processId <= 4) return true; // System / Idle / System Idle Process

                var name = Path.GetFileNameWithoutExtension(processName ?? string.Empty);
                if (string.IsNullOrEmpty(name) && !string.IsNullOrEmpty(processPath))
                    name = Path.GetFileNameWithoutExtension(processPath);

                // 第一层：受保护进程名，绝对禁止
                if (!string.IsNullOrEmpty(name) && ProtectedSystemProcessNames.Contains(name.Trim()))
                    return true;

                // 第二层：位于 Windows 系统目录下的可执行文件一律禁止终止。
                // 系统目录中的程序受 Windows 资源保护（WRP），第三方恶意软件无法写入，
                // 因此位于该目录的进程可安全豁免。
                if (!string.IsNullOrEmpty(processPath))
                {
                    var norm = NormalizePath(processPath);
                    foreach (var sysDir in SystemDirectories)
                    {
                        if (norm.StartsWith(sysDir + Path.DirectorySeparatorChar, StringComparison.Ordinal) ||
                            norm.StartsWith(sysDir + "/", StringComparison.Ordinal))
                            return true;
                    }
                }

                // 第三层：Authenticode 签名验证 + 受信发布者名单
                if (!string.IsNullOrEmpty(processPath) && File.Exists(processPath))
                {
                    var (valid, subject) = VerifyAuthenticode(processPath);
                    if (valid && IsTrustedPublisher(subject))
                        return true;
                }

                return false;
            }
            catch
            {
                // 任何异常一律按受保护处理：宁可漏杀，不可误杀系统进程
                return true;
            }
        }

        /// <summary>
        /// 查杀前的唯一入口。返回 true 表示允许终止；false 表示进程受保护，
        /// 调用方必须放弃终止并记录一条“进程受保护，已跳过查杀”日志。
        /// </summary>
        public static bool CanTerminate(int processId)
        {
            return !IsProtectedProcess(processId);
        }

        public static bool CanTerminate(Process process)
        {
            return !IsProtectedProcess(process);
        }

        public static bool CanTerminate(string processName, string processPath)
        {
            return !IsProtectedProcess(0, processName, processPath);
        }

        /// <summary>批量按进程名终止时的安全版本：跳过所有受保护进程。</summary>
        public static int SafeTerminateByName(string processName)
        {
            int killed = 0;
            try
            {
                foreach (var p in Process.GetProcessesByName(processName))
                {
                    using (p)
                    {
                        if (!CanTerminate(p)) continue;
                        p.Kill();
                        killed++;
                    }
                }
            }
            catch { }
            return killed;
        }

        /// <summary>按 PID 安全终止；受保护进程返回 false 且不做任何操作。</summary>
        public static bool SafeTerminateById(int processId)
        {
            try
            {
                using (var p = Process.GetProcessById(processId))
                {
                    if (!CanTerminate(p)) return false;
                    p.Kill();
                    return true;
                }
            }
            catch
            {
                return false;
            }
        }

        private static string SafeGetProcessName(Process p)
        {
            try { return p.ProcessName; } catch { return string.Empty; }
        }

        private static string SafeGetProcessPath(Process p)
        {
            try { return p.MainModule?.FileName; }
            catch { try { return p.GetMainThreadModulePath(); } catch { return string.Empty; } }
        }

        private static bool IsTrustedPublisher(string subject)
        {
            if (string.IsNullOrEmpty(subject)) return false;
            var lower = subject.ToLowerInvariant();
            foreach (var kw in TrustedPublisherKeywords)
            {
                if (lower.Contains(kw)) return true;
            }
            return false;
        }

        #region WinVerifyTrust (Authenticode)

        [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false)]
        private static extern int WinVerifyTrust(IntPtr hWnd, ref Guid pgActionID, ref WINTRUST_DATA pWVTData);

        private static readonly Guid DriverActionId = new Guid("F750E6C3-38EE-11D1-85E5-00C04FC295EE");
        private static readonly Guid WinTrustActionGenericVerifyV2 = new Guid("00AAC56B-CD44-11d0-8472-00A0C93C588D");

        private const int ERROR_SUCCESS = 0;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WINTRUST_FILE_INFO
        {
            public uint cbStruct;
            [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WINTRUST_DATA
        {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public uint dwUIChoice;
            public uint fdwRevocationChecks;
            public uint dwUnionChoice;
            public IntPtr pFile;      // union -> WINTRUST_FILE_INFO*
            public uint dwStateAction;
            public IntPtr hWVTStateData;
            [MarshalAs(UnmanagedType.LPWStr)] public string pwszURLReference;
            public uint dwProvFlags;
            public uint dwUIContext;
            public IntPtr pSignatureSettings;
        }

        private const uint WTD_UI_NONE = 2;
        private const uint WTD_REVOKE_NONE = 0;
        private const uint WTD_CHOICE_FILE = 1;
        private const uint WTD_STATEACTION_VERIFY = 1;
        private const uint WTD_STATEACTION_CLOSE = 2;

        /// <summary>
        /// 通过 WinVerifyTrust 验证文件的 Authenticode 签名。
        /// 返回 (是否有效签名, 签名主体)。
        /// </summary>
        public static (bool IsValid, string Subject) VerifyAuthenticode(string filePath)
        {
            try
            {
                var fileInfo = new WINTRUST_FILE_INFO
                {
                    cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)),
                    pcwszFilePath = filePath,
                    hFile = IntPtr.Zero,
                    pgKnownSubject = IntPtr.Zero
                };

                var wtd = new WINTRUST_DATA
                {
                    cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_DATA)),
                    pPolicyCallbackData = IntPtr.Zero,
                    pSIPClientData = IntPtr.Zero,
                    dwUIChoice = WTD_UI_NONE,
                    fdwRevocationChecks = WTD_REVOKE_NONE,
                    dwUnionChoice = WTD_CHOICE_FILE,
                    pFile = Marshal.AllocHGlobal(Marshal.SizeOf(fileInfo)),
                    dwStateAction = WTD_STATEACTION_VERIFY,
                    hWVTStateData = IntPtr.Zero,
                    pwszURLReference = null,
                    dwProvFlags = 0,
                    dwUIContext = 0
                };

                try
                {
                    Marshal.StructureToPtr(fileInfo, wtd.pFile, false);

                    // 先按 Authenticode（V2）验证
                    var actionId = WinTrustActionGenericVerifyV2;
                    int result = WinVerifyTrust(IntPtr.Zero, ref actionId, ref wtd);
                    if (result != ERROR_SUCCESS)
                    {
                        // 内核驱动签名文件（如部分系统组件）按驱动策略再验一次
                        actionId = DriverActionId;
                        result = WinVerifyTrust(IntPtr.Zero, ref actionId, ref wtd);
                    }

                    // 关闭状态句柄，避免句柄泄漏
                    wtd.dwStateAction = WTD_STATEACTION_CLOSE;
                    var closeId = WinTrustActionGenericVerifyV2;
                    try { WinVerifyTrust(IntPtr.Zero, ref closeId, ref wtd); } catch { }

                    if (result == ERROR_SUCCESS)
                        return (true, GetAuthenticodeSubject(filePath));
                    return (false, string.Empty);
                }
                finally
                {
                    Marshal.FreeHGlobal(wtd.pFile);
                }
            }
            catch
            {
                return (false, string.Empty);
            }
        }

        private static string GetAuthenticodeSubject(string filePath)
        {
            try
            {
                var cert = X509Certificate.CreateFromSignedFile(filePath);
                return cert.Subject ?? string.Empty;
            }
            catch
            {
                return string.Empty;
            }
        }

        #endregion
    }

    /// <summary>Process 扩展，用于在 MainModule 不可用时兜底取路径。</summary>
    internal static class TrustedProcessGuardExtensions
    {
        public static string GetMainThreadModulePath(this Process p)
        {
            try
            {
                foreach (ProcessModule m in p.Modules)
                {
                    if (m == null) continue;
                    return m.FileName; // 第一个模块即主模块
                }
            }
            catch { }
            return string.Empty;
        }
    }
}
