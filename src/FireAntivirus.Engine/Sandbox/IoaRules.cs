// IOA（Indicators of Attack）行为评分规则集 —— 照搬 XIGUASecurity 10x 的沙箱行为评分体系：
//   行为证据文本化后按规则累加得分，总分 >= 100 判定恶意（MALICIOUS_THRESHOLD 与西瓜一致）。
//   规则覆盖：持久化/提权/注入/防御规避/凭据访问/勒索/下载器/网络/进程链六大类，共 60+ 条。
using System;
using System.Collections.Generic;
using System.Linq;

namespace FireAntivirus.Engine.Sandbox
{
    public sealed class IoaRule
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public int Score { get; set; }
        /// <summary>行为文本匹配键（任一命中即计分，全部小写）。</summary>
        public string[] MatchKeys { get; set; }
    }

    public static class IoaRules
    {
        public const int MaliciousThreshold = 100;

        public static readonly List<IoaRule> Rules = new List<IoaRule>
        {
            // ===== 持久化（自启动/服务/任务）=====
            R("PERSIST-RUN", "写入注册表 Run 自启动", 40, "\\currentversion\\run"),
            R("PERSIST-RUNONCE", "写入 RunOnce 自启动", 40, "\\currentversion\\runonce"),
            R("PERSIST-STARTUP", "写入启动文件夹", 45, "\\start menu\\programs\\startup"),
            R("PERSIST-SERVICE", "创建系统服务", 45, "sc create", "createservice"),
            R("PERSIST-TASK", "创建计划任务", 35, "schtasks", "\\tasks\\"),
            R("PERSIST-IFEO", "IFEO 映像劫持", 50, "image file execution options"),
            R("PERSIST-WINLOGON", "修改 Winlogon Shell/Userinit", 65, "winlogon", "userinit"),
            R("PERSIST-COMHIJACK", "COM 劫持持久化", 40, "\\clsid\\", "inprocserver32"),
            R("PERSIST-WMI", "WMI 事件订阅持久化", 40, "root\\subscription", "__eventfilter"),
            R("PERSIST-ACTIVEX", "ActiveX/浏览器扩展持久化", 30, "\\internet explorer\\", "\\bho\\"),

            // ===== 提权 / 账户 =====
            R("PRIV-UAC-BYPASS", "UAC 绕过命令", 55, "fodhelper", "eventvwr", "sdclt", "computerdefaults", "silentcleanup"),
            R("PRIV-ADD-USER", "创建用户账户", 45, "net user", "net localgroup", "add-localuser"),
            R("PRIV-TOKEN", "令牌窃取/模拟", 55, "duplicatetoken", "impersonatetoken", "settokeninformation"),
            R("PRIV-PRIVILEGE", "提权 API 组合", 45, "adjusttokenprivileges", "seDebugPrivilege".ToLowerInvariant()),

            // ===== 注入 / 进程操控 =====
            R("INJECT-REMOTE-THREAD", "远程线程注入", 60, "createremotethread", "ntcreatethreadex"),
            R("INJECT-HOLLOW", "进程镂空", 65, "ntunmapviewofsection", "setthreadcontext"),
            R("INJECT-APC", "APC 注入", 55, "queueuserapc"),
            R("INJECT-SHELLCODE", "内存 shellcode 执行", 55, "virtualalloc", "virtualprotect", "createthread"),
            R("INJECT-REFLECTIVE", "反射式 DLL 加载", 55, "reflectiveloader", "manualmap"),
            R("PROC-SUSPEND", "挂起进程", 30, "ntsuspendprocess", "suspendthread"),
            R("PROC-PPID", "伪造父进程", 40, "parentprocessid", "ppid-spoof"),

            // ===== 防御规避 =====
            R("EVADE-AMSI", "AMSI 绕过", 55, "amsiutils", "amsi bypass", "amsi.dll"),
            R("EVADE-ETW", "ETW 补丁/绕过", 50, "etwp", "nttraceevent"),
            R("EVADE-DISABLE-DEFENDER", "禁用 Defender", 65, "disablerealtimemonitoring", "set-mppreference", "defender"),
            R("EVADE-DISABLE-FIREWALL", "禁用防火墙", 40, "netsh advfirewall set", "netprofiles"),
            R("EVADE-USER-EXEC-DISABLE", "关闭执行策略", 25, "executionpolicy bypass", "bypass"),
            R("EVADE-HIDE-WINDOW", "隐藏窗口执行", 20, "-windowstyle hidden", "-w hidden", "create_nowindow"),
            R("EVADE-ANTIDEBUG", "反调试/反虚拟机", 35, "isdebuggerpresent", "checkremotedebuggerpresent", "vmdetect"),
            R("EVADE-ROOTKIT", "驱动/内核级隐藏", 70, "\\drivers\\", ".sys"),
            R("EVADE-CLEAN-EVENTLOG", "清除事件日志", 60, "wevtutil cl", "cleareventlog"),

            // ===== 凭据访问 / 窃取 =====
            R("CRED-LSASS", "访问 LSASS 内存", 70, "lsass", "minidump"),
            R("CRED-MIMIKATZ", "Mimikatz 特征", 70, "sekurlsa", "logonpasswords"),
            R("CRED-BROWSER", "浏览器凭据窃取", 50, "\\login data", "\\cookies", "\\web data"),
            R("CRED-WALLET", "钱包文件访问", 55, "wallet.dat", "\\wallets\\", "keystore"),
            R("CRED-KEYLOG", "键盘记录 API", 45, "setwindowshookex", "getasynckeystate"),
            R("CRED-SCREENCAP", "屏幕捕获", 25, "bitblt", "getdc", "createcompatibledc"),
            R("CRED-CLIPBOARD", "剪贴板劫持", 30, "getclipboarddata", "setclipboarddata"),

            // ===== 勒索 / 破坏 =====
            R("RANSOM-SHADOW", "删除卷影副本", 80, "vssadmin delete shadows", "wmic shadowcopy delete"),
            R("RANSOM-RECOVERY", "禁用系统恢复", 70, "recoveryenabled no", "bcdedit /set"),
            R("RANSOM-BACKUP-DELETE", "删除备份目录", 60, "wbadmin delete", "delete catalog"),
            R("RANSOM-EXT", "批量加密文件", 50, ".wncry", ".locked", ".encrypted", ".enc", ".lockbit"),
            R("RANSOM-NOTE", "释放勒索说明文件", 45, "_readme.txt", "decrypt_instruction", "how_to_decrypt"),
            R("RANSOM-MASS-WRITE", "短时大量文件写入", 40, "mass-file-write"),
            R("RANSOM-MASS-RENAME", "短时大量文件重命名", 45, "mass-file-rename"),
            R("RANSOM-BOOT", "修改引导扇区/MBR", 80, "\\\\.\\physicaldrive", "writefile boot"),
            R("RANSOM-MBR-WIPE", "擦除磁盘数据", 80, "cipher /w", "format /p"),

            // ===== 下载器 / 执行链 =====
            R("DL-POWERSHELL", "PowerShell 下载执行", 45, "downloadstring", "invoke-webrequest", "invoke-expression", "iex ("),
            R("DL-CERTUTIL", "certutil 下载解码", 40, "certutil -urlcache", "certutil -decode"),
            R("DL-BITS", "BITS 传输下载", 35, "bitsadmin /transfer", "start-bitstransfer"),
            R("DL-CURL", "curl/wget 下载执行", 30, "curl -o", "wget http"),
            R("DL-MSHTA", "mshta 远程脚本", 45, "mshta http", "mshta javascript"),
            R("DL-REGSVR32", "regsvr32 无注册加载", 45, "regsvr32 /s /u /i:http", "scrobj.dll"),
            R("DL-RUNDLL32", "rundll32 远程执行", 40, "rundll32 javascript", "rundll32 url.dll"),
            R("DL-BASE64", "Base64 编码载荷", 25, "frombase64string", "-encodedcommand"),
            R("DL-EXEC-TEMP", "在临时目录释放可执行文件", 35, "\\temp\\", "\\appdata\\local\\temp\\"),
            R("DL-UNSIGNED-RUN", "运行未签名可执行文件", 20, "unsigned-execute"),

            // ===== 网络 =====
            R("NET-C2-PORT", "连接常见 C2 端口", 35, ":4444", ":5555", ":31337", ":6667", ":1337"),
            R("NET-TOR", "连接 Tor 代理端口", 40, ":9050", ":9150"),
            R("NET-MINER", "连接矿池端口", 40, ":3333", ":14444", ":45700"),
            R("NET-IRCSERVER", "IRC 命令控制通道", 30, "irc.", "pirc"),
            R("NET-FTP-EXFIL", "FTP 数据外传", 30, "ftp upload", "put /"),
            R("NET-RAW-SOCKET", "原始套接字/端口扫描", 35, "sock_raw", "connectex scan"),
            R("NET-DNS-TUNNEL", "DNS 隧道外传", 45, "dns tunnel", "txt exfil"),

            // ===== 进程链 / 系统工具滥用 =====
            R("PROC-SPAWN-MSOFFICE", "Office 派生脚本进程", 40, "winword.exe", "excel.exe", "wscript.exe"),
            R("PROC-SPAWN-WMI", "WMI 派生进程", 40, "wmic process call create"),
            R("PROC-SUSPICIOUS-CHILD", "启动可疑子进程(powershell/mshta)", 35, "powershell.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe"),
            R("PROC-SVCHOST-FAKE", "伪装系统进程名", 35, "svchost32.exe", "lsass32.exe", "explorer32.exe"),
            R("PROC-SELFDELETE", "自删除", 40, "movefileex", "cmd /c del"),
            R("PROC-LOLBIN", "LOLBins 滥用组合", 35, "msbuild.exe", "installutil.exe", "regasm.exe", "cscript.exe"),

            // ===== 反分析逃避（沙箱/虚拟机/调试器/延时，T1497）=====
            R("EVASION-SANDBOX", "沙箱/沙盘痕迹探测", 45, "sbiedll", "sandboxie", "sbiectrl", "autosandbox", "sandbox-artifact"),
            R("EVASION-VM", "虚拟机痕迹探测", 40, "vmware", "vbox", "virtualbox", "vmtoolsd", "qemu", "hyper-v", "parallels"),
            R("EVASION-DEBUGGER", "反调试探测", 40, "isdebuggerpresent", "checkremotedebugger", "processdebugport", "beingdebugged", "ntglobalflag"),
            R("EVASION-DELAY", "时间差/延时规避", 25, "gettickcount", "queryperformancecounter", "rdtsc", "sleep("),
            R("EVASION-HARDWARE", "硬件指纹枚举", 30, "win32_diskdrive", "win32_bios", "serialnumber", "volumeserialnumber"),
            R("EVASION-ANALYSIS-TOOL", "分析工具痕迹", 45, "x64dbg", "ollydbg", "windbg", "procmon", "processhacker"),
        };

        private static IoaRule R(string id, string name, int score, params string[] keys) =>
            new IoaRule { Id = id, Name = name, Score = score, MatchKeys = keys };

        /// <summary>对行为证据文本集合评分。返回总分与命中规则（按分数降序）。</summary>
        public static (int Score, List<IoaRule> Hits) Evaluate(IEnumerable<string> observedBehaviors)
        {
            var hits = new List<IoaRule>();
            int total = 0;
            var evidence = (observedBehaviors ?? Enumerable.Empty<string>())
                .Where(e => !string.IsNullOrWhiteSpace(e))
                .Select(e => e.ToLowerInvariant())
                .ToList();

            foreach (var rule in Rules)
            {
                if (rule.MatchKeys.Any(k => evidence.Any(e => e.Contains(k.ToLowerInvariant()))))
                {
                    hits.Add(rule);
                    total += rule.Score;
                }
            }

            return (total, hits.OrderByDescending(h => h.Score).ToList());
        }
    }
}