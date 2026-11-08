using System;
using System.Runtime.InteropServices;

namespace FireAntivirus.NativeIntegration
{
    #region 威胁类型枚举
    public enum NativeThreatType
    {
        MALWARE = 0,
        VIRUS = 1,
        TROJAN = 2,
        RANSOMWARE = 3,
        SPYWARE = 4,
        ADWARE = 5,
        PHISHING = 6,
        MALICIOUS_SCRIPT = 7,
        SUSPICIOUS_PROCESS = 8,
        UNAUTHORIZED_ACCESS = 9,
        NETWORK_ATTACK = 10,
        REGISTRY_MODIFICATION = 11,
        BROWSER_HIJACK = 12,
        DEVICE_INFECTION = 13,
        DISK_PARTITION_MODIFICATION = 14,
        UEFI_BIOS_ATTACK = 15,
        KERNEL_TAMPERING = 16,
        DOCUMENT_INFECTION = 17,
        NETWORK_TRAFFIC_ANOMALY = 18,
        POPUP_SPAM = 19,
        PRIVACY_VIOLATION = 20,
        WEB_THREAT = 21,
        EMAIL_THREAT = 22,
        PASSWORD_THEFT = 23,
        FIREWALL_BYPASS = 24,
        DEVICE_CONTROL_VIOLATION = 25,
        VULNERABILITY_EXPLOIT = 26,
        CLOUD_STORAGE_THREAT = 27,
        BROWSER_SECURITY_VIOLATION = 28,
        MOBILE_DEVICE_THREAT = 29,
        SYSTEM_PERFORMANCE_ANOMALY = 30,
        BACKUP_FAILURE = 31,
        SECURITY_SCORE_LOW = 32,
        APPLICATION_BEHAVIOR_ANOMALY = 33,
        STARTUP_ITEM_VIOLATION = 34,
        SECURITY_REPORT_ERROR = 35,
        BEHAVIORAL_THREAT = 36,
        SYSTEM_TOOL_MISUSE = 37,
        SYSTEM_INFORMATION_LEAK = 38,
        QUARANTINE_ACCESS_VIOLATION = 39,
        TRUST_ZONE_VIOLATION = 40,
        LOG_CENTER_ERROR = 41,
        PROCESS_MALICIOUS = 42  // 进程恶意
    }
    #endregion

    #region 防护操作枚举
    public enum NativeProtectionAction
    {
        BLOCK = 0,
        ALLOW = 1,
        QUARANTINE = 2,
        DELETE = 3,
        IGNORE = 4,
        REPORT = 5
    }
    #endregion

    #region 防护状态枚举
    public enum NativeProtectionStatus
    {
        DISABLED = 0,
        ENABLED = 1,
        WARNING = 2,
        ERROR = 3,
        PROTECTING = 4
    }
    #endregion

    #region 威胁信息结构体
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct NativeThreatInfo
    {
        public NativeThreatType Type;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 1024)]
        public string Target;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 1024)]
        public string Description;
        public int Severity;
        public ushort Year;
        public ushort Month;
        public ushort DayOfWeek;
        public ushort Day;
        public ushort Hour;
        public ushort Minute;
        public ushort Second;
        public ushort Milliseconds;

        public DateTime Timestamp => new DateTime(Year, Month, Day, Hour, Minute, Second, Milliseconds);

        public override string ToString()
        {
            return $"[{Type}] {Target} - {Description} (Severity: {Severity})";
        }
    }
    #endregion

    #region P/Invoke声明
    public static class NativeSecurityCoreLib
    {
        private const string NATIVE_DLL_NAME = "NativeSecurityCore.dll";

        // 导出函数声明
        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr GetInstance();

        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool Initialize(IntPtr instance);

        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool StartProtection(IntPtr instance);

        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern void StopProtection(IntPtr instance);

        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool IsInitialized(IntPtr instance);

        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool IsRunning(IntPtr instance);

        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern NativeProtectionStatus GetProtectionStatus(IntPtr instance);

        // 文件防护
        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool EnableFileProtection(IntPtr instance, [MarshalAs(UnmanagedType.I1)] bool enable);

        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool IsFileProtectionEnabled(IntPtr instance);

        // 进程防护
        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool EnableProcessProtection(IntPtr instance, [MarshalAs(UnmanagedType.I1)] bool enable);

        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool IsProcessProtectionEnabled(IntPtr instance);

        // 设备防护
        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool EnableDeviceProtection(IntPtr instance, [MarshalAs(UnmanagedType.I1)] bool enable);

        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool IsDeviceProtectionEnabled(IntPtr instance);

        // 注册表防护
        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool EnableRegistryProtection(IntPtr instance, [MarshalAs(UnmanagedType.I1)] bool enable);

        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool IsRegistryProtectionEnabled(IntPtr instance);

        // 浏览器防护
        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool EnableBrowserProtection(IntPtr instance, [MarshalAs(UnmanagedType.I1)] bool enable);

        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool IsBrowserProtectionEnabled(IntPtr instance);

        // 脚本防护
        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool EnableScriptProtection(IntPtr instance, [MarshalAs(UnmanagedType.I1)] bool enable);

        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool IsScriptProtectionEnabled(IntPtr instance);

        // 主动防御
        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool EnableActiveDefense(IntPtr instance, [MarshalAs(UnmanagedType.I1)] bool enable);

        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool IsActiveDefenseEnabled(IntPtr instance);

        // 磁盘防护
        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool EnableDiskProtection(IntPtr instance, [MarshalAs(UnmanagedType.I1)] bool enable);

        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool IsDiskProtectionEnabled(IntPtr instance);

        // UEFI防护
        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool EnableUEFIProtection(IntPtr instance, [MarshalAs(UnmanagedType.I1)] bool enable);

        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool IsUEFIProtectionEnabled(IntPtr instance);

        // 内核防护
        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool EnableKernelProtection(IntPtr instance, [MarshalAs(UnmanagedType.I1)] bool enable);

        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool IsKernelProtectionEnabled(IntPtr instance);

        // 文档防护
        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool EnableDocumentProtection(IntPtr instance, [MarshalAs(UnmanagedType.I1)] bool enable);

        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool IsDocumentProtectionEnabled(IntPtr instance);

        // 网络防护
        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool EnableNetworkProtection(IntPtr instance, [MarshalAs(UnmanagedType.I1)] bool enable);

        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool IsNetworkProtectionEnabled(IntPtr instance);

        // 弹窗拦截
        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool EnablePopupBlocker(IntPtr instance, [MarshalAs(UnmanagedType.I1)] bool enable);

        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool IsPopupBlockerEnabled(IntPtr instance);

        // 勒索软件防护
        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool EnableRansomwareProtection(IntPtr instance, [MarshalAs(UnmanagedType.I1)] bool enable);

        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool IsRansomwareProtectionEnabled(IntPtr instance);

        // 隐私保护
        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool EnablePrivacyProtection(IntPtr instance, [MarshalAs(UnmanagedType.I1)] bool enable);

        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool IsPrivacyProtectionEnabled(IntPtr instance);

        // 网页防护
        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool EnableWebProtection(IntPtr instance, [MarshalAs(UnmanagedType.I1)] bool enable);

        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool IsWebProtectionEnabled(IntPtr instance);

        // 邮件安全
        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool EnableEmailSecurity(IntPtr instance, [MarshalAs(UnmanagedType.I1)] bool enable);

        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool IsEmailSecurityEnabled(IntPtr instance);

        // 密码管理
        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool EnablePasswordManager(IntPtr instance, [MarshalAs(UnmanagedType.I1)] bool enable);

        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool IsPasswordManagerEnabled(IntPtr instance);

        // 网络防火墙
        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool EnableNetworkFirewall(IntPtr instance, [MarshalAs(UnmanagedType.I1)] bool enable);

        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool IsNetworkFirewallEnabled(IntPtr instance);

        // 设备控制
        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool EnableDeviceControl(IntPtr instance, [MarshalAs(UnmanagedType.I1)] bool enable);

        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool IsDeviceControlEnabled(IntPtr instance);

        // 漏洞扫描
        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool EnableVulnerabilityScanner(IntPtr instance, [MarshalAs(UnmanagedType.I1)] bool enable);

        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool IsVulnerabilityScannerEnabled(IntPtr instance);

        // 云查杀
        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool EnableCloudScan(IntPtr instance, [MarshalAs(UnmanagedType.I1)] bool enable);

        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool IsCloudScanEnabled(IntPtr instance);

        // 安全浏览器
        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool EnableSecureBrowser(IntPtr instance, [MarshalAs(UnmanagedType.I1)] bool enable);

        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool IsSecureBrowserEnabled(IntPtr instance);

        // 移动安全
        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool EnableMobileSecurity(IntPtr instance, [MarshalAs(UnmanagedType.I1)] bool enable);

        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool IsMobileSecurityEnabled(IntPtr instance);

        // 系统优化
        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool EnableSystemOptimizer(IntPtr instance, [MarshalAs(UnmanagedType.I1)] bool enable);

        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool IsSystemOptimizerEnabled(IntPtr instance);

        // 备份恢复
        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool EnableBackupRecovery(IntPtr instance, [MarshalAs(UnmanagedType.I1)] bool enable);

        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool IsBackupRecoveryEnabled(IntPtr instance);

        // 安全评分
        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool EnableSecurityScore(IntPtr instance, [MarshalAs(UnmanagedType.I1)] bool enable);

        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool IsSecurityScoreEnabled(IntPtr instance);

        // 网络流量
        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool EnableNetworkTraffic(IntPtr instance, [MarshalAs(UnmanagedType.I1)] bool enable);

        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool IsNetworkTrafficEnabled(IntPtr instance);

        // 应用监控
        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool EnableApplicationMonitor(IntPtr instance, [MarshalAs(UnmanagedType.I1)] bool enable);

        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool IsApplicationMonitorEnabled(IntPtr instance);

        // 启动管理
        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool EnableStartupManager(IntPtr instance, [MarshalAs(UnmanagedType.I1)] bool enable);

        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool IsStartupManagerEnabled(IntPtr instance);

        // 安全报告
        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool EnableSecurityReport(IntPtr instance, [MarshalAs(UnmanagedType.I1)] bool enable);

        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool IsSecurityReportEnabled(IntPtr instance);

        // 行为分析
        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool EnableBehaviorAnalysis(IntPtr instance, [MarshalAs(UnmanagedType.I1)] bool enable);

        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool IsBehaviorAnalysisEnabled(IntPtr instance);

        // 系统工具
        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool EnableSystemTools(IntPtr instance, [MarshalAs(UnmanagedType.I1)] bool enable);

        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool IsSystemToolsEnabled(IntPtr instance);

        // 系统信息
        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool EnableSystemInfo(IntPtr instance, [MarshalAs(UnmanagedType.I1)] bool enable);

        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool IsSystemInfoEnabled(IntPtr instance);

        // 隔离区
        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool EnableQuarantine(IntPtr instance, [MarshalAs(UnmanagedType.I1)] bool enable);

        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool IsQuarantineEnabled(IntPtr instance);

        // 信任区
        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool EnableTrustZone(IntPtr instance, [MarshalAs(UnmanagedType.I1)] bool enable);

        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool IsTrustZoneEnabled(IntPtr instance);

        // 日志中心
        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool EnableLogCenter(IntPtr instance, [MarshalAs(UnmanagedType.I1)] bool enable);

        [DllImport(NATIVE_DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool IsLogCenterEnabled(IntPtr instance);
    }
    #endregion
}
