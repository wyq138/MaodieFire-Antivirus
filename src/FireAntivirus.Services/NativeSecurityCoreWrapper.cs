using System;
using System.Runtime.InteropServices;
using System.Text;

namespace FireAntivirus.Services
{
    /// <summary>
    /// 防护状态枚举
    /// </summary>
    public enum ProtectionState
    {
        Disabled,
        Enabled,
        Error
    }

    /// <summary>
    /// 威胁类型枚举 (Native API 使用)
    /// </summary>
    public enum NativeThreatType
    {
        Unknown,
        FILE_MALICIOUS,
        PROCESS_MALICIOUS,
        DEVICE_UNAUTHORIZED,
        REGISTRY_TAMPERING,
        BROWSER_TAMPERING,
        SCRIPT_MALICIOUS,
        BEHAVIOR_MALICIOUS,
        DISK_TAMPERING,
        UEFI_TAMPERING,
        KERNEL_TAMPERING,
        DOCUMENT_ENCRYPTION,
        NETWORK_MALICIOUS,
        POPUP_AD,
        RANSOMWARE_ACTIVITY,
        PRIVACY_VIOLATION,
        WEB_MALICIOUS,
        EMAIL_PHISHING,
        PASSWORD_WEAK,
        FIREWALL_BLOCKED,
        DEVICE_BLOCKED,
        VULNERABILITY_FOUND,
        CLOUD_THREAT_FOUND,
        BROWSER_VULNERABILITY,
        MOBILE_THREAT,
        SYSTEM_OPTIMIZATION,
        BACKUP_REQUIRED,
        SECURITY_SCORE_LOW,
        NETWORK_TRAFFIC_ANOMALY,
        APPLICATION_ABUSE,
        STARTUP_ITEM_UNAUTHORIZED,
        SECURITY_EVENT,
        BEHAVIOR_SUSPICIOUS,
        SYSTEM_TOOL_OPERATION,
        SYSTEM_INFO_CHANGED,
        QUARANTINE_ITEM,
        TRUST_ZONE_ITEM,
        LOG_EVENT,
        ThreadHijacking,
        ProcessInjection,
        ProcessHollowing,
        PopupAdvertisement,
        PartitionTableModification,
        MBRModification,
        HostsFileModification,
        GPTModification,
        FileIntegrityViolation,
        DNSHijacking,
        BootSectorModification
    }

    /// <summary>
    /// 防护操作枚举
    /// </summary>
    public enum ProtectionAction
    {
        BLOCK,
        ALLOW,
        QUARANTINE,
        DELETE,
        IGNORE,
        REPORT
    }

    /// <summary>
    /// 威胁信息结构体
    /// </summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct ThreatInfo
    {
        public NativeThreatType type;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string processPath;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string targetPath;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string threatDescription;
        public uint processId;
        public uint threadId;
    }

    /// <summary>
    /// 防护状态结构体
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct ProtectionStatus
    {
        public bool fileProtectionEnabled;
        public bool processProtectionEnabled;
        public bool deviceProtectionEnabled;
        public bool registryProtectionEnabled;
        public bool browserProtectionEnabled;
        public bool scriptProtectionEnabled;
        public bool activeDefenseEnabled;
        public bool diskProtectionEnabled;
        public bool uefiProtectionEnabled;
        public bool kernelProtectionEnabled;
        public bool documentProtectionEnabled;
        public bool networkProtectionEnabled;
        public bool popupBlockerEnabled;
        public bool ransomwareProtectionEnabled;
        public bool privacyProtectionEnabled;
        public bool webProtectionEnabled;
        public bool emailSecurityEnabled;
        public bool passwordManagerEnabled;
        public bool networkFirewallEnabled;
        public bool deviceControlEnabled;
        public bool vulnerabilityScannerEnabled;
        public bool cloudScanEnabled;
        public bool secureBrowserEnabled;
        public bool mobileSecurityEnabled;
        public bool systemOptimizerEnabled;
        public bool backupRecoveryEnabled;
        public bool securityScoreEnabled;
        public bool networkTrafficEnabled;
        public bool applicationMonitorEnabled;
        public bool startupManagerEnabled;
        public bool securityReportEnabled;
        public bool behaviorAnalysisEnabled;
        public bool systemToolsEnabled;
        public bool systemInfoEnabled;
        public bool quarantineEnabled;
        public bool trustZoneEnabled;
        public bool logCenterEnabled;
    }

    /// <summary>
    /// 威胁回调委托
    /// </summary>
    /// <param name="threatInfo">威胁信息</param>
    public delegate void ThreatCallback(ThreatInfo threatInfo);

    /// <summary>
    /// 状态回调函数
    /// </summary>
    /// <param name="status">防护状态</param>
    public delegate void StatusCallback(ProtectionState status);

    /// <summary>
    /// NativeSecurityCore.dll 包装类
    /// </summary>
    public class NativeSecurityCoreWrapper
    {
        private const string DllName = "NativeSecurityCore.dll";

        // 获取单例实例
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr GetInstance();

        // 初始化核心库
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool Initialize(IntPtr instance);

        // 启动保护
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool StartProtection(IntPtr instance);

        // 停止保护
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern void StopProtection(IntPtr instance);

        // 检查是否初始化
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool IsInitialized(IntPtr instance);

        // 检查是否正在运行
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool IsRunning(IntPtr instance);

        // 获取当前防护状态
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern ProtectionState GetProtectionStatus(IntPtr instance);

        // 设置威胁回调函数
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern void SetThreatCallback(IntPtr instance, ThreatCallback callback);

        // 设置状态回调函数
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern void SetStatusCallback(IntPtr instance, StatusCallback callback);

        // 处理威胁
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern void HandleThreat(IntPtr instance, ThreatInfo threat, ProtectionAction action);

        // 文件防护
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool EnableFileProtection(IntPtr instance, bool enable);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool IsFileProtectionEnabled(IntPtr instance);

        // 进程防护
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool EnableProcessProtection(IntPtr instance, bool enable);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool IsProcessProtectionEnabled(IntPtr instance);

        // U盘防护
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool EnableDeviceProtection(IntPtr instance, bool enable);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool IsDeviceProtectionEnabled(IntPtr instance);

        // 注册表防护
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool EnableRegistryProtection(IntPtr instance, bool enable);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool IsRegistryProtectionEnabled(IntPtr instance);

        // 浏览器防护
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool EnableBrowserProtection(IntPtr instance, bool enable);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool IsBrowserProtectionEnabled(IntPtr instance);

        // 脚本防护
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool EnableScriptProtection(IntPtr instance, bool enable);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool IsScriptProtectionEnabled(IntPtr instance);

        // 主动防御
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool EnableActiveDefense(IntPtr instance, bool enable);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool IsActiveDefenseEnabled(IntPtr instance);

        // 分区表防护
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool EnableDiskProtection(IntPtr instance, bool enable);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool IsDiskProtectionEnabled(IntPtr instance);

        // UEFI/BIOS防护
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool EnableUEFIProtection(IntPtr instance, bool enable);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool IsUEFIProtectionEnabled(IntPtr instance);

        // 内核防护
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool EnableKernelProtection(IntPtr instance, bool enable);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool IsKernelProtectionEnabled(IntPtr instance);

        // 文档防护
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool EnableDocumentProtection(IntPtr instance, bool enable);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool IsDocumentProtectionEnabled(IntPtr instance);

        // 网络防护
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool EnableNetworkProtection(IntPtr instance, bool enable);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool IsNetworkProtectionEnabled(IntPtr instance);

        // 弹窗拦截
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool EnablePopupBlocker(IntPtr instance, bool enable);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool IsPopupBlockerEnabled(IntPtr instance);

        // 勒索防护
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool EnableRansomwareProtection(IntPtr instance, bool enable);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool IsRansomwareProtectionEnabled(IntPtr instance);

        // 隐私保护
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool EnablePrivacyProtection(IntPtr instance, bool enable);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool IsPrivacyProtectionEnabled(IntPtr instance);

        // 网页防护
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool EnableWebProtection(IntPtr instance, bool enable);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool IsWebProtectionEnabled(IntPtr instance);

        // 邮件安全
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool EnableEmailSecurity(IntPtr instance, bool enable);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool IsEmailSecurityEnabled(IntPtr instance);

        // 密码管理
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool EnablePasswordManager(IntPtr instance, bool enable);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool IsPasswordManagerEnabled(IntPtr instance);

        // 网络防火墙
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool EnableNetworkFirewall(IntPtr instance, bool enable);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool IsNetworkFirewallEnabled(IntPtr instance);

        // 设备控制
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool EnableDeviceControl(IntPtr instance, bool enable);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool IsDeviceControlEnabled(IntPtr instance);

        // 漏洞扫描
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool EnableVulnerabilityScanner(IntPtr instance, bool enable);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool IsVulnerabilityScannerEnabled(IntPtr instance);

        // 云查杀
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool EnableCloudScan(IntPtr instance, bool enable);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool IsCloudScanEnabled(IntPtr instance);

        // 安全浏览器
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool EnableSecureBrowser(IntPtr instance, bool enable);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool IsSecureBrowserEnabled(IntPtr instance);

        // 移动安全
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool EnableMobileSecurity(IntPtr instance, bool enable);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool IsMobileSecurityEnabled(IntPtr instance);

        // 系统优化
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool EnableSystemOptimizer(IntPtr instance, bool enable);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool IsSystemOptimizerEnabled(IntPtr instance);

        // 备份恢复
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool EnableBackupRecovery(IntPtr instance, bool enable);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool IsBackupRecoveryEnabled(IntPtr instance);

        // 安全评分
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool EnableSecurityScore(IntPtr instance, bool enable);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool IsSecurityScoreEnabled(IntPtr instance);

        // 网络流量
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool EnableNetworkTraffic(IntPtr instance, bool enable);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool IsNetworkTrafficEnabled(IntPtr instance);

        // 应用监控
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool EnableApplicationMonitor(IntPtr instance, bool enable);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool IsApplicationMonitorEnabled(IntPtr instance);

        // 启动管理
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool EnableStartupManager(IntPtr instance, bool enable);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool IsStartupManagerEnabled(IntPtr instance);

        // 安全报告
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool EnableSecurityReport(IntPtr instance, bool enable);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool IsSecurityReportEnabled(IntPtr instance);

        // 行为分析
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool EnableBehaviorAnalysis(IntPtr instance, bool enable);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool IsBehaviorAnalysisEnabled(IntPtr instance);

        // 系统工具
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool EnableSystemTools(IntPtr instance, bool enable);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool IsSystemToolsEnabled(IntPtr instance);

        // 系统信息
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool EnableSystemInfo(IntPtr instance, bool enable);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool IsSystemInfoEnabled(IntPtr instance);

        // 隔离区
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool EnableQuarantine(IntPtr instance, bool enable);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool IsQuarantineEnabled(IntPtr instance);

        // 信任区
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool EnableTrustZone(IntPtr instance, bool enable);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool IsTrustZoneEnabled(IntPtr instance);

        // 日志中心
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool EnableLogCenter(IntPtr instance, bool enable);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool IsLogCenterEnabled(IntPtr instance);

        private static IntPtr _instance;
        private static readonly object _lock = new object();

        /// <summary>
        /// 获取单例实例
        /// </summary>
        public static IntPtr Instance
        {
            get
            {
                if (_instance == IntPtr.Zero)
                {
                    lock (_lock)
                    {
                        if (_instance == IntPtr.Zero)
                        {
                            _instance = GetInstance();
                        }
                    }
                }
                return _instance;
            }
        }

        /// <summary>
        /// 初始化核心库
        /// </summary>
        public static bool InitializeCore()
        {
            return Initialize(Instance);
        }

        /// <summary>
        /// 启动保护
        /// </summary>
        public static bool StartProtectionCore()
        {
            return StartProtection(Instance);
        }

        /// <summary>
        /// 停止保护
        /// </summary>
        public static void StopProtectionCore()
        {
            StopProtection(Instance);
        }

        /// <summary>
        /// 检查是否初始化
        /// </summary>
        public static bool IsInitializedCore()
        {
            return IsInitialized(Instance);
        }

        /// <summary>
        /// 检查是否正在运行
        /// </summary>
        public static bool IsRunningCore()
        {
            return IsRunning(Instance);
        }

        /// <summary>
        /// 获取当前防护状态
        /// </summary>
        public static ProtectionState GetProtectionStatusCore()
        {
            return GetProtectionStatus(Instance);
        }

        /// <summary>
        /// 设置威胁回调函数
        /// </summary>
        public static void SetThreatCallbackCore(ThreatCallback callback)
        {
            SetThreatCallback(Instance, callback);
        }

        /// <summary>
        /// 设置状态回调函数
        /// </summary>
        public static void SetStatusCallbackCore(StatusCallback callback)
        {
            SetStatusCallback(Instance, callback);
        }

        /// <summary>
        /// 处理威胁
        /// </summary>
        public static void HandleThreatCore(ThreatInfo threat, ProtectionAction action)
        {
            HandleThreat(Instance, threat, action);
        }

        /// <summary>
        /// 启用/禁用文件防护
        /// </summary>
        public static bool EnableFileProtectionCore(bool enable)
        {
            return EnableFileProtection(Instance, enable);
        }

        /// <summary>
        /// 检查文件防护是否启用
        /// </summary>
        public static bool IsFileProtectionEnabledCore()
        {
            return IsFileProtectionEnabled(Instance);
        }

        /// <summary>
        /// 启用/禁用进程防护
        /// </summary>
        public static bool EnableProcessProtectionCore(bool enable)
        {
            return EnableProcessProtection(Instance, enable);
        }

        /// <summary>
        /// 检查进程防护是否启用
        /// </summary>
        public static bool IsProcessProtectionEnabledCore()
        {
            return IsProcessProtectionEnabled(Instance);
        }

        /// <summary>
        /// 启用/禁用U盘防护
        /// </summary>
        public static bool EnableDeviceProtectionCore(bool enable)
        {
            return EnableDeviceProtection(Instance, enable);
        }

        /// <summary>
        /// 检查U盘防护是否启用
        /// </summary>
        public static bool IsDeviceProtectionEnabledCore()
        {
            return IsDeviceProtectionEnabled(Instance);
        }

        /// <summary>
        /// 启用/禁用注册表防护
        /// </summary>
        public static bool EnableRegistryProtectionCore(bool enable)
        {
            return EnableRegistryProtection(Instance, enable);
        }

        /// <summary>
        /// 检查注册表防护是否启用
        /// </summary>
        public static bool IsRegistryProtectionEnabledCore()
        {
            return IsRegistryProtectionEnabled(Instance);
        }

        /// <summary>
        /// 启用/禁用浏览器防护
        /// </summary>
        public static bool EnableBrowserProtectionCore(bool enable)
        {
            return EnableBrowserProtection(Instance, enable);
        }

        /// <summary>
        /// 检查浏览器防护是否启用
        /// </summary>
        public static bool IsBrowserProtectionEnabledCore()
        {
            return IsBrowserProtectionEnabled(Instance);
        }

        /// <summary>
        /// 启用/禁用脚本防护
        /// </summary>
        public static bool EnableScriptProtectionCore(bool enable)
        {
            return EnableScriptProtection(Instance, enable);
        }

        /// <summary>
        /// 检查脚本防护是否启用
        /// </summary>
        public static bool IsScriptProtectionEnabledCore()
        {
            return IsScriptProtectionEnabled(Instance);
        }

        /// <summary>
        /// 启用/禁用主动防御
        /// </summary>
        public static bool EnableActiveDefenseCore(bool enable)
        {
            return EnableActiveDefense(Instance, enable);
        }

        /// <summary>
        /// 检查主动防御是否启用
        /// </summary>
        public static bool IsActiveDefenseEnabledCore()
        {
            return IsActiveDefenseEnabled(Instance);
        }

        /// <summary>
        /// 启用/禁用分区表防护
        /// </summary>
        public static bool EnableDiskProtectionCore(bool enable)
        {
            return EnableDiskProtection(Instance, enable);
        }

        /// <summary>
        /// 检查分区表防护是否启用
        /// </summary>
        public static bool IsDiskProtectionEnabledCore()
        {
            return IsDiskProtectionEnabled(Instance);
        }

        /// <summary>
        /// 启用/禁用UEFI/BIOS防护
        /// </summary>
        public static bool EnableUEFIProtectionCore(bool enable)
        {
            return EnableUEFIProtection(Instance, enable);
        }

        /// <summary>
        /// 检查UEFI/BIOS防护是否启用
        /// </summary>
        public static bool IsUEFIProtectionEnabledCore()
        {
            return IsUEFIProtectionEnabled(Instance);
        }

        /// <summary>
        /// 启用/禁用内核防护
        /// </summary>
        public static bool EnableKernelProtectionCore(bool enable)
        {
            return EnableKernelProtection(Instance, enable);
        }

        /// <summary>
        /// 检查内核防护是否启用
        /// </summary>
        public static bool IsKernelProtectionEnabledCore()
        {
            return IsKernelProtectionEnabled(Instance);
        }

        /// <summary>
        /// 启用/禁用文档防护
        /// </summary>
        public static bool EnableDocumentProtectionCore(bool enable)
        {
            return EnableDocumentProtection(Instance, enable);
        }

        /// <summary>
        /// 检查文档防护是否启用
        /// </summary>
        public static bool IsDocumentProtectionEnabledCore()
        {
            return IsDocumentProtectionEnabled(Instance);
        }

        /// <summary>
        /// 启用/禁用网络防护
        /// </summary>
        public static bool EnableNetworkProtectionCore(bool enable)
        {
            return EnableNetworkProtection(Instance, enable);
        }

        /// <summary>
        /// 检查网络防护是否启用
        /// </summary>
        public static bool IsNetworkProtectionEnabledCore()
        {
            return IsNetworkProtectionEnabled(Instance);
        }

        /// <summary>
        /// 启用/禁用弹窗拦截
        /// </summary>
        public static bool EnablePopupBlockerCore(bool enable)
        {
            return EnablePopupBlocker(Instance, enable);
        }

        /// <summary>
        /// 检查弹窗拦截是否启用
        /// </summary>
        public static bool IsPopupBlockerEnabledCore()
        {
            return IsPopupBlockerEnabled(Instance);
        }

        /// <summary>
        /// 启用/禁用勒索防护
        /// </summary>
        public static bool EnableRansomwareProtectionCore(bool enable)
        {
            return EnableRansomwareProtection(Instance, enable);
        }

        /// <summary>
        /// 检查勒索防护是否启用
        /// </summary>
        public static bool IsRansomwareProtectionEnabledCore()
        {
            return IsRansomwareProtectionEnabled(Instance);
        }

        /// <summary>
        /// 启用/禁用隐私保护
        /// </summary>
        public static bool EnablePrivacyProtectionCore(bool enable)
        {
            return EnablePrivacyProtection(Instance, enable);
        }

        /// <summary>
        /// 检查隐私保护是否启用
        /// </summary>
        public static bool IsPrivacyProtectionEnabledCore()
        {
            return IsPrivacyProtectionEnabled(Instance);
        }

        /// <summary>
        /// 启用/禁用网页防护
        /// </summary>
        public static bool EnableWebProtectionCore(bool enable)
        {
            return EnableWebProtection(Instance, enable);
        }

        /// <summary>
        /// 检查网页防护是否启用
        /// </summary>
        public static bool IsWebProtectionEnabledCore()
        {
            return IsWebProtectionEnabled(Instance);
        }

        /// <summary>
        /// 启用/禁用邮件安全
        /// </summary>
        public static bool EnableEmailSecurityCore(bool enable)
        {
            return EnableEmailSecurity(Instance, enable);
        }

        /// <summary>
        /// 检查邮件安全是否启用
        /// </summary>
        public static bool IsEmailSecurityEnabledCore()
        {
            return IsEmailSecurityEnabled(Instance);
        }

        /// <summary>
        /// 启用/禁用密码管理
        /// </summary>
        public static bool EnablePasswordManagerCore(bool enable)
        {
            return EnablePasswordManager(Instance, enable);
        }

        /// <summary>
        /// 检查密码管理是否启用
        /// </summary>
        public static bool IsPasswordManagerEnabledCore()
        {
            return IsPasswordManagerEnabled(Instance);
        }

        /// <summary>
        /// 启用/禁用网络防火墙
        /// </summary>
        public static bool EnableNetworkFirewallCore(bool enable)
        {
            return EnableNetworkFirewall(Instance, enable);
        }

        /// <summary>
        /// 检查网络防火墙是否启用
        /// </summary>
        public static bool IsNetworkFirewallEnabledCore()
        {
            return IsNetworkFirewallEnabled(Instance);
        }

        /// <summary>
        /// 启用/禁用设备控制
        /// </summary>
        public static bool EnableDeviceControlCore(bool enable)
        {
            return EnableDeviceControl(Instance, enable);
        }

        /// <summary>
        /// 检查设备控制是否启用
        /// </summary>
        public static bool IsDeviceControlEnabledCore()
        {
            return IsDeviceControlEnabled(Instance);
        }

        /// <summary>
        /// 启用/禁用漏洞扫描
        /// </summary>
        public static bool EnableVulnerabilityScannerCore(bool enable)
        {
            return EnableVulnerabilityScanner(Instance, enable);
        }

        /// <summary>
        /// 检查漏洞扫描是否启用
        /// </summary>
        public static bool IsVulnerabilityScannerEnabledCore()
        {
            return IsVulnerabilityScannerEnabled(Instance);
        }

        /// <summary>
        /// 启用/禁用云查杀
        /// </summary>
        public static bool EnableCloudScanCore(bool enable)
        {
            return EnableCloudScan(Instance, enable);
        }

        /// <summary>
        /// 检查云查杀是否启用
        /// </summary>
        public static bool IsCloudScanEnabledCore()
        {
            return IsCloudScanEnabled(Instance);
        }

        /// <summary>
        /// 启用/禁用安全浏览器
        /// </summary>
        public static bool EnableSecureBrowserCore(bool enable)
        {
            return EnableSecureBrowser(Instance, enable);
        }

        /// <summary>
        /// 检查安全浏览器是否启用
        /// </summary>
        public static bool IsSecureBrowserEnabledCore()
        {
            return IsSecureBrowserEnabled(Instance);
        }

        /// <summary>
        /// 启用/禁用移动安全
        /// </summary>
        public static bool EnableMobileSecurityCore(bool enable)
        {
            return EnableMobileSecurity(Instance, enable);
        }

        /// <summary>
        /// 检查移动安全是否启用
        /// </summary>
        public static bool IsMobileSecurityEnabledCore()
        {
            return IsMobileSecurityEnabled(Instance);
        }

        /// <summary>
        /// 启用/禁用系统优化
        /// </summary>
        public static bool EnableSystemOptimizerCore(bool enable)
        {
            return EnableSystemOptimizer(Instance, enable);
        }

        /// <summary>
        /// 检查系统优化是否启用
        /// </summary>
        public static bool IsSystemOptimizerEnabledCore()
        {
            return IsSystemOptimizerEnabled(Instance);
        }

        /// <summary>
        /// 启用/禁用备份恢复
        /// </summary>
        public static bool EnableBackupRecoveryCore(bool enable)
        {
            return EnableBackupRecovery(Instance, enable);
        }

        /// <summary>
        /// 检查备份恢复是否启用
        /// </summary>
        public static bool IsBackupRecoveryEnabledCore()
        {
            return IsBackupRecoveryEnabled(Instance);
        }

        /// <summary>
        /// 启用/禁用安全评分
        /// </summary>
        public static bool EnableSecurityScoreCore(bool enable)
        {
            return EnableSecurityScore(Instance, enable);
        }

        /// <summary>
        /// 检查安全评分是否启用
        /// </summary>
        public static bool IsSecurityScoreEnabledCore()
        {
            return IsSecurityScoreEnabled(Instance);
        }

        /// <summary>
        /// 启用/禁用网络流量
        /// </summary>
        public static bool EnableNetworkTrafficCore(bool enable)
        {
            return EnableNetworkTraffic(Instance, enable);
        }

        /// <summary>
        /// 检查网络流量是否启用
        /// </summary>
        public static bool IsNetworkTrafficEnabledCore()
        {
            return IsNetworkTrafficEnabled(Instance);
        }

        /// <summary>
        /// 启用/禁用应用监控
        /// </summary>
        public static bool EnableApplicationMonitorCore(bool enable)
        {
            return EnableApplicationMonitor(Instance, enable);
        }

        /// <summary>
        /// 检查应用监控是否启用
        /// </summary>
        public static bool IsApplicationMonitorEnabledCore()
        {
            return IsApplicationMonitorEnabled(Instance);
        }

        /// <summary>
        /// 启用/禁用启动管理
        /// </summary>
        public static bool EnableStartupManagerCore(bool enable)
        {
            return EnableStartupManager(Instance, enable);
        }

        /// <summary>
        /// 检查启动管理是否启用
        /// </summary>
        public static bool IsStartupManagerEnabledCore()
        {
            return IsStartupManagerEnabled(Instance);
        }

        /// <summary>
        /// 启用/禁用安全报告
        /// </summary>
        public static bool EnableSecurityReportCore(bool enable)
        {
            return EnableSecurityReport(Instance, enable);
        }

        /// <summary>
        /// 检查安全报告是否启用
        /// </summary>
        public static bool IsSecurityReportEnabledCore()
        {
            return IsSecurityReportEnabled(Instance);
        }

        /// <summary>
        /// 启用/禁用行为分析
        /// </summary>
        public static bool EnableBehaviorAnalysisCore(bool enable)
        {
            return EnableBehaviorAnalysis(Instance, enable);
        }

        /// <summary>
        /// 检查行为分析是否启用
        /// </summary>
        public static bool IsBehaviorAnalysisEnabledCore()
        {
            return IsBehaviorAnalysisEnabled(Instance);
        }

        /// <summary>
        /// 启用/禁用系统工具
        /// </summary>
        public static bool EnableSystemToolsCore(bool enable)
        {
            return EnableSystemTools(Instance, enable);
        }

        /// <summary>
        /// 检查系统工具是否启用
        /// </summary>
        public static bool IsSystemToolsEnabledCore()
        {
            return IsSystemToolsEnabled(Instance);
        }

        /// <summary>
        /// 启用/禁用系统信息
        /// </summary>
        public static bool EnableSystemInfoCore(bool enable)
        {
            return EnableSystemInfo(Instance, enable);
        }

        /// <summary>
        /// 检查系统信息是否启用
        /// </summary>
        public static bool IsSystemInfoEnabledCore()
        {
            return IsSystemInfoEnabled(Instance);
        }

        /// <summary>
        /// 启用/禁用隔离区
        /// </summary>
        public static bool EnableQuarantineCore(bool enable)
        {
            return EnableQuarantine(Instance, enable);
        }

        /// <summary>
        /// 检查隔离区是否启用
        /// </summary>
        public static bool IsQuarantineEnabledCore()
        {
            return IsQuarantineEnabled(Instance);
        }

        /// <summary>
        /// 启用/禁用信任区
        /// </summary>
        public static bool EnableTrustZoneCore(bool enable)
        {
            return EnableTrustZone(Instance, enable);
        }

        /// <summary>
        /// 检查信任区是否启用
        /// </summary>
        public static bool IsTrustZoneEnabledCore()
        {
            return IsTrustZoneEnabled(Instance);
        }

        /// <summary>
        /// 启用/禁用日志中心
        /// </summary>
        public static bool EnableLogCenterCore(bool enable)
        {
            return EnableLogCenter(Instance, enable);
        }

        /// <summary>
        /// 检查日志中心是否启用
        /// </summary>
        public static bool IsLogCenterEnabledCore()
        {
            return IsLogCenterEnabled(Instance);
        }

        /// <summary>
        /// 将 NativeThreatType 显式转换为 ThreatType
        /// </summary>
        public static ThreatType ConvertToThreatType(NativeThreatType nativeType)
        {
            return nativeType switch
            {
                NativeThreatType.Unknown => ThreatType.Unknown,
                NativeThreatType.FILE_MALICIOUS => ThreatType.Malware,
                NativeThreatType.PROCESS_MALICIOUS => ThreatType.SuspiciousActivity,
                NativeThreatType.DEVICE_UNAUTHORIZED => ThreatType.SuspiciousActivity,
                NativeThreatType.REGISTRY_TAMPERING => ThreatType.SuspiciousActivity,
                NativeThreatType.BROWSER_TAMPERING => ThreatType.SuspiciousActivity,
                NativeThreatType.SCRIPT_MALICIOUS => ThreatType.Exploit,
                NativeThreatType.BEHAVIOR_MALICIOUS => ThreatType.SuspiciousActivity,
                NativeThreatType.DISK_TAMPERING => ThreatType.PartitionTableModification,
                NativeThreatType.UEFI_TAMPERING => ThreatType.SuspiciousActivity,
                NativeThreatType.KERNEL_TAMPERING => ThreatType.Rootkit,
                NativeThreatType.DOCUMENT_ENCRYPTION => ThreatType.Ransomware,
                NativeThreatType.NETWORK_MALICIOUS => ThreatType.BotnetCommunication,
                NativeThreatType.POPUP_AD => ThreatType.Adware,
                NativeThreatType.RANSOMWARE_ACTIVITY => ThreatType.Ransomware,
                NativeThreatType.PRIVACY_VIOLATION => ThreatType.Spyware,
                NativeThreatType.WEB_MALICIOUS => ThreatType.Phishing,
                NativeThreatType.EMAIL_PHISHING => ThreatType.Phishing,
                NativeThreatType.PASSWORD_WEAK => ThreatType.Warning,
                NativeThreatType.FIREWALL_BLOCKED => ThreatType.Warning,
                NativeThreatType.DEVICE_BLOCKED => ThreatType.Warning,
                NativeThreatType.VULNERABILITY_FOUND => ThreatType.Warning,
                NativeThreatType.CLOUD_THREAT_FOUND => ThreatType.KnownMalicious,
                NativeThreatType.BROWSER_VULNERABILITY => ThreatType.Warning,
                NativeThreatType.MOBILE_THREAT => ThreatType.SuspiciousActivity,
                NativeThreatType.SYSTEM_OPTIMIZATION => ThreatType.Info,
                NativeThreatType.BACKUP_REQUIRED => ThreatType.Warning,
                NativeThreatType.SECURITY_SCORE_LOW => ThreatType.Warning,
                NativeThreatType.NETWORK_TRAFFIC_ANOMALY => ThreatType.DataExfiltration,
                NativeThreatType.APPLICATION_ABUSE => ThreatType.SuspiciousActivity,
                NativeThreatType.STARTUP_ITEM_UNAUTHORIZED => ThreatType.SuspiciousActivity,
                NativeThreatType.SECURITY_EVENT => ThreatType.Info,
                NativeThreatType.BEHAVIOR_SUSPICIOUS => ThreatType.SuspiciousActivity,
                NativeThreatType.SYSTEM_TOOL_OPERATION => ThreatType.Info,
                NativeThreatType.SYSTEM_INFO_CHANGED => ThreatType.Info,
                NativeThreatType.QUARANTINE_ITEM => ThreatType.Quarantine,
                NativeThreatType.TRUST_ZONE_ITEM => ThreatType.Info,
                NativeThreatType.LOG_EVENT => ThreatType.Info,
                NativeThreatType.ThreadHijacking => ThreatType.SuspiciousActivity,
                NativeThreatType.ProcessInjection => ThreatType.Trojan,
                NativeThreatType.ProcessHollowing => ThreatType.Trojan,
                NativeThreatType.PopupAdvertisement => ThreatType.Adware,
                NativeThreatType.PartitionTableModification => ThreatType.PartitionTableModification,
                NativeThreatType.MBRModification => ThreatType.MBRModification,
                NativeThreatType.HostsFileModification => ThreatType.SuspiciousActivity,
                NativeThreatType.GPTModification => ThreatType.GPTModification,
                NativeThreatType.FileIntegrityViolation => ThreatType.FileIntegrityViolation,
                NativeThreatType.DNSHijacking => ThreatType.BotnetCommunication,
                NativeThreatType.BootSectorModification => ThreatType.BootSectorModification,
                _ => ThreatType.Unknown
            };
        }
    }
}