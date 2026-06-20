using System;

namespace FireAntivirus.Services
{
    /// <summary>
    /// 侧边栏服务管理类
    /// </summary>
    public class SidebarServices
    {
        private readonly SecurityService _securityService;
        private readonly FireAntivirus.Data.DataManager _dataManager;
        private SidebarNetworkProtectionService _networkProtectionService;
        private SidebarPopupBlockerService _popupBlockerService;
        private SidebarRansomwareProtectionService _ransomwareProtectionService;
        private SidebarPrivacyProtectionService _privacyProtectionService;
        private SidebarWebProtectionService _webProtectionService;
        private SidebarEmailSecurityService _emailSecurityService;
        private SidebarPasswordManagerService _passwordManagerService;
        private SidebarNetworkFirewallService _networkFirewallService;
        private SidebarDeviceControlService _deviceControlService;
        private SidebarVulnerabilityScannerService _vulnerabilityScannerService;
        private SidebarCloudScanService _cloudScanService;
        private SidebarSecureBrowserService _secureBrowserService;
        private SidebarMobileSecurityService _mobileSecurityService;
        private SidebarSystemOptimizerService _systemOptimizerService;
        private SidebarBackupRecoveryService _backupRecoveryService;
        private SidebarSecurityScoreService _securityScoreService;
        private SidebarNetworkTrafficService _networkTrafficService;
        private SidebarApplicationMonitorService _applicationMonitorService;
        private SidebarStartupManagerService _startupManagerService;
        private SidebarSecurityReportService _securityReportService;
        private SidebarBehaviorAnalysisService _behaviorAnalysisService;
        private SidebarSystemToolsService _systemToolsService;
        private SidebarSystemInfoService _systemInfoService;
        private SidebarQuarantineService _quarantineService;
        private SidebarTrustZoneService _trustZoneService;
        private SidebarLogCenterService _logCenterService;

        /// <summary>
        /// 构造函数
        /// </summary>
        /// <param name="securityService">安全服务</param>
        /// <param name="dataManager">数据管理器</param>
        public SidebarServices(SecurityService securityService, FireAntivirus.Data.DataManager dataManager)
        {
            _securityService = securityService;
            _dataManager = dataManager;
        }

        /// <summary>
        /// 初始化侧边栏服务
        /// </summary>
        public void Initialize()
        {
            // 初始化各服务
            _networkProtectionService = new SidebarNetworkProtectionService(_securityService);
            _popupBlockerService = new SidebarPopupBlockerService(_securityService);
            _ransomwareProtectionService = new SidebarRansomwareProtectionService(_securityService);
            _privacyProtectionService = new SidebarPrivacyProtectionService(_securityService);
            _webProtectionService = new SidebarWebProtectionService(_securityService);
            _emailSecurityService = new SidebarEmailSecurityService(_securityService);
            _passwordManagerService = new SidebarPasswordManagerService(_securityService);
            _networkFirewallService = new SidebarNetworkFirewallService(_securityService);
            _deviceControlService = new SidebarDeviceControlService(_dataManager);
            _vulnerabilityScannerService = new SidebarVulnerabilityScannerService(_securityService);
            _cloudScanService = new SidebarCloudScanService(_securityService);
            _secureBrowserService = new SidebarSecureBrowserService(_securityService);
            _mobileSecurityService = new SidebarMobileSecurityService(_securityService);
            _systemOptimizerService = new SidebarSystemOptimizerService(_securityService);
            _backupRecoveryService = new SidebarBackupRecoveryService(_securityService);
            _securityScoreService = new SidebarSecurityScoreService(_securityService);
            _networkTrafficService = new SidebarNetworkTrafficService(_securityService);
            _applicationMonitorService = new SidebarApplicationMonitorService(_securityService);
            _startupManagerService = new SidebarStartupManagerService(_securityService);
            _securityReportService = new SidebarSecurityReportService(_securityService);
            _behaviorAnalysisService = new SidebarBehaviorAnalysisService(_dataManager);
            _systemToolsService = new SidebarSystemToolsService(_securityService);
            _systemInfoService = new SidebarSystemInfoService(_securityService);
            _quarantineService = new SidebarQuarantineService(_securityService);
            _trustZoneService = new SidebarTrustZoneService(_securityService);
            _logCenterService = new SidebarLogCenterService(_securityService);

            LogManager.LogInfo("Sidebar services initialized");
        }

        /// <summary>
        /// 网络防护服务
        /// </summary>
        public SidebarNetworkProtectionService NetworkProtection => _networkProtectionService;

        /// <summary>
        /// 弹窗拦截服务
        /// </summary>
        public SidebarPopupBlockerService PopupBlocker => _popupBlockerService;

        /// <summary>
        /// 勒索防护服务
        /// </summary>
        public SidebarRansomwareProtectionService RansomwareProtection => _ransomwareProtectionService;

        /// <summary>
        /// 隐私保护服务
        /// </summary>
        public SidebarPrivacyProtectionService PrivacyProtection => _privacyProtectionService;

        /// <summary>
        /// 网页防护服务
        /// </summary>
        public SidebarWebProtectionService WebProtection => _webProtectionService;

        /// <summary>
        /// 邮件安全服务
        /// </summary>
        public SidebarEmailSecurityService EmailSecurity => _emailSecurityService;

        /// <summary>
        /// 密码管理服务
        /// </summary>
        public SidebarPasswordManagerService PasswordManager => _passwordManagerService;

        /// <summary>
        /// 网络防火墙服务
        /// </summary>
        public SidebarNetworkFirewallService NetworkFirewall => _networkFirewallService;

        /// <summary>
        /// 设备控制服务
        /// </summary>
        public SidebarDeviceControlService DeviceControl => _deviceControlService;

        /// <summary>
        /// 漏洞扫描服务
        /// </summary>
        public SidebarVulnerabilityScannerService VulnerabilityScanner => _vulnerabilityScannerService;

        /// <summary>
        /// 云查杀服务
        /// </summary>
        public SidebarCloudScanService CloudScan => _cloudScanService;

        /// <summary>
        /// 安全浏览器服务
        /// </summary>
        public SidebarSecureBrowserService SecureBrowser => _secureBrowserService;

        /// <summary>
        /// 移动安全服务
        /// </summary>
        public SidebarMobileSecurityService MobileSecurity => _mobileSecurityService;

        /// <summary>
        /// 系统优化服务
        /// </summary>
        public SidebarSystemOptimizerService SystemOptimizer => _systemOptimizerService;

        /// <summary>
        /// 备份恢复服务
        /// </summary>
        public SidebarBackupRecoveryService BackupRecovery => _backupRecoveryService;

        /// <summary>
        /// 安全评分服务
        /// </summary>
        public SidebarSecurityScoreService SecurityScore => _securityScoreService;

        /// <summary>
        /// 网络流量服务
        /// </summary>
        public SidebarNetworkTrafficService NetworkTraffic => _networkTrafficService;

        /// <summary>
        /// 应用监控服务
        /// </summary>
        public SidebarApplicationMonitorService ApplicationMonitor => _applicationMonitorService;

        /// <summary>
        /// 启动管理服务
        /// </summary>
        public SidebarStartupManagerService StartupManager => _startupManagerService;

        /// <summary>
        /// 安全报告服务
        /// </summary>
        public SidebarSecurityReportService SecurityReport => _securityReportService;

        /// <summary>
        /// 行为分析服务
        /// </summary>
        public SidebarBehaviorAnalysisService BehaviorAnalysis => _behaviorAnalysisService;

        /// <summary>
        /// 系统工具服务
        /// </summary>
        public SidebarSystemToolsService SystemTools => _systemToolsService;

        /// <summary>
        /// 系统信息服务
        /// </summary>
        public SidebarSystemInfoService SystemInfo => _systemInfoService;

        /// <summary>
        /// 隔离区服务
        /// </summary>
        public SidebarQuarantineService Quarantine => _quarantineService;

        /// <summary>
        /// 信任区服务
        /// </summary>
        public SidebarTrustZoneService TrustZone => _trustZoneService;

        /// <summary>
        /// 日志中心服务
        /// </summary>
        public SidebarLogCenterService LogCenter => _logCenterService;
    }

    #region 侧边栏服务包装类

    /// <summary>
    /// 网络防护服务
    /// </summary>
    public class SidebarNetworkProtectionService
    {
        private readonly SecurityService _securityService;

        public SidebarNetworkProtectionService(SecurityService securityService)
        {
            _securityService = securityService;
        }

        public bool Enable(bool enable)
        {
            bool result = _securityService.EnableNetworkProtection(enable);
            if (result)
            {
                AppConfig config = ConfigManager.Config;
                config.NetworkProtectionEnabled = enable;
                ConfigManager.SaveConfig();
                LogManager.LogInfo($"Network protection {(enable ? "enabled" : "disabled")}");
            }
            return result;
        }

        public bool IsEnabled()
        {
            return _securityService.IsNetworkProtectionEnabled();
        }
    }

    /// <summary>
    /// 弹窗拦截服务
    /// </summary>
    public class SidebarPopupBlockerService
    {
        private readonly SecurityService _securityService;

        public SidebarPopupBlockerService(SecurityService securityService)
        {
            _securityService = securityService;
        }

        public bool Enable(bool enable)
        {
            bool result = _securityService.EnablePopupBlocker(enable);
            if (result)
            {
                AppConfig config = ConfigManager.Config;
                config.PopupBlockerEnabled = enable;
                ConfigManager.SaveConfig();
                LogManager.LogInfo($"Popup blocker {(enable ? "enabled" : "disabled")}");
            }
            return result;
        }

        public bool IsEnabled()
        {
            return _securityService.IsPopupBlockerEnabled();
        }
    }

    /// <summary>
    /// 勒索防护服务
    /// </summary>
    public class SidebarRansomwareProtectionService
    {
        private readonly SecurityService _securityService;

        public SidebarRansomwareProtectionService(SecurityService securityService)
        {
            _securityService = securityService;
        }

        public bool Enable(bool enable)
        {
            bool result = _securityService.EnableRansomwareProtection(enable);
            if (result)
            {
                AppConfig config = ConfigManager.Config;
                config.RansomwareProtectionEnabled = enable;
                ConfigManager.SaveConfig();
                LogManager.LogInfo($"Ransomware protection {(enable ? "enabled" : "disabled")}");
            }
            return result;
        }

        public bool IsEnabled()
        {
            return _securityService.IsRansomwareProtectionEnabled();
        }
    }

    /// <summary>
    /// 隐私保护服务
    /// </summary>
    public class SidebarPrivacyProtectionService
    {
        private readonly SecurityService _securityService;

        public SidebarPrivacyProtectionService(SecurityService securityService)
        {
            _securityService = securityService;
        }

        public bool Enable(bool enable)
        {
            bool result = _securityService.EnablePrivacyProtection(enable);
            if (result)
            {
                AppConfig config = ConfigManager.Config;
                config.PrivacyProtectionEnabled = enable;
                ConfigManager.SaveConfig();
                LogManager.LogInfo($"Privacy protection {(enable ? "enabled" : "disabled")}");
            }
            return result;
        }

        public bool IsEnabled()
        {
            return _securityService.IsPrivacyProtectionEnabled();
        }
    }

    /// <summary>
    /// 网页防护服务
    /// </summary>
    public class SidebarWebProtectionService
    {
        private readonly SecurityService _securityService;

        public SidebarWebProtectionService(SecurityService securityService)
        {
            _securityService = securityService;
        }

        public bool Enable(bool enable)
        {
            bool result = _securityService.EnableWebProtection(enable);
            if (result)
            {
                AppConfig config = ConfigManager.Config;
                config.WebProtectionEnabled = enable;
                ConfigManager.SaveConfig();
                LogManager.LogInfo($"Web protection {(enable ? "enabled" : "disabled")}");
            }
            return result;
        }

        public bool IsEnabled()
        {
            return _securityService.IsWebProtectionEnabled();
        }
    }

    /// <summary>
    /// 邮件安全服务
    /// </summary>
    public class SidebarEmailSecurityService
    {
        private readonly SecurityService _securityService;

        public SidebarEmailSecurityService(SecurityService securityService)
        {
            _securityService = securityService;
        }

        public bool Enable(bool enable)
        {
            bool result = _securityService.EnableEmailSecurity(enable);
            if (result)
            {
                AppConfig config = ConfigManager.Config;
                config.EmailSecurityEnabled = enable;
                ConfigManager.SaveConfig();
                LogManager.LogInfo($"Email security {(enable ? "enabled" : "disabled")}");
            }
            return result;
        }

        public bool IsEnabled()
        {
            return _securityService.IsEmailSecurityEnabled();
        }
    }

    /// <summary>
    /// 密码管理服务
    /// </summary>
    public class SidebarPasswordManagerService
    {
        private readonly SecurityService _securityService;

        public SidebarPasswordManagerService(SecurityService securityService)
        {
            _securityService = securityService;
        }

        public bool Enable(bool enable)
        {
            bool result = _securityService.EnablePasswordManager(enable);
            if (result)
            {
                AppConfig config = ConfigManager.Config;
                config.PasswordManagerEnabled = enable;
                ConfigManager.SaveConfig();
                LogManager.LogInfo($"Password manager {(enable ? "enabled" : "disabled")}");
            }
            return result;
        }

        public bool IsEnabled()
        {
            return _securityService.IsPasswordManagerEnabled();
        }
    }

    /// <summary>
    /// 网络防火墙服务
    /// </summary>
    public class SidebarNetworkFirewallService
    {
        private readonly SecurityService _securityService;

        public SidebarNetworkFirewallService(SecurityService securityService)
        {
            _securityService = securityService;
        }

        public bool Enable(bool enable)
        {
            bool result = _securityService.EnableNetworkFirewall(enable);
            if (result)
            {
                AppConfig config = ConfigManager.Config;
                config.NetworkFirewallEnabled = enable;
                ConfigManager.SaveConfig();
                LogManager.LogInfo($"Network firewall {(enable ? "enabled" : "disabled")}");
            }
            return result;
        }

        public bool IsEnabled()
        {
            return _securityService.IsNetworkFirewallEnabled();
        }
    }

    /// <summary>
    /// 设备控制服务
    /// </summary>
    public class SidebarDeviceControlService
    {
        private readonly FireAntivirus.Data.DataManager _dataManager;

        public SidebarDeviceControlService(FireAntivirus.Data.DataManager dataManager)
        {
            _dataManager = dataManager;
        }

        public bool Enable(bool enable)
        {
            AppConfig config = ConfigManager.Config;
            config.DeviceControlEnabled = enable;
            ConfigManager.SaveConfig();
            LogManager.LogInfo($"Device control {(enable ? "enabled" : "disabled")}");
            return true;
        }

        public bool IsEnabled()
        {
            return ConfigManager.Config.DeviceControlEnabled;
        }
    }

    /// <summary>
    /// 漏洞扫描服务
    /// </summary>
    public class SidebarVulnerabilityScannerService
    {
        private readonly SecurityService _securityService;

        public SidebarVulnerabilityScannerService(SecurityService securityService)
        {
            _securityService = securityService;
        }

        public bool Enable(bool enable)
        {
            bool result = _securityService.EnableVulnerabilityScanner(enable);
            if (result)
            {
                AppConfig config = ConfigManager.Config;
                config.VulnerabilityScannerEnabled = enable;
                ConfigManager.SaveConfig();
                LogManager.LogInfo($"Vulnerability scanner {(enable ? "enabled" : "disabled")}");
            }
            return result;
        }

        public bool IsEnabled()
        {
            return _securityService.IsVulnerabilityScannerEnabled();
        }
    }

    /// <summary>
    /// 云查杀服务
    /// </summary>
    public class SidebarCloudScanService
    {
        private readonly SecurityService _securityService;

        public SidebarCloudScanService(SecurityService securityService)
        {
            _securityService = securityService;
        }

        public bool Enable(bool enable)
        {
            bool result = _securityService.EnableCloudScan(enable);
            if (result)
            {
                AppConfig config = ConfigManager.Config;
                config.CloudScanEnabled = enable;
                ConfigManager.SaveConfig();
                LogManager.LogInfo($"Cloud scan {(enable ? "enabled" : "disabled")}");
            }
            return result;
        }

        public bool IsEnabled()
        {
            return _securityService.IsCloudScanEnabled();
        }
    }

    /// <summary>
    /// 安全浏览器服务
    /// </summary>
    public class SidebarSecureBrowserService
    {
        private readonly SecurityService _securityService;

        public SidebarSecureBrowserService(SecurityService securityService)
        {
            _securityService = securityService;
        }

        public bool Enable(bool enable)
        {
            bool result = _securityService.EnableSecureBrowser(enable);
            if (result)
            {
                AppConfig config = ConfigManager.Config;
                config.SecureBrowserEnabled = enable;
                ConfigManager.SaveConfig();
                LogManager.LogInfo($"Secure browser {(enable ? "enabled" : "disabled")}");
            }
            return result;
        }

        public bool IsEnabled()
        {
            return _securityService.IsSecureBrowserEnabled();
        }
    }

    /// <summary>
    /// 移动安全服务
    /// </summary>
    public class SidebarMobileSecurityService
    {
        private readonly SecurityService _securityService;

        public SidebarMobileSecurityService(SecurityService securityService)
        {
            _securityService = securityService;
        }

        public bool Enable(bool enable)
        {
            bool result = _securityService.EnableMobileSecurity(enable);
            if (result)
            {
                AppConfig config = ConfigManager.Config;
                config.MobileSecurityEnabled = enable;
                ConfigManager.SaveConfig();
                LogManager.LogInfo($"Mobile security {(enable ? "enabled" : "disabled")}");
            }
            return result;
        }

        public bool IsEnabled()
        {
            return _securityService.IsMobileSecurityEnabled();
        }
    }

    /// <summary>
    /// 系统优化服务
    /// </summary>
    public class SidebarSystemOptimizerService
    {
        private readonly SecurityService _securityService;

        public SidebarSystemOptimizerService(SecurityService securityService)
        {
            _securityService = securityService;
        }

        public bool Enable(bool enable)
        {
            bool result = _securityService.EnableSystemOptimizer(enable);
            if (result)
            {
                AppConfig config = ConfigManager.Config;
                config.SystemOptimizerEnabled = enable;
                ConfigManager.SaveConfig();
                LogManager.LogInfo($"System optimizer {(enable ? "enabled" : "disabled")}");
            }
            return result;
        }

        public bool IsEnabled()
        {
            return _securityService.IsSystemOptimizerEnabled();
        }
    }

    /// <summary>
    /// 备份恢复服务
    /// </summary>
    public class SidebarBackupRecoveryService
    {
        private readonly SecurityService _securityService;

        public SidebarBackupRecoveryService(SecurityService securityService)
        {
            _securityService = securityService;
        }

        public bool Enable(bool enable)
        {
            bool result = _securityService.EnableBackupRecovery(enable);
            if (result)
            {
                AppConfig config = ConfigManager.Config;
                config.BackupRecoveryEnabled = enable;
                ConfigManager.SaveConfig();
                LogManager.LogInfo($"Backup recovery {(enable ? "enabled" : "disabled")}");
            }
            return result;
        }

        public bool IsEnabled()
        {
            return _securityService.IsBackupRecoveryEnabled();
        }
    }

    /// <summary>
    /// 安全评分服务
    /// </summary>
    public class SidebarSecurityScoreService
    {
        private readonly SecurityService _securityService;

        public SidebarSecurityScoreService(SecurityService securityService)
        {
            _securityService = securityService;
        }

        public bool Enable(bool enable)
        {
            bool result = _securityService.EnableSecurityScore(enable);
            if (result)
            {
                AppConfig config = ConfigManager.Config;
                config.SecurityScoreEnabled = enable;
                ConfigManager.SaveConfig();
                LogManager.LogInfo($"Security score {(enable ? "enabled" : "disabled")}");
            }
            return result;
        }

        public bool IsEnabled()
        {
            return _securityService.IsSecurityScoreEnabled();
        }
    }

    /// <summary>
    /// 网络流量服务
    /// </summary>
    public class SidebarNetworkTrafficService
    {
        private readonly SecurityService _securityService;

        public SidebarNetworkTrafficService(SecurityService securityService)
        {
            _securityService = securityService;
        }

        public bool Enable(bool enable)
        {
            bool result = _securityService.EnableNetworkTraffic(enable);
            if (result)
            {
                AppConfig config = ConfigManager.Config;
                config.NetworkTrafficEnabled = enable;
                ConfigManager.SaveConfig();
                LogManager.LogInfo($"Network traffic {(enable ? "enabled" : "disabled")}");
            }
            return result;
        }

        public bool IsEnabled()
        {
            return _securityService.IsNetworkTrafficEnabled();
        }
    }

    /// <summary>
    /// 应用监控服务
    /// </summary>
    public class SidebarApplicationMonitorService
    {
        private readonly SecurityService _securityService;

        public SidebarApplicationMonitorService(SecurityService securityService)
        {
            _securityService = securityService;
        }

        public bool Enable(bool enable)
        {
            bool result = _securityService.EnableApplicationMonitor(enable);
            if (result)
            {
                AppConfig config = ConfigManager.Config;
                config.ApplicationMonitorEnabled = enable;
                ConfigManager.SaveConfig();
                LogManager.LogInfo($"Application monitor {(enable ? "enabled" : "disabled")}");
            }
            return result;
        }

        public bool IsEnabled()
        {
            return _securityService.IsApplicationMonitorEnabled();
        }
    }

    /// <summary>
    /// 启动管理服务
    /// </summary>
    public class SidebarStartupManagerService
    {
        private readonly SecurityService _securityService;

        public SidebarStartupManagerService(SecurityService securityService)
        {
            _securityService = securityService;
        }

        public bool Enable(bool enable)
        {
            bool result = _securityService.EnableStartupManager(enable);
            if (result)
            {
                AppConfig config = ConfigManager.Config;
                config.StartupManagerEnabled = enable;
                ConfigManager.SaveConfig();
                LogManager.LogInfo($"Startup manager {(enable ? "enabled" : "disabled")}");
            }
            return result;
        }

        public bool IsEnabled()
        {
            return _securityService.IsStartupManagerEnabled();
        }
    }

    /// <summary>
    /// 安全报告服务
    /// </summary>
    public class SidebarSecurityReportService
    {
        private readonly SecurityService _securityService;

        public SidebarSecurityReportService(SecurityService securityService)
        {
            _securityService = securityService;
        }

        public bool Enable(bool enable)
        {
            bool result = _securityService.EnableSecurityReport(enable);
            if (result)
            {
                AppConfig config = ConfigManager.Config;
                config.SecurityReportEnabled = enable;
                ConfigManager.SaveConfig();
                LogManager.LogInfo($"Security report {(enable ? "enabled" : "disabled")}");
            }
            return result;
        }

        public bool IsEnabled()
        {
            return _securityService.IsSecurityReportEnabled();
        }
    }

    /// <summary>
    /// 行为分析服务
    /// </summary>
    public class SidebarBehaviorAnalysisService
    {
        private readonly FireAntivirus.Data.DataManager _dataManager;

        public SidebarBehaviorAnalysisService(FireAntivirus.Data.DataManager dataManager)
        {
            _dataManager = dataManager;
        }

        public bool Enable(bool enable)
        {
            AppConfig config = ConfigManager.Config;
            config.BehaviorAnalysisEnabled = enable;
            ConfigManager.SaveConfig();
            LogManager.LogInfo($"Behavior analysis {(enable ? "enabled" : "disabled")}");
            return true;
        }

        public bool IsEnabled()
        {
            return ConfigManager.Config.BehaviorAnalysisEnabled;
        }
    }

    /// <summary>
    /// 系统工具服务
    /// </summary>
    public class SidebarSystemToolsService
    {
        private readonly SecurityService _securityService;

        public SidebarSystemToolsService(SecurityService securityService)
        {
            _securityService = securityService;
        }

        public bool Enable(bool enable)
        {
            bool result = _securityService.EnableSystemTools(enable);
            if (result)
            {
                AppConfig config = ConfigManager.Config;
                config.SystemToolsEnabled = enable;
                ConfigManager.SaveConfig();
                LogManager.LogInfo($"System tools {(enable ? "enabled" : "disabled")}");
            }
            return result;
        }

        public bool IsEnabled()
        {
            return _securityService.IsSystemToolsEnabled();
        }
    }

    /// <summary>
    /// 系统信息服务
    /// </summary>
    public class SidebarSystemInfoService
    {
        private readonly SecurityService _securityService;

        public SidebarSystemInfoService(SecurityService securityService)
        {
            _securityService = securityService;
        }

        public bool Enable(bool enable)
        {
            bool result = _securityService.EnableSystemInfo(enable);
            if (result)
            {
                AppConfig config = ConfigManager.Config;
                config.SystemInfoEnabled = enable;
                ConfigManager.SaveConfig();
                LogManager.LogInfo($"System info {(enable ? "enabled" : "disabled")}");
            }
            return result;
        }

        public bool IsEnabled()
        {
            return _securityService.IsSystemInfoEnabled();
        }
    }

    /// <summary>
    /// 隔离区服务
    /// </summary>
    public class SidebarQuarantineService
    {
        private readonly SecurityService _securityService;

        public SidebarQuarantineService(SecurityService securityService)
        {
            _securityService = securityService;
        }

        public bool Enable(bool enable)
        {
            bool result = _securityService.EnableQuarantine(enable);
            if (result)
            {
                AppConfig config = ConfigManager.Config;
                config.QuarantineEnabled = enable;
                ConfigManager.SaveConfig();
                LogManager.LogInfo($"Quarantine {(enable ? "enabled" : "disabled")}");
            }
            return result;
        }

        public bool IsEnabled()
        {
            return _securityService.IsQuarantineEnabled();
        }
    }

    /// <summary>
    /// 信任区服务
    /// </summary>
    public class SidebarTrustZoneService
    {
        private readonly SecurityService _securityService;

        public SidebarTrustZoneService(SecurityService securityService)
        {
            _securityService = securityService;
        }

        public bool Enable(bool enable)
        {
            bool result = _securityService.EnableTrustZone(enable);
            if (result)
            {
                AppConfig config = ConfigManager.Config;
                config.TrustZoneEnabled = enable;
                ConfigManager.SaveConfig();
                LogManager.LogInfo($"Trust zone {(enable ? "enabled" : "disabled")}");
            }
            return result;
        }

        public bool IsEnabled()
        {
            return _securityService.IsTrustZoneEnabled();
        }
    }

    /// <summary>
    /// 日志中心服务
    /// </summary>
    public class SidebarLogCenterService
    {
        private readonly SecurityService _securityService;

        public SidebarLogCenterService(SecurityService securityService)
        {
            _securityService = securityService;
        }

        public bool Enable(bool enable)
        {
            bool result = _securityService.EnableLogCenter(enable);
            if (result)
            {
                AppConfig config = ConfigManager.Config;
                config.LogCenterEnabled = enable;
                ConfigManager.SaveConfig();
                LogManager.LogInfo($"Log center {(enable ? "enabled" : "disabled")}");
            }
            return result;
        }

        public bool IsEnabled()
        {
            return _securityService.IsLogCenterEnabled();
        }
    }

    #endregion
}
