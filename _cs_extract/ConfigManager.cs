using System;
using System.IO;
using System.Text.Json;

namespace FireAntivirus.Services
{
    /// <summary>
    /// 配置类
    /// </summary>
    public class AppConfig
    {
        /// <summary>
        /// 文件防护是否启用
        /// </summary>
        public bool FileProtectionEnabled { get; set; } = true;

        /// <summary>
        /// 进程防护是否启用
        /// </summary>
        public bool ProcessProtectionEnabled { get; set; } = true;

        /// <summary>
        /// U盘防护是否启用
        /// </summary>
        public bool DeviceProtectionEnabled { get; set; } = true;

        /// <summary>
        /// 注册表防护是否启用
        /// </summary>
        public bool RegistryProtectionEnabled { get; set; } = true;

        /// <summary>
        /// 浏览器防护是否启用
        /// </summary>
        public bool BrowserProtectionEnabled { get; set; } = true;

        /// <summary>
        /// 脚本防护是否启用
        /// </summary>
        public bool ScriptProtectionEnabled { get; set; } = true;

        /// <summary>
        /// 主动防御是否启用
        /// </summary>
        public bool ActiveDefenseEnabled { get; set; } = true;

        /// <summary>
        /// 分区表防护是否启用
        /// </summary>
        public bool DiskProtectionEnabled { get; set; } = true;

        /// <summary>
        /// UEFI/BIOS防护是否启用
        /// </summary>
        public bool UEFIProtectionEnabled { get; set; } = true;

        /// <summary>
        /// 内核防护是否启用
        /// </summary>
        public bool KernelProtectionEnabled { get; set; } = true;

        /// <summary>
        /// 文档防护是否启用
        /// </summary>
        public bool DocumentProtectionEnabled { get; set; } = true;

        /// <summary>
        /// 网络防护是否启用
        /// </summary>
        public bool NetworkProtectionEnabled { get; set; } = true;

        /// <summary>
        /// 弹窗拦截是否启用
        /// </summary>
        public bool PopupBlockerEnabled { get; set; } = true;

        /// <summary>
        /// 勒索防护是否启用
        /// </summary>
        public bool RansomwareProtectionEnabled { get; set; } = true;

        /// <summary>
        /// 隐私保护是否启用
        /// </summary>
        public bool PrivacyProtectionEnabled { get; set; } = true;

        /// <summary>
        /// 网页防护是否启用
        /// </summary>
        public bool WebProtectionEnabled { get; set; } = true;

        /// <summary>
        /// 邮件安全是否启用
        /// </summary>
        public bool EmailSecurityEnabled { get; set; } = true;

        /// <summary>
        /// 密码管理是否启用
        /// </summary>
        public bool PasswordManagerEnabled { get; set; } = true;

        /// <summary>
        /// 网络防火墙是否启用
        /// </summary>
        public bool NetworkFirewallEnabled { get; set; } = true;

        /// <summary>
        /// 设备控制是否启用
        /// </summary>
        public bool DeviceControlEnabled { get; set; } = true;

        /// <summary>
        /// 漏洞扫描是否启用
        /// </summary>
        public bool VulnerabilityScannerEnabled { get; set; } = true;

        /// <summary>
        /// 云查杀是否启用
        /// </summary>
        public bool CloudScanEnabled { get; set; } = true;

        /// <summary>
        /// 安全浏览器是否启用
        /// </summary>
        public bool SecureBrowserEnabled { get; set; } = true;

        /// <summary>
        /// 移动安全是否启用
        /// </summary>
        public bool MobileSecurityEnabled { get; set; } = true;

        /// <summary>
        /// 系统优化是否启用
        /// </summary>
        public bool SystemOptimizerEnabled { get; set; } = true;

        /// <summary>
        /// 备份恢复是否启用
        /// </summary>
        public bool BackupRecoveryEnabled { get; set; } = true;

        /// <summary>
        /// 安全评分是否启用
        /// </summary>
        public bool SecurityScoreEnabled { get; set; } = true;

        /// <summary>
        /// 网络流量是否启用
        /// </summary>
        public bool NetworkTrafficEnabled { get; set; } = true;

        /// <summary>
        /// 应用监控是否启用
        /// </summary>
        public bool ApplicationMonitorEnabled { get; set; } = true;

        /// <summary>
        /// 启动管理是否启用
        /// </summary>
        public bool StartupManagerEnabled { get; set; } = true;

        /// <summary>
        /// 安全报告是否启用
        /// </summary>
        public bool SecurityReportEnabled { get; set; } = true;

        /// <summary>
        /// 行为分析是否启用
        /// </summary>
        public bool BehaviorAnalysisEnabled { get; set; } = true;

        /// <summary>
        /// 系统工具是否启用
        /// </summary>
        public bool SystemToolsEnabled { get; set; } = true;

        /// <summary>
        /// 系统信息是否启用
        /// </summary>
        public bool SystemInfoEnabled { get; set; } = true;

        /// <summary>
        /// 隔离区是否启用
        /// </summary>
        public bool QuarantineEnabled { get; set; } = true;

        /// <summary>
        /// 信任区是否启用
        /// </summary>
        public bool TrustZoneEnabled { get; set; } = true;

        /// <summary>
        /// 日志中心是否启用
        /// </summary>
        public bool LogCenterEnabled { get; set; } = true;
    }

    /// <summary>
    /// 配置管理器
    /// </summary>
    public static class ConfigManager
    {
        private static string _configFile;
        private static AppConfig _config;
        private static readonly object _lock = new object();
        private static bool _initialized;

        /// <summary>
        /// 初始化配置管理器
        /// </summary>
        public static void Initialize()
        {
            if (_initialized)
            {
                return;
            }

            lock (_lock)
            {
                if (_initialized)
                {
                    return;
                }

                // 创建配置文件路径
                string configDirectory = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Config");
                if (!Directory.Exists(configDirectory))
                {
                    Directory.CreateDirectory(configDirectory);
                }

                _configFile = Path.Combine(configDirectory, "appsettings.json");

                // 加载配置
                LoadConfig();

                _initialized = true;
                LogManager.LogInfo("Config manager initialized");
            }
        }

        /// <summary>
        /// 加载配置
        /// </summary>
        private static void LoadConfig()
        {
            try
            {
                if (File.Exists(_configFile))
                {
                    string json = File.ReadAllText(_configFile);
                    _config = JsonSerializer.Deserialize<AppConfig>(json);
                }
                else
                {
                    // 创建默认配置
                    _config = new AppConfig();
                    SaveConfig();
                }
            }
            catch (Exception ex)
            {
                LogManager.LogError("Failed to load config: " + ex.Message);
                // 创建默认配置
                _config = new AppConfig();
                SaveConfig();
            }
        }

        /// <summary>
        /// 保存配置
        /// </summary>
        public static void SaveConfig()
        {
            try
            {
                lock (_lock)
                {
                    string json = JsonSerializer.Serialize(_config, new JsonSerializerOptions { WriteIndented = true });
                    File.WriteAllText(_configFile, json);
                    LogManager.LogInfo("Config saved");
                }
            }
            catch (Exception ex)
            {
                LogManager.LogError("Failed to save config: " + ex.Message);
            }
        }

        /// <summary>
        /// 获取配置
        /// </summary>
        public static AppConfig Config
        {
            get
            {
                if (!_initialized)
                {
                    Initialize();
                }
                return _config;
            }
        }

        /// <summary>
        /// 获取配置文件路径
        /// </summary>
        public static string ConfigFile => _configFile;
    }
}
