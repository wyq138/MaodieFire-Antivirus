// 抖音用户 耄耋杀毒软件 开发，严禁非法反编译

// 抖音用户 耄耋杀毒软件 开发，严禁非法反编译

using System;

using System.Collections.Generic;

using System.IO;

using System.Linq;

using System.Reflection;

using System.Resources;

using System.Threading;

using Newtonsoft.Json;



namespace FireAntivirus.Common.Localization

{

    public class LanguageManager

    {

        private static LanguageManager _instance;

        private static readonly object _lock = new object();

        private Dictionary<string, Dictionary<string, string>> _languageResources;

        private string _currentLanguage = "zh-CN";



        public event EventHandler LanguageChanged;

        public static event EventHandler GlobalLanguageChanged;



        private LanguageManager()

        {

            // 抖音用户 耄耋杀毒软件 开发，严禁非法反编译

            _languageResources = new Dictionary<string, Dictionary<string, string>>();

            LoadLanguageResources();

        }



        public static LanguageManager Instance

        {

            get

            {

                if (_instance == null)

                {

                    lock (_lock)

                    {

                        if (_instance == null)

                        {

                            _instance = new LanguageManager();

                        }

                    }

                }

                return _instance;

            }

        }



        public string CurrentLanguage

        {

            get { return _currentLanguage; }

            set

            {

                if (_currentLanguage != value && _languageResources.ContainsKey(value))

                {

                    _currentLanguage = value;

                    // 触发实例事件

                    LanguageChanged?.Invoke(this, EventArgs.Empty);

                    // 触发全局静态事件

                    GlobalLanguageChanged?.Invoke(null, EventArgs.Empty);

                    // 保存语言设置到配置文件

                    SaveLanguageSetting(value);

                    // 发送语言变更消息到C++后台

                    SendLanguageChangeMessage(value);

                }

            }

        }



        private void SendLanguageChangeMessage(string language)

        {

            try

            {

                // 使用反射来避免循环引用

                var assembly = Assembly.LoadFrom(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "FireAntivirus.Host.dll"));

                if (assembly != null)

                {

                    var namedPipeClientType = assembly.GetType("FireAntivirus.Host.NamedPipeClient");

                    if (namedPipeClientType != null)

                    {

                        // 创建NamedPipeClient实例

                        var pipeClient = Activator.CreateInstance(namedPipeClientType);

                        if (pipeClient != null)

                        {

                            // 调用Connect方法

                            var connectMethod = namedPipeClientType.GetMethod("Connect");

                            if (connectMethod != null)

                            {

                                var connected = (bool)connectMethod.Invoke(pipeClient, null);

                                if (connected)

                                {

                                    // 创建Message实例

                                    var commonAssembly = Assembly.LoadFrom(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "FireAntivirus.Common.dll"));

                                    if (commonAssembly != null)

                                    {

                                        var messageType = commonAssembly.GetType("FireAntivirus.Common.Message");

                                        if (messageType != null)

                                        {

                                            var message = Activator.CreateInstance(messageType);

                                            if (message != null)

                                            {

                                                // 设置消息属性

                                                messageType.GetProperty("type").SetValue(message, 5); // 语言变更消息

                                                var threatInfoProperty = messageType.GetProperty("threatInfo");

                                                if (threatInfoProperty != null)

                                                {

                                                    var threatInfo = threatInfoProperty.GetValue(message);

                                                    if (threatInfo != null)

                                                    {

                                                        var threatInfoType = threatInfo.GetType();

                                                        var nameProperty = threatInfoType.GetProperty("name");

                                                        if (nameProperty != null)

                                                        {

                                                            nameProperty.SetValue(threatInfo, language);

                                                        }

                                                    }

                                                }

                                                

                                                // 发送消息

                                                var sendMessageMethod = namedPipeClientType.GetMethod("SendMessage");

                                                if (sendMessageMethod != null)

                                                {

                                                    sendMessageMethod.Invoke(pipeClient, new object[] { message });

                                                }

                                            }

                                        }

                                    }

                                }

                            }

                            

                            // 释放资源

                            var disposeMethod = namedPipeClientType.GetMethod("Dispose");

                            if (disposeMethod != null)

                            {

                                disposeMethod.Invoke(pipeClient, null);

                            }

                        }

                    }

                }

            }

            catch (Exception ex)

            {

                Console.WriteLine($"Error sending language change message: {ex.Message}");

            }

        }



        private void SaveLanguageSetting(string language)

        {

            try

            {

                string configPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "config.json");

                dynamic config = new { language = language };

                string json = JsonConvert.SerializeObject(config, Formatting.Indented);

                File.WriteAllText(configPath, json);

            }

            catch { }

        }



        public void LoadLanguageSetting()

        {

            try

            {

                string configPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "config.json");

                if (File.Exists(configPath))

                {

                    string json = File.ReadAllText(configPath);

                    dynamic config = JsonConvert.DeserializeObject(json);

                    if (config.language != null)

                    {

                        string language = config.language.ToString();

                        if (_languageResources.ContainsKey(language))

                        {

                            _currentLanguage = language;

                        }

                    }

                }

            }

            catch { }

        }



        public string GetString(string key, params object[] args)

        {

            if (_languageResources.TryGetValue(_currentLanguage, out var resources) && resources.TryGetValue(key, out var value))

            {

                return string.Format(value, args);

            }



            // 如果当前语言没有找到，尝试使用默认语言

            if (_languageResources.TryGetValue("zh-CN", out var defaultResources) && defaultResources.TryGetValue(key, out var defaultValue))

            {

                return string.Format(defaultValue, args);

            }



            // 如果默认语言也没有找到，返回键本身

            return key;

        }



        public List<string> GetAvailableLanguages()

        {

            return _languageResources.Keys.ToList();

        }



        private void LoadLanguageResources()

        {

            try

            {

                // 加载内置语言资源

                LoadBuiltInResources();



                // 加载外部语言资源

                LoadExternalResources();



                // 加载保存的语言设置

                LoadLanguageSetting();

            }

            catch (Exception ex)

            {

                Console.WriteLine($"加载语言资源失败: {ex.Message}");

            }

        }



        private void LoadBuiltInResources()

        {

            // 简体中文

            _languageResources["zh-CN"] = new Dictionary<string, string>

            {

                { "AppTitle", "耄耋杀毒" },

                { "ProfessionalProtection", "专业级安全防护" },

                { "Home", "首页" },

                { "VirusScan", "病毒查杀" },

                { "RealTimeProtection", "实时防护" },

                { "NetworkProtection", "网络防护" },

                { "PopupBlocker", "弹窗拦截" },

                { "SystemTools", "系统工具" },

                { "SystemInfo", "系统信息" },

                { "Quarantine", "隔离区" },

                { "TrustZone", "信任区" },

                { "LogCenter", "日志中心" },

                { "Settings", "设置" },

                { "About", "关于" },

                { "PrivacyProtection", "隐私保护" },

                { "PrivacyProtectionDescription", "保护您的隐私信息和数据安全" },

                { "PrivacySettings", "隐私设置" },

                { "EnablePrivacyProtection", "启用隐私保护" },

                { "ViewPrivacySettings", "查看隐私设置" },

                { "ApplySettings", "应用设置" },

                { "ParentalControl", "家长控制" },

                { "ParentalControlDescription", "监控和管控孩子的电脑使用" },

                { "WebProtection", "网页防护" },

                { "WebProtectionDescription", "保护您免受恶意网站和钓鱼攻击" },

                { "EmailSecurity", "邮件安全" },

                { "EmailSecurityDescription", "检测和拦截恶意邮件" },

                { "PasswordManager", "密码管理" },

                { "PasswordManagerDescription", "安全管理和检测弱密码" },

                { "SystemOptimization", "系统优化" },

                { "SystemOptimizationDescription", "清理垃圾文件和优化系统性能" },

                { "BackupRecovery", "备份恢复" },

                { "BackupRecoveryDescription", "备份重要文件和恢复数据" },

                { "NetworkFirewall", "网络防火墙" },

                { "NetworkFirewallDescription", "管控网络流量和拦截异常连接" },

                { "DeviceControl", "设备控制" },

                { "DeviceControlDescription", "监控和管理外设接入" },

                { "VulnerabilityScan", "漏洞扫描" },

                { "VulnerabilityScanDescription", "检测系统漏洞和安全风险" },

                { "CloudScan", "云查杀" },

                { "CloudScanDescription", "使用云端技术查杀病毒" },

                { "SafeBrowser", "安全浏览器" },

                { "SafeBrowserDescription", "提供安全的网页浏览体验" },

                { "SecurityScore", "安全评分" },

                { "SecurityScoreDescription", "评估设备安全状态" },

                { "NetworkTraffic", "网络流量" },

                { "NetworkTrafficDescription", "监控和分析网络流量" },

                { "ApplicationMonitor", "应用监控" },

                { "ApplicationMonitorDescription", "监控进程异常行为" },

                { "StartupManager", "启动管理" },

                { "StartupManagerDescription", "管理系统启动项" },

                { "SecurityReport", "安全报告" },

                { "SecurityReportDescription", "生成详细的安全报告" },

                { "BehaviorAnalysis", "行为分析" },

                { "BehaviorAnalysisDescription", "分析程序行为和检测异常" },

                { "MobileSecurity", "移动安全" },

                { "MobileSecurityDescription", "保护移动设备安全" },

                { "Scan", "扫描" },

                { "Cleanup", "清理" },

                { "Monitor", "监控" },

                { "ScanStarted", "扫描已开始" },

                { "CleanupStarted", "清理已开始" },

                { "SettingsOpened", "设置已打开" },

                { "MonitoringStarted", "监控已开始" },

                { "Protection", "防护" },

                { "Tools", "工具" },

                { "Log", "日志" },

                { "QuickScan", "快速扫描" },

                { "FullScan", "全盘扫描" },

                { "CustomScan", "自定义扫描" },

                { "DeepScan", "深度扫描" },

                { "ScanNow", "立即扫描" },

                { "Scanning", "正在扫描..." },

                { "ScanCompleted", "扫描完成" },

                { "NoThreatsFound", "未发现威胁" },

                { "ThreatsFound", "发现 {0} 个威胁" },

                { "Firewall", "防火墙" },

                { "RansomwareProtection", "勒索软件防护" },

                { "ExploitProtection", "漏洞防护" },

                { "MemoryScanning", "内存扫描" },

                { "RegistryScanning", "注册表扫描" },

                { "StartupScanning", "启动项扫描" },

                { "NetworkScanning", "网络扫描" },

                { "ProcessScanning", "进程扫描" },

                { "BehaviorMonitoring", "行为监控" },

                { "RootkitScanning", "Rootkit扫描" },

                { "CleanJunkFiles", "清理垃圾文件" },

                { "CleanTemporaryFiles", "清理临时文件" },

                { "CleanCacheFiles", "清理缓存文件" },

                { "CleanLogFiles", "清理日志文件" },

                { "CleanRecycleBin", "清理回收站" },

                { "CleanBrowserCache", "清理浏览器缓存" },

                { "RegistryCleanup", "注册表清理" },

                { "StartupOptimization", "启动项优化" },

                { "DiskDefragmentation", "磁盘碎片整理" },

                { "NetworkTools", "网络工具" },

                { "FileTools", "文件工具" },

                { "RegistryTools", "注册表工具" },

                { "ProcessManager", "进程管理器" },

                { "ServiceManager", "服务管理器" },

                { "Appearance", "外观" },

                { "ScanSettings", "扫描设置" },

                { "ProtectionSettings", "防护设置" },

                { "NetworkSettings", "网络设置" },

                { "SystemSettings", "系统设置" },

                { "UpdateSettings", "更新设置" },

                { "LanguageSettings", "语言设置" },

                { "Theme", "主题" },

                { "LightTheme", "浅色" },

                { "DarkTheme", "深色" },

                { "AutoTheme", "跟随系统" },

                { "Language", "语言" },

                { "SimplifiedChinese", "简体中文" },

                { "English", "English" },

                { "French", "Français" },

                { "TraditionalChinese", "繁體中文" },

                { "Korean", "한국어" },

                { "Japanese", "日本語" },

                { "Notifications", "通知" },

                { "ShowNotifications", "显示通知" },

                { "ShowTrayIcon", "显示托盘图标" },

                { "MinimizeToTray", "最小化到托盘" },

                { "StartWithWindows", "随Windows启动" },

                { "ShowSplashScreen", "显示启动画面" },

                { "EnableSounds", "启用声音" },

                { "HighDpiSupport", "高DPI支持" },

                { "AutoUpdate", "自动更新" },

                { "VirusDefinitionsAutoUpdate", "病毒库自动更新" },

                { "ProgramAutoUpdate", "程序自动更新" },

                { "BetaUpdates", "测试版更新" },

                { "UpdateCheckInterval", "更新检查间隔" },

                { "VirusDefinitionsUpdateInterval", "病毒库更新间隔" },

                { "UpdateChannel", "更新渠道" },

                { "DownloadOverMeteredConnections", "在计量连接上下载" },

                { "Stable", "稳定版" },

                { "Beta", "测试版" },

                { "Alpha", " alpha 版" },

                { "AdvancedSettings", "高级设置" },

                { "EnableKernelModeProtection", "启用内核模式保护" },

                { "EnableSandbox", "启用沙箱" },

                { "EnableCloudProtection", "启用云保护" },

                { "EnableMachineLearning", "启用机器学习" },

                { "EnableBehaviorAnalysis", "启用行为分析" },

                { "EnableHeuristicAnalysis", "启用启发式分析" },

                // 关于页面

                { "AboutTitle", "关于 耄耋杀毒" },

                { "HomeSubtitle", "全方位保护您的电脑安全" },

                { "ProtectionStatus", "防护状态" },

                { "ProtectionStatusEnabled", "已开启" },

                { "VirusDatabase", "病毒库" },

                { "VirusDatabaseUpToDate", "最新" },

                { "SystemStatus", "系统状态" },

                { "SystemStatusSafe", "安全" },

                { "Version", "版本: {0}" },

                { "Developer", "开发者: 老猫咪" },

                { "Phone", "电话: 18281970402" },

                { "Email", "邮箱: zjhwyq123456@qq.com" },

                { "RecentActivity", "最近活动" },

                { "NoRecentActivity", "系统运行正常，无异常活动" },

                { "AllProtectionRunning", "所有防护功能运行正常" },

                { "VirusDbVersion", "病毒库版本：最新" },

                { "Description", "耄耋杀毒是一款功能强大的安全防护软件，专为Windows系统设计，提供全方位的安全保障：\n\n" +

                              "• 实时病毒查杀：采用先进的病毒扫描引擎，实时监测系统中的可疑文件和程序\n" +

                              "• 网络防护：智能识别并拦截恶意网络连接，保护您的个人信息安全\n" +

                              "• 弹窗拦截：有效阻止各种广告弹窗和恶意推广，提供清爽的上网环境\n" +

                              "• 系统工具：内置垃圾清理、启动项管理、漏洞修复等实用工具\n" +

                              "• 全方位防护：包括分区表保护、UEFI/BIOS保护、内核保护和文档保护\n\n" +

                              "耄耋杀毒致力于为用户提供简单易用但功能强大的安全解决方案，让您的电脑始终保持最佳状态。" },

                { "Copyright", "© 2026 耄耋杀毒. 保留所有权利." },

                { "EnableEmulation", "启用模拟" },

                { "EnableDeepScanning", "启用深度扫描" },

                { "MaxScanThreads", "最大扫描线程数" },

                { "MaxMemoryUsage", "最大内存使用" },

                { "EnableDebugLogging", "启用调试日志" },

                { "LogTitle", "安全日志" },

                { "LogTime", "时间" },

                { "LogType", "类型" },

                { "LogMessage", "消息" },

                { "LogDetails", "详情" },

                { "QuarantineTitle", "隔离区" },

                { "QuarantineTime", "隔离时间" },

                { "QuarantinePath", "原始路径" },

                { "ThreatName", "威胁名称" },

                { "ThreatType", "威胁类型" },

                { "Restore", "恢复" },

                { "Delete", "删除" },

                { "EmptyQuarantine", "清空隔离区" },

                { "MalwareDetected", "检测到恶意软件" },

                { "SuspiciousProcess", "可疑进程" },

                { "UnauthorizedAccess", "未授权访问" },

                { "RegistryTampering", "注册表篡改" },

                { "FileInjection", "文件注入" },

                { "ProcessInjection", "进程注入" },

                { "NetworkAttack", "网络攻击" },

                { "PopupBlocked", "弹窗已阻止" },

                { "UnsignedDriverDetected", "检测到未签名驱动" },

                { "KernelModulesTampered", "内核模块被篡改" },

                { "SystemDllTampered", "系统DLL被篡改" },

                { "NotificationServiceStart", "通知服务已启动" },

                { "NotificationServiceStop", "通知服务已停止" },

                { "SecurityNotification", "安全通知" },

                { "NotificationError", "显示通知失败" },

                { "NotificationServiceError", "通知服务错误" },

                { "NotifyIconInitError", "初始化托盘图标失败" },

                { "NotificationFormError", "显示通知窗口失败" },

                { "UpdateCheckError", "检查更新时出错" },

                { "UpdateDownloadError", "下载更新时出错" },

                { "UpdateInstallError", "安装更新时出错" },

                { "ThreatIntelligenceSyncError", "同步威胁情报时出错" },

                { "VirusDefinitionsUpdateError", "更新病毒库时出错" },

                { "ScanError", "扫描时出错" },

                { "CleanupError", "清理时出错" },

                { "OptimizationError", "优化时出错" },

                { "NetworkError", "网络错误" },

                { "SystemError", "系统错误" },

                { "GeneralError", "一般错误" },

                { "Info", "信息" },

                { "Warning", "警告" },

                { "Error", "错误" },

                { "Success", "成功" },

                { "Cancel", "取消" },

                { "OK", "确定" },

                { "Yes", "是" },

                { "No", "否" },

                { "Close", "关闭" },

                { "Details", "详情" },

                { "ViewDetails", "查看详情" },

                { "OpenMainProgram", "打开主程序" },

                { "ViewLogs", "查看日志" },

                { "ServiceStatus", "服务状态" },

                { "ExitService", "退出服务" },

                { "ExitServiceConfirmation", "确定要退出耄耋杀毒防护服务吗？\n\n退出后将失去实时保护功能。" },

                { "ExitServiceConfirmationTitle", "退出服务确认" },

                { "ServiceStatusMessage", "耄耋杀毒防护服务当前状态: {0}" },

                { "MainProgramNotFound", "无法找到主程序文件" },

                { "LogsNotFound", "无法找到日志文件" },

                { "MainProgramStartError", "启动主程序失败: {0}" },

                { "LogsOpenError", "打开日志失败: {0}" },

                { "ScrollBarColor", "滚动条颜色" },

                { "FollowTheme", "跟随主题" },

                { "ScanThreads", "扫描线程数" },

                { "AllTypes", "全部类型" },

                { "SmartMode", "智能模式" },

                { "NetworkMonitor", "网络监控" },

                { "SelfProtection", "自我保护" },

                { "BackgroundProtection", "后台防护" },

                { "PasswordProtection", "密码保护" },

                { "StartupManagement", "启动项管理" },

                { "Manage", "管理" },

                { "UpdateAvailable", "更新可用" },

                { "PreparingDownload", "准备下载..." },

                { "UpdateSuccess", "更新已成功下载并开始安装。\n\n安装完成后请重启应用程序。" },

                { "UpdateFailed", "更新失败: {0}" },

                { "UpdateProgress", "正在更新" },

                { "UpdateAvailableMessage", "发现新版本 {0}\n\n{1}\n\n是否立即下载并安装？" },

                { "ScanFileTypes", "扫描文件类型" },

                { "Enable", "启用" },

                { "StartupProtection", "开机自启防护" },

                { "ProtectionAlerts", "防护提醒" },

                { "PopupAlerts", "弹窗提醒" },

                { "NetworkMode", "网络模式" },

                { "NotSet", "未设置" },

                { "UpdateFrequency", "更新频率" },

                { "CheckDaily", "每天检查" },

                { "CheckNow", "检查更新" },

                { "UpdateNow", "立即更新" },

                { "StatusReady", "就绪" },

                { "ScanPaused", "扫描已暂停" },

                { "ScanFailed", "扫描失败" },

                { "PleaseSelectScanType", "请先选择扫描类型" },

                { "PauseScan", "暂停扫描" },

                { "StopScan", "停止扫描" },

                { "TurnOn", "开" },

                { "TurnOff", "关" },

                { "ResumeScan", "继续扫描" },

                { "SystemRepair", "系统修复" },

                { "DetectFirstThenRepair", "先检测系统问题，然后进行修复" },

                { "SystemFileCorruption", "系统文件损坏" },

                { "ShortcutIssues", "快捷方式异常" },

                { "NetworkConfigErrors", "网络配置错误" },

                { "DesktopIconIssues", "桌面图标异常" },

                { "FileAssociationErrors", "文件关联错误" },

                { "SystemRestrictions", "系统限制解除" },

                { "ClickDetectButton", "请点击开始检测按钮，先检测系统问题" },

                { "StartDetection", "开始检测" },

                { "StartRepair", "开始修复" },

                { "CheckUpdate", "检查更新" }

            };


        }

        private void LoadExternalResources()

        {

            try

            {

                string langDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Languages");

                if (Directory.Exists(langDir))

                {

                    foreach (string file in Directory.GetFiles(langDir, "*.json"))

                    {

                        try

                        {

                            string content = File.ReadAllText(file);

                            var resources = JsonConvert.DeserializeObject<Dictionary<string, string>>(content);

                            string langCode = Path.GetFileNameWithoutExtension(file);

                            _languageResources[langCode] = resources;

                        }

                        catch (Exception ex)

                        {

                            Console.WriteLine($"加载外部语言资源失败: {ex.Message}");

                        }

                    }

                }

            }

            catch (Exception ex)

            {

                Console.WriteLine($"加载外部语言资源失败: {ex.Message}");

            }

        }



        public void SetLanguage(string languageCode)

        {

            CurrentLanguage = languageCode;

        }



        public string GetLanguageDisplayName(string languageCode)
        {
            return "简体中文";
        }
    }
}


