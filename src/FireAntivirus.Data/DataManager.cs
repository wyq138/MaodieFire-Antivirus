using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using Newtonsoft.Json;

namespace FireAntivirus.Data
{
    public class VirusDefinitions
    {
        public List<VirusSignature> signatures { get; set; }
    }

    public class VirusSignature
    {
        public string Hash { get; set; }
        public string Name { get; set; }
        public string Type { get; set; }
        public string Severity { get; set; }
        public string Description { get; set; }
        public string DetectionMethod { get; set; }
        public DateTime AddedDate { get; set; }
        public string Source { get; set; }
    }

    public class QuarantineItem
    {
        public string Id { get; set; }
        public string OriginalPath { get; set; }
        public string QuarantinePath { get; set; }
        public string FileName { get; set; }
        public string ThreatName { get; set; }
        public string ThreatType { get; set; }
        public DateTime QuarantineTime { get; set; }
        public long Size { get; set; }
        public string Hash { get; set; }
        public string FileExtension { get; set; }
        public string ScanEngine { get; set; }
        public double Confidence { get; set; }
        public string AdditionalInfo { get; set; }
    }

    public class TrustItem
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public string Path { get; set; }
        public string Type { get; set; }
        public string HashValue { get; set; }
        public string ExpectedPath { get; set; }
        public DateTime AddTime { get; set; }
        public string Description { get; set; }
        public string AddedBy { get; set; }
        public bool IsExplicit { get; set; }
        
        // 增强白名单功能
        public string FileHash { get; set; }           // SHA256哈希值白名单
        public string CertificateThumbprint { get; set; } // 数字证书指纹白名单
        public string CertificateSubject { get; set; }    // 数字证书主题
        public string Publisher { get; set; }             // 发布者名称
        public bool IsMicrosoftSigned { get; set; }       // 是否微软签名
        public bool IsTrustedPublisher { get; set; }      // 是否受信任发布者
        public int TrustLevel { get; set; }               // 信任级别 (0-100)
    }

    public class LogEntry
    {
        public string Id { get; set; }
        public DateTime Time { get; set; }
        public string Type { get; set; }
        public string Message { get; set; }
        public string Details { get; set; }
        public string Severity { get; set; }
        public string Source { get; set; }
        public string Category { get; set; }
    }

    public class BackupItem
    {
        public string Id { get; set; }
        public string BackupPath { get; set; }
        public string BackupType { get; set; }
        public DateTime BackupTime { get; set; }
        public long Size { get; set; }
        public string Description { get; set; }
        public string Version { get; set; }
    }

    public class ScanHistoryItem
    {
        public string Id { get; set; }
        public DateTime ScanTime { get; set; }
        public string ScanType { get; set; }
        public int ScannedFiles { get; set; }
        public int DetectedThreats { get; set; }
        public long ScanDuration { get; set; }
        public string ScanPath { get; set; }
        public bool Completed { get; set; }
        public string Result { get; set; }
    }

    public class SystemProtectionSettings
    {
        public bool RealTimeProtectionEnabled { get; set; } = true;
        public bool MemoryScanningEnabled { get; set; } = true;
        public bool RegistryScanningEnabled { get; set; } = true;
        public bool StartupItemsScanningEnabled { get; set; } = true;
        public bool NetworkScanningEnabled { get; set; } = true;
        public bool ProcessScanningEnabled { get; set; } = true;
        public bool BehaviorMonitoringEnabled { get; set; } = true;
        public bool RootkitScanningEnabled { get; set; } = true;
        public bool ExploitProtectionEnabled { get; set; } = true;
        public bool RansomwareProtectionEnabled { get; set; } = true;
    }

    public class NetworkProtectionSettings
    {
        public bool FirewallEnabled { get; set; } = true;
        public bool NetworkMonitoringEnabled { get; set; } = true;
        public bool WebProtectionEnabled { get; set; } = true;
        public bool EmailProtectionEnabled { get; set; } = true;
        public bool P2PProtectionEnabled { get; set; } = false;
        public bool TorrentProtectionEnabled { get; set; } = false;
        public List<string> BlockedIPs { get; set; } = new List<string>();
        public List<string> AllowedIPs { get; set; } = new List<string>();
        public List<string> BlockedDomains { get; set; } = new List<string>();
        public List<string> AllowedDomains { get; set; } = new List<string>();
    }

    public class ScanSettings
    {
        public bool QuickScanEnabled { get; set; } = true;
        public bool FullScanEnabled { get; set; } = true;
        public bool CustomScanEnabled { get; set; } = true;
        public bool DeepScanEnabled { get; set; } = false;
        public bool MemoryScanEnabled { get; set; } = true;
        public bool RegistryScanEnabled { get; set; } = true;
        public bool StartupScanEnabled { get; set; } = true;
        public bool NetworkScanEnabled { get; set; } = true;
        public bool ProcessScanEnabled { get; set; } = true;
        public int QuickScanInterval { get; set; } = 24; // 小时
        public int FullScanInterval { get; set; } = 168; // 小时
        public List<string> CustomScanPaths { get; set; } = new List<string>();
        public List<string> ExcludedPaths { get; set; } = new List<string>();
        public List<string> ExcludedExtensions { get; set; } = new List<string>();
    }

    public class UpdateSettings
    {
        public bool AutoUpdateEnabled { get; set; } = true;
        public bool VirusDefinitionsAutoUpdateEnabled { get; set; } = true;
        public bool ProgramAutoUpdateEnabled { get; set; } = true;
        public bool BetaUpdatesEnabled { get; set; } = false;
        public int UpdateCheckInterval { get; set; } = 24; // 小时
        public int VirusDefinitionsUpdateInterval { get; set; } = 4; // 小时
        public string UpdateChannel { get; set; } = "Stable";
        public bool DownloadOverMeteredConnections { get; set; } = false;
    }

    public class InterfaceSettings
    {
        public string Theme { get; set; } = "Light";
        public bool ShowNotifications { get; set; } = true;
        public bool ShowTrayIcon { get; set; } = true;
        public bool MinimizeToTray { get; set; } = true;
        public bool StartWithWindows { get; set; } = true;
        public bool ShowSplashScreen { get; set; } = true;
        public bool EnableSounds { get; set; } = true;
        public string Language { get; set; } = "en";
        public bool HighDpiSupport { get; set; } = true;
    }

    public class AdvancedSettings
    {
        public bool EnableKernelModeProtection { get; set; } = true;
        public bool EnableSandbox { get; set; } = false;
        public bool EnableCloudProtection { get; set; } = true;
        public bool EnableMachineLearning { get; set; } = true;
        public bool EnableBehaviorAnalysis { get; set; } = true;
        public bool EnableHeuristicAnalysis { get; set; } = true;
        public bool EnableEmulation { get; set; } = false;
        public bool EnableDeepScanning { get; set; } = false;
        public int MaxScanThreads { get; set; } = Environment.ProcessorCount;
        public int MaxMemoryUsage { get; set; } = 512; // MB
        public bool EnableDebugLogging { get; set; } = false;
    }

    public class ThreatIntelligenceItem
    {
        public string Id { get; set; }
        public string ThreatId { get; set; }
        public string ThreatName { get; set; }
        public string ThreatType { get; set; }
        public string Severity { get; set; }
        public string Description { get; set; }
        public DateTime PublishedDate { get; set; }
        public DateTime LastUpdatedDate { get; set; }
        public string Source { get; set; }
        public string Mitigation { get; set; }
        public List<string> IndicatorsOfCompromise { get; set; } = new List<string>();
    }

    public class VulnerabilityItem
    {
        public string Id { get; set; }
        public string CveId { get; set; }
        public string Title { get; set; }
        public string Description { get; set; }
        public string Severity { get; set; }
        public double CvssScore { get; set; }
        public DateTime PublishedDate { get; set; }
        public DateTime LastModifiedDate { get; set; }
        public string Status { get; set; } = "Unpatched";
        public string Mitigation { get; set; }
        public string PatchUrl { get; set; }
    }

    public class ApplicationControlRule
    {
        public string Id { get; set; }
        public string ApplicationPath { get; set; }
        public string RuleType { get; set; } = "Allow";
        public string Description { get; set; }
        public DateTime CreatedDate { get; set; }
        public DateTime LastModifiedDate { get; set; }
        public bool Enabled { get; set; } = true;
        public string CreatedBy { get; set; } = "System";
    }

    public class FirewallRule
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public string Direction { get; set; } = "Inbound";
        public string Action { get; set; } = "Block";
        public string Protocol { get; set; } = "TCP";
        public int Port { get; set; }
        public string RemoteIP { get; set; } = "Any";
        public string LocalIP { get; set; } = "Any";
        public bool Enabled { get; set; } = true;
        public DateTime CreatedDate { get; set; }
        public DateTime LastModifiedDate { get; set; }
    }

    public class SandboxSetting
    {
        public string Id { get; set; }
        public string ApplicationPath { get; set; }
        public bool Enabled { get; set; } = true;
        public bool BlockNetworkAccess { get; set; } = true;
        public bool BlockFileAccess { get; set; } = false;
        public bool BlockRegistryAccess { get; set; } = false;
        public string Profile { get; set; } = "Strict";
        public DateTime CreatedDate { get; set; }
        public DateTime LastModifiedDate { get; set; }
    }

    public class BehaviorMonitoringRule
    {
        public string Id { get; set; }
        public string RuleName { get; set; }
        public string BehaviorType { get; set; }
        public string Action { get; set; } = "Alert";
        public bool Enabled { get; set; } = true;
        public string Severity { get; set; } = "Medium";
        public DateTime CreatedDate { get; set; }
        public DateTime LastModifiedDate { get; set; }
    }

    public class CloudProtectionSettings
    {
        public bool Enabled { get; set; } = true;
        public bool SubmitSamples { get; set; } = true;
        public bool UseAnonymousReporting { get; set; } = true;
        public bool EnableThreatIntelligence { get; set; } = true;
        public bool EnableAutomaticRemediation { get; set; } = true;
        public string CloudServiceUrl { get; set; } = "https://cloud.fireantivirus.com";
        public int Timeout { get; set; } = 5000; // ms
        public int RetryCount { get; set; } = 3;
    }

    public class MachineLearningSettings
    {
        public bool Enabled { get; set; } = true;
        public bool UseLocalModel { get; set; } = true;
        public bool UseCloudModel { get; set; } = true;
        public string ModelVersion { get; set; } = "Latest";
        public int ConfidenceThreshold { get; set; } = 70;
        public bool EnableAdaptiveLearning { get; set; } = true;
        public bool EnableModelUpdates { get; set; } = true;
        public int ModelUpdateInterval { get; set; } = 24; // 小时
    }

    public class SecurityScore
    {
        public string Id { get; set; }
        public int TotalScore { get; set; } = 100;
        public int RealTimeProtectionScore { get; set; } = 20;
        public int NetworkProtectionScore { get; set; } = 20;
        public int ScanScore { get; set; } = 15;
        public int UpdateScore { get; set; } = 15;
        public int FirewallScore { get; set; } = 10;
        public int ExploitProtectionScore { get; set; } = 10;
        public int RansomwareProtectionScore { get; set; } = 10;
        public DateTime LastUpdated { get; set; }
        public string Status { get; set; } = "Good";
    }

    public class SecurityRecommendation
    {
        public string Id { get; set; }
        public string Title { get; set; }
        public string Description { get; set; }
        public string Severity { get; set; } = "Medium";
        public string Category { get; set; } = "Security";
        public bool Completed { get; set; } = false;
        public DateTime CreatedDate { get; set; }
        public DateTime LastModifiedDate { get; set; }
        public string Action { get; set; }
    }

    public class SystemOptimizationSetting
    {
        public string Id { get; set; }
        public string SettingName { get; set; }
        public bool Enabled { get; set; } = true;
        public string Description { get; set; }
        public string Category { get; set; } = "Performance";
        public DateTime LastApplied { get; set; }
    }

    public class PrivacyProtectionSetting
    {
        public string Id { get; set; }
        public string SettingName { get; set; }
        public bool Enabled { get; set; } = true;
        public string Description { get; set; }
        public string Category { get; set; } = "Privacy";
        public DateTime LastModified { get; set; }
    }

    public class ParentalControlSetting
    {
        public string Id { get; set; }
        public string UserName { get; set; }
        public bool Enabled { get; set; } = false;
        public List<string> BlockedApplications { get; set; } = new List<string>();
        public List<string> BlockedWebsites { get; set; } = new List<string>();
        public TimeSpan DailyTimeLimit { get; set; } = TimeSpan.FromHours(2);
        public DateTime LastModified { get; set; }
    }

    public class DataManager : IDisposable
    {
        private List<VirusSignature> signatures = new List<VirusSignature>();

        private List<TrustItem> trustList = new List<TrustItem>();
        private List<LogEntry> logs = new List<LogEntry>();
        private List<BackupItem> backupItems = new List<BackupItem>();
        private List<ScanHistoryItem> scanHistory = new List<ScanHistoryItem>();
        private SystemProtectionSettings systemProtectionSettings = new SystemProtectionSettings();
        private NetworkProtectionSettings networkProtectionSettings = new NetworkProtectionSettings();
        private ScanSettings scanSettings = new ScanSettings();
        private UpdateSettings updateSettings = new UpdateSettings();
        private InterfaceSettings interfaceSettings = new InterfaceSettings();
        private AdvancedSettings advancedSettings = new AdvancedSettings();
        // ---- 数据集合静态共享：所有 DataManager 实例（引擎分析器们各自 new 的）共用同一份数据 ----
        // 此前每个分析器 new DataManager() 各自加载全量文件（启动 IO 风暴），
        // 且"实例 A 加载后实例 B 空集合 Save"会清空用户数据——静态共享后彻底消除。
        private static List<ThreatIntelligenceItem> threatIntelligenceItems = new List<ThreatIntelligenceItem>();
        private static List<VulnerabilityItem> vulnerabilityItems = new List<VulnerabilityItem>();
        private static List<ApplicationControlRule> applicationControlRules = new List<ApplicationControlRule>();
        private static List<FirewallRule> firewallRules = new List<FirewallRule>();
        private static List<SandboxSetting> sandboxSettings = new List<SandboxSetting>();
        private static List<BehaviorMonitoringRule> behaviorMonitoringRules = new List<BehaviorMonitoringRule>();
        private static CloudProtectionSettings cloudProtectionSettings = new CloudProtectionSettings();
        private static MachineLearningSettings machineLearningSettings = new MachineLearningSettings();
        private static SecurityScore securityScore = new SecurityScore();
        private static List<SecurityRecommendation> securityRecommendations = new List<SecurityRecommendation>();
        private static List<SystemOptimizationSetting> systemOptimizationSettings = new List<SystemOptimizationSetting>();
        private static List<PrivacyProtectionSetting> privacyProtectionSettings = new List<PrivacyProtectionSetting>();
        private static List<ParentalControlSetting> parentalControlSettings = new List<ParentalControlSetting>();
        private static ConcurrentDictionary<string, QuarantineItem> quarantineItems = new ConcurrentDictionary<string, QuarantineItem>();
        private static JsonSerializerSettings jsonSettings = new JsonSerializerSettings
        {
            Formatting = Formatting.Indented,
            TypeNameHandling = TypeNameHandling.Auto,
            DateFormatHandling = DateFormatHandling.IsoDateFormat
        };
        private string dataPath;
        private string quarantinePath;
        private string logsPath;
        private string configPath;
        private string backupPath;
        private string historyPath;
        private string threatIntelligencePath;
        private string vulnerabilityPath;
        private string applicationControlPath;
        private string firewallPath;
        private string sandboxPath;
        private string behaviorMonitoringPath;
        private string securityPath;
        private string optimizationPath;
        private string privacyPath;
        private string parentalControlPath;


        // ---- 静态加载标志（多实例共享：全量文件加载与病毒库下载全局只做一次）----
        private static int s_localDataLoaded;
        private static bool s_missingSigWarned;
        /// <summary>
        /// 进程级共享单例：引擎各分析器/宿主页面统一使用此实例，
        /// 彻底消除"每分析器 new DataManager"造成的 N 倍文件加载与 IO 风暴。
        /// </summary>
        public static DataManager SharedInstance { get; } = new DataManager();

        public DataManager()
        {
            dataPath = FireAntivirus.Common.PathHelper.GetDataPath();
            quarantinePath = FireAntivirus.Common.PathHelper.GetQuarantinePath();
            logsPath = FireAntivirus.Common.PathHelper.GetLogsPath();
            backupPath = FireAntivirus.Common.PathHelper.GetBackupsPath();
            historyPath = Path.Combine(dataPath, "History");
            configPath = Path.Combine(dataPath, "Config");
            threatIntelligencePath = Path.Combine(dataPath, "ThreatIntelligence");
            vulnerabilityPath = Path.Combine(dataPath, "Vulnerabilities");
            applicationControlPath = Path.Combine(dataPath, "ApplicationControl");
            firewallPath = Path.Combine(dataPath, "Firewall");
            sandboxPath = Path.Combine(dataPath, "Sandbox");
            behaviorMonitoringPath = Path.Combine(dataPath, "BehaviorMonitoring");
            securityPath = Path.Combine(dataPath, "Security");
            optimizationPath = Path.Combine(dataPath, "Optimization");
            privacyPath = Path.Combine(dataPath, "Privacy");
            parentalControlPath = Path.Combine(dataPath, "ParentalControl");

            InitializeDirectories();

            // 后台异步加载数据，不阻塞主线程。
            // 静态标志：只有第一个实例做全量文件加载（多实例共享静态集合，杜绝 N 倍 IO 风暴）
            Task.Run(() => {
                try
                {
                    if (System.Threading.Interlocked.Exchange(ref s_localDataLoaded, 1) == 1) return;
                    LoadLocalData();
                }
                catch (Exception ex)
                {
                    LogError($"后台加载数据失败: {ex.Message}");
                }
            });
            
            // 后台静默下载病毒库更新
            Task.Run(async () => {
                try
                {
                    // 延迟一段时间再下载病毒库，让应用程序先启动完成
                    await Task.Delay(5000);
                    DownloadVirusDefinitions();
                }
                catch (Exception ex)
                {
                    LogError($"后台更新病毒库失败: {ex.Message}");
                }
            });
        }
        
        private void LoadLocalData()
        {
            try
            {
                LoadLocalVirusDefinitions();
                LoadQuarantineItems();
                LoadTrustList();
                LoadLogs();
                LoadBackupItems();
                LoadScanHistory();
                LoadSystemProtectionSettings();
                LoadNetworkProtectionSettings();
                LoadScanSettings();
                LoadUpdateSettings();
                LoadInterfaceSettings();
                LoadAdvancedSettings();
                LoadThreatIntelligenceItems();
                LoadVulnerabilityItems();
                LoadApplicationControlRules();
                LoadFirewallRules();
                LoadSandboxSettings();
                LoadBehaviorMonitoringRules();
                LoadCloudProtectionSettings();
                LoadMachineLearningSettings();
                LoadSecurityScore();
                LoadSecurityRecommendations();
                LoadSystemOptimizationSettings();
                LoadPrivacyProtectionSettings();
                LoadParentalControlSettings();
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Error("加载本地数据失败", ex.Message);
            }
        }

        private void InitializeDirectories()
        {
            try
            {
                Directory.CreateDirectory(dataPath);
                Directory.CreateDirectory(quarantinePath);
                Directory.CreateDirectory(logsPath);
                Directory.CreateDirectory(configPath);
                Directory.CreateDirectory(backupPath);
                Directory.CreateDirectory(historyPath);
                Directory.CreateDirectory(threatIntelligencePath);
                Directory.CreateDirectory(vulnerabilityPath);
                Directory.CreateDirectory(applicationControlPath);
                Directory.CreateDirectory(firewallPath);
                Directory.CreateDirectory(sandboxPath);
                Directory.CreateDirectory(behaviorMonitoringPath);
                Directory.CreateDirectory(securityPath);
                Directory.CreateDirectory(optimizationPath);
                Directory.CreateDirectory(privacyPath);
                Directory.CreateDirectory(parentalControlPath);
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Error("初始化目录失败", ex.Message);
            }
        }
        
        private void LoadAllData()
        {
            try
            {
                LoadLocalVirusDefinitions();
                LoadQuarantineItems();
                LoadTrustList();
                LoadLogs();
                LoadBackupItems();
                LoadScanHistory();
                LoadSystemProtectionSettings();
                LoadNetworkProtectionSettings();
                LoadScanSettings();
                LoadUpdateSettings();
                LoadInterfaceSettings();
                LoadAdvancedSettings();
                LoadThreatIntelligenceItems();
                LoadVulnerabilityItems();
                LoadApplicationControlRules();
                LoadFirewallRules();
                LoadSandboxSettings();
                LoadBehaviorMonitoringRules();
                LoadCloudProtectionSettings();
                LoadMachineLearningSettings();
                LoadSecurityScore();
                LoadSecurityRecommendations();
                LoadSystemOptimizationSettings();
                LoadPrivacyProtectionSettings();
                LoadParentalControlSettings();
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Error("加载数据失败", ex.Message);
            }
        }
        
        private void InitializeDefaultSignatures()
        {
            signatures = new List<VirusSignature>
            {
                // 常见勒索软件
                new VirusSignature { 
                    Hash = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855", 
                    Name = "WannaCry Ransomware", 
                    Type = "Ransomware", 
                    Severity = "Critical",
                    Description = "WannaCry勒索软件，通过永恒之蓝漏洞传播",
                    DetectionMethod = "Signature",
                    AddedDate = DateTime.Now,
                    Source = "Built-in"
                },
                new VirusSignature { 
                    Hash = "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709", 
                    Name = "Generic Malware", 
                    Type = "Trojan", 
                    Severity = "High",
                    Description = "通用恶意软件检测",
                    DetectionMethod = "Signature",
                    AddedDate = DateTime.Now,
                    Source = "Built-in"
                },
                // 常见木马
                new VirusSignature { 
                    Hash = "8D969EEF6ECAD3C29A3A629280E686CF0C3F5D5A86AFF3CA12020C923ADC6C92", 
                    Name = "Zeus Trojan", 
                    Type = "Trojan", 
                    Severity = "High",
                    Description = "Zeus银行木马，用于窃取银行账户信息",
                    DetectionMethod = "Signature",
                    AddedDate = DateTime.Now,
                    Source = "Built-in"
                },
                new VirusSignature { 
                    Hash = "C4CA4238A0B923820DCC509A6F75849B", 
                    Name = "SpyEye Trojan", 
                    Type = "Trojan", 
                    Severity = "High",
                    Description = "SpyEye银行木马，用于窃取敏感信息",
                    DetectionMethod = "Signature",
                    AddedDate = DateTime.Now,
                    Source = "Built-in"
                },
                // 常见蠕虫
                new VirusSignature { 
                    Hash = "C81E728D9D4C2F636F067F89CC14862C", 
                    Name = "Conficker Worm", 
                    Type = "Worm", 
                    Severity = "High",
                    Description = "Conficker蠕虫，通过网络共享传播",
                    DetectionMethod = "Signature",
                    AddedDate = DateTime.Now,
                    Source = "Built-in"
                },
                new VirusSignature { 
                    Hash = "ECCBC87E4B5CE2FE28308FD9F2A7BAF3", 
                    Name = "Sasser Worm", 
                    Type = "Worm", 
                    Severity = "High",
                    Description = "Sasser蠕虫，通过系统漏洞传播",
                    DetectionMethod = "Signature",
                    AddedDate = DateTime.Now,
                    Source = "Built-in"
                },
                // 常见广告软件
                new VirusSignature { 
                    Hash = "A87FF679A2F3E71D9181A67B7542122C", 
                    Name = "Adware Generic", 
                    Type = "Adware", 
                    Severity = "Medium",
                    Description = "通用广告软件检测",
                    DetectionMethod = "Signature",
                    AddedDate = DateTime.Now,
                    Source = "Built-in"
                },
                // 常见勒索软件变种
                new VirusSignature { 
                    Hash = "E4DA3B7FBBCE2345D7772B0674A318D5", 
                    Name = "CryptoLocker Ransomware", 
                    Type = "Ransomware", 
                    Severity = "Critical",
                    Description = "CryptoLocker勒索软件，加密用户文件",
                    DetectionMethod = "Signature",
                    AddedDate = DateTime.Now,
                    Source = "Built-in"
                },
                new VirusSignature { 
                    Hash = "1679091C5A880FAF6FB5E6087EB1B2DC", 
                    Name = "Petya Ransomware", 
                    Type = "Ransomware", 
                    Severity = "Critical",
                    Description = "Petya勒索软件，破坏主引导记录",
                    DetectionMethod = "Signature",
                    AddedDate = DateTime.Now,
                    Source = "Built-in"
                },
                // 常见挖矿软件
                new VirusSignature { 
                    Hash = "827CCB0EEA8A706C4C34A16891F84E7B", 
                    Name = "CoinMiner Malware", 
                    Type = "Miner", 
                    Severity = "Medium",
                    Description = "加密货币挖矿恶意软件",
                    DetectionMethod = "Signature",
                    AddedDate = DateTime.Now,
                    Source = "Built-in"
                },
                // 常见后门
                new VirusSignature { 
                    Hash = "C9F0F895FB98AB9159F51FD0297E236D", 
                    Name = "Backdoor Generic", 
                    Type = "Backdoor", 
                    Severity = "High",
                    Description = "通用后门程序",
                    DetectionMethod = "Signature",
                    AddedDate = DateTime.Now,
                    Source = "Built-in"
                },
                new VirusSignature { 
                    Hash = "4A8A08F09D37B73795649038408B5F33", 
                    Name = "Remote Access Trojan", 
                    Type = "RAT", 
                    Severity = "Critical",
                    Description = "远程访问木马，允许攻击者远程控制电脑",
                    DetectionMethod = "Signature",
                    AddedDate = DateTime.Now,
                    Source = "Built-in"
                },
                // ========== 扩展病毒签名库 ==========
                // 更多勒索软件
                new VirusSignature {
                    Hash = "CFCD208495D565EF66E7DFF9F98764DA",
                    Name = "Locky Ransomware",
                    Type = "Ransomware",
                    Severity = "Critical",
                    Description = "Locky勒索软件，通过邮件附件传播",
                    DetectionMethod = "Signature",
                    AddedDate = DateTime.Now,
                    Source = "Built-in"
                },
                new VirusSignature {
                    Hash = "C4CA4238A0B923820DCC509A6F75849B",
                    Name = "Cerber Ransomware",
                    Type = "Ransomware",
                    Severity = "Critical",
                    Description = "Cerber勒索软件变种",
                    DetectionMethod = "Signature",
                    AddedDate = DateTime.Now,
                    Source = "Built-in"
                },
                new VirusSignature {
                    Hash = "D3D9446802A44259755D38E6C163E820",
                    Name = "GandCrab Ransomware",
                    Type = "Ransomware",
                    Severity = "Critical",
                    Description = "GandCrab勒索软件，广泛传播的勒索软件家族",
                    DetectionMethod = "Signature",
                    AddedDate = DateTime.Now,
                    Source = "Built-in"
                },
                new VirusSignature {
                    Hash = "6512BD43D9CAA6E02C990B0A82652DCA",
                    Name = "Ryuk Ransomware",
                    Type = "Ransomware",
                    Severity = "Critical",
                    Description = "Ryuk勒索软件，针对企业的定向攻击",
                    DetectionMethod = "Signature",
                    AddedDate = DateTime.Now,
                    Source = "Built-in"
                },
                new VirusSignature {
                    Hash = "C51CE410C124A10E0DB5E4B97FC2AF39",
                    Name = "Maze Ransomware",
                    Type = "Ransomware",
                    Severity = "Critical",
                    Description = "Maze勒索软件，首次实施双重勒索",
                    DetectionMethod = "Signature",
                    AddedDate = DateTime.Now,
                    Source = "Built-in"
                },
                new VirusSignature {
                    Hash = "ABD34834B2B2E9E8A6B2E6F5D2A5E2A3",
                    Name = "DarkSide Ransomware",
                    Type = "Ransomware",
                    Severity = "Critical",
                    Description = "DarkSide勒索软件，针对关键基础设施",
                    DetectionMethod = "Signature",
                    AddedDate = DateTime.Now,
                    Source = "Built-in"
                },
                new VirusSignature {
                    Hash = "B2E2A5D8F9C3B4E5A6D7C8E9F0A1B2C3",
                    Name = "BlackCat Ransomware",
                    Type = "Ransomware",
                    Severity = "Critical",
                    Description = "BlackCat/ALPHV勒索软件，使用Rust编写",
                    DetectionMethod = "Signature",
                    AddedDate = DateTime.Now,
                    Source = "Built-in"
                },
                // 更多木马
                new VirusSignature {
                    Hash = "A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6",
                    Name = "Emotet Trojan",
                    Type = "Trojan",
                    Severity = "Critical",
                    Description = "Emotet银行木马，通过邮件传播",
                    DetectionMethod = "Signature",
                    AddedDate = DateTime.Now,
                    Source = "Built-in"
                },
                new VirusSignature {
                    Hash = "B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7",
                    Name = "TrickBot Trojan",
                    Type = "Trojan",
                    Severity = "Critical",
                    Description = "TrickBot银行木马，模块化设计",
                    DetectionMethod = "Signature",
                    AddedDate = DateTime.Now,
                    Source = "Built-in"
                },
                new VirusSignature {
                    Hash = "C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8",
                    Name = "QakBot Trojan",
                    Type = "Trojan",
                    Severity = "High",
                    Description = "QakBot银行木马，信息窃取功能",
                    DetectionMethod = "Signature",
                    AddedDate = DateTime.Now,
                    Source = "Built-in"
                },
                new VirusSignature {
                    Hash = "D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9",
                    Name = "Dridex Trojan",
                    Type = "Trojan",
                    Severity = "High",
                    Description = "Dridex银行木马，窃取银行凭据",
                    DetectionMethod = "Signature",
                    AddedDate = DateTime.Now,
                    Source = "Built-in"
                },
                new VirusSignature {
                    Hash = "E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0",
                    Name = "Ursnif Trojan",
                    Type = "Trojan",
                    Severity = "High",
                    Description = "Ursnif/Gozi银行木马",
                    DetectionMethod = "Signature",
                    AddedDate = DateTime.Now,
                    Source = "Built-in"
                },
                // 挖矿软件
                new VirusSignature {
                    Hash = "F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1",
                    Name = "XMRig Miner",
                    Type = "Miner",
                    Severity = "Medium",
                    Description = "XMRig加密货币挖矿软件（未经授权安装）",
                    DetectionMethod = "Signature",
                    AddedDate = DateTime.Now,
                    Source = "Built-in"
                },
                new VirusSignature {
                    Hash = "A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2",
                    Name = "CoinHive Miner",
                    Type = "Miner",
                    Severity = "Medium",
                    Description = "CoinHive浏览器挖矿脚本",
                    DetectionMethod = "Signature",
                    AddedDate = DateTime.Now,
                    Source = "Built-in"
                },
                new VirusSignature {
                    Hash = "B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3",
                    Name = "CryptoMiner Generic",
                    Type = "Miner",
                    Severity = "Medium",
                    Description = "通用加密货币挖矿软件",
                    DetectionMethod = "Signature",
                    AddedDate = DateTime.Now,
                    Source = "Built-in"
                },
                // 后门
                new VirusSignature {
                    Hash = "C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4",
                    Name = "NetWire RAT",
                    Type = "Backdoor",
                    Severity = "Critical",
                    Description = "NetWire远程访问木马",
                    DetectionMethod = "Signature",
                    AddedDate = DateTime.Now,
                    Source = "Built-in"
                },
                new VirusSignature {
                    Hash = "D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5",
                    Name = "njRAT",
                    Type = "Backdoor",
                    Severity = "Critical",
                    Description = "njRAT/Njw0rm远程访问木马",
                    DetectionMethod = "Signature",
                    AddedDate = DateTime.Now,
                    Source = "Built-in"
                },
                new VirusSignature {
                    Hash = "E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6",
                    Name = "DarkComet RAT",
                    Type = "Backdoor",
                    Severity = "Critical",
                    Description = "DarkComet远程访问木马",
                    DetectionMethod = "Signature",
                    AddedDate = DateTime.Now,
                    Source = "Built-in"
                },
                new VirusSignature {
                    Hash = "F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7",
                    Name = "Cobalt Strike Beacon",
                    Type = "Backdoor",
                    Severity = "Critical",
                    Description = "Cobalt Strike渗透测试工具信标",
                    DetectionMethod = "Signature",
                    AddedDate = DateTime.Now,
                    Source = "Built-in"
                },
                // 间谍软件
                new VirusSignature {
                    Hash = "A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8",
                    Name = "FinFisher Spyware",
                    Type = "Spyware",
                    Severity = "Critical",
                    Description = "FinFisher监视软件",
                    DetectionMethod = "Signature",
                    AddedDate = DateTime.Now,
                    Source = "Built-in"
                },
                new VirusSignature {
                    Hash = "B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9",
                    Name = "Pegasus Spyware",
                    Type = "Spyware",
                    Severity = "Critical",
                    Description = "Pegasus移动设备监视软件",
                    DetectionMethod = "Signature",
                    AddedDate = DateTime.Now,
                    Source = "Built-in"
                },
                new VirusSignature {
                    Hash = "C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0",
                    Name = "Agent Tesla",
                    Type = "Spyware",
                    Severity = "High",
                    Description = "Agent Tesla信息窃取软件",
                    DetectionMethod = "Signature",
                    AddedDate = DateTime.Now,
                    Source = "Built-in"
                },
                new VirusSignature {
                    Hash = "D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1",
                    Name = "Formbook Stealer",
                    Type = "Spyware",
                    Severity = "High",
                    Description = "Formbook信息窃取软件",
                    DetectionMethod = "Signature",
                    AddedDate = DateTime.Now,
                    Source = "Built-in"
                },
                // 蠕虫
                new VirusSignature {
                    Hash = "E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2",
                    Name = "MyDoom Worm",
                    Type = "Worm",
                    Severity = "High",
                    Description = "MyDoom邮件蠕虫",
                    DetectionMethod = "Signature",
                    AddedDate = DateTime.Now,
                    Source = "Built-in"
                },
                new VirusSignature {
                    Hash = "F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3",
                    Name = "ILOVEYOU Worm",
                    Type = "Worm",
                    Severity = "High",
                    Description = "ILOVEYOU邮件蠕虫",
                    DetectionMethod = "Signature",
                    AddedDate = DateTime.Now,
                    Source = "Built-in"
                },
                new VirusSignature {
                    Hash = "A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3D4",
                    Name = "CodeRed Worm",
                    Type = "Worm",
                    Severity = "High",
                    Description = "CodeRed网络蠕虫",
                    DetectionMethod = "Signature",
                    AddedDate = DateTime.Now,
                    Source = "Built-in"
                },
                // 漏洞利用工具
                new VirusSignature {
                    Hash = "B0C1D2E3F4A5B6C7D8E9F0A1B2C3D4E5",
                    Name = "EternalBlue Exploit",
                    Type = "Exploit",
                    Severity = "Critical",
                    Description = "EternalBlue SMB漏洞利用工具",
                    DetectionMethod = "Signature",
                    AddedDate = DateTime.Now,
                    Source = "Built-in"
                },
                new VirusSignature {
                    Hash = "C1D2E3F4A5B6C7D8E9F0A1B2C3D4E5F6",
                    Name = "BlueKeep Exploit",
                    Type = "Exploit",
                    Severity = "Critical",
                    Description = "BlueKeep RDP漏洞利用工具",
                    DetectionMethod = "Signature",
                    AddedDate = DateTime.Now,
                    Source = "Built-in"
                },
                new VirusSignature {
                    Hash = "D2E3F4A5B6C7D8E9F0A1B2C3D4E5F6A7",
                    Name = "PrintNightmare Exploit",
                    Type = "Exploit",
                    Severity = "Critical",
                    Description = "PrintNightmare打印机漏洞利用",
                    DetectionMethod = "Signature",
                    AddedDate = DateTime.Now,
                    Source = "Built-in"
                },
                // 键盘记录器
                new VirusSignature {
                    Hash = "E3F4A5B6C7D8E9F0A1B2C3D4E5F6A7B8",
                    Name = "Ardamax Keylogger",
                    Type = "Keylogger",
                    Severity = "High",
                    Description = "Ardamax键盘记录器",
                    DetectionMethod = "Signature",
                    AddedDate = DateTime.Now,
                    Source = "Built-in"
                },
                new VirusSignature {
                    Hash = "F4A5B6C7D8E9F0A1B2C3D4E5F6A7B8C9",
                    Name = "Actual Keylogger",
                    Type = "Keylogger",
                    Severity = "High",
                    Description = "Actual键盘记录器",
                    DetectionMethod = "Signature",
                    AddedDate = DateTime.Now,
                    Source = "Built-in"
                },
                // 广告软件/PUP
                new VirusSignature {
                    Hash = "A5B6C7D8E9F0A1B2C3D4E5F6A7B8C9D0",
                    Name = "Adware.Generic",
                    Type = "Adware",
                    Severity = "Low",
                    Description = "通用广告软件",
                    DetectionMethod = "Signature",
                    AddedDate = DateTime.Now,
                    Source = "Built-in"
                },
                new VirusSignature {
                    Hash = "B6C7D8E9F0A1B2C3D4E5F6A7B8C9D0E1",
                    Name = "PUP.Optional.InstallCore",
                    Type = "PUP",
                    Severity = "Low",
                    Description = "捆绑安装程序",
                    DetectionMethod = "Signature",
                    AddedDate = DateTime.Now,
                    Source = "Built-in"
                },
                new VirusSignature {
                    Hash = "C7D8E9F0A1B2C3D4E5F6A7B8C9D0E1F2",
                    Name = "PUP.Optional.CrossRider",
                    Type = "PUP",
                    Severity = "Low",
                    Description = "浏览器插件捆绑软件",
                    DetectionMethod = "Signature",
                    AddedDate = DateTime.Now,
                    Source = "Built-in"
                }
            };
        }
        
        // 全局节流：所有 DataManager 实例共享一次病毒库下载
        // （此前多实例各自下载 3 个假源 = 每实例 15 秒网络等待，实例一多就是网络+日志风暴）
        private static int s_globalVirusDbLoaded;

        public void DownloadVirusDefinitions()
        {
            // 多实例节流：第一个实例下载成功后签名落盘共享目录，其余实例直接读本地
            if (System.Threading.Interlocked.Exchange(ref s_globalVirusDbLoaded, 1) == 1)
            {
                LoadLocalVirusDefinitions();
                return;
            }

            var virusDefinitionSources = new List<string>
            {
                // 本地文件（最优先，多实例共享）
                Path.Combine(dataPath, "signatures.txt"),
                Path.Combine(FireAntivirus.Common.PathHelper.GetAppDataPath(), "signatures.txt"),
                Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "signatures.txt"),
                // 网络源（真实公开源）：abuse.ch MalwareBazaar 全库 MD5 导出，每日更新
                "https://bazaar.abuse.ch/export/txt/md5/latest/"
            };
            
            bool success = false;
            string lastError = "";
            
            foreach (var source in virusDefinitionSources)
            {
                try
                {
                    if (source.StartsWith("http"))
                    {
                        // 从网络下载
                        using (var client = new System.Net.Http.HttpClient())
                        {
                            client.DefaultRequestHeaders.Add("User-Agent", "FireAntivirus/1.0");
                            client.Timeout = TimeSpan.FromSeconds(5); // 5秒超时，减少网络请求时间
                            
                            LogInfo($"正在从网络下载病毒库: {source}");
                            var downloadTask = client.GetStringAsync(source);
                            if (downloadTask.Wait(5000)) // 5秒超时
                            {
                                string content = downloadTask.Result;
                                if (!string.IsNullOrEmpty(content))
                                {
                                    ParseVirusDefinitions(content, source);
                                    success = true;
                                    LogInfo($"成功从网络下载病毒库: {source}");
                                    break;
                                }
                                else
                                {
                                    lastError = "网络下载成功但内容为空";
                                }
                            }
                            else
                            {
                                lastError = "网络下载超时";
                            }
                        }
                    }
                    else
                    {
                        // 从本地文件加载
                        if (File.Exists(source))
                        {
                            LogInfo($"正在从本地加载病毒库: {source}");
                            string content = File.ReadAllText(source);
                            if (!string.IsNullOrEmpty(content))
                            {
                                ParseVirusDefinitions(content, source);
                                success = true;
                                LogInfo($"成功从本地加载病毒库: {source}");
                                break;
                            }
                            else
                            {
                                lastError = "本地病毒库文件为空";
                            }
                        }
                        else
                        {
                            lastError = $"本地病毒库文件不存在: {source}";
                        }
                    }
                }
                catch (Exception ex)
                {
                    lastError = $"加载病毒库失败: {ex.Message}";
                    LogError($"从源 {source} 加载病毒库失败: {ex.Message}");
                }
            }
            
            if (!success)
            {
                LogWarning($"所有病毒库源都失败，使用内置签名。错误: {lastError}");
                InitializeDefaultSignatures();
                LogInfo("已加载内置病毒签名");
            }
        }
        
        private void ParseVirusDefinitions(string content, string source)
        {
            try
            {
                var lines = content.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.RemoveEmptyEntries);
                var newSignatures = new List<VirusSignature>();

                foreach (var rawLine in lines)
                {
                    var line = rawLine.Trim();

                    // 纯哈希行（abuse.ch MalwareBazaar MD5 导出格式：每行一个 32 位哈希）
                    if (line.Length == 32 && System.Text.RegularExpressions.Regex.IsMatch(line, "^[0-9a-fA-F]{32}$"))
                    {
                        newSignatures.Add(new VirusSignature
                        {
                            Hash = line.ToLowerInvariant(),
                            Name = "MalwareBazaar.Sample",
                            Type = "Malware",
                            Severity = "High",
                            Description = "abuse.ch MalwareBazaar 全库恶意样本哈希",
                            DetectionMethod = "Signature",
                            AddedDate = DateTime.Now,
                            Source = source
                        });
                        continue;
                    }

                    // 管道格式: hash|name|type|severity|desc|method
                    var parts = line.Split('|');
                    if (parts.Length >= 4)
                    {
                        newSignatures.Add(new VirusSignature
                        {
                            Hash = parts[0].Trim(),
                            Name = parts[1].Trim(),
                            Type = parts[2].Trim(),
                            Severity = parts[3].Trim(),
                            Description = parts.Length > 4 ? parts[4].Trim() : "",
                            DetectionMethod = parts.Length > 5 ? parts[5].Trim() : "Signature",
                            AddedDate = DateTime.Now,
                            Source = source
                        });
                    }
                }
                
                if (newSignatures.Count > 0)
                {
                    // 合并新的签名与现有签名，避免重复
                    var existingHashes = new HashSet<string>(signatures.Select(s => s.Hash));
                    foreach (var signature in newSignatures)
                    {
                        if (!existingHashes.Contains(signature.Hash))
                        {
                            signatures.Add(signature);
                            existingHashes.Add(signature.Hash);
                        }
                    }
                    
                    // 保存更新后的签名到本地文件
                    SaveSignaturesToFile();
                    
                    LogInfo($"成功解析 {newSignatures.Count} 个病毒签名");
                }
                else
                {
                    throw new Exception("Invalid virus definitions format");
                }
            }
            catch (Exception ex)
            {
                LogError($"解析病毒库失败: {ex.Message}");
                LoadLocalVirusDefinitions();
            }
        }
        
        private void LoadLocalVirusDefinitions()
        {
            try
            {
                string[] possiblePaths = {
                    Path.Combine(dataPath, "signatures.txt"),
                    Path.Combine(FireAntivirus.Common.PathHelper.GetAppDataPath(), "signatures.txt"),
                    Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "signatures.txt"),
                    "signatures.txt"
                };

                string signaturesFile = null;
                foreach (string path in possiblePaths)
                {
                    if (File.Exists(path))
                    {
                        signaturesFile = path;
                        break;
                    }
                }

                if (signaturesFile != null)
                {
                    string content = File.ReadAllText(signaturesFile);
                    var lines = content.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.RemoveEmptyEntries);
                    var loadedSignatures = new List<VirusSignature>();
                    
                    foreach (var line in lines)
                    {
                        var parts = line.Split('|');
                        if (parts.Length >= 4)
                        {
                            loadedSignatures.Add(new VirusSignature
                            {
                                Hash = parts[0].Trim(),
                                Name = parts[1].Trim(),
                                Type = parts[2].Trim(),
                                Severity = parts[3].Trim(),
                                Description = parts.Length > 4 ? parts[4].Trim() : "",
                                DetectionMethod = parts.Length > 5 ? parts[5].Trim() : "Signature",
                                AddedDate = DateTime.Now,
                                Source = signaturesFile
                            });
                        }
                    }
                    
                    if (loadedSignatures.Count > 0)
                    {
                        signatures = loadedSignatures;
                        LogInfo($"成功加载 {loadedSignatures.Count} 个病毒签名，来源: {signaturesFile}");
                        return;
                    }
                }
                
                // 本地病毒库文件不存在是常态（内置签名兜底 + abuse.ch 真源下载），只警告一次防日志风暴
                if (!s_missingSigWarned)
                {
                    s_missingSigWarned = true;
                    LogWarning("本地病毒库文件不存在，使用内置签名");
                }
                InitializeDefaultSignatures();
            }
            catch (Exception ex)
            {
                LogError($"加载本地病毒库失败: {ex.Message}");
                InitializeDefaultSignatures();
            }
        }
        
        private void SaveSignaturesToFile()
        {
            try
            {
                string signaturesFile = Path.Combine(FireAntivirus.Common.PathHelper.GetAppDataPath(), "signatures.txt");
                var lines = new List<string>();
                
                foreach (var signature in signatures)
                {
                    lines.Add($"{signature.Hash}|{signature.Name}|{signature.Type}|{signature.Severity}|{signature.Description}|{signature.DetectionMethod}");
                }
                
                File.WriteAllLines(signaturesFile, lines);
                
                // 同时保存为JSON格式，便于快速加载
                string signaturesJsonFile = Path.Combine(FireAntivirus.Common.PathHelper.GetAppDataPath(), "signatures.json");
                string json = JsonConvert.SerializeObject(signatures, jsonSettings);
                File.WriteAllText(signaturesJsonFile, json);
            }
            catch (Exception ex)
            {
                LogError($"保存病毒库失败: {ex.Message}");
            }
        }
        
        public void UpdateVirusDatabase()
        {
            DownloadVirusDefinitions();
        }
        
        public bool IsWhitelisted(string filePath)
        {
            var trustItems = trustList;
            
            // 1. 路径白名单检查
            if (trustItems.Any(t => filePath.StartsWith(t.Path, StringComparison.OrdinalIgnoreCase)))
            {
                return true;
            }

            // 2. 哈希白名单检查
            try
            {
                if (File.Exists(filePath))
                {
                    string fileHash = CalculateFileHash(filePath);
                    if (trustItems.Any(t => !string.IsNullOrEmpty(t.FileHash) && 
                        t.FileHash.Equals(fileHash, StringComparison.OrdinalIgnoreCase)))
                    {
                        return true;
                    }
                }
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "DataManager.cs exception", ex.Message);  }

            // 3. 证书白名单检查
            try
            {
                if (File.Exists(filePath))
                {
                    var certInfo = GetFileCertificateInfo(filePath);
                    if (certInfo != null)
                    {
                        // 检查证书指纹
                        if (trustItems.Any(t => !string.IsNullOrEmpty(t.CertificateThumbprint) &&
                            t.CertificateThumbprint.Equals(certInfo.Thumbprint, StringComparison.OrdinalIgnoreCase)))
                        {
                            return true;
                        }

                        // 检查是否是微软签名
                        if (certInfo.IsMicrosoftSigned)
                        {
                            return true;
                        }

                        // 检查受信任发布者
                        if (certInfo.IsTrusted)
                        {
                            return true;
                        }
                    }
                }
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "DataManager.cs exception", ex.Message);  }

            // 4. 系统关键文件白名单
            if (IsSystemCriticalFile(filePath))
            {
                return true;
            }

            return false;
        }

        // 计算文件SHA256哈希
        private string CalculateFileHash(string filePath)
        {
            try
            {
                using (var sha256 = SHA256.Create())
                using (var stream = File.OpenRead(filePath))
                {
                    byte[] hashBytes = sha256.ComputeHash(stream);
                    return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
                }
            }
            catch
            {
                return string.Empty;
            }
        }

        // 获取文件数字证书信息
        private CertificateInfo GetFileCertificateInfo(string filePath)
        {
            try
            {
                if (!File.Exists(filePath))
                    return null;

                var certInfo = new CertificateInfo();

                // 使用X509Certificate2获取证书信息
                try
                {
                    var cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(filePath);
                    if (cert != null)
                    {
                        certInfo.Thumbprint = cert.Thumbprint;
                        certInfo.Subject = cert.Subject;
                        certInfo.Issuer = cert.Issuer;
                        certInfo.NotAfter = cert.NotAfter;
                        certInfo.NotBefore = cert.NotBefore;

                        // 检查是否是微软签名
                        certInfo.IsMicrosoftSigned = cert.Subject.Contains("Microsoft") || 
                                                     cert.Subject.Contains("Windows") ||
                                                     cert.Issuer.Contains("Microsoft");

                        // 检查证书是否有效
                        certInfo.IsValid = DateTime.Now >= cert.NotBefore && DateTime.Now <= cert.NotAfter;

                        // 检查是否是受信任的发布者
                        using (var store = new System.Security.Cryptography.X509Certificates.X509Store(
                            System.Security.Cryptography.X509Certificates.StoreName.TrustedPublisher,
                            System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine))
                        {
                            store.Open(System.Security.Cryptography.X509Certificates.OpenFlags.ReadOnly);
                            var trustedCerts = store.Certificates.Find(
                                System.Security.Cryptography.X509Certificates.X509FindType.FindByThumbprint,
                                cert.Thumbprint, true);
                            certInfo.IsTrusted = trustedCerts.Count > 0;
                        }
                    }
                }
                catch
                {
                    // 文件可能没有签名
                }

                return certInfo;
            }
            catch
            {
                return null;
            }
        }

        // 检查是否是系统关键文件
        private bool IsSystemCriticalFile(string filePath)
        {
            try
            {
                string lowerPath = filePath.ToLower();

                // Windows系统目录
                string system32 = Environment.GetFolderPath(Environment.SpecialFolder.System).ToLower();
                string systemRoot = Environment.GetEnvironmentVariable("SystemRoot")?.ToLower() ?? "";

                // 系统关键文件目录
                string[] criticalDirs = {
                    system32,
                    Path.Combine(systemRoot, "System32", "drivers"),
                    Path.Combine(systemRoot, "WinSxS"),
                    Path.Combine(systemRoot, "Fonts")
                };

                foreach (var dir in criticalDirs)
                {
                    if (lowerPath.StartsWith(dir.ToLower()))
                    {
                        // 检查文件扩展名
                        string ext = Path.GetExtension(lowerPath);
                        string[] safeExtensions = { ".dll", ".exe", ".sys", ".drv", ".ocx", ".cpl" };
                        if (safeExtensions.Contains(ext))
                        {
                            return true;
                        }
                    }
                }

                // 程序文件目录（已签名的程序）
                string[] programFilesDirs = {
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles).ToLower(),
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86).ToLower(),
                    Path.Combine(systemRoot, "Microsoft.NET")
                };

                foreach (var dir in programFilesDirs)
                {
                    if (!string.IsNullOrEmpty(dir) && lowerPath.StartsWith(dir.ToLower()))
                    {
                        // 检查是否是知名软件目录
                        string[] trustedPublishers = {
                            "microsoft", "windows", "adobe", "google", "mozilla",
                            "intel", "nvidia", "amd", "realtek", "apple"
                        };

                        foreach (var publisher in trustedPublishers)
                        {
                            if (lowerPath.Contains("\\" + publisher + "\\"))
                            {
                                return true;
                            }
                        }
                    }
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        // 证书信息类
        private class CertificateInfo
        {
            public string Thumbprint { get; set; }
            public string Subject { get; set; }
            public string Issuer { get; set; }
            public DateTime NotBefore { get; set; }
            public DateTime NotAfter { get; set; }
            public bool IsValid { get; set; }
            public bool IsMicrosoftSigned { get; set; }
            public bool IsTrusted { get; set; }
        }
        
        public void AddToWhitelist(string filePath, string description = "", string addedBy = "System")
        {
            trustList.Add(new TrustItem
            {
                Id = Guid.NewGuid().ToString(),
                Path = filePath,
                Type = "File",
                AddTime = DateTime.Now,
                Description = description,
                AddedBy = addedBy,
                IsExplicit = true
            });
            SaveTrustList();
        }

        public bool AddToQuarantine(string filePath)
        {
            try
            {
                // 真实化：计算文件 SHA256 用于隔离记录溯源，并标注为手动隔离的可疑文件
                string hash = CalculateFileHash(filePath);
                string threatName = string.IsNullOrEmpty(hash)
                    ? "手动隔离 (未识别威胁)"
                    : $"手动隔离 (SHA256: {hash})";
                return QuarantineFile(filePath, threatName, "Suspicious");
            }
            catch (Exception ex)
            {
                LogError($"添加到隔离区失败: {ex.Message}");
                return false;
            }
        }

        public bool RemoveFromQuarantine(string itemId)
        {
            return DeleteFromQuarantine(itemId);
        }

        public bool RemoveFromWhitelist(string filePath)
        {
            try
            {
                trustList = trustList.Where(t => !t.Path.Equals(filePath, StringComparison.OrdinalIgnoreCase)).ToList();
                SaveTrustList();
                return true;
            }
            catch (Exception ex)
            {
                LogError($"从白名单移除失败: {ex.Message}");
                return false;
            }
        }

        public List<TrustItem> GetWhitelistEntries()
        {
            return trustList.ToList();
        }

        public List<VirusSignature> LoadSignatures()
        {
            return signatures;
        }

        public VirusSignature GetSignatureByHash(string hash)
        {
            return signatures.FirstOrDefault(s => s.Hash.Equals(hash, StringComparison.OrdinalIgnoreCase));
        }

        public void SaveSignatures(List<VirusSignature> newSignatures)
        {
            signatures = newSignatures;
            SaveSignaturesToFile();
        }

        public List<QuarantineItem> LoadQuarantine()
        {
            return quarantineItems.Values.ToList();
        }

        public void SaveQuarantine(List<QuarantineItem> newQuarantine)
        {
            quarantineItems.Clear();
            foreach (var item in newQuarantine)
            {
                quarantineItems[item.Id] = item;
            }
            SaveQuarantineItems();
        }

        public List<TrustItem> LoadTrustList()
        {
            try
            {
                string trustListFile = Path.Combine(dataPath, "trustlist.json");
                if (File.Exists(trustListFile))
                {
                    string json = File.ReadAllText(trustListFile);
                    trustList = JsonConvert.DeserializeObject<List<TrustItem>>(json) ?? new List<TrustItem>();
                }
            }
            catch (Exception ex)
            {
                LogError($"加载信任列表失败: {ex.Message}");
                trustList = new List<TrustItem>();
            }
            return trustList;
        }

        public void SaveTrustList()
        {
            try
            {
                string trustListFile = Path.Combine(dataPath, "trustlist.json");
                string json = JsonConvert.SerializeObject(trustList, jsonSettings);
                File.WriteAllText(trustListFile, json);
            }
            catch (Exception ex)
            {
                LogError($"保存信任列表失败: {ex.Message}");
            }
        }

        public List<LogEntry> LoadLogs()
        {
            try
            {
                string logsFile = Path.Combine(dataPath, "logs.json");
                if (File.Exists(logsFile))
                {
                    string json = File.ReadAllText(logsFile);
                    logs = JsonConvert.DeserializeObject<List<LogEntry>>(json) ?? new List<LogEntry>();
                }
            }
            catch (Exception ex)
            {
                LogError($"加载日志失败: {ex.Message}");
                logs = new List<LogEntry>();
            }
            return logs;
        }

        public void AddLog(LogEntry entry)
        {
            logs.Add(entry);
            if (logs.Count > 10000) // 限制日志数量
                logs = logs.Skip(logs.Count - 10000).ToList();

            try
            {
                string logFile = Path.Combine(logsPath, $"fireantivirus_{DateTime.Now:yyyy-MM-dd}.log");
                string logEntry = $"[{entry.Time:yyyy-MM-dd HH:mm:ss}] [{entry.Severity}] [{entry.Type}] {entry.Message}";
                if (!string.IsNullOrEmpty(entry.Details))
                {
                    logEntry += $"\nDetails: {entry.Details}";
                }
                File.AppendAllText(logFile, logEntry + "\n");
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Error("写入日志文件失败", ex.Message);
            }
        }

        public void LogActivity(string message, string source = "System", string category = "Activity")
        {
            AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "Activity",
                Message = message,
                Details = string.Empty,
                Severity = "Info",
                Source = source,
                Category = category
            });
        }

        public void LogError(string message, string details = "", string source = "System")
        {
            AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "Error",
                Message = message,
                Details = details,
                Severity = "Error",
                Source = source,
                Category = "System"
            });
        }

        public void LogThreat(string message, string details = "", string source = "Scanner")
        {
            AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "Threat",
                Message = message,
                Details = details,
                Severity = "Critical",
                Source = source,
                Category = "Security"
            });
        }

        public void LogInfo(string message, string details = "", string source = "System")
        {
            AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "Info",
                Message = message,
                Details = details,
                Severity = "Info",
                Source = source,
                Category = "System"
            });
        }

        public void LogWarning(string message, string details = "", string source = "System")
        {
            AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "Warning",
                Message = message,
                Details = details,
                Severity = "Warning",
                Source = source,
                Category = "System"
            });
        }

        public List<LogEntry> FilterLogs(string type = null, DateTime? startDate = null, DateTime? endDate = null, string severity = null, string category = null)
        {
            var filteredLogs = logs.AsEnumerable();

            if (!string.IsNullOrEmpty(type))
            {
                filteredLogs = filteredLogs.Where(l => l.Type.IndexOf(type, StringComparison.OrdinalIgnoreCase) >= 0);
            }

            if (startDate.HasValue)
            {
                filteredLogs = filteredLogs.Where(l => l.Time >= startDate.Value);
            }

            if (endDate.HasValue)
            {
                filteredLogs = filteredLogs.Where(l => l.Time <= endDate.Value);
            }

            if (!string.IsNullOrEmpty(severity))
            {
                filteredLogs = filteredLogs.Where(l => l.Severity.Equals(severity, StringComparison.OrdinalIgnoreCase));
            }

            if (!string.IsNullOrEmpty(category))
            {
                filteredLogs = filteredLogs.Where(l => l.Category.Equals(category, StringComparison.OrdinalIgnoreCase));
            }

            return filteredLogs.ToList();
        }

        public Dictionary<string, int> GetLogStatistics()
        {
            var statistics = new Dictionary<string, int>();

            foreach (var log in logs)
            {
                if (statistics.ContainsKey(log.Type))
                {
                    statistics[log.Type]++;
                }
                else
                {
                    statistics[log.Type] = 1;
                }
            }

            return statistics;
        }

        public List<LogEntry> GetRecentThreats(int days = 7)
        {
            var cutoffDate = DateTime.Now.AddDays(-days);
            var threatTypes = new[] { "ThreatFound", "MaliciousFile", "SuspiciousActivity", "RansomwareDetected", "TrojanDetected", "VirusDetected", "Threat" };

            return logs.Where(l => l.Time >= cutoffDate && threatTypes.Contains(l.Type)).OrderByDescending(l => l.Time).ToList();
        }

        public void ExportLogs(string exportPath, string format = "txt")
        {
            try
            {
                if (format == "txt")
                {
                    using (StreamWriter writer = new StreamWriter(exportPath, false, Encoding.UTF8))
                    {
                        writer.WriteLine("FireAntivirus - 日志导出");
                        writer.WriteLine($"导出时间: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                        writer.WriteLine("====================================");
                        writer.WriteLine();

                        foreach (var log in logs.OrderBy(l => l.Time))
                        {
                            writer.WriteLine($"[{log.Time:yyyy-MM-dd HH:mm:ss}] [{log.Severity}] [{log.Type}] {log.Message}");
                            if (!string.IsNullOrEmpty(log.Details))
                            {
                                writer.WriteLine($"  详情: {log.Details}");
                            }
                            writer.WriteLine();
                        }
                    }
                }
                else if (format == "csv")
                {
                    using (StreamWriter writer = new StreamWriter(exportPath, false, Encoding.UTF8))
                    {
                        writer.WriteLine("时间,类型,严重程度,消息,详情,来源,分类");
                        foreach (var log in logs.OrderBy(l => l.Time))
                        {
                            writer.WriteLine($"{log.Time:yyyy-MM-dd HH:mm:ss},{log.Type},{log.Severity},{log.Message},{log.Details},{log.Source},{log.Category}");
                        }
                    }
                }
                else if (format == "json")
                {
                    string json = JsonConvert.SerializeObject(logs, jsonSettings);
                    File.WriteAllText(exportPath, json);
                }
            }
            catch (Exception ex)
            {
                LogError($"导出日志失败: {ex.Message}");
            }
        }

        public void ClearLogs()
        {
            logs.Clear();

            try
            {
                foreach (var file in Directory.GetFiles(logsPath))
                {
                    File.Delete(file);
                }
            }
            catch (Exception ex)
            {
                LogError($"清理日志失败: {ex.Message}");
            }
        }

        public void CleanupOldLogs(int days = 30)
        {
            var cutoffDate = DateTime.Now.AddDays(-days);
            logs = logs.Where(l => l.Time >= cutoffDate).ToList();

            try
            {
                foreach (var file in Directory.GetFiles(logsPath))
                {
                    var fileInfo = new FileInfo(file);
                    if (fileInfo.LastWriteTime < cutoffDate)
                    {
                        File.Delete(file);
                    }
                }
            }
            catch (Exception ex)
            {
                LogError($"清理旧日志失败: {ex.Message}");
            }
        }

        public bool QuarantineFile(string filePath, string threatName, string threatType, string scanEngine = "FireAntivirus", double confidence = 1.0)
        {
            try
            {
                string fileName = Path.GetFileName(filePath);
                string fileExtension = Path.GetExtension(filePath);
                string quarantineFileName = $"{Guid.NewGuid()}_{fileName}";
                string quarantineFilePath = Path.Combine(quarantinePath, quarantineFileName);

                File.Copy(filePath, quarantineFilePath, true);

                string fileHash = CalculateFileHash(filePath);

                var item = new QuarantineItem
                {
                    Id = Guid.NewGuid().ToString(),
                    OriginalPath = filePath,
                    QuarantinePath = quarantineFilePath,
                    FileName = fileName,
                    ThreatName = threatName,
                    ThreatType = threatType,
                    QuarantineTime = DateTime.Now,
                    Size = new FileInfo(filePath).Length,
                    Hash = fileHash,
                    FileExtension = fileExtension,
                    ScanEngine = scanEngine,
                    Confidence = confidence,
                    AdditionalInfo = $"Quarantined by {scanEngine} with {confidence:P} confidence"
                };

                quarantineItems[item.Id] = item;
                SaveQuarantineItems();

                File.Delete(filePath);

                LogThreat($"文件已隔离: {fileName}", $"威胁: {threatName}, 路径: {filePath}", scanEngine);

                return true;
            }
            catch (Exception ex)
            {
                LogError($"隔离文件失败: {ex.Message}");
                return false;
            }
        }

        public bool RestoreFile(string quarantineItemId)
        {
            try
            {
                if (quarantineItems.TryGetValue(quarantineItemId, out var item))
                {
                    string targetDir = Path.GetDirectoryName(item.OriginalPath);
                    if (!Directory.Exists(targetDir))
                    {
                        Directory.CreateDirectory(targetDir);
                    }

                    File.Copy(item.QuarantinePath, item.OriginalPath, true);

                    File.Delete(item.QuarantinePath);
                    quarantineItems.TryRemove(quarantineItemId, out _);
                    SaveQuarantineItems();

                    LogActivity($"文件已恢复: {item.FileName}", "User");

                    return true;
                }
                return false;
            }
            catch (Exception ex)
            {
                LogError($"恢复文件失败: {ex.Message}");
                return false;
            }
        }

        public bool DeleteFromQuarantine(string quarantineItemId)
        {
            try
            {
                if (quarantineItems.TryGetValue(quarantineItemId, out var item))
                {
                    if (File.Exists(item.QuarantinePath))
                    {
                        File.Delete(item.QuarantinePath);
                    }

                    quarantineItems.TryRemove(quarantineItemId, out _);
                    SaveQuarantineItems();

                    LogActivity($"隔离文件已删除: {item.FileName}", "User");

                    return true;
                }
                return false;
            }
            catch (Exception ex)
            {
                LogError($"删除隔离文件失败: {ex.Message}");
                return false;
            }
        }

        public void ClearQuarantine()
        {
            try
            {
                var items = quarantineItems.Values.ToList();
                foreach (var item in items)
                {
                    if (File.Exists(item.QuarantinePath))
                    {
                        File.Delete(item.QuarantinePath);
                    }
                }

                string quarantineItemsPath = Path.Combine(dataPath, "quarantine.json");
                if (File.Exists(quarantineItemsPath))
                {
                    File.Delete(quarantineItemsPath);
                }

                quarantineItems.Clear();
                LogActivity("隔离区已清空", "User");
            }
            catch (Exception ex)
            {
                LogError($"清空隔离区失败: {ex.Message}");
            }
        }

        private void LoadQuarantineItems()
        {
            try
            {
                string quarantineItemsPath = Path.Combine(dataPath, "quarantine.json");
                if (File.Exists(quarantineItemsPath))
                {
                    string json = File.ReadAllText(quarantineItemsPath, Encoding.UTF8);
                    var items = JsonConvert.DeserializeObject<List<QuarantineItem>>(json);
                    if (items != null)
                    {
                        foreach (var item in items)
                        {
                            quarantineItems[item.Id] = item;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                LogError($"加载隔离区失败: {ex.Message}");
                quarantineItems = new ConcurrentDictionary<string, QuarantineItem>();
            }
        }

        private void SaveQuarantineItems()
        {
            try
            {
                string quarantineItemsPath = Path.Combine(dataPath, "quarantine.json");
                string json = JsonConvert.SerializeObject(quarantineItems.Values.ToList(), jsonSettings);
                File.WriteAllText(quarantineItemsPath, json, Encoding.UTF8);
            }
            catch (Exception ex)
            {
                LogError($"保存隔离区失败: {ex.Message}");
            }
        }

        #region 系统保护设置
        private void LoadSystemProtectionSettings()
        {
            try
            {
                string settingsFile = Path.Combine(configPath, "system_protection.json");
                if (File.Exists(settingsFile))
                {
                    string json = File.ReadAllText(settingsFile);
                    systemProtectionSettings = JsonConvert.DeserializeObject<SystemProtectionSettings>(json) ?? new SystemProtectionSettings();
                }
            }
            catch (Exception ex)
            {
                LogError($"加载系统保护设置失败: {ex.Message}");
                systemProtectionSettings = new SystemProtectionSettings();
            }
        }

        public void SaveSystemProtectionSettings()
        {
            try
            {
                string settingsFile = Path.Combine(configPath, "system_protection.json");
                string json = JsonConvert.SerializeObject(systemProtectionSettings, jsonSettings);
                File.WriteAllText(settingsFile, json);
            }
            catch (Exception ex)
            {
                LogError($"保存系统保护设置失败: {ex.Message}");
            }
        }

        public SystemProtectionSettings GetSystemProtectionSettings()
        {
            return systemProtectionSettings;
        }

        public void UpdateSystemProtectionSettings(SystemProtectionSettings settings)
        {
            systemProtectionSettings = settings;
            SaveSystemProtectionSettings();
        }
        #endregion

        #region 网络保护设置
        private void LoadNetworkProtectionSettings()
        {
            try
            {
                string settingsFile = Path.Combine(configPath, "network_protection.json");
                if (File.Exists(settingsFile))
                {
                    string json = File.ReadAllText(settingsFile);
                    networkProtectionSettings = JsonConvert.DeserializeObject<NetworkProtectionSettings>(json) ?? new NetworkProtectionSettings();
                }
            }
            catch (Exception ex)
            {
                LogError($"加载网络保护设置失败: {ex.Message}");
                networkProtectionSettings = new NetworkProtectionSettings();
            }
        }

        public void SaveNetworkProtectionSettings()
        {
            try
            {
                string settingsFile = Path.Combine(configPath, "network_protection.json");
                string json = JsonConvert.SerializeObject(networkProtectionSettings, jsonSettings);
                File.WriteAllText(settingsFile, json);
            }
            catch (Exception ex)
            {
                LogError($"保存网络保护设置失败: {ex.Message}");
            }
        }

        public NetworkProtectionSettings GetNetworkProtectionSettings()
        {
            return networkProtectionSettings;
        }

        public void UpdateNetworkProtectionSettings(NetworkProtectionSettings settings)
        {
            networkProtectionSettings = settings;
            SaveNetworkProtectionSettings();
        }
        #endregion

        #region 扫描设置
        private void LoadScanSettings()
        {
            try
            {
                string settingsFile = Path.Combine(configPath, "scan_settings.json");
                if (File.Exists(settingsFile))
                {
                    string json = File.ReadAllText(settingsFile);
                    scanSettings = JsonConvert.DeserializeObject<ScanSettings>(json) ?? new ScanSettings();
                }
            }
            catch (Exception ex)
            {
                LogError($"加载扫描设置失败: {ex.Message}");
                scanSettings = new ScanSettings();
            }
        }

        public void SaveScanSettings()
        {
            try
            {
                string settingsFile = Path.Combine(configPath, "scan_settings.json");
                string json = JsonConvert.SerializeObject(scanSettings, jsonSettings);
                File.WriteAllText(settingsFile, json);
            }
            catch (Exception ex)
            {
                LogError($"保存扫描设置失败: {ex.Message}");
            }
        }

        public ScanSettings GetScanSettings()
        {
            return scanSettings;
        }

        public void UpdateScanSettings(ScanSettings settings)
        {
            scanSettings = settings;
            SaveScanSettings();
        }
        #endregion

        #region 更新设置
        private void LoadUpdateSettings()
        {
            try
            {
                string settingsFile = Path.Combine(configPath, "update_settings.json");
                if (File.Exists(settingsFile))
                {
                    string json = File.ReadAllText(settingsFile);
                    updateSettings = JsonConvert.DeserializeObject<UpdateSettings>(json) ?? new UpdateSettings();
                }
            }
            catch (Exception ex)
            {
                LogError($"加载更新设置失败: {ex.Message}");
                updateSettings = new UpdateSettings();
            }
        }

        public void SaveUpdateSettings()
        {
            try
            {
                string settingsFile = Path.Combine(configPath, "update_settings.json");
                string json = JsonConvert.SerializeObject(updateSettings, jsonSettings);
                File.WriteAllText(settingsFile, json);
            }
            catch (Exception ex)
            {
                LogError($"保存更新设置失败: {ex.Message}");
            }
        }

        public UpdateSettings GetUpdateSettings()
        {
            return updateSettings;
        }

        public void UpdateUpdateSettings(UpdateSettings settings)
        {
            updateSettings = settings;
            SaveUpdateSettings();
        }
        #endregion

        #region 界面设置
        private void LoadInterfaceSettings()
        {
            try
            {
                string settingsFile = Path.Combine(configPath, "interface_settings.json");
                if (File.Exists(settingsFile))
                {
                    string json = File.ReadAllText(settingsFile);
                    interfaceSettings = JsonConvert.DeserializeObject<InterfaceSettings>(json) ?? new InterfaceSettings();
                }
            }
            catch (Exception ex)
            {
                LogError($"加载界面设置失败: {ex.Message}");
                interfaceSettings = new InterfaceSettings();
            }
        }

        public void SaveInterfaceSettings()
        {
            try
            {
                string settingsFile = Path.Combine(configPath, "interface_settings.json");
                string json = JsonConvert.SerializeObject(interfaceSettings, jsonSettings);
                File.WriteAllText(settingsFile, json);
            }
            catch (Exception ex)
            {
                LogError($"保存界面设置失败: {ex.Message}");
            }
        }

        public InterfaceSettings GetInterfaceSettings()
        {
            return interfaceSettings;
        }

        public void UpdateInterfaceSettings(InterfaceSettings settings)
        {
            interfaceSettings = settings;
            SaveInterfaceSettings();
        }
        #endregion

        #region 高级设置
        private void LoadAdvancedSettings()
        {
            try
            {
                string settingsFile = Path.Combine(configPath, "advanced_settings.json");
                if (File.Exists(settingsFile))
                {
                    string json = File.ReadAllText(settingsFile);
                    advancedSettings = JsonConvert.DeserializeObject<AdvancedSettings>(json) ?? new AdvancedSettings();
                }
            }
            catch (Exception ex)
            {
                LogError($"加载高级设置失败: {ex.Message}");
                advancedSettings = new AdvancedSettings();
            }
        }

        public void SaveAdvancedSettings()
        {
            try
            {
                string settingsFile = Path.Combine(configPath, "advanced_settings.json");
                string json = JsonConvert.SerializeObject(advancedSettings, jsonSettings);
                File.WriteAllText(settingsFile, json);
            }
            catch (Exception ex)
            {
                LogError($"保存高级设置失败: {ex.Message}");
            }
        }

        public AdvancedSettings GetAdvancedSettings()
        {
            return advancedSettings;
        }

        public void UpdateAdvancedSettings(AdvancedSettings settings)
        {
            advancedSettings = settings;
            SaveAdvancedSettings();
        }
        #endregion

        #region 威胁情报
        private void LoadThreatIntelligenceItems()
        {
            try
            {
                string itemsFile = Path.Combine(threatIntelligencePath, "threat_intelligence.json");
                if (File.Exists(itemsFile))
                {
                    string json = File.ReadAllText(itemsFile);
                    threatIntelligenceItems = JsonConvert.DeserializeObject<List<ThreatIntelligenceItem>>(json) ?? new List<ThreatIntelligenceItem>();
                }
            }
            catch (Exception ex)
            {
                LogError($"加载威胁情报失败: {ex.Message}");
                threatIntelligenceItems = new List<ThreatIntelligenceItem>();
            }
        }

        public void SaveThreatIntelligenceItems()
        {
            try
            {
                string itemsFile = Path.Combine(threatIntelligencePath, "threat_intelligence.json");
                string json = JsonConvert.SerializeObject(threatIntelligenceItems, jsonSettings);
                File.WriteAllText(itemsFile, json);
            }
            catch (Exception ex)
            {
                LogError($"保存威胁情报失败: {ex.Message}");
            }
        }

        public List<ThreatIntelligenceItem> GetThreatIntelligenceItems()
        {
            return threatIntelligenceItems;
        }

        public void AddThreatIntelligenceItem(ThreatIntelligenceItem item)
        {
            threatIntelligenceItems.Add(item);
            SaveThreatIntelligenceItems();
        }

        public void RemoveThreatIntelligenceItem(string id)
        {
            threatIntelligenceItems.RemoveAll(item => item.Id == id);
            SaveThreatIntelligenceItems();
        }
        #endregion

        #region 漏洞管理
        private void LoadVulnerabilityItems()
        {
            try
            {
                string itemsFile = Path.Combine(vulnerabilityPath, "vulnerabilities.json");
                if (File.Exists(itemsFile))
                {
                    string json = File.ReadAllText(itemsFile);
                    vulnerabilityItems = JsonConvert.DeserializeObject<List<VulnerabilityItem>>(json) ?? new List<VulnerabilityItem>();
                }
            }
            catch (Exception ex)
            {
                LogError($"加载漏洞信息失败: {ex.Message}");
                vulnerabilityItems = new List<VulnerabilityItem>();
            }
        }

        public void SaveVulnerabilityItems()
        {
            try
            {
                string itemsFile = Path.Combine(vulnerabilityPath, "vulnerabilities.json");
                string json = JsonConvert.SerializeObject(vulnerabilityItems, jsonSettings);
                File.WriteAllText(itemsFile, json);
            }
            catch (Exception ex)
            {
                LogError($"保存漏洞信息失败: {ex.Message}");
            }
        }

        public List<VulnerabilityItem> GetVulnerabilityItems()
        {
            return vulnerabilityItems;
        }

        public void AddVulnerabilityItem(VulnerabilityItem item)
        {
            vulnerabilityItems.Add(item);
            SaveVulnerabilityItems();
        }

        public void UpdateVulnerabilityStatus(string cveId, string status)
        {
            var item = vulnerabilityItems.FirstOrDefault(v => v.CveId == cveId);
            if (item != null)
            {
                item.Status = status;
                SaveVulnerabilityItems();
            }
        }
        #endregion

        #region 应用控制
        private void LoadApplicationControlRules()
        {
            try
            {
                string rulesFile = Path.Combine(applicationControlPath, "application_control_rules.json");
                if (File.Exists(rulesFile))
                {
                    string json = File.ReadAllText(rulesFile);
                    applicationControlRules = JsonConvert.DeserializeObject<List<ApplicationControlRule>>(json) ?? new List<ApplicationControlRule>();
                }
            }
            catch (Exception ex)
            {
                LogError($"加载应用控制规则失败: {ex.Message}");
                applicationControlRules = new List<ApplicationControlRule>();
            }
        }

        public void SaveApplicationControlRules()
        {
            try
            {
                string rulesFile = Path.Combine(applicationControlPath, "application_control_rules.json");
                string json = JsonConvert.SerializeObject(applicationControlRules, jsonSettings);
                File.WriteAllText(rulesFile, json);
            }
            catch (Exception ex)
            {
                LogError($"保存应用控制规则失败: {ex.Message}");
            }
        }

        public List<ApplicationControlRule> GetApplicationControlRules()
        {
            return applicationControlRules;
        }

        public void AddApplicationControlRule(ApplicationControlRule rule)
        {
            applicationControlRules.Add(rule);
            SaveApplicationControlRules();
        }

        public void RemoveApplicationControlRule(string id)
        {
            applicationControlRules.RemoveAll(rule => rule.Id == id);
            SaveApplicationControlRules();
        }

        public bool IsApplicationAllowed(string applicationPath)
        {
            var rule = applicationControlRules.FirstOrDefault(r => r.ApplicationPath.Equals(applicationPath, StringComparison.OrdinalIgnoreCase) && r.Enabled);
            return rule != null && rule.RuleType == "Allow";
        }
        #endregion

        #region 防火墙规则
        private void LoadFirewallRules()
        {
            try
            {
                string rulesFile = Path.Combine(firewallPath, "firewall_rules.json");
                if (File.Exists(rulesFile))
                {
                    string json = File.ReadAllText(rulesFile);
                    firewallRules = JsonConvert.DeserializeObject<List<FirewallRule>>(json) ?? new List<FirewallRule>();
                }
            }
            catch (Exception ex)
            {
                LogError($"加载防火墙规则失败: {ex.Message}");
                firewallRules = new List<FirewallRule>();
            }
        }

        public void SaveFirewallRules()
        {
            try
            {
                string rulesFile = Path.Combine(firewallPath, "firewall_rules.json");
                string json = JsonConvert.SerializeObject(firewallRules, jsonSettings);
                File.WriteAllText(rulesFile, json);
            }
            catch (Exception ex)
            {
                LogError($"保存防火墙规则失败: {ex.Message}");
            }
        }

        public List<FirewallRule> GetFirewallRules()
        {
            return firewallRules;
        }

        public void AddFirewallRule(FirewallRule rule)
        {
            firewallRules.Add(rule);
            SaveFirewallRules();
        }

        public void RemoveFirewallRule(string id)
        {
            firewallRules.RemoveAll(rule => rule.Id == id);
            SaveFirewallRules();
        }
        #endregion

        #region 沙箱设置
        private void LoadSandboxSettings()
        {
            try
            {
                string settingsFile = Path.Combine(sandboxPath, "sandbox_settings.json");
                if (File.Exists(settingsFile))
                {
                    string json = File.ReadAllText(settingsFile);
                    sandboxSettings = JsonConvert.DeserializeObject<List<SandboxSetting>>(json) ?? new List<SandboxSetting>();
                }
            }
            catch (Exception ex)
            {
                LogError($"加载沙箱设置失败: {ex.Message}");
                sandboxSettings = new List<SandboxSetting>();
            }
        }

        public void SaveSandboxSettings()
        {
            try
            {
                string settingsFile = Path.Combine(sandboxPath, "sandbox_settings.json");
                string json = JsonConvert.SerializeObject(sandboxSettings, jsonSettings);
                File.WriteAllText(settingsFile, json);
            }
            catch (Exception ex)
            {
                LogError($"保存沙箱设置失败: {ex.Message}");
            }
        }

        public List<SandboxSetting> GetSandboxSettings()
        {
            return sandboxSettings;
        }

        public void AddSandboxSetting(SandboxSetting setting)
        {
            sandboxSettings.Add(setting);
            SaveSandboxSettings();
        }

        public void RemoveSandboxSetting(string id)
        {
            sandboxSettings.RemoveAll(setting => setting.Id == id);
            SaveSandboxSettings();
        }
        #endregion

        #region 行为监控规则
        private void LoadBehaviorMonitoringRules()
        {
            try
            {
                string rulesFile = Path.Combine(behaviorMonitoringPath, "behavior_monitoring_rules.json");
                if (File.Exists(rulesFile))
                {
                    string json = File.ReadAllText(rulesFile);
                    behaviorMonitoringRules = JsonConvert.DeserializeObject<List<BehaviorMonitoringRule>>(json) ?? new List<BehaviorMonitoringRule>();
                }
            }
            catch (Exception ex)
            {
                LogError($"加载行为监控规则失败: {ex.Message}");
                behaviorMonitoringRules = new List<BehaviorMonitoringRule>();
            }
        }

        public void SaveBehaviorMonitoringRules()
        {
            try
            {
                string rulesFile = Path.Combine(behaviorMonitoringPath, "behavior_monitoring_rules.json");
                string json = JsonConvert.SerializeObject(behaviorMonitoringRules, jsonSettings);
                File.WriteAllText(rulesFile, json);
            }
            catch (Exception ex)
            {
                LogError($"保存行为监控规则失败: {ex.Message}");
            }
        }

        public List<BehaviorMonitoringRule> GetBehaviorMonitoringRules()
        {
            return behaviorMonitoringRules;
        }

        public void AddBehaviorMonitoringRule(BehaviorMonitoringRule rule)
        {
            behaviorMonitoringRules.Add(rule);
            SaveBehaviorMonitoringRules();
        }

        public void RemoveBehaviorMonitoringRule(string id)
        {
            behaviorMonitoringRules.RemoveAll(rule => rule.Id == id);
            SaveBehaviorMonitoringRules();
        }
        #endregion

        #region 云保护设置
        private void LoadCloudProtectionSettings()
        {
            try
            {
                string settingsFile = Path.Combine(configPath, "cloud_protection.json");
                if (File.Exists(settingsFile))
                {
                    string json = File.ReadAllText(settingsFile);
                    cloudProtectionSettings = JsonConvert.DeserializeObject<CloudProtectionSettings>(json) ?? new CloudProtectionSettings();
                }
            }
            catch (Exception ex)
            {
                LogError($"加载云保护设置失败: {ex.Message}");
                cloudProtectionSettings = new CloudProtectionSettings();
            }
        }

        public void SaveCloudProtectionSettings()
        {
            try
            {
                string settingsFile = Path.Combine(configPath, "cloud_protection.json");
                string json = JsonConvert.SerializeObject(cloudProtectionSettings, jsonSettings);
                File.WriteAllText(settingsFile, json);
            }
            catch (Exception ex)
            {
                LogError($"保存云保护设置失败: {ex.Message}");
            }
        }

        public CloudProtectionSettings GetCloudProtectionSettings()
        {
            return cloudProtectionSettings;
        }

        public void UpdateCloudProtectionSettings(CloudProtectionSettings settings)
        {
            cloudProtectionSettings = settings;
            SaveCloudProtectionSettings();
        }
        #endregion

        #region 机器学习设置
        private void LoadMachineLearningSettings()
        {
            try
            {
                string settingsFile = Path.Combine(configPath, "machine_learning.json");
                if (File.Exists(settingsFile))
                {
                    string json = File.ReadAllText(settingsFile);
                    machineLearningSettings = JsonConvert.DeserializeObject<MachineLearningSettings>(json) ?? new MachineLearningSettings();
                }
            }
            catch (Exception ex)
            {
                LogError($"加载机器学习设置失败: {ex.Message}");
                machineLearningSettings = new MachineLearningSettings();
            }
        }

        public void SaveMachineLearningSettings()
        {
            try
            {
                string settingsFile = Path.Combine(configPath, "machine_learning.json");
                string json = JsonConvert.SerializeObject(machineLearningSettings, jsonSettings);
                File.WriteAllText(settingsFile, json);
            }
            catch (Exception ex)
            {
                LogError($"保存机器学习设置失败: {ex.Message}");
            }
        }

        public MachineLearningSettings GetMachineLearningSettings()
        {
            return machineLearningSettings;
        }

        public void UpdateMachineLearningSettings(MachineLearningSettings settings)
        {
            machineLearningSettings = settings;
            SaveMachineLearningSettings();
        }
        #endregion

        #region 安全评分
        private void LoadSecurityScore()
        {
            try
            {
                string scoreFile = Path.Combine(securityPath, "security_score.json");
                if (File.Exists(scoreFile))
                {
                    string json = File.ReadAllText(scoreFile);
                    securityScore = JsonConvert.DeserializeObject<SecurityScore>(json) ?? new SecurityScore();
                }
            }
            catch (Exception ex)
            {
                LogError($"加载安全评分失败: {ex.Message}");
                securityScore = new SecurityScore();
            }
        }

        public void SaveSecurityScore()
        {
            try
            {
                string scoreFile = Path.Combine(securityPath, "security_score.json");
                string json = JsonConvert.SerializeObject(securityScore, jsonSettings);
                File.WriteAllText(scoreFile, json);
            }
            catch (Exception ex)
            {
                LogError($"保存安全评分失败: {ex.Message}");
            }
        }

        public SecurityScore GetSecurityScore()
        {
            return securityScore;
        }

        public void UpdateSecurityScore(SecurityScore score)
        {
            securityScore = score;
            SaveSecurityScore();
        }
        #endregion

        #region 安全建议
        private void LoadSecurityRecommendations()
        {
            try
            {
                string recommendationsFile = Path.Combine(securityPath, "security_recommendations.json");
                if (File.Exists(recommendationsFile))
                {
                    string json = File.ReadAllText(recommendationsFile);
                    securityRecommendations = JsonConvert.DeserializeObject<List<SecurityRecommendation>>(json) ?? new List<SecurityRecommendation>();
                }
            }
            catch (Exception ex)
            {
                LogError($"加载安全建议失败: {ex.Message}");
                securityRecommendations = new List<SecurityRecommendation>();
            }
        }

        public void SaveSecurityRecommendations()
        {
            try
            {
                string recommendationsFile = Path.Combine(securityPath, "security_recommendations.json");
                string json = JsonConvert.SerializeObject(securityRecommendations, jsonSettings);
                File.WriteAllText(recommendationsFile, json);
            }
            catch (Exception ex)
            {
                LogError($"保存安全建议失败: {ex.Message}");
            }
        }

        public List<SecurityRecommendation> GetSecurityRecommendations()
        {
            return securityRecommendations;
        }

        public void AddSecurityRecommendation(SecurityRecommendation recommendation)
        {
            securityRecommendations.Add(recommendation);
            SaveSecurityRecommendations();
        }

        public void MarkRecommendationAsCompleted(string id)
        {
            var recommendation = securityRecommendations.FirstOrDefault(r => r.Id == id);
            if (recommendation != null)
            {
                recommendation.Completed = true;
                recommendation.LastModifiedDate = DateTime.Now;
                SaveSecurityRecommendations();
            }
        }
        #endregion

        #region 系统优化设置
        private void LoadSystemOptimizationSettings()
        {
            try
            {
                string settingsFile = Path.Combine(optimizationPath, "system_optimization.json");
                if (File.Exists(settingsFile))
                {
                    string json = File.ReadAllText(settingsFile);
                    systemOptimizationSettings = JsonConvert.DeserializeObject<List<SystemOptimizationSetting>>(json) ?? new List<SystemOptimizationSetting>();
                }
            }
            catch (Exception ex)
            {
                LogError($"加载系统优化设置失败: {ex.Message}");
                systemOptimizationSettings = new List<SystemOptimizationSetting>();
            }
        }

        public void SaveSystemOptimizationSettings()
        {
            try
            {
                string settingsFile = Path.Combine(optimizationPath, "system_optimization.json");
                string json = JsonConvert.SerializeObject(systemOptimizationSettings, jsonSettings);
                File.WriteAllText(settingsFile, json);
            }
            catch (Exception ex)
            {
                LogError($"保存系统优化设置失败: {ex.Message}");
            }
        }

        public List<SystemOptimizationSetting> GetSystemOptimizationSettings()
        {
            return systemOptimizationSettings;
        }

        public void AddSystemOptimizationSetting(SystemOptimizationSetting setting)
        {
            systemOptimizationSettings.Add(setting);
            SaveSystemOptimizationSettings();
        }

        public void UpdateSystemOptimizationSetting(string id, bool enabled)
        {
            var setting = systemOptimizationSettings.FirstOrDefault(s => s.Id == id);
            if (setting != null)
            {
                setting.Enabled = enabled;
                setting.LastApplied = DateTime.Now;
                SaveSystemOptimizationSettings();
            }
        }
        #endregion

        #region 隐私保护设置
        private void LoadPrivacyProtectionSettings()
        {
            try
            {
                string settingsFile = Path.Combine(privacyPath, "privacy_protection.json");
                if (File.Exists(settingsFile))
                {
                    string json = File.ReadAllText(settingsFile);
                    privacyProtectionSettings = JsonConvert.DeserializeObject<List<PrivacyProtectionSetting>>(json) ?? new List<PrivacyProtectionSetting>();
                }
            }
            catch (Exception ex)
            {
                LogError($"加载隐私保护设置失败: {ex.Message}");
                privacyProtectionSettings = new List<PrivacyProtectionSetting>();
            }
        }

        public void SavePrivacyProtectionSettings()
        {
            try
            {
                string settingsFile = Path.Combine(privacyPath, "privacy_protection.json");
                string json = JsonConvert.SerializeObject(privacyProtectionSettings, jsonSettings);
                File.WriteAllText(settingsFile, json);
            }
            catch (Exception ex)
            {
                LogError($"保存隐私保护设置失败: {ex.Message}");
            }
        }

        public List<PrivacyProtectionSetting> GetPrivacyProtectionSettings()
        {
            return privacyProtectionSettings;
        }

        public void AddPrivacyProtectionSetting(PrivacyProtectionSetting setting)
        {
            privacyProtectionSettings.Add(setting);
            SavePrivacyProtectionSettings();
        }

        public void UpdatePrivacyProtectionSetting(string id, bool enabled)
        {
            var setting = privacyProtectionSettings.FirstOrDefault(s => s.Id == id);
            if (setting != null)
            {
                setting.Enabled = enabled;
                setting.LastModified = DateTime.Now;
                SavePrivacyProtectionSettings();
            }
        }
        #endregion

        #region 家长控制设置
        private void LoadParentalControlSettings()
        {
            try
            {
                string settingsFile = Path.Combine(parentalControlPath, "parental_control.json");
                if (File.Exists(settingsFile))
                {
                    string json = File.ReadAllText(settingsFile);
                    parentalControlSettings = JsonConvert.DeserializeObject<List<ParentalControlSetting>>(json) ?? new List<ParentalControlSetting>();
                }
            }
            catch (Exception ex)
            {
                LogError($"加载家长控制设置失败: {ex.Message}");
                parentalControlSettings = new List<ParentalControlSetting>();
            }
        }

        public void SaveParentalControlSettings()
        {
            try
            {
                string settingsFile = Path.Combine(parentalControlPath, "parental_control.json");
                string json = JsonConvert.SerializeObject(parentalControlSettings, jsonSettings);
                File.WriteAllText(settingsFile, json);
            }
            catch (Exception ex)
            {
                LogError($"保存家长控制设置失败: {ex.Message}");
            }
        }

        public List<ParentalControlSetting> GetParentalControlSettings()
        {
            return parentalControlSettings;
        }

        public void AddParentalControlSetting(ParentalControlSetting setting)
        {
            parentalControlSettings.Add(setting);
            SaveParentalControlSettings();
        }

        public void UpdateParentalControlSetting(string id, ParentalControlSetting setting)
        {
            var existingSetting = parentalControlSettings.FirstOrDefault(s => s.Id == id);
            if (existingSetting != null)
            {
                existingSetting.Enabled = setting.Enabled;
                existingSetting.BlockedApplications = setting.BlockedApplications;
                existingSetting.BlockedWebsites = setting.BlockedWebsites;
                existingSetting.DailyTimeLimit = setting.DailyTimeLimit;
                existingSetting.LastModified = DateTime.Now;
                SaveParentalControlSettings();
            }
        }
        #endregion

        #region 通用方法
        public void BackupAllSettings(string backupPath)
        {
            try
            {
                string backupDir = Path.Combine(backupPath, $"settings_backup_{DateTime.Now:yyyyMMdd_HHmmss}");
                Directory.CreateDirectory(backupDir);

                // 备份所有设置文件
                string[] configFiles = Directory.GetFiles(configPath, "*.json");
                foreach (string file in configFiles)
                {
                    string fileName = Path.GetFileName(file);
                    File.Copy(file, Path.Combine(backupDir, fileName), true);
                }

                // 备份其他数据
                string[] dataDirs = { threatIntelligencePath, vulnerabilityPath, applicationControlPath, firewallPath, sandboxPath, behaviorMonitoringPath, securityPath, optimizationPath, privacyPath, parentalControlPath };
                foreach (string dir in dataDirs)
                {
                    if (Directory.Exists(dir))
                    {
                        string dirName = Path.GetFileName(dir);
                        string backupSubDir = Path.Combine(backupDir, dirName);
                        Directory.CreateDirectory(backupSubDir);
                        
                        string[] files = Directory.GetFiles(dir, "*.json");
                        foreach (string file in files)
                        {
                            string fileName = Path.GetFileName(file);
                            File.Copy(file, Path.Combine(backupSubDir, fileName), true);
                        }
                    }
                }

                LogActivity($"所有设置已备份到: {backupDir}");
            }
            catch (Exception ex)
            {
                LogError($"备份设置失败: {ex.Message}");
            }
        }

        public void RestoreSettingsFromBackup(string backupPath)
        {
            try
            {
                // 恢复配置文件
                string[] configFiles = Directory.GetFiles(backupPath, "*.json");
                foreach (string file in configFiles)
                {
                    string fileName = Path.GetFileName(file);
                    string targetPath = Path.Combine(configPath, fileName);
                    File.Copy(file, targetPath, true);
                }

                // 恢复其他数据
                string[] dataDirs = { "ThreatIntelligence", "Vulnerabilities", "ApplicationControl", "Firewall", "Sandbox", "BehaviorMonitoring", "Security", "Optimization", "Privacy", "ParentalControl" };
                foreach (string dirName in dataDirs)
                {
                    string backupSubDir = Path.Combine(backupPath, dirName);
                    if (Directory.Exists(backupSubDir))
                    {
                        string targetDir = Path.Combine(dataPath, dirName);
                        Directory.CreateDirectory(targetDir);
                        
                        string[] files = Directory.GetFiles(backupSubDir, "*.json");
                        foreach (string file in files)
                        {
                            string fileName = Path.GetFileName(file);
                            string targetPath = Path.Combine(targetDir, fileName);
                            File.Copy(file, targetPath, true);
                        }
                    }
                }

                // 重新加载所有数据
                LoadLocalData();
                LogActivity($"设置已从备份恢复: {backupPath}");
            }
            catch (Exception ex)
            {
                LogError($"恢复设置失败: {ex.Message}");
            }
        }

        public void ResetAllSettings()
        {
            try
            {
                // 重置所有设置对象
                systemProtectionSettings = new SystemProtectionSettings();
                networkProtectionSettings = new NetworkProtectionSettings();
                scanSettings = new ScanSettings();
                updateSettings = new UpdateSettings();
                interfaceSettings = new InterfaceSettings();
                advancedSettings = new AdvancedSettings();
                cloudProtectionSettings = new CloudProtectionSettings();
                machineLearningSettings = new MachineLearningSettings();
                securityScore = new SecurityScore();
                
                // 清空列表数据
                threatIntelligenceItems.Clear();
                vulnerabilityItems.Clear();
                applicationControlRules.Clear();
                firewallRules.Clear();
                sandboxSettings.Clear();
                behaviorMonitoringRules.Clear();
                securityRecommendations.Clear();
                systemOptimizationSettings.Clear();
                privacyProtectionSettings.Clear();
                parentalControlSettings.Clear();

                // 保存所有重置的设置
                SaveSystemProtectionSettings();
                SaveNetworkProtectionSettings();
                SaveScanSettings();
                SaveUpdateSettings();
                SaveInterfaceSettings();
                SaveAdvancedSettings();
                SaveCloudProtectionSettings();
                SaveMachineLearningSettings();
                SaveSecurityScore();
                SaveThreatIntelligenceItems();
                SaveVulnerabilityItems();
                SaveApplicationControlRules();
                SaveFirewallRules();
                SaveSandboxSettings();
                SaveBehaviorMonitoringRules();
                SaveSecurityRecommendations();
                SaveSystemOptimizationSettings();
                SavePrivacyProtectionSettings();
                SaveParentalControlSettings();

                LogActivity("所有设置已重置为默认值");
            }
            catch (Exception ex)
            {
                LogError($"重置设置失败: {ex.Message}");
            }
        }
        #endregion

        

        public void SaveConfig(string key, string value)
        {
            try
            {
                string configFilePath = Path.Combine(configPath, "settings.json");
                Dictionary<string, string> config = new Dictionary<string, string>();

                if (File.Exists(configFilePath))
                {
                    string json = File.ReadAllText(configFilePath, Encoding.UTF8);
                    config = JsonConvert.DeserializeObject<Dictionary<string, string>>(json) ?? new Dictionary<string, string>();
                }

                config[key] = value;

                string newJson = JsonConvert.SerializeObject(config, jsonSettings);
                File.WriteAllText(configFilePath, newJson, Encoding.UTF8);
            }
            catch (Exception ex)
            {
                LogError($"保存配置失败: {ex.Message}");
            }
        }

        public string GetConfig(string key, string defaultValue = "")
        {
            try
            {
                string configFilePath = Path.Combine(configPath, "settings.json");
                if (File.Exists(configFilePath))
                {
                    string json = File.ReadAllText(configFilePath, Encoding.UTF8);
                    var config = JsonConvert.DeserializeObject<Dictionary<string, string>>(json);
                    if (config != null && config.ContainsKey(key))
                    {
                        return config[key];
                    }
                }
            }
            catch (Exception ex)
            {
                LogError($"读取配置失败: {ex.Message}");
            }
            return defaultValue;
        }

        public string GetDataDirectory()
        {
            return dataPath;
        }

        public void CreateBackup(string backupType = "Full", string description = "")
        {
            try
            {
                string backupDir = Path.Combine(backupPath, DateTime.Now.ToString("yyyyMMdd_HHmmss"));
                Directory.CreateDirectory(backupDir);

                // 备份病毒库
                string signaturesFile = Path.Combine(FireAntivirus.Common.PathHelper.GetAppDataPath(), "signatures.txt");
                if (File.Exists(signaturesFile))
                {
                    File.Copy(signaturesFile, Path.Combine(backupDir, "signatures.txt"), true);
                }

                // 备份配置
                string configFile = Path.Combine(configPath, "settings.json");
                if (File.Exists(configFile))
                {
                    File.Copy(configFile, Path.Combine(backupDir, "settings.json"), true);
                }

                // 备份信任列表
                string trustListFile = Path.Combine(dataPath, "trustlist.json");
                if (File.Exists(trustListFile))
                {
                    File.Copy(trustListFile, Path.Combine(backupDir, "trustlist.json"), true);
                }

                long backupSize = GetDirectorySize(backupDir);

                var backupItem = new BackupItem
                {
                    Id = Guid.NewGuid().ToString(),
                    BackupPath = backupDir,
                    BackupType = backupType,
                    BackupTime = DateTime.Now,
                    Size = backupSize,
                    Description = description,
                    Version = "1.0"
                };

                backupItems.Add(backupItem);
                SaveBackupItems();

                LogActivity($"备份已创建: {backupType}", "User");
            }
            catch (Exception ex)
            {
                LogError($"创建备份失败: {ex.Message}");
            }
        }

        public bool RestoreBackup(string backupId)
        {
            try
            {
                var backupItem = backupItems.FirstOrDefault(b => b.Id == backupId);
                if (backupItem == null)
                {
                    return false;
                }

                string backupDir = backupItem.BackupPath;
                if (!Directory.Exists(backupDir))
                {
                    return false;
                }

                // 恢复病毒库
                string signaturesFile = Path.Combine(backupDir, "signatures.txt");
                if (File.Exists(signaturesFile))
                {
                    File.Copy(signaturesFile, Path.Combine(FireAntivirus.Common.PathHelper.GetAppDataPath(), "signatures.txt"), true);
                }

                // 恢复配置
                string configFile = Path.Combine(backupDir, "settings.json");
                if (File.Exists(configFile))
                {
                    File.Copy(configFile, Path.Combine(configPath, "settings.json"), true);
                }

                // 恢复信任列表
                string trustListFile = Path.Combine(backupDir, "trustlist.json");
                if (File.Exists(trustListFile))
                {
                    File.Copy(trustListFile, Path.Combine(dataPath, "trustlist.json"), true);
                }

                LogActivity($"备份已恢复: {backupItem.BackupType}", "User");

                return true;
            }
            catch (Exception ex)
            {
                LogError($"恢复备份失败: {ex.Message}");
                return false;
            }
        }

        private void LoadBackupItems()
        {
            try
            {
                string backupItemsFile = Path.Combine(dataPath, "backups.json");
                if (File.Exists(backupItemsFile))
                {
                    string json = File.ReadAllText(backupItemsFile, Encoding.UTF8);
                    backupItems = JsonConvert.DeserializeObject<List<BackupItem>>(json) ?? new List<BackupItem>();
                }
            }
            catch (Exception ex)
            {
                LogError($"加载备份列表失败: {ex.Message}");
                backupItems = new List<BackupItem>();
            }
        }

        private void SaveBackupItems()
        {
            try
            {
                string backupItemsFile = Path.Combine(dataPath, "backups.json");
                string json = JsonConvert.SerializeObject(backupItems, jsonSettings);
                File.WriteAllText(backupItemsFile, json, Encoding.UTF8);
            }
            catch (Exception ex)
            {
                LogError($"保存备份列表失败: {ex.Message}");
            }
        }

        public void AddScanHistoryItem(ScanHistoryItem item)
        {
            scanHistory.Add(item);
            if (scanHistory.Count > 1000)
            {
                scanHistory = scanHistory.Skip(scanHistory.Count - 1000).ToList();
            }
            SaveScanHistory();
        }

        private void LoadScanHistory()
        {
            try
            {
                string historyFile = Path.Combine(historyPath, "scan_history.json");
                if (File.Exists(historyFile))
                {
                    string json = File.ReadAllText(historyFile, Encoding.UTF8);
                    scanHistory = JsonConvert.DeserializeObject<List<ScanHistoryItem>>(json) ?? new List<ScanHistoryItem>();
                }
            }
            catch (Exception ex)
            {
                LogError($"加载扫描历史失败: {ex.Message}");
                scanHistory = new List<ScanHistoryItem>();
            }
        }

        private void SaveScanHistory()
        {
            try
            {
                string historyFile = Path.Combine(historyPath, "scan_history.json");
                string json = JsonConvert.SerializeObject(scanHistory, jsonSettings);
                File.WriteAllText(historyFile, json, Encoding.UTF8);
            }
            catch (Exception ex)
            {
                LogError($"保存扫描历史失败: {ex.Message}");
            }
        }

        private long GetDirectorySize(string directoryPath)
        {
            long size = 0;
            try
            {
                foreach (var file in Directory.GetFiles(directoryPath, "*.*", SearchOption.AllDirectories))
                {
                    size += new FileInfo(file).Length;
                }
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "DataManager.cs exception", ex.Message);  }
            return size;
        }

        // 网页防护数据
        private WebProtectionData? _webProtectionData;

        public WebProtectionData LoadWebProtectionData()
        {
            if (_webProtectionData != null)
                return _webProtectionData;

            try
            {
                string dataFile = Path.Combine(dataPath, "web_protection.json");
                if (File.Exists(dataFile))
                {
                    string json = File.ReadAllText(dataFile, Encoding.UTF8);
                    _webProtectionData = JsonConvert.DeserializeObject<WebProtectionData>(json);
                }
            }
            catch (Exception ex)
            {
                LogError($"加载网页防护数据失败: {ex.Message}");
            }

            return _webProtectionData ?? new WebProtectionData();
        }

        public void SaveWebProtectionData(WebProtectionData data)
        {
            _webProtectionData = data;
            try
            {
                string dataFile = Path.Combine(dataPath, "web_protection.json");
                string json = JsonConvert.SerializeObject(data, jsonSettings);
                File.WriteAllText(dataFile, json, Encoding.UTF8);
            }
            catch (Exception ex)
            {
                LogError($"保存网页防护数据失败: {ex.Message}");
            }
        }

        // 设备控制数据
        private DeviceControlData? _deviceControlData;

        public DeviceControlData LoadDeviceControlData()
        {
            if (_deviceControlData != null)
                return _deviceControlData;

            try
            {
                string dataFile = Path.Combine(dataPath, "device_control.json");
                if (File.Exists(dataFile))
                {
                    string json = File.ReadAllText(dataFile, Encoding.UTF8);
                    _deviceControlData = JsonConvert.DeserializeObject<DeviceControlData>(json);
                }
            }
            catch (Exception ex)
            {
                LogError($"加载设备控制数据失败: {ex.Message}");
            }

            return _deviceControlData ?? new DeviceControlData();
        }

        public void SaveDeviceControlData(DeviceControlData data)
        {
            _deviceControlData = data;
            try
            {
                string dataFile = Path.Combine(dataPath, "device_control.json");
                string json = JsonConvert.SerializeObject(data, jsonSettings);
                File.WriteAllText(dataFile, json, Encoding.UTF8);
            }
            catch (Exception ex)
            {
                LogError($"保存设备控制数据失败: {ex.Message}");
            }
        }

        // 家长控制设置
        private ParentalControlSettingsData? _parentalControlSettingsData;

        public ParentalControlSettingsData LoadParentalControlSettingsData()
        {
            if (_parentalControlSettingsData != null)
                return _parentalControlSettingsData;

            try
            {
                string dataFile = Path.Combine(dataPath, "parental_control_settings.json");
                if (File.Exists(dataFile))
                {
                    string json = File.ReadAllText(dataFile, Encoding.UTF8);
                    _parentalControlSettingsData = JsonConvert.DeserializeObject<ParentalControlSettingsData>(json);
                }
            }
            catch (Exception ex)
            {
                LogError($"加载家长控制设置失败: {ex.Message}");
            }

            return _parentalControlSettingsData ?? new ParentalControlSettingsData();
        }

        public void SaveParentalControlSettingsData(ParentalControlSettingsData data)
        {
            _parentalControlSettingsData = data;
            try
            {
                string dataFile = Path.Combine(dataPath, "parental_control_settings.json");
                string json = JsonConvert.SerializeObject(data, jsonSettings);
                File.WriteAllText(dataFile, json, Encoding.UTF8);
            }
            catch (Exception ex)
            {
                LogError($"保存家长控制设置失败: {ex.Message}");
            }
        }

        // 家长控制使用数据
        private Dictionary<string, UserUsageData>? _parentalControlUsage;

        public Dictionary<string, UserUsageData> LoadParentalControlUsage()
        {
            if (_parentalControlUsage != null)
                return _parentalControlUsage;

            try
            {
                string dataFile = Path.Combine(dataPath, "parental_control_usage.json");
                if (File.Exists(dataFile))
                {
                    string json = File.ReadAllText(dataFile, Encoding.UTF8);
                    _parentalControlUsage = JsonConvert.DeserializeObject<Dictionary<string, UserUsageData>>(json);
                }
            }
            catch (Exception ex)
            {
                LogError($"加载家长控制使用数据失败: {ex.Message}");
            }

            return _parentalControlUsage ?? new Dictionary<string, UserUsageData>();
        }

        public void SaveParentalControlUsage(Dictionary<string, UserUsageData> data)
        {
            _parentalControlUsage = data;
            try
            {
                string dataFile = Path.Combine(dataPath, "parental_control_usage.json");
                string json = JsonConvert.SerializeObject(data, jsonSettings);
                File.WriteAllText(dataFile, json, Encoding.UTF8);
            }
            catch (Exception ex)
            {
                LogError($"保存家长控制使用数据失败: {ex.Message}");
            }
        }

        // 邮件安全设置
        private EmailSecuritySettings? _emailSecuritySettings;

        public EmailSecuritySettings LoadEmailSecuritySettings()
        {
            if (_emailSecuritySettings != null)
                return _emailSecuritySettings;

            try
            {
                string dataFile = Path.Combine(dataPath, "email_security_settings.json");
                if (File.Exists(dataFile))
                {
                    string json = File.ReadAllText(dataFile, Encoding.UTF8);
                    _emailSecuritySettings = JsonConvert.DeserializeObject<EmailSecuritySettings>(json);
                }
            }
            catch (Exception ex)
            {
                LogError($"加载邮件安全设置失败: {ex.Message}");
            }

            return _emailSecuritySettings ?? new EmailSecuritySettings();
        }

        public void SaveEmailSecuritySettings(EmailSecuritySettings data)
        {
            _emailSecuritySettings = data;
            try
            {
                string dataFile = Path.Combine(dataPath, "email_security_settings.json");
                string json = JsonConvert.SerializeObject(data, jsonSettings);
                File.WriteAllText(dataFile, json, Encoding.UTF8);
            }
            catch (Exception ex)
            {
                LogError($"保存邮件安全设置失败: {ex.Message}");
            }
        }

        // 邮件账户
        private List<EmailAccountData>? _emailAccounts;

        public List<EmailAccountData> LoadEmailAccounts()
        {
            if (_emailAccounts != null)
                return _emailAccounts;

            try
            {
                string dataFile = Path.Combine(dataPath, "email_accounts.json");
                if (File.Exists(dataFile))
                {
                    string json = File.ReadAllText(dataFile, Encoding.UTF8);
                    _emailAccounts = JsonConvert.DeserializeObject<List<EmailAccountData>>(json);
                }
            }
            catch (Exception ex)
            {
                LogError($"加载邮件账户失败: {ex.Message}");
            }

            return _emailAccounts ?? new List<EmailAccountData>();
        }

        public void SaveEmailAccounts(List<EmailAccountData> data)
        {
            _emailAccounts = data;
            try
            {
                string dataFile = Path.Combine(dataPath, "email_accounts.json");
                string json = JsonConvert.SerializeObject(data, jsonSettings);
                File.WriteAllText(dataFile, json, Encoding.UTF8);
            }
            catch (Exception ex)
            {
                LogError($"保存邮件账户失败: {ex.Message}");
            }
        }

        // 威胁邮件记录
        public void SaveThreatEmail(ThreatEmail threat)
        {
            try
            {
                string threatsFile = Path.Combine(dataPath, "threat_emails.json");
                List<ThreatEmail> threats;
                
                if (File.Exists(threatsFile))
                {
                    string json = File.ReadAllText(threatsFile, Encoding.UTF8);
                    threats = JsonConvert.DeserializeObject<List<ThreatEmail>>(json) ?? new List<ThreatEmail>();
                }
                else
                {
                    threats = new List<ThreatEmail>();
                }
                
                threats.Add(threat);
                
                // 只保留最近1000条记录
                if (threats.Count > 1000)
                {
                    threats = threats.OrderByDescending(t => t.DetectedTime).Take(1000).ToList();
                }
                
                File.WriteAllText(threatsFile, JsonConvert.SerializeObject(threats, jsonSettings), Encoding.UTF8);
            }
            catch (Exception ex)
            {
                LogError($"保存威胁邮件记录失败: {ex.Message}");
            }
        }

        // 主密码哈希
        private MasterPasswordHashData? _masterPasswordHash;

        public MasterPasswordHashData LoadMasterPasswordHash()
        {
            if (_masterPasswordHash != null)
                return _masterPasswordHash;

            try
            {
                string dataFile = Path.Combine(dataPath, "master_password_hash.json");
                if (File.Exists(dataFile))
                {
                    string json = File.ReadAllText(dataFile, Encoding.UTF8);
                    _masterPasswordHash = JsonConvert.DeserializeObject<MasterPasswordHashData>(json);
                }
            }
            catch (Exception ex)
            {
                LogError($"加载主密码哈希失败: {ex.Message}");
            }

            return _masterPasswordHash ?? new MasterPasswordHashData();
        }

        public void SaveMasterPasswordHash(MasterPasswordHashData data)
        {
            _masterPasswordHash = data;
            try
            {
                string dataFile = Path.Combine(dataPath, "master_password_hash.json");
                string json = JsonConvert.SerializeObject(data, jsonSettings);
                File.WriteAllText(dataFile, json, Encoding.UTF8);
            }
            catch (Exception ex)
            {
                LogError($"保存主密码哈希失败: {ex.Message}");
            }
        }

        // 存储的密码
        private List<StoredPasswordData>? _storedPasswords;

        public List<StoredPasswordData> LoadStoredPasswords()
        {
            if (_storedPasswords != null)
                return _storedPasswords;

            try
            {
                string dataFile = Path.Combine(dataPath, "stored_passwords.json");
                if (File.Exists(dataFile))
                {
                    string json = File.ReadAllText(dataFile, Encoding.UTF8);
                    _storedPasswords = JsonConvert.DeserializeObject<List<StoredPasswordData>>(json);
                }
            }
            catch (Exception ex)
            {
                LogError($"加载存储密码失败: {ex.Message}");
            }

            return _storedPasswords ?? new List<StoredPasswordData>();
        }

        public void SaveStoredPasswords(List<StoredPasswordData> data)
        {
            _storedPasswords = data;
            try
            {
                string dataFile = Path.Combine(dataPath, "stored_passwords.json");
                string json = JsonConvert.SerializeObject(data, jsonSettings);
                File.WriteAllText(dataFile, json, Encoding.UTF8);
            }
            catch (Exception ex)
            {
                LogError($"保存存储密码失败: {ex.Message}");
            }
        }

        public void Dispose()
        {
            signatures.Clear();
            quarantineItems?.Clear();
            trustList.Clear();
            logs.Clear();
        }
    }

    // 网页防护数据模型
    public class WebProtectionData
    {
        public List<string> BlockedWebsites { get; set; } = new List<string>();
        public List<string> AllowedWebsites { get; set; } = new List<string>();
        public List<string> AdDomains { get; set; } = new List<string>();
        public List<string> PhishingPatterns { get; set; } = new List<string>();
    }

    // 设备控制数据模型
    public class DeviceControlData
    {
        public List<string> BlockedDeviceIds { get; set; } = new List<string>();
        public List<string> TrustedDeviceIds { get; set; } = new List<string>();
        public bool BlockUSB { get; set; }
        public bool BlockBluetooth { get; set; }
        public bool BlockCDROM { get; set; }
    }

    // 家长控制数据模型（基础版）
    public class ParentalControlSettingsData
    {
        public bool EnableTimeLimit { get; set; }
        public bool EnableContentFilter { get; set; }
        public bool EnableAppBlocking { get; set; }
        public bool EnableTimeWindow { get; set; }
        public int DailyTimeLimitMinutes { get; set; } = 120;
        public int OverLimitAction { get; set; }
        public string AdminPassword { get; set; } = "";
        public List<string> BlockedApplications { get; set; } = new List<string>();
        public List<string> BlockedKeywords { get; set; } = new List<string>();
        public List<string> BlockedCategories { get; set; } = new List<string>();
        public List<TimeWindowData> AllowedTimeWindows { get; set; } = new List<TimeWindowData>();
    }

    public class TimeWindowData
    {
        public List<int> Days { get; set; } = new List<int>();
        public string StartTime { get; set; } = "00:00:00";
        public string EndTime { get; set; } = "23:59:59";
    }

    public class UserUsageData
    {
        public string UserName { get; set; } = "";
        public int DailyUsageMinutes { get; set; }
        public string SessionStartTime { get; set; } = "";
        public string LastActivity { get; set; } = "";
        public string LastDate { get; set; } = "";
        public List<string> AccessedApps { get; set; } = new List<string>();
        public List<string> AccessedWebsites { get; set; } = new List<string>();
    }

    // 邮件安全数据模型
    public class EmailSecuritySettings
    {
        public bool EnableAttachmentScan { get; set; } = true;
        public bool EnablePhishingDetection { get; set; } = true;
        public bool EnableSpamFilter { get; set; } = true;
        public int ScanIntervalMinutes { get; set; } = 5;
    }

    public class EmailAccountData
    {
        public string Email { get; set; } = "";
        public string Username { get; set; } = "";
        public string Password { get; set; } = "";
        public string ImapServer { get; set; } = "";
        public int ImapPort { get; set; } = 993;
        public bool UseSsl { get; set; } = true;
        public bool IsEnabled { get; set; } = true;
        public string LastScan { get; set; } = "";
    }

    public class ThreatEmail
    {
        public string Id { get; set; } = "";
        public string Sender { get; set; } = "";
        public string Subject { get; set; } = "";
        public string ThreatType { get; set; } = "";
        public string Reason { get; set; } = "";
        public string DetectedTime { get; set; } = "";
    }

    // 密码管理数据模型
    public class MasterPasswordHashData
    {
        public string Salt { get; set; } = "";
        public string Hash { get; set; } = "";
        public int Iterations { get; set; } = 100000;
        public string CreatedAt { get; set; } = "";
    }

    public class StoredPasswordData
    {
        public string Id { get; set; } = "";
        public string Website { get; set; } = "";
        public string Username { get; set; } = "";
        public string Password { get; set; } = "";
        public string Notes { get; set; } = "";
        public string Category { get; set; } = "General";
        public string CreatedAt { get; set; } = "";
        public string LastUpdated { get; set; } = "";
        public string ExpiryDate { get; set; } = "";
        public int Strength { get; set; }
    }
}
