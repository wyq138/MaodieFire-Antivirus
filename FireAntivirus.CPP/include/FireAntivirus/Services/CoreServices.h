#pragma once

#include "../Types.h"
#include "../LogHelper.h"
#include "../Helper.h"
#include "../DataManager.h"
#include "../Platform/Windows.h"
#include "../Engine/AntivirusEngine.h"

#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <set>
#include <memory>
#include <mutex>
#include <thread>
#include <chrono>
#include <atomic>
#include <functional>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <ctime>
#include <future>
#include <condition_variable>
#include <filesystem>

namespace FireAntivirus { namespace Services {

// ============ 枚举 ============

enum class LogLevel { Trace, Debug, Info, Warning, Error, Critical, Fatal };
enum class ThreatSeverity { Low = 1, Medium = 2, High = 3, Critical = 4 };
enum class ThreatType { Unknown, Malware, Ransomware, Phishing, Trojan, Virus, Spyware, Adware, Rootkit, Backdoor, Exploit, SuspiciousActivity, KnownMalicious, BotnetCommunication, DataExfiltration, PortScan, CCCommunication, Warning, Quarantine, Error, Info, FileIntegrityViolation, PartitionTableModification, MBRModification, GPTModification, BootSectorModification, PopupAdvertisement };
enum class RiskLevel { Safe = 0, Low = 1, Medium = 2, High = 3, Critical = 4, Unknown = 5 };
enum class RecommendationPriority { Low, Medium, High, Critical };
enum class StartupImpact { None, Low, Medium, High, Unknown };
enum class ConnectionDirection { Inbound, Outbound, Unknown };
enum class NotificationType { Info, Warning, Error, SecurityAlert, PerformanceAlert, UpdateAvailable, Maintenance, SystemInfo };
enum class NotificationLevel { Silent, Low, Normal, High, Verbose };
enum class NotificationFrequency { Low, Medium, High };
enum class NotificationSeverity { Info, Low, Medium, High, Critical };
enum class NotificationDisplayStyle { Banner, Toast, Popup, FullScreen };
enum class LogDetail { Minimal, Basic, Medium, Detailed, Verbose };
enum class ThemeType { SystemDefault, Light, Dark, HighContrast };
enum class LogCategory { SystemError, Security, Performance, UserInteraction, UserFeedback, Configuration, Notification, Network, FileSystem };
enum class EnterpriseEventType { Info, Warning, Error, DeviceRegistered, ScanRecordAdded, ThreatDetected, PolicyCreated, GroupCreated, ReportGenerated };
enum class MonitorPriority { Low, Medium, High, Critical };
enum class SecurityLevel { None, Low, Medium, High, Critical };
enum class SystemStatus { Normal, Warning, Critical, Maintenance, Updating, Scanning };

// ============ IMonitor 接口 ============
class IMonitor {
public:
    virtual ~IMonitor() = default;
    virtual void Start() = 0;
    virtual void Stop() = 0;
};

// ============ SharedTypes 数据类 ============
struct SignatureInfo {
    std::string FilePath;
    bool IsSigned = false;
    bool IsValid = false;
    bool IsTrusted = false;
    std::string Publisher;
    std::string Subject;
    std::string Issuer;
    std::string SignTime;
    std::string NotBefore;
    std::string NotAfter;
    std::string CertificateSubject;
    std::vector<std::string> ChainErrors;
    bool IsTrustedSigner = false;
    std::string Signer;
    std::string SigningTime;
};

struct StartupImpactInfo {
    std::string Name;
    StartupImpact Impact = StartupImpact::Unknown;
    int ImpactScore = 0;
    int BootDelayMs = 0;
    long long MemoryImpactMB = 0;
    bool HasNetworkDependency = false;
};

struct OptimizationRecommendation {
    RecommendationPriority Priority = RecommendationPriority::Medium;
    std::string Title;
    std::string Description;
    std::string PotentialImprovement;
    std::string PotentialGain;
    long long PotentialSavings = 0;
    std::string Category;
};

struct ThreatDetectedEventArgs {
    std::string Url;
    std::string FilePath;
    ThreatSeverity Severity = ThreatSeverity::Low;
    ThreatType Type = ThreatType::Unknown;
    std::string DetectedTime;
    std::string Description;
    std::vector<std::string> Threats;
    RiskLevel RiskLevel = RiskLevel::Safe;
};

struct DiskInfo {
    std::string Name;
    std::string Drive;
    std::string Label;
    std::string Format;
    std::string FileSystem;
    std::string DriveType;
    long long TotalSize = 0;
    long long FreeSpace = 0;
    long long UsedSpace = 0;
    int UsagePercent = 0;
    int UsagePercentage = 0;
    bool IsSSD = false;
    std::string SmartStatus;
};

struct SystemInfo {
    std::string ComputerName;
    std::string UserName;
    std::string Domain;
    std::string OSVersion;
    std::string OSName;
    std::string OSBuild;
    std::string OSArchitecture;
    std::string Processor;
    std::string CPUName;
    int ProcessorCores = 0;
    int ProcessorLogicalProcessors = 0;
    long long TotalMemory = 0;
    long long TotalMemoryBytes = 0;
    uint64_t TotalPhysicalMemory = 0;
    long long AvailableMemory = 0;
    long long AvailableMemoryBytes = 0;
    long UptimeSeconds = 0;
    uint CPULogicalProcessors = 0;
    std::vector<DiskInfo> Disks;
    std::string SystemDirectory;
    std::string InstallDate;
    std::string LastBootTime;
    std::vector<std::string> IPAddresses;
    std::string MACAddress;
    std::string Error;
};

struct NetworkConnectionInfo {
    std::string Protocol;
    std::string LocalAddress;
    int LocalPort = 0;
    std::string RemoteAddress;
    std::string RemoteIP;
    int RemotePort = 0;
    std::string State;
    int ProcessId = 0;
    std::string ProcessName;
    std::string ProcessPath;
    RiskLevel RiskLevel = RiskLevel::Safe;
    int ThreatScore = 0;
    long long BytesSent = 0;
    long long BytesReceived = 0;
    long long BytesTransferred = 0;
    std::string Timestamp;
    std::string LastSeen;
    ThreatType ThreatTypeVal = ThreatType::Unknown;
    std::string ThreatDescription;
    bool IsSuspicious = false;
    ConnectionDirection Direction = ConnectionDirection::Unknown;
};

struct VulnerabilityInfo {
    std::string Id;
    std::string Category;
    std::string Name;
    std::string Title;
    std::string Description;
    std::string Severity;
    std::string Location;
    bool CanAutoFix = false;
    std::string FixAction;
    std::string CveId;
    std::string CVEId;
    double CVSSScore = 0.0;
    std::vector<std::string> AffectedProducts;
    std::string Remediation;
    std::vector<std::string> Remediations;
    std::string Published;
    std::vector<std::string> References;
    std::string DetectedAt;
    bool IsFixed = false;
};

struct MonitorResourceInfo {
    std::string MonitorName;
    MonitorPriority Priority = MonitorPriority::Medium;
    double CpuUsagePercent = 0.0;
    long long MemoryUsageBytes = 0;
    std::string LastUpdated;
    bool IsActive = false;
};

// ============ ConfigManager ============
struct AppConfig {
    bool FileProtectionEnabled = true;
    bool ProcessProtectionEnabled = true;
    bool DeviceProtectionEnabled = true;
    bool RegistryProtectionEnabled = true;
    bool BrowserProtectionEnabled = true;
    bool ScriptProtectionEnabled = true;
    bool ActiveDefenseEnabled = true;
    bool DiskProtectionEnabled = true;
    bool UEFIProtectionEnabled = true;
    bool KernelProtectionEnabled = true;
    bool DocumentProtectionEnabled = true;
    bool NetworkProtectionEnabled = true;
    bool PopupBlockerEnabled = true;
    bool RansomwareProtectionEnabled = true;
    bool PrivacyProtectionEnabled = true;
    bool WebProtectionEnabled = true;
    bool EmailSecurityEnabled = true;
    bool PasswordManagerEnabled = true;
    bool NetworkFirewallEnabled = true;
    bool DeviceControlEnabled = true;
    bool VulnerabilityScannerEnabled = true;
    bool CloudScanEnabled = true;
    bool SecureBrowserEnabled = true;
    bool MobileSecurityEnabled = true;
    bool SystemOptimizerEnabled = true;
    bool BackupRecoveryEnabled = true;
    bool SecurityScoreEnabled = true;
    bool NetworkTrafficEnabled = true;
    bool ApplicationMonitorEnabled = true;
    bool StartupManagerEnabled = true;
    bool SecurityReportEnabled = true;
    bool BehaviorAnalysisEnabled = true;
    bool SystemToolsEnabled = true;
    bool SystemInfoEnabled = true;
    bool QuarantineEnabled = true;
    bool TrustZoneEnabled = true;
    bool LogCenterEnabled = true;
};

class ConfigManager {
public:
    static ConfigManager& Instance();
    static void Initialize();
    static void SaveConfig();
    static AppConfig& Config();
    static const std::string& ConfigFile();

private:
    ConfigManager() = default;
    mutable std::mutex _lock;
    bool _initialized = false;
    std::string _configFile;
    AppConfig _config;
    void LoadConfig();
    static ConfigManager* _instance;
};

// ============ Logger ============
class Logger {
public:
    static void Info(const std::string& message);
    static void Warning(const std::string& message);
    static void Error(const std::string& message);
};

// ============ LogManager ============
class LogManager {
public:
    static void Initialize();
    static void LogDebug(const std::string& message);
    static void LogInfo(const std::string& message);
    static void LogWarning(const std::string& message);
    static void LogError(const std::string& message);
    static void LogFatal(const std::string& message);
    static const std::string& LogDirectory();
    static const std::string& LogFile();

private:
    LogManager() = default;
    static LogManager* _instance;
    static std::mutex _lock;
    static std::string _logDirectory;
    static std::string _logFile;
    static bool _initialized;
    static void Log(LogLevel level, const std::string& message);
    static void CheckLogFileSize();
    static std::string LevelToString(LogLevel level);
    static std::string FormatTimestamp();
};

// ============ EnterpriseManager ============
struct DeviceInfo {
    std::string DeviceId;
    std::string Name;
    std::string IPAddress;
    std::string OSVersion;
    std::string LastSeen;
    std::string Status;
    std::string GroupId;
};

struct ScanRecord {
    std::string RecordId;
    std::string DeviceId;
    std::string ScanType;
    std::string StartTime;
    std::string EndTime;
    std::string Status;
    int DetectedThreats = 0;
    int QuarantinedItems = 0;
};

struct Threat {
    std::string ThreatId;
    std::string DeviceId;
    std::string ScanRecordId;
    std::string FilePath;
    std::string ThreatName;
    std::string ThreatType;
    std::string Severity;
    std::string Status;
    std::string DetectionTime;
};

struct Policy {
    std::string PolicyId;
    std::string PolicyName;
    std::string Description;
    std::string Settings;
    std::string CreatedDate;
    std::string LastModifiedDate;
};

struct Group {
    std::string GroupId;
    std::string GroupName;
    std::string Description;
    std::string PolicyId;
};

struct DeviceReport {
    std::string DeviceId;
    std::string Name;
    std::string IPAddress;
    std::string OSVersion;
    std::string Status;
    std::vector<ScanRecord> ScanRecords;
    std::vector<Threat> Threats;
};

struct Report {
    std::string ReportId;
    std::string ReportName;
    std::string ReportType;
    std::string GeneratedDate;
    int TotalDevices = 0;
    int TotalScans = 0;
    int TotalThreats = 0;
    int CriticalThreats = 0;
    int HighThreats = 0;
    int MediumThreats = 0;
    int LowThreats = 0;
    std::vector<DeviceReport> Devices;
};

struct ReportOptions {
    std::string ReportName;
    std::string ReportType;
    std::string GroupId;
    std::string StartDate;
    std::string EndDate;
};

struct EnterpriseEventArgs {
    EnterpriseEventType EventType = EnterpriseEventType::Info;
    std::string Message;
    std::string Timestamp;
    EnterpriseEventArgs(EnterpriseEventType t, const std::string& m) : EventType(t), Message(m) {
        Timestamp = LogManager::FormatTimestamp();
    }
};

class EnterpriseManager {
public:
    std::function<void(const EnterpriseEventArgs&)> OnEvent;
    EnterpriseManager(const std::string& databasePath = "", const std::string& serverUrl = "");

    DeviceInfo RegisterDevice(const DeviceInfo& deviceInfo);
    ScanRecord AddScanRecord(const ScanRecord& scanRecord);
    Threat AddThreat(const Threat& threat);
    Policy CreatePolicy(const Policy& policy);
    Group CreateGroup(const Group& group);
    std::vector<DeviceInfo> GetDevices();
    std::vector<ScanRecord> GetScanRecords(const std::string& deviceId = "");
    std::vector<Threat> GetThreats(const std::string& deviceId = "", const std::string& scanRecordId = "");
    std::vector<Policy> GetPolicies();
    std::vector<Group> GetGroups();
    Report GenerateReport(const ReportOptions& options);
    void Enable();
    void Disable();
    bool IsEnabled();
    void SetServerUrl(const std::string& url);
    std::string GetServerUrl();

private:
    std::string _databasePath;
    std::string _serverUrl;
    bool _enabled = true;
    std::mutex _managerLock;
    // 内存表（代替 SQLite）
    std::vector<DeviceInfo> _devices;
    std::vector<ScanRecord> _scanRecords;
    std::vector<Threat> _threats;
    std::vector<Policy> _policies;
    std::vector<Group> _groups;
    void InitializeDatabase();
    void SyncDeviceToServer(const DeviceInfo& d);
    void SyncScanRecordToServer(const ScanRecord& r);
    void SyncThreatToServer(const Threat& t);
    void SyncPolicyToServer(const Policy& p);
    void SyncGroupToServer(const Group& g);
    void RaiseEvent(const EnterpriseEventArgs& e);
    void EnsureDirectory(const std::string& path);
};

// ============ ServiceManager ============
enum class ServiceStatus { Stopped, Running, Paused, Unknown };

class ServiceManager {
public:
    static bool InstallService();
    static bool UninstallService();
    static bool StartService();
    static bool StopService();
    static bool IsServiceInstalled();
    static bool IsServiceRunning();
    static ServiceStatus GetServiceStatus();
    static void RunServiceInConsole();

private:
    static const std::string ServiceName;
    static const std::string ServiceDisplayName;
};

// ============ NotificationService ============
struct LogEntry {
    std::string Id;
    std::string Time;
    std::string Type;
    std::string Message;
    std::string Details;
};

class NotificationService {
public:
    static NotificationService& Instance();
    void Start();
    void Stop();
    void ShowNotification(const std::string& title, const std::string& message, NotificationType type);

private:
    NotificationService();
    NotificationService(const NotificationService&) = delete;
    bool _isRunning = false;
    std::thread _notificationThread;
    void RunNotificationService();
    void CheckSecurityEvents();
    bool IsRealThreat(const std::string& logType);
    static NotificationService* _instance;
    static std::mutex _instanceLock;
    // 日志存储（模拟 DataManager::LoadLogs）
    std::vector<LogEntry> _recentLogs;
    std::mutex _logLock;
};

// ============ SidebarServices ============
class SecurityService; // 前向声明

#define DECLARE_SIDEBAR_SERVICE(Name, EnableMethod, IsEnabledMethod) \
class Name { \
public: \
    SecurityService* _securityService; \
    Name(SecurityService* s) : _securityService(s) {} \
    bool Enable(bool enable); \
    bool IsEnabled(); \
};

// 各个 Sidebar 服务包装
class SidebarNetworkProtectionService { public: SecurityService* _s; SidebarNetworkProtectionService(SecurityService* s) : _s(s) {} bool Enable(bool e); bool IsEnabled(); };
class SidebarPopupBlockerService      { public: SecurityService* _s; SidebarPopupBlockerService(SecurityService* s) : _s(s) {} bool Enable(bool e); bool IsEnabled(); };
class SidebarRansomwareProtectionService { public: SecurityService* _s; SidebarRansomwareProtectionService(SecurityService* s) : _s(s) {} bool Enable(bool e); bool IsEnabled(); };
class SidebarPrivacyProtectionService { public: SecurityService* _s; SidebarPrivacyProtectionService(SecurityService* s) : _s(s) {} bool Enable(bool e); bool IsEnabled(); };
class SidebarWebProtectionService     { public: SecurityService* _s; SidebarWebProtectionService(SecurityService* s) : _s(s) {} bool Enable(bool e); bool IsEnabled(); };
class SidebarEmailSecurityService     { public: SecurityService* _s; SidebarEmailSecurityService(SecurityService* s) : _s(s) {} bool Enable(bool e); bool IsEnabled(); };
class SidebarPasswordManagerService   { public: SecurityService* _s; SidebarPasswordManagerService(SecurityService* s) : _s(s) {} bool Enable(bool e); bool IsEnabled(); };
class SidebarNetworkFirewallService  { public: SecurityService* _s; SidebarNetworkFirewallService(SecurityService* s) : _s(s) {} bool Enable(bool e); bool IsEnabled(); };
class SidebarDeviceControlService     { public: FireAntivirus::DataManager* _d; SidebarDeviceControlService(FireAntivirus::DataManager* d) : _d(d) {} bool Enable(bool e); bool IsEnabled(); };
class SidebarVulnerabilityScannerService { public: SecurityService* _s; SidebarVulnerabilityScannerService(SecurityService* s) : _s(s) {} bool Enable(bool e); bool IsEnabled(); };
class SidebarCloudScanService         { public: SecurityService* _s; SidebarCloudScanService(SecurityService* s) : _s(s) {} bool Enable(bool e); bool IsEnabled(); };
class SidebarSecureBrowserService     { public: SecurityService* _s; SidebarSecureBrowserService(SecurityService* s) : _s(s) {} bool Enable(bool e); bool IsEnabled(); };
class SidebarMobileSecurityService    { public: SecurityService* _s; SidebarMobileSecurityService(SecurityService* s) : _s(s) {} bool Enable(bool e); bool IsEnabled(); };
class SidebarSystemOptimizerService   { public: SecurityService* _s; SidebarSystemOptimizerService(SecurityService* s) : _s(s) {} bool Enable(bool e); bool IsEnabled(); };
class SidebarBackupRecoveryService    { public: SecurityService* _s; SidebarBackupRecoveryService(SecurityService* s) : _s(s) {} bool Enable(bool e); bool IsEnabled(); };
class SidebarSecurityScoreService     { public: SecurityService* _s; SidebarSecurityScoreService(SecurityService* s) : _s(s) {} bool Enable(bool e); bool IsEnabled(); };
class SidebarNetworkTrafficService    { public: SecurityService* _s; SidebarNetworkTrafficService(SecurityService* s) : _s(s) {} bool Enable(bool e); bool IsEnabled(); };
class SidebarApplicationMonitorService { public: SecurityService* _s; SidebarApplicationMonitorService(SecurityService* s) : _s(s) {} bool Enable(bool e); bool IsEnabled(); };
class SidebarStartupManagerService    { public: SecurityService* _s; SidebarStartupManagerService(SecurityService* s) : _s(s) {} bool Enable(bool e); bool IsEnabled(); };
class SidebarSecurityReportService    { public: SecurityService* _s; SidebarSecurityReportService(SecurityService* s) : _s(s) {} bool Enable(bool e); bool IsEnabled(); };
class SidebarBehaviorAnalysisService  { public: FireAntivirus::DataManager* _d; SidebarBehaviorAnalysisService(FireAntivirus::DataManager* d) : _d(d) {} bool Enable(bool e); bool IsEnabled(); };
class SidebarSystemToolsService       { public: SecurityService* _s; SidebarSystemToolsService(SecurityService* s) : _s(s) {} bool Enable(bool e); bool IsEnabled(); };
class SidebarSystemInfoService        { public: SecurityService* _s; SidebarSystemInfoService(SecurityService* s) : _s(s) {} bool Enable(bool e); bool IsEnabled(); };
class SidebarQuarantineService        { public: SecurityService* _s; SidebarQuarantineService(SecurityService* s) : _s(s) {} bool Enable(bool e); bool IsEnabled(); };
class SidebarTrustZoneService         { public: SecurityService* _s; SidebarTrustZoneService(SecurityService* s) : _s(s) {} bool Enable(bool e); bool IsEnabled(); };
class SidebarLogCenterService         { public: SecurityService* _s; SidebarLogCenterService(SecurityService* s) : _s(s) {} bool Enable(bool e); bool IsEnabled(); };

class SidebarServices {
public:
    SecurityService* _securityService;
    FireAntivirus::DataManager* _dataManager;

    SidebarNetworkProtectionService NetworkProtection{nullptr};
    SidebarPopupBlockerService PopupBlocker{nullptr};
    SidebarRansomwareProtectionService RansomwareProtection{nullptr};
    SidebarPrivacyProtectionService PrivacyProtection{nullptr};
    SidebarWebProtectionService WebProtection{nullptr};
    SidebarEmailSecurityService EmailSecurity{nullptr};
    SidebarPasswordManagerService PasswordManager{nullptr};
    SidebarNetworkFirewallService NetworkFirewall{nullptr};
    SidebarDeviceControlService DeviceControl{nullptr};
    SidebarVulnerabilityScannerService VulnerabilityScanner{nullptr};
    SidebarCloudScanService CloudScan{nullptr};
    SidebarSecureBrowserService SecureBrowser{nullptr};
    SidebarMobileSecurityService MobileSecurity{nullptr};
    SidebarSystemOptimizerService SystemOptimizer{nullptr};
    SidebarBackupRecoveryService BackupRecovery{nullptr};
    SidebarSecurityScoreService SecurityScore{nullptr};
    SidebarNetworkTrafficService NetworkTraffic{nullptr};
    SidebarApplicationMonitorService ApplicationMonitor{nullptr};
    SidebarStartupManagerService StartupManager{nullptr};
    SidebarSecurityReportService SecurityReport{nullptr};
    SidebarBehaviorAnalysisService BehaviorAnalysis{nullptr};
    SidebarSystemToolsService SystemTools{nullptr};
    SidebarSystemInfoService SystemInfo{nullptr};
    SidebarQuarantineService Quarantine{nullptr};
    SidebarTrustZoneService TrustZone{nullptr};
    SidebarLogCenterService LogCenter{nullptr};

    SidebarServices(SecurityService* securityService, FireAntivirus::DataManager* dataManager);
    void Initialize();
};

// ============ UserExperienceManager ============
struct UserConfig {
    NotificationLevel NotificationLevel = NotificationLevel::Normal;
    bool AutoLearnEnabled = true;
    bool FeedbackCollection = true;
    LogDetail LogDetailLevel = LogDetail::Medium;
    SecurityLevel SecurityConfirmation = SecurityLevel::Medium;
    ThemeType UiTheme = ThemeType::SystemDefault;
    std::string Language = "zh-CN";
    bool EnableSecurityAlerts = true;
    bool EnablePerformanceAlerts = true;
    bool EnableUpdateNotifications = true;
    bool EnableMaintenanceNotifications = true;
    bool EnableNotificationSound = true;
    int NotificationDuration = 5000;
    bool AutoCleanLogs = true;
    int LogRetentionDays = 30;
    bool EnableBiometricAuth = false;
    UserConfig Clone() const { return *this; }
};

struct SystemAlert {
    std::string Id;
    std::string Title;
    std::string Message;
    NotificationType Type = NotificationType::Info;
    NotificationSeverity Severity = NotificationSeverity::Info;
    std::string Timestamp;
    long UserResponseTimeMs = 0;
};

class UserExperienceManager : public IMonitor {
public:
    explicit UserExperienceManager(FireAntivirus::DataManager* dataManager);
    void Start() override;
    void Stop() override;
    void ShowCustomizedNotification(const std::string& title, const std::string& message, NotificationType type, NotificationSeverity severity);
    UserConfig GetCurrentConfiguration();
    void UpdateConfiguration(const UserConfig& newConfig);
    void CollectUserFeedback(const std::string& feedbackType, const std::string& message, int rating);

private:
    FireAntivirus::DataManager* _dataManager;
    std::thread _userFeedbackThread;
    std::thread _learningThread;
    std::atomic<bool> _isRunning;
    UserConfig _userConfig;

    void LoadUserConfiguration();
    void SaveUserConfiguration();
    void InitializeDefaultSettings();
    void UserFeedbackLoop();
    void MachineLearningLoop();
    void ShowWelcomeNotification();
};

}} // namespace FireAntivirus::Services
