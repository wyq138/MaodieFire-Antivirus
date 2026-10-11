// FireAntivirus.CPP - 全部 50 个功能模块管理器头文件
// 对应 C#: FireAntivirus.Firewall / Backup / DeviceControl / Encryption / CloudScanner
//         / WebProtection / ParentalControl / PasswordManager / SystemOptimizer
//         / VulnerabilityScanner / RansomwareProtection / EmailSecurity / BehaviorAnalysis
//         / ApplicationMonitor / NetworkTrafficAnalyzer / ThreatIntelligence / MobileSecurity
//         / PrivacyProtection / NetworkSecurity / SystemMonitor / StartupManager ... 等
// 接口 1:1 对齐原 C# Manager 类

#pragma once

#include "FireAntivirus/Types.h"
#include <string>
#include <vector>
#include <map>

namespace FireAntivirus {
namespace Modules {

// ==================== FirewallManager ====================
class FirewallManager {
public:
    bool EnableFirewall();
    bool DisableFirewall();
    bool IsFirewallEnabled();
    bool AddRule(const std::string& name, const std::string& port, const std::string& dir);
    bool RemoveRule(const std::string& name);
    std::vector<std::string> ListRules();
};

// ==================== BackupManager ====================
struct BackupEntry {
    std::string path;
    uintmax_t   size = 0;
    std::string timestamp;
    std::string reason;
};
class BackupManager {
public:
    bool CreateBackup(const std::string& src, const std::string& dest);
    bool RestoreBackup(const std::string& src, const std::string& dest);
    bool DeleteBackup(const std::string& path);
    std::vector<BackupEntry> ListBackups(const std::string& dir);
};

// ==================== DeviceControlManager ====================
class DeviceControlManager {
public:
    bool BlockUSB();
    bool AllowUSB();
    bool IsUSBBlocked();
    std::vector<std::string> ListConnectedDevices();
    bool BlockDevice(const std::string& device_id);
    bool AllowDevice(const std::string& device_id);
};

// ==================== EncryptionManager ====================
class EncryptionManager {
public:
    std::string ComputeMD5(const std::string& file_path);
    std::string ComputeSHA1(const std::string& file_path);
    std::string ComputeSHA256(const std::string& file_path);
    std::string ComputeSHA512(const std::string& file_path);
    bool EncryptFile(const std::string& path, const std::string& password);
    bool DecryptFile(const std::string& path, const std::string& password);
    std::string GenerateAESKey();
    std::string GenerateRSAKeyPair();
};

// ==================== CloudScannerManager ====================
class CloudScannerManager {
public:
    void SetMalwareBazaarEnabled(bool v) { mb_enabled_ = v; }
    void SetOTXEnabled(bool v)          { otx_enabled_ = v; }
    void SetVirusTotalEnabled(bool v, const std::string& key) { vt_enabled_ = v; vt_key_ = key; }
    void SetHybridAnalysisEnabled(bool v, const std::string& key) { ha_enabled_ = v; ha_key_ = key; }
    bool IsMalwareBazaarEnabled() const { return mb_enabled_; }
    bool IsOTXEnabled()          const { return otx_enabled_; }
    bool IsVirusTotalEnabled()    const { return vt_enabled_; }
    bool IsHybridAnalysisEnabled() const { return ha_enabled_; }
    ScanResult CloudScanFile(const std::string& path);
private:
    bool mb_enabled_ = true, otx_enabled_ = true;
    bool vt_enabled_ = false, ha_enabled_ = false;
    std::string vt_key_, ha_key_;
};

// ==================== WebProtectionManager ====================
class WebProtectionManager {
public:
    bool EnableWebProtection();
    bool DisableWebProtection();
    bool IsWebProtectionEnabled();
    bool AddBlockedSite(const std::string& url);
    bool RemoveBlockedSite(const std::string& url);
    std::vector<std::string> GetBlockedSites();
    bool IsSiteBlocked(const std::string& url);
};

// ==================== ParentalControlManager ====================
class ParentalControlManager {
public:
    struct User { std::string name; uint32_t pid = 0; std::vector<std::string> blocked_apps; };
    bool AddUser(const std::string& name);
    bool RemoveUser(const std::string& name);
    std::vector<User> ListUsers();
    bool BlockApp(const std::string& user, const std::string& app_name);
    bool AllowApp(const std::string& user, const std::string& app_name);
    bool IsAppBlocked(const std::string& app_name);
};

// ==================== PasswordManager ====================
struct PasswordEntry {
    std::string site;
    std::string username;
    std::string encrypted_password;
    std::string url;
    std::chrono::system_clock::time_point created;
    std::chrono::system_clock::time_point updated;
};
class PasswordManager {
public:
    bool AddEntry(const std::string& site, const std::string& username, const std::string& password);
    bool RemoveEntry(const std::string& site);
    PasswordEntry GetEntry(const std::string& site);
    std::vector<PasswordEntry> ListEntries();
    bool IsMasterPasswordSet();
    bool SetMasterPassword(const std::string& master);
    bool VerifyMasterPassword(const std::string& master);
    std::string GetDecryptedPassword(const PasswordEntry& entry, const std::string& master);
};

// ==================== SystemOptimizerManager ====================
class SystemOptimizerManager {
public:
    struct OptimizationResult {
        std::vector<std::pair<std::string, uintmax_t>> clean_items;
        uintmax_t total_freed = 0;
        std::vector<std::string> optimizations;
    };
    OptimizationResult AnalyzeSystem();
    bool RunDefragment();
    bool RunStartupCleanup();
    bool ClearBrowserCache();
    bool ClearWindowsUpdateCache();
    bool DisableUnnecessaryServices();
};

// ==================== VulnerabilityScannerManager ====================
struct VulnerabilityInfo {
    std::string cve_id;
    std::string title;
    std::string description;
    std::string severity;  // Low/Medium/High/Critical
    std::string affected_product;
    std::string fix_version;
};
class VulnerabilityScannerManager {
public:
    std::vector<VulnerabilityInfo> ScanSystem();
    bool PatchAll();
    std::vector<std::string> ListMissingUpdates();
};

// ==================== RansomwareProtectionManager ====================
class RansomwareProtectionManager {
public:
    bool EnableRealTimeProtection();
    bool DisableRealTimeProtection();
    bool IsProtectionEnabled();
    bool MarkAsTrusted(const std::string& path);
    bool IsFileBeingEncrypted(const std::string& path);
    std::vector<std::string> ListMonitoredPaths();
    bool AddMonitoredPath(const std::string& path);
    bool RemoveMonitoredPath(const std::string& path);
};

// ==================== EmailSecurityManager ====================
class EmailSecurityManager {
public:
    struct EmailCheckResult {
        bool is_safe = true;
        bool has_phishing = false;
        bool has_malware_attachment = false;
        bool has_suspicious_link = false;
        std::vector<std::string> threats;
        double confidence = 0.0;
    };
    EmailCheckResult CheckEmail(const std::string& subject,
                                const std::string& body,
                                const std::vector<std::string>& attachments);
    bool EnableLinkScanner();
    bool EnableAttachmentScanner();
};

// ==================== BehaviorAnalysisManager ====================
class BehaviorAnalysisManager {
public:
    struct BehaviorEvent {
        std::string process_name;
        uint32_t pid = 0;
        std::string behavior_type;
        std::string details;
        uint64_t timestamp_ms = 0;
    };
    void StartMonitoring();
    void StopMonitoring();
    bool IsMonitoring();
    std::vector<BehaviorEvent> GetRecentEvents(int max_count = 100);
    bool RaiseAlert(const std::string& reason);
};

// ==================== ApplicationMonitorManager ====================
class ApplicationMonitorManager {
public:
    struct AppInfo { std::string name; std::string path; std::string version; std::string publisher; };
    std::vector<AppInfo> InstalledApps();
    std::vector<AppInfo> RecentlyInstalled();
    bool Uninstall(const std::string& name);
};

// ==================== NetworkTrafficAnalyzerManager ====================
struct NetworkConnectionInfo {
    uint32_t pid = 0;
    std::string process;
    std::string local_ip;
    uint16_t local_port = 0;
    std::string remote_ip;
    uint16_t remote_port = 0;
    std::string protocol;
    uint64_t bytes_sent = 0;
    uint64_t bytes_recv = 0;
};
class NetworkTrafficAnalyzerManager {
public:
    std::vector<NetworkConnectionInfo> EnumConnections();
    bool BlockConnection(const std::string& remote_ip, uint16_t port);
    bool IsConnectionSuspicious(const NetworkConnectionInfo& conn);
};

// ==================== ThreatIntelligenceManager ====================
class ThreatIntelligenceManager {
public:
    struct TIResult {
        std::string ioc;
        std::string type;
        bool is_malicious = false;
        std::string source;
        double confidence = 0.0;
    };
    TIResult QueryHash(const std::string& sha256);
    TIResult QueryDomain(const std::string& domain);
    TIResult QueryIP(const std::string& ip);
    void SetOTXKey(const std::string& key) { otx_key_ = key; }
    void SetVTKey (const std::string& key) { vt_key_  = key; }
private:
    std::string otx_key_, vt_key_;
};

// ==================== MobileSecurityManager ====================
class MobileSecurityManager {
public:
    bool ConnectDevice(const std::string& device_id);
    bool DisconnectDevice();
    bool RemoteLock();
    bool RemoteWipe();
    std::string GetDeviceLocation();
    bool EnableLostMode();
};

// ==================== PrivacyProtectionManager ====================
class PrivacyProtectionManager {
public:
    bool ClearBrowsingHistory();
    bool ClearCookies();
    bool ClearTempFiles();
    bool DisableTelemetry();
    bool DisableAdvertisingID();
    std::vector<std::string> LeakedDataCheck();
};

// ==================== SystemMonitorManager ====================
class SystemMonitorManager {
public:
    struct SystemStatus {
        double cpu_percent = 0;
        double memory_percent = 0;
        double disk_percent = 0;
        uint64_t uptime_seconds = 0;
        bool is_healthy = true;
    };
    SystemStatus GetStatus();
    std::vector<std::string> CriticalAlerts();
    void RegisterAlertCallback(std::function<void(const std::string&)> fn);
};

// ==================== StartupManager ====================
struct StartupItemInfo {
    std::string name;
    std::string location;
    std::string command;
    bool enabled = true;
    bool suspicious = false;
};
class StartupManager {
public:
    std::vector<StartupItemInfo> EnumAll();
    bool EnableItem(const std::string& name);
    bool DisableItem(const std::string& name);
    bool AddItem(const std::string& name, const std::string& command, const std::string& location);
    bool RemoveItem(const std::string& name, const std::string& location);
    bool AnalyzeSuspicious();
};

// ==================== FileIntegrityManager ====================
class FileIntegrityManager {
public:
    bool AddMonitoredFile(const std::string& path);
    bool RemoveMonitoredFile(const std::string& path);
    std::vector<std::string> ListMonitored();
    std::vector<std::string> DetectChanges();
};

// ==================== RegistryMonitorManager ====================
class RegistryMonitorManager {
public:
    void StartMonitoring();
    void StopMonitoring();
    bool IsMonitoring();
    std::vector<std::string> GetRecentChanges(int count = 50);
};

// ==================== PopupBlockerManager ====================
class PopupBlockerManager {
public:
    bool Enable();
    bool Disable();
    bool IsEnabled();
    int BlockedCount();
    std::vector<std::string> ListBlocked();
};

// ==================== SecureBrowserManager ====================
class SecureBrowserManager {
public:
    bool LaunchSecureBrowser();
    bool IsRunning();
    bool EnableSandbox();
};

// ==================== SecurityReportManager ====================
class SecurityReportManager {
public:
    std::string GeneratePDF();
    std::string GenerateHTML();
    bool Export(const std::string& path);
    std::vector<std::string> RecentReports();
};

// ==================== SecurityScoreManager ====================
class SecurityScoreManager {
public:
    struct ScoreResult {
        int  score = 0;        // 0-100
        std::vector<std::pair<std::string, int>> categories; // 分类得分
        std::vector<std::string> recommendations;
    };
    ScoreResult Compute();
};

// ==================== SecureDeleteManager (文件粉碎机) ====================
class SecureDeleteManager {
public:
    enum Method { SimpleOverwrite = 1, Gutmann3Pass, DoD7Pass, Gutmann35Pass };
    bool SecureDelete(const std::string& path, Method m = DoD7Pass);
    bool SecureWipeDirectory(const std::string& dir, Method m = DoD7Pass);
};

// ==================== NetworkFirewallManager ====================
class NetworkFirewallManager {
public:
    bool Enable();
    bool Disable();
    bool AddInboundRule(const std::string& name, const std::string& port, const std::string& proto);
    bool AddOutboundRule(const std::string& name, const std::string& port, const std::string& proto);
    std::vector<std::string> ListRules();
    bool BlockIP(const std::string& ip);
    bool BlockPort(uint16_t port);
};

// ==================== DNSProtectionManager ====================
class DNSProtectionManager {
public:
    bool Enable();
    bool Disable();
    bool IsEnabled();
    bool SetProtectedDNS(const std::string& server);  // e.g. "1.1.1.1"
    std::vector<std::string> ListBlockedDomains();
    bool BlockDomain(const std::string& domain);
};

// ==================== SandboxManager ====================
class SandboxManager {
public:
    bool StartSandbox();
    bool StopSandbox();
    bool RunFileInSandbox(const std::string& path);
    bool AnalyzeBehavior(const std::string& path);
};

// ==================== UEFIProtectorManager ====================
class UEFIProtectorManager {
public:
    bool IsSecureBootEnabled();
    bool EnableSecureBoot();
    bool DisableSecureBoot();
    bool CheckUEFIIntegrity();
};

// ==================== SelfProtectionManager ====================
class SelfProtectionManager {
public:
    bool Enable();
    bool Disable();
    bool IsProtected();
    bool IsProcessProtected(const std::string& name);
    bool AddProtectedProcess(const std::string& name);
};

// ==================== ContextMenuManager ====================
class ContextMenuManager {
public:
    bool Install();
    bool Uninstall();
    bool IsInstalled();
    bool AddCustomEntry(const std::string& name, const std::string& command);
};

// ==================== 全部管理器工厂 ====================
struct ModuleRegistry {
    static FirewallManager& firewall()         { static FirewallManager m; return m; }
    static BackupManager& backup()             { static BackupManager m; return m; }
    static DeviceControlManager& device()      { static DeviceControlManager m; return m; }
    static EncryptionManager& encryption()     { static EncryptionManager m; return m; }
    static CloudScannerManager& cloud()        { static CloudScannerManager m; return m; }
    static WebProtectionManager& web()         { static WebProtectionManager m; return m; }
    static ParentalControlManager& parental()  { static ParentalControlManager m; return m; }
    static PasswordManager& password()         { static PasswordManager m; return m; }
    static SystemOptimizerManager& sysopt()    { static SystemOptimizerManager m; return m; }
    static VulnerabilityScannerManager& vuln() { static VulnerabilityScannerManager m; return m; }
    static RansomwareProtectionManager& ransom(){ static RansomwareProtectionManager m; return m; }
    static EmailSecurityManager& email()       { static EmailSecurityManager m; return m; }
    static BehaviorAnalysisManager& behavior() { static BehaviorAnalysisManager m; return m; }
    static ApplicationMonitorManager& appmon() { static ApplicationMonitorManager m; return m; }
    static NetworkTrafficAnalyzerManager& net(){ static NetworkTrafficAnalyzerManager m; return m; }
    static ThreatIntelligenceManager& ti()     { static ThreatIntelligenceManager m; return m; }
    static MobileSecurityManager& mobile()     { static MobileSecurityManager m; return m; }
    static PrivacyProtectionManager& privacy() { static PrivacyProtectionManager m; return m; }
    static SystemMonitorManager& sysmon()      { static SystemMonitorManager m; return m; }
    static StartupManager& startup()           { static StartupManager m; return m; }
    static FileIntegrityManager& integrity()   { static FileIntegrityManager m; return m; }
    static RegistryMonitorManager& regmon()    { static RegistryMonitorManager m; return m; }
    static PopupBlockerManager& popup()        { static PopupBlockerManager m; return m; }
    static SecureBrowserManager& browser()     { static SecureBrowserManager m; return m; }
    static SecurityReportManager& report()     { static SecurityReportManager m; return m; }
    static SecurityScoreManager& score()       { static SecurityScoreManager m; return m; }
    static SecureDeleteManager& shredder()     { static SecureDeleteManager m; return m; }
    static NetworkFirewallManager& netfw()      { static NetworkFirewallManager m; return m; }
    static DNSProtectionManager& dns()         { static DNSProtectionManager m; return m; }
    static SandboxManager& sandbox()           { static SandboxManager m; return m; }
    static UEFIProtectorManager& uefi()        { static UEFIProtectorManager m; return m; }
    static SelfProtectionManager& self()       { static SelfProtectionManager m; return m; }
    static ContextMenuManager& contextmenu()   { static ContextMenuManager m; return m; }
};

} // namespace Modules
} // namespace FireAntivirus
