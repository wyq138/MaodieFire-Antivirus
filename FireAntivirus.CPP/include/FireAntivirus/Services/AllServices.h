#pragma once

#include "CoreServices.h"
#include "../Network/HttpClient.h"
#include "../Platform/Windows.h"
#include <unordered_map>

namespace FireAntivirus { namespace Services {

// ============ NetworkSecurity ============
class NetworkSecurity {
public:
    NetworkSecurity(FireAntivirus::DataManager* dataManager, FireAntivirus::Engine::AntivirusEngine* antivirusEngine);
    void Start();
    void Stop();
    void BlockConnection(const std::string& ipAddress, int port);
    void AllowConnection(const std::string& ipAddress, int port);
    bool IsConnectionBlocked(const std::string& ipAddress, int port);

private:
    FireAntivirus::DataManager* _dataManager;
    FireAntivirus::Engine::AntivirusEngine* _antivirusEngine;
    std::atomic<bool> _isRunning{false};
    std::thread _monitorThread;
    std::set<std::string> _blockedConnections; // "ip:port"
    std::mutex _lock;
    void MonitorLoop();
};

// ============ NetworkTrafficAnalyzer ============
class NetworkTrafficAnalyzer {
public:
    NetworkTrafficAnalyzer(FireAntivirus::DataManager* dataManager);
    void Start();
    void Stop();
    std::vector<NetworkConnectionInfo> GetConnections();
    long long GetBytesTotal();
    long long GetBytesSent();
    long long GetBytesReceived();

private:
    FireAntivirus::DataManager* _dataManager;
    std::atomic<bool> _isRunning{false};
    std::thread _analyzerThread;
    std::mutex _connLock;
    std::vector<NetworkConnectionInfo> _connections;
    void AnalyzeLoop();
    void CollectNetworkStats();
};

// ============ NetworkTrafficAnalyzerService ============
class NetworkTrafficAnalyzerService {
public:
    explicit NetworkTrafficAnalyzerService(NetworkTrafficAnalyzer* analyzer) : _analyzer(analyzer) {}
    void Enable(bool enable);
    bool IsEnabled();
private:
    NetworkTrafficAnalyzer* _analyzer;
    bool _enabled = true;
};

// ============ DNSProtection ============
class DNSProtection {
public:
    DNSProtection(FireAntivirus::DataManager* dataManager);
    void Start();
    void Stop();
    void BlockDomain(const std::string& domain);
    void AllowDomain(const std::string& domain);
    bool IsDomainBlocked(const std::string& domain);
    void SetCustomDNS(const std::string& primary, const std::string& secondary);

private:
    FireAntivirus::DataManager* _dataManager;
    std::atomic<bool> _isRunning{false};
    std::thread _monitorThread;
    std::set<std::string> _blockedDomains;
    std::mutex _lock;
    std::string _primaryDNS;
    std::string _secondaryDNS;
    void MonitorLoop();
    void FlushDNSCache();
    void ProtectHostsFile();
};

// ============ ARPProtection ============
class ARPProtection {
public:
    ARPProtection(FireAntivirus::DataManager* dataManager);
    void Start();
    void Stop();
    void BindIPToMAC(const std::string& ip, const std::string& mac);
    std::string GetMACAddress(const std::string& ip);

private:
    FireAntivirus::DataManager* _dataManager;
    std::atomic<bool> _isRunning{false};
    std::thread _monitorThread;
    std::mutex _lock;
    std::unordered_map<std::string, std::string> _ipMacBindings;
    void MonitorLoop();
    void CheckARPSpoofing();
};

// ============ FirewallManager ============
class FirewallManager : public IMonitor {
public:
    FirewallManager(FireAntivirus::DataManager* dataManager, FireAntivirus::Engine::AntivirusEngine* antivirusEngine);
    void Start() override;
    void Stop() override;
    bool BlockPort(int port, const std::string& protocol = "TCP");
    bool AllowPort(int port, const std::string& protocol = "TCP");
    bool BlockApp(const std::string& appPath);
    bool AllowApp(const std::string& appPath);

private:
    FireAntivirus::DataManager* _dataManager;
    FireAntivirus::Engine::AntivirusEngine* _antivirusEngine;
    std::atomic<bool> _isRunning{false};
    std::thread _monitorThread;
    void MonitorLoop();
    bool AddFirewallRule(const std::string& name, const std::string& direction, const std::string& action,
                        const std::string& protocol, const std::string& localPort = "",
                        const std::string& remotePort = "", const std::string& program = "");
};

// ============ BehaviorAnalysis / BehaviorAnalysisService / MachineLearning ============
struct BehaviorFeature {
    std::string Name;
    double Value = 0.0;
    std::string Category;
};

struct BehaviorAnalysisResult {
    std::string FilePath;
    std::string ProcessName;
    RiskLevel Risk = RiskLevel::Safe;
    double Score = 0.0;
    std::string Reason;
    std::vector<BehaviorFeature> Features;
};

class MachineLearning {
public:
    MachineLearning();
    bool TrainModel(const std::vector<BehaviorAnalysisResult>& trainingData);
    RiskLevel Predict(const std::vector<BehaviorFeature>& features);
    void SaveModel(const std::string& path);
    void LoadModel(const std::string& path);

private:
    std::unordered_map<std::string, double> _weights;
    bool _trained = false;
    double _bias = 0.0;
};

class BehaviorAnalysis {
public:
    explicit BehaviorAnalysis(FireAntivirus::DataManager* dataManager);
    BehaviorAnalysisResult AnalyzeFile(const std::string& filePath);
    BehaviorAnalysisResult AnalyzeProcess(const std::string& processName, int pid);
    std::vector<BehaviorFeature> ExtractFeatures(const std::string& targetPath);

private:
    FireAntivirus::DataManager* _dataManager;
    MachineLearning _ml;
};

class BehaviorAnalysisService : public IMonitor {
public:
    explicit BehaviorAnalysisService(FireAntivirus::DataManager* dataManager);
    void Start() override;
    void Stop() override;

private:
    FireAntivirus::DataManager* _dataManager;
    std::atomic<bool> _isRunning{false};
    std::thread _analysisThread;
    std::mutex _lock;
    void AnalysisLoop();
};

// ============ Web / AntiPhishing / Popup / SecureBrowser / ContextMenu ============
class AntiPhishing {
public:
    explicit AntiPhishing(FireAntivirus::DataManager* dataManager);
    void Start();
    void Stop();
    bool CheckURL(const std::string& url);
    void AddBlockedURL(const std::string& url);

private:
    FireAntivirus::DataManager* _dataManager;
    std::atomic<bool> _isRunning{false};
    std::thread _monitorThread;
    std::set<std::string> _blockedURLs;
    std::mutex _lock;
    void MonitorLoop();
    bool IsPhishingURL(const std::string& url);
};

class WebProtection {
public:
    WebProtection(FireAntivirus::DataManager* dataManager, FireAntivirus::Engine::AntivirusEngine* antivirusEngine);
    void Start();
    void Stop();
    bool ScanURL(const std::string& url);
    bool ScanPageContent(const std::string& content);

private:
    FireAntivirus::DataManager* _dataManager;
    FireAntivirus::Engine::AntivirusEngine* _antivirusEngine;
    std::atomic<bool> _isRunning{false};
    std::thread _monitorThread;
    void MonitorLoop();
};

class PopupBlocker {
public:
    PopupBlocker(FireAntivirus::DataManager* dataManager);
    void Start();
    void Stop();
    bool IsPopupBlocked(const std::string& windowTitle);
    void AddBlockedPopup(const std::string& titlePattern);

private:
    FireAntivirus::DataManager* _dataManager;
    std::atomic<bool> _isRunning{false};
    std::thread _monitorThread;
    std::vector<std::string> _blockedPatterns;
    std::mutex _lock;
    void MonitorLoop();
};

class SecureBrowserService {
public:
    explicit SecureBrowserService(FireAntivirus::DataManager* dataManager);
    void Start();
    void Stop();
    bool LaunchSecureBrowser(const std::string& url);

private:
    FireAntivirus::DataManager* _dataManager;
    std::atomic<bool> _isRunning{false};
    void SecureBrowse(const std::string& url);
};

class ContextMenuManager {
public:
    ContextMenuManager();
    void InstallContextMenu();
    void UninstallContextMenu();
    bool IsInstalled();

private:
    void RegisterContextMenuHandler(const std::string& extension, const std::string& handlerName, const std::string& command);
};

// ============ Application / Software / Whitelist ============
struct ApplicationInfo {
    std::string Name;
    std::string Path;
    std::string Publisher;
    std::string Version;
    bool IsSigned = false;
    RiskLevel Risk = RiskLevel::Safe;
};

class ApplicationMonitor {
public:
    explicit ApplicationMonitor(FireAntivirus::DataManager* dataManager);
    void Start();
    void Stop();
    std::vector<ApplicationInfo> GetRunningApplications();
    bool IsApplicationTrusted(const std::string& path);

private:
    FireAntivirus::DataManager* _dataManager;
    std::atomic<bool> _isRunning{false};
    std::thread _monitorThread;
    std::mutex _lock;
    std::vector<ApplicationInfo> _apps;
    void MonitorLoop();
    void CollectApplications();
};

class ApplicationControl {
public:
    ApplicationControl(FireAntivirus::DataManager* dataManager);
    void Start();
    void Stop();
    void BlockApplication(const std::string& path);
    void AllowApplication(const std::string& path);
    bool IsBlocked(const std::string& path);

private:
    FireAntivirus::DataManager* _dataManager;
    std::set<std::string> _blockedApps;
    std::mutex _lock;
};

class ApplicationWhitelist {
public:
    explicit ApplicationWhitelist(FireAntivirus::DataManager* dataManager);
    void AddToWhitelist(const std::string& path);
    void RemoveFromWhitelist(const std::string& path);
    bool IsWhitelisted(const std::string& path);
    std::vector<std::string> GetWhitelist();

private:
    FireAntivirus::DataManager* _dataManager;
    std::set<std::string> _whitelist;
    std::mutex _lock;
};

class SoftwareManager {
public:
    SoftwareManager();
    std::vector<ApplicationInfo> GetInstalledSoftware();
    bool UninstallSoftware(const std::string& name);
    std::string GetInstalledSoftwareHash();
};

// ============ Backup ============
struct BackupResult {
    bool Success = false;
    std::string ErrorMessage;
    std::string BackupPath;
    long long BackupSize = 0;
    std::string Timestamp;
};

struct RestoreResult {
    bool Success = false;
    std::string ErrorMessage;
    int RestoredItems = 0;
    std::string Timestamp;
};

class BackupManager {
public:
    explicit BackupManager(const std::string& backupStoragePath = "");
    BackupResult CreateBackup(const BackupOptions& options);
    RestoreResult RestoreBackup(const std::string& backupPath, const std::vector<std::string>& items);
    bool DeleteBackup(const std::string& backupPath);
    std::vector<std::string> GetBackupList();
    bool ValidateBackup(const std::string& backupPath);
    void SetEncryptionPassword(const std::string& password);

    std::function<void(const std::string&, int)> OnProgress;

private:
    std::string _storagePath;
    bool _enabled = true;
    std::string _encryptionPassword;
    std::mutex _lock;
    void InitializeBackupStorage();
    void CreateDirectoryIfNotExists(const std::string& path);
    void CopyFileCompressed(const std::string& src, const std::string& dst);
};

class BackupService {
public:
    explicit BackupService(FireAntivirus::DataManager* dataManager);
    void Start();
    void Stop();
    BackupResult QuickBackup();
    RestoreResult QuickRestore();

private:
    FireAntivirus::DataManager* _dataManager;
    std::atomic<bool> _isRunning{false};
    std::thread _backupThread;
    BackupManager* _backupManager = nullptr;
};

class BackupRestore {
public:
    explicit BackupRestore(FireAntivirus::DataManager* dataManager);
    RestoreResult Restore(const std::string& backupFile, const std::vector<std::string>& components);
    bool VerifyBackupIntegrity(const std::string& backupFile);

private:
    FireAntivirus::DataManager* _dataManager;
};

// ============ UnifiedScan / Update / VirusDB / Signature / Cloud ============
class UnifiedScanService {
public:
    UnifiedScanService(FireAntivirus::DataManager* dataManager, FireAntivirus::Engine::AntivirusEngine* engine);
    ScanResult QuickScan();
    ScanResult FullScan();
    ScanResult CustomScan(const std::vector<std::string>& paths);
    ScanResult CriticalScan();

    long long GetScanProgress();
    void CancelScan();
    bool IsScanning() const { return _isScanning.load(); }

private:
    FireAntivirus::DataManager* _dataManager;
    FireAntivirus::Engine::AntivirusEngine* _engine;
    std::atomic<bool> _isScanning{false};
    std::atomic<bool> _cancelRequested{false};
    std::atomic<long long> _progress{0};
    std::thread _scanThread;
    ScanResult ScanInternal(const std::vector<std::string>& paths);
};

class DefenderScanService {
public:
    explicit DefenderScanService(FireAntivirus::Engine::AntivirusEngine* engine);
    ScanResult ScanWithDefender(const std::string& path);
    bool IsDefenderAvailable();

private:
    FireAntivirus::Engine::AntivirusEngine* _engine;
};

class ClamAVEngine {
public:
    ClamAVEngine(FireAntivirus::DataManager* dataManager, FireAntivirus::Engine::AntivirusEngine* engine);
    bool IsAvailable() const { return _isAvailable; }
    bool Initialize();
    ScanResult ScanFile(const std::string& filePath);
    ScanResult ScanDirectory(const std::string& dirPath);
    bool UpdateDatabase();
    std::string GetDatabasePath() const { return _virusDatabasePath; }

private:
    FireAntivirus::DataManager* _dataManager;
    FireAntivirus::Engine::AntivirusEngine* _antivirusEngine;
    std::string _clamAVPath;
    std::string _virusDatabasePath;
    std::string _clamscanPath;
    bool _isAvailable = false;
    bool _isInitialized = false;
    void InitializePaths();
    std::string ExecuteCommand(const std::string& command);
};

class CloudScannerService {
public:
    CloudScannerService(FireAntivirus::DataManager* dataManager, FireAntivirus::Engine::AntivirusEngine* engine);
    bool IsCloudAvailable();
    ThreatSeverity CloudScanFile(const std::string& filePath);
    ThreatSeverity CloudScanHash(const std::string& fileHash);
    std::string GetReputation(const std::string& fileHash);

private:
    FireAntivirus::DataManager* _dataManager;
    FireAntivirus::Engine::AntivirusEngine* _engine;
    bool _isEnabled = true;
    std::string _cloudEndpoint = "https://api.fireantivirus.example.com";
};

class CloudSecurityService {
public:
    CloudSecurityService(FireAntivirus::DataManager* dataManager);
    void Start();
    void Stop();
    std::string GetThreatIntelligence(const std::string& indicator);
    bool SubmitForAnalysis(const std::string& filePath);

private:
    FireAntivirus::DataManager* _dataManager;
    std::atomic<bool> _isRunning{false};
};

class CloudSecurity {
public:
    explicit CloudSecurity(FireAntivirus::DataManager* dataManager);
    void UploadSample(const std::string& filePath);
    std::string GetScanResult(const std::string& sampleId);
};

class VirusDatabaseManager {
public:
    VirusDatabaseManager(FireAntivirus::DataManager* dataManager);
    bool UpdateDatabase();
    bool IsUpToDate();
    std::string GetDatabaseVersion();
    std::string GetLastUpdateTime();
    void ScheduleAutoUpdate(int hours = 6);

private:
    FireAntivirus::DataManager* _dataManager;
    std::atomic<bool> _isRunning{false};
    std::thread _updateThread;
    void UpdateLoop(int intervalHours);
};

class SignatureVerifier {
public:
    SignatureInfo VerifySignature(const std::string& filePath);
    bool IsTrustedSigner(const std::string& publisher);
};

class UpdateService {
public:
    UpdateService(FireAntivirus::DataManager* dataManager);
    bool CheckForUpdates();
    bool DownloadUpdate(const std::string& version);
    bool InstallUpdate();
    std::string GetCurrentVersion();
    std::string GetAvailableVersion();

private:
    FireAntivirus::DataManager* _dataManager;
    bool _downloading{false};
};

// ============ SecurityReport / SecurityScore / JunkCleaner / FileShredder / SystemRepair / Hardener / Optimizer ============
class SecurityReportService {
public:
    explicit SecurityReportService(FireAntivirus::DataManager* dataManager);
    std::string GenerateDailyReport();
    std::string GenerateWeeklyReport();
    std::string GenerateMonthlyReport();
    std::string GenerateReport(const std::string& fromDate, const std::string& toDate);
    bool ExportReport(const std::string& reportJson, const std::string& outputPath);

private:
    FireAntivirus::DataManager* _dataManager;
};

class SecurityScoreService {
public:
    explicit SecurityScoreService(FireAntivirus::DataManager* dataManager);
    int CalculateSecurityScore();
    std::vector<OptimizationRecommendation> GetImprovementSuggestions();

private:
    FireAntivirus::DataManager* _dataManager;
};

class JunkCleaner {
public:
    explicit JunkCleaner(FireAntivirus::DataManager* dataManager);
    std::vector<std::string> ScanJunkFiles();
    long long EstimatedCleanSize();
    int CleanJunk(const std::vector<std::string>& files);

private:
    FireAntivirus::DataManager* _dataManager;
    std::vector<std::string> _junkPatterns;
    void InitializeJunkPatterns();
};

class FileShredder {
public:
    bool ShredFile(const std::string& filePath, int passes = 3);
    bool ShredFiles(const std::vector<std::string>& filePaths, int passes = 3);
    bool ShredFolder(const std::string& folderPath, int passes = 3);

private:
    bool OverwriteFile(const std::string& filePath, int passes);
};

class SystemRepair {
public:
    explicit SystemRepair(FireAntivirus::DataManager* dataManager);
    std::vector<std::string> ScanSystemIssues();
    bool RepairIssue(const std::string& issueId);
    bool RepairAll();

private:
    FireAntivirus::DataManager* _dataManager;
};

class SystemHardener {
public:
    SystemHardener();
    std::vector<std::string> ScanHardeningStatus();
    bool ApplyHardening(const std::string& itemName);
    bool ApplyAll();

private:
    std::vector<std::string> _hardeningItems;
    void InitializeHardeningItems();
};

class PerformanceOptimizer {
public:
    explicit PerformanceOptimizer(FireAntivirus::DataManager* dataManager);
    long long OptimizeStartupTime();
    long long OptimizeMemoryUsage();
    long long OptimizeDiskPerformance();
};

class SystemOptimizer {
public:
    SystemOptimizer();
    std::vector<std::string> Analyze();
    bool ApplyOptimization(const std::string& id);
    bool CreateSystemRestorePoint(const std::string& name);
};

class SystemOptimizerService {
public:
    explicit SystemOptimizerService(SystemOptimizer* optimizer);
    void Enable(bool enable);
    bool IsEnabled();
private:
    SystemOptimizer* _optimizer;
    bool _enabled = true;
};

// ============ StartupManager ============
struct StartupItem {
    std::string Name;
    std::string Path;
    std::string CommandLine;
    std::string Location;
    bool IsEnabled = true;
    bool IsDigitalSigned = false;
    std::string Publisher;
    StartupImpact Impact = StartupImpact::Unknown;
};

class StartupManager {
public:
    explicit StartupManager(FireAntivirus::DataManager* dataManager);
    std::vector<StartupItem> GetStartupItems();
    bool DisableItem(const std::string& path);
    bool EnableItem(const std::string& path);
    bool DeleteItem(const std::string& path);
    bool AddItem(const StartupItem& item);

private:
    FireAntivirus::DataManager* _dataManager;
    std::vector<StartupItem> ScanRegistryRunKeys();
    std::vector<StartupItem> ScanStartupFolders();
    std::vector<StartupItem> ScanScheduledTasks();
    std::vector<StartupItem> ScanServices();
};

// ============ Sandbox / Device / Mobile ============
class SandboxManager : public IMonitor {
public:
    explicit SandboxManager(FireAntivirus::DataManager* dataManager);
    void Start() override;
    void Stop() override;
    bool RunInSandbox(const std::string& exePath, const std::string& args = "");
    bool IsEnabled() const { return _isRunning.load(); }

private:
    FireAntivirus::DataManager* _dataManager;
    std::atomic<bool> _isRunning{false};
    std::thread _monitorThread;
    std::mutex _lock;
    void MonitorLoop();
};

class DeviceControlService {
public:
    explicit DeviceControlService(FireAntivirus::DataManager* dataManager);
    void Start();
    void Stop();
    void BlockDevice(const std::string& deviceId);
    void AllowDevice(const std::string& deviceId);
    bool IsDeviceBlocked(const std::string& deviceId);

private:
    FireAntivirus::DataManager* _dataManager;
    std::set<std::string> _blockedDevices;
    std::mutex _lock;
    std::atomic<bool> _isRunning{false};
};

class MobileSecurityService {
public:
    MobileSecurityService(FireAntivirus::DataManager* dataManager);
    void Start();
    void Stop();
    bool PairDevice(const std::string& deviceCode);
    std::vector<DeviceInfo> GetPairedDevices();

private:
    FireAntivirus::DataManager* _dataManager;
    std::atomic<bool> _isRunning{false};
    std::vector<DeviceInfo> _pairedDevices;
};

// ============ Privacy Services ============
class PasswordManager {
public:
    PasswordManager(FireAntivirus::DataManager* dataManager);
    bool AddPassword(const std::string& site, const std::string& username, const std::string& password);
    std::string GetPassword(const std::string& site, const std::string& username);
    bool RemovePassword(const std::string& site, const std::string& username);
    std::vector<std::string> GetSites();
    bool IsEnabled() const { return _enabled; }
    void SetEnabled(bool e) { _enabled = e; }

private:
    FireAntivirus::DataManager* _dataManager;
    bool _enabled = true;
    std::mutex _lock;
    std::string Encrypt(const std::string& data, const std::string& key);
    std::string Decrypt(const std::string& data, const std::string& key);
    std::string MasterPassword;
};

class DataLeakageProtection {
public:
    DataLeakageProtection(FireAntivirus::DataManager* dataManager);
    void Start();
    void Stop();
    bool BlockDataTransfer(const std::string& destination);
    bool IsRunning() const { return _isRunning.load(); }

private:
    FireAntivirus::DataManager* _dataManager;
    std::atomic<bool> _isRunning{false};
    std::thread _monitorThread;
    std::mutex _lock;
    void MonitorLoop();
};

class EmailSecurity {
public:
    EmailSecurity(FireAntivirus::DataManager* dataManager, FireAntivirus::Engine::AntivirusEngine* engine);
    void Start();
    void Stop();
    bool ScanEmailAttachment(const std::string& filePath);
    bool IsRunning() const { return _isRunning.load(); }

private:
    FireAntivirus::DataManager* _dataManager;
    FireAntivirus::Engine::AntivirusEngine* _engine;
    std::atomic<bool> _isRunning{false};
};

class ParentalControl {
public:
    explicit ParentalControl(FireAntivirus::DataManager* dataManager);
    void Start();
    void Stop();
    void AddBlockedSite(const std::string& domain);
    void SetTimeLimit(const std::string& username, int minutesPerDay);
    bool IsSiteBlocked(const std::string& domain);

private:
    FireAntivirus::DataManager* _dataManager;
    std::atomic<bool> _isRunning{false};
    std::set<std::string> _blockedSites;
    std::mutex _lock;
    std::thread _monitorThread;
    void MonitorLoop();
};

// ============ Vulnerability ============
class VulnerabilityManager {
public:
    VulnerabilityManager(FireAntivirus::DataManager* dataManager);
    bool LoadVulnerabilityDatabase();
    std::vector<VulnerabilityInfo> GetAllVulnerabilities();
    std::vector<VulnerabilityInfo> GetBySeverity(const std::string& severity);

private:
    FireAntivirus::DataManager* _dataManager;
    std::vector<VulnerabilityInfo> _vulnerabilities;
    std::mutex _lock;
};

class VulnerabilityScanner {
public:
    explicit VulnerabilityScanner(FireAntivirus::DataManager* dataManager);
    std::vector<VulnerabilityInfo> Scan();
    std::vector<VulnerabilityInfo> ScanSoftware();
    std::vector<VulnerabilityInfo> ScanOS();
    std::vector<VulnerabilityInfo> ScanNetwork();

private:
    FireAntivirus::DataManager* _dataManager;
};

class VulnerabilityScannerService {
public:
    explicit VulnerabilityScannerService(FireAntivirus::DataManager* dataManager);
    void Start();
    void Stop();
    void ScheduleDailyScan(int hour = 3);

private:
    FireAntivirus::DataManager* _dataManager;
    std::atomic<bool> _isRunning{false};
    std::thread _scanThread;
    void ScanLoop();
};

// ============ IPC / NamedPipeServer ============
struct MessageReceivedEventArgs {
    std::string ClientId;
    std::string Message;
};

struct ClientConnectedEventArgs {
    std::string ClientId;
};

struct ClientDisconnectedEventArgs {
    std::string ClientId;
};

class NamedPipeServer {
public:
    NamedPipeServer(const std::string& pipeName);
    ~NamedPipeServer();
    void Start();
    void Stop();
    bool IsRunning() const { return _isRunning.load(); }
    void SendToClient(const std::string& clientId, const std::string& message);
    void Broadcast(const std::string& message);

    std::function<void(const MessageReceivedEventArgs&)> OnMessageReceived;
    std::function<void(const ClientConnectedEventArgs&)> OnClientConnected;
    std::function<void(const ClientDisconnectedEventArgs&)> OnClientDisconnected;

private:
    std::string _pipeName;
    std::atomic<bool> _isRunning{false};
    std::thread _listenerThread;
    std::mutex _lock;
    std::set<std::string> _clients;
    void ListenLoop();
};

}} // namespace FireAntivirus::Services
