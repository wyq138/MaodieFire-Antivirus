#pragma once

#include "CoreServices.h"
#include "../Platform/Windows.h"
#include "../Engine/AntivirusEngine.h"
#include "../Engine/KernelProtection.h"

#include <atomic>
#include <memory>

namespace FireAntivirus { namespace Services {

// ============ ThreatInfo / ProtectionState ============
struct ThreatInfo {
    std::string Id;
    std::string FilePath;
    std::string ThreatName;
    std::string ThreatType;
    double Confidence = 0.0;
    std::string DetectionTime;
    std::string DetectionMethod;
    std::string ActionTaken;
    std::string AdditionalInfo;
    std::string Severity;
    std::string Description;
};

struct ProtectionState {
    bool IsFileProtectionEnabled = false;
    bool IsProcessProtectionEnabled = false;
    bool IsDeviceProtectionEnabled = false;
    bool IsRegistryProtectionEnabled = false;
    bool IsBrowserProtectionEnabled = false;
    bool IsScriptProtectionEnabled = false;
    bool IsActiveDefenseEnabled = false;
    bool IsRunning = false;
};

enum class ProtectionAction { Quarantine, Delete, Rename, Allow, Block };

// ============ SecurityService ============
class SecurityService {
public:
    std::function<void(const ThreatInfo&)> OnThreatDetected;
    std::function<void(const ProtectionState&)> OnStatusChanged;
    SecurityService();
    ~SecurityService();

    bool Initialize();
    bool Start();
    void Stop();
    bool IsInitialized() const { return _isInitialized; }
    bool IsRunning() const { return _isRunning; }

    // 各防护模块启用/禁用
    bool EnableFileProtection(bool enable);
    bool EnableProcessProtection(bool enable);
    bool EnableDeviceProtection(bool enable);
    bool EnableRegistryProtection(bool enable);
    bool EnableBrowserProtection(bool enable);
    bool EnableScriptProtection(bool enable);
    bool EnableActiveDefense(bool enable);
    bool EnableNetworkProtection(bool enable);
    bool EnablePopupBlocker(bool enable);
    bool EnableRansomwareProtection(bool enable);
    bool EnablePrivacyProtection(bool enable);
    bool EnableWebProtection(bool enable);
    bool EnableEmailSecurity(bool enable);
    bool EnablePasswordManager(bool enable);
    bool EnableNetworkFirewall(bool enable);
    bool EnableVulnerabilityScanner(bool enable);
    bool EnableCloudScan(bool enable);
    bool EnableSecureBrowser(bool enable);
    bool EnableMobileSecurity(bool enable);
    bool EnableSystemOptimizer(bool enable);
    bool EnableBackupRecovery(bool enable);
    bool EnableSecurityScore(bool enable);
    bool EnableNetworkTraffic(bool enable);
    bool EnableApplicationMonitor(bool enable);
    bool EnableStartupManager(bool enable);
    bool EnableSecurityReport(bool enable);
    bool EnableSystemTools(bool enable);
    bool EnableSystemInfo(bool enable);
    bool EnableQuarantine(bool enable);
    bool EnableTrustZone(bool enable);
    bool EnableLogCenter(bool enable);

    bool IsFileProtectionEnabled();
    bool IsProcessProtectionEnabled();
    bool IsDeviceProtectionEnabled();
    bool IsRegistryProtectionEnabled();
    bool IsBrowserProtectionEnabled();
    bool IsScriptProtectionEnabled();
    bool IsActiveDefenseEnabled();
    bool IsNetworkProtectionEnabled();
    bool IsPopupBlockerEnabled();
    bool IsRansomwareProtectionEnabled();
    bool IsPrivacyProtectionEnabled();
    bool IsWebProtectionEnabled();
    bool IsEmailSecurityEnabled();
    bool IsPasswordManagerEnabled();
    bool IsNetworkFirewallEnabled();
    bool IsVulnerabilityScannerEnabled();
    bool IsCloudScanEnabled();
    bool IsSecureBrowserEnabled();
    bool IsMobileSecurityEnabled();
    bool IsSystemOptimizerEnabled();
    bool IsBackupRecoveryEnabled();
    bool IsSecurityScoreEnabled();
    bool IsNetworkTrafficEnabled();
    bool IsApplicationMonitorEnabled();
    bool IsStartupManagerEnabled();
    bool IsSecurityReportEnabled();
    bool IsSystemToolsEnabled();
    bool IsSystemInfoEnabled();
    bool IsQuarantineEnabled();
    bool IsTrustZoneEnabled();
    bool IsLogCenterEnabled();

    ProtectionState GetProtectionStatus();
    void HandleThreat(const ThreatInfo& threat, ProtectionAction action);

private:
    std::atomic<bool> _isInitialized{false};
    std::atomic<bool> _isRunning{false};
    mutable std::mutex _lock;
    ProtectionState _state;
    std::thread _monitoringThread;
    std::atomic<bool> _monitoringRunning{false};
    void MonitoringLoop();
};

// ============ NativeSecurityCoreWrapper ============
class NativeSecurityCoreWrapper {
public:
    static bool InitializeCore();
    static void ShutdownCore();
    static void SetThreatCallback(void(*cb)(const char* filePath, const char* threatName, int severity));
    static void SetStatusCallback(void(*cb)(int isRunning, const char* status));
    static bool IsInitialized();
    static bool ScanBuffer(const uint8_t* data, size_t size, const char* name);

private:
    static bool _initialized;
    static std::mutex _lock;
};

// ============ RealTimeProtectionManager ============
class RealTimeProtectionManager {
public:
    std::function<void(const ThreatInfo&)> ThreatDetected;
    std::function<void(const ProtectionState&)> StatusChanged;
    explicit RealTimeProtectionManager(SecurityService* securityService);
    ~RealTimeProtectionManager();
    bool Initialize();
    bool Start();
    void Stop();
    bool IsInitialized() const { return _isInitialized; }
    bool IsRunning() const { return _isRunning; }
    bool IsCoreAvailable() const { return _isCoreAvailable; }

    bool EnableFileProtection(bool enable);
    bool IsFileProtectionEnabled();
    bool EnableProcessProtection(bool enable);
    bool IsProcessProtectionEnabled();
    bool EnableDeviceProtection(bool enable);
    bool IsDeviceProtectionEnabled();
    bool EnableRegistryProtection(bool enable);
    bool IsRegistryProtectionEnabled();
    bool EnableBrowserProtection(bool enable);
    bool IsBrowserProtectionEnabled();
    bool EnableScriptProtection(bool enable);
    bool IsScriptProtectionEnabled();
    bool EnableActiveDefense(bool enable);
    bool IsActiveDefenseEnabled();
    ProtectionState GetProtectionStatus();
    void HandleThreat(const ThreatInfo& threat, ProtectionAction action);

private:
    SecurityService* _securityService;
    std::atomic<bool> _isInitialized{false};
    std::atomic<bool> _isRunning{false};
    std::atomic<bool> _isCoreAvailable{true};
    std::mutex _lock;
    std::thread _monitoringTask;
    std::atomic<bool> _monitoringRunning{false};
    void MonitoringLoop();
};

// ============ RealTimeProtectionCommunication ============
struct RealTimeThreatDetection {
    std::string Id;
    std::string FilePath;
    std::string ThreatName;
    std::string ThreatType;
    double Confidence = 0.0;
    std::string DetectionTime;
    std::string DetectionMethod;
    std::string ActionTaken;
    std::string AdditionalInfo;
    std::string Severity;
    std::string Description;
};

struct RealTimeProtectionStatus {
    bool IsRunning = false;
    std::string StartTime;
    std::string StopTime;
    std::vector<std::string> ActiveMonitors;
};

struct ScanSettings {
    bool ScanSystemFiles = true;
    bool ScanEmail = true;
    bool ScanArchive = true;
    bool ScanRemovableMedia = true;
    bool ScanNetworkDrives = false;
    int MaxFileSize = 100 * 1024 * 1024;
    std::vector<std::string> ExcludedPaths;
    std::vector<std::string> ExcludedExtensions;
};

struct CommunicationRequest {
    std::string Command;
    std::map<std::string, std::string> Parameters;
};

struct CommunicationResponse {
    bool Success = false;
    std::string Message;
    std::string DataJson;
};

class RealTimeProtectionServer {
public:
    std::function<void(const ThreatDetectedEventArgs&)> ThreatDetected;
    std::function<void(const ProtectionState&)> StatusChanged;

    RealTimeProtectionServer(FireAntivirus::DataManager* dataManager, FireAntivirus::Engine::AntivirusEngine* antivirusEngine);
    ~RealTimeProtectionServer();
    void StartServer();
    void StopServer();
    RealTimeProtectionStatus GetStatus();
    std::vector<RealTimeThreatDetection> GetRecentThreats();
    bool ScanFile(const std::string& filePath);
    bool AddQuarantine(const std::string& filePath);
    bool RemoveQuarantine(const std::string& itemId);
    bool AddWhitelist(const std::string& filePath);
    bool RemoveWhitelist(const std::string& filePath);
    bool UpdateSignatures();
    bool EnableModule(const std::string& moduleName);
    bool DisableModule(const std::string& moduleName);
    std::map<std::string, bool> GetModuleStatus();
    bool SetScanSettings(const ScanSettings& settings);
    ScanSettings GetScanSettings();

private:
    FireAntivirus::DataManager* _dataManager;
    FireAntivirus::Engine::AntivirusEngine* _antivirusEngine;
    std::atomic<bool> _isRunning{false};
    std::thread _serverThread;
    RealTimeProtectionStatus _currentStatus;
    ScanSettings _scanSettings;
    std::map<std::string, IMonitor*> _monitors;
    void ServerLoop();
    CommunicationResponse ProcessRequest(const CommunicationRequest& request);
};

class RealTimeProtectionClient {
public:
    RealTimeProtectionClient() = default;
    ~RealTimeProtectionClient() = default;
    bool StartProtection();
    bool StopProtection();
    RealTimeProtectionStatus GetStatus();
    std::vector<RealTimeThreatDetection> GetRecentThreats();
    bool ScanFile(const std::string& filePath);
    bool AddQuarantine(const std::string& filePath);
    bool RemoveQuarantine(const std::string& itemId);
    bool AddWhitelist(const std::string& filePath);
    bool RemoveWhitelist(const std::string& filePath);
    bool UpdateSignatures();
    bool EnableModule(const std::string& moduleName);
    bool DisableModule(const std::string& moduleName);
    std::map<std::string, bool> GetModuleStatus();
    bool SetScanSettings(const ScanSettings& settings);
    ScanSettings GetScanSettings();
    void Disconnect();
};

// ============ MemoryProtection ============
enum class SuspiciousLevel { Normal = 0, Low = 1, Medium = 2, High = 3, Critical = 4 };

struct MemoryRegion {
    long long BaseAddress = 0;
    uint64_t Size = 0;
    std::string Name;
    bool IsExecutable = false;
    SuspiciousLevel SuspiciousLevelVal = SuspiciousLevel::Normal;
    std::vector<uint8_t> ContentHash;
};

struct ProcessMemoryInfo {
    int ProcessId = 0;
    std::string ProcessName;
    long long WorkingSet = 0;
    long long PrivateMemory = 0;
    long long VirtualMemory = 0;
    std::vector<MemoryRegion> MemoryRegions;
    std::string ScanTime;
};

class MemoryProtection : public IMonitor {
public:
    MemoryProtection(FireAntivirus::DataManager* dataManager, FireAntivirus::Engine::AntivirusEngine* antivirusEngine);
    void Start() override;
    void Stop() override;

private:
    FireAntivirus::DataManager* _dataManager;
    FireAntivirus::Engine::AntivirusEngine* _antivirusEngine;
    std::atomic<bool> _isRunning{false};
    std::thread _monitorThread;
    std::unordered_map<int, ProcessMemoryInfo> _processMemoryCache;
    std::mutex _cacheLock;
    std::vector<std::string> _suspiciousPatterns;

    void MonitorMemory();
    void ScanProcessMemory();
    void DetectCodeInjections();
    void CheckHeapSpraying();
    void DetectROPChains();
    bool IsSuspiciousModule(const std::string& moduleName);
};

// ============ ProcessInjectionProtection ============
enum class SecurityThreatLevel { None, Low, Medium, High, Critical };

class ProcessInjectionProtection : public IMonitor {
public:
    ProcessInjectionProtection(FireAntivirus::DataManager* dataManager, FireAntivirus::Engine::AntivirusEngine* antivirusEngine);
    void Start() override;
    void Stop() override;

private:
    FireAntivirus::DataManager* _dataManager;
    FireAntivirus::Engine::AntivirusEngine* _antivirusEngine;
    std::atomic<bool> _isRunning{false};
    std::thread _monitorThread;
    std::thread _memoryScanThread;
    std::thread _hookDetectionThread;

    // 配置
    int _scanInterval = 3000;
    int _memoryScanInterval = 10000;
    int _hookDetectionInterval = 15000;
    bool _enableDLLInjectionDetection = true;
    bool _enableProcessHollowingDetection = true;
    bool _enableAPCInjectionDetection = true;
    bool _enableThreadHijackingDetection = true;
    bool _enableAutoTermination = false;

    std::set<std::string> _trustedProcesses;
    std::set<std::string> _systemProcesses;
    std::set<std::string> _injectionAPIs;

    void InitializeTrustedProcesses();
    void InitializeInjectionAPIs();
    void MonitorInjection();
    void MemoryScanLoop();
    void HookDetectionLoop();
    void CheckProcessInjection();
    void CheckDLLInjection();
    void CheckProcessHollowing();
    void CheckAPCInjection();
    void CheckThreadHijacking();
};

// ============ SelfProtectionService ============
class SelfProtectionService {
public:
    explicit SelfProtectionService(FireAntivirus::DataManager* dataManager);
    ~SelfProtectionService();
    void Start();
    void Stop();

private:
    FireAntivirus::DataManager* _dataManager;
    std::atomic<bool> _isRunning{false};
    std::thread _protectionThread;
    std::unordered_map<std::string, std::string> _fileHashes;
    std::mutex _hashLock;

    void InitializeFileHashBaseline();
    void ProtectionLoop();
    std::string CalculateFileHash(const std::string& filePath);
    std::vector<std::string> GetCriticalFiles();
    void CheckFileIntegrity();
    void ProtectCriticalFiles();
    void ProtectRegistry();
    void DetectSuspiciousProcesses();
};

// ============ KernelProtectionStatus ============
enum class KernelProtectionStatus { Disabled, Enabled, Error };

// ============ FireAntivirusKernelWrapper ============
class FireAntivirusKernelWrapper {
public:
    static FireAntivirusKernelWrapper& Instance();
    bool IsInitialized() const { return _initialized; }
    bool Enable();
    bool Disable();
    KernelProtectionStatus GetStatus();

private:
    FireAntivirusKernelWrapper() = default;
    static FireAntivirusKernelWrapper* _instance;
    bool _initialized = false;
};

// ============ KernelMonitor ============
class KernelMonitor : public IMonitor {
public:
    KernelMonitor(FireAntivirus::DataManager* dataManager, FireAntivirus::Engine::AntivirusEngine* antivirusEngine);
    void Start() override;
    void Stop() override;

private:
    FireAntivirus::DataManager* _dataManager;
    FireAntivirus::Engine::AntivirusEngine* _antivirusEngine;
    std::atomic<bool> _isRunning{false};
    std::thread _monitorThread;
    std::set<std::string> _trustedDrivers;
    std::unordered_map<std::string, std::string> _driverHashes;
    std::string _backupDirectory;

    void MonitorKernel();
    void InitializeTrustedDrivers();
    void MonitorDriverLoading();
    void MonitorKernelModules();
    void MonitorSystemCalls();
    void BackupKernelConfiguration();
    std::string CalculateFileHash(const std::string& filePath);
};

// ============ ProtectionService ============
class ProtectionService {
public:
    ProtectionService();
    ~ProtectionService();
    void Start();
    void Stop();

    std::vector<std::string> GetInitErrors() const { return _initErrors; }
    int GetMonitorCount() const { return static_cast<int>(_monitors.size()); }

private:
    std::atomic<bool> _isRunning{false};
    std::thread _protectionThread;
    SecurityService* _securityService = nullptr;
    SelfProtectionService* _selfProtectionService = nullptr;
    std::vector<IMonitor*> _monitors;
    std::vector<std::string> _initErrors;

    void InitializeMonitors();
    void SafeAddMonitor(std::function<IMonitor*()> create, const std::string& name);
    void RunProtection();
    void PerformRegularTasks();
    void Log(const std::string& message);
};

// ============ RansomwareProtectionService ============
struct ThreatEvent {
    ThreatType Type = ThreatType::Warning;
    std::string FilePath;
    std::string Reason;
    ThreatSeverity Severity = ThreatSeverity::Medium;
    std::string Timestamp;
};

class RansomwareProtectionService {
public:
    RansomwareProtectionService();
    ~RansomwareProtectionService();
    void EnableProtection();
    void DisableProtection();
    bool IsEnabled() const { return _isEnabled; }
    void AddProtectedFolder(const std::string& folderPath);
    void RemoveProtectedFolder(const std::string& folderPath);
    std::vector<std::string> GetProtectedFolders();
    void BackupFile(const std::string& filePath);
    bool TryRestoreFile(const std::string& originalPath);
    void BlockProcess(const std::string& processName, const std::string& reason);
    void QuarantineFile(const std::string& filePath, const std::string& reason);
    std::vector<ThreatEvent> GetRecentThreats(int count = 50);

    std::function<void(const ThreatEvent&)> OnThreatDetected;

private:
    std::atomic<bool> _isEnabled{false};
    std::vector<std::string> _protectedFolders;
    std::set<std::string> _suspiciousExtensions;
    std::set<std::string> _protectedFileTypes;
    std::string _backupPath;
    std::string _quarantinePath;
    std::string _configPath;
    std::mutex _lock;
    std::thread _monitorThread;
    std::deque<ThreatEvent> _recentThreats;

    void InitializeKnownExtensions();
    void InitializeProtectedFileTypes();
    void AddDefaultProtectedFolders();
    void StartMonitorLoop();
    void StopMonitorLoop();
    void CheckForRansomwareActivity();
    void CheckSuspiciousProcesses();
    void DetectRansomware(const std::string& filePath, const std::string& reason, ThreatSeverity severity);
    void LogThreat(const ThreatEvent& event);
};

}} // namespace FireAntivirus::Services
