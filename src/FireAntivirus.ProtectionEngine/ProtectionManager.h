#pragma once

class FileProtection;
class ProcessProtection;
class RegistryProtection;
class ScriptProtection;
class DeviceProtection;
class ActiveDefense;
class DocumentProtection;
class DiskProtection;
class PrivacyProtection;
class ParentalControl;
class WebProtection;
class EmailSecurity;
class PasswordManager;
class SystemOptimization;
class BackupRecovery;
class NetworkFirewall;
class DeviceControl;
class VulnerabilityScan;
class CloudScan;
class SafeBrowser;
class SecurityScore;
class NetworkTraffic;
class ApplicationMonitor;
class StartupManager;
class SecurityReport;
class BehaviorAnalysis;
class MobileSecurity;

class ProtectionManager {
private:
    std::shared_ptr<FileProtection> fileProtection;
    std::shared_ptr<ProcessProtection> processProtection;
    std::shared_ptr<RegistryProtection> registryProtection;
    std::shared_ptr<ScriptProtection> scriptProtection;
    std::shared_ptr<DeviceProtection> deviceProtection;
    std::shared_ptr<ActiveDefense> activeDefense;
    std::shared_ptr<DocumentProtection> documentProtection;
    std::shared_ptr<DiskProtection> diskProtection;
    std::shared_ptr<PrivacyProtection> privacyProtection;
    std::shared_ptr<ParentalControl> parentalControl;
    std::shared_ptr<WebProtection> webProtection;
    std::shared_ptr<EmailSecurity> emailSecurity;
    std::shared_ptr<PasswordManager> passwordManager;
    std::shared_ptr<SystemOptimization> systemOptimization;
    std::shared_ptr<BackupRecovery> backupRecovery;
    std::shared_ptr<NetworkFirewall> networkFirewall;
    std::shared_ptr<DeviceControl> deviceControl;
    std::shared_ptr<VulnerabilityScan> vulnerabilityScan;
    std::shared_ptr<CloudScan> cloudScan;
    std::shared_ptr<SafeBrowser> safeBrowser;
    std::shared_ptr<SecurityScore> securityScore;
    std::shared_ptr<NetworkTraffic> networkTraffic;
    std::shared_ptr<ApplicationMonitor> applicationMonitor;
    std::shared_ptr<StartupManager> startupManager;
    std::shared_ptr<SecurityReport> securityReport;
    std::shared_ptr<BehaviorAnalysis> behaviorAnalysis;
    std::shared_ptr<MobileSecurity> mobileSecurity;
    std::atomic<bool> isInitialized;

public:
    ProtectionManager();
    ~ProtectionManager();

    bool Initialize();
    void Update();
    void Cleanup();

    std::shared_ptr<FileProtection> GetFileProtection();
    std::shared_ptr<ProcessProtection> GetProcessProtection();
    std::shared_ptr<RegistryProtection> GetRegistryProtection();
    std::shared_ptr<ScriptProtection> GetScriptProtection();
    std::shared_ptr<DeviceProtection> GetDeviceProtection();
    std::shared_ptr<ActiveDefense> GetActiveDefense();
    std::shared_ptr<DocumentProtection> GetDocumentProtection();
    std::shared_ptr<DiskProtection> GetDiskProtection();
    std::shared_ptr<PrivacyProtection> GetPrivacyProtection();
    std::shared_ptr<ParentalControl> GetParentalControl();
    std::shared_ptr<WebProtection> GetWebProtection();
    std::shared_ptr<EmailSecurity> GetEmailSecurity();
    std::shared_ptr<PasswordManager> GetPasswordManager();
    std::shared_ptr<SystemOptimization> GetSystemOptimization();
    std::shared_ptr<BackupRecovery> GetBackupRecovery();
    std::shared_ptr<NetworkFirewall> GetNetworkFirewall();
    std::shared_ptr<DeviceControl> GetDeviceControl();
    std::shared_ptr<VulnerabilityScan> GetVulnerabilityScan();
    std::shared_ptr<CloudScan> GetCloudScan();
    std::shared_ptr<SafeBrowser> GetSafeBrowser();
    std::shared_ptr<SecurityScore> GetSecurityScore();
    std::shared_ptr<NetworkTraffic> GetNetworkTraffic();
    std::shared_ptr<ApplicationMonitor> GetApplicationMonitor();
    std::shared_ptr<StartupManager> GetStartupManager();
    std::shared_ptr<SecurityReport> GetSecurityReport();
    std::shared_ptr<BehaviorAnalysis> GetBehaviorAnalysis();
    std::shared_ptr<MobileSecurity> GetMobileSecurity();

    bool IsInitialized() const;
    void SetProtectionEnabled(const std::string& protectionName, bool enabled);
};
