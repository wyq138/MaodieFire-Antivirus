#include "pch.h"
#include "ProtectionManager.h"
#include "FileProtection.h"
#include "ProcessProtection.h"
#include "RegistryProtection.h"
#include "ScriptProtection.h"
#include "DeviceProtection.h"
#include "ActiveDefense.h"
#include "DocumentProtection.h"
#include "DiskProtection.h"
#include "PrivacyProtection.h"
#include "ParentalControl.h"
#include "WebProtection.h"
#include "EmailSecurity.h"
#include "PasswordManager.h"
#include "SystemOptimization.h"
#include "BackupRecovery.h"
#include "NetworkFirewall.h"
#include "DeviceControl.h"
#include "VulnerabilityScan.h"
#include "CloudScan.h"
#include "SafeBrowser.h"
#include "SecurityScore.h"
#include "NetworkTraffic.h"
#include "ApplicationMonitor.h"
#include "StartupManager.h"
#include "SecurityReport.h"
#include "BehaviorAnalysis.h"
#include "MobileSecurity.h"

ProtectionManager::ProtectionManager() : isInitialized(false) {
    // Initialize protection modules
    fileProtection = std::make_shared<FileProtection>();
    processProtection = std::make_shared<ProcessProtection>();
    registryProtection = std::make_shared<RegistryProtection>();
    scriptProtection = std::make_shared<ScriptProtection>();
    deviceProtection = std::make_shared<DeviceProtection>();
    activeDefense = std::make_shared<ActiveDefense>();
    documentProtection = std::make_shared<DocumentProtection>();
    diskProtection = std::make_shared<DiskProtection>();
    privacyProtection = std::make_shared<PrivacyProtection>();
    parentalControl = std::make_shared<ParentalControl>();
    webProtection = std::make_shared<WebProtection>();
    emailSecurity = std::make_shared<EmailSecurity>();
    passwordManager = std::make_shared<PasswordManager>();
    systemOptimization = std::make_shared<SystemOptimization>();
    backupRecovery = std::make_shared<BackupRecovery>();
    networkFirewall = std::make_shared<NetworkFirewall>();
    deviceControl = std::make_shared<DeviceControl>();
    vulnerabilityScan = std::make_shared<VulnerabilityScan>();
    cloudScan = std::make_shared<CloudScan>();
    safeBrowser = std::make_shared<SafeBrowser>();
    securityScore = std::make_shared<SecurityScore>();
    networkTraffic = std::make_shared<NetworkTraffic>();
    applicationMonitor = std::make_shared<ApplicationMonitor>();
    startupManager = std::make_shared<StartupManager>();
    securityReport = std::make_shared<SecurityReport>();
    behaviorAnalysis = std::make_shared<BehaviorAnalysis>();
    mobileSecurity = std::make_shared<MobileSecurity>();
}

ProtectionManager::~ProtectionManager() {
    Cleanup();
}

bool ProtectionManager::Initialize() {
    Log(L"Initializing protection modules...");
    
    bool result = true;
    
    // Initialize file protection
    if (!fileProtection->Initialize()) {
        LogError(L"Failed to initialize file protection.");
        result = false;
    }
    
    // Initialize process protection
    if (!processProtection->Initialize()) {
        LogError(L"Failed to initialize process protection.");
        result = false;
    }
    
    // Initialize registry protection
    if (!registryProtection->Initialize()) {
        LogError(L"Failed to initialize registry protection.");
        result = false;
    }
    
    // Initialize script protection
    if (!scriptProtection->Initialize()) {
        LogError(L"Failed to initialize script protection.");
        result = false;
    }
    
    // Initialize device protection
    if (!deviceProtection->Initialize()) {
        LogError(L"Failed to initialize device protection.");
        result = false;
    }
    
    // Initialize active defense
    if (!activeDefense->Initialize()) {
        LogError(L"Failed to initialize active defense.");
        result = false;
    }
    
    // Initialize document protection
    if (!documentProtection->Initialize()) {
        LogError(L"Failed to initialize document protection.");
        result = false;
    }
    
    // Initialize disk protection
    if (!diskProtection->Initialize()) {
        LogError(L"Failed to initialize disk protection.");
        result = false;
    }
    
    // Initialize privacy protection
    if (!privacyProtection->Initialize()) {
        LogError(L"Failed to initialize privacy protection.");
        result = false;
    }
    
    // Initialize parental control
    if (!parentalControl->Initialize()) {
        LogError(L"Failed to initialize parental control.");
        result = false;
    }
    
    // Initialize web protection
    if (!webProtection->Initialize()) {
        LogError(L"Failed to initialize web protection.");
        result = false;
    }
    
    // Initialize email security
    if (!emailSecurity->Initialize()) {
        LogError(L"Failed to initialize email security.");
        result = false;
    }
    
    // Initialize password manager
    if (!passwordManager->Initialize()) {
        LogError(L"Failed to initialize password manager.");
        result = false;
    }
    
    // Initialize system optimization
    if (!systemOptimization->Initialize()) {
        LogError(L"Failed to initialize system optimization.");
        result = false;
    }
    
    // Initialize backup recovery
    if (!backupRecovery->Initialize()) {
        LogError(L"Failed to initialize backup recovery.");
        result = false;
    }
    
    // Initialize network firewall
    if (!networkFirewall->Initialize()) {
        LogError(L"Failed to initialize network firewall.");
        result = false;
    }
    
    // Initialize device control
    if (!deviceControl->Initialize()) {
        LogError(L"Failed to initialize device control.");
        result = false;
    }
    
    // Initialize vulnerability scan
    if (!vulnerabilityScan->Initialize()) {
        LogError(L"Failed to initialize vulnerability scan.");
        result = false;
    }
    
    // Initialize cloud scan
    if (!cloudScan->Initialize()) {
        LogError(L"Failed to initialize cloud scan.");
        result = false;
    }
    
    // Initialize safe browser
    if (!safeBrowser->Initialize()) {
        LogError(L"Failed to initialize safe browser.");
        result = false;
    }
    
    // Initialize security score
    if (!securityScore->Initialize()) {
        LogError(L"Failed to initialize security score.");
        result = false;
    }
    
    // Initialize network traffic
    if (!networkTraffic->Initialize()) {
        LogError(L"Failed to initialize network traffic.");
        result = false;
    }
    
    // Initialize application monitor
    if (!applicationMonitor->Initialize()) {
        LogError(L"Failed to initialize application monitor.");
        result = false;
    }
    
    // Initialize startup manager
    if (!startupManager->Initialize()) {
        LogError(L"Failed to initialize startup manager.");
        result = false;
    }
    
    // Initialize security report
    if (!securityReport->Initialize()) {
        LogError(L"Failed to initialize security report.");
        result = false;
    }
    
    // Initialize behavior analysis
    if (!behaviorAnalysis->Initialize()) {
        LogError(L"Failed to initialize behavior analysis.");
        result = false;
    }
    
    // Initialize mobile security
    if (!mobileSecurity->Initialize()) {
        LogError(L"Failed to initialize mobile security.");
        result = false;
    }
    
    isInitialized = result;
    
    if (result) {
        Log(L"All protection modules initialized successfully.");
    } else {
        LogError(L"Some protection modules failed to initialize.");
    }
    
    return result;
}

void ProtectionManager::Update() {
    if (!isInitialized) {
        return;
    }
    
    // Update file protection
    fileProtection->Update();
    
    // Update process protection
    processProtection->Update();
    
    // Update registry protection
    registryProtection->Update();
    
    // Update script protection
    scriptProtection->Update();
    
    // Update device protection
    deviceProtection->Update();
    
    // Update active defense
    activeDefense->Update();
    
    // Update document protection
    documentProtection->Update();
    
    // Update disk protection
    diskProtection->Update();
    
    // Update privacy protection
    privacyProtection->Update();
    
    // Update parental control
    parentalControl->Update();
    
    // Update web protection
    webProtection->Update();
    
    // Update email security
    emailSecurity->Update();
    
    // Update password manager
    passwordManager->Update();
    
    // Update system optimization
    systemOptimization->Update();
    
    // Update backup recovery
    backupRecovery->Update();
    
    // Update network firewall
    networkFirewall->Update();
    
    // Update device control
    deviceControl->Update();
    
    // Update vulnerability scan
    vulnerabilityScan->Update();
    
    // Update cloud scan
    cloudScan->Update();
    
    // Update safe browser
    safeBrowser->Update();
    
    // Update security score
    securityScore->Update();
    
    // Update network traffic
    networkTraffic->Update();
    
    // Update application monitor
    applicationMonitor->Update();
    
    // Update startup manager
    startupManager->Update();
    
    // Update security report
    securityReport->Update();
    
    // Update behavior analysis
    behaviorAnalysis->Update();
    
    // Update mobile security
    mobileSecurity->Update();
}

void ProtectionManager::Cleanup() {
    Log(L"Cleaning up protection modules...");
    
    // Cleanup disk protection
    if (diskProtection) {
        diskProtection->Cleanup();
    }
    
    // Cleanup document protection
    if (documentProtection) {
        documentProtection->Cleanup();
    }
    
    // Cleanup active defense
    if (activeDefense) {
        activeDefense->Cleanup();
    }
    
    // Cleanup device protection
    if (deviceProtection) {
        deviceProtection->Cleanup();
    }
    
    // Cleanup script protection
    if (scriptProtection) {
        scriptProtection->Cleanup();
    }
    
    // Cleanup registry protection
    if (registryProtection) {
        registryProtection->Cleanup();
    }
    
    // Cleanup process protection
    if (processProtection) {
        processProtection->Cleanup();
    }
    
    // Cleanup file protection
    if (fileProtection) {
        fileProtection->Cleanup();
    }
    
    // Cleanup privacy protection
    if (privacyProtection) {
        privacyProtection->Cleanup();
    }
    
    // Cleanup parental control
    if (parentalControl) {
        parentalControl->Cleanup();
    }
    
    // Cleanup web protection
    if (webProtection) {
        webProtection->Cleanup();
    }
    
    // Cleanup email security
    if (emailSecurity) {
        emailSecurity->Cleanup();
    }
    
    // Cleanup password manager
    if (passwordManager) {
        passwordManager->Cleanup();
    }
    
    // Cleanup system optimization
    if (systemOptimization) {
        systemOptimization->Cleanup();
    }
    
    // Cleanup backup recovery
    if (backupRecovery) {
        backupRecovery->Cleanup();
    }
    
    // Cleanup network firewall
    if (networkFirewall) {
        networkFirewall->Cleanup();
    }
    
    // Cleanup device control
    if (deviceControl) {
        deviceControl->Cleanup();
    }
    
    // Cleanup vulnerability scan
    if (vulnerabilityScan) {
        vulnerabilityScan->Cleanup();
    }
    
    // Cleanup cloud scan
    if (cloudScan) {
        cloudScan->Cleanup();
    }
    
    // Cleanup safe browser
    if (safeBrowser) {
        safeBrowser->Cleanup();
    }
    
    // Cleanup security score
    if (securityScore) {
        securityScore->Cleanup();
    }
    
    // Cleanup network traffic
    if (networkTraffic) {
        networkTraffic->Cleanup();
    }
    
    // Cleanup application monitor
    if (applicationMonitor) {
        applicationMonitor->Cleanup();
    }
    
    // Cleanup startup manager
    if (startupManager) {
        startupManager->Cleanup();
    }
    
    // Cleanup security report
    if (securityReport) {
        securityReport->Cleanup();
    }
    
    // Cleanup behavior analysis
    if (behaviorAnalysis) {
        behaviorAnalysis->Cleanup();
    }
    
    // Cleanup mobile security
    if (mobileSecurity) {
        mobileSecurity->Cleanup();
    }
    
    isInitialized = false;
    
    Log(L"All protection modules cleaned up successfully.");
}

std::shared_ptr<FileProtection> ProtectionManager::GetFileProtection() {
    return fileProtection;
}

std::shared_ptr<ProcessProtection> ProtectionManager::GetProcessProtection() {
    return processProtection;
}

std::shared_ptr<RegistryProtection> ProtectionManager::GetRegistryProtection() {
    return registryProtection;
}

std::shared_ptr<ScriptProtection> ProtectionManager::GetScriptProtection() {
    return scriptProtection;
}

std::shared_ptr<DeviceProtection> ProtectionManager::GetDeviceProtection() {
    return deviceProtection;
}

std::shared_ptr<ActiveDefense> ProtectionManager::GetActiveDefense() {
    return activeDefense;
}

std::shared_ptr<DocumentProtection> ProtectionManager::GetDocumentProtection() {
    return documentProtection;
}

std::shared_ptr<DiskProtection> ProtectionManager::GetDiskProtection() {
    return diskProtection;
}

std::shared_ptr<PrivacyProtection> ProtectionManager::GetPrivacyProtection() {
    return privacyProtection;
}

std::shared_ptr<ParentalControl> ProtectionManager::GetParentalControl() {
    return parentalControl;
}

std::shared_ptr<WebProtection> ProtectionManager::GetWebProtection() {
    return webProtection;
}

std::shared_ptr<EmailSecurity> ProtectionManager::GetEmailSecurity() {
    return emailSecurity;
}

std::shared_ptr<PasswordManager> ProtectionManager::GetPasswordManager() {
    return passwordManager;
}

std::shared_ptr<SystemOptimization> ProtectionManager::GetSystemOptimization() {
    return systemOptimization;
}

std::shared_ptr<BackupRecovery> ProtectionManager::GetBackupRecovery() {
    return backupRecovery;
}

std::shared_ptr<NetworkFirewall> ProtectionManager::GetNetworkFirewall() {
    return networkFirewall;
}

std::shared_ptr<DeviceControl> ProtectionManager::GetDeviceControl() {
    return deviceControl;
}

std::shared_ptr<VulnerabilityScan> ProtectionManager::GetVulnerabilityScan() {
    return vulnerabilityScan;
}

std::shared_ptr<CloudScan> ProtectionManager::GetCloudScan() {
    return cloudScan;
}

std::shared_ptr<SafeBrowser> ProtectionManager::GetSafeBrowser() {
    return safeBrowser;
}

std::shared_ptr<SecurityScore> ProtectionManager::GetSecurityScore() {
    return securityScore;
}

std::shared_ptr<NetworkTraffic> ProtectionManager::GetNetworkTraffic() {
    return networkTraffic;
}

std::shared_ptr<ApplicationMonitor> ProtectionManager::GetApplicationMonitor() {
    return applicationMonitor;
}

std::shared_ptr<StartupManager> ProtectionManager::GetStartupManager() {
    return startupManager;
}

std::shared_ptr<SecurityReport> ProtectionManager::GetSecurityReport() {
    return securityReport;
}

std::shared_ptr<BehaviorAnalysis> ProtectionManager::GetBehaviorAnalysis() {
    return behaviorAnalysis;
}

std::shared_ptr<MobileSecurity> ProtectionManager::GetMobileSecurity() {
    return mobileSecurity;
}

bool ProtectionManager::IsInitialized() const {
    return isInitialized;
}

void ProtectionManager::SetProtectionEnabled(const std::string& protectionName, bool enabled) {
    // 根据防护名称开启或关闭相应的防护功能
    if (protectionName == "FileProtection" && fileProtection) {
        if (enabled) {
            fileProtection->Initialize();
        } else {
            fileProtection->Cleanup();
        }
    } else if (protectionName == "ProcessProtection" && processProtection) {
        if (enabled) {
            processProtection->Initialize();
        } else {
            processProtection->Cleanup();
        }
    } else if (protectionName == "RegistryProtection" && registryProtection) {
        if (enabled) {
            registryProtection->Initialize();
        } else {
            registryProtection->Cleanup();
        }
    } else if (protectionName == "ScriptProtection" && scriptProtection) {
        if (enabled) {
            scriptProtection->Initialize();
        } else {
            scriptProtection->Cleanup();
        }
    } else if (protectionName == "DeviceProtection" && deviceProtection) {
        if (enabled) {
            deviceProtection->Initialize();
        } else {
            deviceProtection->Cleanup();
        }
    } else if (protectionName == "ActiveDefense" && activeDefense) {
        if (enabled) {
            activeDefense->Initialize();
        } else {
            activeDefense->Cleanup();
        }
    } else if (protectionName == "DocumentProtection" && documentProtection) {
        if (enabled) {
            documentProtection->Initialize();
        } else {
            documentProtection->Cleanup();
        }
    } else if (protectionName == "DiskProtection" && diskProtection) {
        if (enabled) {
            diskProtection->Initialize();
        } else {
            diskProtection->Cleanup();
        }
    } else if (protectionName == "PrivacyProtection" && privacyProtection) {
        if (enabled) {
            privacyProtection->Initialize();
        } else {
            privacyProtection->Cleanup();
        }
    } else if (protectionName == "ParentalControl" && parentalControl) {
        if (enabled) {
            parentalControl->Initialize();
        } else {
            parentalControl->Cleanup();
        }
    } else if (protectionName == "WebProtection" && webProtection) {
        if (enabled) {
            webProtection->Initialize();
        } else {
            webProtection->Cleanup();
        }
    } else if (protectionName == "EmailSecurity" && emailSecurity) {
        if (enabled) {
            emailSecurity->Initialize();
        } else {
            emailSecurity->Cleanup();
        }
    } else if (protectionName == "PasswordManager" && passwordManager) {
        if (enabled) {
            passwordManager->Initialize();
        } else {
            passwordManager->Cleanup();
        }
    } else if (protectionName == "SystemOptimization" && systemOptimization) {
        if (enabled) {
            systemOptimization->Initialize();
        } else {
            systemOptimization->Cleanup();
        }
    } else if (protectionName == "BackupRecovery" && backupRecovery) {
        if (enabled) {
            backupRecovery->Initialize();
        } else {
            backupRecovery->Cleanup();
        }
    } else if (protectionName == "NetworkFirewall" && networkFirewall) {
        if (enabled) {
            networkFirewall->Initialize();
        } else {
            networkFirewall->Cleanup();
        }
    } else if (protectionName == "DeviceControl" && deviceControl) {
        if (enabled) {
            deviceControl->Initialize();
        } else {
            deviceControl->Cleanup();
        }
    } else if (protectionName == "VulnerabilityScan" && vulnerabilityScan) {
        if (enabled) {
            vulnerabilityScan->Initialize();
        } else {
            vulnerabilityScan->Cleanup();
        }
    } else if (protectionName == "CloudScan" && cloudScan) {
        if (enabled) {
            cloudScan->Initialize();
        } else {
            cloudScan->Cleanup();
        }
    } else if (protectionName == "SafeBrowser" && safeBrowser) {
        if (enabled) {
            safeBrowser->Initialize();
        } else {
            safeBrowser->Cleanup();
        }
    } else if (protectionName == "SecurityScore" && securityScore) {
        if (enabled) {
            securityScore->Initialize();
        } else {
            securityScore->Cleanup();
        }
    } else if (protectionName == "NetworkTraffic" && networkTraffic) {
        if (enabled) {
            networkTraffic->Initialize();
        } else {
            networkTraffic->Cleanup();
        }
    } else if (protectionName == "ApplicationMonitor" && applicationMonitor) {
        if (enabled) {
            applicationMonitor->Initialize();
        } else {
            applicationMonitor->Cleanup();
        }
    } else if (protectionName == "StartupManager" && startupManager) {
        if (enabled) {
            startupManager->Initialize();
        } else {
            startupManager->Cleanup();
        }
    } else if (protectionName == "SecurityReport" && securityReport) {
        if (enabled) {
            securityReport->Initialize();
        } else {
            securityReport->Cleanup();
        }
    } else if (protectionName == "BehaviorAnalysis" && behaviorAnalysis) {
        if (enabled) {
            behaviorAnalysis->Initialize();
        } else {
            behaviorAnalysis->Cleanup();
        }
    } else if (protectionName == "MobileSecurity" && mobileSecurity) {
        if (enabled) {
            mobileSecurity->Initialize();
        } else {
            mobileSecurity->Cleanup();
        }
    }
}
