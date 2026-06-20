#include "pch.h"
#include "RegistryProtection.h"

RegistryProtection::RegistryProtection() : isInitialized(false), isMonitoring(false) {
}

RegistryProtection::~RegistryProtection() {
    Cleanup();
}

bool RegistryProtection::Initialize() {
    Log(L"Initializing registry protection...");
    
    // Start monitoring thread
    isMonitoring = true;
    monitoringThread = std::thread(&RegistryProtection::MonitorRegistry, this);
    
    isInitialized = true;
    Log(L"Registry protection initialized successfully.");
    return true;
}

void RegistryProtection::Update() {
    // Nothing to do here, monitoring is done in a separate thread
}

void RegistryProtection::Cleanup() {
    Log(L"Cleaning up registry protection...");
    
    // Stop monitoring
    isMonitoring = false;
    
    // Wait for monitoring thread to finish
    if (monitoringThread.joinable()) {
        monitoringThread.join();
    }
    
    // Close handles
    if (hRegistryNotify != NULL) {
        CloseHandle(hRegistryNotify);
        hRegistryNotify = NULL;
    }
    
    isInitialized = false;
    Log(L"Registry protection cleaned up successfully.");
}

bool RegistryProtection::IsInitialized() const {
    return isInitialized;
}

void RegistryProtection::MonitorRegistry() {
    Log(L"Registry monitoring started.");
    
    while (isMonitoring) {
        try {
            // Monitor important registry keys
            std::vector<std::wstring> importantKeys = {
                L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
                L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows"
            };
            
            for (const auto& keyPath : importantKeys) {
                HKEY hKey;
                if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, keyPath.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                    // Check for changes
                    // Note: This is a simplified implementation
                    // In a real-world scenario, you would use RegNotifyChangeKeyValue
                    RegCloseKey(hKey);
                }
            }
            
            // Sleep for a short time to avoid high CPU usage
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        }
        catch (const std::exception& e) {
            std::string errorMsg = e.what();
            std::wstring wideErrorMsg(errorMsg.begin(), errorMsg.end());
            LogError(L"Registry monitoring exception: " + wideErrorMsg);
        }
    }
    
    Log(L"Registry monitoring stopped.");
}

void RegistryProtection::HandleRegistryChange(const std::wstring& keyPath, DWORD action) {
    // Get the process that caused the registry change
    // Note: This is a simplified implementation
    // In a real-world scenario, you would use ETW to get the process information
    DWORD processId = GetCurrentProcessId();
    
    // Check if the registry change is malicious
    if (IsMaliciousRegistryChange(keyPath, processId)) {
        // Report the threat
        ThreatInfo threatInfo;
        threatInfo.type = ThreatType::REGISTRY_MALICIOUS;
        
        // Copy process path
        std::wstring processPathStr = GetProcessPath(processId);
        wcsncpy_s(threatInfo.processPath, processPathStr.c_str(), _TRUNCATE);
        
        // Copy target path
        wcsncpy_s(threatInfo.targetPath, keyPath.c_str(), _TRUNCATE);
        
        // Copy threat description
        wcsncpy_s(threatInfo.threatDescription, L"Malicious registry change detected", _TRUNCATE);
        
        threatInfo.processId = processId;
        threatInfo.threadId = GetCurrentThreadId();
        
        // Send threat to communication manager
        // Note: This would be implemented in the CommunicationManager class
        LogWarning(L"Malicious registry change detected: " + keyPath);
    }
}

bool RegistryProtection::IsMaliciousRegistryChange(const std::wstring& keyPath, DWORD processId) {
    // Check if the registry key is in a sensitive location
    std::vector<std::wstring> sensitiveKeys = {
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows"
    };
    
    if (std::find(sensitiveKeys.begin(), sensitiveKeys.end(), keyPath) != sensitiveKeys.end()) {
        // Check if the process is trusted
        std::wstring processPath = GetProcessPath(processId);
        std::wstring systemDir = GetSystemDirectory();
        std::wstring windowsDir = GetWindowsDirectory();
        
        if (processPath.compare(0, systemDir.length(), systemDir) != 0 &&
            processPath.compare(0, windowsDir.length(), windowsDir) != 0) {
            return true;
        }
    }
    
    return false;
}
