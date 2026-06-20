#include "pch.h"
#include "DiskProtection.h"

DiskProtection::DiskProtection() : isInitialized(false), isMonitoring(false) {
}

DiskProtection::~DiskProtection() {
    Cleanup();
}

bool DiskProtection::Initialize() {
    Log(L"Initializing disk protection...");
    
    // Start monitoring thread
    isMonitoring = true;
    monitoringThread = std::thread(&DiskProtection::MonitorDisks, this);
    
    isInitialized = true;
    Log(L"Disk protection initialized successfully.");
    return true;
}

void DiskProtection::Update() {
    // Nothing to do here, monitoring is done in a separate thread
}

void DiskProtection::Cleanup() {
    Log(L"Cleaning up disk protection...");
    
    // Stop monitoring
    isMonitoring = false;
    
    // Wait for monitoring thread to finish
    if (monitoringThread.joinable()) {
        monitoringThread.join();
    }
    
    isInitialized = false;
    Log(L"Disk protection cleaned up successfully.");
}

bool DiskProtection::IsInitialized() const {
    return isInitialized;
}

void DiskProtection::MonitorDisks() {
    Log(L"Disk monitoring started.");
    
    while (isMonitoring) {
        try {
            // Check for physical disk access
            for (int i = 0; i < 16; i++) { // Check first 16 physical disks
                wchar_t diskPath[20];
                swprintf_s(diskPath, 20, L"\\\\.\\PhysicalDrive%d", i);
                
                // Check if the disk is accessible
                HANDLE hDisk = CreateFile(
                    diskPath,
                    GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    NULL,
                    OPEN_EXISTING,
                    0,
                    NULL
                );
                
                if (hDisk != INVALID_HANDLE_VALUE) {
                    // Check for processes accessing this disk
                    // Note: This is a simplified implementation
                    // In a real-world scenario, you would use ETW to monitor disk access
                    
                    // Close the handle
                    CloseHandle(hDisk);
                }
            }
            
            // Sleep for a short time to avoid high CPU usage
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        }
        catch (const std::exception& e) {
            std::string errorMsg = e.what();
            std::wstring wideErrorMsg(errorMsg.begin(), errorMsg.end());
            LogError(L"Disk monitoring exception: " + wideErrorMsg);
        }
    }
    
    Log(L"Disk monitoring stopped.");
}

void DiskProtection::HandleDiskAccess(const std::wstring& diskPath, DWORD accessMode) {
    // Get the process that is accessing the disk
    // Note: This is a simplified implementation
    // In a real-world scenario, you would use ETW to get the process information
    DWORD processId = GetCurrentProcessId();
    
    // Check if the disk access is malicious
    if (IsMaliciousDiskAccess(diskPath, processId, accessMode)) {
        // Report the threat
        ThreatInfo threatInfo;
        threatInfo.type = ThreatType::DISK_MALICIOUS;
        
        // Copy process path
        std::wstring processPathStr = GetProcessPath(processId);
        wcsncpy_s(threatInfo.processPath, processPathStr.c_str(), _TRUNCATE);
        
        // Copy target path
        wcsncpy_s(threatInfo.targetPath, diskPath.c_str(), _TRUNCATE);
        
        // Copy threat description
        wcsncpy_s(threatInfo.threatDescription, L"Malicious disk access detected", _TRUNCATE);
        
        threatInfo.processId = processId;
        threatInfo.threadId = GetCurrentThreadId();
        
        // Send threat to communication manager
        // Note: This would be implemented in the CommunicationManager class
        LogWarning(L"Malicious disk access detected: " + diskPath);
        
        // Terminate the malicious process
        if (TerminateProcessById(processId)) {
            Log(L"Terminated malicious process: " + GetProcessName(processId));
        }
    }
}

bool DiskProtection::IsMaliciousDiskAccess(const std::wstring& diskPath, DWORD processId, DWORD accessMode) {
    // Check if the disk access is for a physical disk
    if (diskPath.find(L"PhysicalDrive") != std::wstring::npos) {
        // Check if the process is trying to write to the disk
        if (accessMode & GENERIC_WRITE) {
            // Check if the process is trusted
            std::wstring processPath = GetProcessPath(processId);
            std::wstring systemDir = GetSystemDirectory();
            std::wstring windowsDir = GetWindowsDirectory();
            
            // Trusted processes are those from system or windows directories
            if (processPath.compare(0, systemDir.length(), systemDir) != 0 &&
                processPath.compare(0, windowsDir.length(), windowsDir) != 0) {
                // Check if the process is a known disk utility
                std::wstring processName = GetProcessName(processId);
                std::transform(processName.begin(), processName.end(), processName.begin(), ::towlower);
                
                std::vector<std::wstring> trustedDiskUtilities = {
                    L"diskpart.exe", L"format.com", L"chkdsk.exe", L"defrag.exe",
                    L"diskmgmt.msc", L"diskgenius.exe", L"partitionwizard.exe"
                };
                
                if (std::find(trustedDiskUtilities.begin(), trustedDiskUtilities.end(), processName) == trustedDiskUtilities.end()) {
                    return true;
                }
            }
        }
    }
    
    return false;
}
