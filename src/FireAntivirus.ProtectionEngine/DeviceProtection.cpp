#include "pch.h"
#include "DeviceProtection.h"

DeviceProtection::DeviceProtection() : isInitialized(false), isMonitoring(false), hMessageWindow(NULL) {
}

DeviceProtection::~DeviceProtection() {
    Cleanup();
}

bool DeviceProtection::Initialize() {
    Log(L"Initializing device protection...");
    
    // Start monitoring thread
    isMonitoring = true;
    monitoringThread = std::thread(&DeviceProtection::MonitorDevices, this);
    
    isInitialized = true;
    Log(L"Device protection initialized successfully.");
    return true;
}

void DeviceProtection::Update() {
    // Nothing to do here, monitoring is done in a separate thread
}

void DeviceProtection::Cleanup() {
    Log(L"Cleaning up device protection...");
    
    // Stop monitoring
    isMonitoring = false;
    
    // Wait for monitoring thread to finish
    if (monitoringThread.joinable()) {
        monitoringThread.join();
    }
    
    // Destroy message window
    if (hMessageWindow != NULL) {
        DestroyWindow(hMessageWindow);
        hMessageWindow = NULL;
    }
    
    isInitialized = false;
    Log(L"Device protection cleaned up successfully.");
}

bool DeviceProtection::IsInitialized() const {
    return isInitialized;
}

void DeviceProtection::MonitorDevices() {
    Log(L"Device monitoring started.");
    
    while (isMonitoring) {
        try {
            // Enumerate all disk drives
            wchar_t driveLetters[] = L"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            for (size_t i = 0; i < wcslen(driveLetters); i++) {
                wchar_t drivePath[4];
                swprintf_s(drivePath, 4, L"%c:\\", driveLetters[i]);
                
                // Check if the drive is a removable storage device
                UINT driveType = GetDriveType(drivePath);
                if (driveType == DRIVE_REMOVABLE) {
                    // Get device information
                    wchar_t volumeName[MAX_PATH];
                    wchar_t fileSystemName[MAX_PATH];
                    DWORD serialNumber = 0;
                    DWORD maxComponentLength = 0;
                    DWORD fileSystemFlags = 0;
                    
                    if (GetVolumeInformation(drivePath, volumeName, MAX_PATH, &serialNumber, &maxComponentLength, &fileSystemFlags, fileSystemName, MAX_PATH)) {
                        // Check if the device is malicious
                        if (IsMaliciousDevice(drivePath, volumeName)) {
                            // Report the threat
                            ThreatInfo threatInfo;
                            threatInfo.type = ThreatType::DEVICE_MALICIOUS;
                            
                            // Copy process path
                            std::wstring processPathStr = GetProcessPath(GetCurrentProcessId());
                            wcsncpy_s(threatInfo.processPath, processPathStr.c_str(), _TRUNCATE);
                            
                            // Copy target path
                            wcsncpy_s(threatInfo.targetPath, drivePath, _TRUNCATE);
                            
                            // Copy threat description
                            wcsncpy_s(threatInfo.threatDescription, L"Malicious removable device detected", _TRUNCATE);
                            
                            threatInfo.processId = GetCurrentProcessId();
                            threatInfo.threadId = GetCurrentThreadId();
                            
                            // Send threat to communication manager
                            // Note: This would be implemented in the CommunicationManager class
                            LogWarning(L"Malicious removable device detected: " + std::wstring(drivePath));
                        } else {
                            // Scan the device for malicious files
                            ScanDevice(drivePath);
                        }
                    }
                }
            }
            
            // Sleep for a short time to avoid high CPU usage
            std::this_thread::sleep_for(std::chrono::milliseconds(5000));
        }
        catch (const std::exception& e) {
            std::string errorMsg = e.what();
            std::wstring wideErrorMsg(errorMsg.begin(), errorMsg.end());
            LogError(L"Device monitoring exception: " + wideErrorMsg);
        }
    }
    
    Log(L"Device monitoring stopped.");
}

void DeviceProtection::HandleDeviceChange(UINT uMsg, WPARAM wParam, LPARAM lParam) {
    if (uMsg == WM_DEVICECHANGE) {
        switch (wParam) {
            case DBT_DEVICEARRIVAL:
            {
                PDEV_BROADCAST_HDR lpdb = (PDEV_BROADCAST_HDR)lParam;
                if (lpdb->dbch_devicetype == DBT_DEVTYP_VOLUME) {
                    PDEV_BROADCAST_VOLUME lpdbv = (PDEV_BROADCAST_VOLUME)lpdb;
                    // Get drive letter
                    wchar_t driveLetter = 0;
                    for (int i = 0; i < 26; i++) {
                        if (lpdbv->dbcv_unitmask & (1 << i)) {
                            driveLetter = 'A' + i;
                            break;
                        }
                    }
                    
                    if (driveLetter) {
                        wchar_t drivePath[4];
                        swprintf_s(drivePath, 4, L"%c:\\", driveLetter);
                        
                        // Check if the device is malicious
                        wchar_t volumeName[MAX_PATH];
                        if (GetVolumeInformation(drivePath, volumeName, MAX_PATH, NULL, NULL, NULL, NULL, 0)) {
                            if (IsMaliciousDevice(drivePath, volumeName)) {
                                // Report the threat
                                ThreatInfo threatInfo;
                                threatInfo.type = ThreatType::DEVICE_MALICIOUS;
                                threatInfo.processPath = GetProcessPath(GetCurrentProcessId());
                                threatInfo.targetPath = drivePath;
                                threatInfo.threatDescription = L"Malicious removable device detected";
                                threatInfo.processId = GetCurrentProcessId();
                                threatInfo.threadId = GetCurrentThreadId();
                                
                                // Send threat to communication manager
                                // Note: This would be implemented in the CommunicationManager class
                                LogWarning(L"Malicious removable device detected: " + std::wstring(drivePath));
                            } else {
                                // Scan the device for malicious files
                                ScanDevice(drivePath);
                            }
                        }
                    }
                }
                break;
            }
            case DBT_DEVICEREMOVECOMPLETE:
                // Device removed, do nothing
                break;
        }
    }
}

bool DeviceProtection::IsMaliciousDevice(const std::wstring& devicePath, const std::wstring& deviceName) {
    // Check for known malicious device names
    std::wstring lowerDeviceName = deviceName;
    std::transform(lowerDeviceName.begin(), lowerDeviceName.end(), lowerDeviceName.begin(), ::towlower);
    
    std::vector<std::wstring> maliciousDeviceNames = {
        L"malware", L"virus", L"trojan", L"ransomware",
        L"keylogger", L"spyware", L"adware", L"rootkit"
    };
    
    if (std::find(maliciousDeviceNames.begin(), maliciousDeviceNames.end(), lowerDeviceName) != maliciousDeviceNames.end()) {
        return true;
    }
    
    // Check for autorun.inf file
    std::wstring autorunPath = devicePath + L"autorun.inf";
    if (GetFileAttributes(autorunPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
        return true;
    }
    
    return false;
}

void DeviceProtection::ScanDevice(const std::wstring& devicePath) {
    Log(L"Scanning device: " + devicePath);
    
    // Scan the device for malicious files
    // Note: This is a simplified implementation
    // In a real-world scenario, you would use a more comprehensive scanning method
    
    std::wstring searchPath = devicePath + L"*.*";
    WIN32_FIND_DATA findData;
    HANDLE hFind = FindFirstFile(searchPath.c_str(), &findData);
    
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                std::wstring filePath = devicePath + findData.cFileName;
                
                // Check if the file is malicious
                // Note: This would use the same logic as FileProtection::IsMaliciousFile
                Log(L"Scanned file: " + filePath);
            }
        } while (FindNextFile(hFind, &findData));
        
        FindClose(hFind);
    }
    
    Log(L"Device scan completed: " + devicePath);
}
