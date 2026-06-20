#include "pch.h"
#include "FileProtection.h"

FileProtection::FileProtection() : isInitialized(false), isMonitoring(false) {
}

FileProtection::~FileProtection() {
    Cleanup();
}

bool FileProtection::Initialize() {
    Log(L"Initializing file protection...");
    
    // Set monitored path to the system drive
    wchar_t systemDrive[MAX_PATH];
    if (GetSystemDirectory(systemDrive, MAX_PATH)) {
        monitoredPath = systemDrive;
        monitoredPath = monitoredPath.substr(0, 3); // Get drive letter only
    } else {
        monitoredPath = L"C:\\\";
    }
    
    // Start monitoring thread
    isMonitoring = true;
    monitoringThread = std::thread(&FileProtection::MonitorFiles, this);
    
    isInitialized = true;
    Log(L"File protection initialized successfully.");
    return true;
}

void FileProtection::Update() {
    // Nothing to do here, monitoring is done in a separate thread
}

void FileProtection::Cleanup() {
    Log(L"Cleaning up file protection...");
    
    // Stop monitoring
    isMonitoring = false;
    
    // Wait for monitoring thread to finish
    if (monitoringThread.joinable()) {
        monitoringThread.join();
    }
    
    // Close handles
    if (hChangeNotify != NULL) {
        CloseHandle(hChangeNotify);
        hChangeNotify = NULL;
    }
    
    isInitialized = false;
    Log(L"File protection cleaned up successfully.");
}

bool FileProtection::IsInitialized() const {
    return isInitialized;
}

void FileProtection::MonitorFiles() {
    Log(L"File monitoring started.");
    
    while (isMonitoring) {
        try {
            // Use ReadDirectoryChangesW to monitor file changes
            HANDLE hDir = CreateFile(
                monitoredPath.c_str(),
                FILE_LIST_DIRECTORY,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                NULL,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                NULL
            );
            
            if (hDir != INVALID_HANDLE_VALUE) {
                BYTE buffer[1024];
                DWORD bytesReturned;
                
                if (ReadDirectoryChangesW(
                    hDir,
                    buffer,
                    sizeof(buffer),
                    TRUE,
                    FILE_NOTIFY_CHANGE_FILE_NAME |
                    FILE_NOTIFY_CHANGE_DIR_NAME |
                    FILE_NOTIFY_CHANGE_ATTRIBUTES |
                    FILE_NOTIFY_CHANGE_SIZE |
                    FILE_NOTIFY_CHANGE_LAST_WRITE |
                    FILE_NOTIFY_CHANGE_SECURITY,
                    &bytesReturned,
                    NULL,
                    NULL
                )) {
                    PFILE_NOTIFY_INFORMATION pNotify = (PFILE_NOTIFY_INFORMATION)buffer;
                    while (pNotify) {
                        wchar_t fileName[MAX_PATH];
                        size_t fileNameLength = pNotify->FileNameLength / sizeof(wchar_t);
                        if (fileNameLength < MAX_PATH) {
                            memcpy(fileName, pNotify->FileName, pNotify->FileNameLength);
                            fileName[fileNameLength] = L'\0';
                            
                            std::wstring filePath = monitoredPath + fileName;
                            HandleFileChange(pNotify->Action, filePath);
                        }
                        
                        if (pNotify->NextEntryOffset == 0) {
                            break;
                        }
                        pNotify = (PFILE_NOTIFY_INFORMATION)((BYTE*)pNotify + pNotify->NextEntryOffset);
                    }
                }
                
                CloseHandle(hDir);
            }
            
            // Sleep for a short time to avoid high CPU usage
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        catch (const std::exception& e) {
            std::string errorMsg = e.what();
            std::wstring wideErrorMsg(errorMsg.begin(), errorMsg.end());
            LogError(L"File monitoring exception: " + wideErrorMsg);
        }
    }
    
    Log(L"File monitoring stopped.");
}

void FileProtection::HandleFileChange(DWORD action, const std::wstring& filePath) {
    // Get the process that caused the file change
    // Note: This is a simplified implementation
    // In a real-world scenario, you would use ETW to get the process information
    DWORD processId = GetCurrentProcessId();
    
    // Check if the file is malicious
    if (IsMaliciousFile(filePath, processId)) {
        // Report the threat
        ThreatInfo threatInfo;
        threatInfo.type = ThreatType::FILE_MALICIOUS;
        
        // Copy process path
        std::wstring processPathStr = GetProcessPath(processId);
        wcsncpy_s(threatInfo.processPath, processPathStr.c_str(), _TRUNCATE);
        
        // Copy target path
        wcsncpy_s(threatInfo.targetPath, filePath.c_str(), _TRUNCATE);
        
        // Copy threat description
        wcsncpy_s(threatInfo.threatDescription, L"Malicious file detected", _TRUNCATE);
        
        threatInfo.processId = processId;
        threatInfo.threadId = GetCurrentThreadId();
        
        // Send threat to communication manager
        // Note: This would be implemented in the CommunicationManager class
        LogWarning(L"Malicious file detected: " + filePath);
    }
}

bool FileProtection::IsMaliciousFile(const std::wstring& filePath, DWORD processId) {
    // Check file extension
    std::wstring extension = filePath.substr(filePath.find_last_of(L'.') + 1);
    std::transform(extension.begin(), extension.end(), extension.begin(), ::towlower);
    
    // Check for known malicious extensions
    std::vector<std::wstring> maliciousExtensions = {
        L"exe", L"dll", L"sys", L"com", L"bat", L"cmd", L"ps1", L"vbs", L"js", L"jse",
        L"wsf", L"wsh", L"scr", L"pif", L"hta", L"cpl", L"msc", L"msi", L"msp", L"reg"
    };
    
    if (std::find(maliciousExtensions.begin(), maliciousExtensions.end(), extension) != maliciousExtensions.end()) {
        // Check if the file is in a protected directory
        if (IsPathProtected(filePath)) {
            // Check if the process is trusted
            std::wstring processPath = GetProcessPath(processId);
            std::wstring systemDir = GetSystemDirectory();
            std::wstring windowsDir = GetWindowsDirectory();
            
            if (processPath.compare(0, systemDir.length(), systemDir) != 0 &&
                processPath.compare(0, windowsDir.length(), windowsDir) != 0) {
                return true;
            }
        }
    }
    
    return false;
}
