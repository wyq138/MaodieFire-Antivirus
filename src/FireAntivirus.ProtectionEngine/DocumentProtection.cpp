#include "pch.h"
#include "DocumentProtection.h"

DocumentProtection::DocumentProtection() : isInitialized(false), isMonitoring(false) {
}

DocumentProtection::~DocumentProtection() {
    Cleanup();
}

bool DocumentProtection::Initialize() {
    Log(L"Initializing document protection...");
    
    // Start monitoring thread
    isMonitoring = true;
    monitoringThread = std::thread(&DocumentProtection::MonitorDocuments, this);
    
    isInitialized = true;
    Log(L"Document protection initialized successfully.");
    return true;
}

void DocumentProtection::Update() {
    // Nothing to do here, monitoring is done in a separate thread
}

void DocumentProtection::Cleanup() {
    Log(L"Cleaning up document protection...");
    
    // Stop monitoring
    isMonitoring = false;
    
    // Wait for monitoring thread to finish
    if (monitoringThread.joinable()) {
        monitoringThread.join();
    }
    
    isInitialized = false;
    Log(L"Document protection cleaned up successfully.");
}

bool DocumentProtection::IsInitialized() const {
    return isInitialized;
}

void DocumentProtection::MonitorDocuments() {
    Log(L"Document monitoring started.");
    
    while (isMonitoring) {
        try {
            // Get user's documents directory
            wchar_t documentsPath[MAX_PATH];
            if (SHGetFolderPath(NULL, CSIDL_MYDOCUMENTS, NULL, 0, documentsPath)) {
                std::wstring docsPath = documentsPath;
                
                // Monitor documents directory
                HANDLE hDir = CreateFile(
                    docsPath.c_str(),
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
                                
                                std::wstring filePath = docsPath + L"\\" + fileName;
                                HandleDocumentChange(filePath, pNotify->Action);
                            }
                            
                            if (pNotify->NextEntryOffset == 0) {
                                break;
                            }
                            pNotify = (PFILE_NOTIFY_INFORMATION)((BYTE*)pNotify + pNotify->NextEntryOffset);
                        }
                    }
                    
                    CloseHandle(hDir);
                }
            }
            
            // Sleep for a short time to avoid high CPU usage
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        catch (const std::exception& e) {
            std::string errorMsg = e.what();
            std::wstring wideErrorMsg(errorMsg.begin(), errorMsg.end());
            LogError(L"Document monitoring exception: " + wideErrorMsg);
        }
    }
    
    Log(L"Document monitoring stopped.");
}

void DocumentProtection::HandleDocumentChange(const std::wstring& documentPath, DWORD action) {
    // Get the process that caused the document change
    // Note: This is a simplified implementation
    // In a real-world scenario, you would use ETW to get the process information
    DWORD processId = GetCurrentProcessId();
    
    // Check if the document operation is malicious
    if (IsMaliciousDocumentOperation(documentPath, processId)) {
        // Report the threat
        ThreatInfo threatInfo;
        threatInfo.type = ThreatType::DOCUMENT_MALICIOUS;
        
        // Copy process path
        std::wstring processPathStr = GetProcessPath(processId);
        wcsncpy_s(threatInfo.processPath, processPathStr.c_str(), _TRUNCATE);
        
        // Copy target path
        wcsncpy_s(threatInfo.targetPath, documentPath.c_str(), _TRUNCATE);
        
        // Copy threat description
        wcsncpy_s(threatInfo.threatDescription, L"Malicious document operation detected", _TRUNCATE);
        
        threatInfo.processId = processId;
        threatInfo.threadId = GetCurrentThreadId();
        
        // Send threat to communication manager
        // Note: This would be implemented in the CommunicationManager class
        LogWarning(L"Malicious document operation detected: " + documentPath);
    }
}

bool DocumentProtection::IsMaliciousDocumentOperation(const std::wstring& documentPath, DWORD processId) {
    // Check for ransomware-like behavior
    // Note: This is a simplified implementation
    // In a real-world scenario, you would analyze more complex patterns
    
    // Check document extension
    std::wstring extension = documentPath.substr(documentPath.find_last_of(L'.') + 1);
    std::transform(extension.begin(), extension.end(), extension.begin(), ::towlower);
    
    // Check for common document types
    std::vector<std::wstring> documentExtensions = {
        L"doc", L"docx", L"xls", L"xlsx", L"ppt", L"pptx",
        L"pdf", L"txt", L"rtf", L"jpg", L"png", L"gif"
    };
    
    if (std::find(documentExtensions.begin(), documentExtensions.end(), extension) != documentExtensions.end()) {
        // Check if the process is suspicious
        std::wstring processPath = GetProcessPath(processId);
        std::wstring processName = GetProcessName(processId);
        std::transform(processName.begin(), processName.end(), processName.begin(), ::towlower);
        
        // Check for suspicious process names
        std::vector<std::wstring> suspiciousProcesses = {
            L"cmd.exe", L"powershell.exe", L"cscript.exe", L"wscript.exe",
            L"python.exe", L"node.exe", L"java.exe"
        };
        
        if (std::find(suspiciousProcesses.begin(), suspiciousProcesses.end(), processName) != suspiciousProcesses.end()) {
            return true;
        }
    }
    
    return false;
}
