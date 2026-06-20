#include "pch.h"
#include "ProcessProtection.h"

// Static member initialization
BOOL(WINAPI* ProcessProtection::OriginalCreateProcess)(
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
) = CreateProcessW;

ProcessProtection::ProcessProtection() : isInitialized(false), isMonitoring(false) {
}

ProcessProtection::~ProcessProtection() {
    Cleanup();
}

bool ProcessProtection::Initialize() {
    Log(L"Initializing process protection...");
    
    // Hook CreateProcessW
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)OriginalCreateProcess, HookedCreateProcess);
    if (DetourTransactionCommit() != NO_ERROR) {
        LogError(L"Failed to hook CreateProcessW.");
        return false;
    }
    
    // Start monitoring thread
    isMonitoring = true;
    monitoringThread = std::thread(&ProcessProtection::MonitorProcesses, this);
    
    isInitialized = true;
    Log(L"Process protection initialized successfully.");
    return true;
}

void ProcessProtection::Update() {
    // Nothing to do here, monitoring is done in a separate thread
}

void ProcessProtection::Cleanup() {
    Log(L"Cleaning up process protection...");
    
    // Stop monitoring
    isMonitoring = false;
    
    // Wait for monitoring thread to finish
    if (monitoringThread.joinable()) {
        monitoringThread.join();
    }
    
    // Unhook CreateProcessW
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID&)OriginalCreateProcess, HookedCreateProcess);
    DetourTransactionCommit();
    
    // Close handles
    if (hProcessSnapshot != NULL) {
        CloseHandle(hProcessSnapshot);
        hProcessSnapshot = NULL;
    }
    
    isInitialized = false;
    Log(L"Process protection cleaned up successfully.");
}

bool ProcessProtection::IsInitialized() const {
    return isInitialized;
}

void ProcessProtection::MonitorProcesses() {
    Log(L"Process monitoring started.");
    
    while (isMonitoring) {
        try {
            // Take a snapshot of all processes
            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnapshot != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32 pe32;
                pe32.dwSize = sizeof(PROCESSENTRY32);
                
                if (Process32First(hSnapshot, &pe32)) {
                    do {
                        // Check if the process is malicious
                        std::wstring processPath = GetProcessPath(pe32.th32ProcessID);
                        if (!processPath.empty() && IsMaliciousProcess(processPath, pe32.th32ProcessID)) {
                            // Report the threat
                            ThreatInfo threatInfo;
                            threatInfo.type = ThreatType::PROCESS_MALICIOUS;
                            
                            // Copy process path
                            wcsncpy_s(threatInfo.processPath, processPath.c_str(), _TRUNCATE);
                            
                            // Copy target path
                            wcsncpy_s(threatInfo.targetPath, processPath.c_str(), _TRUNCATE);
                            
                            // Copy threat description
                            wcsncpy_s(threatInfo.threatDescription, L"Malicious process detected", _TRUNCATE);
                            
                            threatInfo.processId = pe32.th32ProcessID;
                            threatInfo.threadId = 0;
                            
                            // Send threat to communication manager
                            // Note: This would be implemented in the CommunicationManager class
                            LogWarning(L"Malicious process detected: " + processPath);
                        }
                    } while (Process32Next(hSnapshot, &pe32));
                }
                
                CloseHandle(hSnapshot);
            }
            
            // Sleep for a short time to avoid high CPU usage
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        }
        catch (const std::exception& e) {
            std::string errorMsg = e.what();
            std::wstring wideErrorMsg(errorMsg.begin(), errorMsg.end());
            LogError(L"Process monitoring exception: " + wideErrorMsg);
        }
    }
    
    Log(L"Process monitoring stopped.");
}

bool ProcessProtection::IsMaliciousProcess(const std::wstring& processPath, DWORD processId) {
    // Check for known malicious process names
    std::wstring processName = GetProcessName(processId);
    std::transform(processName.begin(), processName.end(), processName.begin(), ::towlower);
    
    std::vector<std::wstring> maliciousProcesses = {
        L"malware.exe", L"virus.exe", L"trojan.exe", L"ransomware.exe",
        L"keylogger.exe", L"spyware.exe", L"adware.exe", L"rootkit.exe"
    };
    
    if (std::find(maliciousProcesses.begin(), maliciousProcesses.end(), processName) != maliciousProcesses.end()) {
        return true;
    }
    
    // Check if the process is running from a suspicious location
    std::wstring currentDir = GetCurrentDirectory();
    std::wstring tempDir = GetTempPathW(MAX_PATH, NULL);
    
    if (processPath.find(currentDir) != std::wstring::npos ||
        processPath.find(tempDir) != std::wstring::npos) {
        return true;
    }
    
    return false;
}

BOOL WINAPI ProcessProtection::HookedCreateProcess(
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
) {
    // Check if the process is malicious
    std::wstring processPath;
    if (lpApplicationName) {
        processPath = lpApplicationName;
    } else if (lpCommandLine) {
        // Extract process path from command line
        wchar_t buffer[MAX_PATH];
        if (GetModuleFileName(NULL, buffer, MAX_PATH)) {
            processPath = buffer;
        }
    }
    
    if (!processPath.empty()) {
        DWORD processId = GetCurrentProcessId();
        ProcessProtection protection;
        if (protection.IsMaliciousProcess(processPath, processId)) {
            // Report the threat
            ThreatInfo threatInfo;
            threatInfo.type = ThreatType::PROCESS_MALICIOUS;
            threatInfo.processPath = GetProcessPath(processId);
            threatInfo.targetPath = processPath;
            threatInfo.threatDescription = L"Malicious process creation detected";
            threatInfo.processId = processId;
            threatInfo.threadId = GetCurrentThreadId();
            
            // Send threat to communication manager
            // Note: This would be implemented in the CommunicationManager class
            LogWarning(L"Malicious process creation detected: " + processPath);
            
            // Block the process creation
            return FALSE;
        }
    }
    
    // Call the original function
    return OriginalCreateProcess(
        lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation
    );
}
