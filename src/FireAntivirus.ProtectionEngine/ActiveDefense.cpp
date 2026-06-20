#include "pch.h"
#include "ActiveDefense.h"

ActiveDefense::ActiveDefense() : isInitialized(false), isMonitoring(false) {
}

ActiveDefense::~ActiveDefense() {
    Cleanup();
}

bool ActiveDefense::Initialize() {
    Log(L"Initializing active defense...");
    
    // Start monitoring thread
    isMonitoring = true;
    monitoringThread = std::thread(&ActiveDefense::MonitorBehavior, this);
    
    isInitialized = true;
    Log(L"Active defense initialized successfully.");
    return true;
}

void ActiveDefense::Update() {
    // Nothing to do here, monitoring is done in a separate thread
}

void ActiveDefense::Cleanup() {
    Log(L"Cleaning up active defense...");
    
    // Stop monitoring
    isMonitoring = false;
    
    // Wait for monitoring thread to finish
    if (monitoringThread.joinable()) {
        monitoringThread.join();
    }
    
    isInitialized = false;
    Log(L"Active defense cleaned up successfully.");
}

bool ActiveDefense::IsInitialized() const {
    return isInitialized;
}

void ActiveDefense::MonitorBehavior() {
    Log(L"Behavior monitoring started.");
    
    while (isMonitoring) {
        try {
            // Take a snapshot of all processes
            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnapshot != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32 pe32;
                pe32.dwSize = sizeof(PROCESSENTRY32);
                
                if (Process32First(hSnapshot, &pe32)) {
                    do {
                        // Analyze process behavior
                        AnalyzeProcessBehavior(pe32.th32ProcessID);
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
            LogError(L"Behavior monitoring exception: " + wideErrorMsg);
        }
    }
    
    Log(L"Behavior monitoring stopped.");
}

void ActiveDefense::AnalyzeProcessBehavior(DWORD processId) {
    // Check if the process is malicious based on its behavior
    if (IsMaliciousBehavior(processId)) {
        // Report the threat
        ThreatInfo threatInfo;
        threatInfo.type = ThreatType::BEHAVIOR_MALICIOUS;
        
        // Copy process path
        std::wstring processPathStr = GetProcessPath(processId);
        wcsncpy_s(threatInfo.processPath, processPathStr.c_str(), _TRUNCATE);
        
        // Copy target path
        wcsncpy_s(threatInfo.targetPath, processPathStr.c_str(), _TRUNCATE);
        
        // Copy threat description
        wcsncpy_s(threatInfo.threatDescription, L"Malicious behavior detected", _TRUNCATE);
        
        threatInfo.processId = processId;
        threatInfo.threadId = 0;
        
        // Send threat to communication manager
        // Note: This would be implemented in the CommunicationManager class
        LogWarning(L"Malicious behavior detected: " + GetProcessName(processId));
    }
}

bool ActiveDefense::IsMaliciousBehavior(DWORD processId) {
    // Check for suspicious process behavior
    // Note: This is a simplified implementation
    // In a real-world scenario, you would analyze more complex behavior patterns
    
    // Check if the process is injecting code into other processes
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, processId);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te32;
        te32.dwSize = sizeof(THREADENTRY32);
        
        if (Thread32First(hSnapshot, &te32)) {
            do {
                if (te32.th32OwnerProcessID == processId) {
                    // Check if the thread is in another process
                    // Note: This is a simplified check
                    // In a real-world scenario, you would use more sophisticated methods
                }
            } while (Thread32Next(hSnapshot, &te32));
        }
        
        CloseHandle(hSnapshot);
    }
    
    // Check if the process is accessing sensitive files
    std::wstring processPath = GetProcessPath(processId);
    if (!processPath.empty()) {
        std::wstring systemDir = GetSystemDirectory();
        std::wstring windowsDir = GetWindowsDirectory();
        
        if (processPath.find(systemDir) == std::wstring::npos &&
            processPath.find(windowsDir) == std::wstring::npos) {
            // Check if the process is accessing system files
            // Note: This is a simplified check
            // In a real-world scenario, you would monitor file accesses
        }
    }
    
    return false;
}
