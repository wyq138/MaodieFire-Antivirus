#include "pch.h"
#include "ProcessGuard.h"

ProcessGuard::ProcessGuard() : isInitialized(false), isRunning(false), mainProcessId(0), guardProcessId(0), hGuardPipe(INVALID_HANDLE_VALUE) {
}

ProcessGuard::~ProcessGuard() {
    Cleanup();
}

bool ProcessGuard::Initialize() {
    Log(L"Initializing process guard...");
    
    // Get current process ID
    mainProcessId = GetCurrentProcessId();
    
    // Start guard process
    StartGuardProcess();
    
    // Start guard thread
    isRunning = true;
    guardThread = std::thread(&ProcessGuard::GuardThread, this);
    
    isInitialized = true;
    Log(L"Process guard initialized successfully.");
    return true;
}

void ProcessGuard::Update() {
    // Nothing to do here, monitoring is done in a separate thread
}

void ProcessGuard::Cleanup() {
    Log(L"Cleaning up process guard...");
    
    // Stop running
    isRunning = false;
    
    // Wait for guard thread to finish
    if (guardThread.joinable()) {
        guardThread.join();
    }
    
    // Close guard pipe
    if (hGuardPipe != INVALID_HANDLE_VALUE) {
        CloseHandle(hGuardPipe);
        hGuardPipe = INVALID_HANDLE_VALUE;
    }
    
    isInitialized = false;
    Log(L"Process guard cleaned up successfully.");
}

bool ProcessGuard::IsInitialized() const {
    return isInitialized;
}

void ProcessGuard::GuardThread() {
    Log(L"Process guard thread started.");
    
    while (isRunning) {
        try {
            // Monitor main process
            MonitorMainProcess();
            
            // Monitor guard process
            MonitorGuardProcess();
            
            // Sleep for a short time to avoid high CPU usage
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        }
        catch (const std::exception& e) {
            std::string errorMsg = e.what();
            std::wstring wideErrorMsg(errorMsg.begin(), errorMsg.end());
            LogError(L"Process guard thread exception: " + wideErrorMsg);
        }
    }
    
    Log(L"Process guard thread stopped.");
}

void ProcessGuard::StartGuardProcess() {
    // Get current executable path
    wchar_t executablePath[MAX_PATH];
    if (GetModuleFileName(NULL, executablePath, MAX_PATH)) {
        // Start guard process with a special argument
        STARTUPINFO si = { sizeof(STARTUPINFO) };
        PROCESS_INFORMATION pi;
        
        wchar_t commandLine[MAX_PATH + 10];
        swprintf_s(commandLine, MAX_PATH + 10, L"%s --guard", executablePath);
        
        if (CreateProcess(NULL, commandLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
            guardProcessId = pi.dwProcessId;
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            Log(L"Guard process started with ID: " + std::to_wstring(guardProcessId));
        } else {
            LogError(L"Failed to start guard process.");
        }
    } else {
        LogError(L"Failed to get executable path.");
    }
}

void ProcessGuard::MonitorMainProcess() {
    // Check if main process is running
    if (!IsProcessRunning(mainProcessId)) {
        LogWarning(L"Main process is not running. Restarting...");
        if (StartMainProcess()) {
            Log(L"Main process restarted successfully.");
        } else {
            LogError(L"Failed to restart main process.");
        }
    }
}

void ProcessGuard::MonitorGuardProcess() {
    // Check if guard process is running
    if (!IsProcessRunning(guardProcessId)) {
        LogWarning(L"Guard process is not running. Restarting...");
        StartGuardProcess();
    }
}

bool ProcessGuard::IsProcessRunning(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (hProcess) {
        DWORD exitCode;
        if (GetExitCodeProcess(hProcess, &exitCode)) {
            CloseHandle(hProcess);
            return exitCode == STILL_ACTIVE;
        }
        CloseHandle(hProcess);
    }
    return false;
}

bool ProcessGuard::StartMainProcess() {
    // Get current executable path
    wchar_t executablePath[MAX_PATH];
    if (GetModuleFileName(NULL, executablePath, MAX_PATH)) {
        // Start main process
        STARTUPINFO si = { sizeof(STARTUPINFO) };
        PROCESS_INFORMATION pi;
        
        if (CreateProcess(NULL, executablePath, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
            mainProcessId = pi.dwProcessId;
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return true;
        }
    }
    return false;
}

bool ProcessGuard::StartGuardProcessInternal() {
    // This method is called by the guard process to start itself
    // Note: This would be implemented in a real-world scenario
    return false;
}
