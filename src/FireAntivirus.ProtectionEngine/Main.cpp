#include "pch.h"
#include "Main.h"

// Static member initialization
std::atomic<bool> Main::isRunning(false);
std::thread Main::protectionThread;
std::thread Main::communicationThread;
std::thread Main::guardThread;
std::shared_ptr<ProtectionManager> Main::protectionManager;
std::shared_ptr<CommunicationManager> Main::communicationManager;
std::shared_ptr<ProcessGuard> Main::processGuard;

int Main::Run(int argc, char* argv[]) {
    try {
        // Check if this is a guard process
        bool isGuardProcess = false;
        for (int i = 1; i < argc; i++) {
            if (strcmp(argv[i], "--guard") == 0) {
                isGuardProcess = true;
                break;
            }
        }
        
        if (isGuardProcess) {
            Log(L"Starting FireAntivirus Protection Engine (Guard Mode)...");
            // In guard mode, only start the guard thread
            Initialize();
            isRunning = true;
            guardThread = std::thread(&Main::GuardThread);
            if (guardThread.joinable()) {
                guardThread.join();
            }
            Cleanup();
            Log(L"FireAntivirus Protection Engine (Guard Mode) stopped.");
        } else {
            Log(L"Starting FireAntivirus Protection Engine...");
            
            // Initialize the protection engine
            Initialize();
            
            // Set running flag
            isRunning = true;
            
            // Start threads
            protectionThread = std::thread(&Main::ProtectionThread);
            communicationThread = std::thread(&Main::CommunicationThread);
            guardThread = std::thread(&Main::GuardThread);
            
            // Wait for threads to finish
            if (protectionThread.joinable()) {
                protectionThread.join();
            }
            if (communicationThread.joinable()) {
                communicationThread.join();
            }
            if (guardThread.joinable()) {
                guardThread.join();
            }
            
            // Cleanup
            Cleanup();
            
            Log(L"FireAntivirus Protection Engine stopped.");
        }
        return ERROR_SUCCESS;
    }
    catch (const std::exception& e) {
        std::string errorMsg = e.what();
        std::wstring wideErrorMsg(errorMsg.begin(), errorMsg.end());
        LogError(L"Exception: " + wideErrorMsg);
        return ERROR_FAILURE;
    }
    catch (...) {
        LogError(L"Unknown exception occurred.");
        return ERROR_FAILURE;
    }
}

void Main::Stop() {
    Log(L"Stopping FireAntivirus Protection Engine...");
    isRunning = false;
}

bool Main::IsRunning() {
    return isRunning;
}

void Main::ProtectionThread() {
    Log(L"Protection thread started.");
    
    while (isRunning) {
        try {
            protectionManager->Update();
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        catch (const std::exception& e) {
            std::string errorMsg = e.what();
            std::wstring wideErrorMsg(errorMsg.begin(), errorMsg.end());
            LogError(L"Protection thread exception: " + wideErrorMsg);
        }
    }
    
    Log(L"Protection thread stopped.");
}

void Main::CommunicationThread() {
    Log(L"Communication thread started.");
    
    while (isRunning) {
        try {
            communicationManager->Update();
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        catch (const std::exception& e) {
            std::string errorMsg = e.what();
            std::wstring wideErrorMsg(errorMsg.begin(), errorMsg.end());
            LogError(L"Communication thread exception: " + wideErrorMsg);
        }
    }
    
    Log(L"Communication thread stopped.");
}

void Main::GuardThread() {
    Log(L"Guard thread started.");
    
    while (isRunning) {
        try {
            processGuard->Update();
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        }
        catch (const std::exception& e) {
            std::string errorMsg = e.what();
            std::wstring wideErrorMsg(errorMsg.begin(), errorMsg.end());
            LogError(L"Guard thread exception: " + wideErrorMsg);
        }
    }
    
    Log(L"Guard thread stopped.");
}

void Main::Initialize() {
    Log(L"Initializing FireAntivirus Protection Engine...");
    
    // Create protection manager
    protectionManager = std::make_shared<ProtectionManager>();
    
    // Create communication manager
    communicationManager = std::make_shared<CommunicationManager>();
    
    // Create process guard
    processGuard = std::make_shared<ProcessGuard>();
    
    // Initialize protection modules
    protectionManager->Initialize();
    
    // Initialize communication
    communicationManager->Initialize();
    
    // Initialize process guard
    processGuard->Initialize();
    
    Log(L"FireAntivirus Protection Engine initialized successfully.");
}

void Main::Cleanup() {
    Log(L"Cleaning up FireAntivirus Protection Engine...");
    
    // Cleanup protection manager
    if (protectionManager) {
        protectionManager->Cleanup();
    }
    
    // Cleanup communication manager
    if (communicationManager) {
        communicationManager->Cleanup();
    }
    
    // Cleanup process guard
    if (processGuard) {
        processGuard->Cleanup();
    }
    
    Log(L"FireAntivirus Protection Engine cleanup completed.");
}

// Utility functions
std::wstring GetProcessPath(DWORD processId) {
    std::wstring path;
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (hProcess) {
        wchar_t buffer[MAX_PATH];
        if (GetModuleFileNameEx(hProcess, NULL, buffer, MAX_PATH)) {
            path = buffer;
        }
        CloseHandle(hProcess);
    }
    return path;
}

std::wstring GetProcessName(DWORD processId) {
    std::wstring name;
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (hProcess) {
        wchar_t buffer[MAX_PATH];
        if (GetModuleBaseName(hProcess, NULL, buffer, MAX_PATH)) {
            name = buffer;
        }
        CloseHandle(hProcess);
    }
    return name;
}

DWORD GetParentProcessId(DWORD processId) {
    DWORD parentId = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &pe32)) {
            do {
                if (pe32.th32ProcessID == processId) {
                    parentId = pe32.th32ParentProcessID;
                    break;
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
    return parentId;
}

bool IsProcessRunning(DWORD processId) {
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

bool TerminateProcessById(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processId);
    if (hProcess) {
        bool result = TerminateProcess(hProcess, 0);
        CloseHandle(hProcess);
        return result;
    }
    return false;
}

std::wstring GetCurrentDirectory() {
    wchar_t buffer[MAX_PATH];
    if (GetCurrentDirectory(MAX_PATH, buffer)) {
        return buffer;
    }
    return L"";
}

std::wstring GetSystemDirectory() {
    wchar_t buffer[MAX_PATH];
    if (GetSystemDirectory(buffer, MAX_PATH)) {
        return buffer;
    }
    return L"";
}

std::wstring GetWindowsDirectory() {
    wchar_t buffer[MAX_PATH];
    if (GetWindowsDirectory(buffer, MAX_PATH)) {
        return buffer;
    }
    return L"";
}

bool IsPathProtected(const std::wstring& path) {
    // Check if the path is in a protected directory
    std::wstring systemDir = GetSystemDirectory();
    std::wstring windowsDir = GetWindowsDirectory();
    
    if (path.compare(0, systemDir.length(), systemDir) == 0) {
        return true;
    }
    if (path.compare(0, windowsDir.length(), windowsDir) == 0) {
        return true;
    }
    if (path.find(L"\\Program Files\\") != std::wstring::npos) {
        return true;
    }
    if (path.find(L"\\Program Files (x86)\\") != std::wstring::npos) {
        return true;
    }
    if (path.find(L"\\Users\\") != std::wstring::npos) {
        return true;
    }
    return false;
}

bool IsProcessProtected(DWORD processId) {
    std::wstring processPath = GetProcessPath(processId);
    return IsPathProtected(processPath);
}

void Log(const std::wstring& message) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    std::wstringstream ss;
    ss << std::setw(4) << st.wYear << L"-" 
       << std::setw(2) << std::setfill(L'0') << st.wMonth << L"-" 
       << std::setw(2) << std::setfill(L'0') << st.wDay << L" " 
       << std::setw(2) << std::setfill(L'0') << st.wHour << L":" 
       << std::setw(2) << std::setfill(L'0') << st.wMinute << L":" 
       << std::setw(2) << std::setfill(L'0') << st.wSecond << L"." 
       << std::setw(3) << std::setfill(L'0') << st.wMilliseconds << L" [INFO] " << message;
    std::wcout << ss.str() << std::endl;
}

void LogError(const std::wstring& message) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    std::wstringstream ss;
    ss << std::setw(4) << st.wYear << L"-" 
       << std::setw(2) << std::setfill(L'0') << st.wMonth << L"-" 
       << std::setw(2) << std::setfill(L'0') << st.wDay << L" " 
       << std::setw(2) << std::setfill(L'0') << st.wHour << L":" 
       << std::setw(2) << std::setfill(L'0') << st.wMinute << L":" 
       << std::setw(2) << std::setfill(L'0') << st.wSecond << L"." 
       << std::setw(3) << std::setfill(L'0') << st.wMilliseconds << L" [ERROR] " << message;
    std::wcerr << ss.str() << std::endl;
}

void LogWarning(const std::wstring& message) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    std::wstringstream ss;
    ss << std::setw(4) << st.wYear << L"-" 
       << std::setw(2) << std::setfill(L'0') << st.wMonth << L"-" 
       << std::setw(2) << std::setfill(L'0') << st.wDay << L" " 
       << std::setw(2) << std::setfill(L'0') << st.wHour << L":" 
       << std::setw(2) << std::setfill(L'0') << st.wMinute << L":" 
       << std::setw(2) << std::setfill(L'0') << st.wSecond << L"." 
       << std::setw(3) << std::setfill(L'0') << st.wMilliseconds << L" [WARNING] " << message;
    std::wcout << ss.str() << std::endl;
}
