#include "pch.h"
#include "ScriptProtection.h"

ScriptProtection::ScriptProtection() : isInitialized(false), isMonitoring(false) {
}

ScriptProtection::~ScriptProtection() {
    Cleanup();
}

bool ScriptProtection::Initialize() {
    Log(L"Initializing script protection...");
    
    // Start monitoring thread
    isMonitoring = true;
    monitoringThread = std::thread(&ScriptProtection::MonitorScripts, this);
    
    isInitialized = true;
    Log(L"Script protection initialized successfully.");
    return true;
}

void ScriptProtection::Update() {
    // Nothing to do here, monitoring is done in a separate thread
}

void ScriptProtection::Cleanup() {
    Log(L"Cleaning up script protection...");
    
    // Stop monitoring
    isMonitoring = false;
    
    // Wait for monitoring thread to finish
    if (monitoringThread.joinable()) {
        monitoringThread.join();
    }
    
    isInitialized = false;
    Log(L"Script protection cleaned up successfully.");
}

bool ScriptProtection::IsInitialized() const {
    return isInitialized;
}

void ScriptProtection::MonitorScripts() {
    Log(L"Script monitoring started.");
    
    while (isMonitoring) {
        try {
            // Take a snapshot of all processes
            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnapshot != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32 pe32;
                pe32.dwSize = sizeof(PROCESSENTRY32);
                
                if (Process32First(hSnapshot, &pe32)) {
                    do {
                        // Check if the process is a script interpreter
                        std::wstring processName = GetProcessName(pe32.th32ProcessID);
                        std::transform(processName.begin(), processName.end(), processName.begin(), ::towlower);
                        
                        std::vector<std::wstring> scriptInterpreters = {
                            L"cscript.exe", L"wscript.exe", L"powershell.exe", L"cmd.exe",
                            L"python.exe", L"pythonw.exe", L"node.exe", L"nodejs.exe"
                        };
                        
                        if (std::find(scriptInterpreters.begin(), scriptInterpreters.end(), processName) != scriptInterpreters.end()) {
                            // Get the command line
                            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
                            if (hProcess) {
                                wchar_t commandLine[MAX_PATH * 2];
                                if (GetProcessCommandLine(hProcess, commandLine, MAX_PATH * 2)) {
                                    std::wstring cmdLine = commandLine;
                                    std::wstring scriptPath;
                                    
                                    // Extract script path from command line
                                    size_t pos = cmdLine.find(L".js");
                                    if (pos == std::wstring::npos) {
                                        pos = cmdLine.find(L".vbs");
                                    }
                                    if (pos == std::wstring::npos) {
                                        pos = cmdLine.find(L".ps1");
                                    }
                                    if (pos == std::wstring::npos) {
                                        pos = cmdLine.find(L".bat");
                                    }
                                    if (pos == std::wstring::npos) {
                                        pos = cmdLine.find(L".cmd");
                                    }
                                    
                                    if (pos != std::wstring::npos) {
                                        // Extract script path
                                        size_t startPos = cmdLine.rfind(L' ', pos);
                                        if (startPos != std::wstring::npos) {
                                            scriptPath = cmdLine.substr(startPos + 1, pos - startPos + 3);
                                            // Remove quotes if present
                                            if (!scriptPath.empty() && scriptPath[0] == L'"') {
                                                scriptPath = scriptPath.substr(1, scriptPath.length() - 2);
                                            }
                                            
                                            HandleScriptExecution(scriptPath, cmdLine);
                                        }
                                    }
                                }
                                CloseHandle(hProcess);
                            }
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
            LogError(L"Script monitoring exception: " + wideErrorMsg);
        }
    }
    
    Log(L"Script monitoring stopped.");
}

void ScriptProtection::HandleScriptExecution(const std::wstring& scriptPath, const std::wstring& commandLine) {
    // Get the process that is executing the script
    DWORD processId = GetCurrentProcessId();
    
    // Check if the script is malicious
    if (IsMaliciousScript(scriptPath, commandLine, processId)) {
        // Report the threat
        ThreatInfo threatInfo;
        threatInfo.type = ThreatType::SCRIPT_MALICIOUS;
        
        // Copy process path
        std::wstring processPathStr = GetProcessPath(processId);
        wcsncpy_s(threatInfo.processPath, processPathStr.c_str(), _TRUNCATE);
        
        // Copy target path
        wcsncpy_s(threatInfo.targetPath, scriptPath.c_str(), _TRUNCATE);
        
        // Copy threat description
        wcsncpy_s(threatInfo.threatDescription, L"Malicious script execution detected", _TRUNCATE);
        
        threatInfo.processId = processId;
        threatInfo.threadId = GetCurrentThreadId();
        
        // Send threat to communication manager
        // Note: This would be implemented in the CommunicationManager class
        LogWarning(L"Malicious script execution detected: " + scriptPath);
    }
}

bool ScriptProtection::IsMaliciousScript(const std::wstring& scriptPath, const std::wstring& commandLine, DWORD processId) {
    // Check for malicious script content
    // Note: This is a simplified implementation
    // In a real-world scenario, you would analyze the script content
    
    // Check for known malicious keywords in command line
    std::wstring lowerCommandLine = commandLine;
    std::transform(lowerCommandLine.begin(), lowerCommandLine.end(), lowerCommandLine.begin(), ::towlower);
    
    std::vector<std::wstring> maliciousKeywords = {
        L"format", L"delete", L"rmdir", L"erase", L"wscript.shell",
        L"createobject", L"getobject", L"exec", L"shell", L"registry"
    };
    
    for (const auto& keyword : maliciousKeywords) {
        if (lowerCommandLine.find(keyword) != std::wstring::npos) {
            return true;
        }
    }
    
    // Check if the script is in a suspicious location
    std::wstring tempDir = GetTempPathW(MAX_PATH, NULL);
    if (scriptPath.find(tempDir) != std::wstring::npos) {
        return true;
    }
    
    return false;
}

// Helper function to get process command line
BOOL GetProcessCommandLine(HANDLE hProcess, LPWSTR lpCommandLine, DWORD nSize) {
    BOOL result = FALSE;
    HMODULE hModule = GetModuleHandle(L"psapi.dll");
    if (hModule) {
        typedef BOOL(WINAPI* GETPROCESSCOMMANDLINE)(HANDLE, LPWSTR, DWORD);
        GETPROCESSCOMMANDLINE GetProcessCommandLineFunc = (GETPROCESSCOMMANDLINE)GetProcAddress(hModule, "GetProcessCommandLineW");
        if (GetProcessCommandLineFunc) {
            result = GetProcessCommandLineFunc(hProcess, lpCommandLine, nSize);
        }
    }
    return result;
}
