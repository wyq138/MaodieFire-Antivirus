// ProcessProtection.cpp

#include "pch.h"
#include "ProcessProtection.h"

ProcessProtection::ProcessProtection() : 
    isEnabled(false),
    isInitialized(false),
    isMonitoring(false) {
}

ProcessProtection::~ProcessProtection() {
    Cleanup();
}

// 初始化
bool ProcessProtection::Initialize() {
    if (isInitialized) {
        return true;
    }
    
    isInitialized = true;
    return true;
}

// 清理
void ProcessProtection::Cleanup() {
    if (!isInitialized) {
        return;
    }
    
    // 停止监控
    Enable(false);
    
    isInitialized = false;
}

// 启用/禁用
bool ProcessProtection::Enable(bool enable) {
    if (!isInitialized) {
        return false;
    }
    
    if (isEnabled == enable) {
        return true;
    }
    
    if (enable) {
        // 启动监控线程
        isMonitoring = true;
        monitoringThread = std::thread(&ProcessProtection::MonitoringThread, this);
    } else {
        // 停止监控线程
        isMonitoring = false;
        if (monitoringThread.joinable()) {
            monitoringThread.join();
        }
    }
    
    isEnabled = enable;
    return true;
}

// 检查是否启用
bool ProcessProtection::IsEnabled() const {
    return isEnabled;
}

// 检查是否初始化
bool ProcessProtection::IsInitialized() const {
    return isInitialized;
}

// 设置威胁回调函数
void ProcessProtection::SetThreatCallback(std::function<void(const ThreatInfo&)> callback) {
    threatCallback = callback;
}

// 扫描进程
bool ProcessProtection::ScanProcess(DWORD processId, ThreatInfo& threatInfo) {
    try {
        // 获取进程路径
        std::wstring processPath = GetProcessPath(processId);
        if (processPath.empty()) {
            return false;
        }
        
        // 检查进程是否恶意
        if (IsMaliciousProcess(processId, processPath)) {
            // 填充威胁信息
            threatInfo.type = ThreatType::PROCESS_MALICIOUS;
            wcsncpy_s(threatInfo.processPath, processPath.c_str(), _TRUNCATE);
            wcsncpy_s(threatInfo.targetPath, processPath.c_str(), _TRUNCATE);
            wcsncpy_s(threatInfo.threatDescription, L"Malicious process detected", _TRUNCATE);
            threatInfo.processId = processId;
            threatInfo.threadId = GetCurrentThreadId();
            
            return true;
        }
        
        return false;
    } catch (const std::exception& e) {
        std::cerr << "Error scanning process: " << e.what() << std::endl;
        return false;
    }
}

// 扫描所有进程
bool ProcessProtection::ScanAllProcesses(std::vector<ThreatInfo>& threatInfos) {
    try {
        DWORD processes[1024];
        DWORD cbNeeded;
        
        if (!EnumProcesses(processes, sizeof(processes), &cbNeeded)) {
            return false;
        }
        
        DWORD processCount = cbNeeded / sizeof(DWORD);
        
        for (DWORD i = 0; i < processCount; i++) {
            DWORD processId = processes[i];
            if (processId != 0) {
                ThreatInfo threatInfo;
                if (ScanProcess(processId, threatInfo)) {
                    threatInfos.push_back(threatInfo);
                }
            }
        }
        
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error scanning all processes: " << e.what() << std::endl;
        return false;
    }
}

// 监控线程函数
void ProcessProtection::MonitoringThread() {
    while (isMonitoring) {
        try {
            // 枚举所有进程
            EnumProcesses();
            
            // 休眠一段时间
            std::this_thread::sleep_for(std::chrono::seconds(1));
        } catch (const std::exception& e) {
            std::cerr << "Error in process protection monitoring thread: " << e.what() << std::endl;
        }
    }
}

// 枚举所有进程
void ProcessProtection::EnumProcesses() {
    DWORD processes[1024];
    DWORD cbNeeded;
    
    if (!::EnumProcesses(processes, sizeof(processes), &cbNeeded)) {
        return;
    }
    
    DWORD processCount = cbNeeded / sizeof(DWORD);
    
    for (DWORD i = 0; i < processCount; i++) {
        DWORD processId = processes[i];
        if (processId != 0) {
            // 分析进程
            AnalyzeProcess(processId);
        }
    }
}

// 分析进程
void ProcessProtection::AnalyzeProcess(DWORD processId) {
    try {
        // 获取进程路径
        std::wstring processPath = GetProcessPath(processId);
        if (processPath.empty()) {
            return;
        }
        
        // 检查进程是否恶意
        if (IsMaliciousProcess(processId, processPath)) {
            // 填充威胁信息
            ThreatInfo threatInfo;
            threatInfo.type = ThreatType::PROCESS_MALICIOUS;
            wcsncpy_s(threatInfo.processPath, processPath.c_str(), _TRUNCATE);
            wcsncpy_s(threatInfo.targetPath, processPath.c_str(), _TRUNCATE);
            wcsncpy_s(threatInfo.threatDescription, L"Malicious process detected", _TRUNCATE);
            threatInfo.processId = processId;
            threatInfo.threadId = GetCurrentThreadId();
            
            // 调用回调函数
            if (threatCallback) {
                threatCallback(threatInfo);
            }
            
            // 终止恶意进程
            TerminateMaliciousProcess(processId);
        }
    } catch (const std::exception& e) {
        std::cerr << "Error analyzing process: " << e.what() << std::endl;
    }
}

// 获取进程路径
std::wstring ProcessProtection::GetProcessPath(DWORD processId) {
    std::wstring processPath;
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    
    if (hProcess) {
        WCHAR path[MAX_PATH];
        if (GetModuleFileNameEx(hProcess, NULL, path, MAX_PATH)) {
            processPath = path;
        }
        CloseHandle(hProcess);
    }
    
    return processPath;
}

// 获取进程名称
std::wstring ProcessProtection::GetProcessName(DWORD processId) {
    std::wstring processName;
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    
    if (hProcess) {
        WCHAR path[MAX_PATH];
        if (GetModuleFileNameEx(hProcess, NULL, path, MAX_PATH)) {
            processName = PathFindFileName(path);
        }
        CloseHandle(hProcess);
    }
    
    return processName;
}

// 检查进程是否恶意
bool ProcessProtection::IsMaliciousProcess(DWORD processId, const std::wstring& processPath) {
    try {
        // 这里需要实现恶意进程的检测逻辑
        // 由于实现较为复杂，这里只做简单的模拟
        
        // 检查进程路径
        std::wstring processName = GetProcessName(processId);
        std::transform(processName.begin(), processName.end(), processName.begin(), ::towlower);
        
        // 模拟检测恶意进程
        if (processName.find(L"malicious") != std::wstring::npos ||
            processName.find(L"virus") != std::wstring::npos ||
            processName.find(L"trojan") != std::wstring::npos) {
            return true;
        }
        
        // 随机返回结果
        return rand() % 100 < 2; // 2%的概率认为是恶意进程
    } catch (const std::exception& e) {
        std::cerr << "Error checking malicious process: " << e.what() << std::endl;
        return false;
    }
}

// 终止进程
bool ProcessProtection::TerminateMaliciousProcess(DWORD processId) {
    try {
        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processId);
        if (hProcess) {
            bool result = TerminateProcess(hProcess, 0);
            CloseHandle(hProcess);
            return result;
        }
        return false;
    } catch (const std::exception& e) {
        std::cerr << "Error terminating process: " << e.what() << std::endl;
        return false;
    }
}

// 阻止进程启动
bool ProcessProtection::BlockProcessStartup(const std::wstring& processPath) {
    try {
        // 这里需要实现进程启动的阻止逻辑
        // 由于实现较为复杂，这里只做简单的模拟
        std::wcout << L"Blocking process startup: " << processPath << std::endl;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error blocking process startup: " << e.what() << std::endl;
        return false;
    }
}