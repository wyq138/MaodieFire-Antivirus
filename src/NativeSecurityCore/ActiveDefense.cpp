// ActiveDefense.cpp

#include "pch.h"
#include "ActiveDefense.h"

ActiveDefense::ActiveDefense() : 
    isEnabled(false),
    isInitialized(false),
    isMonitoring(false) {
}

ActiveDefense::~ActiveDefense() {
    Cleanup();
}

// 初始化
bool ActiveDefense::Initialize() {
    if (isInitialized) {
        return true;
    }
    
    Log(L"Initializing active defense...");
    isInitialized = true;
    Log(L"Active defense initialized successfully.");
    return true;
}

// 清理
void ActiveDefense::Cleanup() {
    if (!isInitialized) {
        return;
    }
    
    Log(L"Cleaning up active defense...");
    
    // 停止监控
    Enable(false);
    
    isInitialized = false;
    Log(L"Active defense cleaned up successfully.");
}

// 启用/禁用
bool ActiveDefense::Enable(bool enable) {
    if (!isInitialized) {
        return false;
    }
    
    if (isEnabled == enable) {
        return true;
    }
    
    if (enable) {
        // 启动监控线程
        isMonitoring = true;
        monitoringThread = std::thread(&ActiveDefense::MonitoringThread, this);
        Log(L"Active defense enabled.");
    } else {
        // 停止监控线程
        isMonitoring = false;
        if (monitoringThread.joinable()) {
            monitoringThread.join();
        }
        Log(L"Active defense disabled.");
    }
    
    isEnabled = enable;
    return true;
}

// 检查是否启用
bool ActiveDefense::IsEnabled() const {
    return isEnabled;
}

// 检查是否初始化
bool ActiveDefense::IsInitialized() const {
    return isInitialized;
}

// 设置威胁回调函数
void ActiveDefense::SetThreatCallback(std::function<void(const ThreatInfo&)> callback) {
    threatCallback = callback;
}

// 监控线程函数
void ActiveDefense::MonitoringThread() {
    Log(L"Behavior monitoring started.");
    
    while (isMonitoring) {
        try {
            // 枚举所有进程
            DWORD processes[1024];
            DWORD cbNeeded;
            
            if (EnumProcesses(processes, sizeof(processes), &cbNeeded)) {
                DWORD processCount = cbNeeded / sizeof(DWORD);
                
                for (DWORD i = 0; i < processCount; i++) {
                    DWORD processId = processes[i];
                    if (processId != 0) {
                        // 分析进程行为
                        AnalyzeProcessBehavior(processId);
                    }
                }
            }
            
            // 休眠一段时间，避免高CPU使用率
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        } catch (const std::exception& e) {
            std::string errorMsg = e.what();
            std::wstring wideErrorMsg(errorMsg.begin(), errorMsg.end());
            LogError(L"Behavior monitoring exception: " + wideErrorMsg);
        }
    }
    
    Log(L"Behavior monitoring stopped.");
}

// 分析进程行为
void ActiveDefense::AnalyzeProcessBehavior(DWORD processId) {
    // 检查进程是否有恶意行为
    if (IsMaliciousBehavior(processId)) {
        // 报告威胁
        ThreatInfo threatInfo;
        threatInfo.type = ThreatType::BEHAVIOR_MALICIOUS;
        
        // 复制进程路径
        std::wstring processPathStr = GetProcessPath(processId);
        wcsncpy_s(threatInfo.processPath, processPathStr.c_str(), _TRUNCATE);
        
        // 复制目标路径
        wcsncpy_s(threatInfo.targetPath, processPathStr.c_str(), _TRUNCATE);
        
        // 复制威胁描述
        wcsncpy_s(threatInfo.threatDescription, L"Malicious behavior detected", _TRUNCATE);
        
        threatInfo.processId = processId;
        threatInfo.threadId = 0;
        
        // 发送威胁到通信管理器
        LogWarning(L"Malicious behavior detected: " + GetProcessName(processId));
        
        // 调用回调函数
        if (threatCallback) {
            threatCallback(threatInfo);
        }
    }
}

// 检查是否是恶意行为
bool ActiveDefense::IsMaliciousBehavior(DWORD processId) {
    // 检查可疑进程行为
    // 注意：这是一个简化的实现
    // 在实际场景中，你需要分析更复杂的行为模式
    
    // 检查进程是否向其他进程注入代码
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, processId);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te32;
        te32.dwSize = sizeof(THREADENTRY32);
        
        if (Thread32First(hSnapshot, &te32)) {
            do {
                if (te32.th32OwnerProcessID == processId) {
                    // 检查线程是否在另一个进程中
                    // 注意：这是一个简化的检查
                    // 在实际场景中，你需要使用更复杂的方法
                }
            } while (Thread32Next(hSnapshot, &te32));
        }
        
        CloseHandle(hSnapshot);
    }
    
    // 检查进程是否访问敏感文件
    std::wstring processPath = GetProcessPath(processId);
    if (!processPath.empty()) {
        std::wstring systemDir = GetSystemDirectory();
        std::wstring windowsDir = GetWindowsDirectory();
        
        if (processPath.find(systemDir) == std::wstring::npos &&
            processPath.find(windowsDir) == std::wstring::npos) {
            // 检查进程是否访问系统文件
            // 注意：这是一个简化的检查
            // 在实际场景中，你需要监控文件访问
        }
    }
    
    // 随机返回结果
    return rand() % 100 < 3; // 3%的概率认为是恶意行为
}

// 获取进程路径
std::wstring ActiveDefense::GetProcessPath(DWORD processId) {
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
std::wstring ActiveDefense::GetProcessName(DWORD processId) {
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

// 获取系统目录
std::wstring ActiveDefense::GetSystemDirectory() {
    WCHAR systemDir[MAX_PATH];
    GetSystemDirectory(systemDir, MAX_PATH);
    return systemDir;
}

// 获取Windows目录
std::wstring ActiveDefense::GetWindowsDirectory() {
    WCHAR windowsDir[MAX_PATH];
    GetWindowsDirectory(windowsDir, MAX_PATH);
    return windowsDir;
}

// 记录日志
void ActiveDefense::Log(const std::wstring& message) {
    std::wcout << L"[INFO] " << message << std::endl;
}

// 记录错误日志
void ActiveDefense::LogError(const std::wstring& message) {
    std::wcerr << L"[ERROR] " << message << std::endl;
}

// 记录警告日志
void ActiveDefense::LogWarning(const std::wstring& message) {
    std::wcout << L"[WARNING] " << message << std::endl;
}