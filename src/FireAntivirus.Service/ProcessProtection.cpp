// ProcessProtection.cpp

#include "pch.h"
#include "ProcessProtection.h"
#include <fstream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

ProcessProtection::ProcessProtection() : 
    isEnabled(false),
    isInitialized(false),
    protectionMutex(nullptr),
    isMonitoring(false),
    mainProcessId(0) {
}

ProcessProtection::~ProcessProtection() {
    Cleanup();
}

// 初始化
bool ProcessProtection::Initialize() {
    if (isInitialized) {
        return true;
    }
    
    // 创建互斥体
    protectionMutex = CreateMutex(nullptr, FALSE, PROTECTION_MUTEX_NAME);
    if (!protectionMutex) {
        std::cerr << "Error creating protection mutex: " << GetLastError() << std::endl;
        return false;
    }
    
    // 设置退出标志文件路径
    WCHAR szPath[MAX_PATH];
    if (GetModuleFileName(nullptr, szPath, MAX_PATH)) {
        std::wstring path(szPath);
        size_t pos = path.find_last_of(L"\\");
        if (pos != std::wstring::npos) {
            exitFlagPath = path.substr(0, pos + 1) + EXIT_FLAG_FILE;
        }
    }
    
    // 清除旧的退出标志
    ClearExitFlag();
    
    // 添加自身到受保护进程列表
    AddProtectedProcess(GetCurrentProcessId());
    
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
    
    // 关闭互斥体
    if (protectionMutex) {
        CloseHandle(protectionMutex);
        protectionMutex = nullptr;
    }
    
    // 清空受保护进程列表
    std::lock_guard<std::mutex> lock(processesMutex);
    protectedProcesses.clear();
    
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

// 更新保护状态
void ProcessProtection::Update() {
    if (!isEnabled) {
        return;
    }
    
    // 枚举所有进程
    EnumProcesses();
}

// 添加受保护进程
bool ProcessProtection::AddProtectedProcess(const std::wstring& processPath) {
    try {
        // 启动进程
        STARTUPINFO si = { sizeof(STARTUPINFO) };
        PROCESS_INFORMATION pi;
        
        if (CreateProcess(processPath.c_str(), nullptr, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
            // 添加到受保护进程列表
            AddProtectedProcess(pi.dwProcessId);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return true;
        }
        
        return false;
    } catch (const std::exception& e) {
        std::cerr << "Error adding protected process: " << e.what() << std::endl;
        return false;
    }
}

// 移除受保护进程
bool ProcessProtection::RemoveProtectedProcess(const std::wstring& processPath) {
    try {
        std::lock_guard<std::mutex> lock(processesMutex);
        
        for (auto it = protectedProcesses.begin(); it != protectedProcesses.end(); ) {
            if (it->processPath == processPath) {
                it = protectedProcesses.erase(it);
            } else {
                ++it;
            }
        }
        
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error removing protected process: " << e.what() << std::endl;
        return false;
    }
}

// 获取受保护进程列表
std::vector<ProcessInfo> ProcessProtection::GetProtectedProcesses() {
    std::lock_guard<std::mutex> lock(processesMutex);
    return protectedProcesses;
}

// 监控线程函数
void ProcessProtection::MonitoringThread() {
    while (isMonitoring) {
        try {
            // 枚举所有进程
            EnumProcesses();
            
            // 检查互斥体状态
            if (WaitForSingleObject(protectionMutex, 0) != WAIT_OBJECT_0) {
                // 互斥体被占用，说明另一个进程在运行
                std::cout << "Protection mutex is active." << std::endl;
            }
            
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
    std::vector<DWORD> runningProcesses;
    
    for (DWORD i = 0; i < processCount; i++) {
        DWORD processId = processes[i];
        if (processId != 0) {
            runningProcesses.push_back(processId);
            
            // 检查进程是否受保护
            if (IsProtectedProcess(processId)) {
                // 保护进程
                ProtectProcess(processId);
            }
        }
    }
    
    // 检查受保护进程是否仍在运行
    std::lock_guard<std::mutex> lock(processesMutex);
    for (auto it = protectedProcesses.begin(); it != protectedProcesses.end(); ) {
        if (std::find(runningProcesses.begin(), runningProcesses.end(), it->processId) == runningProcesses.end()) {
            // 进程已终止，尝试重启
            std::cout << "Protected process terminated: " << it->processName << std::endl;
            
            // 尝试重启进程
            STARTUPINFO si = { sizeof(STARTUPINFO) };
            PROCESS_INFORMATION pi;
            
            if (CreateProcess(it->processPath.c_str(), nullptr, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
                std::cout << "Restarted protected process: " << it->processName << std::endl;
                it->processId = pi.dwProcessId;
                ++it;
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
            } else {
                std::cerr << "Error restarting protected process: " << GetLastError() << std::endl;
                it = protectedProcesses.erase(it);
            }
        } else {
            ++it;
        }
    }
}

// 检查进程是否受保护
bool ProcessProtection::IsProtectedProcess(DWORD processId) {
    std::lock_guard<std::mutex> lock(processesMutex);
    
    for (const auto& process : protectedProcesses) {
        if (process.processId == processId) {
            return true;
        }
    }
    
    return false;
}

// 添加受保护进程
void ProcessProtection::AddProtectedProcess(DWORD processId) {
    ProcessInfo processInfo = GetProcessInfo(processId);
    if (processInfo.processId != 0) {
        std::lock_guard<std::mutex> lock(processesMutex);
        protectedProcesses.push_back(processInfo);
        std::cout << "Added protected process: " << processInfo.processName << std::endl;
    }
}

// 移除受保护进程
void ProcessProtection::RemoveProtectedProcess(DWORD processId) {
    std::lock_guard<std::mutex> lock(processesMutex);
    
    for (auto it = protectedProcesses.begin(); it != protectedProcesses.end(); ) {
        if (it->processId == processId) {
            std::cout << "Removed protected process: " << it->processName << std::endl;
            it = protectedProcesses.erase(it);
        } else {
            ++it;
        }
    }
}

// 保护进程
void ProcessProtection::ProtectProcess(DWORD processId) {
    // 这里可以添加进程保护的具体逻辑
    // 例如，设置进程权限、监控进程状态等
    
    // 简化实现，仅输出日志
    ProcessInfo processInfo = GetProcessInfo(processId);
    if (processInfo.processId != 0) {
        // std::cout << "Protecting process: " << processInfo.processName << std::endl;
    }
}

// 检查进程是否存在
bool ProcessProtection::IsProcessRunning(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (hProcess) {
        CloseHandle(hProcess);
        return true;
    }
    return false;
}

// 获取进程信息
ProcessInfo ProcessProtection::GetProcessInfo(DWORD processId) {
    ProcessInfo processInfo = { 0 };
    
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (hProcess) {
        WCHAR path[MAX_PATH];
        if (GetModuleFileNameEx(hProcess, NULL, path, MAX_PATH)) {
            processInfo.processId = processId;
            processInfo.processPath = path;
            processInfo.processName = PathFindFileName(path);
            processInfo.isProtected = true;
        }
        CloseHandle(hProcess);
    }
    
    return processInfo;
}

// =====================================================
// WatchdogGuardian 实现
// =====================================================

WatchdogGuardian::WatchdogGuardian() : 
    isRunning(false),
    missedHeartbeats(0),
    mainProcessId(0),
    hPipe(nullptr) {
}

WatchdogGuardian::~WatchdogGuardian() {
    Stop();
}

// 启动看门狗
bool WatchdogGuardian::Start() {
    if (isRunning) {
        return true;
    }
    
    isRunning = true;
    missedHeartbeats = 0;
    
    // 清除旧的退出标志
    ClearExitFlag();
    
    // 启动管道服务器线程
    pipeServerThread = std::thread(&WatchdogGuardian::PipeServerThread, this);
    
    // 启动看门狗监控线程
    watchdogThread = std::thread(&WatchdogGuardian::WatchdogThread, this);
    
    std::cout << "[WatchdogGuardian] Started" << std::endl;
    return true;
}

// 停止看门狗
void WatchdogGuardian::Stop() {
    isRunning = false;
    
    // 等待线程结束
    if (watchdogThread.joinable()) {
        watchdogThread.join();
    }
    
    if (pipeServerThread.joinable()) {
        pipeServerThread.join();
    }
    
    // 关闭管道
    if (hPipe && hPipe != INVALID_HANDLE_VALUE) {
        CloseHandle(hPipe);
        hPipe = nullptr;
    }
    
    std::cout << "[WatchdogGuardian] Stopped" << std::endl;
}

// 管道服务器线程
void WatchdogGuardian::PipeServerThread() {
    while (isRunning) {
        try {
            // 创建命名管道
            hPipe = CreateNamedPipe(
                L"\\\\.\\pipe\\" WATCHDOG_PIPE_NAME,
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                4096,
                4096,
                0,
                nullptr
            );
            
            if (hPipe == INVALID_HANDLE_VALUE) {
                std::cerr << "[WatchdogGuardian] CreateNamedPipe failed: " << GetLastError() << std::endl;
                std::this_thread::sleep_for(std::chrono::seconds(1));
                continue;
            }
            
            // 等待客户端连接
            if (ConnectNamedPipe(hPipe, nullptr) || GetLastError() == ERROR_PIPE_CONNECTED) {
                // 读取客户端消息
                char buffer[4096];
                DWORD bytesRead;
                
                while (isRunning) {
                    if (ReadFile(hPipe, buffer, sizeof(buffer) - 1, &bytesRead, nullptr) && bytesRead > 0) {
                        buffer[bytesRead] = '\0';
                        HandleClientMessage(std::string(buffer, bytesRead));
                    } else {
                        break;
                    }
                }
            }
            
            CloseHandle(hPipe);
            hPipe = nullptr;
        } catch (const std::exception& e) {
            std::cerr << "[WatchdogGuardian] Pipe server error: " << e.what() << std::endl;
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

// 处理客户端消息
void WatchdogGuardian::HandleClientMessage(const std::string& message) {
    try {
        json msg = json::parse(message);
        
        std::string action = msg.value("Action", "");
        std::string processType = msg.value("ProcessType", "");
        int processId = msg.value("ProcessId", 0);
        std::string mainPath = msg.value("MainProcessPath", "");
        
        std::cout << "[WatchdogGuardian] Received message: " << action << " from " << processType << std::endl;
        
        if (action == "Heartbeat") {
            // 收到心跳，重置计数器
            missedHeartbeats = 0;
            
            // 更新主进程信息
            if (processId > 0 && !mainPath.empty()) {
                mainProcessId = processId;
                mainProcessPath = std::wstring(mainPath.begin(), mainPath.end());
            }
            
            // 发送响应
            SendHeartbeatResponse();
        }
        else if (action == "Register") {
            // 注册主进程
            mainProcessId = processId;
            mainProcessPath = std::wstring(mainPath.begin(), mainPath.end());
            missedHeartbeats = 0;
            
            std::cout << "[WatchdogGuardian] Main process registered: PID=" << processId << std::endl;
        }
        else if (action == "Exit") {
            // 主进程请求退出
            std::cout << "[WatchdogGuardian] Main process requested exit" << std::endl;
            CreateExitFlag();
            isRunning = false;
        }
    } catch (const std::exception& e) {
        std::cerr << "[WatchdogGuardian] Error parsing message: " << e.what() << std::endl;
    }
}

// 看门狗监控线程
void WatchdogGuardian::WatchdogThread() {
    while (isRunning) {
        try {
            // 检查退出标志
            if (ShouldExit()) {
                std::cout << "[WatchdogGuardian] Exit flag detected, stopping" << std::endl;
                isRunning = false;
                break;
            }
            
            // 检查主进程心跳
            if (missedHeartbeats >= HEARTBEAT_TIMEOUT_COUNT) {
                // 主进程可能已退出，检查进程是否存在
                if (mainProcessId > 0 && !IsMainProcessRunning()) {
                    std::cout << "[WatchdogGuardian] Main process died, attempting restart" << std::endl;
                    
                    // 重启主进程
                    if (!RestartMainProcess()) {
                        std::cerr << "[WatchdogGuardian] Failed to restart main process" << std::endl;
                    }
                }
                
                missedHeartbeats = 0;
            }
            
            missedHeartbeats++;
            std::this_thread::sleep_for(std::chrono::milliseconds(HEARTBEAT_INTERVAL_MS));
        } catch (const std::exception& e) {
            std::cerr << "[WatchdogGuardian] Watchdog thread error: " << e.what() << std::endl;
        }
    }
}

// 重启主进程
bool WatchdogGuardian::RestartMainProcess() {
    if (mainProcessPath.empty()) {
        std::cerr << "[WatchdogGuardian] No main process path to restart" << std::endl;
        return false;
    }
    
    STARTUPINFO si = { sizeof(STARTUPINFO) };
    PROCESS_INFORMATION pi;
    
    // 隐藏窗口启动
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    if (CreateProcess(
        mainProcessPath.c_str(),
        nullptr,
        nullptr,
        nullptr,
        FALSE,
        CREATE_NEW_CONSOLE,
        nullptr,
        nullptr,
        &si,
        &pi
    )) {
        std::cout << "[WatchdogGuardian] Restarted main process: PID=" << pi.dwProcessId << std::endl;
        mainProcessId = pi.dwProcessId;
        
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return true;
    }
    
    std::cerr << "[WatchdogGuardian] CreateProcess failed: " << GetLastError() << std::endl;
    return false;
}

// 检查主进程是否运行
bool WatchdogGuardian::IsMainProcessRunning() {
    if (mainProcessId == 0) {
        return false;
    }
    
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, mainProcessId);
    if (hProcess) {
        DWORD exitCode;
        bool isRunning = GetExitCodeProcess(hProcess, &exitCode) && exitCode == STILL_ACTIVE;
        CloseHandle(hProcess);
        return isRunning;
    }
    
    return false;
}

// 检查退出标志
bool WatchdogGuardian::ShouldExit() {
    if (exitFlagPath.empty()) {
        return false;
    }
    
    DWORD attrib = GetFileAttributes(exitFlagPath.c_str());
    return attrib != INVALID_FILE_ATTRIBUTES;
}

// 创建退出标志文件
void WatchdogGuardian::CreateExitFlag() {
    if (exitFlagPath.empty()) {
        return;
    }
    
    try {
        std::ofstream file(exitFlagPath);
        if (file.is_open()) {
            auto now = std::chrono::system_clock::now();
            auto time = std::chrono::system_clock::to_time_t(now);
            file << std::ctime(&time);
            file.close();
        }
    } catch (...) {}
}

// 清除退出标志文件
void WatchdogGuardian::ClearExitFlag() {
    if (exitFlagPath.empty()) {
        return;
    }
    
    DeleteFile(exitFlagPath.c_str());
}

// 发送心跳响应
void WatchdogGuardian::SendHeartbeatResponse() {
    // 简单的响应，主进程知道守护进程还在运行即可
}

// 注册主进程
void WatchdogGuardian::RegisterMainProcess(DWORD processId, const std::wstring& processPath) {
    mainProcessId = processId;
    mainProcessPath = processPath;
    missedHeartbeats = 0;
    
    std::cout << "[WatchdogGuardian] Registered main process: PID=" << processId << std::endl;
}

// 请求退出
void WatchdogGuardian::RequestExit() {
    CreateExitFlag();
    isRunning = false;
}
