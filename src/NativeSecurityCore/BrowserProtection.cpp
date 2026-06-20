// BrowserProtection.cpp

#include "pch.h"
#include "BrowserProtection.h"

BrowserProtection::BrowserProtection() : 
    isEnabled(false),
    isInitialized(false),
    isMonitoring(false) {
}

BrowserProtection::~BrowserProtection() {
    Cleanup();
}

// 初始化
bool BrowserProtection::Initialize() {
    if (isInitialized) {
        return true;
    }
    
    isInitialized = true;
    return true;
}

// 清理
void BrowserProtection::Cleanup() {
    if (!isInitialized) {
        return;
    }
    
    // 停止监控
    Enable(false);
    
    isInitialized = false;
}

// 启用/禁用
bool BrowserProtection::Enable(bool enable) {
    if (!isInitialized) {
        return false;
    }
    
    if (isEnabled == enable) {
        return true;
    }
    
    if (enable) {
        // 启动监控线程
        isMonitoring = true;
        monitoringThread = std::thread(&BrowserProtection::MonitoringThread, this);
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
bool BrowserProtection::IsEnabled() const {
    return isEnabled;
}

// 检查是否初始化
bool BrowserProtection::IsInitialized() const {
    return isInitialized;
}

// 设置威胁回调函数
void BrowserProtection::SetThreatCallback(std::function<void(const ThreatInfo&)> callback) {
    threatCallback = callback;
}

// 扫描浏览器
bool BrowserProtection::ScanBrowser(ThreatInfo& threatInfo) {
    try {
        // 这里需要实现浏览器的扫描逻辑
        // 由于实现较为复杂，这里只做简单的模拟
        
        // 模拟发现威胁
        if (rand() % 100 < 8) { // 8%的概率发现威胁
            threatInfo.type = ThreatType::BROWSER_TAMPERING;
            wcsncpy_s(threatInfo.processPath, L"Browser", _TRUNCATE);
            wcsncpy_s(threatInfo.targetPath, L"Browser settings", _TRUNCATE);
            wcsncpy_s(threatInfo.threatDescription, L"Browser tampering detected", _TRUNCATE);
            threatInfo.processId = GetCurrentProcessId();
            threatInfo.threadId = GetCurrentThreadId();
            
            return true;
        }
        
        return false;
    } catch (const std::exception& e) {
        std::cerr << "Error scanning browser: " << e.what() << std::endl;
        return false;
    }
}

// 监控线程函数
void BrowserProtection::MonitoringThread() {
    while (isMonitoring) {
        try {
            // 监控浏览器进程
            MonitorBrowserProcesses();
            
            // 休眠一段时间
            std::this_thread::sleep_for(std::chrono::seconds(2));
        } catch (const std::exception& e) {
            std::cerr << "Error in browser protection monitoring thread: " << e.what() << std::endl;
        }
    }
}

// 监控浏览器进程
void BrowserProtection::MonitorBrowserProcesses() {
    try {
        DWORD processes[1024];
        DWORD cbNeeded;
        
        if (!EnumProcesses(processes, sizeof(processes), &cbNeeded)) {
            return;
        }
        
        DWORD processCount = cbNeeded / sizeof(DWORD);
        
        for (DWORD i = 0; i < processCount; i++) {
            DWORD processId = processes[i];
            if (processId != 0) {
                // 获取进程路径
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
                if (hProcess) {
                    WCHAR path[MAX_PATH];
                    if (GetModuleFileNameEx(hProcess, NULL, path, MAX_PATH)) {
                        std::wstring processPath = path;
                        std::wstring processName = PathFindFileName(path);
                        
                        // 检查是否是浏览器进程
                        std::transform(processName.begin(), processName.end(), processName.begin(), ::towlower);
                        if (processName.find(L"chrome.exe") != std::wstring::npos ||
                            processName.find(L"firefox.exe") != std::wstring::npos ||
                            processName.find(L"edge.exe") != std::wstring::npos ||
                            processName.find(L"iexplore.exe") != std::wstring::npos) {
                            // 检查浏览器是否被篡改
                            if (IsBrowserTampered(processId, processPath)) {
                                // 填充威胁信息
                                ThreatInfo threatInfo;
                                threatInfo.type = ThreatType::BROWSER_TAMPERING;
                                wcsncpy_s(threatInfo.processPath, processPath.c_str(), _TRUNCATE);
                                wcsncpy_s(threatInfo.targetPath, processPath.c_str(), _TRUNCATE);
                                wcsncpy_s(threatInfo.threatDescription, L"Browser tampering detected", _TRUNCATE);
                                threatInfo.processId = processId;
                                threatInfo.threadId = GetCurrentThreadId();
                                
                                // 调用回调函数
                                if (threatCallback) {
                                    threatCallback(threatInfo);
                                }
                                
                                // 修复浏览器设置
                                FixBrowserSettings(processId, processPath);
                            }
                        }
                    }
                    CloseHandle(hProcess);
                }
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Error monitoring browser processes: " << e.what() << std::endl;
    }
}

// 检查浏览器是否被篡改
bool BrowserProtection::IsBrowserTampered(DWORD processId, const std::wstring& processPath) {
    try {
        // 这里需要实现浏览器篡改的检测逻辑
        // 由于实现较为复杂，这里只做简单的模拟
        
        // 随机返回结果
        return rand() % 100 < 5; // 5%的概率认为浏览器被篡改
    } catch (const std::exception& e) {
        std::cerr << "Error checking browser tampering: " << e.what() << std::endl;
        return false;
    }
}

// 修复浏览器设置
bool BrowserProtection::FixBrowserSettings(DWORD processId, const std::wstring& processPath) {
    try {
        // 这里需要实现浏览器设置的修复逻辑
        // 由于实现较为复杂，这里只做简单的模拟
        std::wcout << L"Fixing browser settings for: " << processPath << std::endl;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error fixing browser settings: " << e.what() << std::endl;
        return false;
    }
}