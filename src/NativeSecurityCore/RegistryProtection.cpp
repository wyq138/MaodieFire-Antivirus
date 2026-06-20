// RegistryProtection.cpp

#include "pch.h"
#include "RegistryProtection.h"

RegistryProtection::RegistryProtection() : 
    isEnabled(false),
    isInitialized(false),
    isMonitoring(false) {
}

RegistryProtection::~RegistryProtection() {
    Cleanup();
}

// 初始化
bool RegistryProtection::Initialize() {
    if (isInitialized) {
        return true;
    }
    
    isInitialized = true;
    return true;
}

// 清理
void RegistryProtection::Cleanup() {
    if (!isInitialized) {
        return;
    }
    
    // 停止监控
    Enable(false);
    
    isInitialized = false;
}

// 启用/禁用
bool RegistryProtection::Enable(bool enable) {
    if (!isInitialized) {
        return false;
    }
    
    if (isEnabled == enable) {
        return true;
    }
    
    if (enable) {
        // 启动监控线程
        isMonitoring = true;
        monitoringThread = std::thread(&RegistryProtection::MonitoringThread, this);
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
bool RegistryProtection::IsEnabled() const {
    return isEnabled;
}

// 检查是否初始化
bool RegistryProtection::IsInitialized() const {
    return isInitialized;
}

// 设置威胁回调函数
void RegistryProtection::SetThreatCallback(std::function<void(const ThreatInfo&)> callback) {
    threatCallback = callback;
}

// 扫描注册表
bool RegistryProtection::ScanRegistry(ThreatInfo& threatInfo) {
    try {
        // 这里需要实现注册表的扫描逻辑
        // 由于实现较为复杂，这里只做简单的模拟
        
        // 模拟发现威胁
        if (rand() % 100 < 5) { // 5%的概率发现威胁
            threatInfo.type = ThreatType::REGISTRY_TAMPERING;
            wcsncpy_s(threatInfo.processPath, L"Registry", _TRUNCATE);
            wcsncpy_s(threatInfo.targetPath, L"HKLM\\SOFTWARE\\MaliciousKey", _TRUNCATE);
            wcsncpy_s(threatInfo.threatDescription, L"Registry tampering detected", _TRUNCATE);
            threatInfo.processId = GetCurrentProcessId();
            threatInfo.threadId = GetCurrentThreadId();
            
            return true;
        }
        
        return false;
    } catch (const std::exception& e) {
        std::cerr << "Error scanning registry: " << e.what() << std::endl;
        return false;
    }
}

// 监控线程函数
void RegistryProtection::MonitoringThread() {
    while (isMonitoring) {
        try {
            // 监控注册表操作
            MonitorRegistryOperations();
            
            // 休眠一段时间
            std::this_thread::sleep_for(std::chrono::seconds(1));
        } catch (const std::exception& e) {
            std::cerr << "Error in registry protection monitoring thread: " << e.what() << std::endl;
        }
    }
}

// 监控注册表操作
void RegistryProtection::MonitorRegistryOperations() {
    try {
        // 这里需要实现注册表操作的监控
        // 由于实现较为复杂，这里只做简单的模拟
        
        // 模拟注册表操作
        HKEY hKey = HKEY_LOCAL_MACHINE;
        std::wstring subKey = L"SOFTWARE\\Test";
        std::wstring valueName = L"TestValue";
        
        // 检查注册表操作是否恶意
        if (IsMaliciousRegistryOperation(hKey, subKey, valueName)) {
            // 填充威胁信息
            ThreatInfo threatInfo;
            threatInfo.type = ThreatType::REGISTRY_TAMPERING;
            wcsncpy_s(threatInfo.processPath, L"Registry", _TRUNCATE);
            wcsncpy_s(threatInfo.targetPath, (subKey + L"\\" + valueName).c_str(), _TRUNCATE);
            wcsncpy_s(threatInfo.threatDescription, L"Registry tampering detected", _TRUNCATE);
            threatInfo.processId = GetCurrentProcessId();
            threatInfo.threadId = GetCurrentThreadId();
            
            // 调用回调函数
            if (threatCallback) {
                threatCallback(threatInfo);
            }
            
            // 阻止注册表操作
            BlockRegistryOperation(hKey, subKey, valueName);
        }
    } catch (const std::exception& e) {
        std::cerr << "Error monitoring registry operations: " << e.what() << std::endl;
    }
}

// 检查注册表操作是否恶意
bool RegistryProtection::IsMaliciousRegistryOperation(HKEY hKey, const std::wstring& subKey, const std::wstring& valueName) {
    try {
        // 这里需要实现注册表操作的恶意检测逻辑
        // 由于实现较为复杂，这里只做简单的模拟
        
        // 检查是否是敏感的注册表项
        if (subKey.find(L"Microsoft\\Windows\\CurrentVersion\\Run") != std::wstring::npos ||
            subKey.find(L"Microsoft\\Windows\\CurrentVersion\\RunOnce") != std::wstring::npos ||
            subKey.find(L"Microsoft\\Windows\\CurrentVersion\\Policies") != std::wstring::npos) {
            // 随机返回结果
            return rand() % 100 < 10; // 10%的概率认为是恶意操作
        }
        
        return false;
    } catch (const std::exception& e) {
        std::cerr << "Error checking malicious registry operation: " << e.what() << std::endl;
        return false;
    }
}

// 阻止注册表操作
bool RegistryProtection::BlockRegistryOperation(HKEY hKey, const std::wstring& subKey, const std::wstring& valueName) {
    try {
        // 这里需要实现注册表操作的阻止逻辑
        // 由于实现较为复杂，这里只做简单的模拟
        std::wcout << L"Blocking registry operation: " << subKey << L"\\" << valueName << std::endl;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error blocking registry operation: " << e.what() << std::endl;
        return false;
    }
}