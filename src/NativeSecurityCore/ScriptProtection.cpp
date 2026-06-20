// ScriptProtection.cpp

#include "pch.h"
#include "ScriptProtection.h"

ScriptProtection::ScriptProtection() : 
    isEnabled(false),
    isInitialized(false),
    isMonitoring(false) {
}

ScriptProtection::~ScriptProtection() {
    Cleanup();
}

// 初始化
bool ScriptProtection::Initialize() {
    if (isInitialized) {
        return true;
    }
    
    isInitialized = true;
    return true;
}

// 清理
void ScriptProtection::Cleanup() {
    if (!isInitialized) {
        return;
    }
    
    // 停止监控
    Enable(false);
    
    isInitialized = false;
}

// 启用/禁用
bool ScriptProtection::Enable(bool enable) {
    if (!isInitialized) {
        return false;
    }
    
    if (isEnabled == enable) {
        return true;
    }
    
    if (enable) {
        // 启动监控线程
        isMonitoring = true;
        monitoringThread = std::thread(&ScriptProtection::MonitoringThread, this);
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
bool ScriptProtection::IsEnabled() const {
    return isEnabled;
}

// 检查是否初始化
bool ScriptProtection::IsInitialized() const {
    return isInitialized;
}

// 设置威胁回调函数
void ScriptProtection::SetThreatCallback(std::function<void(const ThreatInfo&)> callback) {
    threatCallback = callback;
}

// 扫描脚本
bool ScriptProtection::ScanScript(const std::wstring& scriptPath, ThreatInfo& threatInfo) {
    try {
        // 检查脚本是否存在
        if (GetFileAttributes(scriptPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
            return false;
        }
        
        // 检查脚本是否恶意
        if (IsMaliciousScript(scriptPath)) {
            // 填充威胁信息
            threatInfo.type = ThreatType::SCRIPT_MALICIOUS;
            wcsncpy_s(threatInfo.processPath, scriptPath.c_str(), _TRUNCATE);
            wcsncpy_s(threatInfo.targetPath, scriptPath.c_str(), _TRUNCATE);
            wcsncpy_s(threatInfo.threatDescription, L"Malicious script detected", _TRUNCATE);
            threatInfo.processId = GetCurrentProcessId();
            threatInfo.threadId = GetCurrentThreadId();
            
            return true;
        }
        
        return false;
    } catch (const std::exception& e) {
        std::cerr << "Error scanning script: " << e.what() << std::endl;
        return false;
    }
}

// 监控线程函数
void ScriptProtection::MonitoringThread() {
    while (isMonitoring) {
        try {
            // 监控脚本执行
            MonitorScriptExecution();
            
            // 休眠一段时间
            std::this_thread::sleep_for(std::chrono::seconds(1));
        } catch (const std::exception& e) {
            std::cerr << "Error in script protection monitoring thread: " << e.what() << std::endl;
        }
    }
}

// 监控脚本执行
void ScriptProtection::MonitorScriptExecution() {
    try {
        // 这里需要实现脚本执行的监控
        // 由于实现较为复杂，这里只做简单的模拟
        
        // 模拟脚本执行
        std::wstring scriptPath = L"C:\\test\\malicious.js";
        
        // 检查脚本是否恶意
        if (IsMaliciousScript(scriptPath)) {
            // 填充威胁信息
            ThreatInfo threatInfo;
            threatInfo.type = ThreatType::SCRIPT_MALICIOUS;
            wcsncpy_s(threatInfo.processPath, scriptPath.c_str(), _TRUNCATE);
            wcsncpy_s(threatInfo.targetPath, scriptPath.c_str(), _TRUNCATE);
            wcsncpy_s(threatInfo.threatDescription, L"Malicious script detected", _TRUNCATE);
            threatInfo.processId = GetCurrentProcessId();
            threatInfo.threadId = GetCurrentThreadId();
            
            // 调用回调函数
            if (threatCallback) {
                threatCallback(threatInfo);
            }
            
            // 阻止脚本执行
            BlockScriptExecution(scriptPath);
        }
    } catch (const std::exception& e) {
        std::cerr << "Error monitoring script execution: " << e.what() << std::endl;
    }
}

// 检查脚本是否恶意
bool ScriptProtection::IsMaliciousScript(const std::wstring& scriptPath) {
    try {
        // 检查脚本扩展名
        std::wstring extension = scriptPath.substr(scriptPath.find_last_of(L".") + 1);
        std::transform(extension.begin(), extension.end(), extension.begin(), ::towlower);
        
        // 检查是否是脚本文件
        if (extension == L"js" || extension == L"vbs" || extension == L"ps1" ||
            extension == L"bat" || extension == L"cmd" || extension == L"sh") {
            // 这里需要实现脚本内容的分析
            // 由于实现较为复杂，这里只做简单的模拟
            
            // 随机返回结果
            return rand() % 100 < 15; // 15%的概率认为是恶意脚本
        }
        
        return false;
    } catch (const std::exception& e) {
        std::cerr << "Error checking malicious script: " << e.what() << std::endl;
        return false;
    }
}

// 阻止脚本执行
bool ScriptProtection::BlockScriptExecution(const std::wstring& scriptPath) {
    try {
        // 这里需要实现脚本执行的阻止逻辑
        // 由于实现较为复杂，这里只做简单的模拟
        std::wcout << L"Blocking script execution: " << scriptPath << std::endl;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error blocking script execution: " << e.what() << std::endl;
        return false;
    }
}