// DeviceProtection.cpp

#include "pch.h"
#include "DeviceProtection.h"

DeviceProtection::DeviceProtection() : 
    isEnabled(false),
    isInitialized(false),
    hWnd(nullptr),
    isMonitoring(false) {
}

DeviceProtection::~DeviceProtection() {
    Cleanup();
}

// 初始化
bool DeviceProtection::Initialize() {
    if (isInitialized) {
        return true;
    }
    
    isInitialized = true;
    return true;
}

// 清理
void DeviceProtection::Cleanup() {
    if (!isInitialized) {
        return;
    }
    
    // 停止监控
    Enable(false);
    
    isInitialized = false;
}

// 启用/禁用
bool DeviceProtection::Enable(bool enable) {
    if (!isInitialized) {
        return false;
    }
    
    if (isEnabled == enable) {
        return true;
    }
    
    if (enable) {
        // 启动监控线程
        isMonitoring = true;
        monitoringThread = std::thread(&DeviceProtection::MonitoringThread, this);
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
bool DeviceProtection::IsEnabled() const {
    return isEnabled;
}

// 检查是否初始化
bool DeviceProtection::IsInitialized() const {
    return isInitialized;
}

// 设置威胁回调函数
void DeviceProtection::SetThreatCallback(std::function<void(const ThreatInfo&)> callback) {
    threatCallback = callback;
}

// 扫描指定设备
bool DeviceProtection::ScanDevice(const std::wstring& devicePath, ThreatInfo& threatInfo) {
    try {
        // 检查设备是否存在
        if (GetDriveType(devicePath.c_str()) == DRIVE_UNKNOWN) {
            return false;
        }
        
        // 检查设备是否授权
        if (!IsAuthorizedDevice(devicePath)) {
            // 填充威胁信息
            threatInfo.type = ThreatType::DEVICE_UNAUTHORIZED;
            wcsncpy_s(threatInfo.processPath, devicePath.c_str(), _TRUNCATE);
            wcsncpy_s(threatInfo.targetPath, devicePath.c_str(), _TRUNCATE);
            wcsncpy_s(threatInfo.threatDescription, L"Unauthorized device detected", _TRUNCATE);
            threatInfo.processId = GetCurrentProcessId();
            threatInfo.threadId = GetCurrentThreadId();
            
            return true;
        }
        
        // 这里应该扫描设备上的文件
        // 由于实现较为复杂，这里只做简单的模拟
        
        return false;
    } catch (const std::exception& e) {
        std::cerr << "Error scanning device: " << e.what() << std::endl;
        return false;
    }
}

// 扫描所有设备
bool DeviceProtection::ScanAllDevices(std::vector<ThreatInfo>& threatInfos) {
    try {
        // 枚举所有设备
        EnumDevices();
        
        // 这里应该扫描所有设备
        // 由于实现较为复杂，这里只做简单的模拟
        
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error scanning all devices: " << e.what() << std::endl;
        return false;
    }
}

// 监控线程函数
void DeviceProtection::MonitoringThread() {
    while (isMonitoring) {
        try {
            // 枚举所有设备
            EnumDevices();
            
            // 休眠一段时间
            std::this_thread::sleep_for(std::chrono::seconds(5));
        } catch (const std::exception& e) {
            std::cerr << "Error in device protection monitoring thread: " << e.what() << std::endl;
        }
    }
}

// 处理设备事件
void DeviceProtection::ProcessDeviceEvent(DWORD eventType, const std::wstring& devicePath) {
    try {
        switch (eventType) {
        case DBT_DEVICEARRIVAL:
            // 设备插入
            std::wcout << L"Device inserted: " << devicePath << std::endl;
            
            // 检查设备是否授权
            if (!IsAuthorizedDevice(devicePath)) {
                // 填充威胁信息
                ThreatInfo threatInfo;
                threatInfo.type = ThreatType::DEVICE_UNAUTHORIZED;
                wcsncpy_s(threatInfo.processPath, devicePath.c_str(), _TRUNCATE);
                wcsncpy_s(threatInfo.targetPath, devicePath.c_str(), _TRUNCATE);
                wcsncpy_s(threatInfo.threatDescription, L"Unauthorized device detected", _TRUNCATE);
                threatInfo.processId = GetCurrentProcessId();
                threatInfo.threadId = GetCurrentThreadId();
                
                // 调用回调函数
                if (threatCallback) {
                    threatCallback(threatInfo);
                }
                
                // 阻止设备访问
                BlockDeviceAccess(devicePath);
            } else {
                // 扫描设备
                std::vector<ThreatInfo> threatInfos;
                ScanDevice(devicePath, threatInfos);
                
                // 处理扫描结果
                for (const auto& threat : threatInfos) {
                    if (threatCallback) {
                        threatCallback(threat);
                    }
                }
            }
            break;
        
        case DBT_DEVICEREMOVECOMPLETE:
            // 设备拔出
            std::wcout << L"Device removed: " << devicePath << std::endl;
            break;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error processing device event: " << e.what() << std::endl;
    }
}

// 枚举所有设备
void DeviceProtection::EnumDevices() {
    try {
        // 枚举所有逻辑驱动器
        WCHAR drives[256];
        if (GetLogicalDriveStrings(sizeof(drives), drives)) {
            WCHAR* drive = drives;
            while (*drive) {
                // 检查驱动器类型
                UINT driveType = GetDriveType(drive);
                if (driveType == DRIVE_REMOVABLE) {
                    // 可移动设备
                    std::wstring devicePath = drive;
                    ProcessDeviceEvent(DBT_DEVICEARRIVAL, devicePath);
                }
                
                // 移动到下一个驱动器
                drive += wcslen(drive) + 1;
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Error enumerating devices: " << e.what() << std::endl;
    }
}

// 检查设备是否授权
bool DeviceProtection::IsAuthorizedDevice(const std::wstring& devicePath) {
    try {
        // 这里需要实现设备授权的检查逻辑
        // 由于实现较为复杂，这里只做简单的模拟
        
        // 随机返回结果
        return rand() % 100 < 95; // 95%的概率认为是授权设备
    } catch (const std::exception& e) {
        std::cerr << "Error checking authorized device: " << e.what() << std::endl;
        return false;
    }
}

// 阻止设备访问
bool DeviceProtection::BlockDeviceAccess(const std::wstring& devicePath) {
    try {
        // 这里需要实现设备访问的阻止逻辑
        // 由于实现较为复杂，这里只做简单的模拟
        std::wcout << L"Blocking device access: " << devicePath << std::endl;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error blocking device access: " << e.what() << std::endl;
        return false;
    }
}

// 扫描设备
bool DeviceProtection::ScanDevice(const std::wstring& devicePath, std::vector<ThreatInfo>& threatInfos) {
    try {
        // 这里需要实现设备的扫描逻辑
        // 由于实现较为复杂，这里只做简单的模拟
        
        // 模拟发现威胁
        if (rand() % 100 < 10) { // 10%的概率发现威胁
            ThreatInfo threatInfo;
            threatInfo.type = ThreatType::FILE_MALICIOUS;
            wcsncpy_s(threatInfo.processPath, devicePath.c_str(), _TRUNCATE);
            wcsncpy_s(threatInfo.targetPath, (devicePath + L"\\malicious.exe").c_str(), _TRUNCATE);
            wcsncpy_s(threatInfo.threatDescription, L"Malicious file detected on device", _TRUNCATE);
            threatInfo.processId = GetCurrentProcessId();
            threatInfo.threadId = GetCurrentThreadId();
            
            threatInfos.push_back(threatInfo);
        }
        
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error scanning device: " << e.what() << std::endl;
        return false;
    }
}