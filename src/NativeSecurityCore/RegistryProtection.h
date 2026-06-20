// RegistryProtection.h

#pragma once

#include "pch.h"

class RegistryProtection {
private:
    bool isEnabled;
    bool isInitialized;
    
    // 监控线程
    std::thread monitoringThread;
    std::atomic<bool> isMonitoring;
    
    // 回调函数
    std::function<void(const ThreatInfo&)> threatCallback;
    
    // 监控线程函数
    void MonitoringThread();
    
    // 监控注册表操作
    void MonitorRegistryOperations();
    
    // 检查注册表操作是否恶意
    bool IsMaliciousRegistryOperation(HKEY hKey, const std::wstring& subKey, const std::wstring& valueName);
    
    // 阻止注册表操作
    bool BlockRegistryOperation(HKEY hKey, const std::wstring& subKey, const std::wstring& valueName);
    
public:
    RegistryProtection();
    ~RegistryProtection();
    
    // 初始化
    bool Initialize();
    
    // 清理
    void Cleanup();
    
    // 启用/禁用
    bool Enable(bool enable);
    
    // 检查是否启用
    bool IsEnabled() const;
    
    // 检查是否初始化
    bool IsInitialized() const;
    
    // 设置威胁回调函数
    void SetThreatCallback(std::function<void(const ThreatInfo&)> callback);
    
    // 扫描注册表
    bool ScanRegistry(ThreatInfo& threatInfo);
};