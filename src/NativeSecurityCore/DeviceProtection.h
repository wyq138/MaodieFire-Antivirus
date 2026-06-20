// DeviceProtection.h

#pragma once

#include "pch.h"

class DeviceProtection {
private:
    bool isEnabled;
    bool isInitialized;
    
    // 设备通知句柄
    HWND hWnd;
    
    // 监控线程
    std::thread monitoringThread;
    std::atomic<bool> isMonitoring;
    
    // 回调函数
    std::function<void(const ThreatInfo&)> threatCallback;
    
    // 监控线程函数
    void MonitoringThread();
    
    // 处理设备事件
    void ProcessDeviceEvent(DWORD eventType, const std::wstring& devicePath);
    
    // 枚举所有设备
    void EnumDevices();
    
    // 检查设备是否授权
    bool IsAuthorizedDevice(const std::wstring& devicePath);
    
    // 阻止设备访问
    bool BlockDeviceAccess(const std::wstring& devicePath);
    
    // 扫描设备
    bool ScanDevice(const std::wstring& devicePath, std::vector<ThreatInfo>& threatInfos);
    
public:
    DeviceProtection();
    ~DeviceProtection();
    
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
    
    // 扫描指定设备
    bool ScanDevice(const std::wstring& devicePath, ThreatInfo& threatInfo);
    
    // 扫描所有设备
    bool ScanAllDevices(std::vector<ThreatInfo>& threatInfos);
};