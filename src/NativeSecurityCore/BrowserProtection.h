// BrowserProtection.h

#pragma once

#include "pch.h"

class BrowserProtection {
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
    
    // 监控浏览器进程
    void MonitorBrowserProcesses();
    
    // 检查浏览器是否被篡改
    bool IsBrowserTampered(DWORD processId, const std::wstring& processPath);
    
    // 修复浏览器设置
    bool FixBrowserSettings(DWORD processId, const std::wstring& processPath);
    
public:
    BrowserProtection();
    ~BrowserProtection();
    
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
    
    // 扫描浏览器
    bool ScanBrowser(ThreatInfo& threatInfo);
};