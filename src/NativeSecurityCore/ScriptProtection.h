// ScriptProtection.h

#pragma once

#include "pch.h"

class ScriptProtection {
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
    
    // 监控脚本执行
    void MonitorScriptExecution();
    
    // 检查脚本是否恶意
    bool IsMaliciousScript(const std::wstring& scriptPath);
    
    // 阻止脚本执行
    bool BlockScriptExecution(const std::wstring& scriptPath);
    
public:
    ScriptProtection();
    ~ScriptProtection();
    
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
    
    // 扫描脚本
    bool ScanScript(const std::wstring& scriptPath, ThreatInfo& threatInfo);
};