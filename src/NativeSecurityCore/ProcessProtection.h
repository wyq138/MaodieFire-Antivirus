// ProcessProtection.h

#pragma once

#include "pch.h"

class ProcessProtection {
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
    
    // 枚举所有进程
    void EnumProcesses();
    
    // 分析进程
    void AnalyzeProcess(DWORD processId);
    
    // 获取进程路径
    std::wstring GetProcessPath(DWORD processId);
    
    // 获取进程名称
    std::wstring GetProcessName(DWORD processId);
    
    // 检查进程是否恶意
    bool IsMaliciousProcess(DWORD processId, const std::wstring& processPath);
    
    // 终止进程
    bool TerminateMaliciousProcess(DWORD processId);
    
    // 阻止进程启动
    bool BlockProcessStartup(const std::wstring& processPath);
    
public:
    ProcessProtection();
    ~ProcessProtection();
    
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
    
    // 扫描进程
    bool ScanProcess(DWORD processId, ThreatInfo& threatInfo);
    
    // 扫描所有进程
    bool ScanAllProcesses(std::vector<ThreatInfo>& threatInfos);
};