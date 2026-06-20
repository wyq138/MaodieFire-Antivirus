// ActiveDefense.h

#pragma once

#include "pch.h"

class ActiveDefense {
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
    
    // 分析进程行为
    void AnalyzeProcessBehavior(DWORD processId);
    
    // 检查是否是恶意行为
    bool IsMaliciousBehavior(DWORD processId);
    
    // 获取进程路径
    std::wstring GetProcessPath(DWORD processId);
    
    // 获取进程名称
    std::wstring GetProcessName(DWORD processId);
    
    // 获取系统目录
    std::wstring GetSystemDirectory();
    
    // 获取Windows目录
    std::wstring GetWindowsDirectory();
    
    // 记录日志
    void Log(const std::wstring& message);
    
    // 记录错误日志
    void LogError(const std::wstring& message);
    
    // 记录警告日志
    void LogWarning(const std::wstring& message);
    
public:
    ActiveDefense();
    ~ActiveDefense();
    
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
};