// FileProtection.h

#pragma once

#include "pch.h"

class FileProtection {
private:
    bool isEnabled;
    bool isInitialized;
    
    // ETW相关
    REGHANDLE etwSession;
    
    // 监控线程
    std::thread monitoringThread;
    std::atomic<bool> isMonitoring;
    
    // 回调函数
    std::function<void(const ThreatInfo&)> threatCallback;
    
    // 初始化ETW会话
    bool InitializeETW();
    
    // 清理ETW会话
    void CleanupETW();
    
    // 监控线程函数
    void MonitoringThread();
    
    // 处理文件事件
    void ProcessFileEvent(const std::wstring& filePath, DWORD processId);
    
    // 计算文件哈希
    std::string CalculateFileHash(const std::wstring& filePath);
    
    // 检查文件是否恶意
    bool IsMaliciousFile(const std::wstring& filePath, const std::string& hash);
    
    // 阻断文件操作
    bool BlockFileOperation(const std::wstring& filePath);
    
    // 隔离文件
    bool QuarantineFile(const std::wstring& filePath);
    
public:
    FileProtection();
    ~FileProtection();
    
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
    
    // 扫描文件
    bool ScanFile(const std::wstring& filePath, ThreatInfo& threatInfo);
    
    // 扫描目录
    bool ScanDirectory(const std::wstring& directoryPath, bool recursive, std::vector<ThreatInfo>& threatInfos);
};