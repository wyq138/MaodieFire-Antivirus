// ProcessProtection.h

#pragma once

#include "pch.h"

// 看门狗配置
#define HEARTBEAT_INTERVAL_MS 3000
#define HEARTBEAT_TIMEOUT_COUNT 3
#define WATCHDOG_PIPE_NAME L"FireAntivirus_Watchdog"
#define EXIT_FLAG_FILE L"exit_flag.dat"

class ProcessProtection {
private:
    bool isEnabled;
    bool isInitialized;
    
    // 互斥体
    HANDLE protectionMutex;
    
    // 监控线程
    std::thread monitoringThread;
    std::atomic<bool> isMonitoring;
    
    // 受保护的进程列表
    std::vector<ProcessInfo> protectedProcesses;
    std::mutex processesMutex;
    
    // 监控线程函数
    void MonitoringThread();
    
    // 枚举所有进程
    void EnumProcesses();
    
    // 检查进程是否受保护
    bool IsProtectedProcess(DWORD processId);
    
    // 添加受保护进程
    void AddProtectedProcess(DWORD processId);
    
    // 移除受保护进程
    void RemoveProtectedProcess(DWORD processId);
    
    // 保护进程
    void ProtectProcess(DWORD processId);
    
    // 检查进程是否存在
    bool IsProcessRunning(DWORD processId);
    
    // 获取进程信息
    ProcessInfo GetProcessInfo(DWORD processId);
    
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
    
    // 更新保护状态
    void Update();
    
    // 添加受保护进程
    bool AddProtectedProcess(const std::wstring& processPath);
    
    // 移除受保护进程
    bool RemoveProtectedProcess(const std::wstring& processPath);
    
    // 获取受保护进程列表
    std::vector<ProcessInfo> GetProtectedProcesses();
};

// 看门狗守护类 - 监控主进程并在其退出时重启
class WatchdogGuardian {
private:
    std::atomic<bool> isRunning;
    std::atomic<int> missedHeartbeats;
    std::thread watchdogThread;
    std::thread pipeServerThread;
    
    // 主进程信息
    DWORD mainProcessId;
    std::wstring mainProcessPath;
    
    // 命名管道
    HANDLE hPipe;
    std::mutex pipeMutex;
    
    // 退出标志文件路径
    std::wstring exitFlagPath;
    
    // 监控线程函数
    void WatchdogThread();
    
    // 管道服务器线程
    void PipeServerThread();
    
    // 处理客户端消息
    void HandleClientMessage(const std::string& message);
    
    // 重启主进程
    bool RestartMainProcess();
    
    // 检查退出标志
    bool ShouldExit();
    
    // 创建退出标志文件
    void CreateExitFlag();
    
    // 清除退出标志文件
    void ClearExitFlag();
    
    // 发送心跳响应
    void SendHeartbeatResponse();
    
public:
    WatchdogGuardian();
    ~WatchdogGuardian();
    
    // 启动看门狗
    bool Start();
    
    // 停止看门狗
    void Stop();
    
    // 注册主进程
    void RegisterMainProcess(DWORD processId, const std::wstring& processPath);
    
    // 检查主进程是否运行
    bool IsMainProcessRunning();
    
    // 请求退出
    void RequestExit();
};
