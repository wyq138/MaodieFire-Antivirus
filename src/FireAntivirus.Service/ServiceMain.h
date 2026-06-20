// ServiceMain.h

#pragma once

#include "pch.h"

class ServiceMain {
private:
    static ServiceMain* instance;
    static std::mutex instanceMutex;
    
    // 服务状态
    SERVICE_STATUS serviceStatus;
    SERVICE_STATUS_HANDLE serviceStatusHandle;
    ServiceState currentState;
    
    // 停止事件
    HANDLE stopEvent;
    
    // 监控线程
    std::thread monitoringThread;
    std::atomic<bool> isMonitoring;
    
    // 进程保护
    class ProcessProtection* processProtection;
    
    // 进程间通信
    class InterprocessCommunication* ipc;
    
    // 看门狗守护
    class WatchdogGuardian* watchdogGuardian;
    
    // 私有构造函数
    ServiceMain();
    ~ServiceMain();
    
    // 服务主函数
    static void WINAPI ServiceMainFunction(DWORD argc, LPTSTR* argv);
    
    // 服务控制处理函数
    static DWORD WINAPI ServiceControlHandler(DWORD control, DWORD eventType, LPVOID eventData, LPVOID context);
    
    // 启动服务
    bool StartServiceInternal();
    
    // 停止服务
    void StopServiceInternal();
    
    // 监控线程函数
    void MonitoringThread();
    
    // 安装服务
    static bool InstallService();
    
    // 卸载服务
    static bool UninstallService();
    
    // 运行服务
    static void RunService();
    
    // 显示帮助信息
    static void ShowHelp();
    
public:
    // 获取单例实例
    static ServiceMain* GetInstance();
    
    // 初始化服务
    bool Initialize();
    
    // 运行服务
    void Run(int argc, char* argv[]);
    
    // 启动服务
    bool Start();
    
    // 停止服务
    void Stop();
    
    // 检查服务状态
    ServiceState GetState() const;
    
    // 发送服务状态
    void SetServiceStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint);
};
