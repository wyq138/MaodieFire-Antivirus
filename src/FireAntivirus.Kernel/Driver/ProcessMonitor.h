#pragma once

#include <ntddk.h>
#include <wdm.h>

// 保护标志定义
#define PROCESS_PROTECTION_BASIC        0x00000001
#define PROCESS_PROTECTION_MEMORY       0x00000002
#define PROCESS_PROTECTION_THREAD       0x00000004
#define PROCESS_PROTECTION_FULL         0x00000007

// 安全事件类型
typedef enum _SECURITY_EVENT_TYPE {
    PROCESS_CREATION = 1,
    PROCESS_TERMINATION,
    PROCESS_ACCESS_ATTEMPT,
    THREAD_INJECTION_ATTEMPT,
    MEMORY_ACCESS_VIOLATION,
    UNPROTECTED_PROCESS_MODIFICATION
} SECURITY_EVENT_TYPE;

class ProcessMonitor
{
public:
    ProcessMonitor();
    ~ProcessMonitor();

    // 初始化/清理
    NTSTATUS Initialize();
    VOID Cleanup();

    // 进程保护管理
    NTSTATUS ProtectProcess(PULONG ProcessId);
    NTSTATUS UnprotectProcess(PULONG ProcessId);
    BOOLEAN IsProcessProtected(ULONG ProcessId);

private:
    // 回调函数
    static OB_PREOP_CALLBACK_STATUS ProcessPreOperationCallback(
        PVOID RegistrationContext, 
        POB_PRE_OPERATION_INFORMATION OperationInfo);
    
    static OB_PREOP_CALLBACK_STATUS ThreadPreOperationCallback(
        PVOID RegistrationContext, 
        POB_PRE_OPERATION_INFORMATION OperationInfo);

    // 内部功能
    NTSTATUS RegisterThreadCallbacks();
    VOID LogSecurityEvent(ULONG ProcessId, SECURITY_EVENT_TYPE EventType, ULONG Operation);
    VOID ClearProtectedProcessList();

    // 进程验证
    BOOLEAN ValidateProcessImage(PEPROCESS Process);
    BOOLEAN CheckProcessIntegrity(PEPROCESS Process);
    
    // 辅助函数
    static NTSTATUS GetProcessImageName(PEPROCESS Process, PWCHAR Buffer, ULONG BufferSize);
};

// 全局回调声明
extern "C" {
    OB_PREOP_CALLBACK_STATUS ProcessCreateCallback(
        PVOID RegistrationContext, 
        POB_PRE_OPERATION_INFORMATION OperationInformation);
        
    OB_PREOP_CALLBACK_STATUS ProcessTerminateCallback(
        PVOID RegistrationContext, 
        POB_PRE_OPERATION_INFORMATION OperationInformation);
}