#pragma once

#include <ntddk.h>
#include <wdf.h>

// IOCTL控制码定义
#define IOCTL_FIREAV_PROTECT_PROCESS     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_FIREAV_UNPROTECT_PROCESS   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_FIREAV_QUERY_EVENTS        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_FIREAV_SET_POLICY          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

// 防护事件类型定义
typedef enum _PROTECTION_EVENT_TYPE {
    ProcessCreation = 1,
    ProcessTermination,
    FileAccess,
    RegistryAccess,
    NetworkConnection,
    MemoryAccess,
    ThreadInjection,
    DriverLoading
} PROTECTION_EVENT_TYPE;

// 事件数据结构
typedef struct _PROTECTION_EVENT {
    ULONG EventType;
    ULONG ProcessId;
    ULONG ThreadId;
    ULONG64 Timestamp;
    WCHAR ImagePath[256];
    WCHAR Operation[64];
    NTSTATUS Status;
} PROTECTION_EVENT, *PPROTECTION_EVENT;

// 策略配置结构
typedef struct _PROTECTION_POLICY {
    ULONG PolicyId;
    ULONG Flags;
    WCHAR ProcessName[64];
    ULONG AccessRights;
    ULONG BlockActions;
} PROTECTION_POLICY, *PPROTECTION_POLICY;

// 驱动状态结构
typedef struct _DRIVER_STATUS {
    ULONG IsRunning;
    ULONG NumberOfEvents;
    ULONG MemoryUsage;
    ULONG64 Uptime;
} DRIVER_STATUS, *PDRIVER_STATUS;

// 外部可见的函数声明
extern "C" {
    NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
    
    // 内核回调函数
    OB_PREOP_CALLBACK_STATUS ProcessCreateCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation);
    OB_PREOP_CALLBACK_STATUS ProcessTerminateCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation);
    
    // 保护模块初始化/清理
    NTSTATUS InitializeProtectionModules();
    VOID CleanupProtectionModules();
    
    // 事件处理
    NTSTATUS QuerySecurityEvents(PVOID buffer, size_t bufferSize);
    NTSTATUS SetProtectionPolicy(PVOID policyData, size_t policySize);
    
    // 实用工具函数
    BOOLEAN IsProcessProtected(ULONG ProcessId);
    BOOLEAN IsImageValid(PUNICODE_STRING ImagePath);
    NTSTATUS LogSecurityEvent(PPROTECTION_EVENT Event);
    
    // 内存管理
    PVOID SafeAllocateMemory(SIZE_T Size, ULONG Tag);
    VOID SafeFreeMemory(PVOID Memory, ULONG Tag);
}