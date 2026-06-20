#pragma once

// 添加预编译头文件
#pragma warning(push)
#pragma warning(disable: 4201) // 非标准扩展: 无名称结构/联合
#pragma warning(disable: 4214) // 非标准扩展: 位域类型不是 int

// Windows 内核头文件
#include <ntddk.h>
#include <wdm.h>

// 安全相关的头文件
#include <ntsecapi.h>
#include <ntseapi.h>

// 网络相关头文件
#include <fwpmk.h>
#include <fwpsk.h>
#include <ws2def.h>
#include <in6addr.h>

// 文件系统过滤相关
#include <fltKernel.h>

// 其他必要的头文件
#include <ntstrsafe.h>
#include <minwindef.h>
#include <stdlib.h>

#pragma warning(pop)

// 内核驱动公共定义
#define DRIVER_TAG 'FADr'
#define MAX_PROTECTED_PROCESSES 64

// IOCTL控制码
#define IOCTL_PROTECT_PROCESS         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_UNPROTECT_PROCESS       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_PROTECTED_LIST      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_MONITOR_POLICY      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_SECURITY_EVENTS     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

// 事件数据结构
typedef struct _SECURITY_EVENT {
    LARGE_INTEGER Timestamp;
    ULONG ProcessId;
    ULONG EventType;
    ULONG Operation;
    BOOLEAN Blocked;
    WCHAR Description[256];
} SECURITY_EVENT, *PSECURITY_EVENT;

// 进程保护策略
typedef struct _PROTECTION_POLICY {
    BOOLEAN EnableProcessProtection;
    BOOLEAN EnableMemoryProtection;
    BOOLEAN EnableRegistryProtection;
    BOOLEAN EnableFileProtection;
    BOOLEAN EnableNetworkProtection;
    ULONG ProtectedProcesses[MAX_PROTECTED_PROCESSES];
} PROTECTION_POLICY, *PPROTECTION_POLICY;

// 驱动全局上下文
typedef struct _DRIVER_CONTEXT {
    PDRIVER_OBJECT DriverObject;
    PDEVICE_OBJECT DeviceObject;
    BOOLEAN Initialized;
    PROTECTION_POLICY Policy;
    KSPIN_LOCK ProtectListLock;
} DRIVER_CONTEXT, *PDRIVER_CONTEXT;

// 全局上下文声明
extern DRIVER_CONTEXT g_DriverContext;

// 实用函数声明
NTSTATUS InitializeDriverContext(_In_ PDRIVER_OBJECT DriverObject);
VOID CleanupDriverContext();
BOOLEAN IsKernelInitialized();