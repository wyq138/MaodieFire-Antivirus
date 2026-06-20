#pragma once

#include <ntddk.h>
#include <wdm.h>

extern PDRIVER_OBJECT DriverObject;
extern PVOID g_CallbackHandle;
extern BOOLEAN g_MemoryMonitorInitialized;

// 受保护内存区域结构
typedef struct _PROTECTED_MEMORY_REGION {
    ULONG ProcessId;
    PVOID BaseAddress;
    SIZE_T RegionSize;
    ULONG ProtectionFlags;
    struct _PROTECTED_MEMORY_REGION* Next;
} PROTECTED_MEMORY_REGION, *PPROTECTED_MEMORY_REGION;

// 全局变量声明
extern PROTECTED_MEMORY_REGION* g_ProtectedRegions;
extern KSPIN_LOCK g_ProtectedRegionsLock;

class MemoryProtection
{
public:
    // 初始化和清理
    static NTSTATUS Initialize();
    static VOID Cleanup();

    // 内存保护管理
    static NTSTATUS ProtectProcessImageMemory(
        _In_ PEPROCESS Process,
        _In_ ULONG ProcessId);
    
    static NTSTATUS AddProtectedRegion(
        _In_ ULONG ProcessId,
        _In_ PVOID BaseAddress,
        _In_ SIZE_T RegionSize,
        _In_ ULONG ProtectionFlags);
        
    static VOID RemoveProtectedRegions(_In_ ULONG ProcessId);
    static BOOLEAN IsProcessMemoryProtected(_In_ ULONG ProcessId);
    
    // 安全检查
    static BOOLEAN IsCriticalProcess(_In_ ULONG ProcessId);
    static BOOLEAN HasMinimalMemoryAccess(_In_ ACCESS_MASK DesiredAccess);

private:
    // 回调函数
    static VOID ProcessNotifyRoutineEx(
        _Inout_ PEPROCESS Process,
        _In_ HANDLE ProcessId,
        _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo);
        
    static NTSTATUS ObCallbackRegistration();
    static OB_PREOP_CALLBACK_STATUS PreOperationCallback(
        _In_ PVOID RegistrationContext,
        _In_ POB_PRE_OPERATION_INFORMATION OperationInformation);
    
    // 内部实现
    static NTSTATUS SetMemoryProtection(
        _In_ ULONG ProcessId,
        _In_ PVOID BaseAddress,
        _In_ SIZE_T RegionSize,
        _In_ ULONG NewProtection);
        
    static NTSTATUS GetProcessImageBaseAndSize(
        _In_ PEPROCESS Process,
        _Out_ PVOID* ImageBase,
        _Out_ SIZE_T* ImageSize);
        
    static VOID ClearProtectedRegions();
    static VOID LogMemoryEvent(
        _In_ ULONG ProcessId,
        _In_ PVOID Address,
        _In_ SIZE_T Size,
        _In_ ULONG Operation,
        _In_ BOOLEAN Blocked);
};

// 全局回调声明
extern "C" {
    OB_PREOP_CALLBACK_STATUS PreOpCallback(
        _In_ PVOID RegistrationContext,
        _In_ POB_PRE_OPERATION_INFORMATION OperationInformation);
        
    VOID ProcessNotifyCallback(
        _Inout_ PEPROCESS Process,
        _In_ HANDLE ProcessId,
        _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo);
}