#include "pch.h"
#include "MemoryProtection.h"
#include "Driver.h"

#define MEMORY_PROTECTION_TAG 'MMPT'

// 内存保护回调句柄
PVOID g_CallbackHandle = NULL;
BOOLEAN g_MemoryMonitorInitialized = FALSE;

// 受保护的进程内存区域列表
typedef struct _PROTECTED_MEMORY_REGION {
    ULONG ProcessId;
    PVOID BaseAddress;
    SIZE_T RegionSize;
    ULONG ProtectionFlags;
    struct _PROTECTED_MEMORY_REGION* Next;
} PROTECTED_MEMORY_REGION, *PPROTECTED_MEMORY_REGION;

// 全局受保护内存区域链表
PPROTECTED_MEMORY_REGION g_ProtectedRegions = NULL;
KSPIN_LOCK g_ProtectedRegionsLock;

NTSTATUS
MemoryProtection::Initialize()
{
    NTSTATUS status;
    
    KdPrint(("[FireAntivirus.MemoryProtection] Initializing memory protection\n"));

    // 初始化受保护区域链表锁
    KeInitializeSpinLock(&g_ProtectedRegionsLock);

    // 注册虚拟内存操作回调
    status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyRoutineEx, FALSE);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("[FireAntivirus.MemoryProtection] Failed to register process notify routine: 0x%X\n", status));
        return status;
    }

    // 注册内存保护回调
    status = ObRegisterCallbacks(ObCallbackRegistration, &g_CallbackHandle);
    if (!NT_SUCCESS(status))
    {
        PsSetCreateProcessNotifyRoutineEx(ProcessNotifyRoutineEx, TRUE);
        KdPrint(("[FireAntivirus.MemoryProtection] Failed to register object callbacks: 0x%X\n", status));
        return status;
    }

    g_MemoryMonitorInitialized = TRUE;
    KdPrint(("[FireAntivirus.MemoryProtection] Memory protection initialized successfully\n"));
    
    return status;
}

VOID
MemoryProtection::Cleanup()
{
    if (g_MemoryMonitorInitialized)
    {
        // 取消注册回调
        if (g_CallbackHandle != NULL)
        {
            ObUnRegisterCallbacks(g_CallbackHandle);
            g_CallbackHandle = NULL;
        }
        
        PsSetCreateProcessNotifyRoutineEx(ProcessNotifyRoutineEx, TRUE);
        
        // 清理受保护内存区域
        ClearProtectedRegions();
    }
    
    g_MemoryMonitorInitialized = FALSE;
    KdPrint(("[FireAntivirus.MemoryProtection] Memory protection cleanup completed\n"));
}

// 进程创建/销毁通知回调
VOID
MemoryProtection::ProcessNotifyRoutineEx(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
    if (CreateInfo != NULL)
    {
        // 新进程创建
        KdPrint(("[FireAntivirus.MemoryProtection] New process created: PID=%lu\n", (ULONG)ProcessId));
        
        // 保护关键进程的映像基址
        if (IsCriticalProcess((ULONG)ProcessId))
        {
            ProtectProcessImageMemory(Process, (ULONG)ProcessId);
        }
    }
    else
    {
        // 进程终止
        KdPrint(("[FireAntivirus.MemoryProtection] Process terminated: PID=%lu\n", (ULONG)ProcessId));
        
        // 清理该进程的受保护内存区域
        RemoveProtectedRegions((ULONG)ProcessId);
    }
}

// 对象管理器回调注册
OB_OPERATION_REGISTRATION ObCallbackRegistration[1];
OB_CALLBACK_REGISTRATION CallbackReg = {0};

// 配置对象管理器回调
NTSTATUS
MemoryProtection::ObCallbackRegistration()
{
    NTSTATUS status;
    
    // 设置回调注册信息
    CallbackReg.Version = ObGetFilterVersion();
    CallbackReg.OperationRegistrationCount = 1;
    CallbackReg.RegistrationContext = NULL;
    
    // 设置进程句柄操作回调
    RtlZeroMemory(&ObCallbackRegistration[0], sizeof(OB_OPERATION_REGISTRATION));
    ObCallbackRegistration[0].ObjectType = PsProcessType;
    ObCallbackRegistration[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    ObCallbackRegistration[0].PreOperation = PreOperationCallback;
    ObCallbackRegistration[0].PostOperation = NULL;
    
    CallbackReg.OperationRegistration = ObCallbackRegistration;
    
    // 注册回调
    status = ObRegisterCallbacks(&CallbackReg, &g_CallbackHandle);
    
    return status;
}

// 对象操作前回调
OB_PREOP_CALLBACK_STATUS
MemoryProtection::PreOperationCallback(
    _In_ PVOID RegistrationContext,
    _In_ POB_PRE_OPERATION_INFORMATION OperationInformation
)
{
    UNREFERENCED_PARAMETER(RegistrationContext);
    
    if (OperationInformation->ObjectType == PsProcessType &&
        OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
    {
        PEPROCESS TargetProcess = (PEPROCESS)OperationInformation->Object;
        ULONG targetProcessId = (ULONG)PsGetProcessId(TargetProcess);
        
        // 检查目标进程是否受保护
        if (IsProcessMemoryProtected(targetProcessId))
        {
            // 检查权限是否足够低
            ACCESS_MASK grantedAccess = OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess;
            
            if (!HasMinimalMemoryAccess(grantedAccess))
            {
                // 限制访问权限
                KdPrint(("[FireAntivirus.MemoryProtection] Restricting memory access to protected process %lu\n", 
                    targetProcessId));
                
                ACCESS_MASK newAccess = grantedAccess & (~(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION));
                OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = newAccess;
            }
        }
    }
    
    return OB_PREOP_SUCCESS;
}

// 保护进程映像内存
NTSTATUS
MemoryProtection::ProtectProcessImageMemory(
    _In_ PEPROCESS Process,
    _In_ ULONG ProcessId
)
{
    NTSTATUS status;
    PVOID imageBase = NULL;
    SIZE_T imageSize = 0;
    
    // 获取进程映像基址和大小
    status = GetProcessImageBaseAndSize(Process, &imageBase, &imageSize);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    
    // 添加内存区域保护
    status = AddProtectedRegion(ProcessId, imageBase, imageSize, 
        PAGE_EXECUTE_READ | PAGE_GUARD);
    
    if (NT_SUCCESS(status))
    {
        KdPrint(("[FireAntivirus.MemoryProtection] Protected process image memory: PID=%lu, Base=%p, Size=%zu\n",
            ProcessId, imageBase, imageSize));
    }
    
    return status;
}

// 添加受保护内存区域
NTSTATUS
MemoryProtection::AddProtectedRegion(
    _In_ ULONG ProcessId,
    _In_ PVOID BaseAddress,
    _In_ SIZE_T RegionSize,
    _In_ ULONG ProtectionFlags
)
{
    PPROTECTED_MEMORY_REGION newRegion;
    KIRQL oldIrql;
    
    // 分配新的内存区域结构
    newRegion = (PPROTECTED_MEMORY_REGION)ExAllocatePoolWithTag(
        NonPagedPool, 
        sizeof(PROTECTED_MEMORY_REGION), 
        MEMORY_PROTECTION_TAG
    );
    
    if (newRegion == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    // 初始化新区域
    newRegion->ProcessId = ProcessId;
    newRegion->BaseAddress = BaseAddress;
    newRegion->RegionSize = RegionSize;
    newRegion->ProtectionFlags = ProtectionFlags;
    
    // 获取链表锁并插入新区域
    KeAcquireSpinLock(&g_ProtectedRegionsLock, &oldIrql);
    newRegion->Next = g_ProtectedRegions;
    g_ProtectedRegions = newRegion;
    KeReleaseSpinLock(&g_ProtectedRegionsLock, oldIrql);
    
    // 设置实际的内存保护
    return SetMemoryProtection(ProcessId, BaseAddress, RegionSize, ProtectionFlags);
}

// 删除进程的所有受保护区域
VOID
MemoryProtection::RemoveProtectedRegions(_In_ ULONG ProcessId)
{
    PPROTECTED_MEMORY_REGION prev = NULL;
    PPROTECTED_MEMORY_REGION current = g_ProtectedRegions;
    KIRQL oldIrql;
    
    KeAcquireSpinLock(&g_ProtectedRegionsLock, &oldIrql);
    
    while (current != NULL)
    {
        if (current->ProcessId == ProcessId)
        {
            // 删除匹配的区域
            PPROTECTED_MEMORY_REGION toDelete = current;
            
            if (prev == NULL)
            {
                g_ProtectedRegions = current->Next;
            }
            else
            {
                prev->Next = current->Next;
            }
            
            current = current->Next;
            
            // 恢复内存保护
            SetMemoryProtection(toDelete->ProcessId, toDelete->BaseAddress, 
                toDelete->RegionSize, PAGE_READWRITE);
            
            // 释放内存
            ExFreePoolWithTag(toDelete, MEMORY_PROTECTION_TAG);
        }
        else
        {
            prev = current;
            current = current->Next;
        }
    }
    
    KeReleaseSpinLock(&g_ProtectedRegionsLock, oldIrql);
}

// 清理所有受保护区域
VOID
MemoryProtection::ClearProtectedRegions()
{
    PPROTECTED_MEMORY_REGION current = g_ProtectedRegions;
    PPROTECTED_MEMORY_REGION next;
    KIRQL oldIrql;
    
    KeAcquireSpinLock(&g_ProtectedRegionsLock, &oldIrql);
    
    while (current != NULL)
    {
        next = current->Next;
        
        // 恢复内存保护
        SetMemoryProtection(current->ProcessId, current->BaseAddress, 
            current->RegionSize, PAGE_READWRITE);
        
        ExFreePoolWithTag(current, MEMORY_PROTECTION_TAG);
        current = next;
    }
    
    g_ProtectedRegions = NULL;
    KeReleaseSpinLock(&g_ProtectedRegionsLock, oldIrql);
}

// 设置内存保护
NTSTATUS
MemoryProtection::SetMemoryProtection(
    _In_ ULONG ProcessId,
    _In_ PVOID BaseAddress,
    _In_ SIZE_T RegionSize,
    _In_ ULONG NewProtection
)
{
    PEPROCESS targetProcess;
    NTSTATUS status;
    
    // 通过进程ID获取进程对象
    status = PsLookupProcessByProcessId((HANDLE)ProcessId, &targetProcess);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    
    // 设置内存保护
    KAPC_STATE apcState;
    KeStackAttachProcess(targetProcess, &apcState);
    
    PVOID actualBase = BaseAddress;
    SIZE_T actualSize = RegionSize;
    ULONG oldProtection;
    
    status = ZwProtectVirtualMemory(
        NtCurrentProcess(),
        &actualBase,
        &actualSize,
        NewProtection,
        &oldProtection
    );
    
    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(targetProcess);
    
    return status;
}

// 获取进程映像基址和大小
NTSTATUS
MemoryProtection::GetProcessImageBaseAndSize(
    _In_ PEPROCESS Process,
    _Out_ PVOID* ImageBase,
    _Out_ SIZE_T* ImageSize
)
{
    PPEB peb = PsGetProcessPeb(Process);
    if (peb == NULL || peb->ImageBaseAddress == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }
    
    *ImageBase = peb->ImageBaseAddress;
    
    // 获取映像大小（简化实现）
    PLDR_DATA_TABLE_ENTRY moduleEntry = NULL;
    PLIST_ENTRY moduleListHead = &peb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY moduleListEntry = moduleListHead->Flink;
    
    while (moduleListEntry != moduleListHead)
    {
        moduleEntry = CONTAINING_RECORD(moduleListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        
        if (moduleEntry->DllBase == *ImageBase)
        {
            *ImageSize = moduleEntry->SizeOfImage;
            return STATUS_SUCCESS;
        }
        
        moduleListEntry = moduleListEntry->Flink;
    }
    
    // 如果没找到，使用默认大小
    *ImageSize = 0x100000; // 1MB
    return STATUS_SUCCESS;
}

// 检查进程内存是否受保护
BOOLEAN
MemoryProtection::IsProcessMemoryProtected(_In_ ULONG ProcessId)
{
    PPROTECTED_MEMORY_REGION current;
    KIRQL oldIrql;
    
    KeAcquireSpinLock(&g_ProtectedRegionsLock, &oldIrql);
    
    for (current = g_ProtectedRegions; current != NULL; current = current->Next)
    {
        if (current->ProcessId == ProcessId)
        {
            KeReleaseSpinLock(&g_ProtectedRegionsLock, oldIrql);
            return TRUE;
        }
    }
    
    KeReleaseSpinLock(&g_ProtectedRegionsLock, oldIrql);
    return FALSE;
}

// 检查是否为关键进程
BOOLEAN
MemoryProtection::IsCriticalProcess(_In_ ULONG ProcessId)
{
    ULONG criticalProcesses[] = {4}; // System process
    USHORT i;
    
    for (i = 0; i < ARRAYSIZE(criticalProcesses); i++)
    {
        if (ProcessId == criticalProcesses[i])
        {
            return TRUE;
        }
    }
    
    return FALSE;
}

// 检查访问权限是否最小化
BOOLEAN
MemoryProtection::HasMinimalMemoryAccess(_In_ ACCESS_MASK DesiredAccess)
{
    // 检查是否包含危险的权限
    ACCESS_MASK dangerousAccess = PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD;
    
    return ((DesiredAccess & dangerousAccess) == 0);
}

// 记录内存保护事件
VOID
MemoryProtection::LogMemoryEvent(
    _In_ ULONG ProcessId,
    _In_ PVOID Address,
    _In_ SIZE_T Size,
    _In_ ULONG Operation,
    _In_ BOOLEAN Blocked
)
{
    LARGE_INTEGER currentTime;
    
    KeQuerySystemTime(&currentTime);
    
    KdPrint(("[FireAntivirus.MemoryProtection] Memory event: Process=%lu, Address=%p, Size=%zu, Operation=%lu, Blocked=%u, Time=%I64d\n",
        ProcessId, Address, Size, Operation, Blocked, currentTime.QuadPart));
}