#include <ntddk.h>
#include <wdm.h>
#include "ProcessMonitor.h"

// 进程保护回调注册句柄
PVOID g_ProcessCreateCallbackHandle = NULL;
PVOID g_ProcessTerminateCallbackHandle = NULL;
PVOID g_ThreadCreateCallbackHandle = NULL;

// 受保护进程列表
LIST_ENTRY g_ProtectedProcessList;
KSPIN_LOCK g_ProtectedProcessLock;

// 内部进程保护结构
typedef struct _PROTECTED_PROCESS {
    LIST_ENTRY ListEntry;
    ULONG ProcessId;
    ULONG ProtectionFlags;
    WCHAR ProcessName[64];
} PROTECTED_PROCESS, *PPROTECTED_PROCESS;

ProcessMonitor::ProcessMonitor()
{
    InitializeListHead(&g_ProtectedProcessList);
    KeInitializeSpinLock(&g_ProtectedProcessLock);
}

ProcessMonitor::~ProcessMonitor()
{
}

NTSTATUS ProcessMonitor::Initialize()
{
    NTSTATUS status = STATUS_SUCCESS;
    OBJECT_ATTRIBUTES objectAttributes;
    OB_OPERATION_REGISTRATION operations[2];
    OB_CALLBACK_REGISTRATION callbackRegistration;

    KdPrint(("ProcessMonitor: 初始化开始\n"));

    // 注册进程创建回调
    RtlZeroMemory(&callbackRegistration, sizeof(OB_CALLBACK_REGISTRATION));
    callbackRegistration.Version = ObGetFilterVersion();
    callbackRegistration.OperationRegistrationCount = 2;
    callbackRegistration.RegistrationContext = NULL;

    // 进程创建回调
    operations[0].ObjectType = PsProcessType;
    operations[0].Operations |= OB_OPERATION_HANDLE_CREATE;
    operations[0].PreOperation = ProcessPreOperationCallback;
    operations[0].PostOperation = NULL;

    // 进程终止回调
    operations[1].ObjectType = PsProcessType;
    operations[1].Operations |= OB_OPERATION_HANDLE_DUPLICATE;
    operations[1].PreOperation = ProcessPreOperationCallback;
    operations[1].PostOperation = NULL;

    callbackRegistration.OperationRegistration = operations;

    status = ObRegisterCallbacks(&callbackRegistration, &g_ProcessCreateCallbackHandle);
    if (!NT_SUCCESS(status)) {
        KdPrint(("ProcessMonitor: 进程回调注册失败 (0x%X)\n", status));
        return status;
    }

    // 注册线程创建回调（用于检测线程注入）
    if (!NT_SUCCESS(RegisterThreadCallbacks())) {
        KdPrint(("ProcessMonitor: 线程回调注册失败\n"));
        // 非致命错误，继续执行
    }

    KdPrint(("ProcessMonitor: 初始化完成\n"));
    return STATUS_SUCCESS;
}

VOID ProcessMonitor::Cleanup()
{
    KdPrint(("ProcessMonitor: 清理开始\n"));

    // 取消回调注册
    if (g_ProcessCreateCallbackHandle) {
        ObUnRegisterCallbacks(g_ProcessCreateCallbackHandle);
        g_ProcessCreateCallbackHandle = NULL;
    }

    if (g_ThreadCreateCallbackHandle) {
        ObUnRegisterCallbacks(g_ThreadCreateCallbackHandle);
        g_ThreadCreateCallbackHandle = NULL;
    }

    // 清理受保护进程列表
    ClearProtectedProcessList();

    KdPrint(("ProcessMonitor: 清理完成\n"));
}

NTSTATUS ProcessMonitor::ProtectProcess(PULONG ProcessId)
{
    NTSTATUS status = STATUS_SUCCESS;
    PPROTECTED_PROCESS protectedProcess = NULL;
    PEPROCESS targetProcess = NULL;
    KIRQL oldIrql;

    if (!ProcessId) {
        return STATUS_INVALID_PARAMETER;
    }

    KdPrint(("ProcessMonitor: 保护进程 ID: %lu\n", *ProcessId));

    // 获取目标进程
    status = PsLookupProcessByProcessId((HANDLE)*ProcessId, &targetProcess);
    if (!NT_SUCCESS(status)) {
        KdPrint(("ProcessMonitor: 进程查找失败 (0x%X)\n", status));
        return status;
    }

    // 分配受保护进程结构
    protectedProcess = (PPROTECTED_PROCESS)ExAllocatePoolWithTag(
        NonPagedPool, sizeof(PROTECTED_PROCESS), 'PMPR');
    
    if (!protectedProcess) {
        ObDereferenceObject(targetProcess);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // 填充进程信息
    protectedProcess->ProcessId = *ProcessId;
    protectedProcess->ProtectionFlags = PROCESS_PROTECTION_FULL;
    
    // 获取进程映像名称
    PUNICODE_STRING imageName = NULL;
    SeLocateProcessImageName(targetProcess, &imageName);
    if (imageName) {
        RtlCopyMemory(protectedProcess->ProcessName, 
                     imageName->Buffer, 
                     min(imageName->Length, sizeof(protectedProcess->ProcessName) - sizeof(WCHAR)));
        ExFreePool(imageName);
    }

    // 添加到受保护列表
    KeAcquireSpinLock(&g_ProtectedProcessLock, &oldIrql);
    InsertHeadList(&g_ProtectedProcessList, &protectedProcess->ListEntry);
    KeReleaseSpinLock(&g_ProtectedProcessLock, oldIrql);

    ObDereferenceObject(targetProcess);

    KdPrint(("ProcessMonitor: 进程保护成功\n"));
    return STATUS_SUCCESS;
}

NTSTATUS ProcessMonitor::UnprotectProcess(PULONG ProcessId)
{
    KIRQL oldIrql;
    PLIST_ENTRY listEntry;
    PPROTECTED_PROCESS protectedProcess;

    if (!ProcessId) {
        return STATUS_INVALID_PARAMETER;
    }

    KdPrint(("ProcessMonitor: 取消保护进程 ID: %lu\n", *ProcessId));

    KeAcquireSpinLock(&g_ProtectedProcessLock, &oldIrql);

    // 遍历列表查找目标进程
    listEntry = g_ProtectedProcessList.Flink;
    while (listEntry != &g_ProtectedProcessList) {
        protectedProcess = CONTAINING_RECORD(listEntry, PROTECTED_PROCESS, ListEntry);
        
        if (protectedProcess->ProcessId == *ProcessId) {
            // 从列表中移除
            RemoveEntryList(&protectedProcess->ListEntry);
            ExFreePoolWithTag(protectedProcess, 'PMPR');
            
            KeReleaseSpinLock(&g_ProtectedProcessLock, oldIrql);
            KdPrint(("ProcessMonitor: 进程取消保护成功\n"));
            return STATUS_SUCCESS;
        }
        
        listEntry = listEntry->Flink;
    }

    KeReleaseSpinLock(&g_ProtectedProcessLock, oldIrql);
    KdPrint(("ProcessMonitor: 进程未在保护列表中\n"));
    return STATUS_NOT_FOUND;
}

BOOLEAN ProcessMonitor::IsProcessProtected(ULONG ProcessId)
{
    KIRQL oldIrql;
    PLIST_ENTRY listEntry;
    PPROTECTED_PROCESS protectedProcess;
    BOOLEAN isProtected = FALSE;

    KeAcquireSpinLock(&g_ProtectedProcessLock, &oldIrql);

    listEntry = g_ProtectedProcessList.Flink;
    while (listEntry != &g_ProtectedProcessList) {
        protectedProcess = CONTAINING_RECORD(listEntry, PROTECTED_PROCESS, ListEntry);
        
        if (protectedProcess->ProcessId == ProcessId) {
            isProtected = TRUE;
            break;
        }
        
        listEntry = listEntry->Flink;
    }

    KeReleaseSpinLock(&g_ProtectedProcessLock, oldIrql);
    return isProtected;
}

OB_PREOP_CALLBACK_STATUS ProcessMonitor::ProcessPreOperationCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInfo)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    PPROTECTED_PROCESS protectedProcess = NULL;
    PEPROCESS targetProcess = NULL;
    ULONG processId;
    
    if (!OperationInfo || !OperationInfo->Object) {
        return OB_PREOP_SUCCESS;
    }

    // 获取进程ID
    processId = (ULONG)PsGetProcessId((PEPROCESS)OperationInfo->Object);

    // 检查是否是受保护进程
    if (IsProcessProtected(processId)) {
        KdPrint(("ProcessMonitor: 拦截对受保护进程的操作, PID: %lu\n", processId));
        
        // 根据操作类型决定是否拦截
        switch (OperationInfo->Operation) {
            case OB_OPERATION_HANDLE_CREATE:
                // 拦截进程创建或打开
                OperationInfo->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_ALL_ACCESS;
                OperationInfo->Parameters->CreateHandleInformation.DesiredAccess |= PROCESS_QUERY_LIMITED_INFORMATION;
                break;
                
            case OB_OPERATION_HANDLE_DUPLICATE:
                // 拦截句柄复制
                OperationInfo->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_ALL_ACCESS;
                OperationInfo->Parameters->DuplicateHandleInformation.DesiredAccess |= PROCESS_QUERY_LIMITED_INFORMATION;
                break;
        }
        
        // 记录安全事件
        LogSecurityEvent(processId, PROCESS_ACCESS_ATTEMPT, OperationInfo->Operation);
    }

    return OB_PREOP_SUCCESS;
}

NTSTATUS ProcessMonitor::RegisterThreadCallbacks()
{
    NTSTATUS status;
    OB_OPERATION_REGISTRATION operations[1];
    OB_CALLBACK_REGISTRATION callbackRegistration;

    RtlZeroMemory(&callbackRegistration, sizeof(OB_CALLBACK_REGISTRATION));
    callbackRegistration.Version = ObGetFilterVersion();
    callbackRegistration.OperationRegistrationCount = 1;
    callbackRegistration.RegistrationContext = NULL;

    // 线程创建回调
    operations[0].ObjectType = PsThreadType;
    operations[0].Operations |= OB_OPERATION_HANDLE_CREATE;
    operations[0].PreOperation = ThreadPreOperationCallback;
    operations[0].PostOperation = NULL;

    callbackRegistration.OperationRegistration = operations;

    status = ObRegisterCallbacks(&callbackRegistration, &g_ThreadCreateCallbackHandle);
    return status;
}

OB_PREOP_CALLBACK_STATUS ProcessMonitor::ThreadPreOperationCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInfo)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (!OperationInfo || !OperationInfo->Object) {
        return OB_PREOP_SUCCESS;
    }

    // 检查线程注入尝试
    PETHREAD thread = (PETHREAD)OperationInfo->Object;
    PEPROCESS ownerProcess = PsGetThreadProcess(thread);
    ULONG ownerProcessId = (ULONG)PsGetProcessId(ownerProcess);

    // 如果目标进程是受保护进程，记录安全事件
    if (IsProcessProtected(ownerProcessId)) {
        KdPrint(("ProcessMonitor: 检测到对受保护进程的线程操作, PID: %lu\n", ownerProcessId));
        LogSecurityEvent(ownerProcessId, THREAD_INJECTION_ATTEMPT, OperationInfo->Operation);
    }

    return OB_PREOP_SUCCESS;
}

VOID ProcessMonitor::LogSecurityEvent(ULONG ProcessId, SECURITY_EVENT_TYPE EventType, ULONG Operation)
{
    // 实现安全事件记录逻辑
    // 这里应该将事件记录到安全日志或发送给用户态服务
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(EventType);
    UNREFERENCED_PARAMETER(Operation);
    
    // 临时调试输出
    KdPrint(("ProcessMonitor: 安全事件记录 - PID: %lu, 类型: %lu\n", ProcessId, EventType));
}

VOID ProcessMonitor::ClearProtectedProcessList()
{
    KIRQL oldIrql;
    PLIST_ENTRY listEntry;
    PPROTECTED_PROCESS protectedProcess;

    KeAcquireSpinLock(&g_ProtectedProcessLock, &oldIrql);

    while (!IsListEmpty(&g_ProtectedProcessList)) {
        listEntry = RemoveHeadList(&g_ProtectedProcessList);
        protectedProcess = CONTAINING_RECORD(listEntry, PROTECTED_PROCESS, ListEntry);
        ExFreePoolWithTag(protectedProcess, 'PMPR');
    }

    KeReleaseSpinLock(&g_ProtectedProcessLock, oldIrql);
}