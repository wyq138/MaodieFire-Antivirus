/* ============================================================
 * FireAntivirusKrn - 耄耋安全 内核防护驱动 (完整版)
 * 模块: 1) IOCTL 设备接口(\Device\FireAntivirusKernel)
 *       2) 进程创建拦截(PsSetCreateProcessNotifyRoutineEx)
 *       3) 注册表自启动/服务注入防护(CmRegisterCallbackEx)
 *       4) 多进程自保护(ObRegisterCallbacks 防杀 + 注入尝试检测)
 *       5) 分区表/UEFI 防护(磁盘写过滤: MBR + GPT 头/分区表)
 *       6) 内核事件上报管道(环形队列, 用户态 IOCTL 0x805 轮询→弹窗)
 * 对齐用户态: FireAntivirus.Engine.Kernel.KernelProtectionInterface.cs
 * 构建: EWDK/WDK, 见 build.cmd
 * ============================================================ */
#include "driver.h"
#include <fltkernel.h>

#pragma warning(disable : 4100) /* 未引用形参 */

/* ============================================================
 * 全局状态
 * ============================================================ */
FAV_GLOBAL_STATE g_Fav = { 0 };

PDEVICE_OBJECT g_ControlDevice = NULL;
BOOLEAN g_SymlinkCreated = FALSE;
BOOLEAN g_DeviceCreated = FALSE;

/* ============================================================
 * 事件日志 (DebugView /内核调试器可见)
 * ============================================================ */
VOID
FavLog(
    _In_ PCSTR Format,
    ...
)
{
    char buffer[256];
    va_list args;

    va_start(args, Format);
    RtlStringCbVPrintfA(buffer, sizeof(buffer), Format, args);
    va_end(args);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[FireAntivirusKrn] %s\n", buffer);
}

/* ============================================================
 * 内核事件队列（环形缓冲 + 自旋锁, 用户态 0x805 轮询拉取→弹窗）
 * ============================================================ */
static ULONG g_EventHead = 0;   /* 写入位置 */
static ULONG g_EventTail = 0;   /* 读出位置 */

/* 取消挂起的异步事件 IRP（用户态 CancelIoEx / 进程退出时触发） */
static VOID
FavCancelPendingEventIrp(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
)
{
    KIRQL oldIrql;
    UNREFERENCED_PARAMETER(DeviceObject);

    KeAcquireSpinLock(&g_Fav.PendingLock, &oldIrql);
    if (g_Fav.PendingEventIrp == Irp) {
        g_Fav.PendingEventIrp = NULL;
    }
    KeReleaseSpinLock(&g_Fav.PendingLock, oldIrql);

    IoReleaseCancelSpinLock(Irp->CancelIrql);
    Irp->IoStatus.Status = STATUS_CANCELLED;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

/* 事件入队后完成挂起的异步 IRP（把队列事件直接拷进其输出缓冲） */
static VOID
FavTryCompletePendingEventIrp(VOID)
{
    PIRP pending;
    KIRQL oldIrql;
    PUCHAR buffer;
    ULONG outputLength, maxEvents, count;
    PFAV_EVENT outEvents;

    KeAcquireSpinLock(&g_Fav.PendingLock, &oldIrql);
    pending = g_Fav.PendingEventIrp;
    g_Fav.PendingEventIrp = NULL;
    KeReleaseSpinLock(&g_Fav.PendingLock, oldIrql);

    if (pending == NULL) return;

    /* 已被取消：取消例程负责完成 */
    if (IoSetCancelRoutine(pending, NULL) == NULL) return;

    outputLength = IoGetCurrentIrpStackLocation(pending)->
                       Parameters.DeviceIoControl.OutputBufferLength;
    buffer = (PUCHAR)pending->AssociatedIrp.SystemBuffer;
    if (buffer == NULL || outputLength < sizeof(ULONG)) {
        pending->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
        pending->IoStatus.Information = 0;
        IoCompleteRequest(pending, IO_NO_INCREMENT);
        return;
    }

    KeAcquireSpinLock(&g_Fav.EventLock, &oldIrql);
    maxEvents = (outputLength - sizeof(ULONG)) / sizeof(FAV_EVENT);
    count = 0;
    outEvents = (PFAV_EVENT)(buffer + sizeof(ULONG));
    while (g_EventTail != g_EventHead && count < maxEvents) {
        outEvents[count] = g_Fav.EventQueue[g_EventTail];
        g_EventTail = (g_EventTail + 1) % FAV_EVENT_QUEUE_SIZE;
        count++;
    }
    KeReleaseSpinLock(&g_Fav.EventLock, oldIrql);

    *(PULONG)buffer = count;
    pending->IoStatus.Status = STATUS_SUCCESS;
    pending->IoStatus.Information = sizeof(ULONG) + count * sizeof(FAV_EVENT);
    IoCompleteRequest(pending, IO_NO_INCREMENT);
}

VOID
FavPushEvent(
    _In_ ULONG Type,
    _In_ ULONG Pid,
    _In_opt_ PCWSTR Source,
    _In_opt_ PCWSTR Detail
)
{
    KIRQL oldIrql;
    ULONG next;

    KeAcquireSpinLock(&g_Fav.EventLock, &oldIrql);

    next = (g_EventHead + 1) % FAV_EVENT_QUEUE_SIZE;
    if (next != g_EventTail)    /* 队列未满才写入（满则丢弃新事件） */
    {
        PFAV_EVENT e = &g_Fav.EventQueue[g_EventHead];
        e->Type = Type;
        e->Pid = Pid;
        RtlStringCchCopyW(e->Source, FAV_EVENT_TEXT, Source ? Source : L"");
        RtlStringCchCopyW(e->Detail, FAV_EVENT_TEXT, Detail ? Detail : L"");
        g_EventHead = next;
    }

    KeReleaseSpinLock(&g_Fav.EventLock, oldIrql);

    /* 真异步：有挂起 IRP 时立即把事件推给用户态 */
    FavTryCompletePendingEventIrp();
}

/* ============================================================
 * minifilter：文件写/删除实时采集（预操作回调，仅上报不阻塞）
 *   FltRegisterFilter + FltStartFiltering；驱动卸载时 FltUnregisterFilter。
 *   事件经 FavPushEvent 进入队列 → 用户态异步 IOCTL 推送 → 熵时序/时间线/处置。
 * ============================================================ */
static PFLT_FILTER g_FavFilter = NULL;
static BOOLEAN g_FilterStarted = FALSE;

static FLT_PREOP_CALLBACK_STATUS
FavPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_ PVOID *CompletionContext
)
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (Data->RequestorMode == KernelMode) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    status = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (NT_SUCCESS(status)) {
        FltParseFileNameInformation(nameInfo);
        FavPushEvent(FAV_EVT_FILE_WRITE, FltGetRequestorProcessId(Data),
            nameInfo->Name.Buffer, L"minifilter 文件写入");
        FltReleaseFileNameInformation(nameInfo);
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static FLT_PREOP_CALLBACK_STATUS
FavPreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_ PVOID *CompletionContext
)
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (Data->RequestorMode == KernelMode) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass != FileDispositionInformation)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    status = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (NT_SUCCESS(status)) {
        FltParseFileNameInformation(nameInfo);
        FavPushEvent(FAV_EVT_FILE_DELETE, FltGetRequestorProcessId(Data),
            nameInfo->Name.Buffer, L"minifilter 文件删除");
        FltReleaseFileNameInformation(nameInfo);
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static const FLT_OPERATION_REGISTRATION FavFilterCallbacks[] = {
    { IRP_MJ_WRITE, 0, FavPreWrite, NULL },
    { IRP_MJ_SET_INFORMATION, 0, FavPreSetInformation, NULL },
    { IRP_MJ_OPERATION_END }
};

static NTSTATUS
FavFilterUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Flags);
    if (g_FavFilter != NULL) {
        FltUnregisterFilter(g_FavFilter);
        g_FavFilter = NULL;
        g_FilterStarted = FALSE;
    }
    return STATUS_SUCCESS;
}

static FLT_REGISTRATION FavFilterRegistration;

VOID
FavStartMiniFilter(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    NTSTATUS status;

    RtlZeroMemory(&FavFilterRegistration, sizeof(FavFilterRegistration));
    FavFilterRegistration.Size = sizeof(FLT_REGISTRATION);
    FavFilterRegistration.Version = FLT_REGISTRATION_VERSION;
    FavFilterRegistration.Flags = 0;
    FavFilterRegistration.OperationRegistration = FavFilterCallbacks;
    FavFilterRegistration.FilterUnloadCallback = FavFilterUnload;

    status = FltRegisterFilter(DriverObject, &FavFilterRegistration, &g_FavFilter);
    if (!NT_SUCCESS(status)) {
        FavLog("FltRegisterFilter failed: 0x%08X", status);
        g_FavFilter = NULL;
        return;
    }

    status = FltStartFiltering(g_FavFilter);
    if (!NT_SUCCESS(status)) {
        FavLog("FltStartFiltering failed: 0x%08X", status);
        FltUnregisterFilter(g_FavFilter);
        g_FavFilter = NULL;
        return;
    }

    g_FilterStarted = TRUE;
    FavLog("minifilter started (write/delete telemetry)");
}

/* 受保护 PID 数组查找（多进程自保护） */
BOOLEAN
FavIsProtectedPid(
    _In_ HANDLE ProcessId
)
{
    ULONG i;
    for (i = 0; i < g_Fav.ProtectedPidCount && i < FAV_MAX_PIDS; i++)
    {
        if (g_Fav.ProtectedPids[i] == ProcessId)
            return TRUE;
    }
    return FALSE;
}


/* ============================================================
 * 内部工具: UnicodeString 大小写不敏感子串匹配
 * ============================================================ */
static BOOLEAN
FavUnicodeContainsPath(
    _In_ PCUNICODE_STRING String,
    _In_ PCWSTR Pattern
)
{
    UNICODE_STRING pattern;
    RtlInitUnicodeString(&pattern, Pattern);

    if (String->Length < pattern.Length) {
        return FALSE;
    }

    for (USHORT i = 0; i + pattern.Length <= String->Length; i += 2) {
        UNICODE_STRING slice;
        slice.Buffer = (PWSTR)((PUCHAR)String->Buffer + i);
        slice.Length = pattern.Length;
        slice.MaximumLength = pattern.Length;

        if (RtlEqualUnicodeString(&slice, &pattern, TRUE)) {
            return TRUE;
        }
    }
    return FALSE;
}

/* ============================================================
 * 进程创建回调 (进程防护)
 * 规则: 临时/下载目录进程创建拦截; PowerShell 编码/隐藏命令行拦截
 * 全部拦截行为入内核事件队列(用户态轮询→弹窗)
 * ============================================================ */
VOID
FavProcessNotifyCallback(
    _In_ HANDLE ParentId,
    _In_ HANDLE ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
    UNREFERENCED_PARAMETER(ParentId);

    if (!CreateInfo || !CreateInfo->ImageFileName) {
        return; /* 进程退出通知 */
    }

    if (!g_Fav.ProcessGuardEnabled) {
        return; /* 防护未开启: 不拦截 */
    }

    /* 规则1: 临时目录 / 下载目录下的可执行进程 */
    if (FavUnicodeContainsPath(CreateInfo->ImageFileName, L"\\temp\\") ||
        FavUnicodeContainsPath(CreateInfo->ImageFileName, L"\\tmp\\") ||
        FavUnicodeContainsPath(CreateInfo->ImageFileName, L"\\downloads\\")) {

        FavLog("process blocked: %wZ (PID %llu)", CreateInfo->ImageFileName, (ULONG64)(ULONG_PTR)ProcessId);
        FavPushEvent(FAV_EVT_PROCESS_BLOCKED,
                     (ULONG)(ULONG_PTR)ProcessId,
                     CreateInfo->ImageFileName->Buffer,
                     L"临时/下载目录进程创建被拦截");
        CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
        return;
    }

    /* 规则2: 命令行注入特征 (powershell -enc / -w hidden / invoke-expression) */
    if (CreateInfo->CommandLine && CreateInfo->CommandLine->Length > 0) {
        if (FavUnicodeContainsPath(CreateInfo->CommandLine, L"-enc") ||
            FavUnicodeContainsPath(CreateInfo->CommandLine, L"-w hidden") ||
            FavUnicodeContainsPath(CreateInfo->CommandLine, L"invoke-expression")) {

            FavLog("script injection blocked: %wZ", CreateInfo->CommandLine);
            FavPushEvent(FAV_EVT_PROCESS_BLOCKED,
                         (ULONG)(ULONG_PTR)ProcessId,
                         CreateInfo->ImageFileName->Buffer,
                         L"PowerShell 编码/隐藏执行被拦截");
            CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
        }
    }
}

/* ============================================================
 * 注册表回调 (注册表防护)
 * 规则1: 自启动键 (CurrentVersion\Run / RunOnce) 写删拦截
 * 规则2: 服务注入拦截 (Services\<name>\ImagePath 指向临时目录)
 * 全部拦截行为入内核事件队列
 * ============================================================ */
NTSTATUS
FavRegistryCallback(
    _In_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2
)
{
    UNREFERENCED_PARAMETER(CallbackContext);

    if (!Argument1 || !Argument2) {
        return STATUS_SUCCESS;
    }

    if (!g_Fav.RegistryGuardEnabled) {
        return STATUS_SUCCESS;
    }

    REG_NOTIFY_CLASS notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;

    if (notifyClass == RegNtPreSetValueKey)
    {
        PREG_SET_VALUE_KEY_INFORMATION info = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;

        if (info && info->Object)
        {
            PUNICODE_STRING keyPath = NULL;
            if (NT_SUCCESS(CmCallbackGetKeyObjectIDEx(&g_Fav.RegistryCookie, info->Object, NULL, &keyPath, 0)) && keyPath)
            {
                BOOLEAN blocked = FALSE;

                /* 规则1: 自启动键写拦截 */
                if (FavUnicodeContainsPath(keyPath, L"\\CurrentVersion\\Run") ||
                    FavUnicodeContainsPath(keyPath, L"\\CurrentVersion\\RunOnce"))
                {
                    FavPushEvent(FAV_EVT_REGISTRY_BLOCKED,
                                 (ULONG)(ULONG_PTR)PsGetCurrentProcessId(),
                                 keyPath->Buffer,
                                 L"自启动键写入被拦截");
                    FavLog("registry guard: blocked autorun write");
                    blocked = TRUE;
                }
                /* 规则2: 服务注入拦截 —— Services\<name>\ImagePath 指向临时目录 */
                else if (FavUnicodeContainsPath(keyPath, L"\\Services\\") &&
                         info->ValueName && info->ValueName->Length > 0)
                {
                    UNICODE_STRING imagePath;
                    RtlInitUnicodeString(&imagePath, L"ImagePath");

                    if (RtlEqualUnicodeString(info->ValueName, &imagePath, TRUE) && info->Data && info->DataSize >= 8)
                    {
                        /* REG_SZ 数据为宽字符, 检查是否指向临时/下载目录 */
                        UNICODE_STRING dataStr;
                        dataStr.Buffer = (PWSTR)info->Data;
                        dataStr.Length = (USHORT)(info->DataSize > 512 ? 512 : (info->DataSize & ~1));
                        dataStr.MaximumLength = dataStr.Length;

                        if (FavUnicodeContainsPath(&dataStr, L"\\temp\\") ||
                            FavUnicodeContainsPath(&dataStr, L"\\tmp\\") ||
                            FavUnicodeContainsPath(&dataStr, L"\\downloads\\"))
                        {
                            FavPushEvent(FAV_EVT_REGISTRY_BLOCKED,
                                         (ULONG)(ULONG_PTR)PsGetCurrentProcessId(),
                                         keyPath->Buffer,
                                         L"服务 ImagePath 指向临时目录（服务注入被拦截）");
                            FavLog("registry guard: blocked service injection");
                            blocked = TRUE;
                        }
                    }
                }

                CmCallbackReleaseKeyObjectIDEx(keyPath);

                if (blocked)
                    return STATUS_ACCESS_DENIED;
            }
        }
    }
    else if (notifyClass == RegNtPreDeleteKey)
    {
        PREG_DELETE_KEY_INFORMATION info = (PREG_DELETE_KEY_INFORMATION)Argument2;

        if (info && info->Object)
        {
            PUNICODE_STRING keyPath = NULL;
            if (NT_SUCCESS(CmCallbackGetKeyObjectIDEx(&g_Fav.RegistryCookie, info->Object, NULL, &keyPath, 0)) && keyPath)
            {
                BOOLEAN blocked =
                    FavUnicodeContainsPath(keyPath, L"\\CurrentVersion\\Run") ||
                    FavUnicodeContainsPath(keyPath, L"\\CurrentVersion\\RunOnce");

                if (blocked)
                {
                    FavPushEvent(FAV_EVT_REGISTRY_BLOCKED,
                                 (ULONG)(ULONG_PTR)PsGetCurrentProcessId(),
                                 keyPath->Buffer,
                                 L"自启动键删除被拦截");
                    FavLog("registry guard: blocked autorun key delete");
                }

                CmCallbackReleaseKeyObjectIDEx(keyPath);

                if (blocked)
                    return STATUS_ACCESS_DENIED;
            }
        }
    }

    return STATUS_SUCCESS;
}

/* ============================================================
 * Ob 句柄回调 (多进程自保护 + 注入尝试检测)
 * 行为: 外部进程打开受保护进程句柄时剥离危险权限;
 *       请求含 VM_WRITE / CREATE_THREAD 时上报注入尝试事件
 * ============================================================ */
OB_PREOP_CALLBACK_STATUS
FavObPreOperationCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (OperationInformation->Object == NULL ||
        g_Fav.ProtectedPidCount == 0)
    {
        return OB_PREOP_SUCCESS;
    }

    if (OperationInformation->KernelHandle ||
        OperationInformation->ObjectType != *PsProcessType)
    {
        return OB_PREOP_SUCCESS;
    }

    PEPROCESS targetProcess = (PEPROCESS)OperationInformation->Object;
    HANDLE targetPid = PsGetProcessId(targetProcess);

    if (!FavIsProtectedPid(targetPid))
    {
        return OB_PREOP_SUCCESS;
    }

    ULONG requested = OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
    ULONG stripped = requested & (PROCESS_TERMINATE | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION);
    ULONG injected = requested & (PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION);
    ULONG sourcePid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();

    if (injected)
    {
        /* 注入尝试: 上报内核事件（用户态轮询→弹窗） */
        WCHAR detail[FAV_EVENT_TEXT];

        RtlStringCchPrintfW(detail, FAV_EVENT_TEXT,
                            L"PID %u attempted cross-process write/injection into protected process (PID %llu)",
                            sourcePid, (ULONG64)(ULONG_PTR)targetPid);

        FavPushEvent(FAV_EVT_INJECTION_ATTEMPT, sourcePid, L"injection", detail);
        FavLog("injection attempt: PID %u -> protected PID %llu",
               sourcePid, (ULONG64)(ULONG_PTR)targetPid);
    }

    /* 剥离危险权限（防杀/防注入） */
    OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &=
        ~stripped;

    /* 有实际剥离才上报句柄剥离事件（用户态"进程保护"弹窗） */
    if (stripped)
    {
        WCHAR stripDetail[FAV_EVENT_TEXT];

        RtlStringCchPrintfW(stripDetail, FAV_EVENT_TEXT,
                            L"PID %u open handle to protected process (PID %llu) stripped: rights=0x%08X",
                            sourcePid, (ULONG64)(ULONG_PTR)targetPid, stripped);

        FavPushEvent(FAV_EVT_HANDLE_STRIPPED, sourcePid, L"handle-strip", stripDetail);
        FavLog("handle stripped: PID %u -> protected PID %llu, rights=0x%08X",
               sourcePid, (ULONG64)(ULONG_PTR)targetPid, stripped);
    }

    return OB_PREOP_SUCCESS;
}

/* ============================================================
 * 注册进程/注册表/Ob 回调
 * ============================================================ */
static NTSTATUS
FavRegisterCallbacks(VOID)
{
    NTSTATUS status;

    /* 1. 进程创建回调 */
    status = PsSetCreateProcessNotifyRoutineEx(FavProcessNotifyCallback, FALSE);
    if (!NT_SUCCESS(status)) {
        FavLog("register process callback failed: 0x%08X", status);
        return status;
    }
    g_Fav.ProcessCallbackRegistered = TRUE;

    /* 2. 注册表回调 */
    UNICODE_STRING altitude;
    RtlInitUnicodeString(&altitude, L"380090");

    status = CmRegisterCallbackEx(FavRegistryCallback, &altitude, g_ControlDevice, NULL, &g_Fav.RegistryCookie, NULL);
    if (!NT_SUCCESS(status)) {
        FavLog("register registry callback failed: 0x%08X", status);
        return status;
    }
    g_Fav.RegistryCallbackRegistered = TRUE;

    /* 3. Ob 句柄回调 (多进程自保护) */
    OB_OPERATION_REGISTRATION obOperations[1];
    OB_CALLBACK_REGISTRATION obRegistration;

    RtlZeroMemory(obOperations, sizeof(obOperations));
    obOperations[0].ObjectType = PsProcessType;
    obOperations[0].Operations |= OB_OPERATION_HANDLE_CREATE;
    obOperations[0].Operations |= OB_OPERATION_HANDLE_DUPLICATE;
    obOperations[0].PreOperation = FavObPreOperationCallback;
    obOperations[0].PostOperation = NULL;

    RtlInitUnicodeString(&altitude, L"380091");
    obRegistration.Version = OB_FLT_REGISTRATION_VERSION;
    obRegistration.OperationRegistrationCount = 1;
    obRegistration.Altitude = altitude;
    obRegistration.RegistrationContext = NULL;
    obRegistration.OperationRegistration = obOperations;

    status = ObRegisterCallbacks(&obRegistration, &g_Fav.ObCallbackHandle);
    if (!NT_SUCCESS(status)) {
        /* Ob 回调需要驱动具备受保护标志(ILK), 失败不致命: 记录并继续 */
        FavLog("register Ob callback failed (needs signing): 0x%08X", status);
        g_Fav.ObCallbackRegistered = FALSE;
    }
    else {
        g_Fav.ObCallbackRegistered = TRUE;
    }

    return STATUS_SUCCESS;
}

/* ============================================================
 * 磁盘写保护: 附加到系统盘 \Device\Harddisk0\Partition0 设备栈
 * ============================================================ */
NTSTATUS
FavAttachToDiskStack(VOID)
{
    NTSTATUS status;
    UNICODE_STRING diskPath;
    PFILE_OBJECT fileObject = NULL;
    PDEVICE_OBJECT diskDevice = NULL;
    PDEVICE_OBJECT filterDevice = NULL;

    RtlInitUnicodeString(&diskPath, L"\\Device\\Harddisk0\\Partition0");

    status = IoGetDeviceObjectPointer(&diskPath, FILE_READ_ATTRIBUTES, &fileObject, &diskDevice);
    if (!NT_SUCCESS(status)) {
        FavLog("locate harddisk0 failed: 0x%08X", status);
        return status;
    }

    status = IoCreateDevice(g_Fav.DriverObject,
                            sizeof(FAV_DEVICE_EXTENSION),
                            NULL,
                            diskDevice->DeviceType,
                            diskDevice->Characteristics,
                            FALSE,
                            &filterDevice);
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(fileObject);
        FavLog("create disk filter device failed: 0x%08X", status);
        return status;
    }

    filterDevice->Flags |= DO_DIRECT_IO;
    filterDevice->Flags |= DO_BUFFERED_IO;
    filterDevice->Flags &= ~DO_DEVICE_INITIALIZING;

    PFAV_DEVICE_EXTENSION ext = (PFAV_DEVICE_EXTENSION)filterDevice->DeviceExtension;
    ext->TargetDevice = IoAttachDeviceToDeviceStack(filterDevice, diskDevice);
    ext->DiskFileObject = fileObject;

    if (ext->TargetDevice == NULL) {
        IoDeleteDevice(filterDevice);
        ObDereferenceObject(fileObject);
        FavLog("attach to disk stack failed");
        return STATUS_UNSUCCESSFUL;
    }

    g_Fav.DiskFilterDevice = filterDevice;
    g_Fav.DiskTargetDevice = ext->TargetDevice;
    g_Fav.DiskFileObject = fileObject;

    FavLog("disk write guard attached to Harddisk0 stack");
    return STATUS_SUCCESS;
}

VOID
FavDetachFromDiskStack(VOID)
{
    if (g_Fav.DiskFilterDevice && g_Fav.DiskTargetDevice) {
        IoDetachDevice(g_Fav.DiskTargetDevice);
    }
    if (g_Fav.DiskFilterDevice) {
        IoDeleteDevice(g_Fav.DiskFilterDevice);
        g_Fav.DiskFilterDevice = NULL;
    }
    if (g_Fav.DiskFileObject) {
        ObDereferenceObject(g_Fav.DiskFileObject);
        g_Fav.DiskFileObject = NULL;
    }
}

/* ============================================================
 * IRP_MJ_WRITE (磁盘过滤): MBR / GPT 分级写拦截 + 事件上报
 * ============================================================ */
NTSTATUS
FavDispatchWrite(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
)
{
    /* 非磁盘过滤设备(控制设备)不处理写请求 */
    if (DeviceObject != g_Fav.DiskFilterDevice) {
        Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    PFAV_DEVICE_EXTENSION ext = (PFAV_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);

    if (irpSp->Parameters.Write.Length > 0) {
        LARGE_INTEGER byteOffset = irpSp->Parameters.Write.ByteOffset;

        /* 分区表防护: MBR 写拦截 (LBA0, 前 512 字节) */
        if (g_Fav.DiskGuardEnabled &&
            byteOffset.QuadPart >= 0 && byteOffset.QuadPart < 512) {
            FavPushEvent(FAV_EVT_DISK_WRITE_BLOCKED,
                         (ULONG)(ULONG_PTR)PsGetCurrentProcessId(),
                         L"Harddisk0",
                         L"MBR 写入被拦截（分区表防护）");
            FavLog("MBR write blocked (offset %lld, len %u)",
                   byteOffset.QuadPart, irpSp->Parameters.Write.Length);
            Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
            Irp->IoStatus.Information = 0;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_ACCESS_DENIED;
        }

        /* UEFI 防护: GPT 头与分区表写拦截 (LBA1..33, 512B~17KB) */
        if (g_Fav.GptGuardEnabled &&
            byteOffset.QuadPart >= 512 && byteOffset.QuadPart < FAV_MBR_GPT_PROTECT_BYTES) {
            FavPushEvent(FAV_EVT_DISK_WRITE_BLOCKED,
                         (ULONG)(ULONG_PTR)PsGetCurrentProcessId(),
                         L"Harddisk0",
                         L"GPT 引导结构写入被拦截（UEFI 防护）");
            FavLog("GPT write blocked (offset %lld, len %u)",
                   byteOffset.QuadPart, irpSp->Parameters.Write.Length);
            Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
            Irp->IoStatus.Information = 0;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_ACCESS_DENIED;
        }
    }

    /* 放行: 传递给下层设备 */
    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(ext->TargetDevice, Irp);
}

/* ============================================================
 * IOCTL 处理
 * ============================================================ */
static NTSTATUS
FavHandleIoctl(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION irpSp
)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG ioctl = irpSp->Parameters.DeviceIoControl.IoControlCode;
    PVOID buffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG inputLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outputLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

    switch (ioctl) {

    case FAV_IOCTL_SET_FILE_FILTER:
    {
        if (inputLength < sizeof(FAV_FILE_CONFIG)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        PFAV_FILE_CONFIG cfg = (PFAV_FILE_CONFIG)buffer;
        g_Fav.FileGuardEnabled = cfg->BlockSuspiciousExtensions ? 1 : 0;
        FavLog("file filter config received (guard=%d)", g_Fav.FileGuardEnabled);
        break;
    }

    case FAV_IOCTL_SET_PROCESS_FILTER:
    {
        if (inputLength < sizeof(FAV_PROCESS_CONFIG)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        PFAV_PROCESS_CONFIG cfg = (PFAV_PROCESS_CONFIG)buffer;
        g_Fav.ProcessGuardEnabled = (cfg->MonitorProcessCreation && cfg->BlockCodeInjection) ? 1 : 0;
        FavLog("process filter config received (guard=%d)", g_Fav.ProcessGuardEnabled);
        break;
    }

    case FAV_IOCTL_SET_REGISTRY_FILTER:
    {
        if (inputLength < sizeof(FAV_REGISTRY_CONFIG)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        PFAV_REGISTRY_CONFIG cfg = (PFAV_REGISTRY_CONFIG)buffer;
        g_Fav.RegistryGuardEnabled = (cfg->MonitorAutoRun && cfg->BlockSuspiciousKeys) ? 1 : 0;
        FavLog("registry filter config received (guard=%d)", g_Fav.RegistryGuardEnabled);
        break;
    }

    case FAV_IOCTL_SET_PROTECTED_PID:
    {
        /* 输入: [ULONG count][ULONG pids[count]] —— 批量受保护进程 */
        if (inputLength < sizeof(ULONG)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        ULONG count = *(PULONG)buffer;
        if (count > FAV_MAX_PIDS) count = FAV_MAX_PIDS;
        if (inputLength < sizeof(ULONG) + count * sizeof(ULONG)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        PULONG pids = (PULONG)((PUCHAR)buffer + sizeof(ULONG));
        g_Fav.ProtectedPidCount = count;
        for (ULONG i = 0; i < count; i++)
            g_Fav.ProtectedPids[i] = (HANDLE)(ULONG_PTR)pids[i];

        FavLog("protected processes updated: %u", count);
        break;
    }

    case FAV_IOCTL_ENABLE_DISK_GUARD:
    {
        /* 输入 8 字节: [0] mbrGuard(分区表防护), [4] gptGuard(UEFI防护) */
        if (inputLength < 2 * sizeof(LONG)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        LONG mbrGuard = ((LONG *)buffer)[0];
        LONG gptGuard = ((LONG *)buffer)[1];

        g_Fav.DiskGuardEnabled = mbrGuard ? 1 : 0;
        g_Fav.GptGuardEnabled = gptGuard ? 1 : 0;
        FavLog("disk guard: mbr=%d, gpt=%d", g_Fav.DiskGuardEnabled, g_Fav.GptGuardEnabled);
        break;
    }

    case FAV_IOCTL_GET_EVENTS:
    {
        /* 输出: [ULONG count][FAV_EVENT × count]
           队列非空 → 立即返回；队列空 → 挂起 IRP（异步），事件入队时完成 */
        if (outputLength < sizeof(ULONG)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        KIRQL oldIrql;
        ULONG maxEvents;
        ULONG count = 0;
        PFAV_EVENT outEvents = (PFAV_EVENT)((PUCHAR)buffer + sizeof(ULONG));
        BOOLEAN empty;

        KeAcquireSpinLock(&g_Fav.EventLock, &oldIrql);
        empty = (g_EventHead == g_EventTail);
        if (!empty) {
            maxEvents = (outputLength - sizeof(ULONG)) / sizeof(FAV_EVENT);
            while (g_EventTail != g_EventHead && count < maxEvents) {
                outEvents[count] = g_Fav.EventQueue[g_EventTail];
                g_EventTail = (g_EventTail + 1) % FAV_EVENT_QUEUE_SIZE;
                count++;
            }
        }
        KeReleaseSpinLock(&g_Fav.EventLock, oldIrql);

        if (!empty) {
            *(PULONG)buffer = count;
            Irp->IoStatus.Information = sizeof(ULONG) + count * sizeof(FAV_EVENT);
            status = STATUS_SUCCESS;
            break;
        }

        /* 空队列：只允许一个挂起 IRP，其余同步返回空（用户态单通道） */
        if (g_Fav.PendingEventIrp != NULL) {
            *(PULONG)buffer = 0;
            Irp->IoStatus.Information = sizeof(ULONG);
            status = STATUS_SUCCESS;
            break;
        }

        if (IoSetCancelRoutine(Irp, FavCancelPendingEventIrp) != NULL) {
            status = STATUS_CANCELLED;
            break;
        }
        if (Irp->Cancel) {
            if (IoSetCancelRoutine(Irp, NULL) != NULL) {
                status = STATUS_CANCELLED;
                break;
            }
        }

        g_Fav.PendingEventIrp = Irp;
        IoMarkIrpPending(Irp);
        status = STATUS_PENDING;
        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    return status;
}

NTSTATUS
FavDispatchDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
)
{
    NTSTATUS status;
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG ioctl = irpSp->Parameters.DeviceIoControl.IoControlCode;

    UNREFERENCED_PARAMETER(DeviceObject);

    status = FavHandleIoctl(Irp, irpSp);

    /* 异步事件 IRP：已 IoMarkIrpPending 并挂起，不能在这里完成 */
    if (status == STATUS_PENDING) {
        return STATUS_PENDING;
    }

    /* GET_EVENTS 由 HandleIoctl 设置 Information（事件数据长度），其余清零 */
    if (ioctl != FAV_IOCTL_GET_EVENTS)
    {
        Irp->IoStatus.Information = 0;
    }

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS
FavDispatchCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/* ============================================================
 * 驱动卸载
 * ============================================================ */
VOID
FavUnload(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    UNREFERENCED_PARAMETER(DriverObject);

    if (g_Fav.ProcessCallbackRegistered) {
        PsSetCreateProcessNotifyRoutineEx(FavProcessNotifyCallback, TRUE);
    }
    if (g_Fav.RegistryCallbackRegistered) {
        CmUnRegisterCallback(g_Fav.RegistryCookie);
    }
    if (g_Fav.ObCallbackRegistered) {
        ObUnRegisterCallbacks(g_Fav.ObCallbackHandle);
    }

    /* 卸载：完成所有挂起的异步事件 IRP，避免引用计数导致卸载挂起 */
    {
        KIRQL oldIrql;
        PIRP pending;
        KeAcquireSpinLock(&g_Fav.PendingLock, &oldIrql);
        pending = g_Fav.PendingEventIrp;
        g_Fav.PendingEventIrp = NULL;
        KeReleaseSpinLock(&g_Fav.PendingLock, oldIrql);

        if (pending != NULL && IoSetCancelRoutine(pending, NULL) != NULL) {
            pending->IoStatus.Status = STATUS_CANCELLED;
            pending->IoStatus.Information = 0;
            IoCompleteRequest(pending, IO_NO_INCREMENT);
        }
    }

    /* minifilter 注销（必须在磁盘过滤设备删除前） */
    if (g_FavFilter != NULL) {
        FltUnregisterFilter(g_FavFilter);
        g_FavFilter = NULL;
        g_FilterStarted = FALSE;
    }

    FavDetachFromDiskStack();

    if (g_SymlinkCreated) {
        UNICODE_STRING symlink;
        RtlInitUnicodeString(&symlink, FAV_SYMLINK_NAME);
        IoDeleteSymbolicLink(&symlink);
    }
    if (g_DeviceCreated && g_ControlDevice) {
        IoDeleteDevice(g_ControlDevice);
    }

    FavLog("driver unloaded");
}

/* ============================================================
 * 驱动入口
 * ============================================================ */
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status;
    UNICODE_STRING deviceName;
    UNICODE_STRING symlinkName;

    UNREFERENCED_PARAMETER(RegistryPath);

    RtlZeroMemory(&g_Fav, sizeof(g_Fav));
    g_Fav.DriverObject = DriverObject;
    KeInitializeSpinLock(&g_Fav.EventLock);
    KeInitializeSpinLock(&g_Fav.PendingLock);

    FavLog("driver loading (full build 2.0.0.0)");

    /* 0. minifilter 文件写/删除遥测（失败不阻断其余防护） */
    FavStartMiniFilter(DriverObject);

    /* 1. 创建控制设备 + 符号链接 */
    RtlInitUnicodeString(&deviceName, FAV_DEVICE_NAME);
    status = IoCreateDevice(DriverObject,
                            0,
                            &deviceName,
                            FILE_DEVICE_UNKNOWN,
                            FILE_DEVICE_SECURE_OPEN,
                            FALSE,
                            &g_ControlDevice);
    if (!NT_SUCCESS(status)) {
        FavLog("create control device failed: 0x%08X", status);
        return status;
    }
    g_DeviceCreated = TRUE;

    RtlInitUnicodeString(&symlinkName, FAV_SYMLINK_NAME);
    status = IoCreateSymbolicLink(&symlinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        FavLog("create symlink failed: 0x%08X", status);
        IoDeleteDevice(g_ControlDevice);
        g_DeviceCreated = FALSE;
        return status;
    }
    g_SymlinkCreated = TRUE;

    /* 2. 分派例程 */
    DriverObject->MajorFunction[IRP_MJ_CREATE] = FavDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = FavDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = FavDispatchDeviceControl;
    DriverObject->MajorFunction[IRP_MJ_WRITE] = FavDispatchWrite;
    DriverObject->DriverUnload = FavUnload;

    /* 3. 注册三大回调 */
    status = FavRegisterCallbacks();
    if (!NT_SUCCESS(status)) {
        FavLog("callback registration failed, aborting: 0x%08X", status);
        FavUnload(DriverObject);
        return status;
    }

    /* 4. 附加磁盘设备栈 (分区表/UEFI 防护) */
    status = FavAttachToDiskStack();
    if (!NT_SUCCESS(status)) {
        /* 非致命: 其他防护仍可用 */
        FavLog("disk filter attach failed (disk guard unavailable): 0x%08X", status);
    }

    FavLog("driver loaded: process/registry/multi-process-protection/disk-guard/event-pipeline ready");
    return STATUS_SUCCESS;
}