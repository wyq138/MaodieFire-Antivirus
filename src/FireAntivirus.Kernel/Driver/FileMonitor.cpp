#include "pch.h"
#include "FileMonitor.h"
#include "Driver.h"
#include <fltKernel.h>

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

#define FILE_MONITOR_TAG 'FMNT'

// 受保护的文件模式（通配符匹配）
static UNICODE_STRING ProtectedFilePatterns[] = {
    RTL_CONSTANT_STRING(L"*\\windows\\system32\\config\\*"),
    RTL_CONSTANT_STRING(L"*\\windows\\system32\\drivers\\*"),
    RTL_CONSTANT_STRING(L"*\\windows\\system32\\*.exe"),
    RTL_CONSTANT_STRING(L"*\\windows\\system32\\*.dll"),
    RTL_CONSTANT_STRING(L"*\\program files\\*\\*.exe"),
    RTL_CONSTANT_STRING(L"*\\fireantivirus\\*")
};

// 文件操作类型
typedef enum _FILE_OPERATION {
    CREATE_OPERATION = 0,
    DELETE_OPERATION,
    MODIFY_OPERATION,
    RENAME_OPERATION
} FILE_OPERATION;

// 全局过滤器句柄
PFLT_FILTER g_FileFilter = NULL;
BOOLEAN g_FileMonitorInitialized = FALSE;

NTSTATUS
FileMonitor::Initialize()
{
    NTSTATUS status = STATUS_SUCCESS;
    PSECURITY_DESCRIPTOR sd;
    
    KdPrint(("[FireAntivirus.FileMonitor] Initializing file monitoring driver\n"));

    // 注册文件系统微过滤器
    status = RegisterMinifilter();
    if (!NT_SUCCESS(status))
    {
        KdPrint(("[FireAntivirus.FileMonitor] Failed to register minifilter: 0x%X\n", status));
        return status;
    }

    g_FileMonitorInitialized = TRUE;
    KdPrint(("[FireAntivirus.FileMonitor] File monitoring initialized successfully\n"));
    
    return status;
}

VOID
FileMonitor::Cleanup()
{
    if (g_FileFilter != NULL)
    {
        FltUnregisterFilter(g_FileFilter);
        g_FileFilter = NULL;
    }
    
    g_FileMonitorInitialized = FALSE;
    KdPrint(("[FireAntivirus.FileMonitor] File monitoring cleanup completed\n"));
}

NTSTATUS
FileMonitor::RegisterMinifilter()
{
    NTSTATUS status;
    FLT_REGISTRATION fltRegistration;
    
    // 配置过滤器注册信息
    RtlZeroMemory(&fltRegistration, sizeof(FLT_REGISTRATION));
    
    fltRegistration.Size = sizeof(FLT_REGISTRATION);
    fltRegistration.Version = FLT_REGISTRATION_VERSION;
    fltRegistration.Flags = 0;
    fltRegistration.ContextRegistration = NULL;
    fltRegistration.OperationRegistration = OperationRegistration;
    fltRegistration.FilterUnloadCallback = FileFilterUnload;
    fltRegistration.InstanceSetupCallback = FileInstanceSetup;
    fltRegistration.InstanceQueryTeardownCallback = FileInstanceQueryTeardown;
    fltRegistration.InstanceTeardownStartCallback = NULL;
    fltRegistration.InstanceTeardownCompleteCallback = NULL;
    fltRegistration.GenerateFileNameCallback = NULL;
    fltRegistration.NormalizeNameComponentCallback = NULL;
    fltRegistration.NormalizeContextCleanupCallback = NULL;
    
    // 注册过滤器
    status = FltRegisterFilter(
        DriverObject,
        &fltRegistration,
        &g_FileFilter
    );
    
    if (NT_SUCCESS(status))
    {
        // 启动过滤器
        status = FltStartFiltering(g_FileFilter);
        if (!NT_SUCCESS(status))
        {
            FltUnregisterFilter(g_FileFilter);
            g_FileFilter = NULL;
        }
    }
    
    return status;
}

// 文件打开回调
FLT_PREOP_CALLBACK_STATUS
FileMonitor::FilePreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PVOID *CompletionContext
)
{
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(FltObjects);
    
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status;
    
    // 获取文件名信息
    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo
    );
    
    if (NT_SUCCESS(status) && nameInfo != NULL)
    {
        // 检查是否为受保护文件
        if (IsFileProtected(nameInfo->Name))
        {
            // 记录安全事件
            LogFileEvent(nameInfo->Name, Data->RequestorMode != KernelMode, CREATE_OPERATION);
            
            // 如果是用户模式请求，可能需要拦截
            if (Data->RequestorMode != KernelMode)
            {
                // 检查权限 - 系统文件只允许管理员访问
                if (IsSystemFile(nameInfo->Name))
                {
                    // TODO: 实现权限检查逻辑
                }
            }
        }
        
        FltReleaseFileNameInformation(nameInfo);
    }
    
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// 文件写入回调
FLT_PREOP_CALLBACK_STATUS
FileMonitor::FilePreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PVOID *CompletionContext
)
{
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(FltObjects);
    
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status;
    
    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo
    );
    
    if (NT_SUCCESS(status) && nameInfo != NULL)
    {
        if (IsFileProtected(nameInfo->Name))
        {
            LogFileEvent(nameInfo->Name, Data->RequestorMode != KernelMode, MODIFY_OPERATION);
            
            // 检查是否有写权限
            if (Data->RequestorMode != KernelMode)
            {
                if (IsSystemExecutable(nameInfo->Name))
                {
                    // 系统可执行文件只允许可信进程修改
                    if (!IsTrustedProcess(PsGetCurrentProcessId()))
                    {
                        KdPrint(("[FireAntivirus.FileMonitor] Blocking unauthorized write to system executable %wZ\n", nameInfo->Name));
                        FltReleaseFileNameInformation(nameInfo);
                        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                        return FLT_PREOP_COMPLETE;
                    }
                }
            }
        }
        
        FltReleaseFileNameInformation(nameInfo);
    }
    
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// 文件删除回调
FLT_PREOP_CALLBACK_STATUS
FileMonitor::FilePreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PVOID *CompletionContext
)
{
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(FltObjects);
    
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    PFILE_OBJECT fileObject = Data->Iopb->TargetFileObject;
    NTSTATUS status;
    
    // 检查是否是删除操作
    if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileDispositionInformation)
    {
        PFILE_DISPOSITION_INFORMATION disposition = 
            (PFILE_DISPOSITION_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
        
        if (disposition->DeleteFile)
        {
            status = FltGetFileNameInformation(
                Data,
                FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
                &nameInfo
            );
            
            if (NT_SUCCESS(status) && nameInfo != NULL)
            {
                if (IsFileProtected(nameInfo->Name))
                {
                    LogFileEvent(nameInfo->Name, Data->RequestorMode != KernelMode, DELETE_OPERATION);
                    
                    // 系统文件不允许删除
                    if (IsSystemFile(nameInfo->Name))
                    {
                        KdPrint(("[FireAntivirus.FileMonitor] Blocking deletion of system file %wZ\n", nameInfo->Name));
                        FltReleaseFileNameInformation(nameInfo);
                        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                        return FLT_PREOP_COMPLETE;
                    }
                }
                
                FltReleaseFileNameInformation(nameInfo);
            }
        }
    }
    
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// 判断文件是否受保护
BOOLEAN
FileMonitor::IsFileProtected(_In_ PUNICODE_STRING FileName)
{
    USHORT i;
    
    for (i = 0; i < ARRAYSIZE(ProtectedFilePatterns); i++)
    {
        if (FsRtlIsNameInExpression(&ProtectedFilePatterns[i], FileName, TRUE, NULL))
        {
            return TRUE;
        }
    }
    
    return FALSE;
}

// 判断是否为系统文件
BOOLEAN
FileMonitor::IsSystemFile(_In_ PUNICODE_STRING FileName)
{
    UNICODE_STRING windowsPath = RTL_CONSTANT_STRING(L"\\windows\\");
    UNICODE_STRING system32Path = RTL_CONSTANT_STRING(L"\\windows\\system32\\");
    
    return (wcsstr(FileName->Buffer, L"\\windows\\") != NULL);
}

// 判断是否为系统可执行文件
BOOLEAN
FileMonitor::IsSystemExecutable(_In_ PUNICODE_STRING FileName)
{
    return (IsSystemFile(FileName) && 
            (wcsstr(FileName->Buffer, L".exe") != NULL || 
             wcsstr(FileName->Buffer, L".dll") != NULL ||
             wcsstr(FileName->Buffer, L".sys") != NULL));
}

// 判断是否为可信进程
BOOLEAN
FileMonitor::IsTrustedProcess(_In_ ULONG ProcessId)
{
    // 可信进程列表：系统进程、安全软件进程等
    ULONG trustedProcesses[] = { 4, 0 }; // System (PID 4), ...
    USHORT i;
    
    for (i = 0; trustedProcesses[i] != 0; i++)
    {
        if (ProcessId == trustedProcesses[i])
        {
            return TRUE;
        }
    }
    
    return FALSE;
}

// 记录文件安全事件
VOID
FileMonitor::LogFileEvent(
    _In_ PUNICODE_STRING FileName,
    _In_ BOOLEAN IsUserMode,
    _In_ FILE_OPERATION Operation
)
{
    LARGE_INTEGER currentTime;
    ULONG processId = (ULONG)PsGetCurrentProcessId();
    
    KeQuerySystemTime(&currentTime);
    
    KdPrint(("[FireAntivirus.FileMonitor] File operation: Process=%lu, File=%wZ, Operation=%lu, UserMode=%u, Time=%I64d\n",
        processId, FileName, Operation, IsUserMode, currentTime.QuadPart));
}

// 过滤器操作注册表
CONST FLT_OPERATION_REGISTRATION OperationRegistration[] = {
    {
        IRP_MJ_CREATE,
        0,
        FileMonitor::FilePreCreate,
        NULL
    },
    {
        IRP_MJ_WRITE,
        0,
        FileMonitor::FilePreWrite,
        NULL
    },
    {
        IRP_MJ_SET_INFORMATION,
        0,
        FileMonitor::FilePreSetInformation,
        NULL
    },
    {
        IRP_MJ_OPERATION_END
    }
};

// 过滤器卸载回调
NTSTATUS
FileMonitor::FileFilterUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Flags);
    
    KdPrint(("[FireAntivirus.FileMonitor] File monitoring filter unloading\n"));
    return STATUS_SUCCESS;
}

// 实例设置回调
NTSTATUS
FileMonitor::FileInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);
    
    return STATUS_SUCCESS;
}

// 实例查询拆除回调
NTSTATUS
FileMonitor::FileInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    
    return STATUS_SUCCESS;
}