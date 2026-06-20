#pragma once

#include <fltKernel.h>

extern PDRIVER_OBJECT DriverObject;
extern PFLT_FILTER g_FileFilter;
extern BOOLEAN g_FileMonitorInitialized;

class FileMonitor
{
public:
    // 初始化和清理
    static NTSTATUS Initialize();
    static VOID Cleanup();

    // 文件保护检查
    static BOOLEAN IsFileProtected(_In_ PUNICODE_STRING FileName);
    static BOOLEAN IsSystemFile(_In_ PUNICODE_STRING FileName);
    static BOOLEAN IsSystemExecutable(_In_ PUNICODE_STRING FileName);
    static BOOLEAN IsTrustedProcess(_In_ ULONG ProcessId);

private:
    // 过滤器注册
    static NTSTATUS RegisterMinifilter();
    
    // 回调函数
    static FLT_PREOP_CALLBACK_STATUS FilePreCreate(
        _Inout_ PFLT_CALLBACK_DATA Data,
        _In_ PCFLT_RELATED_OBJECTS FltObjects,
        _Out_ PVOID *CompletionContext);
        
    static FLT_PREOP_CALLBACK_STATUS FilePreWrite(
        _Inout_ PFLT_CALLBACK_DATA Data,
        _In_ PCFLT_RELATED_OBJECTS FltObjects,
        _Out_ PVOID *CompletionContext);
        
    static FLT_PREOP_CALLBACK_STATUS FilePreSetInformation(
        _Inout_ PFLT_CALLBACK_DATA Data,
        _In_ PCFLT_RELATED_OBJECTS FltObjects,
        _Out_ PVOID *CompletionContext);

    // 辅助函数
    static VOID LogFileEvent(
        _In_ PUNICODE_STRING FileName,
        _In_ BOOLEAN IsUserMode,
        _In_ FILE_OPERATION Operation);
        
    // WDF函数声明
    static NTSTATUS FileFilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);
    static NTSTATUS FileInstanceSetup(
        _In_ PCFLT_RELATED_OBJECTS FltObjects,
        _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
        _In_ DEVICE_TYPE VolumeDeviceType,
        _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType);
    static NTSTATUS FileInstanceQueryTeardown(
        _In_ PCFLT_RELATED_OBJECTS FltObjects,
        _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags);
};

// 过滤器操作注册表声明
extern CONST FLT_OPERATION_REGISTRATION OperationRegistration[];