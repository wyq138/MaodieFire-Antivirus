// SystemCallHooker.h

#pragma once

#include <Windows.h>
#include <vector>
#include <string>

class SystemCallHooker {
private:
    static SystemCallHooker* instance;
    bool isInitialized;
    bool isHookingEnabled;

public:
    static SystemCallHooker* GetInstance();

    bool Initialize();
    void Shutdown();
    bool IsInitialized();

    // 挂钩管理
    bool EnableHooking();
    bool DisableHooking();
    bool IsHookingEnabled();

    // 系统调用挂钩
    bool HookSystemCall(DWORD syscallNumber, PVOID hookFunction);
    bool UnhookSystemCall(DWORD syscallNumber);
    bool IsSystemCallHooked(DWORD syscallNumber);

    // 常用系统调用挂钩
    bool HookProcessCreation();
    bool UnhookProcessCreation();
    bool HookFileOperations();
    bool UnhookFileOperations();
    bool HookRegistryOperations();
    bool UnhookRegistryOperations();
    bool HookNetworkOperations();
    bool UnhookNetworkOperations();

    // 回调函数类型
    typedef NTSTATUS(WINAPI* NtCreateProcessEx_t)(
        OUT PHANDLE ProcessHandle,
        IN ACCESS_MASK DesiredAccess,
        IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
        IN HANDLE ParentProcess,
        IN BOOLEAN InheritObjectTable,
        IN HANDLE SectionHandle OPTIONAL,
        IN HANDLE DebugPort OPTIONAL,
        IN HANDLE ExceptionPort OPTIONAL
    );

    typedef NTSTATUS(WINAPI* NtOpenProcess_t)(
        OUT PHANDLE ProcessHandle,
        IN ACCESS_MASK DesiredAccess,
        IN POBJECT_ATTRIBUTES ObjectAttributes,
        IN PCLIENT_ID ClientId
    );

    typedef NTSTATUS(WINAPI* NtCreateFile_t)(
        OUT PHANDLE FileHandle,
        IN ACCESS_MASK DesiredAccess,
        IN POBJECT_ATTRIBUTES ObjectAttributes,
        OUT PIO_STATUS_BLOCK IoStatusBlock,
        IN PLARGE_INTEGER AllocationSize OPTIONAL,
        IN ULONG FileAttributes,
        IN ULONG ShareAccess,
        IN ULONG CreateDisposition,
        IN ULONG CreateOptions,
        IN PVOID EaBuffer OPTIONAL,
        IN ULONG EaLength
    );

    // 原始函数指针
    static NtCreateProcessEx_t OriginalNtCreateProcessEx;
    static NtOpenProcess_t OriginalNtOpenProcess;
    static NtCreateFile_t OriginalNtCreateFile;

private:
    SystemCallHooker();
    ~SystemCallHooker();

    // 挂钩回调函数
    static NTSTATUS WINAPI HookedNtCreateProcessEx(
        OUT PHANDLE ProcessHandle,
        IN ACCESS_MASK DesiredAccess,
        IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
        IN HANDLE ParentProcess,
        IN BOOLEAN InheritObjectTable,
        IN HANDLE SectionHandle OPTIONAL,
        IN HANDLE DebugPort OPTIONAL,
        IN HANDLE ExceptionPort OPTIONAL
    );

    static NTSTATUS WINAPI HookedNtOpenProcess(
        OUT PHANDLE ProcessHandle,
        IN ACCESS_MASK DesiredAccess,
        IN POBJECT_ATTRIBUTES ObjectAttributes,
        IN PCLIENT_ID ClientId
    );

    static NTSTATUS WINAPI HookedNtCreateFile(
        OUT PHANDLE FileHandle,
        IN ACCESS_MASK DesiredAccess,
        IN POBJECT_ATTRIBUTES ObjectAttributes,
        OUT PIO_STATUS_BLOCK IoStatusBlock,
        IN PLARGE_INTEGER AllocationSize OPTIONAL,
        IN ULONG FileAttributes,
        IN ULONG ShareAccess,
        IN ULONG CreateDisposition,
        IN ULONG CreateOptions,
        IN PVOID EaBuffer OPTIONAL,
        IN ULONG EaLength
    );

    // 辅助方法
    bool InitializeSystemCallTable();
    bool RestoreSystemCallTable();
    PVOID GetSystemCallAddress(DWORD syscallNumber);
    bool WriteToKernelMemory(PVOID address, PVOID data, SIZE_T size);
};
