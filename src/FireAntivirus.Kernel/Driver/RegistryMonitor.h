#pragma once

#include <ntddk.h>
#include <wdm.h>

extern PDRIVER_OBJECT DriverObject;
extern PVOID g_CallbackHandle;
extern BOOLEAN g_RegistryMonitorInitialized;

// 注册表操作类型枚举
typedef enum _REGISTRY_OPERATION {
    REG_CREATE_KEY = 1,
    REG_OPEN_KEY,
    REG_DELETE_KEY,
    REG_SET_VALUE,
    REG_DELETE_VALUE,
    REG_RENAME_KEY
} REGISTRY_OPERATION;

class RegistryMonitor
{
public:
    // 初始化和清理
    static NTSTATUS Initialize();
    static VOID Cleanup();

    // 注册表保护检查
    static BOOLEAN IsRegistryKeyProtected(_In_ PUNICODE_STRING KeyName);
    static BOOLEAN IsAutoRunKey(_In_ PUNICODE_STRING KeyName);
    static BOOLEAN IsCriticalSystemValue(
        _In_ PUNICODE_STRING KeyName,
        _In_ PUNICODE_STRING ValueName);
    
    // 进程检查
    static BOOLEAN HasSufficientPrivilege(
        _In_ ULONG ProcessId,
        _In_ REGISTRY_OPERATION Operation);
    static BOOLEAN IsTrustedProcess(_In_ ULONG ProcessId);

private:
    // 注册表回调函数
    static NTSTATUS RegistryCallback(
        _In_ PVOID CallbackContext,
        _In_opt_ PVOID Argument1,
        _In_opt_ PVOID Argument2);
    
    // 各种操作的前回调
    static NTSTATUS PreCreateKeyCallback(
        _In_ PREG_PRE_CREATE_KEY_INFORMATION CallbackInfo);
        
    static NTSTATUS PreCreateKeyExCallback(
        _In_ PREG_CREATE_KEY_INFORMATION CallbackInfo);
        
    static NTSTATUS PreOpenKeyCallback(
        _In_ PREG_PRE_OPEN_KEY_INFORMATION CallbackInfo);
        
    static NTSTATUS PreDeleteKeyCallback(
        _In_ PREG_PRE_DELETE_KEY_INFORMATION CallbackInfo);
        
    static NTSTATUS PreSetValueCallback(
        _In_ PREG_PRE_SET_VALUE_KEY_INFORMATION CallbackInfo);
        
    static NTSTATUS PreDeleteValueCallback(
        _In_ PREG_PRE_DELETE_VALUE_KEY_INFORMATION CallbackInfo);
        
    static NTSTATUS PreRenameKeyCallback(
        _In_ PREG_PRE_RENAME_KEY_INFORMATION CallbackInfo);
    
    // 辅助函数
    static BOOLEAN GetKeyNameFromObject(
        _In_ PVOID Object,
        _Out_ PUNICODE_STRING KeyName);
        
    static VOID LogRegistryEvent(
        _In_ PUNICODE_STRING KeyName,
        _In_ ULONG ProcessId,
        _In_ REGISTRY_OPERATION Operation);
};

// 全局回调声明
extern "C" {
    NTSTATUS RegCallback(
        _In_ PVOID CallbackContext,
        _In_opt_ PVOID Argument1,
        _In_opt_ PVOID Argument2);
}