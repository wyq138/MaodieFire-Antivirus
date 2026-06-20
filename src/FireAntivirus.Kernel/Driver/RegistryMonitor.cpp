#include "pch.h"
#include "RegistryMonitor.h"
#include "Driver.h"
#include <ntstrsafe.h>

#define REGISTRY_MONITOR_TAG 'RMNT'

// 注册表回调句柄
PVOID g_CallbackHandle = NULL;
BOOLEAN g_RegistryMonitorInitialized = FALSE;

// 受保护的注册表路径
static UNICODE_STRING ProtectedRegistryKeys[] = {
    RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"),
    RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
    RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services"),
    RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows Defender"),
    RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SOFTWARE\\Policies"),
    RTL_CONSTANT_STRING(L"\\Registry\\User\\*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
    RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SOFTWARE\\FireAntivirus")
};

// 注册表操作类型枚举
typedef enum _REGISTRY_OPERATION {
    REG_CREATE_KEY = 1,
    REG_OPEN_KEY,
    REG_DELETE_KEY,
    REG_SET_VALUE,
    REG_DELETE_VALUE,
    REG_RENAME_KEY
} REGISTRY_OPERATION;

NTSTATUS
RegistryMonitor::Initialize()
{
    NTSTATUS status;
    
    KdPrint(("[FireAntivirus.RegistryMonitor] Initializing registry monitoring\n"));

    // 注册注册表回调
    UNICODE_STRING altitude = RTL_CONSTANT_STRING(L"360000");
    
    status = CmRegisterCallbackEx(
        RegistryCallback,
        &altitude,
        DriverObject,
        NULL,
        &g_CallbackHandle,
        NULL
    );
    
    if (!NT_SUCCESS(status))
    {
        KdPrint(("[FireAntivirus.RegistryMonitor] Failed to register registry callback: 0x%X\n", status));
        return status;
    }

    g_RegistryMonitorInitialized = TRUE;
    KdPrint(("[FireAntivirus.RegistryMonitor] Registry monitoring initialized successfully\n"));
    
    return status;
}

VOID
RegistryMonitor::Cleanup()
{
    if (g_CallbackHandle != NULL)
    {
        CmUnRegisterCallback(g_CallbackHandle);
        g_CallbackHandle = NULL;
    }
    
    g_RegistryMonitorInitialized = FALSE;
    KdPrint(("[FireAntivirus.RegistryMonitor] Registry monitoring cleanup completed\n"));
}

// 注册表回调函数
NTSTATUS
RegistryMonitor::RegistryCallback(
    _In_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2
)
{
    UNREFERENCED_PARAMETER(CallbackContext);
    
    REG_NOTIFY_CLASS notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
    
    switch (notifyClass)
    {
    case RegNtPreCreateKey:
        return PreCreateKeyCallback((PREG_PRE_CREATE_KEY_INFORMATION)Argument2);
        
    case RegNtPreCreateKeyEx:
        return PreCreateKeyExCallback((PREG_CREATE_KEY_INFORMATION)Argument2);
        
    case RegNtPreOpenKey:
        return PreOpenKeyCallback((PREG_PRE_OPEN_KEY_INFORMATION)Argument2);
        
    case RegNtPreDeleteKey:
        return PreDeleteKeyCallback((PREG_PRE_DELETE_KEY_INFORMATION)Argument2);
        
    case RegNtPreSetValueKey:
        return PreSetValueCallback((PREG_PRE_SET_VALUE_KEY_INFORMATION)Argument2);
        
    case RegNtPreDeleteValueKey:
        return PreDeleteValueCallback((PREG_PRE_DELETE_VALUE_KEY_INFORMATION)Argument2);
        
    case RegNtPreRenameKey:
        return PreRenameKeyCallback((PREG_PRE_RENAME_KEY_INFORMATION)Argument2);
        
    default:
        return STATUS_SUCCESS;
    }
}

// 创建键前回调
NTSTATUS
RegistryMonitor::PreCreateKeyCallback(
    _In_ PREG_PRE_CREATE_KEY_INFORMATION CallbackInfo
)
{
    UNICODE_STRING targetKeyName;
    
    if (CallbackInfo->CompleteName != NULL)
    {
        RtlInitUnicodeString(&targetKeyName, CallbackInfo->CompleteName->Buffer);
        
        if (IsRegistryKeyProtected(&targetKeyName))
        {
            LogRegistryEvent(&targetKeyName, PsGetCurrentProcessId(), REG_CREATE_KEY);
            
            // 检查是否有权限创建受保护键
            if (!HasSufficientPrivilege(PsGetCurrentProcessId(), REG_CREATE_KEY))
            {
                KdPrint(("[FireAntivirus.RegistryMonitor] Blocking registry key creation: %wZ\n", &targetKeyName));
                return STATUS_ACCESS_DENIED;
            }
        }
    }
    
    return STATUS_SUCCESS;
}

// 创建键扩展回调
NTSTATUS
RegistryMonitor::PreCreateKeyExCallback(
    _In_ PREG_CREATE_KEY_INFORMATION CallbackInfo
)
{
    UNICODE_STRING targetKeyName;
    
    if (CallbackInfo->CompleteName != NULL)
    {
        RtlInitUnicodeString(&targetKeyName, CallbackInfo->CompleteName->Buffer);
        
        if (IsRegistryKeyProtected(&targetKeyName))
        {
            LogRegistryEvent(&targetKeyName, PsGetCurrentProcessId(), REG_CREATE_KEY);
            
            if (!HasSufficientPrivilege(PsGetCurrentProcessId(), REG_CREATE_KEY))
            {
                KdPrint(("[FireAntivirus.RegistryMonitor] Blocking registry key creation (ex): %wZ\n", &targetKeyName));
                return STATUS_ACCESS_DENIED;
            }
        }
    }
    
    return STATUS_SUCCESS;
}

// 打开键前回调
NTSTATUS
RegistryMonitor::PreOpenKeyCallback(
    _In_ PREG_PRE_OPEN_KEY_INFORMATION CallbackInfo
)
{
    UNICODE_STRING targetKeyName;
    
    if (CallbackInfo->CompleteName != NULL)
    {
        RtlInitUnicodeString(&targetKeyName, CallbackInfo->CompleteName->Buffer);
        
        if (IsRegistryKeyProtected(&targetKeyName))
        {
            LogRegistryEvent(&targetKeyName, PsGetCurrentProcessId(), REG_OPEN_KEY);
            
            // TODO: 根据访问权限进行检查
        }
    }
    
    return STATUS_SUCCESS;
}

// 删除键前回调
NTSTATUS
RegistryMonitor::PreDeleteKeyCallback(
    _In_ PREG_PRE_DELETE_KEY_INFORMATION CallbackInfo
)
{
    UNICODE_STRING targetKeyName;
    
    if (CallbackInfo->Object != NULL)
    {
        // 获取键名
        if (GetKeyNameFromObject(CallbackInfo->Object, &targetKeyName))
        {
            if (IsRegistryKeyProtected(&targetKeyName))
            {
                LogRegistryEvent(&targetKeyName, PsGetCurrentProcessId(), REG_DELETE_KEY);
                
                // 受保护键不允许删除
                KdPrint(("[FireAntivirus.RegistryMonitor] Blocking registry key deletion: %wZ\n", &targetKeyName));
                return STATUS_ACCESS_DENIED;
            }
            
            ExFreePool(targetKeyName.Buffer);
        }
    }
    
    return STATUS_SUCCESS;
}

// 设置值前回调
NTSTATUS
RegistryMonitor::PreSetValueCallback(
    _In_ PREG_PRE_SET_VALUE_KEY_INFORMATION CallbackInfo
)
{
    UNICODE_STRING targetKeyName;
    
    if (CallbackInfo->Object != NULL)
    {
        if (GetKeyNameFromObject(CallbackInfo->Object, &targetKeyName))
        {
            if (IsRegistryKeyProtected(&targetKeyName))
            {
                LogRegistryEvent(&targetKeyName, PsGetCurrentProcessId(), REG_SET_VALUE);
                
                // 检查是否为自动启动项
                if (IsAutoRunKey(&targetKeyName))
                {
                    if (!IsTrustedProcess(PsGetCurrentProcessId()))
                    {
                        KdPrint(("[FireAntivirus.RegistryMonitor] Blocking autorun value set: %wZ\n", &targetKeyName));
                        ExFreePool(targetKeyName.Buffer);
                        return STATUS_ACCESS_DENIED;
                    }
                }
            }
            
            ExFreePool(targetKeyName.Buffer);
        }
    }
    
    return STATUS_SUCCESS;
}

// 删除值前回调
NTSTATUS
RegistryMonitor::PreDeleteValueCallback(
    _In_ PREG_PRE_DELETE_VALUE_KEY_INFORMATION CallbackInfo
)
{
    UNICODE_STRING targetKeyName;
    
    if (CallbackInfo->Object != NULL)
    {
        if (GetKeyNameFromObject(CallbackInfo->Object, &targetKeyName))
        {
            if (IsRegistryKeyProtected(&targetKeyName))
            {
                LogRegistryEvent(&targetKeyName, PsGetCurrentProcessId(), REG_DELETE_VALUE);
                
                // 重要的系统值不允许删除
                if (IsCriticalSystemValue(&targetKeyName, CallbackInfo->ValueName))
                {
                    KdPrint(("[FireAntivirus.RegistryMonitor] Blocking critical value deletion: %wZ\\%wZ\n", 
                        &targetKeyName, CallbackInfo->ValueName));
                    ExFreePool(targetKeyName.Buffer);
                    return STATUS_ACCESS_DENIED;
                }
            }
            
            ExFreePool(targetKeyName.Buffer);
        }
    }
    
    return STATUS_SUCCESS;
}

// 重命名键前回调
NTSTATUS
RegistryMonitor::PreRenameKeyCallback(
    _In_ PREG_PRE_RENAME_KEY_INFORMATION CallbackInfo
)
{
    UNICODE_STRING targetKeyName;
    
    if (CallbackInfo->Object != NULL)
    {
        if (GetKeyNameFromObject(CallbackInfo->Object, &targetKeyName))
        {
            if (IsRegistryKeyProtected(&targetKeyName))
            {
                LogRegistryEvent(&targetKeyName, PsGetCurrentProcessId(), REG_RENAME_KEY);
                
                // 受保护键不允许重命名
                KdPrint(("[FireAntivirus.RegistryMonitor] Blocking registry key rename: %wZ\n", &targetKeyName));
                ExFreePool(targetKeyName.Buffer);
                return STATUS_ACCESS_DENIED;
            }
            
            ExFreePool(targetKeyName.Buffer);
        }
    }
    
    return STATUS_SUCCESS;
}

// 检查注册表键是否受保护
BOOLEAN
RegistryMonitor::IsRegistryKeyProtected(_In_ PUNICODE_STRING KeyName)
{
    USHORT i;
    
    for (i = 1; i < ARRAYSIZE(ProtectedRegistryKeys); i++) // 跳过第一个空项
    {
        if (RtlCompareUnicodeString(KeyName, &ProtectedRegistryKeys[i], TRUE) == 0 ||
            RtlPrefixUnicodeString(&ProtectedRegistryKeys[i], KeyName, TRUE))
        {
            return TRUE;
        }
    }
    
    return FALSE;
}

// 从对象获取键名
BOOLEAN
RegistryMonitor::GetKeyNameFromObject(
    _In_ PVOID Object,
    _Out_ PUNICODE_STRING KeyName
)
{
    NTSTATUS status;
    ULONG resultLength;
    
    // 查询对象名
    status = ObQueryNameString(Object, NULL, 0, &resultLength);
    if (status != STATUS_INFO_LENGTH_MISMATCH)
    {
        return FALSE;
    }
    
    KeyName->Buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, resultLength, REGISTRY_MONITOR_TAG);
    if (KeyName->Buffer == NULL)
    {
        return FALSE;
    }
    
    status = ObQueryNameString(Object, KeyName, resultLength, &resultLength);
    if (!NT_SUCCESS(status))
    {
        ExFreePool(KeyName->Buffer);
        return FALSE;
    }
    
    return TRUE;
}

// 检查是否为自动启动键
BOOLEAN
RegistryMonitor::IsAutoRunKey(_In_ PUNICODE_STRING KeyName)
{
    UNICODE_STRING runKey = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
    UNICODE_STRING runOnceKey = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
    
    return (RtlCompareUnicodeString(KeyName, &runKey, TRUE) == 0 ||
            RtlCompareUnicodeString(KeyName, &runOnceKey, TRUE) == 0);
}

// 检查是否为关键系统值
BOOLEAN
RegistryMonitor::IsCriticalSystemValue(
    _In_ PUNICODE_STRING KeyName,
    _In_ PUNICODE_STRING ValueName
)
{
    // 检查是否为重要的系统配置值
    if (ValueName == NULL)
    {
        return FALSE;
    }
    
    UNICODE_STRING systemKey = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SYSTEM");
    UNICODE_STRING softwareKey = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SOFTWARE");
    
    if (RtlPrefixUnicodeString(&systemKey, KeyName, TRUE) ||
        RtlPrefixUnicodeString(&softwareKey, KeyName, TRUE))
    {
        // 检查特定的关键值名
        UNICODE_STRING criticalValues[] = {
            RTL_CONSTANT_STRING(L"ImagePath"),
            RTL_CONSTANT_STRING(L"Start"),
            RTL_CONSTANT_STRING(L"Type")
        };
        
        USHORT i;
        for (i = 0; i < ARRAYSIZE(criticalValues); i++)
        {
            if (RtlCompareUnicodeString(ValueName, &criticalValues[i], TRUE) == 0)
            {
                return TRUE;
            }
        }
    }
    
    return FALSE;
}

// 检查是否有足够权限
BOOLEAN
RegistryMonitor::HasSufficientPrivilege(
    _In_ ULONG ProcessId,
    _In_ REGISTRY_OPERATION Operation
)
{
    // TODO: 实现权限检查逻辑
    // 检查进程是否为系统进程或可信进程
    
    if (ProcessId == 4) // System process
    {
        return TRUE;
    }
    
    // 对受保护键的操作需要管理员权限
    if (Operation == REG_CREATE_KEY || 
        Operation == REG_DELETE_KEY || 
        Operation == REG_SET_VALUE || 
        Operation == REG_RENAME_KEY)
    {
        // TODO: 检查进程权限级别
        return FALSE; // 假设非系统进程没有足够权限
    }
    
    return FALSE;
}

// 检查是否为可信进程
BOOLEAN
RegistryMonitor::IsTrustedProcess(_In_ ULONG ProcessId)
{
    ULONG trustedProcesses[] = {4}; // System process
    USHORT i;
    
    for (i = 0; i < ARRAYSIZE(trustedProcesses); i++)
    {
        if (ProcessId == trustedProcesses[i])
        {
            return TRUE;
        }
    }
    
    return FALSE;
}

// 记录注册表事件
VOID
RegistryMonitor::LogRegistryEvent(
    _In_ PUNICODE_STRING KeyName,
    _In_ ULONG ProcessId,
    _In_ REGISTRY_OPERATION Operation
)
{
    LARGE_INTEGER currentTime;
    
    KeQuerySystemTime(&currentTime);
    
    KdPrint(("[FireAntivirus.RegistryMonitor] Registry operation: Process=%lu, Key=%wZ, Operation=%lu, Time=%I64d\n",
        ProcessId, KeyName, Operation, currentTime.QuadPart));
}