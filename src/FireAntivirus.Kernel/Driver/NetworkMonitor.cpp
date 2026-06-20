#include "pch.h"
#include "NetworkMonitor.h"
#include "Driver.h"
#include <fwpmk.h>
#include <fwpsk.h>
#include <ws2def.h>
#include <in6addr.h>

#define NETWORK_MONITOR_TAG 'NMTK'

// 网络过滤引擎句柄
HANDLE g_EngineHandle = NULL;
HANDLE g_InboundCalloutHandle = NULL;
HANDLE g_OutboundCalloutHandle = NULL;
BOOLEAN g_NetworkMonitorInitialized = FALSE;

// 允许的网络连接规则
static ULONG AllowedProcesses[] = {
    4,  // System
    0
};

static ULONG BlockedPorts[] = {
    135, 139, 445,  // SMB/RPC ports commonly used by malware
    593, 1234, 12345,  // Common backdoor ports
    0
};

// 网络事件回调函数
typedef VOID (*NETWORK_EVENT_CALLBACK)(
    ULONG ProcessId,
    ULONG LocalPort,
    ULONG RemotePort,
    ULONG Protocol,
    BOOLEAN IsOutbound,
    BOOLEAN IsBlocked
);

NETWORK_EVENT_CALLBACK g_EventCallback = NULL;

NTSTATUS
NetworkMonitor::Initialize()
{
    NTSTATUS status = STATUS_SUCCESS;
    FWPM_SESSION session = {0};
    
    KdPrint(("[FireAntivirus.NetworkMonitor] Initializing network monitoring\n"));

    // 打开过滤会话
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    RtlStringCbCopyW(session.displayData.name, 
        sizeof(session.displayData.name), 
        L"FireAntivirus Network Monitor");
    
    status = FwpmEngineOpen0(
        NULL,
        RPC_C_AUTHN_WINNT,
        NULL,
        &session,
        &g_EngineHandle
    );
    
    if (!NT_SUCCESS(status))
    {
        KdPrint(("[FireAntivirus.NetworkMonitor] Failed to open filtering engine: 0x%X\n", status));
        return status;
    }

    // 添加出站过滤规则
    status = AddOutboundFilter();
    if (!NT_SUCCESS(status))
    {
        KdPrint(("[FireAntivirus.NetworkMonitor] Failed to add outbound filter: 0x%X\n", status));
        goto Cleanup;
    }

    // 添加入站过滤规则
    status = AddInboundFilter();
    if (!NT_SUCCESS(status))
    {
        KdPrint(("[FireAntivirus.NetworkMonitor] Failed to add inbound filter: 0x%X\n", status));
        goto Cleanup;
    }

    // 注册网络回调
    status = RegisterNetworkCallout();
    if (!NT_SUCCESS(status))
    {
        KdPrint(("[FireAntivirus.NetworkMonitor] Failed to register callout: 0x%X\n", status));
        goto Cleanup;
    }

    g_NetworkMonitorInitialized = TRUE;
    KdPrint(("[FireAntivirus.NetworkMonitor] Network monitoring initialized successfully\n"));
    
    return status;

Cleanup:
    if (g_EngineHandle != NULL)
    {
        NetworkMonitor::Cleanup();
    }
    
    return status;
}

VOID
NetworkMonitor::Cleanup()
{
    if (g_EngineHandle != NULL)
    {
        // 移除过滤规则
        if (g_InboundCalloutHandle != NULL)
        {
            FwpmCalloutDeleteById0(g_EngineHandle, g_InboundCalloutHandle);
            g_InboundCalloutHandle = NULL;
        }
        
        if (g_OutboundCalloutHandle != NULL)
        {
            FwpmCalloutDeleteById0(g_EngineHandle, g_OutboundCalloutHandle);
            g_OutboundCalloutHandle = NULL;
        }
        
        // 关闭过滤引擎
        FwpmEngineClose0(g_EngineHandle);
        g_EngineHandle = NULL;
    }
    
    g_NetworkMonitorInitialized = FALSE;
    KdPrint(("[FireAntivirus.NetworkMonitor] Network monitoring cleanup completed\n"));
}

NTSTATUS
NetworkMonitor::AddOutboundFilter()
{
    NTSTATUS status;
    FWPM_FILTER filter = {0};
    FWPM_DISPLAY_DATA displayData = {0};
    
    // 设置显示数据
    displayData.name = L"FireAntivirus Outbound Filter";
    displayData.description = L"Blocks malicious outbound connections";
    
    // 设置过滤条件
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.displayData = displayData;
    filter.flags = FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;
    
    // 设置过滤规则
    FWPM_FILTER_CONDITION conditions[3] = {0};
    
    // 条件1：进程ID在允许列表之外
    conditions[0].fieldKey = FWPM_CONDITION_ALE_PACKAGE_ID;
    conditions[0].matchType = FWP_MATCH_NOT_EQUAL;
    
    // 条件2：目标端口在阻止列表
    conditions[1].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
    conditions[1].matchType = FWP_MATCH_EQUAL;
    
    // 条件3：协议为TCP
    conditions[2].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
    conditions[2].matchType = FWP_MATCH_EQUAL;
    conditions[2].conditionValue.type = FWP_UINT8;
    conditions[2].conditionValue.uint8 = IPPROTO_TCP;
    
    filter.filterCondition = conditions;
    filter.numFilterConditions = 3;
    
    filter.action.type = FWP_ACTION_CALLOUT_UNKNOWN;
    filter.action.calloutKey = OUTBOUND_CALLOUT_GUID;
    
    // 添加过滤规则
    status = FwpmFilterAdd0(g_EngineHandle, &filter, NULL, &g_OutboundCalloutHandle);
    
    return status;
}

NTSTATUS
NetworkMonitor::AddInboundFilter()
{
    NTSTATUS status;
    FWPM_FILTER filter = {0};
    FWPM_DISPLAY_DATA displayData = {0};
    
    displayData.name = L"FireAntivirus Inbound Filter";
    displayData.description = L"Blocks malicious inbound connections";
    
    filter.layerKey = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4;
    filter.displayData = displayData;
    filter.flags = FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;
    
    FWPM_FILTER_CONDITION conditions[2] = {0};
    
    // 条件1：本地端口在阻止列表
    conditions[0].fieldKey = FWPM_CONDITION_IP_LOCAL_PORT;
    conditions[0].matchType = FWP_MATCH_EQUAL;
    
    // 条件2：协议为TCP
    conditions[1].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
    conditions[1].matchType = FWP_MATCH_EQUAL;
    conditions[1].conditionValue.type = FWP_UINT8;
    conditions[1].conditionValue.uint8 = IPPROTO_TCP;
    
    filter.filterCondition = conditions;
    filter.numFilterConditions = 2;
    
    filter.action.type = FWP_ACTION_CALLOUT_UNKNOWN;
    filter.action.calloutKey = INBOUND_CALLOUT_GUID;
    
    status = FwpmFilterAdd0(g_EngineHandle, &filter, NULL, &g_InboundCalloutHandle);
    
    return status;
}

NTSTATUS
NetworkMonitor::RegisterNetworkCallout()
{
    NTSTATUS status;
    FWPS_CALLOUT callout = {0};
    
    // 注册出站回调
    callout.calloutKey = OUTBOUND_CALLOUT_GUID;
    callout.flags = 0;
    callout.classifyFn = NetworkClassifyOutbound;
    callout.notifyFn = NetworkNotifyOutbound;
    callout.flowDeleteFn = NetworkFlowDelete;
    
    status = FwpsCalloutRegister0((void*)DriverObject, &callout, NULL);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    
    // 注册入站回调
    callout.calloutKey = INBOUND_CALLOUT_GUID;
    callout.classifyFn = NetworkClassifyInbound;
    callout.notifyFn = NetworkNotifyInbound;
    
    status = FwpsCalloutRegister0((void*)DriverObject, &callout, NULL);
    
    return status;
}

// 出站连接分类回调
VOID NTAPI
NetworkMonitor::NetworkClassifyOutbound(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER0* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut
)
{
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);
    
    ULONG processId = 0;
    USHORT remotePort = 0;
    
    // 从元数据获取进程ID
    if (inMetaValues != NULL && inMetaValues->processId != 0)
    {
        processId = inMetaValues->processId;
    }
    
    // 从固定值获取远程端口
    if (inFixedValues != NULL && 
        inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value.type == FWP_UINT16)
    {
        remotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value.uint16;
    }
    
    // 检查是否需要阻止连接
    if (IsConnectionBlocked(processId, remotePort, TRUE))
    {
        classifyOut->actionType = FWP_ACTION_BLOCK;
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
        
        // 记录安全事件
        LogNetworkEvent(processId, 0, remotePort, IPPROTO_TCP, TRUE, TRUE);
    }
    else
    {
        classifyOut->actionType = FWP_ACTION_PERMIT;
        LogNetworkEvent(processId, 0, remotePort, IPPROTO_TCP, TRUE, FALSE);
    }
}

// 入站连接分类回调
VOID NTAPI
NetworkMonitor::NetworkClassifyInbound(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER0* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut
)
{
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);
    
    ULONG processId = 0;
    USHORT localPort = 0;
    
    if (inMetaValues != NULL && inMetaValues->processId != 0)
    {
        processId = inMetaValues->processId;
    }
    
    if (inFixedValues != NULL && 
        inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_PORT].value.type == FWP_UINT16)
    {
        localPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_PORT].value.uint16;
    }
    
    if (IsConnectionBlocked(processId, localPort, FALSE))
    {
        classifyOut->actionType = FWP_ACTION_BLOCK;
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
        
        LogNetworkEvent(processId, localPort, 0, IPPROTO_TCP, FALSE, TRUE);
    }
    else
    {
        classifyOut->actionType = FWP_ACTION_PERMIT;
        LogNetworkEvent(processId, localPort, 0, IPPROTO_TCP, FALSE, FALSE);
    }
}

// 通知回调
NTSTATUS NTAPI
NetworkMonitor::NetworkNotifyOutbound(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ FWPS_FILTER0* filter
)
{
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    
    if (notifyType == FWPS_CALLOUT_NOTIFY_ADD_FILTER)
    {
        KdPrint(("[FireAntivirus.NetworkMonitor] Outbound filter added\n"));
    }
    
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI
NetworkMonitor::NetworkNotifyInbound(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ FWPS_FILTER0* filter
)
{
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    
    if (notifyType == FWPS_CALLOUT_NOTIFY_ADD_FILTER)
    {
        KdPrint(("[FireAntivirus.NetworkMonitor] Inbound filter added\n"));
    }
    
    return STATUS_SUCCESS;
}

// 流删除回调
VOID NTAPI
NetworkMonitor::NetworkFlowDelete(
    _In_ UINT16 layerId,
    _In_ UINT32 calloutId,
    _In_ UINT64 flowContext
)
{
    UNREFERENCED_PARAMETER(layerId);
    UNREFERENCED_PARAMETER(calloutId);
    UNREFERENCED_PARAMETER(flowContext);
    
    KdPrint(("[FireAntivirus.NetworkMonitor] Network flow deleted\n"));
}

// 检查连接是否应该被阻止
BOOLEAN
NetworkMonitor::IsConnectionBlocked(
    _In_ ULONG ProcessId,
    _In_ USHORT Port,
    _In_ BOOLEAN IsOutbound
)
{
    USHORT i;
    
    // 检查进程是否在允许列表中
    for (i = 0; AllowedProcesses[i] != 0; i++)
    {
        if (ProcessId == AllowedProcesses[i])
        {
            return FALSE; // 允许列表中的进程
        }
    }
    
    // 检查端口是否在阻止列表中
    for (i = 0; BlockedPorts[i] != 0; i++)
    {
        if (Port == BlockedPorts[i])
        {
            return TRUE; // 阻止列表中端口
        }
    }
    
    // 额外的安全检查
    if (IsOutbound && IsSuspiciousOutboundConnection(ProcessId, Port))
    {
        return TRUE;
    }
    
    if (!IsOutbound && IsSuspiciousInboundConnection(ProcessId, Port))
    {
        return TRUE;
    }
    
    return FALSE;
}

// 检查可疑出站连接
BOOLEAN
NetworkMonitor::IsSuspiciousOutboundConnection(
    _In_ ULONG ProcessId,
    _In_ USHORT Port
)
{
    // 检查是否为非系统进程连接到非常用端口
    if (ProcessId > 4 && Port > 1024)
    {
        // 检查进程是否已知的安全进程
        if (!IsKnownSafeProcess(ProcessId))
        {
            return TRUE;
        }
    }
    
    return FALSE;
}

// 检查可疑入站连接
BOOLEAN
NetworkMonitor::IsSuspiciousInboundConnection(
    _In_ ULONG ProcessId,
    _In_ USHORT Port
)
{
    // 高端口上的入站连接可能为后门
    if (Port > 1024 && !IsSystemProcess(ProcessId))
    {
        return TRUE;
    }
    
    return FALSE;
}

// 检查是否为已知安全进程
BOOLEAN
NetworkMonitor::IsKnownSafeProcess(_In_ ULONG ProcessId)
{
    // TODO: 实现进程白名单检查
    // 这里可以实现进程签名验证或路径检查
    
    if (ProcessId == 4) // System process
    {
        return TRUE;
    }
    
    return FALSE;
}

// 检查是否为系统进程
BOOLEAN
NetworkMonitor::IsSystemProcess(_In_ ULONG ProcessId)
{
    return (ProcessId == 4); // System PID
}

// 记录网络事件
VOID
NetworkMonitor::LogNetworkEvent(
    _In_ ULONG ProcessId,
    _In_ USHORT LocalPort,
    _In_ USHORT RemotePort,
    _In_ ULONG Protocol,
    _In_ BOOLEAN IsOutbound,
    _In_ BOOLEAN IsBlocked
)
{
    LARGE_INTEGER currentTime;
    
    KeQuerySystemTime(&currentTime);
    
    KdPrint(("[FireAntivirus.NetworkMonitor] Network event: Process=%lu, LocalPort=%hu, RemotePort=%hu, Protocol=%lu, Outbound=%u, Blocked=%u, Time=%I64d\n",
        ProcessId, LocalPort, RemotePort, Protocol, IsOutbound, IsBlocked, currentTime.QuadPart));
    
    // 调用外部回调函数（如果已注册）
    if (g_EventCallback != NULL)
    {
        g_EventCallback(ProcessId, LocalPort, RemotePort, Protocol, IsOutbound, IsBlocked);
    }
}

// 注册事件回调
VOID
NetworkMonitor::RegisterEventCallback(_In_ NETWORK_EVENT_CALLBACK Callback)
{
    g_EventCallback = Callback;
}