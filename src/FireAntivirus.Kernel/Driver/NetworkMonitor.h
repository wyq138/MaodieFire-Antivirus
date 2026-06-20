#pragma once

#include <fwpmk.h>
#include <fwpsk.h>

extern PDRIVER_OBJECT DriverObject;
extern HANDLE g_EngineHandle;
extern HANDLE g_InboundCalloutHandle;
extern HANDLE g_OutboundCalloutHandle;
extern BOOLEAN g_NetworkMonitorInitialized;

// 网络回调GUID定义
DEFINE_GUID(OUTBOUND_CALLOUT_GUID, 
    0x12345678, 0x1234, 0x1234, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0);
    
DEFINE_GUID(INBOUND_CALLOUT_GUID,
    0x12345679, 0x1234, 0x1234, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf1);

// 网络事件回调函数指针类型
typedef VOID (*NETWORK_EVENT_CALLBACK)(
    ULONG ProcessId,
    ULONG LocalPort,
    ULONG RemotePort,
    ULONG Protocol,
    BOOLEAN IsOutbound,
    BOOLEAN IsBlocked
);

extern NETWORK_EVENT_CALLBACK g_EventCallback;

class NetworkMonitor
{
public:
    // 初始化和清理
    static NTSTATUS Initialize();
    static VOID Cleanup();

    // 网络连接检查
    static BOOLEAN IsConnectionBlocked(
        _In_ ULONG ProcessId,
        _In_ USHORT Port,
        _In_ BOOLEAN IsOutbound);
        
    static BOOLEAN IsKnownSafeProcess(_In_ ULONG ProcessId);
    static BOOLEAN IsSystemProcess(_In_ ULONG ProcessId);
    
    // 事件回调注册
    static VOID RegisterEventCallback(_In_ NETWORK_EVENT_CALLBACK Callback);

private:
    // 过滤器规则
    static NTSTATUS AddOutboundFilter();
    static NTSTATUS AddInboundFilter();
    static NTSTATUS RegisterNetworkCallout();
    
    // 回调函数
    static VOID NTAPI NetworkClassifyOutbound(
        _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
        _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
        _Inout_opt_ void* layerData,
        _In_opt_ const void* classifyContext,
        _In_ const FWPS_FILTER0* filter,
        _In_ UINT64 flowContext,
        _Inout_ FWPS_CLASSIFY_OUT0* classifyOut);
        
    static VOID NTAPI NetworkClassifyInbound(
        _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
        _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
        _Inout_opt_ void* layerData,
        _In_opt_ const void* classifyContext,
        _In_ const FWPS_FILTER0* filter,
        _In_ UINT64 flowContext,
        _Inout_ FWPS_CLASSIFY_OUT0* classifyOut);
        
    static NTSTATUS NTAPI NetworkNotifyOutbound(
        _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
        _In_ const GUID* filterKey,
        _Inout_ FWPS_FILTER0* filter);
        
    static NTSTATUS NTAPI NetworkNotifyInbound(
        _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
        _In_ const GUID* filterKey,
        _Inout_ FWPS_FILTER0* filter);
        
    static VOID NTAPI NetworkFlowDelete(
        _In_ UINT16 layerId,
        _In_ UINT32 calloutId,
        _In_ UINT64 flowContext);
    
    // 安全检查
    static BOOLEAN IsSuspiciousOutboundConnection(
        _In_ ULONG ProcessId,
        _In_ USHORT Port);
        
    static BOOLEAN IsSuspiciousInboundConnection(
        _In_ ULONG ProcessId,
        _In_ USHORT Port);
    
    // 事件记录
    static VOID LogNetworkEvent(
        _In_ ULONG ProcessId,
        _In_ USHORT LocalPort,
        _In_ USHORT RemotePort,
        _In_ ULONG Protocol,
        _In_ BOOLEAN IsOutbound,
        _In_ BOOLEAN IsBlocked);
};

// 全局回调声明
extern "C" {
    VOID NTAPI NetworkClassifyFunction(
        _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
        _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
        _Inout_opt_ void* layerData,
        _In_opt_ const void* classifyContext,
        _In_ const FWPS_FILTER0* filter,
        _In_ UINT64 flowContext,
        _Inout_ FWPS_CLASSIFY_OUT0* classifyOut);
}