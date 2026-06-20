// NetworkFilter.h

#pragma once

#include <Windows.h>
#include <vector>
#include <string>

class NetworkFilter {
private:
    static NetworkFilter* instance;
    bool isInitialized;
    bool isFilterEnabled;

public:
    static NetworkFilter* GetInstance();

    bool Initialize();
    void Shutdown();
    bool IsInitialized();

    // 过滤器管理
    bool EnableFilter();
    bool DisableFilter();
    bool IsFilterEnabled();

    // 网络操作监控
    bool MonitorTcpConnections();
    bool UnmonitorTcpConnections();
    bool MonitorUdpConnections();
    bool UnmonitorUdpConnections();
    bool MonitorIcmpPackets();
    bool UnmonitorIcmpPackets();
    bool MonitorDnsRequests();
    bool UnmonitorDnsRequests();

    // IP地址过滤
    bool AddIpAddressToBlocklist(const char* ipAddress);
    bool RemoveIpAddressFromBlocklist(const char* ipAddress);
    bool IsIpAddressBlocked(const char* ipAddress);
    bool AddIpAddressToAllowlist(const char* ipAddress);
    bool RemoveIpAddressFromAllowlist(const char* ipAddress);
    bool IsIpAddressAllowed(const char* ipAddress);

    // 端口过滤
    bool AddPortToBlocklist(WORD port, DWORD protocol);
    bool RemovePortFromBlocklist(WORD port, DWORD protocol);
    bool IsPortBlocked(WORD port, DWORD protocol);

    // URL过滤
    bool AddUrlToBlocklist(const wchar_t* url);
    bool RemoveUrlFromBlocklist(const wchar_t* url);
    bool IsUrlBlocked(const wchar_t* url);

    // 应用程序网络访问控制
    bool BlockApplicationNetworkAccess(const wchar_t* applicationPath);
    bool AllowApplicationNetworkAccess(const wchar_t* applicationPath);
    bool IsApplicationNetworkAccessBlocked(const wchar_t* applicationPath);

    // 回调函数类型
    typedef bool (*NetworkOperationCallback)(
        const char* sourceIp,
        const char* destinationIp,
        WORD sourcePort,
        WORD destinationPort,
        DWORD protocol,
        DWORD processId,
        const wchar_t* processName
    );

    // 设置回调函数
    void SetNetworkOperationCallback(NetworkOperationCallback callback);

private:
    NetworkFilter();
    ~NetworkFilter();

    // 回调函数
    static NetworkOperationCallback networkOperationCallback;

    // 辅助方法
    bool InitializeNetworkDriver();
    bool ShutdownNetworkDriver();
    bool RegisterNetworkCallbacks();
    bool UnregisterNetworkCallbacks();
};
