#pragma once

class NetworkFirewall {
private:
    std::atomic<bool> isInitialized;
    std::atomic<bool> isEnabled;

public:
    NetworkFirewall();
    ~NetworkFirewall();

    bool Initialize();
    void Update();
    void Cleanup();

    bool IsEnabled() const;
    void SetEnabled(bool enabled);

    // 网络流量管控
    bool ControlNetworkTraffic();
    
    // 异常连接检测
    bool DetectAbnormalConnections();
};