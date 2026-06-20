#pragma once

class NetworkTraffic {
private:
    std::atomic<bool> isInitialized;
    std::atomic<bool> isEnabled;

public:
    NetworkTraffic();
    ~NetworkTraffic();

    bool Initialize();
    void Update();
    void Cleanup();

    bool IsEnabled() const;
    void SetEnabled(bool enabled);

    // 网络流量数据采集
    bool CollectNetworkTrafficData();
    
    // 异常流量检测
    bool DetectAbnormalTraffic();
};