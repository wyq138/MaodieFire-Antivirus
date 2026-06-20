#pragma once

class DeviceControl {
private:
    std::atomic<bool> isInitialized;
    std::atomic<bool> isEnabled;

public:
    DeviceControl();
    ~DeviceControl();

    bool Initialize();
    void Update();
    void Cleanup();

    bool IsEnabled() const;
    void SetEnabled(bool enabled);

    // 外设接入监控
    bool MonitorDeviceAccess();
    
    // 设备白名单管理
    bool ManageDeviceWhitelist();
};