#pragma once

class MobileSecurity {
private:
    std::atomic<bool> isInitialized;
    std::atomic<bool> isEnabled;

public:
    MobileSecurity();
    ~MobileSecurity();

    bool Initialize();
    void Update();
    void Cleanup();

    bool IsEnabled() const;
    void SetEnabled(bool enabled);

    // 移动设备基础安全检测
    bool CheckMobileDeviceSecurity();
};