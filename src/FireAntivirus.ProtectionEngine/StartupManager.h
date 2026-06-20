#pragma once

class StartupManager {
private:
    std::atomic<bool> isInitialized;
    std::atomic<bool> isEnabled;

public:
    StartupManager();
    ~StartupManager();

    bool Initialize();
    void Update();
    void Cleanup();

    bool IsEnabled() const;
    void SetEnabled(bool enabled);

    // 枚举系统启动项
    bool EnumStartupItems();
};