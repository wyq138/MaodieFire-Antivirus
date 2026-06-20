#pragma once

class ApplicationMonitor {
private:
    std::atomic<bool> isInitialized;
    std::atomic<bool> isEnabled;

public:
    ApplicationMonitor();
    ~ApplicationMonitor();

    bool Initialize();
    void Update();
    void Cleanup();

    bool IsEnabled() const;
    void SetEnabled(bool enabled);

    // 进程异常行为监控
    bool MonitorProcessBehavior();
};