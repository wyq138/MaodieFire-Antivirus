#pragma once

class ParentalControl {
private:
    std::atomic<bool> isInitialized;
    std::atomic<bool> isEnabled;

public:
    ParentalControl();
    ~ParentalControl();

    bool Initialize();
    void Update();
    void Cleanup();

    bool IsEnabled() const;
    void SetEnabled(bool enabled);

    // 进程枚举
    bool EnumProcesses();
    
    // 窗口监控
    bool MonitorWindows();
    
    // 网址过滤管控
    bool FilterUrls();
};