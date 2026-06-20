#pragma once

class ActiveDefense {
private:
    std::atomic<bool> isInitialized;
    std::thread monitoringThread;
    std::atomic<bool> isMonitoring;

public:
    ActiveDefense();
    ~ActiveDefense();

    bool Initialize();
    void Update();
    void Cleanup();

    bool IsInitialized() const;

private:
    void MonitorBehavior();
    void AnalyzeProcessBehavior(DWORD processId);
    bool IsMaliciousBehavior(DWORD processId);
};
