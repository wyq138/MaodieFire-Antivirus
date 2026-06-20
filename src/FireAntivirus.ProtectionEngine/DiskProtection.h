#pragma once

class DiskProtection {
private:
    std::atomic<bool> isInitialized;
    std::thread monitoringThread;
    std::atomic<bool> isMonitoring;

public:
    DiskProtection();
    ~DiskProtection();

    bool Initialize();
    void Update();
    void Cleanup();

    bool IsInitialized() const;

private:
    void MonitorDisks();
    void HandleDiskAccess(const std::wstring& diskPath, DWORD accessMode);
    bool IsMaliciousDiskAccess(const std::wstring& diskPath, DWORD processId, DWORD accessMode);
};
