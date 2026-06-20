#pragma once

class RegistryProtection {
private:
    std::atomic<bool> isInitialized;
    std::thread monitoringThread;
    std::atomic<bool> isMonitoring;
    HANDLE hRegistryNotify;

public:
    RegistryProtection();
    ~RegistryProtection();

    bool Initialize();
    void Update();
    void Cleanup();

    bool IsInitialized() const;

private:
    void MonitorRegistry();
    void HandleRegistryChange(const std::wstring& keyPath, DWORD action);
    bool IsMaliciousRegistryChange(const std::wstring& keyPath, DWORD processId);
};
