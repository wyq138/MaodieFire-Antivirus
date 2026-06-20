#pragma once

class DeviceProtection {
private:
    std::atomic<bool> isInitialized;
    std::thread monitoringThread;
    std::atomic<bool> isMonitoring;
    HWND hMessageWindow;

public:
    DeviceProtection();
    ~DeviceProtection();

    bool Initialize();
    void Update();
    void Cleanup();

    bool IsInitialized() const;

private:
    void MonitorDevices();
    void HandleDeviceChange(UINT uMsg, WPARAM wParam, LPARAM lParam);
    bool IsMaliciousDevice(const std::wstring& devicePath, const std::wstring& deviceName);
    void ScanDevice(const std::wstring& devicePath);
};
