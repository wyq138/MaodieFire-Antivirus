#pragma once

class FileProtection {
private:
    std::atomic<bool> isInitialized;
    std::thread monitoringThread;
    std::atomic<bool> isMonitoring;
    HANDLE hChangeNotify;
    std::wstring monitoredPath;

public:
    FileProtection();
    ~FileProtection();

    bool Initialize();
    void Update();
    void Cleanup();

    bool IsInitialized() const;

private:
    void MonitorFiles();
    void HandleFileChange(DWORD action, const std::wstring& filePath);
    bool IsMaliciousFile(const std::wstring& filePath, DWORD processId);
};
