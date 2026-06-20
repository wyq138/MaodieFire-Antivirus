#pragma once

class ProcessProtection {
private:
    std::atomic<bool> isInitialized;
    std::thread monitoringThread;
    std::atomic<bool> isMonitoring;
    HANDLE hProcessSnapshot;

    // Detour functions
    static BOOL(WINAPI* OriginalCreateProcess)(
        LPCWSTR lpApplicationName,
        LPWSTR lpCommandLine,
        LPSECURITY_ATTRIBUTES lpProcessAttributes,
        LPSECURITY_ATTRIBUTES lpThreadAttributes,
        BOOL bInheritHandles,
        DWORD dwCreationFlags,
        LPVOID lpEnvironment,
        LPCWSTR lpCurrentDirectory,
        LPSTARTUPINFOW lpStartupInfo,
        LPPROCESS_INFORMATION lpProcessInformation
    );

    static BOOL WINAPI HookedCreateProcess(
        LPCWSTR lpApplicationName,
        LPWSTR lpCommandLine,
        LPSECURITY_ATTRIBUTES lpProcessAttributes,
        LPSECURITY_ATTRIBUTES lpThreadAttributes,
        BOOL bInheritHandles,
        DWORD dwCreationFlags,
        LPVOID lpEnvironment,
        LPCWSTR lpCurrentDirectory,
        LPSTARTUPINFOW lpStartupInfo,
        LPPROCESS_INFORMATION lpProcessInformation
    );

public:
    ProcessProtection();
    ~ProcessProtection();

    bool Initialize();
    void Update();
    void Cleanup();

    bool IsInitialized() const;

private:
    void MonitorProcesses();
    bool IsMaliciousProcess(const std::wstring& processPath, DWORD processId);
};
