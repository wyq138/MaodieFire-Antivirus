#pragma once

class ProcessGuard {
private:
    std::atomic<bool> isInitialized;
    std::thread guardThread;
    std::atomic<bool> isRunning;
    DWORD mainProcessId;
    DWORD guardProcessId;
    HANDLE hGuardPipe;

public:
    ProcessGuard();
    ~ProcessGuard();

    bool Initialize();
    void Update();
    void Cleanup();

    bool IsInitialized() const;

private:
    void GuardThread();
    void StartGuardProcess();
    void MonitorMainProcess();
    void MonitorGuardProcess();
    bool IsProcessRunning(DWORD processId);
    bool StartMainProcess();
    bool StartGuardProcessInternal();
};
