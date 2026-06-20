#pragma once

class ScriptProtection {
private:
    std::atomic<bool> isInitialized;
    std::thread monitoringThread;
    std::atomic<bool> isMonitoring;

public:
    ScriptProtection();
    ~ScriptProtection();

    bool Initialize();
    void Update();
    void Cleanup();

    bool IsInitialized() const;

private:
    void MonitorScripts();
    void HandleScriptExecution(const std::wstring& scriptPath, const std::wstring& commandLine);
    bool IsMaliciousScript(const std::wstring& scriptPath, const std::wstring& commandLine, DWORD processId);
};
