#pragma once

class DocumentProtection {
private:
    std::atomic<bool> isInitialized;
    std::thread monitoringThread;
    std::atomic<bool> isMonitoring;

public:
    DocumentProtection();
    ~DocumentProtection();

    bool Initialize();
    void Update();
    void Cleanup();

    bool IsInitialized() const;

private:
    void MonitorDocuments();
    void HandleDocumentChange(const std::wstring& documentPath, DWORD action);
    bool IsMaliciousDocumentOperation(const std::wstring& documentPath, DWORD processId);
};
