// ETWProvider.h

#pragma once

#include <Windows.h>
#include <evntprov.h>

class ETWProvider {
private:
    static GUID providerId;
    static HANDLE registrationHandle;
    static bool isInitialized;

public:
    static bool Initialize();
    static void Shutdown();
    static bool StartMonitoring();
    static bool StopMonitoring();

    // 事件发布方法
    static bool PublishProtectionStatus(bool isEnabled);
    static bool PublishProcessCreation(DWORD processId, const wchar_t* processName);
    static bool PublishFileAccess(const wchar_t* filePath, DWORD accessType);
};

class ETWConsumer {
private:
    HANDLE hEvent;

public:
    ETWConsumer();
    ~ETWConsumer();

    bool StartConsuming();
    void StopConsuming();
};
