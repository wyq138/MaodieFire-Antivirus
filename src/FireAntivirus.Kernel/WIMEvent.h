// WIMEvent.h

#pragma once

#include <Windows.h>
#include <wrl/client.h>

class WIMEvent {
private:
    static bool isRegistered;

public:
    static bool RegisterEvents();
    static bool UnregisterEvents();
    static bool IsRegistered();

private:
    // WIM事件回调函数
    static void WINAPI WIMEventCallback(
        HANDLE hEvent,
        DWORD dwEventID,
        DWORD dwEventFlags,
        DWORD_PTR dwUserData,
        DWORD dwDataSize,
        LPCVOID lpData
    );
};
