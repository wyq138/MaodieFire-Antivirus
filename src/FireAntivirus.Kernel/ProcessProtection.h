// ProcessProtection.h

#pragma once

#include <Windows.h>
#include <vector>
#include <map>
#include "FireAntivirusKernel.h"

class ProcessProtection {
private:
    static bool isInitialized;
    static ProcessProtectionPolicy currentPolicy;
    static std::vector<DWORD> protectedProcesses;
    static std::map<DWORD, HANDLE> processHandles;

public:
    static bool Initialize();
    static void Shutdown();
    static bool IsInitialized();

    // 策略管理
    static void SetPolicy(const ProcessProtectionPolicy& policy);
    static ProcessProtectionPolicy GetPolicy();

    // 进程保护
    static bool ProtectProcess(DWORD processId);
    static bool UnprotectProcess(DWORD processId);
    static bool IsProcessProtected(DWORD processId);

    // 防护功能
    static bool BlockUnsignedProcess(DWORD processId);
    static bool BlockRemoteThreadInjection(DWORD targetProcessId, DWORD sourceProcessId);
    static bool BlockDllInjection(DWORD processId, const wchar_t* dllPath);
    static bool BlockProcessHollowing(DWORD processId);

private:
    // 辅助方法
    static bool IsProcessSigned(DWORD processId);
    static HANDLE GetProcessHandle(DWORD processId);
    static void ReleaseProcessHandle(DWORD processId);
};
