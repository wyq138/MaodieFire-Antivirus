// MemoryProtection.h

#pragma once

#include <Windows.h>
#include <vector>
#include <string>

class MemoryProtection {
private:
    static MemoryProtection* instance;
    bool isInitialized;
    std::vector<DWORD> protectedProcesses;

public:
    static MemoryProtection* GetInstance();

    bool Initialize();
    void Shutdown();
    bool IsInitialized();

    // 进程内存保护
    bool ProtectProcessMemory(DWORD processId);
    bool UnprotectProcessMemory(DWORD processId);
    bool IsProcessMemoryProtected(DWORD processId);

    // 内存区域保护
    bool ProtectMemoryRegion(DWORD processId, PVOID baseAddress, SIZE_T size, DWORD protectFlags);
    bool UnprotectMemoryRegion(DWORD processId, PVOID baseAddress, SIZE_T size);

    // 内存操作监控
    bool MonitorMemoryAccess(DWORD processId);
    bool UnmonitorMemoryAccess(DWORD processId);

    // 内存注入防护
    bool BlockMemoryInjection(DWORD processId);
    bool AllowMemoryInjection(DWORD processId);

    // 内存扫描
    bool ScanProcessMemory(DWORD processId, std::vector<PVOID>* suspiciousRegions);

private:
    MemoryProtection();
    ~MemoryProtection();

    // 辅助方法
    bool IsValidProcess(DWORD processId);
    HANDLE OpenProcessWithAccess(DWORD processId, DWORD desiredAccess);
    bool CheckMemoryInjection(DWORD processId);
    bool AnalyzeMemoryRegion(DWORD processId, PVOID baseAddress, SIZE_T size);
};
