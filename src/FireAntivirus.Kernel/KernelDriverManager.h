// KernelDriverManager.h

#pragma once

#include <Windows.h>
#include <vector>
#include <string>

class KernelDriverManager {
private:
    static KernelDriverManager* instance;
    bool isInitialized;
    std::vector<std::wstring> trustedDrivers;
    std::vector<std::wstring> loadedDrivers;

public:
    static KernelDriverManager* GetInstance();

    bool Initialize();
    void Shutdown();
    bool IsInitialized();

    // 驱动管理
    bool LoadDriver(const wchar_t* driverPath, const wchar_t* serviceName);
    bool UnloadDriver(const wchar_t* serviceName);
    bool IsDriverLoaded(const wchar_t* serviceName);
    bool IsDriverTrusted(const wchar_t* driverPath);

    // 驱动信息
    std::vector<std::wstring> GetLoadedDrivers();
    std::vector<std::wstring> GetTrustedDrivers();

    // 驱动签名检查
    bool CheckDriverSignature(const wchar_t* driverPath);

    // 驱动保护
    bool ProtectDriver(const wchar_t* serviceName);
    bool UnprotectDriver(const wchar_t* serviceName);

private:
    KernelDriverManager();
    ~KernelDriverManager();

    // 辅助方法
    bool IsDriverSigned(const wchar_t* driverPath);
    bool AddDriverToTrustedList(const wchar_t* driverPath);
    bool RemoveDriverFromTrustedList(const wchar_t* driverPath);
};
