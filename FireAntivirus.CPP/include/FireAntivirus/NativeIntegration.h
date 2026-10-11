// FireAntivirus.CPP - NativeIntegration (P/Invoke 封装)
// 移植自 FireAntivirus.NativeIntegration.cs (7个文件)
// 与 C# 版 FireAntivirus.NativeMethods 1:1 对齐
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#if defined(_WIN32)
    #include <windows.h>
#endif

namespace FireAntivirus {
namespace Native {

// ==================== 基础类型 ====================

struct PROCESS_BASIC_INFORMATION {
    uint64_t Reserved1;
    uint64_t PebBaseAddress;
    uint64_t Reserved2[2];
    uint64_t UniqueProcessId;
    uint64_t Reserved3;
};

enum class NTSTATUS : uint32_t {
    STATUS_SUCCESS = 0x00000000,
    STATUS_ACCESS_DENIED = 0xC0000022,
    STATUS_INVALID_PARAMETER = 0xC000000D
};

// ==================== NativeMethods (直接用 Win32 API, 无需 P/Invoke) ====================

class NativeMethods {
public:
    // NtQueryInformationProcess (简化版)
    static bool NtQueryProcessBasicInformation(uint32_t pid, PROCESS_BASIC_INFORMATION& pbi);

    // NtSetInformationProcess - 反调试保护 (ProcessDebugFlags)
    static bool NtSetProcessDebugFlags(uint32_t pid, uint32_t flags);

    // CheckRemoteDebuggerPresent
    static bool CheckRemoteDebuggerPresent(HANDLE hProcess, bool& is_debugged);

    // IsProcessInJob
    static bool IsProcessInJob(HANDLE hProcess);

    // 进程内存操作
    static bool ReadProcessMemoryBytes(HANDLE hProcess, uintptr_t address,
                                       std::vector<uint8_t>& out, size_t size);
    static bool WriteProcessMemoryBytes(HANDLE hProcess, uintptr_t address,
                                        const std::vector<uint8_t>& data);

    // CreateRemoteThread
    static HANDLE CreateRemoteThreadEx(HANDLE hProcess, uintptr_t start_address,
                                       uintptr_t parameter);
};

// ==================== NativeProcessProtection ====================

class NativeProcessProtection {
public:
    // 进程签名验证
    static bool VerifyProcessSignature(uint32_t pid, bool& has_signature, bool& is_valid);

    // 获取进程可执行路径 (OpenProcess + QueryFullProcessImageNameW)
    static std::string GetProcessImagePath(uint32_t pid);

    // 检查进程是否被注入 (对比 PE section 与磁盘)
    static bool IsProcessInjected(uint32_t pid);

    // 获取进程 PEB 地址
    static uintptr_t GetProcessPeb(uint32_t pid);
};

// ==================== NativeFileProtection ====================

class NativeFileProtection {
public:
    // IsFileSigned (Authenticode)
    static bool IsFileSigned(const std::string& path, bool& has_sig, bool& sig_valid);

    // IsFileMalicious (哈希)
    static bool IsFileMalicious(const std::string& sha256);

    // GetFileZone (MarkOfTheWeb)
    static bool GetFileZone(const std::string& path, int& zone);

    // DeleteFilePermanently (SecureZeroMemory + DeleteFileW)
    static bool SecureDelete(const std::string& path, int passes = 3);
};

// ==================== NativeRegistryProtection ====================

class NativeRegistryProtection {
public:
    static bool IsRunKeyEntrySuspicious(const std::string& value_name, const std::string& command);
    static bool RemovePersistenceKeysForProcess(const std::string& process_name);
    static bool DisableAutorun();
};

// ==================== NativeBrowserProtection ====================

class NativeBrowserProtection {
public:
    struct BrowserInfo { std::string name; std::string exe; std::string user_data_path; };
    static std::vector<BrowserInfo> DetectInstalledBrowsers();
    static bool IsBrowserProtected();
    static bool ClearBrowserCookies(const std::string& browser_name);
    static bool EnableSafeMode(const std::string& browser_name);
};

// ==================== NativeDeviceProtection ====================

class NativeDeviceProtection {
public:
    struct DeviceInfo { std::string device_id; std::string name; std::string status; };
    static std::vector<DeviceInfo> EnumConnectedDevices();
    static bool BlockUSBPort(const std::string& port_name);
    static bool DisableCDROM();
};

// ==================== NativeSecurityCoreWrapper ====================
// 对 AntivirusEngine / KernelProtection 做 Native 封装 (避免 P/Invoke 边界)
class NativeSecurityCoreWrapper {
public:
    static bool Initialize();
    static void Shutdown();
    static bool IsRunning();
};

} // namespace Native
} // namespace FireAntivirus
