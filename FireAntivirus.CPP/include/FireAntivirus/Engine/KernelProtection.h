// FireAntivirus.CPP - 内核驱动接口
// 移植自 FireAntivirus.Engine.Kernel.KernelProtectionInterface
// 同时提供 .sys 自签名驱动骨架 (WDK + 测试签名脚本)
#pragma once

#include "FireAntivirus/Types.h"
#include "FireAntivirus/Helper.h"

#include <string>
#include <vector>
#include <cstdint>

#if defined(_WIN32)
    #include <windows.h>
    #include <winioctl.h>
#endif

namespace FireAntivirus {
namespace Engine {
namespace Kernel {

// ==================== 驱动设备名和 IOCTL ====================

constexpr const wchar_t* kDeviceName = L"FireAntivirusKernel";
constexpr const wchar_t* kDosPath    = L"\\\\.\\FireAntivirusKernel";

// FILE_DEVICE_UNKNOWN = 0x22, METHOD_BUFFERED = 0, FILE_ANY_ACCESS = 0
#define FA_CTL_CODE(f) CTL_CODE(0x00000022, 0x800 + (f), 0, 0)

constexpr uint32_t IOCTL_SET_FILE_FILTER     = FA_CTL_CODE(0);
constexpr uint32_t IOCTL_SET_PROCESS_FILTER  = FA_CTL_CODE(1);
constexpr uint32_t IOCTL_SET_REGISTRY_FILTER = FA_CTL_CODE(2);
constexpr uint32_t IOCTL_QUERY_STATUS        = FA_CTL_CODE(3);
constexpr uint32_t IOCTL_SEND_SIGNAL         = FA_CTL_CODE(4);

#undef FA_CTL_CODE

// ==================== 结构体(与 C# 版一致) ====================

enum class FileOperationType : int { Create, Read, Write, Delete, Execute };

struct FileFilterConfig {
    bool monitor_create            = true;
    bool monitor_write             = true;
    bool monitor_delete            = true;
    bool monitor_execute           = true;
    bool block_suspicious_exts     = true;
};

struct ProcessFilterConfig {
    bool monitor_process_creation  = true;
    bool monitor_thread_creation   = true;
    bool monitor_remote_thread     = true;
    bool block_code_injection      = true;
};

struct RegistryFilterConfig {
    bool monitor_autorun           = true;
    bool monitor_services          = true;
    bool monitor_browser_extensions= true;
    bool block_suspicious_keys     = true;
};

struct FileOperationInfo {
    std::string file_path;
    FileOperationType operation;
    uint32_t    process_id = 0;
    uint64_t    timestamp_ms = 0;
};

struct ProcessCreationInfo {
    std::string image_path;
    std::string command_line;
    uint32_t    parent_process_id = 0;
    uint64_t    timestamp_ms = 0;
};

// ==================== KernelProtectionInterface ====================

/// <summary>
/// 内核保护接口 — 连接自签名 .sys 驱动做文件/进程/注册表过滤
/// 如果驱动不存在则自动降级到用户模式保护
/// 自签名方法: 见项目 FireAntivirus.CPP/KernelDriver/ 下的说明和脚本
/// </summary>
class KernelProtectionInterface {
public:
    KernelProtectionInterface();
    ~KernelProtectionInterface();

    KernelProtectionInterface(const KernelProtectionInterface&) = delete;
    KernelProtectionInterface& operator=(const KernelProtectionInterface&) = delete;

    bool Initialize();
    void Shutdown();

    bool IsInitialized() const { return is_initialized_; }
    bool IsDriverConnected() const { return driver_connected_; }

    // 安装过滤器
    bool InstallFileFilter();
    bool InstallProcessFilter();
    bool InstallRegistryFilter();

    // 主动拦截(由驱动回调或用户模式轮询调用)
    bool InterceptFileOperation(const std::string& file_path, FileOperationType op);
    bool InterceptProcessCreation(const std::string& image_path, const std::string& command_line);

    // 全局禁用/启用保护
    void  Enable(bool on) { enabled_ = on; }
    bool  IsEnabled() const { return enabled_; }

private:
    bool SendIoControl(uint32_t code, const void* in_buf, uint32_t in_size);
    bool InitializeUserModeProtection();

    // 可疑判定逻辑(用户模式/驱动模式共用)
    bool IsSuspiciousFileOperation(const FileOperationInfo& fi);
    bool IsSuspiciousProcessCreation(const ProcessCreationInfo& pi);

private:
#if defined(_WIN32)
    HANDLE driver_handle_ = nullptr;
#endif
    bool is_initialized_    = false;
    bool driver_connected_ = false;
    bool enabled_           = true;
};

} // namespace Kernel
} // namespace Engine
} // namespace FireAntivirus
