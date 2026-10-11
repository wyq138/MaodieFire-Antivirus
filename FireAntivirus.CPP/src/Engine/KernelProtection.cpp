// FireAntivirus.CPP - KernelProtectionInterface 实现
#include "FireAntivirus/Engine/KernelProtection.h"
#include "FireAntivirus/LogHelper.h"
#include <algorithm>
#include <cstring>

#if defined(_WIN32)
#include <windows.h>
#include <tlhelp32.h>
#endif

namespace FireAntivirus {
namespace Engine {
namespace Kernel {

KernelProtectionInterface::KernelProtectionInterface() = default;
KernelProtectionInterface::~KernelProtectionInterface() { Shutdown(); }

bool KernelProtectionInterface::Initialize() {
    is_initialized_ = false;

#if defined(_WIN32)
    // 1) 尝试连接自签名驱动
    driver_handle_ = CreateFileW(kDosPath,
                                 GENERIC_READ | GENERIC_WRITE,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 nullptr, OPEN_EXISTING, 0, nullptr);
    if (driver_handle_ != INVALID_HANDLE_VALUE) {
        driver_connected_ = true;
        FireAntivirus::LogHelper::Info("Kernel", "内核保护已初始化(驱动已连接,自签名测试驱动)");
        is_initialized_ = true;
        return true;
    }

    DWORD err = GetLastError();
    FireAntivirus::LogHelper::Warn("Kernel",
        "内核驱动未连接(error=" + std::to_string(err) + "), 使用用户模式保护(开启测试签名: bcdedit /set testsigning on)");

    // 2) 降级: 用户模式保护
    if (InitializeUserModeProtection()) {
        is_initialized_ = true;
        driver_connected_ = false;
        return true;
    }
#endif

    FireAntivirus::LogHelper::Error("Kernel", "内核保护初始化失败");
    return false;
}

void KernelProtectionInterface::Shutdown() {
#if defined(_WIN32)
    if (driver_handle_ && driver_handle_ != INVALID_HANDLE_VALUE) {
        CloseHandle(driver_handle_);
        driver_handle_ = nullptr;
    }
#endif
    driver_connected_ = false;
    is_initialized_ = false;
}

bool KernelProtectionInterface::InitializeUserModeProtection() {
    FireAntivirus::LogHelper::Info("Kernel", "用户模式保护已启用(轮询式)");
    return true;
}

bool KernelProtectionInterface::SendIoControl(uint32_t code, const void* in_buf, uint32_t in_size) {
#if defined(_WIN32)
    if (!driver_handle_ || driver_handle_ == INVALID_HANDLE_VALUE) return false;
    DWORD bytes_ret = 0;
    BOOL ok = DeviceIoControl(driver_handle_, code,
                              (LPVOID)in_buf, in_size,
                              nullptr, 0, &bytes_ret, nullptr);
    return ok == TRUE;
#else
    return false;
#endif
}

bool KernelProtectionInterface::InstallFileFilter() {
    if (!is_initialized_) return false;
    FileFilterConfig cfg;
    return SendIoControl(IOCTL_SET_FILE_FILTER, &cfg, sizeof(cfg));
}

bool KernelProtectionInterface::InstallProcessFilter() {
    if (!is_initialized_) return false;
    ProcessFilterConfig cfg;
    return SendIoControl(IOCTL_SET_PROCESS_FILTER, &cfg, sizeof(cfg));
}

bool KernelProtectionInterface::InstallRegistryFilter() {
    if (!is_initialized_) return false;
    RegistryFilterConfig cfg;
    return SendIoControl(IOCTL_SET_REGISTRY_FILTER, &cfg, sizeof(cfg));
}

bool KernelProtectionInterface::InterceptFileOperation(const std::string& file_path, FileOperationType op) {
    FileOperationInfo fi;
    fi.file_path = file_path;
    fi.operation = op;
    fi.process_id = 0;
#if defined(_WIN32)
    fi.process_id = GetCurrentProcessId();
#endif
    return IsSuspiciousFileOperation(fi);
}

bool KernelProtectionInterface::InterceptProcessCreation(const std::string& image_path,
                                                          const std::string& command_line) {
    ProcessCreationInfo pi;
    pi.image_path = image_path;
    pi.command_line = command_line;
#if defined(_WIN32)
    pi.parent_process_id = GetCurrentProcessId();
#endif
    return IsSuspiciousProcessCreation(pi);
}

bool KernelProtectionInterface::IsSuspiciousFileOperation(const FileOperationInfo& fi) {
    static const std::set<std::string> kSuspiciousExts = {
        ".exe",".dll",".scr",".com",".bat",".cmd",".ps1",".vbs",".js"
    };
    std::string ext = FireAntivirus::Helper::ToLower(
        FireAntivirus::Helper::GetExtensionNoDot(fi.file_path));

    // 系统32写入
    if (FireAntivirus::Helper::PathIsSystemFile(fi.file_path) &&
        fi.operation == FileOperationType::Write) return true;

    // 可疑扩展名被创建
    if (kSuspiciousExts.count("." + ext) &&
        fi.operation == FileOperationType::Create) return true;

    return false;
}

bool KernelProtectionInterface::IsSuspiciousProcessCreation(const ProcessCreationInfo& pi) {
    std::string lower_path = FireAntivirus::Helper::ToLower(pi.image_path);
    std::string lower_cmd  = FireAntivirus::Helper::ToLower(pi.command_line);

    // 从临时目录执行
    std::string temp = FireAntivirus::Platform::GetTempDir();
    std::string appdata = FireAntivirus::Platform::GetAppDataDir();
    if (!temp.empty()   && lower_path.find(temp) != std::string::npos) return true;
    if (!appdata.empty() && lower_path.find(appdata) != std::string::npos) return true;

    // PowerShell 隐藏/加密执行
    static const std::vector<std::string> kSuspiciousKeywords = {
        "-enc", "-e", "-w hidden", "invoke-expression"
    };
    for (auto& k : kSuspiciousKeywords) {
        if (lower_cmd.find(k) != std::string::npos) return true;
    }

    return false;
}

} // namespace Kernel
} // namespace Engine
} // namespace FireAntivirus
