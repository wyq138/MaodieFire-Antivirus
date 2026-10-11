// FireAntivirus.CPP - Windows 平台工具层
// 进程/注册表/系统路径/签名验证
#pragma once

#include "FireAntivirus/Types.h"
#include "FireAntivirus/Helper.h"

#include <string>
#include <vector>
#include <cstdint>

#if defined(_WIN32)
    #include <windows.h>
    #include <winreg.h>
    #include <psapi.h>
    #include <tlhelp32.h>
#endif

namespace FireAntivirus {
namespace Platform {

// ==================== 进程相关 ====================

/// <summary>进程快照信息</summary>
struct ProcessInfo {
    uint32_t pid = 0;
    uint32_t parent_pid = 0;
    std::string name;
    std::string exe_path;
};

/// <summary>枚举当前系统所有进程</summary>
std::vector<ProcessInfo> EnumProcesses();

/// <summary>按名称查找进程(PID列表)</summary>
std::vector<uint32_t> FindProcessByName(const std::string& name);

/// <summary>终止指定 PID 的进程,返回 true 表示成功</summary>
bool TerminateProcess(uint32_t pid);

// ==================== 注册表 ====================

enum class RegistryRoot {
    HKCU, HKLM, HKCR, HKU, HKCC
};

/// <summary>读取注册表字符串值</summary>
bool RegQueryString(RegistryRoot root,
                    const std::string& sub_key,
                    const std::string& value_name,
                    std::string& out_value);

/// <summary>写入注册表字符串值</summary>
bool RegWriteString(RegistryRoot root,
                    const std::string& sub_key,
                    const std::string& value_name,
                    const std::string& value);

/// <summary>删除注册表值</summary>
bool RegDeleteValue(RegistryRoot root,
                    const std::string& sub_key,
                    const std::string& value_name);

/// <summary>枚举 Run / RunOnce 启动项</summary>
struct RegistryRunEntry {
    std::string full_key_path; // "HKCU\...\Run\ValueName"
    std::string value_name;
    std::string command;
};
std::vector<RegistryRunEntry> EnumRegistryRunKeys();

// ==================== 系统路径 ====================

std::string GetWindowsDir();
std::string GetSystemDir();
std::string GetProgramDataDir();
std::string GetLocalAppDataDir();
std::string GetTempDir();
std::string GetAppDataDir();

// ==================== PE / 签名 ====================

/// <summary>检查 PE 文件 DOS/PE 头有效性</summary>
bool IsPeFile(const std::vector<uint8_t>& data);

/// <summary>读取 PE 文件节区数量</summary>
int GetPeSectionCount(const std::vector<uint8_t>& data);

/// <summary>读取 PE 文件导入的 DLL 名列表</summary>
std::vector<std::string> GetPeImports(const std::vector<uint8_t>& data);

/// <summary>检查 Authenticode 签名是否有效且在可信发布者列表中</summary>
struct SignVerifyResult {
    bool has_signature = false;
    bool signature_valid = false;
    std::string subject;
    std::string issuer;
    bool trusted_publisher = false;
};
SignVerifyResult VerifyFileSignature(const std::string& path);

// ==================== 可信发布者 ====================

const std::set<std::string>& GetTrustedPublishers();

} // namespace Platform
} // namespace FireAntivirus
