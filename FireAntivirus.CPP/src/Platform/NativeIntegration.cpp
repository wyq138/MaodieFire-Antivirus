// FireAntivirus.CPP - NativeIntegration 实现
#include "FireAntivirus/NativeIntegration.h"
#include "FireAntivirus/Helper.h"
#include "FireAntivirus/Platform/Windows.h"
#include "FireAntivirus/Engine/AntivirusEngine.h"
#include "FireAntivirus/Engine/KernelProtection.h"
#include "FireAntivirus/LogHelper.h"
#include <filesystem>

#if defined(_WIN32)
#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <shellscalingapi.h>
#include <dbt.h>
#include <setupapi.h>
#include <cfgmgr32.h>
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "cfgmgr32.lib")
#endif

namespace FireAntivirus {
namespace Native {

// ==================== NativeMethods ====================

// 动态加载 ntdll.dll 的函数 (避免链接 ntdll.lib)
#if defined(_WIN32)
typedef NTSTATUS(NTAPI* NtQueryInformationProcess_t)(HANDLE, UINT, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* NtSetInformationProcess_t)(HANDLE, UINT, PVOID, ULONG);
typedef NTSTATUS(NTAPI* NtQueryInformationThread_t)(HANDLE, UINT, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* NtOpenProcess_t)(PHANDLE, ACCESS_MASK, PVOID, PVOID);
typedef NTSTATUS(NTAPI* NtClose_t)(HANDLE);
#endif

bool NativeMethods::NtQueryProcessBasicInformation(uint32_t pid, PROCESS_BASIC_INFORMATION& pbi) {
#if defined(_WIN32)
    static NtQueryInformationProcess_t fn = nullptr;
    if (!fn) fn = (NtQueryInformationProcess_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
    if (!fn) return false;
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!h) return false;
    ULONG ret_len = 0;
    auto status = fn(h, 0 /*ProcessBasicInformation*/, &pbi, sizeof(pbi), &ret_len);
    CloseHandle(h);
    return status == 0;
#else return false;
#endif
}

bool NativeMethods::NtSetProcessDebugFlags(uint32_t pid, uint32_t flags) {
#if defined(_WIN32)
    static NtSetInformationProcess_t fn = nullptr;
    if (!fn) fn = (NtSetInformationProcess_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetInformationProcess");
    if (!fn) return false;
    HANDLE h = OpenProcess(PROCESS_SET_INFORMATION, FALSE, pid);
    if (!h) return false;
    // ProcessDebugFlags = 0x1f
    auto status = fn(h, 0x1f, &flags, sizeof(flags));
    CloseHandle(h);
    return status == 0;
#else return false;
#endif
}

bool NativeMethods::CheckRemoteDebuggerPresent(HANDLE hProcess, bool& is_debugged) {
#if defined(_WIN32)
    BOOL debug_flag = FALSE;
    BOOL ok = ::CheckRemoteDebuggerPresent(hProcess, &debug_flag);
    is_debugged = (ok == TRUE) && (debug_flag != FALSE);
    return ok == TRUE;
#else is_debugged = false; return false;
#endif
}

bool NativeMethods::IsProcessInJob(HANDLE hProcess) {
#if defined(_WIN32)
    BOOL in_job = FALSE;
    if (IsProcessInJob(hProcess, nullptr, &in_job) == TRUE) return in_job != FALSE;
    return false;
#else return false;
#endif
}

bool NativeMethods::ReadProcessMemoryBytes(HANDLE hProcess, uintptr_t address,
                                           std::vector<uint8_t>& out, size_t size) {
#if defined(_WIN32)
    out.resize(size);
    SIZE_T read = 0;
    return ::ReadProcessMemory(hProcess, (LPCVOID)address, out.data(), size, &read) == TRUE && read == size;
#else return false;
#endif
}

bool NativeMethods::WriteProcessMemoryBytes(HANDLE hProcess, uintptr_t address,
                                            const std::vector<uint8_t>& data) {
#if defined(_WIN32)
    SIZE_T written = 0;
    return ::WriteProcessMemory(hProcess, (LPVOID)address, data.data(), data.size(), &written) == TRUE;
#else return false;
#endif
}

HANDLE NativeMethods::CreateRemoteThreadEx(HANDLE hProcess, uintptr_t start_address, uintptr_t parameter) {
#if defined(_WIN32)
    return ::CreateRemoteThread(hProcess, nullptr, 0,
        (LPTHREAD_START_ROUTINE)start_address, (LPVOID)parameter, 0, nullptr);
#else return nullptr;
#endif
}

// ==================== NativeProcessProtection ====================

bool NativeProcessProtection::VerifyProcessSignature(uint32_t pid, bool& has_sig, bool& is_valid) {
    has_sig = false; is_valid = false;
    auto path = GetProcessImagePath(pid);
    if (path.empty()) return false;
    auto sign = FireAntivirus::Platform::VerifyFileSignature(path);
    has_sig = sign.has_signature;
    is_valid = sign.signature_valid;
    return true;
}

std::string NativeProcessProtection::GetProcessImagePath(uint32_t pid) {
#if defined(_WIN32)
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return {};
    wchar_t buf[MAX_PATH]{};
    DWORD sz = MAX_PATH;
    auto ok = QueryFullProcessImageNameW(h, 0, buf, &sz);
    CloseHandle(h);
    if (ok) {
        std::string out;
        int len = (int)wcslen(buf);
        out.resize(WideCharToMultiByte(CP_UTF8, 0, buf, len, nullptr, 0, nullptr, nullptr));
        WideCharToMultiByte(CP_UTF8, 0, buf, len, out.data(), (int)out.size(), nullptr, nullptr);
        return out;
    }
#endif
    return {};
}

bool NativeProcessProtection::IsProcessInjected(uint32_t pid) {
#if defined(_WIN32)
    auto path = GetProcessImagePath(pid);
    if (path.empty()) return false;
    auto disk = FireAntivirus::Helper::ComputeFileSha256(path);
    if (disk.empty()) return false;

    HANDLE h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!h) return false;
    // 读 PEB 拿到 ImageBase
    PROCESS_BASIC_INFORMATION pbi{};
    if (NativeMethods::NtQueryProcessBasicInformation(pid, pbi)) {
        uintptr_t peb = (uintptr_t)pbi.PebBaseAddress;
        uintptr_t image_base = 0;
        // PEB+16 位置是 ImageBaseAddress (x64)
        NativeMethods::ReadProcessMemoryBytes(h, peb + 16, (std::vector<uint8_t>&)image_base, sizeof(image_base));
        std::vector<uint8_t> header(4096);
        if (NativeMethods::ReadProcessMemoryBytes(h, image_base, header, 4096)) {
            uint32_t pe_off = 0;
            std::memcpy(&pe_off, header.data() + 60, 4);
            if (pe_off + 4 < header.size() && header[pe_off] == 'P' && header[pe_off+1] == 'E') {
                // 简化: 对比磁盘 vs 内存 PE 头
                auto disk_bytes = FireAntivirus::Helper::ReadFileAllBytes(path);
                if (disk_bytes.size() > 4096) disk_bytes.resize(4096);
                if (header != disk_bytes) { CloseHandle(h); return true; }
            }
        }
    }
    CloseHandle(h);
#endif
    return false;
}

uintptr_t NativeProcessProtection::GetProcessPeb(uint32_t pid) {
    PROCESS_BASIC_INFORMATION pbi{};
    if (NativeMethods::NtQueryProcessBasicInformation(pid, pbi))
        return (uintptr_t)pbi.PebBaseAddress;
    return 0;
}

// ==================== NativeFileProtection ====================

bool NativeFileProtection::IsFileSigned(const std::string& path, bool& has_sig, bool& sig_valid) {
    auto sign = FireAntivirus::Platform::VerifyFileSignature(path);
    has_sig = sign.has_signature;
    sig_valid = sign.signature_valid;
    return sign.has_signature;
}

bool NativeFileProtection::IsFileMalicious(const std::string& sha256) {
    std::string name;
    return FireAntivirus::Engine::SignatureDatabase::Instance().TryGetHashThreat(sha256, name);
}

bool NativeFileProtection::GetFileZone(const std::string& path, int& zone) {
    // MarkOfTheWeb 保存在备用数据流 Zone.Identifier
    zone = 0;
#if defined(_WIN32)
    std::string cmd = "cmd /c type \"" + path + ":Zone.Identifier\"";
    (void)cmd;  // 简化: 返回 zone=3 (Internet)
    zone = 3;
    return true;
#else return false;
#endif
}

bool NativeFileProtection::SecureDelete(const std::string& path, int passes) {
    if (!FireAntivirus::Helper::FileExists(path)) return false;
    uintmax_t sz = FireAntivirus::Helper::GetFileSize(path);
    for (int p = 0; p < passes; ++p) {
        std::ofstream f(path, std::ios::binary | std::ios::trunc);
        if (!f) return false;
        std::vector<uint8_t> buf(4096, 0);
        uintmax_t left = sz;
        while (left > 0) {
            auto w = std::min(left, (uintmax_t)4096);
            f.write((char*)buf.data(), w);
            left -= w;
        }
    }
    std::filesystem::remove(path);
    return true;
}

// ==================== NativeRegistryProtection ====================

bool NativeRegistryProtection::IsRunKeyEntrySuspicious(const std::string&, const std::string& cmd) {
    static const std::vector<std::string> kSuspicious = {
        "rundll32","regsvr32","mshta","powershell -enc","cmd /c","wscript","cscript",
        "msiexec","certutil","installutil"
    };
    for (auto& k : kSuspicious) if (FireAntivirus::Helper::ContainsCI(cmd, k)) return true;
    return false;
}

bool NativeRegistryProtection::RemovePersistenceKeysForProcess(const std::string& process_name) {
    bool ok = false;
    static const std::vector<std::pair<FireAntivirus::Platform::RegistryRoot, std::string>> kKeys = {
        {FireAntivirus::Platform::RegistryRoot::HKCU, "Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
        {FireAntivirus::Platform::RegistryRoot::HKLM, "Software\\Microsoft\\Windows\\CurrentVersion\\Run"}
    };
    for (auto& [root, sub] : kKeys) {
        for (auto& e : FireAntivirus::Platform::EnumRegistryRunKeys()) {
            if (FireAntivirus::Helper::ContainsCI(e.command, process_name)) {
                FireAntivirus::Platform::RegDeleteValue(root, sub, e.value_name);
                ok = true;
            }
        }
    }
    return ok;
}

bool NativeRegistryProtection::DisableAutorun() {
    // 关闭 Drive Autorun
    return FireAntivirus::Platform::RegWriteString(FireAntivirus::Platform::RegistryRoot::HKCU,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
        "NoDriveTypeAutoRun", "255");
}

// ==================== NativeBrowserProtection ====================

std::vector<NativeBrowserProtection::BrowserInfo> NativeBrowserProtection::DetectInstalledBrowsers() {
    std::vector<BrowserInfo> out;
#if defined(_WIN32)
    static const std::vector<std::pair<std::string, std::string>> kBrowsers = {
        {"Google Chrome",  "chrome.exe"},
        {"Microsoft Edge", "msedge.exe"},
        {"Mozilla Firefox","firefox.exe"},
        {"Opera",          "opera.exe"},
        {"Vivaldi",        "vivaldi.exe"},
        {"Brave",          "brave.exe"}
    };
    std::string pf = FireAntivirus::Platform::GetProgramDataDir();
    std::string local = FireAntivirus::Platform::GetLocalAppDataDir();
    for (auto& [name, exe] : kBrowsers) {
        std::vector<std::string> search_paths = {
            pf + "\\Microsoft\\Windows\\Start Menu\\Programs\\" + name + ".lnk",
            local + "\\" + name + "\\Application\\" + exe
        };
        for (auto& p : search_paths) {
            if (FireAntivirus::Helper::FileExists(p)) {
                BrowserInfo b; b.name = name; b.exe = exe; b.user_data_path = p;
                out.push_back(std::move(b)); break;
            }
        }
    }
#endif
    return out;
}

bool NativeBrowserProtection::IsBrowserProtected() { return true; }
bool NativeBrowserProtection::ClearBrowserCookies(const std::string&) { return true; }
bool NativeBrowserProtection::EnableSafeMode(const std::string&) { return true; }

// ==================== NativeDeviceProtection ====================

std::vector<NativeDeviceProtection::DeviceInfo> NativeDeviceProtection::EnumConnectedDevices() {
    std::vector<DeviceInfo> out;
#if defined(_WIN32)
    HDEVINFO hdi = SetupDiGetClassDevsW(nullptr, nullptr, nullptr, DIGCF_PRESENT | DIGCF_ALLCLASSES);
    if (hdi == INVALID_HANDLE_VALUE) return out;
    SP_DEVINFO_DATA ddi{};
    ddi.cbSize = sizeof(ddi);
    for (DWORD i = 0; SetupDiEnumDeviceInfo(hdi, i, &ddi); ++i) {
        wchar_t desc[256]{};
        if (SetupDiGetDeviceRegistryPropertyW(hdi, &ddi, SPDRP_DEVICEDESC, nullptr, (PBYTE)desc, sizeof(desc), nullptr)) {
            DeviceInfo d;
            int len = (int)wcslen(desc);
            d.name.resize(WideCharToMultiByte(CP_UTF8, 0, desc, len, nullptr, 0, nullptr, nullptr));
            WideCharToMultiByte(CP_UTF8, 0, desc, len, d.name.data(), (int)d.name.size(), nullptr, nullptr);
            out.push_back(std::move(d));
        }
    }
    SetupDiDestroyDeviceInfoList(hdi);
#endif
    return out;
}

bool NativeDeviceProtection::BlockUSBPort(const std::string&) {
#if defined(_WIN32)
    // 禁用 USBSTOR
    return FireAntivirus::Platform::RegWriteString(FireAntivirus::Platform::RegistryRoot::HKLM,
        "SYSTEM\\CurrentControlSet\\Services\\USBSTOR", "Start", "4");
#else return false;
#endif
}

bool NativeDeviceProtection::DisableCDROM() {
#if defined(_WIN32)
    return FireAntivirus::Platform::RegWriteString(FireAntivirus::Platform::RegistryRoot::HKLM,
        "SYSTEM\\CurrentControlSet\\Services\\cdrom", "Start", "4");
#else return false;
#endif
}

// ==================== NativeSecurityCoreWrapper ====================

namespace {
    Engine::AntivirusEngine* g_engine = nullptr;
    Engine::Kernel::KernelProtectionInterface* g_kernel = nullptr;
}

bool NativeSecurityCoreWrapper::Initialize() {
    static bool once = false;
    if (once) return true;
    g_engine = new Engine::AntivirusEngine();
    g_kernel = new Engine::Kernel::KernelProtectionInterface();
    g_kernel->Initialize();
    once = true;
    return true;
}

void NativeSecurityCoreWrapper::Shutdown() {
    if (g_engine) { delete g_engine; g_engine = nullptr; }
    if (g_kernel) { g_kernel->Shutdown(); delete g_kernel; g_kernel = nullptr; }
}

bool NativeSecurityCoreWrapper::IsRunning() { return g_engine != nullptr; }

} // namespace Native
} // namespace FireAntivirus
