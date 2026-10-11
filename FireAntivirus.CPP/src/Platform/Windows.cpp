// FireAntivirus.CPP - Windows 平台工具实现
// 移植自 FireAntivirus.Kernel.DriverLoader / FireAntivirus.Common / SystemMonitor
#include "FireAntivirus/Platform/Windows.h"
#include <algorithm>

#if defined(_WIN32)
#include <tlhelp32.h>
#include <winreg.h>
#include <psapi.h>
#include <shlobj.h>
#include <bcrypt.h>
#endif

namespace FireAntivirus {
namespace Platform {

#if defined(_WIN32)

// ==================== 进程 ====================

std::vector<ProcessInfo> EnumProcesses() {
    std::vector<ProcessInfo> out;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return out;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(hSnap, &pe)) {
        do {
            ProcessInfo info;
            info.pid = pe.th32ProcessID;
            info.parent_pid = pe.th32ParentProcessID;
            // Convert WCHAR name to UTF-8
            int wlen = (int)wcslen(pe.szExeFile);
            info.name.resize(WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, wlen, nullptr, 0, nullptr, nullptr));
            WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, wlen, info.name.data(), (int)info.name.size(), nullptr, nullptr);
            out.push_back(std::move(info));
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return out;
}

std::vector<uint32_t> FindProcessByName(const std::string& name) {
    std::vector<uint32_t> pids;
    auto procs = EnumProcesses();
    std::string lower = Helper::ToLower(name);
    for (auto& p : procs) {
        if (Helper::ToLower(p.name) == lower || Helper::StartsWithCI(p.name, lower)) {
            pids.push_back(p.pid);
        }
    }
    return pids;
}

bool TerminateProcess(uint32_t pid) {
    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!h) return false;
    BOOL ok = ::TerminateProcess(h, 0);
    CloseHandle(h);
    return ok == TRUE;
}

// ==================== 注册表 ====================

static HKEY reg_root(RegistryRoot r) {
    switch (r) {
        case RegistryRoot::HKCU: return HKEY_CURRENT_USER;
        case RegistryRoot::HKLM: return HKEY_LOCAL_MACHINE;
        case RegistryRoot::HKCR: return HKEY_CLASSES_ROOT;
        case RegistryRoot::HKU:  return HKEY_USERS;
        case RegistryRoot::HKCC: return HKEY_CURRENT_CONFIG;
    }
    return HKEY_LOCAL_MACHINE;
}

bool RegQueryString(RegistryRoot root, const std::string& sub_key,
                    const std::string& value_name, std::string& out_value) {
    HKEY hk = nullptr;
    LONG rc = RegOpenKeyExA(reg_root(root), sub_key.c_str(), 0, KEY_READ, &hk);
    if (rc != ERROR_SUCCESS) return false;
    DWORD type = 0;
    DWORD size = 0;
    rc = RegQueryValueExA(hk, value_name.c_str(), nullptr, &type, nullptr, &size);
    if (rc != ERROR_SUCCESS) { RegCloseKey(hk); return false; }
    std::vector<char> buf(size);
    rc = RegQueryValueExA(hk, value_name.c_str(), nullptr, &type, (BYTE*)buf.data(), &size);
    RegCloseKey(hk);
    if (rc != ERROR_SUCCESS) return false;
    out_value = buf.data();
    return true;
}

bool RegWriteString(RegistryRoot root, const std::string& sub_key,
                    const std::string& value_name, const std::string& value) {
    HKEY hk = nullptr;
    LONG rc = RegCreateKeyExA(reg_root(root), sub_key.c_str(), 0, nullptr,
                              REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &hk, nullptr);
    if (rc != ERROR_SUCCESS) return false;
    rc = RegSetValueExA(hk, value_name.c_str(), 0, REG_SZ,
                        (BYTE*)value.c_str(), (DWORD)(value.size() + 1));
    RegCloseKey(hk);
    return rc == ERROR_SUCCESS;
}

bool RegDeleteValue(RegistryRoot root, const std::string& sub_key,
                    const std::string& value_name) {
    HKEY hk = nullptr;
    LONG rc = RegOpenKeyExA(reg_root(root), sub_key.c_str(), 0, KEY_SET_VALUE, &hk);
    if (rc != ERROR_SUCCESS) return false;
    rc = RegDeleteValueA(hk, value_name.c_str());
    RegCloseKey(hk);
    return rc == ERROR_SUCCESS;
}

static void collect_run_entries(RegistryRoot root, const char* sub,
                                std::vector<RegistryRunEntry>& out) {
    HKEY hk = nullptr;
    if (RegOpenKeyExA(reg_root(root), sub, 0, KEY_READ, &hk) != ERROR_SUCCESS) return;
    DWORD count = 0, max_name = 0;
    RegQueryInfoKeyA(hk, nullptr, nullptr, nullptr, &count, &max_name, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
    std::string prefix = (root == RegistryRoot::HKCU ? "HKCU" : "HKLM");
    prefix += "\\" + std::string(sub);
    for (DWORD i = 0; i < count; ++i) {
        std::string name(max_name + 1, '\0');
        DWORD name_len = (DWORD)name.size();
        DWORD type = 0, data_len = 0;
        if (RegEnumValueA(hk, i, name.data(), &name_len, nullptr, &type, nullptr, &data_len) != ERROR_SUCCESS) continue;
        std::vector<char> data(data_len + 1);
        if (RegQueryValueExA(hk, name.c_str(), nullptr, &type, (BYTE*)data.data(), &data_len) != ERROR_SUCCESS) continue;
        RegistryRunEntry e;
        e.value_name = name.substr(0, name_len);
        e.command = data.data();
        e.full_key_path = prefix + "\\" + e.value_name;
        out.push_back(std::move(e));
    }
    RegCloseKey(hk);
}

std::vector<RegistryRunEntry> EnumRegistryRunKeys() {
    std::vector<RegistryRunEntry> out;
    collect_run_entries(RegistryRoot::HKCU, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", out);
    collect_run_entries(RegistryRoot::HKLM, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", out);
    collect_run_entries(RegistryRoot::HKCU, "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", out);
    collect_run_entries(RegistryRoot::HKLM, "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", out);
    return out;
}

// ==================== 系统路径 ====================

static std::string wcs_to_utf8(const std::wstring& w) {
    int len = (int)WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string out(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), out.data(), len, nullptr, nullptr);
    return out;
}

std::string GetWindowsDir() {
    wchar_t buf[MAX_PATH]{};
    GetWindowsDirectoryW(buf, MAX_PATH);
    return wcs_to_utf8(buf);
}
std::string GetSystemDir() {
    wchar_t buf[MAX_PATH]{};
    GetSystemDirectoryW(buf, MAX_PATH);
    return wcs_to_utf8(buf);
}
std::string GetProgramDataDir() {
    wchar_t buf[MAX_PATH]{};
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, buf)))
        return wcs_to_utf8(buf);
    return "C:\\ProgramData";
}
std::string GetLocalAppDataDir() {
    wchar_t buf[MAX_PATH]{};
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, buf)))
        return wcs_to_utf8(buf);
    return {};
}
std::string GetTempDir() {
    wchar_t buf[MAX_PATH]{};
    GetTempPathW(MAX_PATH, buf);
    return wcs_to_utf8(buf);
}
std::string GetAppDataDir() {
    wchar_t buf[MAX_PATH]{};
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, 0, buf)))
        return wcs_to_utf8(buf);
    return {};
}

// ==================== PE 解析 ====================

bool IsPeFile(const std::vector<uint8_t>& data) {
    if (data.size() < 64 || data[0] != 'M' || data[1] != 'Z') return false;
    uint32_t pe_off = 0;
    std::memcpy(&pe_off, &data[60], 4);
    if (pe_off + 4 > data.size()) return false;
    return data[pe_off] == 'P' && data[pe_off + 1] == 'E';
}

int GetPeSectionCount(const std::vector<uint8_t>& data) {
    if (!IsPeFile(data)) return 0;
    uint32_t pe_off = 0;
    std::memcpy(&pe_off, &data[60], 4);
    uint16_t num_sec = 0;
    std::memcpy(&num_sec, &data[pe_off + 6], 2);
    return num_sec;
}

std::vector<std::string> GetPeImports(const std::vector<uint8_t>& data) {
    // 简化版: 扫描 .text/.rdata 区段字符串,找常见 kernel32.dll 等
    std::vector<std::string> imports;
    std::string ascii(data.begin(), data.end());
    std::vector<std::string> dlls = {"kernel32.dll","user32.dll","advapi32.dll","ws2_32.dll",
                                     "ntdll.dll","gdi32.dll","shell32.dll","ole32.dll",
                                     "oleaut32.dll","comctl32.dll","shlwapi.dll","psapi.dll",
                                     "crypt32.dll","bcrypt.dll","winhttp.dll","wininet.dll",
                                     "urlmon.dll","secur32.dll","wintrust.dll"};
    for (auto& d : dlls) {
        if (Helper::ContainsCI(ascii, d)) imports.push_back(d);
    }
    return imports;
}

SignVerifyResult VerifyFileSignature(const std::string& path) {
    SignVerifyResult result;
    result.has_signature = false;
    result.signature_valid = false;
    result.trusted_publisher = false;

    // 1. 用 WinVerifyTrust 做 Authenticode 校验
    std::wstring wpath(path.begin(), path.end());
    WINTRUST_FILE_INFOW fileInfo{};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = wpath.c_str();
    fileInfo.hFile = nullptr;
    fileInfo.pgKnownSubject = nullptr;

    GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATAW winTrustData{};
    winTrustData.cbStruct = sizeof(winTrustData);
    winTrustData.pPolicyCallbackData = nullptr;
    winTrustData.pSIPClientData = nullptr;
    winTrustData.dwUIChoice = WTD_UI_NONE;
    winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    winTrustData.hWVTStateData = nullptr;
    winTrustData.pwszURLReference = nullptr;
    winTrustData.dwProvFlags = WTD_SAFER_FLAG;
    winTrustData.pFile = &fileInfo;

    LONG lStatus = WinVerifyTrust(nullptr, &WVTPolicyGUID, &winTrustData);
    result.signature_valid = (lStatus == ERROR_SUCCESS);
    result.has_signature = true;  // 至少调通了

    // 2. 从签名中提取 subject
    if (result.signature_valid) {
        // 简化:用 CryptQueryObject 获取 cert
        CERT_CONTEXT* pCertCtx = nullptr;
        if (CryptQueryObject(CERT_QUERY_OBJECT_FILE, wpath.c_str(),
                             CERT_QUERY_CONTENT_FLAG_ALL,
                             CERT_QUERY_FORMAT_FLAG_ALL,
                             0, nullptr, nullptr, nullptr, nullptr, nullptr,
                             (const void**)&pCertCtx)) {
            if (pCertCtx) {
                // 解码 subject
                char subject[512] = {};
                CertGetNameStringA(pCertCtx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, subject, sizeof(subject));
                result.subject = subject;
                // issuer
                char issuer[512] = {};
                CertGetNameStringA(pCertCtx, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG,
                                   nullptr, issuer, sizeof(issuer));
                result.issuer = issuer;
                CertFreeCertificateContext(pCertCtx);

                // 检查是否在可信列表
                auto& trusted = GetTrustedPublishers();
                for (auto& t : trusted) {
                    if (Helper::ContainsCI(result.subject, t)) {
                        result.trusted_publisher = true;
                        break;
                    }
                }
            }
        }
    }
    return result;
}

const std::set<std::string>& GetTrustedPublishers() {
    static const std::set<std::string> s = {
        "Microsoft Corporation", "Microsoft Windows", "Microsoft",
        "Google LLC", "Google Inc", "Apple Inc.", "Mozilla Corporation",
        "Adobe Inc.", "Intel Corporation", "NVIDIA Corporation", "AMD",
        "Oracle Corporation", "VMware, Inc.", "Cisco Systems, Inc.",
        "Dell Inc.", "HP Inc.", "Lenovo", "ASUSTeK Computer Inc.",
        "Kaspersky Lab", "Symantec Corporation", "McAfee, Inc.",
        "Trend Micro, Inc.", "Bitdefender", "ESET, spol. s r.o.",
        "360 Security Technology Inc.", "Tencent", "Huawei", "Baidu, Inc."
    };
    return s;
}

#endif // _WIN32

} // namespace Platform
} // namespace FireAntivirus
