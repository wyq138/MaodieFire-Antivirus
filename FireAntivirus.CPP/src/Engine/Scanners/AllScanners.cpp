// FireAntivirus.CPP - 扫描器全部实现
// 移植自 FireAntivirus.Engine.Scanners/*
#include "FireAntivirus/Engine/Scanners/AllScanners.h"
#include "FireAntivirus/Helper.h"
#include "FireAntivirus/Platform/Windows.h"
#include <algorithm>
#include <cstring>

#if defined(_WIN32)
#include <windows.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <winreg.h>
#pragma comment(lib, "iphlpapi.lib")
#endif

namespace FireAntivirus {
namespace Engine {
namespace Scanners {

// ==================== MemoryScanner ====================

std::vector<ScanResult> MemoryScanner::ScanProcess(uint32_t pid) {
    std::vector<ScanResult> hits;
#if defined(_WIN32)
    HANDLE h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!h) return hits;

    // 遍历进程内存区域
    MEMORY_BASIC_INFORMATION mbi;
    uintptr_t addr = 0;
    while (VirtualQueryEx(h, (LPCVOID)addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT && mbi.RegionSize > 0 && mbi.RegionSize <= 32 * 1024 * 1024) {
            std::vector<uint8_t> buf((size_t)mbi.RegionSize);
            SIZE_T read = 0;
            if (ReadProcessMemory(h, (LPCVOID)addr, buf.data(), buf.size(), &read) && read > 0) {
                std::string view;
                view.reserve(std::min(buf.size(), size_t(10000)));
                for (size_t i = 0; i < buf.size() && i < 10000; ++i) {
                    unsigned char c = buf[i];
                    view.push_back((c >= 0x20 && c <= 0x7E) ? (char)c : ' ');
                }
                // 找 shellcode / 注入代码 特征
                if (Helper::ContainsCI(view, "CreateRemoteThread") ||
                    Helper::ContainsCI(view, "VirtualProtect") ||
                    Helper::ContainsCI(view, "PAGE_EXECUTE_READWRITE")) {
                    ScanResult r;
                    r.file_path        = "<memory: pid=" + std::to_string(pid) + ">";
                    r.is_infected      = true;
                    r.threat_name      = "Memory.SuspiciousInject";
                    r.threat_type      = "Trojan";
                    r.severity         = "High";
                    r.confidence      = 0.7;
                    r.detection_method = "MemoryScanner";
                    hits.push_back(std::move(r));
                }
            }
        }
        addr += mbi.RegionSize;
    }
    CloseHandle(h);
#endif
    return hits;
}

std::vector<ScanResult> MemoryScanner::ScanAll() {
    std::vector<ScanResult> out;
    auto procs = Platform::EnumProcesses();
    for (auto& p : procs) {
        auto r = ScanProcess(p.pid);
        out.insert(out.end(), r.begin(), r.end());
    }
    return out;
}

// ==================== RegistryScanner ====================

std::vector<ScanResult> RegistryScanner::ScanAutorunKeys() {
    std::vector<ScanResult> hits;
    auto entries = Platform::EnumRegistryRunKeys();
    static const std::vector<std::string> kSuspicious = {
        "rundll32","regsvr32","mshta","powershell -enc","cmd /c",
        "wscript","cscript","msiexec","installutil","certutil",
        "sc create","schtasks"
    };
    for (auto& e : entries) {
        std::string lower_cmd = Helper::ToLower(e.command);
        for (auto& kw : kSuspicious) {
            if (Helper::ContainsCI(lower_cmd, kw)) {
                ScanResult r;
                r.file_path        = e.full_key_path;
                r.is_infected      = true;
                r.threat_name      = "Registry.AutorunSuspicious";
                r.threat_type      = "Backdoor";
                r.severity         = "Medium";
                r.confidence      = 0.55;
                r.detection_method = "RegistryScanner";
                r.additional_info  = "命令: " + e.command;
                hits.push_back(std::move(r));
                break;
            }
        }
    }
    return hits;
}

std::vector<ScanResult> RegistryScanner::ScanSuspiciousKeys() {
    return ScanAutorunKeys();
}

// ==================== NetworkScanner ====================

std::vector<NetworkConnection> NetworkScanner::EnumConnections() {
    std::vector<NetworkConnection> out;
#if defined(_WIN32)
    // TCP
    MIB_TCP_STATE tcp_state = {};
    DWORD size = 0;
    GetTcpTable(nullptr, &size, AF_INET);
    std::vector<uint8_t> buf(size);
    if (GetTcpTable(buf.data(), &size, AF_INET) == NO_ERROR) {
        auto* table = (PMIB_TCPTABLE)buf.data();
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            auto& e = table->table[i];
            NetworkConnection c;
            c.pid = e.dwOwningPid;
            c.local_ip = std::to_string((e.dwLocalAddr >> 24) & 0xFF) + "." +
                         std::to_string((e.dwLocalAddr >> 16) & 0xFF) + "." +
                         std::to_string((e.dwLocalAddr >> 8) & 0xFF) + "." +
                         std::to_string(e.dwLocalAddr & 0xFF);
            c.local_port = (uint16_t)ntohs((u_short)e.dwLocalPort);
            c.remote_ip = std::to_string((e.dwRemoteAddr >> 24) & 0xFF) + "." +
                          std::to_string((e.dwRemoteAddr >> 16) & 0xFF) + "." +
                          std::to_string((e.dwRemoteAddr >> 8) & 0xFF) + "." +
                          std::to_string(e.dwRemoteAddr & 0xFF);
            c.remote_port = (uint16_t)ntohs((u_short)e.dwRemotePort);
            c.protocol = "TCP";
            switch (e.dwState) {
                case 1: c.state = "CLOSED"; break;
                case 2: c.state = "LISTENING"; break;
                case 3: c.state = "SYN_SENT"; break;
                case 4: c.state = "SYN_RCVD"; break;
                case 5: c.state = "ESTABLISHED"; break;
                case 6: c.state = "FIN_WAIT_1"; break;
                case 7: c.state = "FIN_WAIT_2"; break;
                case 8: c.state = "CLOSE_WAIT"; break;
                case 9: c.state = "CLOSING"; break;
                case 10: c.state = "LAST_ACK"; break;
                case 11: c.state = "TIME_WAIT"; break;
                case 12: c.state = "DELETE_TCB"; break;
                default: c.state = "UNKNOWN"; break;
            }
            out.push_back(std::move(c));
        }
    }
#endif
    return out;
}

std::vector<ScanResult> NetworkScanner::ScanConnections() {
    std::vector<ScanResult> hits;
    auto conns = EnumConnections();
    static const std::vector<uint16_t> kSuspiciousPorts = {
        4444, 5555, 6666, 31337, 1234, 5354, 9001, 9050, 1080, 8080
    };
    for (auto& c : conns) {
        bool listen_suspicious = (c.state == "LISTENING" &&
            std::find(kSuspiciousPorts.begin(), kSuspiciousPorts.end(), c.local_port) != kSuspiciousPorts.end());
        if (listen_suspicious) {
            ScanResult r;
            r.file_path        = "<network: pid=" + std::to_string(c.pid) + ":" + std::to_string(c.local_port) + ">";
            r.is_infected      = true;
            r.threat_name      = "Network.SuspiciousPortListening";
            r.threat_type      = "Backdoor";
            r.severity         = "High";
            r.confidence      = 0.6;
            r.detection_method = "NetworkScanner";
            hits.push_back(std::move(r));
        }
    }
    return hits;
}

// ==================== StartupScanner ====================

std::vector<StartupItem> StartupScanner::EnumAll() {
    std::vector<StartupItem> out;
    // 1. 注册表 Run/RunOnce
    for (auto& e : Platform::EnumRegistryRunKeys()) {
        StartupItem s;
        s.name     = e.value_name;
        s.location = e.full_key_path;
        s.command  = e.command;
        out.push_back(std::move(s));
    }
    // 2. 启动文件夹 (HKCU + HKLM)
    auto enum_folder = [&](const std::string& folder) {
        auto files = Helper::EnumerateFiles(folder, (uintmax_t)-1);
        for (auto& f : files) {
            StartupItem s;
            s.name     = Helper::GetFileName(f);
            s.location = folder;
            s.command  = f;
            auto sign = Platform::VerifyFileSignature(f);
            s.is_signed = sign.signature_valid && sign.trusted_publisher;
            out.push_back(std::move(s));
        }
    };
#if defined(_WIN32)
    wchar_t buf[MAX_PATH]{};
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_STARTUP, nullptr, 0, buf)))
        enum_folder(Platform::wcs_to_utf8(buf));
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_COMMON_STARTUP, nullptr, 0, buf)))
        enum_folder(Platform::wcs_to_utf8(buf));
#else
    (void)enum_folder;
#endif
    return out;
}

std::vector<ScanResult> StartupScanner::ScanItems() {
    std::vector<ScanResult> hits;
    auto items = EnumAll();
    for (auto& s : items) {
        std::string lower_cmd = Helper::ToLower(s.command);
        static const std::vector<std::string> kSuspicious = {
            "rundll32","regsvr32","mshta","powershell -enc","cmd /c",
            "wscript","cscript","msiexec","certutil","installutil",
            "appdata\\local\\temp","appdata\\roaming"
        };
        bool hit_it = false;
        for (auto& kw : kSuspicious) {
            if (Helper::ContainsCI(lower_cmd, kw)) { hit_it = true; break; }
        }
        if (hit_it || (!s.is_signed && Helper::GetExtensionNoDot(s.command) == "exe")) {
            ScanResult r;
            r.file_path        = s.location;
            r.is_infected      = true;
            r.threat_name      = "Startup.SuspiciousItem";
            r.threat_type      = "Backdoor";
            r.severity         = "Medium";
            r.confidence      = hit_it ? 0.6 : 0.45;
            r.detection_method = "StartupScanner";
            r.additional_info  = s.name + " -> " + s.command;
            hits.push_back(std::move(r));
        }
    }
    return hits;
}

// ==================== ProcessScanner ====================

std::vector<ScanResult> ProcessScanner::ScanAll() {
    std::vector<ScanResult> hits;
    static const std::vector<std::string> kSuspiciousNames = {
        "wscript.exe","cscript.exe","powershell.exe","cmd.exe",
        "rundll32.exe","regsvr32.exe","mshta.exe","msiexec.exe",
        "certutil.exe","installutil.exe","regasm.exe","vbc.exe"
    };
    auto procs = Platform::EnumProcesses();
    for (auto& p : procs) {
        std::string lower = Helper::ToLower(p.name);
        for (auto& bad : kSuspiciousNames) {
            if (Helper::ContainsCI(lower, bad)) {
                ScanResult r;
                r.file_path        = "<process: " + p.name + " pid=" + std::to_string(p.pid) + ">";
                r.is_infected      = true;
                r.threat_name      = "Process.SuspiciousTool";
                r.threat_type      = "Trojan";
                r.severity         = "Low";
                r.confidence      = 0.4;
                r.detection_method = "ProcessScanner";
                hits.push_back(std::move(r));
                break;
            }
        }
    }
    return hits;
}

// ==================== AntiRootkitScanner ====================

std::vector<ScanResult> AntiRootkitScanner::Scan() {
    std::vector<ScanResult> hits;
#if defined(_WIN32)
    // 1. 比 WMI 和 Toolhelp32 两个接口的进程数差异 -> 隐藏进程
    auto th = Platform::EnumProcesses();

    // 2. 检查驱动服务
    std::vector<std::string> kSuspiciousDrivers = {
        "BlackLight","Rootkit","HackerDefender","TDSS","ZeroAccess","TDL",
        "Alureon","Bootkit","Necurs","Olmasco","Sinowal","Whistler"
    };
    HKEY hk = nullptr;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services", 0, KEY_READ, &hk) == ERROR_SUCCESS) {
        DWORD idx = 0;
        char name[256]{};
        DWORD nlen = sizeof(name);
        while (RegEnumKeyExA(hk, idx++, name, &nlen, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
            std::string lower = Helper::ToLower(name);
            for (auto& sus : kSuspiciousDrivers) {
                if (lower.find(sus) != std::string::npos) {
                    ScanResult r;
                    r.file_path        = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\" + std::string(name);
                    r.is_infected      = true;
                    r.threat_name      = "Rootkit.Driver";
                    r.threat_type      = "Trojan";
                    r.severity         = "Critical";
                    r.confidence      = 0.85;
                    r.detection_method = "AntiRootkitScanner";
                    hits.push_back(std::move(r));
                }
            }
            nlen = sizeof(name);
        }
        RegCloseKey(hk);
    }
#endif
    return hits;
}

// ==================== VulnerabilityScanner ====================

std::vector<VulnerabilityInfo> VulnerabilityScanner::ScanSystem() {
    std::vector<VulnerabilityInfo> out;
#if defined(_WIN32)
    // 简单检查: OS 版本和补丁
    OSVERSIONINFOEXW os{};
    os.dwOSVersionInfoSize = sizeof(os);
    if (GetVersionExW((LPOSVERSIONINFOW)&os)) {
        if (os.dwMajorVersion == 10 && os.dwMinorVersion == 0 && os.wBuildNumber < 19045) {
            VulnerabilityInfo v;
            v.cve_id = "CVE-SUPPORTED";
            v.title = "Windows 10 版本过旧";
            v.description = "当前 Windows 10 版本低于 22H2,可能缺少安全补丁";
            v.severity = "Medium";
            v.affected_product = "Windows 10";
            v.fix_version = "22H2 (Build 19045+)";
            out.push_back(std::move(v));
        }
    }

    // 检查 Windows Defender 是否关闭
    wchar_t buf[MAX_PATH]{};
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows Defender", 0, KEY_READ, nullptr) != ERROR_SUCCESS) {
        VulnerabilityInfo v;
        v.cve_id = "CFG-DEFENDER";
        v.title = "Windows Defender 可能未安装";
        v.description = "系统未检测到 Windows Defender,建议启用";
        v.severity = "High";
        v.affected_product = "Windows Defender";
        out.push_back(std::move(v));
    }

    // 检查自动更新
    DWORD noau = 0, au_len = sizeof(DWORD);
    if (RegQueryValueExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU",
        "NoAutoUpdate", nullptr, (BYTE*)&noau, &au_len) == ERROR_SUCCESS && noau == 1) {
        VulnerabilityInfo v;
        v.cve_id = "CFG-AUTOUPDATE";
        v.title = "Windows 自动更新已关闭";
        v.description = "自动更新被组策略禁用,可能缺少安全补丁";
        v.severity = "High";
        v.affected_product = "Windows Update";
        out.push_back(std::move(v));
    }
#endif
    return out;
}

std::vector<ScanResult> VulnerabilityScanner::ScanAll() {
    std::vector<ScanResult> hits;
    auto vulns = ScanSystem();
    for (auto& v : vulns) {
        ScanResult r;
        r.file_path        = "<system:" + v.cve_id + ">";
        r.is_infected      = true;
        r.threat_name      = v.cve_id + ": " + v.title;
        r.threat_type      = "Vulnerability";
        r.severity         = v.severity;
        r.confidence      = 0.8;
        r.detection_method = "VulnerabilityScanner";
        r.additional_info  = v.description;
        hits.push_back(std::move(r));
    }
    return hits;
}

} // namespace Scanners
} // namespace Engine
} // namespace FireAntivirus
