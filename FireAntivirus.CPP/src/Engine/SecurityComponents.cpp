// FireAntivirus.CPP - SecurityComponents 全部实现
#include "FireAntivirus/Engine/SecurityComponents.h"
#include "FireAntivirus/Engine/SignatureDatabase.h"
#include "FireAntivirus/DataManager.h"
#include "FireAntivirus/LogHelper.h"

#if defined(_WIN32)
#include <windows.h>
#include <winreg.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <shlobj.h>
#include <wbemidl.h>
#endif

#include <algorithm>
#include <filesystem>
#include <cstring>
#include <cmath>

namespace FireAntivirus {
namespace Engine {

// ==================== MalwareAnalyzer ====================

MalwareAnalyzer::MalwareAnalyzer() {
    families_ = {
        {"Emotet","Trojan",{"__import__","powershell","rundll32","regsvr32"},{"exe","dll","docm"},"High"},
        {"TrickBot","Trojan",{"mshta.exe","reg add","schtasks create"},{"exe","dll"},"High"},
        {"Ransom.Generic","Ransomware",{"CryptEncrypt","Aes.Create","BitLocker","vssadmin"},{"exe","dll"},"Critical"},
        {"Keylogger.Generic","Spyware",{"SetWindowsHookEx","GetAsyncKeyState","WH_KEYBOARD_LL"},{"exe","dll"},"High"},
        {"Miner.Generic","Miner",{"stratum+tcp","xmrig","cgminer","wallet"},{"exe"},"High"},
        {"Rootkit.Generic","Trojan",{"\\Device\\","\\.\\","KiAttachProcess","IoCreateDevice"},{"sys","dll"},"Critical"}
    };
}

MalwareAnalyzer::MalwareAnalysisResult MalwareAnalyzer::Analyze(const std::string& path) {
    MalwareAnalysisResult r;
    r.file_path = path;
    if (!Helper::FileExists(path)) return r;

    auto bytes = Helper::ReadFileAllBytes(path);
    std::string view;
    view.reserve(std::min(bytes.size(), size_t(50000)));
    for (size_t i = 0; i < bytes.size() && i < 50000; ++i) {
        unsigned char c = bytes[i];
        view.push_back((c >= 0x20 && c <= 0x7E) ? (char)c : ' ');
    }
    std::string ext = Helper::GetExtensionNoDot(path);

    for (auto& f : families_) {
        bool matched = false;
        for (auto& p : f.patterns) {
            if (Helper::ContainsCI(view, p)) { r.matched_patterns.push_back(p); matched = true; }
        }
        for (auto& e : f.file_extensions) {
            if (Helper::ToLower(e) == ext) { r.matched_extensions.push_back(e); matched = true; }
        }
        if (matched) {
            r.is_malware = true;
            r.family = f.name;
            r.type = f.type;
            r.risk_level = f.risk_level;
            r.confidence += 0.3;
        }
    }
    return r;
}

// ==================== SystemOptimizer ====================

SystemOptimizer::OptimizationResult SystemOptimizer::CleanTempFiles() {
    OptimizationResult r;
    std::vector<std::string> paths = {
        Platform::GetTempDir(),
        Platform::GetWindowsDir() + "\\Temp",
        Platform::GetLocalAppDataDir() + "\\Temp",
        Platform::GetWindowsDir() + "\\Prefetch"
    };
    for (auto& p : paths) {
        if (!Helper::DirectoryExists(p)) continue;
        try {
            for (auto& e : std::filesystem::directory_iterator(p)) {
                if (!e.is_regular_file()) continue;
                auto last_access = std::filesystem::last_write_time(e.path());
                auto now = std::filesystem::file_time_type::clock::now();
                auto days = std::chrono::duration_cast<std::chrono::days>(now - last_access).count();
                if (days >= 7) {
                    CleanupItem item;
                    item.path = e.path().string();
                    item.size = e.file_size();
                    item.type = "TempFile";
                    r.items.push_back(item);
                    r.total_size += item.size;
                }
            }
        } catch (...) {}
    }
    return r;
}

std::vector<std::string> SystemOptimizer::GetStartupItems() {
    return Platform::EnumRegistryRunKeys() | std::views::transform([](auto& e){ return e.full_key_path; }) | std::vector<std::string>{};
}

// ==================== ThreatHunter ====================

std::vector<ThreatHunter::ThreatHuntResult> ThreatHunter::HuntThreats() {
    std::vector<ThreatHuntResult> out;
    // 1. 可疑进程
    auto procs = Platform::EnumProcesses();
    static const std::vector<std::string> kSuspiciousProcessNames = {
        "miner","xmrig","cgminer","notcoin","bhdminer","poweliks","zeus","emotet","trickbot"
    };
    for (auto& p : procs) {
        std::string lower = Helper::ToLower(p.name);
        for (auto& sus : kSuspiciousProcessNames) {
            if (lower.find(sus) != std::string::npos) {
                ThreatHuntResult r;
                r.type = "SuspiciousProcess";
                r.name = p.name;
                r.path = "";
                r.risk_level = "High";
                out.push_back(std::move(r));
            }
        }
    }
    // 2. Temp / AppData 下可疑 exe
    std::vector<std::string> dirs = {
        Platform::GetAppDataDir(),
        Platform::GetTempDir()
    };
    for (auto& d : dirs) {
        if (!Helper::DirectoryExists(d)) continue;
        auto files = Helper::EnumerateFiles(d + "\\Microsoft", (uintmax_t)-1);
        for (auto& f : files) {
            if (Helper::GetExtensionNoDot(f) == "exe") {
                auto ana = MalwareAnalyzer().Analyze(f);
                if (ana.is_malware) {
                    ThreatHuntResult r;
                    r.type = "MalwareFile";
                    r.name = Helper::GetFileName(f);
                    r.path = f;
                    r.risk_level = ana.risk_level;
                    out.push_back(std::move(r));
                }
            }
        }
    }
    return out;
}

// ==================== IncidentResponder ====================

IncidentResponder::ResponseResult IncidentResponder::Respond(const ThreatHunter::ThreatHuntResult& threat) {
    ResponseResult r;
    try {
        if (threat.type == "SuspiciousProcess") {
            auto pids = Platform::FindProcessByName(Helper::GetFileNameNoExt(threat.path));
            for (auto pid : pids) {
                if (Platform::CanTerminateProcess(pid)) {
                    Platform::TerminateProcess(pid);
                    r.actions.push_back("终止进程: " + threat.name);
                }
            }
        } else if (threat.type == "MalwareFile") {
            auto qpath = Platform::GetTempDir() + "\\Quarantine\\" +
                         std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".quar";
            Helper::DirectoryCreate(Platform::GetTempDir() + "\\Quarantine");
            try {
                std::filesystem::rename(threat.path, qpath);
                r.actions.push_back("隔离文件: " + threat.path + " -> " + qpath);
            } catch (...) {}
        }
        r.success = true;
    } catch (std::exception& e) { r.error_message = e.what(); }
    return r;
}

// ==================== ForensicAnalyzer ====================

ForensicAnalyzer::ForensicResult ForensicAnalyzer::AnalyzeFile(const std::string& path) {
    ForensicResult r;
    r.file_path = path;
    if (!Helper::FileExists(path)) return r;
    try {
        std::error_code ec;
        auto st = std::filesystem::status(path, ec);
        auto ft = std::filesystem::file_time_type::clock::now();
        r.file_size = std::filesystem::file_size(path, ec);
        r.file_hash = Helper::ComputeFileSha256(path);

        auto bytes = Helper::ReadFileAllBytes(path);
        if (bytes.size() >= 4) {
            char hex[16]{};
            for (int i = 0; i < 4; ++i) std::snprintf(hex + i * 4, 5, "%02X ", bytes[i]);
            r.signature = hex;
        }
        // ADS (简化: 用 cmd dir /R)
#if defined(_WIN32)
        std::string dir = Platform::GetDirectory(path);
        STARTUPINFOA si{};
        PROCESS_INFORMATION pi{};
        std::string cmd = "cmd.exe /c dir /R \"" + dir + "\"";
        std::vector<char> output(32768);
        SECURITY_ATTRIBUTES sa{}; sa.nLength = sizeof(sa);
        HANDLE hReadPipe, hWritePipe;
        CreatePipe(&hReadPipe, &hWritePipe, &sa, 4096);
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdOutput = hWritePipe; si.hStdError = hWritePipe;
        std::vector<char> cmd_buf(cmd.begin(), cmd.end()); cmd_buf.push_back('\0');
        if (CreateProcessA(nullptr, cmd_buf.data(), nullptr, nullptr, TRUE,
                           CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
            CloseHandle(hWritePipe);
            WaitForSingleObject(pi.hProcess, 10000);
            DWORD read = 0;
            if (ReadFile(hReadPipe, output.data(), (DWORD)output.size(), &read, nullptr)) {
                std::string txt(output.data(), read);
                size_t pos = 0;
                std::string fname = Helper::GetFileName(path);
                while ((pos = txt.find(fname, pos)) != std::string::npos) {
                    size_t colon2 = txt.find(':', pos);
                    size_t colon3 = txt.find(':', colon2 + 1);
                    if (colon2 != std::string::npos && colon3 != std::string::npos) {
                        std::string stream = txt.substr(colon2 + 1, colon3 - colon2 - 1);
                        if (!stream.empty() && stream != "$DATA")
                            r.alternate_data_streams.push_back(stream);
                    }
                    pos++;
                }
            }
            CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
            CloseHandle(hReadPipe);
        }
#endif
        (void)ft;
    } catch (...) {}
    return r;
}

// ==================== MalwareRemover ====================

MalwareRemover::RemovalResult MalwareRemover::Remove(const std::string& path) {
    RemovalResult r;
    if (!Helper::FileExists(path)) return r;
    try {
        // 1. 终止进程
        std::string fname = Helper::GetFileNameNoExt(path);
        auto pids = Platform::FindProcessByName(fname);
        for (auto pid : pids) {
            if (Platform::CanTerminateProcess(pid)) {
                Platform::TerminateProcess(pid);
                r.actions.push_back("终止进程 PID " + std::to_string(pid));
            }
        }
        // 2. 隔离
        std::string qdir = Platform::GetTempDir() + "\\Quarantine";
        Helper::DirectoryCreate(qdir);
        std::string qpath = qdir + "\\" + Helper::GetFileName(path) + "_" +
                            std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".quar";
        try {
            std::filesystem::copy(path, qpath);
            std::filesystem::remove(path);
            r.quarantine_path = qpath;
            r.actions.push_back("隔离 -> " + qpath);
        } catch (...) {}
        // 3. 清理注册表
        RemoveRegistryEntries(fname, r);
        r.success = true;
    } catch (std::exception& e) { r.error_message = e.what(); }
    return r;
}

void MalwareRemover::RemoveRegistryEntries(const std::string& fname, RemovalResult& r) {
    static const std::vector<std::pair<Platform::RegistryRoot, std::string>> kKeys = {
        {Platform::RegistryRoot::HKCU, "Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
        {Platform::RegistryRoot::HKCU, "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"},
        {Platform::RegistryRoot::HKLM, "Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
        {Platform::RegistryRoot::HKLM, "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"}
    };
    for (auto& [root, sub] : kKeys) {
        auto entries = Platform::EnumRegistryRunKeys();
        for (auto& e : entries) {
            if (Helper::ContainsCI(e.command, fname)) {
                Platform::RegDeleteValue(root, sub, e.value_name);
                r.actions.push_back("删除注册表: " + e.full_key_path);
            }
        }
    }
}

// ==================== SystemRestorer ====================

SystemRestorer::RestoreResult SystemRestorer::RestoreSystemSettings() {
    RestoreResult r;
    RestoreHostsFile(r);
    RestoreFirewallSettings(r);
    RestoreWindowsUpdateSettings(r);
    return r;
}

void SystemRestorer::RestoreHostsFile(RestoreResult& r) {
#if defined(_WIN32)
    std::string hosts = Platform::GetSystemDir() + "\\drivers\\etc\\hosts";
    if (!Helper::FileExists(hosts)) return;
    auto content = Helper::ReadFileAllText(hosts);
    std::string clean;
    size_t pos = 0;
    while ((pos = content.find('\n')) != std::string::npos) {
        std::string line = content.substr(0, pos);
        if (!Helper::ContainsCI(line, "# Malware") && !Helper::ContainsCI(line, "# Redirect"))
            clean += line + "\n";
        content = content.substr(pos + 1);
    }
    if (clean.size() != content.size()) {
        std::ofstream f(hosts, std::ios::trunc);
        f << clean;
        r.actions.push_back("清理 Hosts 文件");
    }
#endif
}

void SystemRestorer::RestoreFirewallSettings(RestoreResult& r) {
#if defined(_WIN32)
    DWORD enable = 0, sz = sizeof(enable);
    HKEY hk = nullptr;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile",
        0, KEY_SET_VALUE | KEY_READ, &hk) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hk, "EnableFirewall", nullptr, nullptr, (BYTE*)&enable, &sz) == ERROR_SUCCESS && enable == 0) {
            enable = 1;
            RegSetValueExA(hk, "EnableFirewall", 0, REG_DWORD, (BYTE*)&enable, sizeof(enable));
            r.actions.push_back("启用 Windows 防火墙");
        }
        RegCloseKey(hk);
    }
#endif
}

void SystemRestorer::RestoreWindowsUpdateSettings(RestoreResult& r) {
#if defined(_WIN32)
    DWORD noau = 0, sz = sizeof(noau);
    HKEY hk = nullptr;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU",
        0, KEY_SET_VALUE | KEY_READ, &hk) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hk, "NoAutoUpdate", nullptr, nullptr, (BYTE*)&noau, &sz) == ERROR_SUCCESS && noau == 1) {
            noau = 0;
            RegSetValueExA(hk, "NoAutoUpdate", 0, REG_DWORD, (BYTE*)&noau, sizeof(noau));
            r.actions.push_back("启用 Windows 自动更新");
        }
        RegCloseKey(hk);
    }
#endif
}

// ==================== BackupAnalyzer ====================

BackupAnalyzer::BackupAnalysisResult BackupAnalyzer::AnalyzeBackups() {
    BackupAnalysisResult r;
#if defined(_WIN32)
    // WMI 查询 Win32_ShadowCopy
    HKEY hk = nullptr;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsBackup", 0, KEY_READ, &hk) == ERROR_SUCCESS) {
        r.has_windows_backup = true;
        r.backup_locations.push_back("Windows Backup 已配置");
        RegCloseKey(hk);
    }
#endif
    return r;
}

// ==================== IntegrityVerifier ====================

void IntegrityVerifier::LoadKnownHashes() {
    std::string sys32 = Platform::GetSystemDir();
    static const char* kCritical[] = {
        "kernel32.dll","ntdll.dll","user32.dll","advapi32.dll",
        "gdi32.dll","win32u.dll","ole32.dll"
    };
    for (auto* name : kCritical) {
        std::string path = sys32 + "\\" + name;
        if (Helper::FileExists(path)) system_file_hashes_[name] = Helper::ComputeFileSha256(path);
    }
}

std::vector<IntegrityVerifier::IntegrityResult> IntegrityVerifier::VerifySystemFiles() {
    std::vector<IntegrityVerifier::IntegrityResult> out;
    if (system_file_hashes_.empty()) LoadKnownHashes();
    std::string sys32 = Platform::GetSystemDir();
    for (auto& [name, original_hash] : system_file_hashes_) {
        std::string path = sys32 + "\\" + name;
        IntegrityResult r;
        r.file_path = path;
        r.original_hash = original_hash;
        if (Helper::FileExists(path)) {
            r.current_hash = Helper::ComputeFileSha256(path);
            r.is_intact = (r.current_hash == original_hash);
        }
        out.push_back(std::move(r));
    }
    return out;
}

// ==================== SandboxAnalyzer ====================

SandboxAnalyzer::SandboxResult SandboxAnalyzer::Analyze(const std::string& path) {
    SandboxResult r; r.file_path = path;
    auto bytes = Helper::ReadFileAllBytes(path);
    if (bytes.empty()) return r;
    std::string view;
    view.reserve(std::min(bytes.size(), size_t(100000)));
    for (size_t i = 0; i < bytes.size() && i < 100000; ++i) {
        unsigned char c = bytes[i];
        view.push_back((c >= 0x20 && c <= 0x7E) ? (char)c : ' ');
    }

    if (Helper::ContainsCI(view, "CreateRemoteThread") || Helper::ContainsCI(view, "WriteProcessMemory")) {
        r.behaviors.push_back("Process Injection"); r.risk_score += 30;
    }
    if (Helper::ContainsCI(view, "CurrentVersion\\Run") || Helper::ContainsCI(view, "RunOnce")) {
        r.behaviors.push_back("Registry Persistence"); r.risk_score += 20;
    }
    if (Helper::ContainsCI(view, "HttpWebRequest") || Helper::ContainsCI(view, "Socket")) {
        r.behaviors.push_back("Network Communication"); r.risk_score += 15;
    }
    if (Helper::ContainsCI(view, "CryptEncrypt") || Helper::ContainsCI(view, "Aes.Create")) {
        r.behaviors.push_back("File Encryption"); r.risk_score += 25;
    }
    if (Helper::ContainsCI(view, "IsDebuggerPresent") || Helper::ContainsCI(view, "CheckRemoteDebuggerPresent")) {
        r.behaviors.push_back("Anti-Debug"); r.risk_score += 20;
    }
    if (Helper::ContainsCI(view, "VirtualBox") || Helper::ContainsCI(view, "VMware") || Helper::ContainsCI(view, "Sandbox")) {
        r.behaviors.push_back("VM Detection"); r.risk_score += 15;
    }
    r.is_malicious = r.risk_score >= 50;
    return r;
}

// ==================== MachineLearningDetector ====================

std::map<std::string, double> MachineLearningDetector::ExtractFeatures(const std::vector<uint8_t>& data) {
    std::map<std::string, double> f;
    if (data.empty()) return f;
    // 熵值
    int freq[256]{};
    for (auto b : data) freq[b]++;
    double ent = 0;
    for (int c : freq) if (c > 0) { double p=(double)c/data.size(); ent -= p*std::log2(p); }
    f["entropy"] = std::min(ent / 8.0, 1.0);

    std::string view;
    view.reserve(std::min(data.size(), size_t(50000)));
    for (size_t i = 0; i < data.size() && i < 50000; ++i) {
        unsigned char c = data[i];
        view.push_back((c >= 0x20 && c <= 0x7E) ? (char)c : ' ');
    }
    // 可疑 API 数
    static const std::vector<std::string> kSuspicious = {
        "CreateRemoteThread","WriteProcessMemory","VirtualAllocEx","RegSetValue"
    };
    int cnt = 0;
    for (auto& a : kSuspicious) if (Helper::ContainsCI(view, a)) cnt++;
    f["suspicious_apis"] = std::min((double)cnt / 20.0, 1.0);
    return f;
}

double MachineLearningDetector::CalculateScore(const std::map<std::string, double>& f) {
    static const std::map<std::string, double> kWeights = {
        {"entropy",0.15},{"import_count",0.10},{"section_count",0.08},
        {"string_entropy",0.12},{"pe_characteristics",0.15},{"suspicious_apis",0.20},
        {"resource_count",0.05},{"digital_signature",0.15}
    };
    double s = 0;
    for (auto& [k, v] : f) {
        auto it = kWeights.find(k);
        if (it != kWeights.end()) s += v * it->second;
    }
    return std::min(s, 1.0);
}

MachineLearningDetector::MLDetectionResult MachineLearningDetector::Detect(const std::string& path) {
    MLDetectionResult r; r.file_path = path;
    auto bytes = Helper::ReadFileAllBytes(path);
    if (bytes.empty()) return r;
    r.features = ExtractFeatures(bytes);
    r.score = CalculateScore(r.features);
    r.is_malicious = r.score > 0.7;
    return r;
}

// ==================== BehavioralHeuristics ====================

BehavioralHeuristics::HeuristicResult BehavioralHeuristics::Analyze(const std::string& path) {
    HeuristicResult r; r.file_path = path;
    auto bytes = Helper::ReadFileAllBytes(path);
    if (bytes.empty()) return r;
    std::string view;
    view.reserve(std::min(bytes.size(), size_t(100000)));
    for (size_t i = 0; i < bytes.size() && i < 100000; ++i) {
        unsigned char c = bytes[i];
        view.push_back((c >= 0x20 && c <= 0x7E) ? (char)c : ' ');
    }
    // 模式
    struct Pat { const char* name; std::vector<std::string> conds; const char* risk; };
    static const std::vector<Pat> patterns = {
        {"Ransomware", {"CryptEncrypt","GetFiles","vssadmin"}, "Critical"},
        {"Keylogger",  {"SetWindowsHookEx","BitBlt","Send"},   "High"},
        {"Downloader", {"HttpWebRequest","File.Create","CreateProcess"}, "High"}
    };
    for (auto& p : patterns) {
        int matched = 0;
        for (auto& cond : p.conds) if (Helper::ContainsCI(view, cond)) matched++;
        if (matched >= 2) {
            r.detected_patterns.push_back(p.name);
            r.risk_score += std::string(p.risk) == "Critical" ? 50 : 30;
        }
    }
    r.is_malicious = r.risk_score >= 50;
    return r;
}

// ==================== CryptoAnalyzer ====================

CryptoAnalyzer::CryptoAnalysisResult CryptoAnalyzer::Analyze(const std::string& path) {
    CryptoAnalysisResult r; r.file_path = path;
    auto bytes = Helper::ReadFileAllBytes(path);
    if (bytes.empty()) return r;
    std::string view;
    view.reserve(std::min(bytes.size(), size_t(100000)));
    for (size_t i = 0; i < bytes.size() && i < 100000; ++i) {
        unsigned char c = bytes[i];
        view.push_back((c >= 0x20 && c <= 0x7E) ? (char)c : ' ');
    }
    static const std::vector<std::string> kMiningPools = {
        "stratum+tcp://","stratum+ssl://","x.pool.zpool","stratum.f2pool",
        "nicehash","hashrefinery","miningpoolhub"
    };
    static const std::vector<std::string> kCryptoPatterns = {
        "wallet","bitcoin","ethereum","monero","litecoin","hashrate","mining","xmrig"
    };
    for (auto& p : kMiningPools) {
        if (Helper::ContainsCI(view, p)) { r.mining_pools.push_back(p); r.risk_score += 30; }
    }
    for (auto& p : kCryptoPatterns) {
        if (Helper::ContainsCI(view, p)) { r.crypto_patterns.push_back(p); r.risk_score += 5; }
    }
    r.is_crypto_malware = r.risk_score >= 30;
    return r;
}

} // namespace Engine
} // namespace FireAntivirus
