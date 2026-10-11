// FireAntivirus.CPP - RealTimeProtectionPlus + AI + ClamAV + CloudAV 实现
#include "FireAntivirus/RealTimeProtectionPlus.h"
#include "FireAntivirus/Helper.h"
#include "FireAntivirus/Platform/Windows.h"
#include "FireAntivirus/Engine/AntivirusEngine.h"
#include "FireAntivirus/Engine/KernelProtection.h"
#include "FireAntivirus/LogHelper.h"
#include "FireAntivirus/Network/HttpClient.h"

#include <algorithm>
#include <filesystem>
#include <chrono>

#if defined(_WIN32)
#include <windows.h>
#include <tlhelp32.h>
#endif

namespace FireAntivirus {

// ==================== RTPPlus ====================

namespace RTPPlus {

bool ProtectionModule::Initialize() {
    if (active_.load()) return true;
    active_.store(true);
    worker_ = std::thread([this]{ MonitorWorker(); });
    return true;
}

void ProtectionModule::Shutdown() {
    active_.store(false);
    if (worker_.joinable()) worker_.join();
}

void ProtectionModule::MonitorWorker() {
    // 简化实时保护: 每秒扫描 Temp/AppData 下新出现的 exe
    std::vector<std::string> watch_dirs = {
        Platform::GetTempDir(),
        Platform::GetLocalAppDataDir() + "\\Temp",
        Platform::GetAppDataDir() + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
    };
    std::map<std::string, std::filesystem::file_time_type> last_seen;

    while (active_.load()) {
        for (auto& d : watch_dirs) {
            if (!Helper::DirectoryExists(d)) continue;
            try {
                for (auto& e : std::filesystem::directory_iterator(d)) {
                    if (!e.is_regular_file()) continue;
                    std::string name = Helper::GetFileName(e.path().string());
                    std::string ext  = Helper::ToLower(Helper::GetExtensionNoDot(e.path().string()));
                    static const std::vector<std::string> kBad = {"exe","dll","scr","com","bat","cmd","ps1","vbs","js"};
                    bool is_bad = false;
                    for (auto& b : kBad) if (ext == b) is_bad = true;
                    if (!is_bad) continue;

                    auto ft = e.last_write_time();
                    auto now = std::filesystem::file_time_type::clock::now();
                    auto diff = std::chrono::duration_cast<std::chrono::seconds>(now - ft).count();

                    auto it = last_seen.find(e.path().string());
                    bool is_new = (it == last_seen.end() || it->second != ft);
                    if (is_new && diff < 15) {  // 15 秒内新写入的
                        FileAlert alert;
                        alert.path = e.path().string();
                        alert.reason = "临时目录/AppData下新出现的可疑文件";
                        alert.should_block = false;
                        if (alert_cb_) alert_cb_(alert);
                        // 自动拦截: 用引擎扫一下
                        auto scan_result = Engine::AntivirusEngine().ScanFile(alert.path);
                        if (scan_result.is_infected) {
                            alert.should_block = true;
                            FireAntivirus::Data::DataManager::Instance().Quarantine(alert.path, "RealTimeProtectionPlus");
                            if (alert_cb_) alert_cb_(alert);
                        }
                    }
                    last_seen[e.path().string()] = ft;
                }
            } catch (...) {}
        }
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
}

std::vector<FeatureSelfTest::TestResult> FeatureSelfTest::RunAll() {
    std::vector<TestResult> out;
    #if defined(_WIN32)
    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    out.push_back({"NTDLL Available", nt != nullptr, nt ? "OK" : "FAILED"});
    #endif
    out.push_back({"Kernel Protection",
        Engine::Kernel::KernelProtectionInterface().IsInitialized(),
        Engine::Kernel::KernelProtectionInterface().IsDriverConnected() ? "驱动已连接" : "用户模式降级"});
    out.push_back({"Signature DB",
        Engine::SignatureDatabase::Instance().IsLoaded(),
        std::to_string(Engine::SignatureDatabase::Instance().HashCount()) + " 条"});
    return out;
}

RealTimeProtectionPlusManager& RealTimeProtectionPlusManager::Instance() {
    static RealTimeProtectionPlusManager inst;
    return inst;
}

bool RealTimeProtectionPlusManager::Start() { return file_.Initialize(); }
bool RealTimeProtectionPlusManager::Stop()  { file_.Shutdown(); return true; }
bool RealTimeProtectionPlusManager::IsRunning() { return file_.IsActive(); }

} // namespace RTPPlus

// ==================== AI ====================

namespace AI {

bool AdvancedAIDetectionEngine::Initialize() {
    feature_weights_ = {
        {"entropy",            0.15},
        {"section_count",      0.08},
        {"suspicious_api",     0.25},
        {"import_count",       0.08},
        {"pe_characteristics", 0.15},
        {"digital_signature",  0.15},
        {"network_strings",    0.10},
        {"crypto_strings",     0.08}
    };
    enabled_.store(true);
    return true;
}

AdvancedAIDetectionEngine::AIResult AdvancedAIDetectionEngine::AnalyzeFile(const std::string& path) {
    AIResult r; r.model_version = "FireAntivirus.AI.v1";
    if (!enabled_.load()) return r;
    auto bytes = Helper::ReadFileAllBytes(path);
    if (bytes.empty()) return r;

    // 特征提取
    std::map<std::string, double> features;
    int freq[256]{};
    for (auto b : bytes) freq[b]++;
    double ent = 0;
    for (int c : freq) if (c > 0) { double p=(double)c/bytes.size(); ent -= p*std::log2(p); }
    features["entropy"] = std::min(ent / 8.0, 1.0);

    std::string view;
    view.reserve(std::min(bytes.size(), size_t(50000)));
    for (size_t i = 0; i < bytes.size() && i < 50000; ++i) {
        unsigned char c = bytes[i];
        view.push_back((c >= 0x20 && c <= 0x7E) ? (char)c : ' ');
    }
    static const std::vector<std::string> kSuspiciousApi = {
        "CreateRemoteThread","WriteProcessMemory","VirtualAllocEx","RegSetValueExA",
        "CryptEncrypt","IsDebuggerPresent","GetAsyncKeyState","SetWindowsHookEx"
    };
    int api_hit = 0;
    for (auto& a : kSuspiciousApi) if (Helper::ContainsCI(view, a)) api_hit++;
    features["suspicious_api"] = std::min((double)api_hit / 4.0, 1.0);

    static const std::vector<std::string> kNetStr = {
        "socket","HttpWebRequest","Socket.Connect","http://","https://"
    };
    int net = 0;
    for (auto& s : kNetStr) if (Helper::ContainsCI(view, s)) net++;
    features["network_strings"] = std::min((double)net / 3.0, 1.0);

    static const std::vector<std::string> kCryptoStr = {
        "CryptEncrypt","CryptAcquireContext","Aes.Create","RSA.Encrypt","Stratum"
    };
    int cr = 0;
    for (auto& s : kCryptoStr) if (Helper::ContainsCI(view, s)) cr++;
    features["crypto_strings"] = std::min((double)cr / 2.0, 1.0);

    // 数字签名特征
    auto sign = Platform::VerifyFileSignature(path);
    features["digital_signature"] = (sign.signature_valid && sign.trusted_publisher) ? 0.0 : 1.0;

    // 加权打分
    double score = 0;
    for (auto& [k, fv] : features) {
        auto it = feature_weights_.find(k);
        if (it != feature_weights_.end()) score += fv * it->second;
    }
    r.confidence = std::min(score * 1.4, 1.0);
    r.is_malicious = r.confidence > 0.5;
    for (auto& [k, v] : features) if (v > 0.3) r.features.push_back(k + "=" + std::to_string((int)(v*100)));
    return r;
}

AdvancedAIDetectionEngine::AIResult AdvancedAIDetectionEngine::AnalyzeBehavior(const std::vector<std::string>& api_calls) {
    AIResult r; r.model_version = "FireAntivirus.AI.Behavior.v1";
    if (!enabled_.load()) return r;
    std::string combined;
    for (auto& a : api_calls) combined += a + ",";
    double score = 0;
    static const std::vector<std::pair<std::string, double>> kRules = {
        {"CreateRemoteThread", 0.25}, {"WriteProcessMemory", 0.25},
        {"RegSetValue",       0.15}, {"CryptEncrypt",    0.25},
        {"IsDebuggerPresent",  0.15}, {"SetWindowsHookEx", 0.20}
    };
    for (auto& [k, w] : kRules) if (Helper::ContainsCI(combined, k)) score += w;
    r.confidence = std::min(score, 1.0);
    r.is_malicious = r.confidence > 0.4;
    return r;
}

} // namespace AI

// ==================== ClamAV ====================

namespace ClamAV {

bool ClamAVManager::IsAvailable() {
#if defined(_WIN32)
    return !Helper::FileExists(clamscan_path_);
#else return false;
#endif
}

bool ClamAVManager::Initialize() {
#if defined(_WIN32)
    // 搜索 clamscan.exe
    for (auto& dir : {Helper::GetDirectory(""), ".", "ClamAV", "clamav",
                      Helper::GetWindowsDir() + "\\System32",
                      "C:\\Program Files\\ClamAV"}) {
        std::string p = dir + "\\clamscan.exe";
        if (Helper::FileExists(p)) {
            clamscan_path_ = p;
            db_path_ = dir + "\\db";
            if (!Helper::DirectoryExists(db_path_)) db_path_ = dir + "\\database";
            initialized_ = true;
            return true;
        }
    }
#endif
    return false;
}

bool ClamAVManager::Shutdown() { initialized_ = false; return true; }

ScanResult ClamAVManager::ScanFile(const std::string& path) {
    ScanResult r; r.file_path = path; r.detection_method = "ClamAV";
    if (!initialized_ && !Initialize()) return r;
#if defined(_WIN32)
    std::string cmd = "\"" + clamscan_path_ + "\"";
    if (!db_path_.empty()) cmd += " --database=\"" + db_path_ + "\"";
    cmd += " --no-summary \"" + path + "\"";

    STARTUPINFOA si{}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    std::vector<char> cmd_buf(cmd.begin(), cmd.end()); cmd_buf.push_back('\0');

    SECURITY_ATTRIBUTES sa{}; sa.nLength = sizeof(sa);
    HANDLE hRead = nullptr, hWrite = nullptr;
    CreatePipe(&hRead, &hWrite, &sa, 65536);
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWrite; si.hStdError = hWrite;

    if (CreateProcessA(nullptr, cmd_buf.data(), nullptr, nullptr, TRUE,
                       CREATE_NO_WINDOW | DETACHED_PROCESS, nullptr, nullptr, &si, &pi)) {
        CloseHandle(hWrite);
        WaitForSingleObject(pi.hProcess, 60000);
        DWORD ec = 0;
        GetExitCodeProcess(pi.hProcess, &ec);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);

        char buf[65536]{};
        DWORD rd = 0;
        std::string output;
        while (ReadFile(hRead, buf, sizeof(buf), &rd, nullptr) && rd > 0) output.append(buf, rd);
        CloseHandle(hRead);

        if (ec == 1 || output.find("FOUND") != std::string::npos) {
            r.is_infected = true;
            r.confidence = 1.0;
            r.severity = "High";
            r.threat_type = "Virus";
            // 提取威胁名
            size_t pos = output.find("FOUND");
            if (pos != std::string::npos) {
                size_t line = output.rfind('\n', pos);
                size_t colon = output.find(':', pos);
                size_t slash = output.rfind('/', colon);
                if (slash != std::string::npos && colon != std::string::npos)
                    r.threat_name = output.substr(slash + 1, colon - slash - 1);
            }
            r.additional_info = output.substr(0, 200);
        } else {
            r.detection_method = "ClamAV.Clean";
        }
    }
#endif
    return r;
}

ClamAVManager::EngineInfo ClamAVManager::GetInfo() {
    EngineInfo info;
    if (Initialize()) {
        info.available = true;
        info.db_path = db_path_;
        // 简化: 遍历 db_path 下的文件数作为特征数
        if (Helper::DirectoryExists(db_path_)) {
            size_t cnt = 0;
            for (auto& e : std::filesystem::directory_iterator(db_path_))
                if (e.is_regular_file()) cnt++;
            info.signature_count = cnt;
        }
        info.version = "0.103.x";
    }
    return info;
}

bool ClamAVManager::UpdateDatabase() {
#if defined(_WIN32)
    std::string freshclam;
    for (auto& dir : {Helper::GetDirectory(clamscan_path_), ".", "ClamAV"}) {
        std::string p = dir + "\\freshclam.exe";
        if (Helper::FileExists(p)) { freshclam = p; break; }
    }
    if (freshclam.empty()) return false;

    std::string cmd = "\"" + freshclam + "\"";
    STARTUPINFOA si{}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    std::vector<char> cb(cmd.begin(), cmd.end()); cb.push_back('\0');
    if (CreateProcessA(nullptr, cb.data(), nullptr, nullptr, FALSE,
                       CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 120000);
        DWORD ec = 0; GetExitCodeProcess(pi.hProcess, &ec);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        return ec == 0;
    }
#endif
    return false;
}

} // namespace ClamAV

// ==================== CloudAV ====================

namespace CloudAV {

bool CloudAVManager::Initialize() {
    if (Engine::SignatureDatabase::Instance().IsLoaded()) return true;
    Engine::SignatureDatabase::Instance().Initialize();
    return true;
}

CloudAVManager::CloudResult CloudAVManager::QueryHash(const std::string& sha256) {
    CloudResult r; r.detection_method = "Local-SigDB";
    std::string name;
    if (Engine::SignatureDatabase::Instance().TryGetHashThreat(sha256, name)) {
        r.is_malicious = true;
        r.name = name;
        r.confidence = 0.9;
        r.vendor_results["EmbeddedDB"] = 1;
    }
    // 并行云查询 (简化)
    auto f = std::async(std::launch::async, [&]{
        Network::HttpClient client;
        client.SetTimeout(10);
        if (mb_enabled_) {
            auto resp = client.PostMultipart("https://mb-api.abuse.ch/api/v1/", "query", "get_info");
            (void)resp;
        }
        if (!vt_key_.empty()) {
            client.SetHeader("x-apikey", vt_key_);
            auto resp = client.Get("https://www.virustotal.com/api/v3/files/" + sha256);
            (void)resp;
        }
    });
    f.wait_for(std::chrono::seconds(8));
    return r;
}

CloudAVManager::CloudResult CloudAVManager::QueryFile(const std::string& path) {
    std::string sha = Helper::ComputeFileSha256(path);
    if (sha.empty()) return {};
    return QueryHash(sha);
}

} // namespace CloudAV

} // namespace FireAntivirus
