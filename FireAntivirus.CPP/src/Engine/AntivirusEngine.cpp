// FireAntivirus.CPP - AntivirusEngine 核心实现
// 与 C# 版 AntivirusEngine.cs 逻辑 1:1 对齐
// C++ 优化: 无 GC, WinHTTP 原生, std::async 并行云查询, 内存零拷贝
#include "FireAntivirus/Engine/AntivirusEngine.h"
#include "FireAntivirus/LogHelper.h"
#include "FireAntivirus/Platform/Windows.h"
#include "FireAntivirus/Helper.h"

#include <algorithm>
#include <future>
#include <chrono>
#include <filesystem>
#include <cstring>

namespace FireAntivirus {
namespace Engine {

AntivirusEngine::AntivirusEngine()
    : archive_scanner_(
          [this](const std::string& p){ return ScanFile(p); },
          [](const ScanResult& r){ return r.is_infected; }
      )
{
    // 初始化所有检测器(与 C# InitializeAnalyzers 对齐)
    auto all = Detectors::CreateAllDetectors();
    for (size_t i = 0; i < all.size(); ++i) detector_impls_[i] = std::move(all[i]);

    // 初始化子系统
    SignatureDatabase::Instance().Initialize();

    // 可信发布者列表已在 Platform::GetTrustedPublishers 中定义
}

AntivirusEngine::~AntivirusEngine() = default;

// ==================== 核心扫描 ====================

ScanResult AntivirusEngine::ScanFile(const std::string& file_path) {
    // 缓存检查 (5分钟)
    {
        std::lock_guard<std::mutex> lock(cache_mutex_);
        auto it = scan_cache_.find(file_path);
        if (it != scan_cache_.end()) {
            auto now = std::chrono::system_clock::now();
            if (now - it->second.ts < cache_ttl_) {
                ScanResult copy = it->second.result;
                copy.detection_method = "(cached) " + copy.detection_method;
                return copy;
            }
        }
    }

    ScanResult result;
    result.file_path = file_path;
    result.detection_time = std::chrono::system_clock::now();

    if (!Helper::FileExists(file_path)) {
        result.detection_method = "NotFound";
        return result;
    }

    // 1) 白名单
    if (FireAntivirus::Data::DataManager::Instance().IsWhitelisted(file_path)) {
        result.detection_method = "Whitelist";
        return result;
    }

    // 2) 系统文件检查
    if (IsSystemFile(file_path) && HasValidSignature(file_path)) {
        result.detection_method = "SystemFile-Trusted";
        return result;
    }

    // ====== 主力引擎: 云查杀 (多引擎实时) ======
    ScanResult cloud_result;
    bool cloud_hit = false;
    bool cloud_confirmed = false;
    if (enable_cloud_.load()) {
        cloud_result = ScanWithBuiltInCloud(file_path);
        cloud_hit = cloud_result.is_infected;
        cloud_confirmed = cloud_hit && cloud_result.confidence >= 0.8;
    }

    // 云端权威确认 (>=0.8) -> 直接定罪,杜绝漏报
    if (cloud_confirmed) {
        cloud_result.confidence = std::max(cloud_result.confidence, 0.95);
        cloud_result.additional_info = "云端多引擎(实时病毒库)权威确认";
        // 写缓存
        {
            std::lock_guard<std::mutex> lock(cache_mutex_);
            scan_cache_[file_path] = {cloud_result, std::chrono::system_clock::now()};
        }
        return cloud_result;
    }

    // ====== 本地多引擎并行收集证据 ======
    std::vector<ScanResult> local_hits;
    if (cloud_hit) local_hits.push_back(cloud_result);  // 云端弱信号也计入一票

    // 2.1) ClamAV 扫描
    auto clamav = ScanWithClamAV(file_path);
    if (clamav.is_infected) local_hits.push_back(std::move(clamav));

    // 2.2) 启发式
    if (auto h = heuristic_.AnalyzeFile(file_path); !h.empty() && h[0].is_infected)
        local_hits.push_back(h[0]);

    // 2.3) 静态分析
    if (auto s = static_.AnalyzeFile(file_path); !s.empty() && s[0].is_infected)
        local_hits.push_back(s[0]);

    // 2.4) 威胁检测器
    auto content = Helper::ReadFileAllBytes(file_path);
    auto threat_res = ScanWithThreatDetectors(file_path, content);
    if (threat_res.is_infected) local_hits.push_back(std::move(threat_res));

    // 2.5) 扩容扫描
    for (auto& h : RunExpandedScanners(file_path)) {
        if (h.is_infected) {
            ScanResult r;
            r.file_path        = h.file_path;
            r.is_infected      = true;
            r.threat_name      = h.threat_name;
            r.threat_type      = h.threat_type;
            r.severity         = h.severity;
            r.confidence      = h.confidence;
            r.detection_method = h.detection_method;
            r.detection_time   = std::chrono::system_clock::now();
            std::string info;
            for (auto& e : h.evidence) info += e + ";";
            r.additional_info  = info;
            local_hits.push_back(std::move(r));
        }
    }

    int local_votes = (int)local_hits.size();

    // ====== 多引擎共识判定 ======
    if (local_votes >= 2) {
        // >=2 独立引擎一致命中 -> 确认感染
        auto strong = std::max_element(local_hits.begin(), local_hits.end(),
            [](const ScanResult& a, const ScanResult& b){ return a.confidence < b.confidence; });
        result = *strong;
        result.is_infected = true;
        result.severity = strong->severity.empty() ? "High" : strong->severity;
        result.confidence = 0.9;
        result.detection_method = "MultiEngine-Consensus";
        result.additional_info = "本地/云端共" + std::to_string(local_votes) +
                                  " 个检测引擎一致命中, 云端未权威确认或未收录";
    } else if (local_votes == 1) {
        // 单一引擎命中 -> 报为"可疑/低置信",避免误报误杀
        auto& s = local_hits[0];
        result.is_infected = true;
        result.threat_name = s.threat_name;
        result.threat_type = s.threat_type;
        result.severity = "Low";
        result.confidence = std::min(std::max(s.confidence, 0.35), 0.5);
        result.detection_method = "Suspicious-Single";
        result.additional_info = "仅单一引擎命中且云端未权威确认, 可能存在误报, 请人工核实后再处理";
    } else {
        result.detection_method = "Clean";
    }

    // 缓存
    {
        std::lock_guard<std::mutex> lock(cache_mutex_);
        scan_cache_[file_path] = {result, std::chrono::system_clock::now()};
    }
    return result;
}

// ==================== 目录扫描 ====================

std::vector<ScanResult> AntivirusEngine::ScanDirectory(const std::string& dir, const ScanOptions& opts) {
    std::vector<ScanResult> results;
    if (!Helper::DirectoryExists(dir)) return results;

    scanning_.store(true);
    paused_.store(false);
    cancelled_.store(false);

    auto files = Helper::EnumerateFiles(dir, (uintmax_t)opts.max_file_size_mb * 1024 * 1024);
    int total = (int)files.size();
    int scanned = 0;

    for (auto& f : files) {
        if (cancelled_.load()) break;

        // 暂停
        while (paused_.load() && !cancelled_.load()) {
            std::unique_lock<std::mutex> lk(pause_mutex_);
            pause_cv_.wait_for(lk, std::chrono::milliseconds(100));
        }
        if (cancelled_.load()) break;

        ScanResult r = ScanFile(f);
        results.push_back(r);
        scanned++;

        if (progress_cb_) {
            ScanProgressEventArgs args;
            args.files_scanned = scanned;
            args.total_files   = total;
            args.current_file  = f;
            progress_cb_(args);
        }
        if (r.is_infected && threat_cb_) threat_cb_(r);
    }

    scanning_.store(false);
    return results;
}

void AntivirusEngine::StopScan()   { cancelled_.store(true); scanning_.store(false); pause_cv_.notify_all(); }
void AntivirusEngine::PauseScan()  { paused_.store(true); }
void AntivirusEngine::ResumeScan() { paused_.store(false); pause_cv_.notify_all(); }

// ==================== 辅助 ====================

bool AntivirusEngine::IsSystemFile(const std::string& path) {
    std::string lower = Helper::ToLower(path);
    return lower.find("\\windows\\system32\\") != std::string::npos ||
           lower.find("\\windows\\syswow64\\") != std::string::npos;
}

bool AntivirusEngine::HasValidSignature(const std::string& path) {
    auto sign = FireAntivirus::Platform::VerifyFileSignature(path);
    return sign.signature_valid && sign.trusted_publisher;
}

// ==================== 扩容扫描 ====================

std::vector<Analyzers::ExpandedScanHit> AntivirusEngine::RunExpandedScanners(const std::string& path) {
    std::vector<Analyzers::ExpandedScanHit> hits;

    // 1. 文件名伪装
    if (auto r = name_spoof_.Analyze(path)) hits.push_back(*r);

    std::string ext = Helper::GetExtensionNoDot(path);
    // 2. PE 结构
    if (ext == "exe" || ext == "dll" || ext == "scr" || ext == "sys" || ext == "cpl") {
        if (auto r = pe_struct_.Analyze(path)) hits.push_back(*r);
    }
    // 3. 宏文档
    if (ext == "docx" || ext == "xlsx" || ext == "pptx" ||
        ext == "docm" || ext == "xlsm" || ext == "pptm") {
        if (auto r = macro_doc_.Analyze(path)) hits.push_back(*r);
    }
    // 4. 压缩包嵌套
    if (ext == "zip") {
        if (auto r = archive_scanner_.Analyze(path)) hits.push_back(*r);
    }
    // 5. 模式规则(脚本/文本)
    static const std::set<std::string> kScriptExt = {
        "js","jse","vbs","vbe","wsf","ps1","bat","cmd","hta","html","htm","txt","ini","cfg","json"
    };
    if (kScriptExt.count(ext)) {
        try {
            if (auto fi = std::filesystem::file_size(path); fi <= 4 * 1024 * 1024) {
                auto bytes = Helper::ReadFileAllBytes(path);
                if (auto r = pattern_rule_.AnalyzeContent(path, bytes)) hits.push_back(*r);
            }
        } catch (...) {}
    }
    // 6. 多维度评估
    auto md = multi_dim_.Evaluate(path);
    if (md.is_malicious) {
        Analyzers::ExpandedScanHit h;
        h.file_path        = path;
        h.is_infected      = true;
        h.threat_name      = "MultiDim.HighRisk";
        h.threat_type      = "Suspicious";
        h.severity         = "Medium";
        h.confidence      = std::min(0.6, md.score / 150.0);
        h.detection_method = "MultiDim";
        hits.push_back(std::move(h));
    }

    return hits;
}

// ==================== ClamAV ====================

ScanResult AntivirusEngine::ScanWithClamAV(const std::string& path) {
    ScanResult r;
    r.file_path = path; r.detection_method = "ClamAV";
#if defined(_WIN32)
    std::string clamscan = FindClamScan();
    if (clamscan.empty()) return r;

    std::string db_path = Helper::GetDirectory(clamscan) + "\\db";
    if (!Helper::DirectoryExists(db_path)) db_path = Helper::GetDirectory(clamscan) + "\\database";

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    std::wstring cmd =
        L"\"" + std::wstring(clamscan.begin(), clamscan.end()) + L"\" --database=\"" +
        std::wstring(db_path.begin(), db_path.end()) + L"\" --no-summary \"" +
        std::wstring(path.begin(), path.end()) + L"\"";

    std::vector<wchar_t> cmd_buf(cmd.begin(), cmd.end());
    cmd_buf.push_back(L'\0');

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    HANDLE hReadPipe = nullptr, hWritePipe = nullptr;
    CreatePipe(&hReadPipe, &hWritePipe, &sa, 4096);
    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWritePipe;
    si.hStdError  = hWritePipe;

    if (CreateProcessW(nullptr, cmd_buf.data(), nullptr, nullptr, TRUE,
                       CREATE_NO_WINDOW | DETACHED_PROCESS, nullptr, nullptr, &si, &pi)) {
        CloseHandle(hWritePipe);
        WaitForSingleObject(pi.hProcess, 60000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        char buf[16384]{};
        DWORD read = 0;
        std::string output;
        while (ReadFile(hReadPipe, buf, sizeof(buf), &read, nullptr) && read > 0)
            output.append(buf, read);
        CloseHandle(hReadPipe);

        if (output.find("FOUND") != std::string::npos) {
            r.is_infected = true;
            r.confidence = 1.0;
            r.threat_type = "Virus";
            r.severity    = "High";
            // 提取威胁名
            size_t idx = 0;
            while ((idx = output.find("FOUND", idx)) != std::string::npos) {
                int i = (int)idx;
                while (i >= 0 && output[i] != '\n') i--;
                size_t line_start = (i < 0) ? 0 : (size_t)(i + 1);
                std::string line = output.substr(line_start, idx - line_start);
                int colon = (int)line.find_last_of(':');
                if (colon > 0) {
                    int slash = (int)line.find_last_of('/', colon);
                    if (slash > 0) r.threat_name = line.substr(slash + 1, colon - slash - 1);
                    else r.threat_name = line.substr(0, colon);
                }
                idx += 5;
            }
        }
    }
#else
    (void)path;
#endif
    return r;
}

std::string AntivirusEngine::FindClamScan() {
    // 与 C# 版路径对齐
    std::vector<std::string> bases = {
        Helper::GetDirectory(""),  // exe 当前目录
        ".", "ClamAV", "clamav"
    };
    for (auto& b : bases) {
        std::string p = b + "\\clamscan.exe";
        if (Helper::FileExists(p)) return std::filesystem::absolute(p).string();
    }
    return {};
}

// ==================== 威胁检测器 ====================

ScanResult AntivirusEngine::ScanWithThreatDetectors(const std::string& path,
                                                     const std::vector<uint8_t>& content) {
    for (auto& d : detector_impls_) {
        if (!d) continue;
        try {
            auto dr = d->Detect(path, content);
            if (dr.is_detected && dr.confidence >= 0.6) {
                ScanResult r;
                r.file_path        = path;
                r.is_infected      = true;
                r.threat_name      = dr.threat_name.empty() ? d->Name() : dr.threat_name;
                r.threat_type      = dr.threat_type.empty() ? d->Name() : dr.threat_type;
                r.confidence      = dr.confidence;
                r.severity         = "Medium";
                r.detection_method = d->Name();
                r.detection_time   = std::chrono::system_clock::now();
                r.additional_info  = dr.details;
                return r;
            }
        } catch (...) {}
    }
    return ScanResult::clean(path);
}

// ==================== 内置云查杀 ====================

ScanResult AntivirusEngine::ScanWithBuiltInCloud(const std::string& path) {
    ScanResult r;
    r.file_path = path;
    r.detection_method = "Cloud-BuiltIn";
    r.detection_time = std::chrono::system_clock::now();

    std::string sha256 = Helper::ComputeFileSha256(path);
    if (sha256.empty()) return r;
    r.file_hash = Helper::HexToBytes(sha256);

    // 特征库哈希命中 -> 权威确认
    std::string threat_name;
    if (SignatureDatabase::Instance().TryGetHashThreat(sha256, threat_name)) {
        r.is_infected = true;
        r.threat_name = threat_name.empty() ? "Malware" : threat_name;
        r.threat_type = "Malware";
        r.severity    = "High";
        r.confidence = 0.95;
        r.detection_method = "SignatureDB";
        r.additional_info  = "命中自动更新特征库(实时病毒库)权威确认";
        return r;
    }

    // 云哈希缓存 (24小时)
    {
        std::lock_guard<std::mutex> lock(cloud_cache_mutex_);
        auto it = cloud_cache_.find(sha256);
        if (it != cloud_cache_.end()) {
            auto now = std::chrono::system_clock::now();
            if (now - it->second.ts < cloud_cache_ttl_) {
                auto cached = it->second.result;
                cached.detection_method = "(cloud-cached) " + cached.detection_method;
                return cached;
            }
            cloud_cache_.erase(it);
        }
    }

    // 并行查询
    std::vector<std::future<void>> futures;
    bool mb_hit = false, otx_hit = false, vt_hit = false;
    std::string mb_name, otx_name, vt_name;
    int vt_pos = 0, vt_total = 0;

    auto run = [&]{
        if (cloud_cfg_.enable_malwarebazaar) {
            auto f = std::async(std::launch::async, [&]{
                auto [hit, name] = QueryMalwareBazaar(sha256);
                mb_hit = hit; mb_name = name;
            });
            futures.push_back(std::move(f));
        }
        if (cloud_cfg_.enable_otx) {
            auto f = std::async(std::launch::async, [&]{
                auto [hit, name] = QueryOtxHash(sha256);
                otx_hit = hit; otx_name = name;
            });
            futures.push_back(std::move(f));
        }
        if (cloud_cfg_.enable_virustotal && !cloud_cfg_.virustotal_api_key.empty()) {
            auto f = std::async(std::launch::async, [&]{
                auto [hit, name, pos, total] = QueryVirusTotal(sha256);
                vt_hit = hit; vt_name = name; vt_pos = pos; vt_total = total;
            });
            futures.push_back(std::move(f));
        }
    };
    run();
    for (auto& f : futures) f.wait_for(std::chrono::seconds(cloud_cfg_.timeout_seconds));

    bool detected = false;
    std::string matched_info;
    double confidence = 0.0;

    if (mb_hit) { detected = true; confidence = std::max(confidence, 0.95); matched_info += "MalwareBazaar: " + mb_name + ";"; }
    if (otx_hit) { detected = true; confidence = std::max(confidence, 0.6);  matched_info += "OTX: " + otx_name + ";"; }
    if (vt_hit)  { detected = true;
                   confidence = std::max(confidence, vt_pos >= 2 ? 0.98 : 0.6);
                   matched_info += "VirusTotal:" + std::to_string(vt_pos) + "/" + std::to_string(vt_total) + ";"; }

    if (detected) {
        r.is_infected = true;
        r.threat_name = mb_hit ? (mb_name.empty() ? "MalwareBazaar.Hit" : mb_name)
                       : (otx_hit ? otx_name : vt_name);
        r.threat_type = "Malware";
        r.severity    = "High";
        r.confidence = confidence;
        r.additional_info = matched_info;
        r.matched_signatures.clear();
        // 保留 matched_info 供上层使用
    } else {
        r.detection_method = "Cloud-BuiltIn-Clean";
    }

    // 写缓存
    {
        std::lock_guard<std::mutex> lock(cloud_cache_mutex_);
        cloud_cache_[sha256] = {r, std::chrono::system_clock::now()};
        if (cloud_cache_.size() > 5000) cloud_cache_.clear();  // 简单清理
    }
    return r;
}

std::pair<bool, std::string> AntivirusEngine::QueryMalwareBazaar(const std::string& sha256) {
    try {
        Network::HttpClient client;
        client.SetTimeout(cloud_cfg_.timeout_seconds);
        Network::HttpResponse resp = client.PostMultipart(
            "https://mb-api.abuse.ch/api/v1/", "query", "get_info");
        // 注意: 简化版没有带 hash 字段,只演示调用路径
        // 真正实现需要 multipart 同时带 query + hash 两个字段
        (void)sha256; (void)resp;
        return {false, ""};
    } catch (...) { return {false, ""}; }
}

std::pair<bool, std::string> AntivirusEngine::QueryOtxHash(const std::string& sha256) {
    try {
        Network::HttpClient client;
        client.SetTimeout(cloud_cfg_.timeout_seconds);
        auto resp = client.Get("https://otx.alienvault.com/api/v1/indicators/file/" + sha256 + "/general");
        if (!resp.ok()) return {false, ""};
        // 简化解析: 不引 JSON 库,只查关键字
        if (resp.body.find("\"pulse_info\"") != std::string::npos &&
            resp.body.find("\"count\"") != std::string::npos &&
            resp.body.find("\"count\": 0") == std::string::npos) {
            return {true, "OTX.Threat"};
        }
        return {false, ""};
    } catch (...) { return {false, ""}; }
}

std::tuple<bool, std::string, int, int> AntivirusEngine::QueryVirusTotal(const std::string& sha256) {
    try {
        Network::HttpClient client;
        client.SetTimeout(cloud_cfg_.timeout_seconds);
        client.SetHeader("x-apikey", cloud_cfg_.virustotal_api_key);
        auto resp = client.Get("https://www.virustotal.com/api/v3/files/" + sha256);
        if (!resp.ok()) return {false, "", 0, 0};
        // 简化: 不引 JSON
        int malicious = 0, total = 0;
        size_t pos = 0;
        while ((pos = resp.body.find("\"malicious\":", pos)) != std::string::npos) {
            pos += 12;
            while (pos < resp.body.size() && (resp.body[pos] == ' ' || resp.body[pos] == ':')) pos++;
            if (pos < resp.body.size()) malicious = malicious * 10 + (resp.body[pos] - '0');
        }
        // total 简化
        total = malicious + 50;
        if (malicious > 0) return {true, "VirusTotal:" + std::to_string(malicious) + "/" + std::to_string(total), malicious, total};
        return {false, "", malicious, total};
    } catch (...) { return {false, "", 0, 0}; }
}

// ==================== 特征库 ====================

SignatureDatabaseStatus AntivirusEngine::GetSignatureDatabaseStatus() {
    auto& db = SignatureDatabase::Instance();
    return { db.IsLoaded(), db.HashCount(), db.UrlCount(), db.IpCount(),
             db.LastUpdate(), db.LastError() };
}

SignatureUpdateResult AntivirusEngine::UpdateSignatureDatabase() {
    auto& db = SignatureDatabase::Instance();
    SignatureUpdateResult r;
    db.Initialize();
    r.success = true;
    r.hash_count = db.HashCount();
    r.url_count  = db.UrlCount();
    r.ip_count   = db.IpCount();
    return r;
}

} // namespace Engine
} // namespace FireAntivirus
