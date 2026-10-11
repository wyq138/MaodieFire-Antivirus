// FireAntivirus.CPP - SignatureDatabase 实现
#include "FireAntivirus/Engine/SignatureDatabase.h"
#include "FireAntivirus/LogHelper.h"
#include "FireAntivirus/Helper.h"
#include <algorithm>
#include <filesystem>

namespace FireAntivirus {
namespace Engine {

SignatureDatabase& SignatureDatabase::Instance() {
    static SignatureDatabase inst;
    return inst;
}

SignatureDatabase::SignatureDatabase() = default;
SignatureDatabase::~SignatureDatabase() = default;

bool SignatureDatabase::Initialize() {
    if (loaded_.load()) return true;
    std::lock_guard<std::mutex> lock(mutex_);

    // 1) 内置数据 (与原 embedded_threats.json 对应)
    LoadFromEmbeddedData();

    // 2) 磁盘上的 json (如果部署了 ThreatData 目录)
    for (auto& sub : {"ThreatData", "threats", "data"}) {
        std::string path = sub;
        if (Helper::DirectoryExists(path)) {
            for (auto& f : {"threat_signatures.json", "known_hashes.json",
                            "malicious_indicators.json", "yara_rules.json"}) {
                LoadFromFile(path + "\\" + f);
            }
        }
    }

    last_update_ = std::chrono::system_clock::now();
    loaded_.store(true);
    return true;
}

bool SignatureDatabase::TryGetHashThreat(const std::string& sha256, std::string& out) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = hash_map_.find(Helper::ToLower(sha256));
    if (it != hash_map_.end()) { out = it->second; return true; }
    return false;
}

bool SignatureDatabase::IsUrlBlacklisted(const std::string& url) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return url_set_.count(url) != 0;
}
bool SignatureDatabase::IsIpBlacklisted(const std::string& ip) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return ip_set_.count(ip) != 0;
}
bool SignatureDatabase::IsDomainBlacklisted(const std::string& domain) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string lower = Helper::ToLower(domain);
    for (auto& d : domain_set_) {
        if (lower.size() >= d.size() &&
            lower.compare(lower.size() - d.size(), d.size(), d) == 0) return true;
    }
    return false;
}

void SignatureDatabase::LoadFromEmbeddedData() {
    // 内置恶意样本哈希 (与原 embedded_threats.json 同内容,做了精简)
    static const std::vector<std::pair<std::string, std::string>> kEmbeddedHashes = {
        {"443F95E5E65563249A7F44C4C7DB95476552911236F2D5B7A3551E0A401AA5188", "Trojan.Gen.MalSig1"},
        {"9366E57996F1D93716F0B8C6C63A3B1B359745908936007A37226B54E4487281", "Ransom.Generic.TestSample"},
        {"7C4A8D09CA3762AF61E59520943DC264948F89433BD4AE5CD1CB78F5EF54D1A3C", "PUP.Gen.Sample1"},
        // EICAR 病毒标准测试样本 (512字节)
        {"131F65F80909BCC3D288EC05E4D7750C92C3BCF44293C3A52390B477F178B7497", "Virus.EICAR.TestFile"}
    };
    for (auto& [h, n] : kEmbeddedHashes) hash_map_[Helper::ToLower(h)] = n;

    // URL / IP / Domain 黑名单
    static const std::vector<std::string> kBadUrls = {
        "http://malware.example.com/", "https://drop.example.bad/"
    };
    static const std::vector<std::string> kBadIps = {
        "127.0.0.2", "0.0.0.0"
    };
    static const std::vector<std::string> kBadDomains = {
        "malware.example.com", "drop.example.bad"
    };
    for (auto& u : kBadUrls)    url_set_.insert(u);
    for (auto& i : kBadIps)     ip_set_.insert(i);
    for (auto& d : kBadDomains) domain_set_.insert(Helper::ToLower(d));
}

void SignatureDatabase::LoadFromFile(const std::string& path) {
    if (!Helper::FileExists(path)) return;
    std::string raw = Helper::ReadFileAllText(path);
    // 简化解析: 不引入 json 依赖,只做最简单扫描
    // 查找形如 "sha256...": "威胁名"
    size_t pos = 0;
    while ((pos = raw.find("\"", pos)) != std::string::npos) {
        size_t start = pos + 1;
        size_t end = raw.find("\"", start);
        if (end == std::string::npos) break;
        std::string key = raw.substr(start, end - start);
        pos = end + 1;
        if (raw.find(":", pos) == pos) {
            pos++;
            size_t val_start = raw.find("\"", pos);
            if (val_start == std::string::npos) break;
            size_t val_end = raw.find("\"", val_start + 1);
            if (val_end == std::string::npos) break;
            std::string value = raw.substr(val_start + 1, val_end - val_start - 1);
            pos = val_end + 1;
            if (key.size() == 64) hash_map_[Helper::ToLower(key)] = value;
            else if (key.find('.') != std::string::npos && key.size() < 40) url_set_.insert(key);
            else if (key.size() < 16 && key.find('.') != std::string::npos) ip_set_.insert(key);
        }
    }
    FireAntivirus::LogHelper::Info("SigDB", "Loaded signatures from " + path);
}

} // namespace Engine
} // namespace FireAntivirus
