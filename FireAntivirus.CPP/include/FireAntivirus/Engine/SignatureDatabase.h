// FireAntivirus.CPP - 签名数据库 (Hash/URL/IP)
// 移植自 FireAntivirus.Engine.SignatureDatabaseUpdater
// 存储本地已持久化的恶意特征,同时支持实时查询 VirusTotal / MalwareBazaar / OTX 返回的数据
#pragma once

#include "FireAntivirus/Types.h"
#include "FireAntivirus/Helper.h"

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <chrono>
#include <atomic>
#include <vector>

namespace FireAntivirus {
namespace Engine {

/// <summary>自动更新签名数据库 (等价于原 C# SignatureDatabaseUpdater)</summary>
class SignatureDatabase {
public:
    static SignatureDatabase& Instance();

    bool Initialize();
    bool TryGetHashThreat(const std::string& sha256, std::string& out_threat_name) const;

    // URL / IP / Domain 黑名单 (与原 ExternalThreatData 同功能)
    bool IsUrlBlacklisted(const std::string& url) const;
    bool IsIpBlacklisted (const std::string& ip)  const;
    bool IsDomainBlacklisted(const std::string& domain) const;

    // 基础 API
    size_t HashCount() const { return hash_map_.size(); }
    size_t UrlCount()  const { return url_set_.size(); }
    size_t IpCount()   const { return ip_set_.size(); }
    bool   IsLoaded()  const { return loaded_.load(); }
    std::chrono::system_clock::time_point LastUpdate() const { return last_update_; }
    const std::string& LastError() const { return last_error_; }

private:
    SignatureDatabase();
    ~SignatureDatabase();

    // 从 JSON ThreatData 文件加载
    void LoadFromEmbeddedData();
    void LoadFromFile(const std::string& json_path);

    mutable std::mutex mutex_;
    std::unordered_map<std::string, std::string> hash_map_;   // sha256 -> threat_name
    std::unordered_set<std::string> url_set_;
    std::unordered_set<std::string> ip_set_;
    std::unordered_set<std::string> domain_set_;

    std::atomic<bool> loaded_{false};
    std::chrono::system_clock::time_point last_update_;
    std::string last_error_;
};

/// <summary>对外别名,保持与原 C# 一致</summary>
using SignatureDatabaseUpdater = SignatureDatabase;

} // namespace Engine
} // namespace FireAntivirus
