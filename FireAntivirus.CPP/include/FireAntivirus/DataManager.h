// FireAntivirus.CPP - DataManager (白名单 / 隔离区)
// 移植自 FireAntivirus.Data.DataManager + Common.Helper.TrustedProcessGuard
#pragma once

#include "FireAntivirus/Types.h"
#include <string>
#include <vector>
#include <mutex>
#include <unordered_set>

namespace FireAntivirus {
namespace Data {

class DataManager {
public:
    static DataManager& Instance();

    // 白名单: 文件路径
    bool AddWhitelist(const std::string& path);
    bool RemoveWhitelist(const std::string& path);
    bool IsWhitelisted(const std::string& path) const;

    // 可信进程 (反杀保护)
    bool IsTrustedProcess(const std::string& process_name) const;
    bool CanTerminateProcess(const std::string& process_name) const;

    // 隔离区
    bool Quarantine(const std::string& source_path, const std::string& reason = "");
    bool RestoreFromQuarantine(const std::string& quar_path);
    bool DeleteQuarantine(const std::string& quar_path);
    std::vector<std::string> ListQuarantine() const;

    // 路径
    std::string QuarantineDir() const { return quarantine_dir_; }
    std::string ConfigDir()     const { return config_dir_; }
    std::string LogFile()       const { return log_file_; }

private:
    DataManager();
    void EnsureDirs();

    mutable std::mutex mutex_;
    std::unordered_set<std::string> whitelist_;
    std::unordered_set<std::string> trusted_procs_;

    std::string config_dir_;
    std::string quarantine_dir_;
    std::string log_file_;
    std::string whitelist_file_;
};

} // namespace Data

namespace Common {
    /// <summary>与 C# 版完全等价的可信进程守卫</summary>
    inline bool CanTerminateProcess(const std::string& name) {
        return !Data::DataManager::Instance().CanTerminateProcess(name);
    }
    inline bool IsTrustedProcess(const std::string& name) {
        return Data::DataManager::Instance().IsTrustedProcess(name);
    }
}

} // namespace FireAntivirus
