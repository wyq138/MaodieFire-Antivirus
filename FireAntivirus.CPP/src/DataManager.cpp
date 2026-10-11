// FireAntivirus.CPP - DataManager 实现
#include "FireAntivirus/DataManager.h"
#include "FireAntivirus/Platform/Windows.h"
#include "FireAntivirus/LogHelper.h"
#include <algorithm>
#include <filesystem>

namespace FireAntivirus {
namespace Data {

DataManager& DataManager::Instance() {
    static DataManager inst;
    return inst;
}

DataManager::DataManager() {
#if defined(_WIN32)
    std::string local_appdata = Platform::GetLocalAppDataDir();
    config_dir_    = local_appdata + "\\FireAntivirus";
    quarantine_dir_= config_dir_ + "\\Quarantine";
    log_file_      = config_dir_ + "\\service.log";
    whitelist_file_= config_dir_ + "\\whitelist.txt";
#else
    config_dir_ = "FireAntivirus";
    quarantine_dir_ = config_dir_ + "/Quarantine";
    log_file_   = config_dir_ + "/service.log";
    whitelist_file_ = config_dir_ + "/whitelist.txt";
#endif
    EnsureDirs();

    // 预加载可信进程
    static const std::vector<std::string> kTrusted = {
        "explorer.exe","csrss.exe","wininit.exe","services.exe","lsass.exe",
        "smss.exe","svchost.exe","runtimebroker.exe","dwm.exe","winlogon.exe",
        "firewall.exe","taskhostex.exe","taskeng.exe","searchhost.exe"
    };
    for (auto& n : kTrusted) trusted_procs_.insert(Helper::ToLower(n));
}

void DataManager::EnsureDirs() {
    Helper::DirectoryCreate(config_dir_);
    Helper::DirectoryCreate(quarantine_dir_);
    // 加载已有白名单
    if (Helper::FileExists(whitelist_file_)) {
        std::string raw = Helper::ReadFileAllText(whitelist_file_);
        size_t pos = 0;
        while ((pos = raw.find_first_not_of("\r\n", pos)) != std::string::npos) {
            size_t end = raw.find_first_of("\r\n", pos);
            if (end == std::string::npos) end = raw.size();
            whitelist_.insert(raw.substr(pos, end - pos));
            pos = end;
        }
    }
}

bool DataManager::AddWhitelist(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    whitelist_.insert(path);
    return true;
}
bool DataManager::RemoveWhitelist(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    whitelist_.erase(path);
    return true;
}
bool DataManager::IsWhitelisted(const std::string& path) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return whitelist_.count(path) != 0;
}

bool DataManager::IsTrustedProcess(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return trusted_procs_.count(Helper::ToLower(name)) != 0;
}
bool DataManager::CanTerminateProcess(const std::string& name) const {
    // 与原 C# TrustedProcessGuard.CanTerminate 语义一致:
    // true=可以终止
    return !IsTrustedProcess(name);
}

bool DataManager::Quarantine(const std::string& src, const std::string& reason) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string name = Helper::GetFileName(src);
    std::string dest = quarantine_dir_ + "\\" + name + "." +
                       std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".quar";
    try {
        std::filesystem::copy(src, dest, std::filesystem::copy_options::overwrite_existing);
        std::filesystem::remove(src);
        FireAntivirus::LogHelper::Info("Quarantine", "隔离 " + src + " -> " + dest + " (" + reason + ")");
        return true;
    } catch (std::exception& e) {
        FireAntivirus::LogHelper::Error("Quarantine", "隔离失败: " + std::string(e.what()));
        return false;
    }
}

bool DataManager::RestoreFromQuarantine(const std::string& quar_path) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::filesystem::path p(quar_path);
    std::string dest = quarantine_dir_ + "\\..\\" + p.stem().string();
    try {
        std::filesystem::copy(quar_path, dest, std::filesystem::copy_options::overwrite_existing);
        std::filesystem::remove(quar_path);
        return true;
    } catch (...) { return false; }
}

bool DataManager::DeleteQuarantine(const std::string& quar_path) {
    std::lock_guard<std::mutex> lock(mutex_);
    try { std::filesystem::remove(quar_path); return true; } catch (...) { return false; }
}

std::vector<std::string> DataManager::ListQuarantine() const {
    std::vector<std::string> out;
    std::error_code ec;
    for (auto& e : std::filesystem::directory_iterator(quarantine_dir_, ec)) {
        out.push_back(e.path().string());
    }
    return out;
}

} // namespace Data
} // namespace FireAntivirus
