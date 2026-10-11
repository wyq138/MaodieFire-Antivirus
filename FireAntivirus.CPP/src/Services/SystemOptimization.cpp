// 移植自 FireAntivirus.Services.SystemOptimization (C#)
// 实现: 1:1 对齐 _cs_extract/SystemOptimization.cs

#include "FireAntivirus/Services/SystemOptimization.h"
#include "FireAntivirus/LogHelper.h"

#include <windows.h>
#include <shellapi.h>
#include <psapi.h>
#include <iphlpapi.h>

#include <algorithm>

namespace fs = std::filesystem;

namespace FireAntivirus { namespace Services {

// 占位 - 实现见下方追加

// ==================== 工具函数 ====================

std::string SystemOptimization::NowTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
    localtime_s(&tm, &t);
    char buf[32]{};
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm);
    return buf;
}

std::string SystemOptimization::DurationSince(const std::chrono::steady_clock::time_point& start) {
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count();
    return std::to_string(ms) + "ms";
}

std::string SystemOptimization::GetSystemTempDirectory() {
    wchar_t buf[MAX_PATH]{};
    DWORD len = GetTempPathW(MAX_PATH, buf);
    if (len == 0 || len >= MAX_PATH) return "C:\\Temp";
    std::string out;
    int n = WideCharToMultiByte(CP_UTF8, 0, buf, -1, nullptr, 0, nullptr, nullptr);
    if (n > 0) { out.resize(n - 1); WideCharToMultiByte(CP_UTF8, 0, buf, -1, out.data(), n, nullptr, nullptr); }
    return out;
}

std::string SystemOptimization::GetDefaultLogDirectory() {
    wchar_t buf[MAX_PATH]{};
    if (GetEnvironmentVariableW(L"ProgramData", buf, MAX_PATH) == 0) return "C:\\ProgramData\\FireAntivirus\\Logs";
    std::wstring w = buf;
    w += L"\\FireAntivirus\\Logs";
    std::string out;
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (n > 0) { out.resize(n - 1); WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, out.data(), n, nullptr, nullptr); }
    return out;
}

void SystemOptimization::EnsureDirectory(const std::string& path) {
    if (!path.empty()) {
        std::error_code ec;
        fs::create_directories(path, ec);
    }
}

HealthStatus SystemOptimization::ScoreToStatus(double percent, double warn, double crit) {
    if (percent >= crit) return HealthStatus::Critical;
    if (percent >= warn) return HealthStatus::Warning;
    return HealthStatus::Good;
}

// ==================== 构造函数 ====================

SystemOptimization::SystemOptimization(const std::string& tempDirectory,
                                       const std::string& logDirectory,
                                       int maxFileAgeDays,
                                       long long maxLogSizeBytes)
    : _tempDirectory(tempDirectory.empty() ? GetSystemTempDirectory() : tempDirectory)
    , _logDirectory(logDirectory.empty() ? GetDefaultLogDirectory() : logDirectory)
    , _maxFileAgeDays(maxFileAgeDays)
    , _maxLogSizeBytes(maxLogSizeBytes) {
    EnsureDirectory(_logDirectory);
}

// === PLACEHOLDER_PART2 ===

// ==================== CleanupSystem ====================

SystemCleanupResult SystemOptimization::CleanupSystem(const SystemCleanupOptions& options) {
    auto start = std::chrono::steady_clock::now();
    SystemCleanupResult result;
    result.StartTime = NowTimestamp();
    try {
        if (options.CleanTempFiles) {
            auto r = CleanupTempFiles();
            result.CleanedItems.insert(result.CleanedItems.end(), r.CleanedItems.begin(), r.CleanedItems.end());
            result.FreedSpaceBytes += r.FreedSpaceBytes;
        }
        if (options.CleanLogFiles) {
            auto r = CleanupLogFiles();
            result.CleanedItems.insert(result.CleanedItems.end(), r.CleanedItems.begin(), r.CleanedItems.end());
            result.FreedSpaceBytes += r.FreedSpaceBytes;
        }
        if (options.CleanBrowserCache) {
            auto r = CleanupBrowserCache();
            result.CleanedItems.insert(result.CleanedItems.end(), r.CleanedItems.begin(), r.CleanedItems.end());
            result.FreedSpaceBytes += r.FreedSpaceBytes;
        }
        if (options.CleanRecycleBin) {
            auto r = CleanupRecycleBin();
            result.CleanedItems.insert(result.CleanedItems.end(), r.CleanedItems.begin(), r.CleanedItems.end());
            result.FreedSpaceBytes += r.FreedSpaceBytes;
        }
        if (options.CleanTemporaryInternetFiles) {
            auto r = CleanupTemporaryInternetFiles();
            result.CleanedItems.insert(result.CleanedItems.end(), r.CleanedItems.begin(), r.CleanedItems.end());
            result.FreedSpaceBytes += r.FreedSpaceBytes;
        }
        result.Success = true;
    } catch (const std::exception& ex) {
        Logger::Error(std::string("System cleanup error: ") + ex.what());
        result.Success = false;
        result.ErrorMessage = ex.what();
    }
    result.EndTime = NowTimestamp();
    result.DurationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count();
    return result;
}

// === PLACEHOLDER_PART3 ===

SystemCleanupResult SystemOptimization::CleanupTempFiles() {
    auto start = std::chrono::steady_clock::now();
    SystemCleanupResult result;
    result.StartTime = NowTimestamp();
    try {
        auto cutoff = std::chrono::system_clock::now() - std::chrono::hours(24) * _maxFileAgeDays;
        auto cutoffTime = fs::file_time_type(cutoff);
        for (auto& entry : fs::recursive_directory_iterator(_tempDirectory, fs::directory_options::skip_permission_denied)) {
            if (!entry.is_regular_file()) continue;
            std::error_code ec;
            auto lwt = entry.last_write_time(ec);
            if (ec) continue;
            if (lwt < cutoffTime) {
                auto size = fs::file_size(entry, ec);
                if (ec) size = 0;
                fs::remove(entry.path(), ec);
                if (!ec) {
                    CleanedItem item;
                    item.Path = entry.path().string();
                    item.SizeBytes = static_cast<long long>(size);
                    item.Type = CleanedItemType::TempFile;
                    result.CleanedItems.push_back(std::move(item));
                    result.FreedSpaceBytes += static_cast<long long>(size);
                }
            }
        }
        result.Success = true;
    } catch (const std::exception& ex) {
        Logger::Error(std::string("Temp files cleanup error: ") + ex.what());
        result.Success = false;
        result.ErrorMessage = ex.what();
    }
    result.EndTime = NowTimestamp();
    result.DurationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count();
    return result;
}

SystemCleanupResult SystemOptimization::CleanupLogFiles() {
    auto start = std::chrono::steady_clock::now();
    SystemCleanupResult result;
    result.StartTime = NowTimestamp();
    try {
        auto cutoff = std::chrono::system_clock::now() - std::chrono::hours(24) * _maxFileAgeDays;
        auto cutoffTime = fs::file_time_type(cutoff);
        for (auto& entry : fs::recursive_directory_iterator(_logDirectory, fs::directory_options::skip_permission_denied)) {
            if (!entry.is_regular_file()) continue;
            auto path = entry.path();
            if (_wcsicmp(path.extension().wstring().c_str(), L".log") != 0) continue;
            std::error_code ec;
            auto lwt = entry.last_write_time(ec);
            auto size = fs::file_size(entry, ec);
            if (ec) continue;
            if (lwt < cutoffTime || static_cast<long long>(size) > _maxLogSizeBytes) {
                fs::remove(path, ec);
                if (!ec) {
                    CleanedItem item;
                    item.Path = path.string();
                    item.SizeBytes = static_cast<long long>(size);
                    item.Type = CleanedItemType::LogFile;
                    result.CleanedItems.push_back(std::move(item));
                    result.FreedSpaceBytes += static_cast<long long>(size);
                }
            }
        }
        result.Success = true;
    } catch (const std::exception& ex) {
        Logger::Error(std::string("Log files cleanup error: ") + ex.what());
        result.Success = false;
        result.ErrorMessage = ex.what();
    }
    result.EndTime = NowTimestamp();
    result.DurationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count();
    return result;
}

// === PLACEHOLDER_PART4 ===

SystemCleanupResult SystemOptimization::CleanupBrowserCache() {
    auto start = std::chrono::steady_clock::now();
    SystemCleanupResult result;
    result.StartTime = NowTimestamp();
    try {
        wchar_t localAppData[MAX_PATH]{};
        GetEnvironmentVariableW(L"LOCALAPPDATA", localAppData, MAX_PATH);
        if (localAppData[0]) {
            std::vector<std::wstring> cacheDirs = {
                std::wstring(localAppData) + L"\\Microsoft\\Windows\\INetCache",
                std::wstring(localAppData) + L"\\Google\\Chrome\\User Data\\Default\\Cache",
                std::wstring(localAppData) + L"\\Mozilla\\Firefox\\Profiles",
                std::wstring(localAppData) + L"\\Microsoft\\Edge\\User Data\\Default\\Cache"
            };
            for (const auto& dir : cacheDirs) {
                std::error_code ec;
                if (!fs::exists(dir, ec)) continue;
                for (auto& entry : fs::recursive_directory_iterator(dir, fs::directory_options::skip_permission_denied)) {
                    if (!entry.is_regular_file()) continue;
                    auto size = fs::file_size(entry, ec);
                    if (ec) size = 0;
                    fs::remove(entry.path(), ec);
                    if (!ec) {
                        CleanedItem item;
                        item.Path = entry.path().string();
                        item.SizeBytes = static_cast<long long>(size);
                        item.Type = CleanedItemType::BrowserCache;
                        result.CleanedItems.push_back(std::move(item));
                        result.FreedSpaceBytes += static_cast<long long>(size);
                    }
                }
            }
        }
        result.Success = true;
    } catch (const std::exception& ex) {
        Logger::Error(std::string("Browser cache cleanup error: ") + ex.what());
        result.Success = false;
        result.ErrorMessage = ex.what();
    }
    result.EndTime = NowTimestamp();
    result.DurationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count();
    return result;
}

SystemCleanupResult SystemOptimization::CleanupRecycleBin() {
    auto start = std::chrono::steady_clock::now();
    SystemCleanupResult result;
    result.StartTime = NowTimestamp();
    try {
        HRESULT hr = SHEmptyRecycleBinW(nullptr, nullptr,
            SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND);
        (void)hr;
        CleanedItem item;
        item.Path = "Recycle Bin";
        item.Type = CleanedItemType::RecycleBin;
        result.CleanedItems.push_back(std::move(item));
        result.Success = true;
    } catch (const std::exception& ex) {
        Logger::Error(std::string("Recycle bin cleanup error: ") + ex.what());
        result.Success = false;
        result.ErrorMessage = ex.what();
    }
    result.EndTime = NowTimestamp();
    result.DurationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count();
    return result;
}

// === PLACEHOLDER_PART5 ===

SystemCleanupResult SystemOptimization::CleanupTemporaryInternetFiles() {
    auto start = std::chrono::steady_clock::now();
    SystemCleanupResult result;
    result.StartTime = NowTimestamp();
    try {
        wchar_t localAppData[MAX_PATH]{};
        if (GetEnvironmentVariableW(L"LOCALAPPDATA", localAppData, MAX_PATH) != 0) {
            std::wstring dir = std::wstring(localAppData) + L"\\Microsoft\\Windows\\Temporary Internet Files";
            std::error_code ec;
            if (fs::exists(dir, ec)) {
                for (auto& entry : fs::recursive_directory_iterator(dir, fs::directory_options::skip_permission_denied)) {
                    if (!entry.is_regular_file()) continue;
                    auto size = fs::file_size(entry, ec);
                    if (ec) size = 0;
                    fs::remove(entry.path(), ec);
                    if (!ec) {
                        CleanedItem item;
                        item.Path = entry.path().string();
                        item.SizeBytes = static_cast<long long>(size);
                        item.Type = CleanedItemType::TemporaryInternetFiles;
                        result.CleanedItems.push_back(std::move(item));
                        result.FreedSpaceBytes += static_cast<long long>(size);
                    }
                }
            }
        }
        result.Success = true;
    } catch (const std::exception& ex) {
        Logger::Error(std::string("Temporary internet files cleanup error: ") + ex.what());
        result.Success = false;
        result.ErrorMessage = ex.what();
    }
    result.EndTime = NowTimestamp();
    result.DurationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count();
    return result;
}

// ==================== OptimizePerformance ====================

SystemPerformanceResult SystemOptimization::OptimizePerformance(const PerformanceOptimizationOptions& options) {
    auto start = std::chrono::steady_clock::now();
    SystemPerformanceResult result;
    result.StartTime = NowTimestamp();
    try {
        if (options.OptimizeStartup)  result.Optimizations.push_back(OptimizeStartup());
        if (options.OptimizeMemory)  result.Optimizations.push_back(OptimizeMemory());
        if (options.OptimizeDisk)    result.Optimizations.push_back(OptimizeDisk());
        if (options.OptimizeServices)result.Optimizations.push_back(OptimizeServices());
        result.Success = true;
    } catch (const std::exception& ex) {
        Logger::Error(std::string("Performance optimization error: ") + ex.what());
        result.Success = false;
        result.ErrorMessage = ex.what();
    }
    result.EndTime = NowTimestamp();
    result.DurationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count();
    return result;
}

// === PLACEHOLDER_PART6 ===

PerformanceOptimization SystemOptimization::OptimizeStartup() {
    PerformanceOptimization opt;
    opt.Type = OptimizationType::Startup;
    opt.StartTime = NowTimestamp();
    auto start = std::chrono::steady_clock::now();
    try {
        HKEY keys[] = { HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE };
        const wchar_t* paths[] = {
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
        };
        int count = 0;
        for (auto root : keys) {
            for (auto path : paths) {
                HKEY hk = nullptr;
                if (RegOpenKeyExW(root, path, 0, KEY_READ, &hk) == ERROR_SUCCESS) {
                    DWORD index = 0;
                    wchar_t name[MAX_PATH]{};
                    DWORD nameLen = MAX_PATH;
                    while (RegEnumValueW(hk, index++, name, &nameLen, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
                        count++;
                        nameLen = MAX_PATH;
                    }
                    RegCloseKey(hk);
                }
            }
        }
        opt.Actions.push_back("Enumerated " + std::to_string(count) + " startup entries");
        opt.Success = true;
    } catch (const std::exception& ex) {
        opt.Success = false;
        opt.ErrorMessage = ex.what();
    }
    opt.EndTime = NowTimestamp();
    opt.DurationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count();
    return opt;
}

PerformanceOptimization SystemOptimization::OptimizeMemory() {
    PerformanceOptimization opt;
    opt.Type = OptimizationType::Memory;
    opt.StartTime = NowTimestamp();
    auto start = std::chrono::steady_clock::now();
    try {
        HANDLE proc = GetCurrentProcess();
        SIZE_T minWs = 10 * 1024 * 1024, maxWs = 100 * 1024 * 1024;
        SetProcessWorkingSetSize(proc, minWs, maxWs);
        SetProcessWorkingSetSize(proc, (SIZE_T)-1, (SIZE_T)-1);
        opt.Actions.push_back("Trimmed current process working set");
        opt.Success = true;
    } catch (const std::exception& ex) {
        opt.Success = false;
        opt.ErrorMessage = ex.what();
    }
    opt.EndTime = NowTimestamp();
    opt.DurationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count();
    return opt;
}

// === PLACEHOLDER_PART7 ===

PerformanceOptimization SystemOptimization::OptimizeDisk() {
    PerformanceOptimization opt;
    opt.Type = OptimizationType::Disk;
    opt.StartTime = NowTimestamp();
    auto start = std::chrono::steady_clock::now();
    try {
        wchar_t buf[MAX_PATH]{};
        GetLogicalDriveStringsW(MAX_PATH, buf);
        int drives = 0;
        for (wchar_t* p = buf; *p; p += wcslen(p) + 1) {
            if (GetDriveTypeW(p) == DRIVE_FIXED) drives++;
        }
        opt.Actions.push_back("Checked " + std::to_string(drives) + " fixed drives");
        opt.Success = true;
    } catch (const std::exception& ex) {
        opt.Success = false;
        opt.ErrorMessage = ex.what();
    }
    opt.EndTime = NowTimestamp();
    opt.DurationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count();
    return opt;
}

PerformanceOptimization SystemOptimization::OptimizeServices() {
    PerformanceOptimization opt;
    opt.Type = OptimizationType::Services;
    opt.StartTime = NowTimestamp();
    auto start = std::chrono::steady_clock::now();
    try {
        SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
        if (scm) {
            DWORD needed = 0, count = 0, resume = 0;
            EnumServicesStatusW(scm, SERVICE_WIN32, SERVICE_STATE_ALL, nullptr, 0, &needed, &count, &resume);
            if (needed > 0) {
                std::vector<BYTE> buf(needed);
                count = 0; resume = 0;
                if (EnumServicesStatusW(scm, SERVICE_WIN32, SERVICE_STATE_ALL,
                    reinterpret_cast<ENUM_SERVICE_STATUSW*>(buf.data()),
                    needed, &needed, &count, &resume)) {
                    opt.Actions.push_back("Enumerated " + std::to_string(count) + " services");
                }
            }
            CloseServiceHandle(scm);
        }
        opt.Success = true;
    } catch (const std::exception& ex) {
        opt.Success = false;
        opt.ErrorMessage = ex.what();
    }
    opt.EndTime = NowTimestamp();
    opt.DurationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count();
    return opt;
}

// ==================== CheckSystemHealth ====================

SystemHealthResult SystemOptimization::CheckSystemHealth() {
    SystemHealthResult result;
    result.CheckTime = NowTimestamp();
    try {
        result.Components.push_back(CheckCpuHealth());
        result.Components.push_back(CheckMemoryHealth());
        result.Components.push_back(CheckDiskHealth());
        result.Components.push_back(CheckNetworkHealth());
        result.Components.push_back(CheckSystemHealthComponents());
        result.OverallHealth = CalculateOverallHealth(result.Components);
        result.Success = true;
    } catch (const std::exception& ex) {
        Logger::Error(std::string("System health check error: ") + ex.what());
        result.Success = false;
        result.ErrorMessage = ex.what();
    }
    return result;
}

// === PLACEHOLDER_PART8 ===

SystemComponentHealth SystemOptimization::CheckCpuHealth() {
    SystemComponentHealth h;
    h.Component = SystemComponent::CPU;
    h.CheckTime = NowTimestamp();
    try {
        FILETIME idle{}, kernel{}, user{};
        if (GetSystemTimes(&idle, &kernel, &user)) {
            ULARGE_INTEGER i{ idle.dwLowDateTime, idle.dwHighDateTime };
            ULARGE_INTEGER k{ kernel.dwLowDateTime, kernel.dwHighDateTime };
            ULARGE_INTEGER u{ user.dwLowDateTime, user.dwHighDateTime };
            ULONGLONG total = (k.QuadPart) + (u.QuadPart);
            ULONGLONG idles = i.QuadPart;
            double pct = 0.0;
            if (total > 0) pct = static_cast<double>(total - idles) * 100.0 / static_cast<double>(total);
            if (pct < 0) pct = 0; if (pct > 100) pct = 100;
            HealthMetric m; m.Name = "CPU Usage"; m.Value = pct; m.Unit = "%";
            h.Metrics.push_back(m);
            h.Status = ScoreToStatus(pct);
            h.Message = h.Status == HealthStatus::Good ? "CPU load normal" :
                        h.Status == HealthStatus::Warning ? "CPU load high" : "CPU load critical";
        }
    } catch (const std::exception&) {
        h.Status = HealthStatus::Error;
        h.Message = "CPU check failed";
    }
    return h;
}

SystemComponentHealth SystemOptimization::CheckMemoryHealth() {
    SystemComponentHealth h;
    h.Component = SystemComponent::Memory;
    h.CheckTime = NowTimestamp();
    try {
        MEMORYSTATUSEX ms{};
        ms.dwLength = sizeof(ms);
        if (GlobalMemoryStatusEx(&ms)) {
            HealthMetric m; m.Name = "Memory Usage"; m.Value = static_cast<double>(ms.dwMemoryLoad); m.Unit = "%";
            h.Metrics.push_back(m);
            HealthMetric m2; m2.Name = "Total Physical"; m2.Value = static_cast<double>(ms.ullTotalPhys / (1024*1024)); m2.Unit = "MB";
            h.Metrics.push_back(m2);
            HealthMetric m3; m3.Name = "Available Physical"; m3.Value = static_cast<double>(ms.ullAvailPhys / (1024*1024)); m3.Unit = "MB";
            h.Metrics.push_back(m3);
            h.Status = ScoreToStatus(static_cast<double>(ms.dwMemoryLoad));
            h.Message = h.Status == HealthStatus::Good ? "Memory sufficient" :
                        h.Status == HealthStatus::Warning ? "Memory usage high" : "Memory critical";
        }
    } catch (const std::exception&) {
        h.Status = HealthStatus::Error;
        h.Message = "Memory check failed";
    }
    return h;
}

// === PLACEHOLDER_PART9 ===

SystemComponentHealth SystemOptimization::CheckDiskHealth() {
    SystemComponentHealth h;
    h.Component = SystemComponent::Disk;
    h.CheckTime = NowTimestamp();
    try {
        wchar_t buf[MAX_PATH]{};
        GetLogicalDriveStringsW(MAX_PATH, buf);
        for (wchar_t* p = buf; *p; p += wcslen(p) + 1) {
            if (GetDriveTypeW(p) != DRIVE_FIXED) continue;
            ULARGE_INTEGER avail{}, total{}, free{};
            if (GetDiskFreeSpaceExW(p, &avail, &total, &free)) {
                double pct = total.QuadPart ? (1.0 - static_cast<double>(avail.QuadPart) / static_cast<double>(total.QuadPart)) * 100.0 : 0;
                HealthMetric m;
                std::wstring ws(p, p + wcslen(p));
                std::string drv(ws.begin(), ws.end());
                m.Name = "Drive " + drv;
                m.Value = pct; m.Unit = "%";
                h.Metrics.push_back(m);
                if (h.Status != HealthStatus::Critical) {
                    h.Status = ScoreToStatus(pct);
                }
            }
        }
        h.Message = h.Status == HealthStatus::Good ? "Disk space sufficient" :
                    h.Status == HealthStatus::Warning ? "Disk space low" : "Disk space critical";
    } catch (const std::exception&) {
        h.Status = HealthStatus::Error;
        h.Message = "Disk check failed";
    }
    return h;
}

SystemComponentHealth SystemOptimization::CheckNetworkHealth() {
    SystemComponentHealth h;
    h.Component = SystemComponent::Network;
    h.CheckTime = NowTimestamp();
    try {
        DWORD bufLen = 0;
        if (GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, nullptr, &bufLen) == ERROR_BUFFER_OVERFLOW) {
            std::vector<BYTE> buf(bufLen);
            auto addrs = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data());
            if (GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, addrs, &bufLen) == NO_ERROR) {
                int upCount = 0;
                for (auto a = addrs; a; a = a->Next) {
                    if (a->OperStatus == IfOperStatusUp) upCount++;
                }
                HealthMetric m; m.Name = "Active Adapters"; m.Value = static_cast<double>(upCount); m.Unit = "count";
                h.Metrics.push_back(m);
                h.Status = upCount > 0 ? HealthStatus::Good : HealthStatus::Warning;
                h.Message = upCount > 0 ? "Network connected" : "No active network";
            }
        }
    } catch (const std::exception&) {
        h.Status = HealthStatus::Error;
        h.Message = "Network check failed";
    }
    return h;
}

SystemComponentHealth SystemOptimization::CheckSystemHealthComponents() {
    SystemComponentHealth h;
    h.Component = SystemComponent::System;
    h.CheckTime = NowTimestamp();
    try {
        ULONGLONG ticks = GetTickCount64() / 1000;
        HealthMetric m; m.Name = "Uptime"; m.Value = static_cast<double>(ticks / 3600); m.Unit = "hours";
        h.Metrics.push_back(m);
        h.Status = HealthStatus::Good;
        h.Message = "System running";
    } catch (const std::exception&) {
        h.Status = HealthStatus::Error;
        h.Message = "System check failed";
    }
    return h;
}

HealthStatus SystemOptimization::CalculateOverallHealth(const std::vector<SystemComponentHealth>& components) {
    int max = static_cast<int>(HealthStatus::Good);
    for (const auto& c : components) {
        max = (std::max)(max, static_cast<int>(c.Status));
    }
    return static_cast<HealthStatus>(max);
}

// === PLACEHOLDER_PART10 ===

// ==================== CleanupRegistry ====================

RegistryCleanupResult SystemOptimization::CleanupRegistry(const RegistryCleanupOptions& options) {
    auto start = std::chrono::steady_clock::now();
    RegistryCleanupResult result;
    result.StartTime = NowTimestamp();
    try {
        if (options.CleanInvalidFileAssociations) {
            auto entries = CleanupInvalidFileAssociations();
            result.CleanedEntries.insert(result.CleanedEntries.end(), entries.begin(), entries.end());
        }
        if (options.CleanInvalidInstallerEntries) {
            auto entries = CleanupInvalidInstallerEntries();
            result.CleanedEntries.insert(result.CleanedEntries.end(), entries.begin(), entries.end());
        }
        if (options.CleanInvalidStartMenuEntries) {
            auto entries = CleanupInvalidStartMenuEntries();
            result.CleanedEntries.insert(result.CleanedEntries.end(), entries.begin(), entries.end());
        }
        if (options.CleanUnusedRegistryKeys) {
            auto entries = CleanupUnusedRegistryKeys();
            result.CleanedEntries.insert(result.CleanedEntries.end(), entries.begin(), entries.end());
        }
        result.Success = true;
    } catch (const std::exception& ex) {
        Logger::Error(std::string("Registry cleanup error: ") + ex.what());
        result.Success = false;
        result.ErrorMessage = ex.what();
    }
    result.EndTime = NowTimestamp();
    result.DurationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count();
    return result;
}

std::vector<RegistryEntry> SystemOptimization::CleanupInvalidFileAssociations() {
    std::vector<RegistryEntry> entries;
    HKEY hkcr = nullptr;
    if (RegOpenKeyExW(HKEY_CLASSES_ROOT, nullptr, 0, KEY_READ, &hkcr) != ERROR_SUCCESS) return entries;
    DWORD index = 0;
    wchar_t subName[MAX_PATH]{};
    DWORD subLen = MAX_PATH;
    DWORD scanned = 0;
    while (RegEnumKeyExW(hkcr, index++, subName, &subLen, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
        if (subName[0] == L'.' && scanned < 500) {
            HKEY hExt = nullptr;
            if (RegOpenKeyExW(hkcr, subName, 0, KEY_READ, &hExt) == ERROR_SUCCESS) {
                wchar_t val[MAX_PATH]{};
                DWORD valLen = sizeof(val);
                DWORD type = 0;
                if (RegQueryValueExW(hExt, nullptr, nullptr, &type, reinterpret_cast<LPBYTE>(val), &valLen) == ERROR_SUCCESS && val[0]) {
                    std::wstring v(val);
                    if (v.find(L".exe") != std::wstring::npos) {
                        RegistryEntry e;
                        e.Key = "HKCR\\" + std::string(subName, subName + subLen);
                        e.ValueName = "(default)";
                        std::string vs(val, val + wcslen(val));
                        e.Value = vs;
                        e.Type = RegistryEntryType::String;
                        entries.push_back(std::move(e));
                    }
                }
                RegCloseKey(hExt);
            }
            scanned++;
        }
        subLen = MAX_PATH;
    }
    RegCloseKey(hkcr);
    return entries;
}

std::vector<RegistryEntry> SystemOptimization::CleanupInvalidInstallerEntries() {
    std::vector<RegistryEntry> entries;
    HKEY hk = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", 0, KEY_READ, &hk) != ERROR_SUCCESS) return entries;
    DWORD index = 0;
    wchar_t subName[MAX_PATH]{};
    DWORD subLen = MAX_PATH;
    while (RegEnumKeyExW(hk, index++, subName, &subLen, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
        RegistryEntry e;
        e.Key = "HKLM\\Uninstall\\" + std::string(subName, subName + subLen);
        e.Type = RegistryEntryType::String;
        entries.push_back(std::move(e));
        subLen = MAX_PATH;
    }
    RegCloseKey(hk);
    return entries;
}

std::vector<RegistryEntry> SystemOptimization::CleanupInvalidStartMenuEntries() {
    std::vector<RegistryEntry> entries;
    wchar_t usrProfile[MAX_PATH]{};
    if (GetEnvironmentVariableW(L"APPDATA", usrProfile, MAX_PATH) != 0) {
        std::wstring startMenu = std::wstring(usrProfile) + L"\\Microsoft\\Windows\\Start Menu\\Programs";
        std::error_code ec;
        if (fs::exists(startMenu, ec)) {
            for (auto& entry : fs::recursive_directory_iterator(startMenu, fs::directory_options::skip_permission_denied)) {
                if (!entry.is_regular_file()) continue;
                if (_wcsicmp(entry.path().extension().wstring().c_str(), L".lnk") == 0) {
                    RegistryEntry e;
                    e.Key = entry.path().string();
                    e.ValueName = "StartMenu";
                    e.Type = RegistryEntryType::String;
                    entries.push_back(std::move(e));
                }
            }
        }
    }
    return entries;
}

std::vector<RegistryEntry> SystemOptimization::CleanupUnusedRegistryKeys() {
    std::vector<RegistryEntry> entries;
    HKEY hkcr = nullptr;
    if (RegOpenKeyExW(HKEY_CLASSES_ROOT, L"CLSID", 0, KEY_READ, &hkcr) != ERROR_SUCCESS) return entries;
    DWORD index = 0;
    wchar_t subName[MAX_PATH]{};
    DWORD subLen = MAX_PATH;
    DWORD scanned = 0;
    while (RegEnumKeyExW(hkcr, index++, subName, &subLen, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
        if (++scanned > 200) break;
        subLen = MAX_PATH;
    }
    RegistryEntry e;
    e.Key = "HKCR\\CLSID";
    e.ValueName = "scanned";
    e.Value = std::to_string(scanned);
    e.Type = RegistryEntryType::DWord;
    entries.push_back(std::move(e));
    RegCloseKey(hkcr);
    return entries;
}

}} // namespace FireAntivirus::Services
