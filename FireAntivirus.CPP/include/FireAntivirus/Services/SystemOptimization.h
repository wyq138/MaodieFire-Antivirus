// 移植自 FireAntivirus.Services.SystemOptimization (C#)
// 系统优化: 清理 / 性能优化 / 健康检查 / 注册表清理
// 1:1 对齐 _cs_extract/SystemOptimization.cs

#pragma once

#include "CoreServices.h"   // 复用 Logger / LogManager / ConfigManager 等

#include <string>
#include <vector>
#include <chrono>
#include <filesystem>
#include <mutex>

namespace FireAntivirus { namespace Services {

// ============ 枚举 (对齐 C# enum) ============
enum class CleanedItemType {
    TempFile, LogFile, BrowserCache, RecycleBin, TemporaryInternetFiles, Other
};

enum class OptimizationType {
    Startup, Memory, Disk, Services, Network, Other
};

enum class SystemComponent {
    CPU, Memory, Disk, Network, System, Other
};

enum class HealthStatus {
    Good, Warning, Critical, Error
};

enum class RegistryEntryType {
    String, ExpandString, Binary, DWord, QWord, MultiString, Other
};

// ============ 数据结构 (对齐 C# class/struct) ============
struct CleanedItem {
    std::string Path;
    long long SizeBytes = 0;
    CleanedItemType Type = CleanedItemType::Other;
};

struct SystemCleanupResult {
    std::string StartTime;
    std::string EndTime;
    long long DurationMs = 0;
    bool Success = false;
    std::string ErrorMessage;
    std::vector<CleanedItem> CleanedItems;
    long long FreedSpaceBytes = 0;
    int CleanedItemsCount() const { return static_cast<int>(CleanedItems.size()); }
};

struct PerformanceOptimization {
    OptimizationType Type = OptimizationType::Other;
    std::string StartTime;
    std::string EndTime;
    long long DurationMs = 0;
    bool Success = false;
    std::string ErrorMessage;
    std::vector<std::string> Actions;
};

struct SystemPerformanceResult {
    std::string StartTime;
    std::string EndTime;
    long long DurationMs = 0;
    bool Success = false;
    std::string ErrorMessage;
    std::vector<PerformanceOptimization> Optimizations;
};

struct HealthMetric {
    std::string Name;
    double Value = 0.0;
    std::string Unit;
};

struct SystemComponentHealth {
    SystemComponent Component = SystemComponent::Other;
    std::string CheckTime;
    HealthStatus Status = HealthStatus::Good;
    std::string Message;
    std::vector<HealthMetric> Metrics;
};

struct SystemHealthResult {
    std::string CheckTime;
    bool Success = false;
    std::string ErrorMessage;
    std::vector<SystemComponentHealth> Components;
    HealthStatus OverallHealth = HealthStatus::Good;
};

struct RegistryEntry {
    std::string Key;
    std::string ValueName;
    std::string Value;
    RegistryEntryType Type = RegistryEntryType::Other;
};

struct RegistryCleanupResult {
    std::string StartTime;
    std::string EndTime;
    long long DurationMs = 0;
    bool Success = false;
    std::string ErrorMessage;
    std::vector<RegistryEntry> CleanedEntries;
    int CleanedEntriesCount() const { return static_cast<int>(CleanedEntries.size()); }
};

// ============ 选项结构 ============
struct SystemCleanupOptions {
    bool CleanTempFiles = true;
    bool CleanLogFiles = true;
    bool CleanBrowserCache = true;
    bool CleanRecycleBin = true;
    bool CleanTemporaryInternetFiles = true;
};

struct PerformanceOptimizationOptions {
    bool OptimizeStartup = true;
    bool OptimizeMemory = true;
    bool OptimizeDisk = true;
    bool OptimizeServices = true;
};

struct RegistryCleanupOptions {
    bool CleanInvalidFileAssociations = true;
    bool CleanInvalidInstallerEntries = true;
    bool CleanInvalidStartMenuEntries = true;
    bool CleanUnusedRegistryKeys = true;
};

// ============ SystemOptimization 主类 ============
class SystemOptimization {
public:
    // tempDirectory: 临时目录 (空 => 系统临时目录)
    // logDirectory:  日志目录   (空 => %ProgramData%/FireAntivirus/Logs)
    // maxFileAgeDays: 清理超过该天数的文件
    // maxLogSizeBytes: 单个日志文件超过该字节数即清理
    SystemOptimization(const std::string& tempDirectory = "",
                       const std::string& logDirectory = "",
                       int maxFileAgeDays = 7,
                       long long maxLogSizeBytes = 10LL * 1024 * 1024); // 10MB

    // ---- 公开方法 (对齐 C# public async) ----
    SystemCleanupResult      CleanupSystem(const SystemCleanupOptions& options);
    SystemPerformanceResult OptimizePerformance(const PerformanceOptimizationOptions& options);
    SystemHealthResult       CheckSystemHealth();
    RegistryCleanupResult    CleanupRegistry(const RegistryCleanupOptions& options);

private:
    std::string _tempDirectory;
    std::string _logDirectory;
    int _maxFileAgeDays;
    long long _maxLogSizeBytes;
    mutable std::mutex _lock;

    // ---- 清理子任务 ----
    SystemCleanupResult CleanupTempFiles();
    SystemCleanupResult CleanupLogFiles();
    SystemCleanupResult CleanupBrowserCache();
    SystemCleanupResult CleanupRecycleBin();
    SystemCleanupResult CleanupTemporaryInternetFiles();

    // ---- 性能优化子任务 ----
    PerformanceOptimization OptimizeStartup();
    PerformanceOptimization OptimizeMemory();
    PerformanceOptimization OptimizeDisk();
    PerformanceOptimization OptimizeServices();

    // ---- 健康检查子任务 ----
    SystemComponentHealth CheckCpuHealth();
    SystemComponentHealth CheckMemoryHealth();
    SystemComponentHealth CheckDiskHealth();
    SystemComponentHealth CheckNetworkHealth();
    SystemComponentHealth CheckSystemHealthComponents();
    HealthStatus CalculateOverallHealth(const std::vector<SystemComponentHealth>& components);

    // ---- 注册表清理子任务 ----
    std::vector<RegistryEntry> CleanupInvalidFileAssociations();
    std::vector<RegistryEntry> CleanupInvalidInstallerEntries();
    std::vector<RegistryEntry> CleanupInvalidStartMenuEntries();
    std::vector<RegistryEntry> CleanupUnusedRegistryKeys();

    // ---- 工具 ----
    void EnsureDirectory(const std::string& path);
    static std::string NowTimestamp();
    static std::string DurationSince(const std::chrono::steady_clock::time_point& start);
    static std::string GetSystemTempDirectory();
    static std::string GetDefaultLogDirectory();
    HealthStatus ScoreToStatus(double percent, double warn = 60.0, double crit = 85.0);
};

}} // namespace FireAntivirus::Services
