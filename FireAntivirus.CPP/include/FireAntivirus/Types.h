// FireAntivirus.CPP - 核心类型定义
// 移植自 FireAntivirus.Engine.SecurityTypes.cs / AntivirusEngine.cs
#pragma once

#include <string>
#include <vector>
#include <memory>
#include <cstdint>
#include <chrono>
#include <functional>
#include <map>
#include <unordered_map>
#include <set>
#include <optional>

namespace FireAntivirus {

// ==================== 枚举 ====================

/// <summary>威胁级别</summary>
enum class ThreatLevel : int {
    Safe     = 0,   // 安全
    Low      = 1,   // 低风险
    Medium   = 2,   // 中风险
    High     = 3,   // 高风险
    Critical = 4    // 严重风险
};

/// <summary>扫描类型</summary>
enum class ScanType : int {
    Quick,      // 快速扫描
    Full,       // 全盘扫描
    Custom,     // 自定义路径
    Deep,       // 深度扫描
    Memory,     // 内存扫描
    Registry,   // 注册表扫描
    Startup,    // 启动项扫描
    Network     // 网络扫描
};

/// <summary>日志级别</summary>
enum class LogLevel : int {
    Debug = 0,
    Info  = 1,
    Warn  = 2,
    Error = 3,
    Fatal = 4
};

/// <summary>扫描进度回调</summary>
struct ScanProgressEventArgs {
    int files_scanned = 0;
    int total_files   = 0;
    std::string current_file;
    double progress() const {
        return total_files > 0 ? (double)files_scanned / total_files * 100.0 : 0.0;
    }
};

// ==================== 扫描结果 ====================

/// <summary>单个文件扫描结果</summary>
struct ScanResult {
    std::string file_path;
    std::string threat_name;
    std::string threat_type;
    std::string severity;           // "Low" / "Medium" / "High" / "Critical"
    bool        is_infected = false;
    bool        is_malicious() const { return is_infected; }
    double      confidence = 0.0;   // 0.0 ~ 1.0
    std::string detection_method;   // "ClamAV" / "Heuristic" / "Cloud" / "MultiEngine-Consensus" 等
    std::chrono::system_clock::time_point detection_time;
    std::string additional_info;
    std::string error;
    std::vector<uint8_t> file_hash;
    std::vector<std::string> matched_signatures;

    // 便捷工厂
    static ScanResult clean(const std::string& path) {
        ScanResult r;
        r.file_path = path;
        r.is_infected = false;
        r.detection_time = std::chrono::system_clock::now();
        return r;
    }
};

/// <summary>综合检测结果(检测器返回)</summary>
struct DetectionResult {
    bool        is_threat = false;
    ThreatLevel threat_level = ThreatLevel::Safe;
    std::string threat_name;
    std::string description;
    std::string scanner_name;
    std::chrono::system_clock::time_point detection_time;

    bool        is_detected = false;
    std::string threat_type;
    double      confidence = 0.0;
    std::string details;
    std::string additional_info;
    std::string severity;
    std::string detection_method;
    bool        is_infected = false;
    std::string file_path;
    int         detection_id = 0;
    std::string recommended_action;
    bool        is_false_positive = false;
    bool        is_quarantined = false;
};

// ==================== 扫描配置 ====================

/// <summary>扫描配置</summary>
struct ScanConfiguration {
    bool   enable_heuristic_scan = true;
    bool   enable_signature_scan  = true;
    bool   enable_behavior_scan   = true;
    int    max_scan_threads       = 4;
    int    scan_timeout_seconds    = 300;  // 5分钟
    std::vector<std::string> excluded_paths;
};

/// <summary>扫描选项(AntivirusEngine 使用)</summary>
struct ScanOptions {
    ScanType scan_type = ScanType::Quick;
    std::vector<std::string> custom_paths;
    bool scan_memory        = true;
    bool scan_registry      = true;
    bool scan_startup_items = true;
    bool scan_network_connections = false;
    bool scan_processes     = true;
    bool deep_scan         = false;
    bool use_heuristics    = true;
    bool use_behavior_analysis = true;
    int  max_file_size_mb  = 100;
};

// ==================== 威胁情报数据 ====================

struct ThreatIntelligenceData {
    std::string hash;
    std::string file_path;
    ThreatLevel level = ThreatLevel::Safe;
    std::string threat_type;
    std::chrono::system_clock::time_point last_updated;
    std::string source;
};

// ==================== 威胁检测结果(各 ThreatDetector 返回) ====================

/// <summary>单一威胁检测器的输出</summary>
struct ThreatDetectorResult {
    bool        is_detected = false;
    std::string threat_name;
    std::string threat_type;
    double      confidence = 0.0;   // 0.0 ~ 1.0
    std::string details;
};

// ==================== 特征库状态 ====================

struct SignatureDatabaseStatus {
    bool        is_loaded   = false;
    size_t      hash_count  = 0;
    size_t      url_count   = 0;
    size_t      ip_count    = 0;
    std::chrono::system_clock::time_point last_update;
    std::string last_error;
};

struct SignatureUpdateResult {
    bool   success = false;
    size_t hash_count = 0;
    size_t url_count  = 0;
    size_t ip_count   = 0;
    std::string error_message;
};

} // namespace FireAntivirus
