// FireAntivirus.CPP - SecurityComponents 全部类
// 移植自 FireAntivirus.Engine.SecurityComponents.cs (11 个类)
#pragma once

#include "FireAntivirus/Types.h"
#include "FireAntivirus/Helper.h"
#include "FireAntivirus/Platform/Windows.h"

#include <string>
#include <vector>
#include <map>

namespace FireAntivirus {
namespace Engine {

// ==================== MalwareFamily ====================

struct MalwareFamilyDef {
    std::string name;
    std::string type;
    std::vector<std::string> patterns;
    std::vector<std::string> file_extensions;
    std::string risk_level;
};

// ==================== MalwareAnalyzer ====================

class MalwareAnalyzer {
public:
    MalwareAnalyzer();
    struct MalwareAnalysisResult {
        std::string file_path;
        bool        is_malware = false;
        std::string family = "Unknown";
        std::string type;
        std::string risk_level = "Low";
        double      confidence = 0.0;
        std::vector<std::string> matched_patterns;
        std::vector<std::string> matched_extensions;
    };
    MalwareAnalysisResult Analyze(const std::string& file_path);

private:
    std::vector<MalwareFamilyDef> families_;
};

// ==================== SystemOptimizer ====================

class SystemOptimizer {
public:
    struct CleanupItem { std::string path; uintmax_t size = 0; std::string type; };
    struct OptimizationResult { std::vector<CleanupItem> items; uintmax_t total_size = 0; };

    OptimizationResult CleanTempFiles();
    std::vector<std::string> GetStartupItems();
};

// ==================== ThreatHunter ====================

class ThreatHunter {
public:
    struct ThreatHuntResult {
        std::string type;      // "SuspiciousProcess" / "MalwareFile"
        std::string name;
        std::string path;
        std::string risk_level;
    };
    std::vector<ThreatHuntResult> HuntThreats();
};

// ==================== IncidentResponder ====================

class IncidentResponder {
public:
    struct ResponseResult {
        bool success = false;
        std::vector<std::string> actions;
        std::string error_message;
    };
    ResponseResult Respond(const ThreatHunter::ThreatHuntResult& threat);
};

// ==================== ForensicAnalyzer ====================

class ForensicAnalyzer {
public:
    struct ForensicResult {
        std::string file_path;
        std::chrono::system_clock::time_point creation_time;
        std::chrono::system_clock::time_point last_write_time;
        std::chrono::system_clock::time_point last_access_time;
        uintmax_t   file_size = 0;
        std::string file_hash;
        std::string signature;
        std::string attributes;
        std::vector<std::string> alternate_data_streams;
    };
    ForensicResult AnalyzeFile(const std::string& file_path);
};

// ==================== MalwareRemover ====================

class MalwareRemover {
public:
    struct RemovalResult {
        bool success = false;
        std::string quarantine_path;
        std::vector<std::string> actions;
        std::string error_message;
    };
    RemovalResult Remove(const std::string& file_path);

private:
    void RemoveRegistryEntries(const std::string& file_name, RemovalResult& r);
};

// ==================== SystemRestorer ====================

class SystemRestorer {
public:
    struct RestoreResult { bool success = true; std::vector<std::string> actions; };
    RestoreResult RestoreSystemSettings();

private:
    void RestoreHostsFile(RestoreResult& r);
    void RestoreFirewallSettings(RestoreResult& r);
    void RestoreWindowsUpdateSettings(RestoreResult& r);
};

// ==================== BackupAnalyzer ====================

class BackupAnalyzer {
public:
    struct BackupAnalysisResult {
        bool has_windows_backup = false;
        int  restore_point_count = 0;
        std::vector<std::string> backup_locations;
    };
    BackupAnalysisResult AnalyzeBackups();
};

// ==================== IntegrityVerifier ====================

class IntegrityVerifier {
public:
    struct IntegrityResult {
        std::string file_path;
        std::string original_hash;
        std::string current_hash;
        bool        is_intact = true;
    };
    std::vector<IntegrityResult> VerifySystemFiles();

private:
    std::map<std::string, std::string> system_file_hashes_;
    void LoadKnownHashes();
};

// ==================== SandboxAnalyzer (静态行为沙箱) ====================

class SandboxAnalyzer {
public:
    struct SandboxResult {
        std::string file_path;
        std::vector<std::string> behaviors;
        int  risk_score = 0;
        bool is_malicious = false;
    };
    SandboxResult Analyze(const std::string& file_path);
};

// ==================== MachineLearningDetector (简化特征向量) ====================

class MachineLearningDetector {
public:
    struct MLDetectionResult {
        std::string file_path;
        double      score = 0;
        bool        is_malicious = false;
        std::map<std::string, double> features;
    };
    MLDetectionResult Detect(const std::string& file_path);

private:
    std::map<std::string, double> ExtractFeatures(const std::vector<uint8_t>& data);
    double CalculateScore(const std::map<std::string, double>& features);
};

// ==================== BehavioralHeuristics ====================

class BehavioralHeuristics {
public:
    struct HeuristicResult {
        std::string file_path;
        std::vector<std::string> detected_patterns;
        int  risk_score = 0;
        bool is_malicious = false;
    };
    HeuristicResult Analyze(const std::string& file_path);
};

// ==================== CryptoAnalyzer ====================

class CryptoAnalyzer {
public:
    struct CryptoAnalysisResult {
        std::string file_path;
        std::vector<std::string> mining_pools;
        std::vector<std::string> crypto_patterns;
        int  risk_score = 0;
        bool is_crypto_malware = false;
    };
    CryptoAnalysisResult Analyze(const std::string& file_path);
};

} // namespace Engine
} // namespace FireAntivirus
