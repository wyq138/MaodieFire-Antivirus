// FireAntivirus.CPP - RealTimeProtectionPlus + AI 引擎 + ClamAV/CloudAV 独立模块 + 主程序
#pragma once

#include "FireAntivirus/Types.h"
#include <string>
#include <vector>
#include <atomic>
#include <thread>
#include <map>
#include <functional>

namespace FireAntivirus {

// ==================== RealTimeProtectionPlus (增强实时保护) ====================
// 移植自 FireAntivirus.RealTimeProtectionPlus (4 cs 文件)
namespace RTPPlus {

class ProtectionModule {
public:
    /// <summary>文件系统微过滤器回调驱动的实时保护</summary>
    bool Initialize();
    void Shutdown();
    bool IsActive() const { return active_.load(); }

    struct FileAlert {
        std::string path;
        std::string process_name;
        std::string reason;
        bool should_block;
    };
    using AlertFn = std::function<void(const FileAlert&)>;
    void SetAlertCallback(AlertFn fn) { alert_cb_ = std::move(fn); }

    // 内部逻辑: 监控临时目录/AppData下的可疑exe创建
    void MonitorWorker();

private:
    std::atomic<bool> active_{false};
    std::thread worker_;
    AlertFn alert_cb_;
};

class FeatureSelfTest {
public:
    struct TestResult { std::string name; bool passed; std::string details; };
    std::vector<TestResult> RunAll();
};

class RealTimeProtectionPlusManager {
public:
    static RealTimeProtectionPlusManager& Instance();
    bool Start();
    bool Stop();
    bool IsRunning();

    ProtectionModule& file_protection() { return file_; }
private:
    RealTimeProtectionPlusManager() = default;
    ProtectionModule file_;
};

} // namespace RTPPlus

// ==================== AdvancedAIDetectionEngine ====================
// 移植自 FireAntivirus.AI.AdvancedAIDetectionEngine.cs
namespace AI {

class AdvancedAIDetectionEngine {
public:
    struct AIResult {
        bool is_malicious = false;
        double confidence = 0.0;
        std::vector<std::string> features;
        std::string model_version;
    };

    bool Initialize();
    AIResult AnalyzeFile(const std::string& file_path);
    AIResult AnalyzeBehavior(const std::vector<std::string>& api_calls);

    void Enable(bool v) { enabled_.store(v); }
    bool IsEnabled() const { return enabled_.load(); }

private:
    std::atomic<bool> enabled_{false};
    // 简化 ML 模型: 基于特征权重打分 (与 C# 版 AI 检测思路一致, 无 ONNX 依赖)
    std::map<std::string, double> feature_weights_;
};

} // namespace AI

// ==================== ClamAVManager (独立模块) ====================
// 移植自 FireAntivirus.ClamAV.ClamAVManager + ClamAVEngineInitializer
namespace ClamAV {

class ClamAVManager {
public:
    bool IsAvailable();
    bool Initialize();
    bool Shutdown();
    ScanResult ScanFile(const std::string& path);

    struct EngineInfo {
        bool available = false;
        std::string version;
        size_t signature_count = 0;
        std::string db_path;
    };
    EngineInfo GetInfo();

    bool UpdateDatabase();

private:
    std::string clamscan_path_;
    std::string db_path_;
    bool initialized_ = false;
};

} // namespace ClamAV

// ==================== CloudAVManager (独立模块) ====================
// 移植自 FireAntivirus.CloudAV.CloudAVManager
namespace CloudAV {

class CloudAVManager {
public:
    struct CloudResult {
        bool is_malicious = false;
        std::string name;
        std::string detection_method;
        double confidence = 0.0;
        std::map<std::string, int> vendor_results;  // vendor -> positive_count
    };

    bool Initialize();
    CloudResult QueryHash(const std::string& sha256);
    CloudResult QueryFile(const std::string& path);

    void SetVirusTotalKey(const std::string& key) { vt_key_ = key; }
    void SetMalwareBazaarEnabled(bool v)          { mb_enabled_ = v; }
    void SetOTXEnabled(bool v)                    { otx_enabled_ = v; }
    void SetHybridAnalysisKey(const std::string& key) { ha_key_ = key; }

private:
    std::string vt_key_, ha_key_;
    bool mb_enabled_ = true, otx_enabled_ = true;
};

} // namespace CloudAV

} // namespace FireAntivirus
