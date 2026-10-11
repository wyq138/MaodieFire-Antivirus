// FireAntivirus.CPP - AntivirusEngine 核心
// 移植自 FireAntivirus.Engine.AntivirusEngine.cs
// 保持逻辑完全一致,做了 C++ 性能优化(无 GC,零拷贝读文件,WinHTTP 原生调用)
#pragma once

#include "FireAntivirus/Types.h"
#include "FireAntivirus/Engine/Detectors/AllDetectors.h"
#include "FireAntivirus/Engine/Analyzers/AllAnalyzers.h"
#include "FireAntivirus/Engine/Scanners/AllScanners.h"
#include "FireAntivirus/Engine/KernelProtection.h"
#include "FireAntivirus/Engine/SignatureDatabase.h"
#include "FireAntivirus/DataManager.h"
#include "FireAntivirus/Network/HttpClient.h"

#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <future>

namespace FireAntivirus {
namespace Engine {

/// <summary>云查杀配置(对外暴露)</summary>
struct CloudScanConfig {
    bool enable_malwarebazaar = true;
    bool enable_otx           = true;
    bool enable_virustotal    = false;
    bool enable_hybrid_analysis = false;
    std::string virustotal_api_key;
    std::string hybrid_analysis_api_key;
    int         timeout_seconds = 15;
};

/// <summary>AntivirusEngine - 主引擎类,与原 C# 接口对齐</summary>
class AntivirusEngine {
public:
    AntivirusEngine();
    ~AntivirusEngine();

    // ===== 核心扫描 =====
    ScanResult ScanFile(const std::string& file_path);
    std::vector<ScanResult> ScanDirectory(const std::string& dir,
                                          const ScanOptions& opts = ScanOptions{});

    // ===== 扫描控制 =====
    bool IsScanning()  const { return scanning_.load(); }
    bool IsPaused()    const { return paused_.load(); }
    void StopScan();
    void PauseScan();
    void ResumeScan();

    // ===== 云查杀配置 =====
    void  SetCloudConfig(const CloudScanConfig& cfg) { cloud_cfg_ = cfg; }
    CloudScanConfig GetCloudConfig() const { return cloud_cfg_; }
    void  SetEnableCloudScan(bool v) { enable_cloud_.store(v); }
    bool  EnableCloudScan() const { return enable_cloud_.load(); }
    void  SetCloudTimeout(int seconds) { cloud_cfg_.timeout_seconds = seconds; }

    // ===== 特征库 =====
    SignatureDatabaseStatus GetSignatureDatabaseStatus();
    SignatureUpdateResult   UpdateSignatureDatabase();

    // ===== 事件回调(等价于 C# 的 EventHandler) =====
    using ProgressFn = std::function<void(const ScanProgressEventArgs&)>;
    using ThreatFn   = std::function<void(const ScanResult&)>;
    using CompleteFn = std::function<void(const ScanResult&)>;

    void OnProgress(ProgressFn fn)  { progress_cb_  = std::move(fn); }
    void OnThreat(ThreatFn fn)      { threat_cb_    = std::move(fn); }
    void OnComplete(CompleteFn fn)  { complete_cb_  = std::move(fn); }

private:
    // 辅助
    bool IsSystemFile(const std::string& path);
    bool HasValidSignature(const std::string& path);

    // 扩容扫描(文件名伪装/PE/宏/压缩包/模式规则/多维度)
    std::vector<Analyzers::ExpandedScanHit> RunExpandedScanners(const std::string& path);

    // ClamAV 扫描
    ScanResult ScanWithClamAV(const std::string& path);
    std::string FindClamScan();

    // 威胁检测器
    ScanResult ScanWithThreatDetectors(const std::string& path,
                                       const std::vector<uint8_t>& content);

    // 内置云查杀 (MalwareBazaar / OTX / VirusTotal)
    ScanResult ScanWithBuiltInCloud(const std::string& path);
    std::pair<bool, std::string> QueryMalwareBazaar(const std::string& sha256);
    std::pair<bool, std::string> QueryOtxHash(const std::string& sha256);
    std::tuple<bool, std::string, int, int> QueryVirusTotal(const std::string& sha256);

    // 内部状态
    std::atomic<bool> scanning_{false};
    std::atomic<bool> paused_{false};
    std::atomic<bool> cancelled_{false};
    std::mutex        pause_mutex_;
    std::condition_variable pause_cv_;

    // 缓存 (5分钟文件扫描缓存 + 24小时云哈希缓存)
    struct CacheEntry { ScanResult result; std::chrono::system_clock::time_point ts; };
    std::unordered_map<std::string, CacheEntry> scan_cache_;
    std::mutex         cache_mutex_;
    std::chrono::milliseconds cache_ttl_{5 * 60 * 1000};

    std::unordered_map<std::string, CacheEntry> cloud_cache_;
    std::mutex         cloud_cache_mutex_;
    std::chrono::milliseconds cloud_cache_ttl_{24 * 3600 * 1000};

    // 配置
    CloudScanConfig cloud_cfg_;
    std::atomic<bool> enable_cloud_{true};

    // 子系统实例
    std::unique_ptr<Detectors::ThreatDetectorBase> detector_impls_[11]; // 所有威胁检测器(按名调用,避免 factory)
    Analyzers::HeuristicEngine      heuristic_;
    Analyzers::StaticAnalyzer       static_;
    Analyzers::BehaviorAnalyzer     behavior_;
    Analyzers::FileNameSpoofAnalyzer name_spoof_;
    Analyzers::PEStructureAnalyzer  pe_struct_;
    Analyzers::MacroDocumentAnalyzer macro_doc_;
    Analyzers::ArchiveNestedScanner archive_scanner_;
    Analyzers::PatternRuleEngine    pattern_rule_;
    Analyzers::MultiDimFileEvaluator multi_dim_;

    // 事件回调
    ProgressFn  progress_cb_;
    ThreatFn    threat_cb_;
    CompleteFn  complete_cb_;
};

} // namespace Engine
} // namespace FireAntivirus
