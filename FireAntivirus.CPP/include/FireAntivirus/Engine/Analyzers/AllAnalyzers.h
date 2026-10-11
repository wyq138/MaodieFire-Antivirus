// FireAntivirus.CPP - 分析器合集
// 移植自 FireAntivirus.Engine.Analyzers (Heuristic / Static / Behavior / PE 等)
#pragma once

#include "FireAntivirus/Types.h"
#include <string>
#include <vector>
#include <memory>
#include <cstdint>

namespace FireAntivirus {
namespace Engine {
namespace Analyzers {

/// <summary>扩展扫描器命中结构体</summary>
struct ExpandedScanHit {
    std::string file_path;
    bool        is_infected = false;
    std::string threat_name;
    std::string threat_type;
    std::string severity;
    double      confidence = 0.0;
    std::string detection_method;
    std::vector<std::string> evidence;
};

// ==================== HeuristicEngine ====================

class HeuristicEngine {
public:
    HeuristicEngine() = default;

    /// <summary>启发式扫描文件,返回零个或多个扫描命中</summary>
    std::vector<ScanResult> AnalyzeFile(const std::string& file_path);

private:
    struct HeuristicRule {
        std::string name;
        std::string needle;
        double      confidence;
        std::string threat_type;
        std::string severity;
    };
    std::vector<HeuristicRule> BuildRules() const;
};

// ==================== StaticAnalyzer ====================

class StaticAnalyzer {
public:
    std::vector<ScanResult> AnalyzeFile(const std::string& file_path);

    /// <summary>计算熵值</summary>
    static double ComputeEntropy(const std::vector<uint8_t>& data);
};

// ==================== BehaviorAnalyzer ====================

class BehaviorAnalyzer {
public:
    std::vector<ScanResult> AnalyzeFile(const std::string& file_path);

    struct SuspiciousBehavior {
        std::string name;
        std::vector<std::string> keywords;
        int         risk_score = 0;
    };
};

// ==================== FileNameSpoofAnalyzer ====================

/// <summary>双重扩展名/RTLO/魔数不符检测</summary>
class FileNameSpoofAnalyzer {
public:
    std::optional<ExpandedScanHit> Analyze(const std::string& file_path);
};

// ==================== PEStructureAnalyzer ====================

/// <summary>PE结构深度分析:节熵/导入异常/EntryPoint 可疑</summary>
class PEStructureAnalyzer {
public:
    std::optional<ExpandedScanHit> Analyze(const std::string& file_path);
};

// ==================== MacroDocumentAnalyzer ====================

/// <summary>OOXML 宏文档检测 (.docx/.xlsx/.pptx/.docm/.xlsm/.pptm)</summary>
class MacroDocumentAnalyzer {
public:
    std::optional<ExpandedScanHit> Analyze(const std::string& file_path);
};

// ==================== ArchiveNestedScanner ====================

/// <summary>ZIP/OOXML 容器递归扫描 (带回调)</summary>
class ArchiveNestedScanner {
public:
    using ScanFn  = std::function<ScanResult(const std::string&)>;
    using HitFn   = std::function<bool(const ScanResult&)>;

    ArchiveNestedScanner(ScanFn scan, HitFn is_hit)
        : scan_(std::move(scan)), is_hit_(std::move(is_hit)) {}

    std::optional<ExpandedScanHit> Analyze(const std::string& archive_path);

private:
    ScanFn scan_;
    HitFn  is_hit_;
};

// ==================== PatternRuleEngine ====================

/// <summary>嵌入式模式规则引擎 (脚本/文本小文件)</summary>
class PatternRuleEngine {
public:
    std::optional<ExpandedScanHit> AnalyzeContent(const std::string& path,
                                                   const std::vector<uint8_t>& content);

private:
    struct Pattern {
        std::string name;
        std::string needle;
        double      confidence;
    };
    std::vector<Pattern> BuildPatterns() const;
};

// ==================== MultiDimFileEvaluator ====================

/// <summary>多维度文件评估器(哈希+PE结构+签名+节熵+导入)</summary>
struct MultiDimEval {
    bool   is_malicious = false;
    double score = 0;
};
class MultiDimFileEvaluator {
public:
    MultiDimEval Evaluate(const std::string& file_path);
};

} // namespace Analyzers
} // namespace Engine
} // namespace FireAntivirus
