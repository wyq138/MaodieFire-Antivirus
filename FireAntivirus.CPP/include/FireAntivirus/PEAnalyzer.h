// FireAntivirus.CPP - PEAnalyzer 独立模块
// 移植自 FireAntivirus.PEAnalyzer.cs
#pragma once

#include "FireAntivirus/Types.h"
#include <string>
#include <vector>
#include <cstdint>

namespace FireAntivirus {
namespace PEAnalyze {

struct PEHeaderInfo {
    bool is_pe = false;
    uint16_t machine = 0;   // IMAGE_FILE_MACHINE_I386=0x14C, AMD64=0x8664
    uint16_t section_count = 0;
    uint32_t size_of_optional = 0;
    uint32_t size_of_image = 0;
    uint32_t address_of_entry_point = 0;
    uint16_t characteristics = 0;
    bool is_executable = false;
    bool is_dll = false;
};

struct PESectionInfo {
    char name[9]{};
    uint32_t virtual_size = 0;
    uint32_t virtual_address = 0;
    uint32_t raw_size = 0;
    uint32_t characteristics = 0;
    double entropy = 0;
};

struct PEImportEntry {
    std::string dll_name;
    std::vector<std::string> functions;
};

struct PEAnalysisResult {
    PEHeaderInfo header;
    std::vector<PESectionInfo> sections;
    std::vector<PEImportEntry> imports;
    std::string digital_signature_subject;
    std::string digital_signature_issuer;
    bool signature_valid = false;
    double overall_risk_score = 0;
    std::vector<std::string> suspicious_findings;
};

class PEAnalyzer {
public:
    static PEAnalysisResult Analyze(const std::string& file_path);
    static PEAnalysisResult AnalyzeBytes(const std::vector<uint8_t>& data);

private:
    static PEHeaderInfo ParseHeader(const std::vector<uint8_t>& data);
    static std::vector<PESectionInfo> ParseSections(const std::vector<uint8_t>& data);
    static std::vector<PEImportEntry> ParseImports(const std::vector<uint8_t>& data);
    static void ComputeEntropy(PESectionInfo& sec, const std::vector<uint8_t>& data);
};

} // namespace PEAnalyze
} // namespace FireAntivirus
