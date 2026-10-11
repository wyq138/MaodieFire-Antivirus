// FireAntivirus.CPP - PEAnalyzer 实现
#include "FireAntivirus/PEAnalyzer.h"
#include "FireAntivirus/Helper.h"
#include "FireAntivirus/Platform/Windows.h"
#include <cstring>
#include <cmath>
#include <algorithm>

namespace FireAntivirus {
namespace PEAnalyze {

PEHeaderInfo PEAnalyzer::ParseHeader(const std::vector<uint8_t>& data) {
    PEHeaderInfo h;
    if (data.size() < 64 || data[0] != 'M' || data[1] != 'Z') return h;
    uint32_t pe_off = 0;
    std::memcpy(&pe_off, &data[60], 4);
    if (pe_off + 24 > data.size()) return h;
    h.is_pe = (data[pe_off] == 'P' && data[pe_off + 1] == 'E');
    if (!h.is_pe) return h;
    std::memcpy(&h.machine,               &data[pe_off + 4], 2);
    std::memcpy(&h.section_count,         &data[pe_off + 6], 2);
    std::memcpy(&h.size_of_optional,      &data[pe_off + 20], 2);
    uint32_t opt_off = pe_off + 24;
    std::memcpy(&h.address_of_entry_point, &data[opt_off + 16], 4);
    std::memcpy(&h.size_of_image,          &data[opt_off + 56], 4);
    std::memcpy(&h.characteristics,         &data[pe_off + 22], 2);
    h.is_executable = (h.characteristics & 0x0002) != 0;  // IMAGE_FILE_EXECUTABLE_IMAGE
    h.is_dll        = (h.characteristics & 0x2000) != 0;  // IMAGE_FILE_DLL
    return h;
}

void PEAnalyzer::ComputeEntropy(PESectionInfo& sec, const std::vector<uint8_t>& data) {
    if (sec.raw_size == 0 || sec.virtual_address + sec.raw_size > data.size()) return;
    uintptr_t off = sec.virtual_address;
    // 这里 raw 可能指向 raw offset 而非 virtual, 简化: 假设 raw offset 在前一次 parse 时修正
    int freq[256]{};
    for (uint32_t i = 0; i < sec.raw_size; ++i) {
        if (off + i < data.size()) freq[data[off + i]]++;
    }
    double ent = 0;
    for (int c : freq) if (c > 0) { double p=(double)c/sec.raw_size; ent -= p*std::log2(p); }
    sec.entropy = ent;
}

std::vector<PESectionInfo> PEAnalyzer::ParseSections(const std::vector<uint8_t>& data) {
    std::vector<PESectionInfo> out;
    if (data.size() < 64 || data[0] != 'M' || data[1] != 'Z') return out;
    uint32_t pe_off = 0;
    std::memcpy(&pe_off, &data[60], 4);
    if (pe_off + 24 > data.size()) return out;
    uint16_t num_sec = 0, size_opt = 0;
    std::memcpy(&num_sec, &data[pe_off + 6], 2);
    std::memcpy(&size_opt, &data[pe_off + 20], 2);

    uint32_t sec_table_off = pe_off + 24 + size_opt;
    for (uint16_t i = 0; i < num_sec; ++i) {
        uint32_t sh_off = sec_table_off + i * 40;
        if (sh_off + 40 > data.size()) break;
        PESectionInfo s;
        std::memcpy(s.name, data.data() + sh_off, 8);
        s.name[8] = '\0';
        std::memcpy(&s.virtual_size,     data.data() + sh_off + 8, 4);
        std::memcpy(&s.virtual_address,  data.data() + sh_off + 12, 4);
        std::memcpy(&s.raw_size,         data.data() + sh_off + 16, 4);
        uint32_t raw_ptr = 0;
        std::memcpy(&raw_ptr,            data.data() + sh_off + 20, 4);
        std::memcpy(&s.characteristics, data.data() + sh_off + 36, 4);
        // 用 raw offset 计算熵
        int freq[256]{};
        uint32_t n = std::min(s.raw_size, (uint32_t)data.size() - raw_ptr);
        for (uint32_t j = 0; j < n && raw_ptr + j < data.size(); ++j) freq[data[raw_ptr + j]]++;
        double ent = 0;
        for (int c : freq) if (c > 0) { double p=(double)c/n; ent -= p*std::log2(p); }
        s.entropy = ent;
        out.push_back(std::move(s));
    }
    return out;
}

std::vector<PEImportEntry> PEAnalyzer::ParseImports(const std::vector<uint8_t>& data) {
    std::vector<PEImportEntry> out;
    std::string view(data.begin(), data.end());
    // 找常见 DLL 字符串 + 可疑 API
    static const std::vector<std::string> kDlls = {
        "kernel32.dll","user32.dll","advapi32.dll","ntdll.dll","ws2_32.dll",
        "gdi32.dll","shell32.dll","ole32.dll","oleaut32.dll","comctl32.dll",
        "shlwapi.dll","psapi.dll","crypt32.dll","bcrypt.dll","winhttp.dll",
        "urlmon.dll","secur32.dll","wintrust.dll","netapi32.dll","powrprof.dll"
    };
    for (auto& d : kDlls) {
        PEImportEntry e; e.dll_name = d;
        if (Helper::ContainsCI(view, d)) out.push_back(std::move(e));
    }
    return out;
}

PEAnalysisResult PEAnalyzer::AnalyzeBytes(const std::vector<uint8_t>& data) {
    PEAnalysisResult r;
    r.header = ParseHeader(data);
    if (!r.header.is_pe) return r;
    r.sections = ParseSections(data);
    r.imports  = ParseImports(data);

    // 数字签名 (仅当有文件路径才能完整验证)
    // 此处保持空

    // 风险评估
    if (r.sections.size() > 12) {
        r.suspicious_findings.push_back("PE 节数过多 (" + std::to_string(r.sections.size()) + ")");
        r.overall_risk_score += 20;
    }
    int high_entropy = 0;
    int rwx_sections = 0;
    for (auto& s : r.sections) {
        if (s.entropy > 7.5) high_entropy++;
        if ((s.characteristics & 0x20000000) && (s.characteristics & 0x80000000)) {
            rwx_sections++;
        }
    }
    if (high_entropy >= 2) {
        r.suspicious_findings.push_back(">=2 个节熵值 > 7.5 (疑似加壳)");
        r.overall_risk_score += 25;
    }
    if (rwx_sections >= 1) {
        r.suspicious_findings.push_back("存在可写+可执行节");
        r.overall_risk_score += 30;
    }
    // 可疑 API
    static const std::vector<std::string> kSusApi = {
        "CreateRemoteThread","WriteProcessMemory","VirtualAllocEx","RegSetValueExA",
        "CryptEncrypt","IsDebuggerPresent","SetWindowsHookEx","GetAsyncKeyState"
    };
    std::string view(data.begin(), data.end());
    int api_hits = 0;
    for (auto& a : kSusApi) if (Helper::ContainsCI(view, a)) api_hits++;
    if (api_hits >= 3) {
        r.suspicious_findings.push_back("命中 " + std::to_string(api_hits) + " 个可疑 API");
        r.overall_risk_score += api_hits * 8;
    }
    r.overall_risk_score = std::min(r.overall_risk_score / 100.0, 1.0);
    return r;
}

PEAnalysisResult PEAnalyzer::Analyze(const std::string& file_path) {
    auto data = Helper::ReadFileAllBytes(file_path);
    if (data.empty()) return {};
    auto r = AnalyzeBytes(data);
    // 补签名信息
    auto sign = Platform::VerifyFileSignature(file_path);
    r.digital_signature_subject = sign.subject;
    r.digital_signature_issuer  = sign.issuer;
    r.signature_valid = sign.signature_valid;
    if (!sign.signature_valid && r.header.is_pe) {
        r.suspicious_findings.push_back("PE 文件无有效 Authenticode 签名");
        r.overall_risk_score += 0.1;
    }
    return r;
}

} // namespace PEAnalyze
} // namespace FireAntivirus
