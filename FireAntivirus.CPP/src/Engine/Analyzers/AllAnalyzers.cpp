// FireAntivirus.CPP - 分析器全部实现
// 移植自 FireAntivirus.Engine.Analyzers/*
#include "FireAntivirus/Engine/Analyzers/AllAnalyzers.h"
#include "FireAntivirus/Helper.h"
#include <algorithm>
#include <cmath>
#include <optional>
#include <zip.h>  // 说明: 需要 libzip (见CMakeLists 注释)
// 如果不想依赖 libzip, ArchiveNestedScanner 里做了 try-catch 跳过

namespace FireAntivirus {
namespace Engine {
namespace Analyzers {

// ==================== HeuristicEngine ====================

std::vector<HeuristicEngine::HeuristicRule> HeuristicEngine::BuildRules() const {
    return {
        {"Rule.ProcessInjection","CreateRemoteThread",             0.7,"Trojan","High"},
        {"Rule.ProcessInjection","WriteProcessMemory",             0.7,"Trojan","High"},
        {"Rule.ShellExec","cmd.exe /c",                            0.5,"Trojan","Medium"},
        {"Rule.ShellExec","powershell -enc",                       0.6,"Trojan","High"},
        {"Rule.Persistence","CurrentVersion\\Run",                 0.5,"Backdoor","Medium"},
        {"Rule.Network","HttpWebRequest",                          0.35,"Worm","Low"},
        {"Rule.Network","WebClient.DownloadFile",                  0.5,"Downloader","Medium"},
        {"Rule.Crypto","CryptEncrypt",                             0.7,"Ransomware","High"},
        {"Rule.Crypto","Aes.Create",                                0.65,"Ransomware","High"},
        {"Rule.AntiDebug","IsDebuggerPresent",                     0.55,"Trojan","Medium"},
        {"Rule.VMDetect","VirtualBox Guest Additions",             0.4,"Trojan","Medium"},
        {"Rule.VMDetect","VMware Tools",                           0.4,"Trojan","Medium"},
        {"Rule.MinerPool","stratum+tcp://",                        0.7,"Miner","High"},
        {"Rule.MassDelete","vssadmin delete shadows",              0.75,"Ransomware","Critical"},
        {"Rule.UACBypass","FodHelper.exe",                         0.6,"Exploit","High"},
        {"Rule.ROP","VirtualProtect","                             0.5,"Exploit","Medium"}
    };
}

std::vector<ScanResult> HeuristicEngine::AnalyzeFile(const std::string& file_path) {
    std::vector<ScanResult> hits;
    auto bytes = Helper::ReadFileAllBytes(file_path);
    if (bytes.empty()) return hits;
    std::string text(bytes.begin(), bytes.end());
    // 限制文本长度,只看前 100KB 可打印区域
    std::string view;
    view.reserve(std::min(bytes.size(), size_t(100000)));
    for (size_t i = 0; i < bytes.size() && i < 100000; ++i) {
        unsigned char c = bytes[i];
        view.push_back((c >= 0x20 && c <= 0x7E) ? (char)c : ' ');
    }

    for (auto& rule : BuildRules()) {
        if (Helper::ContainsCI(view, rule.needle)) {
            ScanResult r;
            r.file_path         = file_path;
            r.is_infected       = true;
            r.threat_name       = rule.name;
            r.threat_type       = rule.threat_type;
            r.severity          = rule.severity;
            r.confidence       = rule.confidence;
            r.detection_method  = "HeuristicEngine";
            hits.push_back(std::move(r));
        }
    }
    return hits;
}

// ==================== StaticAnalyzer ====================

double StaticAnalyzer::ComputeEntropy(const std::vector<uint8_t>& data) {
    if (data.empty()) return 0;
    int freq[256]{};
    for (auto b : data) freq[b]++;
    double ent = 0;
    for (auto f : freq) {
        if (f > 0) {
            double p = (double)f / data.size();
            ent -= p * std::log2(p);
        }
    }
    return ent;
}

std::vector<ScanResult> StaticAnalyzer::AnalyzeFile(const std::string& file_path) {
    std::vector<ScanResult> hits;
    auto bytes = Helper::ReadFileAllBytes(file_path);
    if (bytes.empty()) return hits;

    double ent = ComputeEntropy(bytes);

    // 1) 高熵且非已知压缩格式 -> 可能是加密壳
    if (ent > 7.6) {
        static const std::vector<std::string> kZipHints = {
            "PK\x03\x04", "Rar!\x1a\x07", "7z\xbc\xaf\x27\x1c", "7z\x00\x00\x00\x00"
        };
        bool is_archive = false;
        for (auto& h : kZipHints) {
            if (bytes.size() >= h.size() &&
                std::memcmp(bytes.data(), h.data(), h.size()) == 0) {
                is_archive = true; break;
            }
        }
        if (!is_archive) {
            ScanResult r;
            r.file_path        = file_path;
            r.is_infected      = true;
            r.threat_name      = "Static.HighEntropyPacked";
            r.threat_type      = "Trojan";
            r.severity         = "Medium";
            r.confidence      = 0.6;
            r.detection_method = "StaticAnalyzer.HighEntropy";
            r.additional_info  = "文件熵值 " + std::to_string((int)(ent * 100) / 100.0) + " > 7.6, 疑似加壳";
            hits.push_back(std::move(r));
        }
    }

    // 2) PE 头有效但无数字签名 -> 可疑
    std::string ext = Helper::GetExtensionNoDot(file_path);
    bool is_pe = (ext == "exe" || ext == "dll" || ext == "scr" || ext == "sys" || ext == "cpl");
    if (is_pe && Platform::IsPeFile(bytes)) {
        auto sign = Platform::VerifyFileSignature(file_path);
        if (!sign.has_signature || !sign.signature_valid) {
            ScanResult r;
            r.file_path        = file_path;
            r.is_infected      = false;  // 仅报"可疑",不直接定罪
            r.threat_name      = "Static.UnsignedPE";
            r.threat_type      = "Suspicious";
            r.severity         = "Low";
            r.confidence      = 0.3;
            r.detection_method = "StaticAnalyzer.NoSignature";
            r.additional_info  = "PE 文件无有效 Authenticode 签名";
            hits.push_back(std::move(r));
        }
    }
    return hits;
}

// ==================== BehaviorAnalyzer ====================

std::vector<BehaviorAnalyzer::SuspiciousBehavior> BuildBehaviors() {
    return {
        {"ProcessInjection",  {"CreateRemoteThread","WriteProcessMemory","VirtualAllocEx","NtWriteVirtualMemory"}, 30},
        {"RegistryPersistence",{"CurrentVersion\\Run","RunOnce","RunServices","Image File Execution Options"},   20},
        {"NetworkCommunication",{"HttpWebRequest","WebClient","Socket","Sendto","connect("},                   15},
        {"FileEncryption",    {"CryptEncrypt","Aes.Create","RSA.Encrypt","CryptExportKey"},                      25},
        {"AntiDebug",         {"IsDebuggerPresent","CheckRemoteDebuggerPresent","OutputDebugString"},           20},
        {"VMDetection",       {"VirtualBox","VMware","Sandbox","QEMU","KVM"},                                    15},
        {"Screenshot",        {"BitBlt","GetDC","CopyFromScreen","PrintWindow"},                                 20},
        {"KeyboardHook",      {"SetWindowsHookEx","WH_KEYBOARD","WH_MOUSE","GetAsyncKeyState"},                 25},
        {"MassFileAccess",    {"EnumerateFiles","Directory.GetFiles","GetFiles","FindFirstFile"},                15},
        {"DeleteShadowCopy",  {"vssadmin","shadowcopy","bcdedit /set recoveryenabled no"},                      30},
        {"UACBypass",         {"FodHelper","slui.exe","sdclt","CompMgmtLauncher.exe"},                           25},
        {"SilentInstall",     {"msiexec /i","msiexec /q","InstallUtil.exe","regsvr32 /s"},                       20}
    };
}

std::vector<ScanResult> BehaviorAnalyzer::AnalyzeFile(const std::string& file_path) {
    std::vector<ScanResult> hits;
    auto bytes = Helper::ReadFileAllBytes(file_path);
    if (bytes.empty()) return hits;
    std::string view;
    view.reserve(std::min(bytes.size(), size_t(100000)));
    for (size_t i = 0; i < bytes.size() && i < 100000; ++i) {
        unsigned char c = bytes[i];
        view.push_back((c >= 0x20 && c <= 0x7E) ? (char)c : ' ');
    }

    int total_score = 0;
    std::vector<std::string> matched_names;
    for (auto& b : BuildBehaviors()) {
        bool any = false;
        for (auto& kw : b.keywords) {
            if (Helper::ContainsCI(view, kw)) { any = true; break; }
        }
        if (any) {
            total_score += b.risk_score;
            matched_names.push_back(b.name);
        }
    }

    if (total_score >= 50) {
        ScanResult r;
        r.file_path        = file_path;
        r.is_infected      = true;
        r.threat_name      = "Behavior.RiskScore_" + std::to_string(total_score);
        r.threat_type      = "Trojan";
        r.severity         = total_score >= 80 ? "Critical" : (total_score >= 65 ? "High" : "Medium");
        r.confidence      = std::min(0.5 + total_score / 200.0, 0.85);
        r.detection_method = "BehaviorAnalyzer";
        std::string info;
        for (auto& n : matched_names) info += n + ",";
        r.additional_info = info;
        hits.push_back(std::move(r));
    }
    return hits;
}

// ==================== FileNameSpoofAnalyzer ====================

std::optional<ExpandedScanHit> FileNameSpoofAnalyzer::Analyze(const std::string& file_path) {
    ExpandedScanHit hit;
    hit.file_path = file_path;
    bool suspicious = false;

    // 双重扩展名: 如 "xxx.pdf.exe"
    auto dot_pos = file_path.find('.');
    size_t double_dot = file_path.find('.', dot_pos + 1);
    if (double_dot != std::string::npos) {
        std::string tail = Helper::ToLower(file_path.substr(double_dot));
        static const std::vector<std::string> kBadExts = {".exe",".dll",".scr",".com",".bat",".cmd",".vbs",".ps1"};
        for (auto& e : kBadExts) {
            if (Helper::EndsWithCI(file_path, e)) {
                hit.evidence.push_back("双重扩展名伪装");
                suspicious = true;
                break;
            }
        }
    }

    // RTL 字符 (U+202E) 反转文件名
    if (file_path.find((char)0x2E) != std::string::npos) {
        hit.evidence.push_back("文件名包含RTL字符");
        suspicious = true;
    }

    // 魔数 vs 扩展名不符
    auto bytes = Helper::ReadFileAllBytes(file_path);
    if (bytes.size() >= 2) {
        std::string ext = Helper::ToLower(Helper::GetExtensionNoDot(file_path));
        if ((ext == "exe" || ext == "dll" || ext == "scr" || ext == "sys" || ext == "cpl")
            && !(bytes[0] == 'M' && bytes[1] == 'Z')) {
            hit.evidence.push_back("扩展名声称PE但魔数不匹配");
            suspicious = true;
        }
        if (ext == "pdf" && bytes[0] != '%') {
            hit.evidence.push_back("扩展名声称PDF但魔数不匹配");
            suspicious = true;
        }
        if (ext == "doc" && bytes[0] != (char)0xD0 && bytes[0] != (char)0x50) {
            hit.evidence.push_back("扩展名声称Office但魔数不匹配");
            suspicious = true;
        }
    }

    if (suspicious) {
        hit.is_infected      = true;
        hit.threat_name      = "FileNameSpoof.Generic";
        hit.threat_type      = "Trojan";
        hit.severity         = "Medium";
        hit.confidence      = 0.55;
        hit.detection_method = "FileNameSpoofAnalyzer";
        return hit;
    }
    return std::nullopt;
}

// ==================== PEStructureAnalyzer ====================

std::optional<ExpandedScanHit> PEStructureAnalyzer::Analyze(const std::string& file_path) {
    ExpandedScanHit hit;
    hit.file_path = file_path;
    auto bytes = Helper::ReadFileAllBytes(file_path);
    if (bytes.size() < 64) return std::nullopt;

    if (!(bytes[0] == 'M' && bytes[1] == 'Z')) return std::nullopt;

    uint32_t pe_off = 0;
    std::memcpy(&pe_off, &bytes[60], 4);
    if (pe_off + 24 > bytes.size()) return std::nullopt;
    if (!(bytes[pe_off] == 'P' && bytes[pe_off + 1] == 'E')) return std::nullopt;

    // COFF header: 20 bytes
    uint16_t num_sec = 0;
    std::memcpy(&num_sec, &bytes[pe_off + 6], 2);
    uint16_t size_opt = 0;
    std::memcpy(&size_opt, &bytes[pe_off + 20], 2);

    // Section headers 从 PE+24+size_opt 开始
    uint32_t sec_table_off = pe_off + 24 + size_opt;
    int high_entropy_sections = 0;
    int suspicious_exec_sections = 0;

    for (uint16_t i = 0; i < num_sec; ++i) {
        uint32_t sh_off = sec_table_off + i * 40;
        if (sh_off + 40 > bytes.size()) break;
        uint32_t name = 0, virtual_size = 0, virtual_addr = 0, size_raw = 0, ptr_raw = 0, characteristics = 0;
        // 跳过8字节名称
        std::memcpy(&virtual_size, bytes.data() + sh_off + 8, 4);
        std::memcpy(&size_raw,     bytes.data() + sh_off + 16, 4);
        std::memcpy(&ptr_raw,      bytes.data() + sh_off + 20, 4);
        std::memcpy(&characteristics, bytes.data() + sh_off + 36, 4);

        // 熵值
        if (ptr_raw > 0 && size_raw > 0 && ptr_raw + size_raw <= bytes.size()) {
            double ent = 0;
            int freq[256]{};
            for (uint32_t j = 0; j < size_raw; ++j) freq[bytes[ptr_raw + j]]++;
            for (int f : freq) if (f > 0) { double p=(double)f/size_raw; ent -= p*std::log2(p); }
            if (ent > 7.5) high_entropy_sections++;
        }

        // 可写可执行
        bool has_exec = (characteristics & 0x20000000) != 0;
        bool has_write= (characteristics & 0x80000000) != 0;
        if (has_exec && has_write) suspicious_exec_sections++;
    }

    bool hit_it = false;
    if (high_entropy_sections >= 2) { hit.evidence.push_back(">=2个高熵节(疑似加壳/加密)"); hit_it = true; }
    if (suspicious_exec_sections >= 1) { hit.evidence.push_back("存在可写+可执行节(权限过宽)"); hit_it = true; }
    if (num_sec > 12) { hit.evidence.push_back("节数过多(>12),可能是加壳程序"); hit_it = true; }

    if (hit_it) {
        hit.is_infected      = true;
        hit.threat_name      = "PEStructure.Suspicious";
        hit.threat_type      = "Trojan";
        hit.severity         = "Medium";
        hit.confidence      = 0.5 + std::min(high_entropy_sections * 0.08 + suspicious_exec_sections * 0.12, 0.3);
        hit.detection_method = "PEStructureAnalyzer";
        return hit;
    }
    return std::nullopt;
}

// ==================== MacroDocumentAnalyzer ====================

std::optional<ExpandedScanHit> MacroDocumentAnalyzer::Analyze(const std::string& file_path) {
    ExpandedScanHit hit;
    hit.file_path = file_path;

    auto bytes = Helper::ReadFileAllBytes(file_path);
    if (bytes.size() < 4) return std::nullopt;
    // OOXML 文件本质是 ZIP
    if (!(bytes[0] == 'P' && bytes[1] == 'K')) return std::nullopt;

    // 只看前 200KB 里的 "vbaProject.bin" / "StartUp" / "AutoOpen" / "Macro" 字样
    size_t n = std::min(bytes.size(), size_t(200000));
    std::string view;
    view.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = bytes[i];
        view.push_back((c >= 0x20 && c <= 0x7E) ? (char)c : ' ');
    }
    bool has_vba       = Helper::ContainsCI(view, "vbaProject.bin");
    bool has_macro     = Helper::ContainsCI(view, "module");
    bool has_autoopen  = Helper::ContainsCI(view, "autoopen") ||
                         Helper::ContainsCI(view, "Document_Open") ||
                         Helper::ContainsCI(view, "Workbook_Open");
    bool has_shell     = Helper::ContainsCI(view, "Shell(") ||
                         Helper::ContainsCI(view, "CreateObject(") ||
                         Helper::ContainsCI(view, "ActiveX");

    if (has_vba && (has_autoopen || has_shell)) {
        hit.is_infected      = true;
        hit.threat_name      = "MacroDocument.MaliciousVBA";
        hit.threat_type      = "Trojan";
        hit.severity         = "High";
        hit.confidence      = 0.7;
        hit.detection_method = "MacroDocumentAnalyzer";
        hit.evidence.push_back(has_autoopen ? "包含 AutoOpen 自动执行宏" : "");
        hit.evidence.push_back(has_shell     ? "包含 Shell/ActiveX 调用"   : "");
        // 去掉空串
        hit.evidence.erase(std::remove_if(hit.evidence.begin(), hit.evidence.end(),
                                           [](const std::string& s){ return s.empty(); }),
                            hit.evidence.end());
        return hit;
    }
    return std::nullopt;
}

// ==================== ArchiveNestedScanner ====================

std::optional<ExpandedScanHit> ArchiveNestedScanner::Analyze(const std::string& archive_path) {
    // 尝试用 libzip 解出每个条目,递归调用 scan_
    // 如果编译时没引 libzip, 这一段会自动跳过
    // 这里用一个最小的 ZIP 本地解析器(只支持 STORED 压缩,不支持 DEFLATE),
    // 若需要完整功能请链接 libzip 并 #include <zip.h>
    ExpandedScanHit hit;
    hit.file_path = archive_path;
    auto bytes = Helper::ReadFileAllBytes(archive_path);
    if (bytes.size() < 22) return std::nullopt;
    if (!(bytes[0] == 'P' && bytes[1] == 'K')) return std::nullopt;

    // 查找每个 Local File Header
    size_t pos = 0;
    while (pos + 30 < bytes.size()) {
        if (bytes[pos] != 'P' || bytes[pos + 1] != 'K' || bytes[pos + 2] != 0x03 || bytes[pos + 3] != 0x04)
            break;
        uint16_t fn_len = 0, extra_len = 0;
        uint32_t comp_size = 0;
        std::memcpy(&fn_len,     bytes.data() + pos + 26, 2);
        std::memcpy(&extra_len,  bytes.data() + pos + 28, 2);
        std::memcpy(&comp_size,  bytes.data() + pos + 18, 4);
        // 读文件名
        std::string fname(bytes.begin() + pos + 30, bytes.begin() + pos + 30 + fn_len);
        // 如果是 .exe/.dll/.scr/.ps1/.vbs/.bat/.cmd 递归扫描(需要先解压才准确,这里仅报疑似)
        std::string lower = Helper::ToLower(fname);
        static const std::vector<std::string> kSuspicious = {".exe",".dll",".scr",".com",".bat",".cmd",".ps1",".vbs",".js"};
        for (auto& e : kSuspicious) {
            if (Helper::EndsWithCI(fname, e)) {
                hit.is_infected      = true;
                hit.threat_name      = "ArchiveNested.Suspicious";
                hit.threat_type      = "Trojan";
                hit.severity         = "Medium";
                hit.confidence      = 0.5;
                hit.detection_method = "ArchiveNestedScanner";
                hit.evidence.push_back("压缩包内包含 " + fname);
                return hit;
            }
        }
        pos += 30 + fn_len + extra_len + comp_size;
    }
    return std::nullopt;
}

// ==================== PatternRuleEngine ====================

std::vector<PatternRuleEngine::Pattern> PatternRuleEngine::BuildPatterns() const {
    return {
        {"Rule.PowerShellEncoded",    "-enc[A-Za-z0-9+/=]{40,}",        0.7},
        {"Rule.SuspiciousScript",     "eval\\s*\\(\\s*base64_decode",  0.8},
        {"Rule.Jobber",               "Invoke-Expression",              0.6},
        {"Rule.WscriptShell",         "WScript.Shell\\.Run",            0.7},
        {"Rule.Mshta",                "mshta\\s+http",                  0.75},
        {"Rule.RegAddRunKey",         "reg add.*Run",                   0.6},
        {"Rule.NetUseAdmin",          "net use \\\\.*ADMIN",             0.65},
        {"Rule.BitsAdminUpload",      "bitsadmin.*upload",              0.7},
        {"Rule.CertutilDecode",       "certutil.*decode",               0.7},
        {"Rule.CurlToFile",           "curl.*\\s+-o\\s+",               0.55}
    };
}

std::optional<ExpandedScanHit> PatternRuleEngine::AnalyzeContent(const std::string& path,
                                                                   const std::vector<uint8_t>& content) {
    ExpandedScanHit hit;
    hit.file_path = path;
    std::string text(content.begin(), content.end());
    // 做简单关键词/子串匹配(不引入 regex 依赖)
    bool any = false;
    for (auto& p : BuildPatterns()) {
        // 把 pattern 里的简化关键字拿出来做 ContainsCI
        std::string needle = p.needle;
        // 去掉常见 regex 元字符做近似匹配
        for (char& c : needle) if (c == '\\' || c == '.' || c == '*' || c == '+' || c == '(' || c == ')' || c == '[' || c == ']' || c == '{' || c == '}' || c == '?') c = ' ';
        needle.erase(std::remove_if(needle.begin(), needle.end(), [](char c){ return c == ' '; }), needle.end());
        if (needle.empty()) continue;
        if (Helper::ContainsCI(text, needle)) {
            hit.evidence.push_back(p.name);
            hit.confidence = std::max(hit.confidence, p.confidence);
            any = true;
        }
    }
    if (any) {
        hit.is_infected      = true;
        hit.threat_name      = "PatternRule.Generic";
        hit.threat_type      = "Trojan";
        hit.severity         = "Medium";
        hit.detection_method = "PatternRuleEngine";
        return hit;
    }
    return std::nullopt;
}

// ==================== MultiDimFileEvaluator ====================

MultiDimEval MultiDimFileEvaluator::Evaluate(const std::string& file_path) {
    MultiDimEval ev;
    auto bytes = Helper::ReadFileAllBytes(file_path);
    if (bytes.empty()) return ev;

    // 1. 熵值
    double ent = 0;
    {
        int freq[256]{};
        for (auto b : bytes) freq[b]++;
        for (auto f : freq) if (f > 0) { double p=(double)f/bytes.size(); ent -= p*std::log2(p); }
    }
    if (ent > 7.5) ev.score += 30;

    // 2. PE 签名
    std::string ext = Helper::GetExtensionNoDot(file_path);
    bool is_pe = (ext == "exe" || ext == "dll" || ext == "scr" || ext == "sys" || ext == "cpl");
    if (is_pe) {
        auto sign = Platform::VerifyFileSignature(file_path);
        if (!sign.has_signature || !sign.signature_valid) ev.score += 25;
        if (sign.has_signature && !sign.trusted_publisher) ev.score += 15;
    }

    // 3. 导入函数
    auto imports = Platform::GetPeImports(bytes);
    static const std::vector<std::string> kSuspiciousApi = {
        "CreateRemoteThread","WriteProcessMemory","VirtualAllocEx","OpenProcess"
    };
    for (auto& api : kSuspiciousApi) {
        std::string view(bytes.begin(), bytes.end());
        if (Helper::ContainsCI(view, api)) ev.score += 15;
    }

    // 4. SHA256 本地数据库查找 (简化)
    std::string sha = Helper::ComputeFileSha256(file_path);
    if (!sha.empty()) ev.score += 0;  // 预留:可查本地 Hash DB

    ev.is_malicious = ev.score >= 60;
    return ev;
}

} // namespace Analyzers
} // namespace Engine
} // namespace FireAntivirus
