// FireAntivirus.CPP - 全部 12 类威胁检测器实现
// 移植自 FireAntivirus.Engine.ThreatDetectors.cs
// 每个检测器扫描文件内容中的特征字符串/API/节熵/导入函数
#include "FireAntivirus/Engine/Detectors/AllDetectors.h"
#include "FireAntivirus/Helper.h"
#include <algorithm>
#include <string>
#include <cmath>

namespace FireAntivirus {
namespace Engine {
namespace Detectors {

namespace {

// 把任意字节缓冲区转成可检索的 ASCII 字符串 (取 printable 范围)
std::string bytes_to_ascii_view(const std::vector<uint8_t>& data, size_t max = 100000) {
    std::string out;
    size_t n = std::min(data.size(), max);
    out.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = data[i];
        if (c >= 0x20 && c <= 0x7E) out.push_back((char)c);
        else out.push_back(' ');
    }
    return out;
}

bool contains_any_ci(const std::string& text, const std::vector<std::string>& needles) {
    for (auto& n : needles) {
        if (Helper::ContainsCI(text, n)) return true;
    }
    return false;
}

double section_entropy(const std::vector<uint8_t>& data, size_t off, size_t len) {
    if (off + len > data.size()) return 0;
    int freq[256]{};
    for (size_t i = 0; i < len; ++i) freq[data[off + i]]++;
    double ent = 0;
    for (auto f : freq) {
        if (f > 0) {
            double p = (double)f / len;
            ent -= p * std::log2(p);
        }
    }
    return ent;
}

} // anon

// ==================== Exploit ====================
ThreatDetectorResult ExploitDetector::Detect(const std::string&, const std::vector<uint8_t>& content) {
    ThreatDetectorResult r;
    if (content.empty()) return r;
    auto t = bytes_to_ascii_view(content);
    static const std::vector<std::string> pats = {
        "ROP gadget","VirtualProtect","shellcode","nop sled","Int 0x2e",
        "KiRaiseException","StackOverflow","HeapOverflow","GdiSetADCnt","UseAfterFree",
        "BufferOverflow","GS cookie","__security_cookie","NtQueryInformationProcess"
    };
    int hit = 0;
    for (auto& p : pats) if (Helper::ContainsCI(t, p)) hit++;
    if (hit >= 2) {
        r.is_detected = true;
        r.threat_name = "Exploit.Generic";
        r.threat_type = "Exploit";
        r.confidence = std::min(0.5 + hit * 0.1, 0.9);
        r.details = "Exploit特征命中";
    }
    return r;
}

// ==================== Ransomware ====================
ThreatDetectorResult RansomwareDetector::Detect(const std::string&, const std::vector<uint8_t>& content) {
    ThreatDetectorResult r;
    if (content.empty()) return r;
    auto t = bytes_to_ascii_view(content);
    static const std::vector<std::string> pats = {
        "CryptEncrypt","CryptAcquireContext","Aes.Create","RSA.Encrypt",
        "GetFiles","EnumerateFiles","Directory.GetFiles","for * in",
        "vssadmin","delete shadows","shadowcopy","bcdedit /set recoveryenabled",
        "BitLocker",".locked",".enc",".crypz","personal_key.txt","README_DECRYPT"
    };
    int hit = 0;
    for (auto& p : pats) if (Helper::ContainsCI(t, p)) hit++;
    if (hit >= 2) {
        r.is_detected = true;
        r.threat_name = "Ransomware.Generic";
        r.threat_type = "Ransomware";
        r.confidence = std::min(0.55 + hit * 0.1, 0.92);
        r.details = "勒索行为特征命中(加密+批量文件访问)";
    }
    return r;
}

// ==================== Trojan ====================
ThreatDetectorResult TrojanDetector::Detect(const std::string&, const std::vector<uint8_t>& content) {
    ThreatDetectorResult r;
    if (content.empty()) return r;
    auto t = bytes_to_ascii_view(content);
    static const std::vector<std::string> pats = {
        "CreateRemoteThread","WriteProcessMemory","VirtualAllocEx","NtWriteVirtualMemory",
        "OpenProcess","SeDebugPrivilege","LoadLibrary","GetProcAddress",
        "reg add","schtasks","cmd /c","powershell -enc","Mshta.exe",
        "rundll32","regsvr32","msiexec /i"
    };
    int hit = 0;
    for (auto& p : pats) if (Helper::ContainsCI(t, p)) hit++;
    if (hit >= 3) {
        r.is_detected = true;
        r.threat_name = "Trojan.Generic";
        r.threat_type = "Trojan";
        r.confidence = std::min(0.55 + hit * 0.08, 0.9);
        r.details = "木马行为特征(进程注入+远程shell)";
    }
    return r;
}

// ==================== Spyware ====================
ThreatDetectorResult SpywareDetector::Detect(const std::string&, const std::vector<uint8_t>& content) {
    ThreatDetectorResult r;
    if (content.empty()) return r;
    auto t = bytes_to_ascii_view(content);
    static const std::vector<std::string> pats = {
        "SetWindowsHookEx","WH_KEYBOARD_LL","GetAsyncKeyState","RegisterHotKey",
        "BitBlt","GetDC","keybd_event","GetForegroundWindow","GetWindowText",
        "Clipboard","OpenClipboard","GetClipboardData","WebBrowser1","HttpPost",
        "FTP upload","POST /steal"
    };
    int hit = 0;
    for (auto& p : pats) if (Helper::ContainsCI(t, p)) hit++;
    if (hit >= 2) {
        r.is_detected = true;
        r.threat_name = "Spyware.KeyloggerLike";
        r.threat_type = "Spyware";
        r.confidence = std::min(0.5 + hit * 0.1, 0.85);
        r.details = "键盘/截屏/剪贴板监控特征";
    }
    return r;
}

// ==================== Adware ====================
ThreatDetectorResult AdwareDetector::Detect(const std::string&, const std::vector<uint8_t>& content) {
    ThreatDetectorResult r;
    if (content.empty()) return r;
    auto t = bytes_to_ascii_view(content);
    static const std::vector<std::string> pats = {
        "InstallMonster","Conduit","SearchProtect","MySearchDial","SweetIM",
        "BrowserHelperObject","BHO","CLSID\\{00000000-0000-0000-0000-000000000000}",
        "startpage","newtab","chrome-extension","toolbar"
    };
    int hit = 0;
    for (auto& p : pats) if (Helper::ContainsCI(t, p)) hit++;
    if (hit >= 3) {
        r.is_detected = true;
        r.threat_name = "Adware.Generic";
        r.threat_type = "Adware";
        r.confidence = std::min(0.45 + hit * 0.08, 0.8);
        r.details = "广告软件/浏览器劫持特征";
    }
    return r;
}

// ==================== Keylogger ====================
ThreatDetectorResult KeyloggerDetector::Detect(const std::string&, const std::vector<uint8_t>& content) {
    ThreatDetectorResult r;
    if (content.empty()) return r;
    auto t = bytes_to_ascii_view(content);
    static const std::vector<std::string> pats = {
        "WH_KEYBOARD","WH_KEYBOARD_LL","WH_MOUSE_LL","SetWindowsHookEx",
        "GetAsyncKeyState","GetKeyState","keybd_event","VK_ENTER","VK_TAB","VK_SPACE",
        "keylog","keystroke","savekeys","passw","password.txt"
    };
    int hit = 0;
    for (auto& p : pats) if (Helper::ContainsCI(t, p)) hit++;
    if (hit >= 2) {
        r.is_detected = true;
        r.threat_name = "Keylogger.Generic";
        r.threat_type = "Keylogger";
        r.confidence = std::min(0.55 + hit * 0.1, 0.9);
        r.details = "键盘记录器特征";
    }
    return r;
}

// ==================== Backdoor ====================
ThreatDetectorResult BackdoorDetector::Detect(const std::string&, const std::vector<uint8_t>& content) {
    ThreatDetectorResult r;
    if (content.empty()) return r;
    auto t = bytes_to_ascii_view(content);
    static const std::vector<std::string> pats = {
        "ReverseShell","cmd.exe /c","/bin/sh -c","nc -e","netcat","winsock bind",
        "listen()","accept()","connect()","CreateService","SC_MANAGER",
        "Port 4444","Port 5555","bind 0.0.0.0","meterpreter","CobaltStrike",
        "beacon","shellcode","socat","ncat","backdoor"
    };
    int hit = 0;
    for (auto& p : pats) if (Helper::ContainsCI(t, p)) hit++;
    if (hit >= 2) {
        r.is_detected = true;
        r.threat_name = "Backdoor.Generic";
        r.threat_type = "Backdoor";
        r.confidence = std::min(0.5 + hit * 0.1, 0.88);
        r.details = "后门/远程访问特征";
    }
    return r;
}

// ==================== Worm ====================
ThreatDetectorResult WormDetector::Detect(const std::string&, const std::vector<uint8_t>& content) {
    ThreatDetectorResult r;
    if (content.empty()) return r;
    auto t = bytes_to_ascii_view(content);
    static const std::vector<std::string> pats = {
        "smbclient","net use \\\\\\","IPC$","ADMIN$","C$","D$","E$",
        "WMI","Win32_Process","Create(")","mshta http","autorun.inf","open=",
        "p2p","worm","Conficker","WannaCry","USB spread","share folder"
    };
    int hit = 0;
    for (auto& p : pats) if (Helper::ContainsCI(t, p)) hit++;
    if (hit >= 2) {
        r.is_detected = true;
        r.threat_name = "Worm.Generic";
        r.threat_type = "Worm";
        r.confidence = std::min(0.5 + hit * 0.08, 0.85);
        r.details = "蠕虫传播特征(SMB/USB/网络)";
    }
    return r;
}

// ==================== Virus ====================
ThreatDetectorResult VirusDetector::Detect(const std::string& path, const std::vector<uint8_t>& content) {
    ThreatDetectorResult r;
    if (content.empty()) return r;
    auto t = bytes_to_ascii_view(content);
    // 高熵 + 自修改 + 节可写可执行
    double ent = section_entropy(content, 0, content.size());
    static const std::vector<std::string> pats = {
        "VirtualProtect","PAGE_EXECUTE_READWRITE","PAGE_EXECUTE_WRITECOPY",
        "self-modifying","infects","EP section","EntryPoint","relocatable","write PE header",
        "append to file","appending virus"
    };
    int hit = 0;
    for (auto& p : pats) if (Helper::ContainsCI(t, p)) hit++;
    bool high_entropy = ent > 7.2;
    if ((hit >= 2) || (hit >= 1 && high_entropy)) {
        r.is_detected = true;
        r.threat_name = "Virus.Generic";
        r.threat_type = "Virus";
        r.confidence = std::min(0.5 + hit * 0.1 + (high_entropy ? 0.15 : 0), 0.9);
        r.details = high_entropy ? "高熵自解密+自修改病毒特征" : "病毒特征";
    }
    return r;
}

// ==================== Miner ====================
ThreatDetectorResult MinerDetector::Detect(const std::string&, const std::vector<uint8_t>& content) {
    ThreatDetectorResult r;
    if (content.empty()) return r;
    auto t = bytes_to_ascii_view(content);
    static const std::vector<std::string> pats = {
        "stratum+tcp","stratum+ssl","x.pool.zpool","stratum.f2pool",
        "xmrig","cgminer","bfgminer","nicehash","miningpoolhub","hashrefinery",
        "wallet","bitcoin","ethereum","monero","cryptonight","RandomX","hashrate"
    };
    int hit = 0;
    for (auto& p : pats) if (Helper::ContainsCI(t, p)) hit++;
    if (hit >= 2) {
        r.is_detected = true;
        r.threat_name = "Miner.Generic";
        r.threat_type = "Miner";
        r.confidence = std::min(0.6 + hit * 0.08, 0.92);
        r.details = "挖矿程序特征(矿池+钱包+算法)";
    }
    return r;
}

// ==================== PUP (Potentially Unwanted Program) ====================
ThreatDetectorResult PUPDetector::Detect(const std::string&, const std::vector<uint8_t>& content) {
    ThreatDetectorResult r;
    if (content.empty()) return r;
    auto t = bytes_to_ascii_view(content);
    static const std::vector<std::string> pats = {
        "bundleware","installcore","rebrogen","openinstall","softplus",
        "conduit toolbar","browse2save","browser guardian","dealply","lyrics",
        "desktop toolbar","optimizer","cleaner","PC Accelerator","registry cleaner",
        "toolbar","extension","installs additional offers"
    };
    int hit = 0;
    for (auto& p : pats) if (Helper::ContainsCI(t, p)) hit++;
    if (hit >= 2) {
        r.is_detected = true;
        r.threat_name = "PUP.Generic";
        r.threat_type = "PUP";
        r.confidence = std::min(0.4 + hit * 0.08, 0.75);
        r.details = "可疑程序/捆绑软件特征";
    }
    return r;
}

// ==================== 工厂 ====================

std::vector<std::unique_ptr<ThreatDetectorBase>> CreateAllDetectors() {
    std::vector<std::unique_ptr<ThreatDetectorBase>> v;
    v.push_back(std::make_unique<ExploitDetector>());
    v.push_back(std::make_unique<RansomwareDetector>());
    v.push_back(std::make_unique<TrojanDetector>());
    v.push_back(std::make_unique<SpywareDetector>());
    v.push_back(std::make_unique<AdwareDetector>());
    v.push_back(std::make_unique<KeyloggerDetector>());
    v.push_back(std::make_unique<BackdoorDetector>());
    v.push_back(std::make_unique<WormDetector>());
    v.push_back(std::make_unique<VirusDetector>());
    v.push_back(std::make_unique<MinerDetector>());
    v.push_back(std::make_unique<PUPDetector>());
    return v;
}

} // namespace Detectors
} // namespace Engine
} // namespace FireAntivirus
