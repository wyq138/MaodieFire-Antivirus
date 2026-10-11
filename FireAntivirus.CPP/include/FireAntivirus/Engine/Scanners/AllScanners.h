// FireAntivirus.CPP - 扫描器合集
// 移植自 FireAntivirus.Engine.Scanners (Memory / Registry / Network / Startup / Process / AntiRootkit / Vulnerability)
#pragma once

#include "FireAntivirus/Types.h"
#include <string>
#include <vector>
#include <cstdint>

namespace FireAntivirus {
namespace Engine {
namespace Scanners {

// ==================== MemoryScanner ====================

class MemoryScanner {
public:
    /// <summary>扫描指定 PID 的进程内存,寻找可疑特征</summary>
    std::vector<ScanResult> ScanProcess(uint32_t pid);

    /// <summary>扫描全部进程内存</summary>
    std::vector<ScanResult> ScanAll();
};

// ==================== RegistryScanner ====================

class RegistryScanner {
public:
    /// <summary>扫描启动项 Run/RunOnce/Services</summary>
    std::vector<ScanResult> ScanAutorunKeys();

    /// <summary>扫描全注册表可疑键</summary>
    std::vector<ScanResult> ScanSuspiciousKeys();
};

// ==================== NetworkScanner ====================

struct NetworkConnection {
    uint32_t pid        = 0;
    std::string local_ip;
    uint16_t local_port = 0;
    std::string remote_ip;
    uint16_t remote_port = 0;
    std::string protocol; // "TCP" / "UDP"
    std::string state;    // "LISTENING" / "ESTABLISHED" / ...
};

class NetworkScanner {
public:
    std::vector<NetworkConnection> EnumConnections();
    std::vector<ScanResult> ScanConnections();
};

// ==================== StartupScanner ====================

struct StartupItem {
    std::string name;
    std::string location;     // 注册路径或文件夹路径
    std::string command;      // 执行命令
    bool        is_signed     = false;
};

class StartupScanner {
public:
    std::vector<StartupItem> EnumAll();
    std::vector<ScanResult> ScanItems();
};

// ==================== ProcessScanner ====================

class ProcessScanner {
public:
    /// <summary>枚举所有进程并判定可疑</summary>
    std::vector<ScanResult> ScanAll();
};

// ==================== AntiRootkitScanner ====================

class AntiRootkitScanner {
public:
    /// <summary>检测隐藏进程 / 内核钩子 / 驱动异常</summary>
    std::vector<ScanResult> Scan();
};

// ==================== VulnerabilityScanner ====================

struct VulnerabilityInfo {
    std::string cve_id;
    std::string title;
    std::string description;
    std::string severity;  // Low / Medium / High / Critical
    std::string affected_product;
    std::string fix_version;
};

class VulnerabilityScanner {
public:
    /// <summary>扫描系统版本/补丁状态,判定已知漏洞</summary>
    std::vector<VulnerabilityInfo> ScanSystem();
    std::vector<ScanResult> ScanAll();
};

} // namespace Scanners
} // namespace Engine
} // namespace FireAntivirus
