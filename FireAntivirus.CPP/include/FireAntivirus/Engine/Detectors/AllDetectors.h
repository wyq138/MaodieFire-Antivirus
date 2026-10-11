// FireAntivirus.CPP - 全部 12 类威胁检测器
// 移植自 FireAntivirus.Engine.ThreatDetectors
#pragma once

#include "FireAntivirus/Types.h"
#include <string>
#include <vector>
#include <cstdint>

namespace FireAntivirus {
namespace Engine {
namespace Detectors {

/// <summary>威胁检测器基类</summary>
class ThreatDetectorBase {
public:
    virtual ~ThreatDetectorBase() = default;
    virtual std::string Name() const = 0;
    virtual ThreatDetectorResult Detect(const std::string& file_path,
                                        const std::vector<uint8_t>& content) = 0;
};

// ---------- 12 类检测器 ----------

class ExploitDetector    : public ThreatDetectorBase {
public:
    std::string Name() const override { return "Exploit"; }
    ThreatDetectorResult Detect(const std::string& file_path, const std::vector<uint8_t>& content) override;
};
class RansomwareDetector : public ThreatDetectorBase {
public:
    std::string Name() const override { return "Ransomware"; }
    ThreatDetectorResult Detect(const std::string& file_path, const std::vector<uint8_t>& content) override;
};
class TrojanDetector     : public ThreatDetectorBase {
public:
    std::string Name() const override { return "Trojan"; }
    ThreatDetectorResult Detect(const std::string& file_path, const std::vector<uint8_t>& content) override;
};
class SpywareDetector    : public ThreatDetectorBase {
public:
    std::string Name() const override { return "Spyware"; }
    ThreatDetectorResult Detect(const std::string& file_path, const std::vector<uint8_t>& content) override;
};
class AdwareDetector     : public ThreatDetectorBase {
public:
    std::string Name() const override { return "Adware"; }
    ThreatDetectorResult Detect(const std::string& file_path, const std::vector<uint8_t>& content) override;
};
class KeyloggerDetector  : public ThreatDetectorBase {
public:
    std::string Name() const override { return "Keylogger"; }
    ThreatDetectorResult Detect(const std::string& file_path, const std::vector<uint8_t>& content) override;
};
class BackdoorDetector   : public ThreatDetectorBase {
public:
    std::string Name() const override { return "Backdoor"; }
    ThreatDetectorResult Detect(const std::string& file_path, const std::vector<uint8_t>& content) override;
};
class WormDetector       : public ThreatDetectorBase {
public:
    std::string Name() const override { return "Worm"; }
    ThreatDetectorResult Detect(const std::string& file_path, const std::vector<uint8_t>& content) override;
};
class VirusDetector      : public ThreatDetectorBase {
public:
    std::string Name() const override { return "Virus"; }
    ThreatDetectorResult Detect(const std::string& file_path, const std::vector<uint8_t>& content) override;
};
class MinerDetector      : public ThreatDetectorBase {
public:
    std::string Name() const override { return "Miner"; }
    ThreatDetectorResult Detect(const std::string& file_path, const std::vector<uint8_t>& content) override;
};
class PUPDetector        : public ThreatDetectorBase {
public:
    std::string Name() const override { return "PUP"; }
    ThreatDetectorResult Detect(const std::string& file_path, const std::vector<uint8_t>& content) override;
};

/// <summary>检测器工厂: 返回全部 12 个检测器</summary>
std::vector<std::unique_ptr<ThreatDetectorBase>> CreateAllDetectors();

} // namespace Detectors
} // namespace Engine
} // namespace FireAntivirus
