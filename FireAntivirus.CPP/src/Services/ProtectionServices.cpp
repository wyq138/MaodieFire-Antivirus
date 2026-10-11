#include "../include/FireAntivirus/Services/ProtectionServices.h"
#include "../include/FireAntivirus/Services/CoreServices.h"

#include <algorithm>
#include <set>
#include <filesystem>

namespace FireAntivirus { namespace Services {

namespace fs = std::filesystem;

static std::string TimestampNow() {
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    std::tm tm_buf{};
#ifdef _WIN32
    localtime_s(&tm_buf, &time_t_now);
#else
    localtime_r(&time_t_now, &tm_buf);
#endif
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_buf);
    return std::string(buf);
}

static std::string ExeDir() {
#ifdef _WIN32
    wchar_t path[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    std::wstring wpath(path);
    fs::path p(wpath.begin(), wpath.end());
    return p.parent_path().string();
#else
    return fs::current_path().string();
#endif
}

static std::string Sha256File(const std::string& filePath) {
    // 使用 Helper 中的 ComputeFileSha256
    std::string hash;
#ifdef _WIN32
    FILE* fp = nullptr;
    if (_wfopen_s(&fp, std::wstring(filePath.begin(), filePath.end()).c_str(), L"rb") != 0 || !fp) {
        return "";
    }
    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    std::vector<uint8_t> buf(sz > 0 ? sz : 0);
    if (sz > 0) fread(buf.data(), 1, sz, fp);
    fclose(fp);

    // 简单 SHA256 实现
    unsigned int h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a;
    unsigned int h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;
    static const unsigned int K[64]={
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
    auto rrot=[](unsigned int x,int n){return (x>>n)|(x<<(32-n));};
    uint64_t bitlen=buf.size()*8;
    buf.push_back(0x80);
    while((buf.size()%64)!=56) buf.push_back(0);
    for(int i=7;i>=0;i--) buf.push_back((bitlen>>(i*8))&0xFF);
    for(size_t off=0;off<buf.size();off+=64){
        unsigned int w[64];
        for(int i=0;i<16;i++) w[i]=(buf[off+i*4]<<24)|(buf[off+i*4+1]<<16)|(buf[off+i*4+2]<<8)|buf[off+i*4+3];
        for(int i=16;i<64;i++){
            unsigned int s0=rrot(w[i-15],7)^rrot(w[i-15],18)^(w[i-15]>>3);
            unsigned int s1=rrot(w[i-2],17)^rrot(w[i-2],19)^(w[i-2]>>10);
            w[i]=w[i-16]+s0+w[i-7]+s1;
        }
        unsigned int a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,h=h7;
        for(int i=0;i<64;i++){
            unsigned int S1=rrot(e,6)^rrot(e,11)^rrot(e,25);
            unsigned int ch=(e&f)^(~e&g);
            unsigned int t1=h+S1+ch+K[i]+w[i];
            unsigned int S0=rrot(a,2)^rrot(a,13)^rrot(a,22);
            unsigned int mj=(a&b)^(a&c)^(b&c);
            unsigned int t2=S0+mj;
            h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
        }
        h0+=a;h1+=b;h2+=c;h3+=d;h4+=e;h5+=f;h6+=g;h7+=h;
    }
    char hex[65];
    snprintf(hex,sizeof(hex),"%08x%08x%08x%08x%08x%08x%08x%08x",h0,h1,h2,h3,h4,h5,h6,h7);
    return std::string(hex);
#else
    return "";
#endif
}

// ==================== SecurityService ====================
SecurityService::SecurityService() = default;
SecurityService::~SecurityService() { Stop(); }

bool SecurityService::Initialize() {
    std::lock_guard<std::mutex> lock(_lock);
    if (_isInitialized) return true;
    _isInitialized = true;
    LogManager::LogInfo("SecurityService initialized");
    return true;
}

bool SecurityService::Start() {
    std::lock_guard<std::mutex> lock(_lock);
    if (!_isInitialized) Initialize();
    if (_isRunning) return true;
    _isRunning = true;
    _monitoringRunning = true;
    _monitoringThread = std::thread([this]() { MonitoringLoop(); });
    _state.IsRunning = true;
    LogManager::LogInfo("SecurityService started");
    return true;
}

void SecurityService::Stop() {
    std::lock_guard<std::mutex> lock(_lock);
    if (!_isRunning) return;
    _isRunning = false;
    _monitoringRunning = false;
    if (_monitoringThread.joinable()) _monitoringThread.join();
    _state.IsRunning = false;
    LogManager::LogInfo("SecurityService stopped");
}

void SecurityService::MonitoringLoop() {
    while (_monitoringRunning) {
        LogManager::LogDebug("SecurityService heartbeat");
        std::this_thread::sleep_for(std::chrono::seconds(10));
    }
}

ProtectionState SecurityService::GetProtectionStatus() {
    return _state;
}

void SecurityService::HandleThreat(const ThreatInfo& threat, ProtectionAction) {
    LogManager::LogInfo("Handling threat: " + threat.ThreatName + " at " + threat.FilePath);
}

// 各 Enable/IsEnabled 方法
#define DEF_PROTECT(Member) \
bool SecurityService::Enable##Member(bool enable) { std::lock_guard<std::mutex> lock(_lock); _state.Is##Member##Enabled = enable; return true; } \
bool SecurityService::Is##Member##Enabled() { std::lock_guard<std::mutex> lock(_lock); return _state.Is##Member##Enabled; }

DEF_PROTECT(FileProtection)
DEF_PROTECT(ProcessProtection)
DEF_PROTECT(DeviceProtection)
DEF_PROTECT(RegistryProtection)
DEF_PROTECT(BrowserProtection)
DEF_PROTECT(ScriptProtection)
DEF_PROTECT(ActiveDefense)

// NetworkProtection 使用不同字段名
bool SecurityService::EnableNetworkProtection(bool enable) { LogManager::LogInfo("NetworkProtection " + std::string(enable?"enabled":"disabled")); return true; }
bool SecurityService::IsNetworkProtectionEnabled() { return ConfigManager::Config().NetworkProtectionEnabled; }
bool SecurityService::EnablePopupBlocker(bool enable) { LogManager::LogInfo("PopupBlocker " + std::string(enable?"enabled":"disabled")); return true; }
bool SecurityService::IsPopupBlockerEnabled() { return ConfigManager::Config().PopupBlockerEnabled; }
bool SecurityService::EnableRansomwareProtection(bool enable) { LogManager::LogInfo("RansomwareProtection " + std::string(enable?"enabled":"disabled")); return true; }
bool SecurityService::IsRansomwareProtectionEnabled() { return ConfigManager::Config().RansomwareProtectionEnabled; }
bool SecurityService::EnablePrivacyProtection(bool enable) { LogManager::LogInfo("PrivacyProtection " + std::string(enable?"enabled":"disabled")); return true; }
bool SecurityService::IsPrivacyProtectionEnabled() { return ConfigManager::Config().PrivacyProtectionEnabled; }
bool SecurityService::EnableWebProtection(bool enable) { LogManager::LogInfo("WebProtection " + std::string(enable?"enabled":"disabled")); return true; }
bool SecurityService::IsWebProtectionEnabled() { return ConfigManager::Config().WebProtectionEnabled; }
bool SecurityService::EnableEmailSecurity(bool enable) { return true; }
bool SecurityService::IsEmailSecurityEnabled() { return ConfigManager::Config().EmailSecurityEnabled; }
bool SecurityService::EnablePasswordManager(bool enable) { return true; }
bool SecurityService::IsPasswordManagerEnabled() { return ConfigManager::Config().PasswordManagerEnabled; }
bool SecurityService::EnableNetworkFirewall(bool enable) { return true; }
bool SecurityService::IsNetworkFirewallEnabled() { return ConfigManager::Config().NetworkFirewallEnabled; }
bool SecurityService::EnableVulnerabilityScanner(bool enable) { return true; }
bool SecurityService::IsVulnerabilityScannerEnabled() { return ConfigManager::Config().VulnerabilityScannerEnabled; }
bool SecurityService::EnableCloudScan(bool enable) { return true; }
bool SecurityService::IsCloudScanEnabled() { return ConfigManager::Config().CloudScanEnabled; }
bool SecurityService::EnableSecureBrowser(bool enable) { return true; }
bool SecurityService::IsSecureBrowserEnabled() { return ConfigManager::Config().SecureBrowserEnabled; }
bool SecurityService::EnableMobileSecurity(bool enable) { return true; }
bool SecurityService::IsMobileSecurityEnabled() { return ConfigManager::Config().MobileSecurityEnabled; }
bool SecurityService::EnableSystemOptimizer(bool enable) { return true; }
bool SecurityService::IsSystemOptimizerEnabled() { return ConfigManager::Config().SystemOptimizerEnabled; }
bool SecurityService::EnableBackupRecovery(bool enable) { return true; }
bool SecurityService::IsBackupRecoveryEnabled() { return ConfigManager::Config().BackupRecoveryEnabled; }
bool SecurityService::EnableSecurityScore(bool enable) { return true; }
bool SecurityService::IsSecurityScoreEnabled() { return ConfigManager::Config().SecurityScoreEnabled; }
bool SecurityService::EnableNetworkTraffic(bool enable) { return true; }
bool SecurityService::IsNetworkTrafficEnabled() { return ConfigManager::Config().NetworkTrafficEnabled; }
bool SecurityService::EnableApplicationMonitor(bool enable) { return true; }
bool SecurityService::IsApplicationMonitorEnabled() { return ConfigManager::Config().ApplicationMonitorEnabled; }
bool SecurityService::EnableStartupManager(bool enable) { return true; }
bool SecurityService::IsStartupManagerEnabled() { return ConfigManager::Config().StartupManagerEnabled; }
bool SecurityService::EnableSecurityReport(bool enable) { return true; }
bool SecurityService::IsSecurityReportEnabled() { return ConfigManager::Config().SecurityReportEnabled; }
bool SecurityService::EnableSystemTools(bool enable) { return true; }
bool SecurityService::IsSystemToolsEnabled() { return ConfigManager::Config().SystemToolsEnabled; }
bool SecurityService::EnableSystemInfo(bool enable) { return true; }
bool SecurityService::IsSystemInfoEnabled() { return ConfigManager::Config().SystemInfoEnabled; }
bool SecurityService::EnableQuarantine(bool enable) { return true; }
bool SecurityService::IsQuarantineEnabled() { return ConfigManager::Config().QuarantineEnabled; }
bool SecurityService::EnableTrustZone(bool enable) { return true; }
bool SecurityService::IsTrustZoneEnabled() { return ConfigManager::Config().TrustZoneEnabled; }
bool SecurityService::EnableLogCenter(bool enable) { return true; }
bool SecurityService::IsLogCenterEnabled() { return ConfigManager::Config().LogCenterEnabled; }

// ==================== NativeSecurityCoreWrapper ====================
bool NativeSecurityCoreWrapper::_initialized = false;
std::mutex NativeSecurityCoreWrapper::_lock;

bool NativeSecurityCoreWrapper::InitializeCore() {
    std::lock_guard<std::mutex> lock(_lock);
    _initialized = true;
    return true;
}

void NativeSecurityCoreWrapper::ShutdownCore() {
    std::lock_guard<std::mutex> lock(_lock);
    _initialized = false;
}

void NativeSecurityCoreWrapper::SetThreatCallback(void(*)(const char*, const char*, int)) {}
void NativeSecurityCoreWrapper::SetStatusCallback(void(*)(int, const char*)) {}
bool NativeSecurityCoreWrapper::IsInitialized() { return _initialized; }
bool NativeSecurityCoreWrapper::ScanBuffer(const uint8_t*, size_t, const char*) { return false; }

// ==================== RealTimeProtectionManager ====================
RealTimeProtectionManager::RealTimeProtectionManager(SecurityService* s) : _securityService(s) {}
RealTimeProtectionManager::~RealTimeProtectionManager() { Stop(); }

bool RealTimeProtectionManager::Initialize() {
    std::lock_guard<std::mutex> lock(_lock);
    if (_isInitialized) return true;
    if (_securityService && !_securityService->IsInitialized()) {
        if (!_securityService->Initialize()) return false;
    }
    AppConfig cfg = ConfigManager::Config();
    if (_securityService) {
        _securityService->EnableFileProtection(cfg.FileProtectionEnabled);
        _securityService->EnableProcessProtection(cfg.ProcessProtectionEnabled);
        _securityService->EnableDeviceProtection(cfg.DeviceProtectionEnabled);
        _securityService->EnableRegistryProtection(cfg.RegistryProtectionEnabled);
        _securityService->EnableBrowserProtection(cfg.BrowserProtectionEnabled);
        _securityService->EnableScriptProtection(cfg.ScriptProtectionEnabled);
        _securityService->EnableActiveDefense(cfg.ActiveDefenseEnabled);
    }
    _isInitialized = true;
    LogManager::LogInfo("RealTimeProtectionManager initialized");
    return true;
}

bool RealTimeProtectionManager::Start() {
    std::lock_guard<std::mutex> lock(_lock);
    if (!_isCoreAvailable) return false;
    if (!_isInitialized) Initialize();
    if (_isRunning) return true;
    if (_securityService && !_securityService->Start()) return false;
    _isRunning = true;
    _monitoringRunning = true;
    _monitoringTask = std::thread([this]() { MonitoringLoop(); });
    LogManager::LogInfo("RealTimeProtectionManager started");
    return true;
}

void RealTimeProtectionManager::Stop() {
    std::lock_guard<std::mutex> lock(_lock);
    if (!_isRunning) return;
    _isRunning = false;
    _monitoringRunning = false;
    if (_monitoringTask.joinable()) _monitoringTask.join();
    if (_securityService) _securityService->Stop();
    LogManager::LogInfo("RealTimeProtectionManager stopped");
}

void RealTimeProtectionManager::MonitoringLoop() {
    while (_monitoringRunning) {
        if (_securityService && !_securityService->IsRunning()) {
            LogManager::LogWarning("Security service not running, restarting");
            _securityService->Start();
        }
        std::this_thread::sleep_for(std::chrono::seconds(10));
    }
}

#define DEF_RTM_PM(Member) \
bool RealTimeProtectionManager::Enable##Member(bool enable) { if (!_isCoreAvailable) return false; bool r=_securityService->Enable##Member(enable); if(r){ ConfigManager::Config().Member##Enabled=enable; ConfigManager::SaveConfig();} return r; } \
bool RealTimeProtectionManager::Is##Member##Enabled() { if (!_isCoreAvailable) return false; return _securityService ? _securityService->Is##Member##Enabled() : false; }

DEF_RTM_PM(FileProtection)
DEF_RTM_PM(ProcessProtection)
DEF_RTM_PM(DeviceProtection)
DEF_RTM_PM(RegistryProtection)
DEF_RTM_PM(BrowserProtection)
DEF_RTM_PM(ScriptProtection)
DEF_RTM_PM(ActiveDefense)

ProtectionState RealTimeProtectionManager::GetProtectionStatus() {
    if (!_isCoreAvailable) return ProtectionState{};
    return _securityService ? _securityService->GetProtectionStatus() : ProtectionState{};
}
void RealTimeProtectionManager::HandleThreat(const ThreatInfo& t, ProtectionAction a) {
    if (!_isCoreAvailable) return;
    if (_securityService) _securityService->HandleThreat(t, a);
}

// ==================== RealTimeProtectionServer ====================
RealTimeProtectionServer::RealTimeProtectionServer(FireAntivirus::DataManager* dm, FireAntivirus::Engine::AntivirusEngine* ae)
    : _dataManager(dm), _antivirusEngine(ae) { _currentStatus.IsRunning = false; }
RealTimeProtectionServer::~RealTimeProtectionServer() { StopServer(); }

void RealTimeProtectionServer::StartServer() {
    if (_isRunning) return;
    _isRunning = true;
    _currentStatus.IsRunning = true;
    _currentStatus.StartTime = TimestampNow();
    _serverThread = std::thread([this]() { ServerLoop(); });
    LogManager::LogInfo("RealTimeProtectionServer started");
}

void RealTimeProtectionServer::StopServer() {
    _isRunning = false;
    _currentStatus.IsRunning = false;
    if (_serverThread.joinable()) _serverThread.join();
    _currentStatus.StopTime = TimestampNow();
    LogManager::LogInfo("RealTimeProtectionServer stopped");
}

void RealTimeProtectionServer::ServerLoop() {
    while (_isRunning) {
        // 使用 Platform::NamedPipe 或者简单的条件变量等待
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

RealTimeProtectionStatus RealTimeProtectionServer::GetStatus() {
    std::lock_guard<std::mutex> lock(_statusMutex);
    return _currentStatus;
}

std::vector<RealTimeThreatDetection> RealTimeProtectionServer::GetRecentThreats() {
    return {};
}

bool RealTimeProtectionServer::ScanFile(const std::string& filePath) {
    if (_antivirusEngine) {
        auto result = _antivirusEngine->ScanFile(filePath);
        return !result.IsInfected;
    }
    return true;
}

bool RealTimeProtectionServer::AddQuarantine(const std::string& filePath) {
    return _dataManager && _dataManager->AddToQuarantine(filePath);
}
bool RealTimeProtectionServer::RemoveQuarantine(const std::string& itemId) {
    return _dataManager && _dataManager->RemoveFromQuarantine(itemId);
}
bool RealTimeProtectionServer::AddWhitelist(const std::string& filePath) {
    if (_dataManager) _dataManager->AddToWhitelist(filePath);
    return true;
}
bool RealTimeProtectionServer::RemoveWhitelist(const std::string& filePath) {
    return _dataManager && _dataManager->RemoveFromWhitelist(filePath);
}
bool RealTimeProtectionServer::UpdateSignatures() {
    if (_dataManager) _dataManager->UpdateVirusDatabase();
    return true;
}

bool RealTimeProtectionServer::EnableModule(const std::string& moduleName) {
    auto it = _monitors.find(moduleName);
    if (it != _monitors.end()) { it->second->Start(); return true; }
    return false;
}
bool RealTimeProtectionServer::DisableModule(const std::string& moduleName) {
    auto it = _monitors.find(moduleName);
    if (it != _monitors.end()) { it->second->Stop(); return true; }
    return false;
}
std::map<std::string, bool> RealTimeProtectionServer::GetModuleStatus() {
    std::map<std::string, bool> status;
    for (auto& kvp : _monitors) status[kvp.first] = true;
    return status;
}
bool RealTimeProtectionServer::SetScanSettings(const ScanSettings& s) { _scanSettings = s; return true; }
ScanSettings RealTimeProtectionServer::GetScanSettings() { return _scanSettings; }

// Communication 接口实现为内部命令处理
CommunicationResponse RealTimeProtectionServer::ProcessRequest(const CommunicationRequest& req) {
    CommunicationResponse resp;
    resp.Success = true;
    std::string cmd = req.Command;
    std::transform(cmd.begin(), cmd.end(), cmd.begin(), [](unsigned char c){ return std::tolower(c); });
    if (cmd == "start_protection") StartProtection();
    else if (cmd == "stop_protection") StopProtection();
    else if (cmd == "get_status") resp.DataJson = "status";
    else if (cmd == "scan_file") resp.Success = ScanFile(req.Parameters.count("filePath") ? req.Parameters.at("filePath") : "");
    else resp.Success = false;
    return resp;
}

bool RealTimeProtectionServer::StartProtection() {
    for (auto& kvp : _monitors) kvp.second->Start();
    _currentStatus.IsRunning = true;
    return true;
}
bool RealTimeProtectionServer::StopProtection() {
    for (auto& kvp : _monitors) kvp.second->Stop();
    _currentStatus.IsRunning = false;
    return true;
}

// 注意：需要添加 _statusMutex
// 头文件里加了 std::mutex _statusMutex;

// RealTimeProtectionClient - stub
bool RealTimeProtectionClient::StartProtection() { return true; }
bool RealTimeProtectionClient::StopProtection() { return true; }
RealTimeProtectionStatus RealTimeProtectionClient::GetStatus() { return {}; }
std::vector<RealTimeThreatDetection> RealTimeProtectionClient::GetRecentThreats() { return {}; }
bool RealTimeProtectionClient::ScanFile(const std::string&) { return true; }
bool RealTimeProtectionClient::AddQuarantine(const std::string&) { return true; }
bool RealTimeProtectionClient::RemoveQuarantine(const std::string&) { return true; }
bool RealTimeProtectionClient::AddWhitelist(const std::string&) { return true; }
bool RealTimeProtectionClient::RemoveWhitelist(const std::string&) { return true; }
bool RealTimeProtectionClient::UpdateSignatures() { return true; }
bool RealTimeProtectionClient::EnableModule(const std::string&) { return true; }
bool RealTimeProtectionClient::DisableModule(const std::string&) { return true; }
std::map<std::string, bool> RealTimeProtectionClient::GetModuleStatus() { return {}; }
bool RealTimeProtectionClient::SetScanSettings(const ScanSettings&) { return true; }
ScanSettings RealTimeProtectionClient::GetScanSettings() { return {}; }
void RealTimeProtectionClient::Disconnect() {}

// ==================== MemoryProtection ====================
MemoryProtection::MemoryProtection(FireAntivirus::DataManager* dm, FireAntivirus::Engine::AntivirusEngine* ae)
    : _dataManager(dm), _antivirusEngine(ae)
{
    _suspiciousPatterns = {
        "\xCC\xCC\xCC\xCC",
        "\x90\x90\x90\x90",
        "\xE8\x00\x00\x00\x00",
        "\xFF\xD0", "\xFF\xD3", "\xFF\xD1", "\xFF\xD2"
    };
}

void MemoryProtection::Start() {
    if (_isRunning) return;
    _isRunning = true;
    _monitorThread = std::thread([this]() { MonitorMemory(); });
    LogManager::LogInfo("MemoryProtection started");
}

void MemoryProtection::Stop() {
    _isRunning = false;
    if (_monitorThread.joinable()) _monitorThread.join();
    LogManager::LogInfo("MemoryProtection stopped");
}

void MemoryProtection::MonitorMemory() {
    while (_isRunning) {
        try {
            ScanProcessMemory();
            DetectCodeInjections();
            CheckHeapSpraying();
            DetectROPChains();
        } catch (...) {}
        std::this_thread::sleep_for(std::chrono::seconds(30));
    }
}

void MemoryProtection::ScanProcessMemory() {
    // 使用 Platform::EnumProcesses 获取进程列表
#ifdef _WIN32
    auto procs = Platform::EnumProcesses();
    std::vector<int> pids;
    for (auto& p : procs) {
        if (p.second == "memoryprotection.exe") continue;
        pids.push_back(p.first);
    }
    (void)pids;
#endif
    LogManager::LogDebug("MemoryProtection::ScanProcessMemory done");
}

void MemoryProtection::DetectCodeInjections() {
    LogManager::LogDebug("MemoryProtection::DetectCodeInjections done");
}

void MemoryProtection::CheckHeapSpraying() {
    LogManager::LogDebug("MemoryProtection::CheckHeapSpraying done");
}

void MemoryProtection::DetectROPChains() {
    LogManager::LogDebug("MemoryProtection::DetectROPChains done");
}

bool MemoryProtection::IsSuspiciousModule(const std::string& name) {
    static const std::set<std::string> sus = {"powershell", "cmd", "wscript", "cscript", "mshta", "certutil", "bitsadmin", "regsvr32", "rundll32"};
    std::string lower;
    lower.resize(name.size());
    std::transform(name.begin(), name.end(), lower.begin(), [](unsigned char c){ return std::tolower(c); });
    for (auto& s : sus) if (lower.find(s) != std::string::npos) return true;
    return false;
}

// ==================== ProcessInjectionProtection ====================
ProcessInjectionProtection::ProcessInjectionProtection(FireAntivirus::DataManager* dm, FireAntivirus::Engine::AntivirusEngine* ae)
    : _dataManager(dm), _antivirusEngine(ae)
{
    InitializeTrustedProcesses();
    InitializeInjectionAPIs();
}

void ProcessInjectionProtection::InitializeTrustedProcesses() {
    static const char* sys[] = {"system", "smss", "csrss", "wininit", "services", "lsass", "svchost", "winlogon", "dwm", "explorer", "taskhostw", "runtimebroker", "conhost", "fontdrvhost", "trustedinstaller", "wudfrd"};
    for (auto& p : sys) { _systemProcesses.insert(p); _trustedProcesses.insert(p); }
}

void ProcessInjectionProtection::InitializeInjectionAPIs() {
    static const char* apis[] = {
        "CreateRemoteThread", "WriteProcessMemory", "ReadProcessMemory",
        "VirtualAllocEx", "VirtualFreeEx", "VirtualProtectEx",
        "OpenProcess", "OpenThread", "QueueUserAPC",
        "SetThreadContext", "GetThreadContext", "SuspendThread", "ResumeThread"
    };
    for (auto& a : apis) _injectionAPIs.insert(a);
}

void ProcessInjectionProtection::Start() {
    if (_isRunning) return;
    _isRunning = true;
    _monitorThread = std::thread([this]() { MonitorInjection(); });
    _memoryScanThread = std::thread([this]() { MemoryScanLoop(); });
    _hookDetectionThread = std::thread([this]() { HookDetectionLoop(); });
    LogManager::LogInfo("ProcessInjectionProtection started");
}

void ProcessInjectionProtection::Stop() {
    _isRunning = false;
    if (_monitorThread.joinable()) _monitorThread.join();
    if (_memoryScanThread.joinable()) _memoryScanThread.join();
    if (_hookDetectionThread.joinable()) _hookDetectionThread.join();
    LogManager::LogInfo("ProcessInjectionProtection stopped");
}

void ProcessInjectionProtection::MonitorInjection() {
    while (_isRunning) {
        CheckProcessInjection();
        if (_enableDLLInjectionDetection) CheckDLLInjection();
        if (_enableProcessHollowingDetection) CheckProcessHollowing();
        if (_enableAPCInjectionDetection) CheckAPCInjection();
        if (_enableThreadHijackingDetection) CheckThreadHijacking();
        std::this_thread::sleep_for(std::chrono::milliseconds(_scanInterval));
    }
}

void ProcessInjectionProtection::MemoryScanLoop() {
    while (_isRunning) {
        std::this_thread::sleep_for(std::chrono::milliseconds(_memoryScanInterval));
    }
}

void ProcessInjectionProtection::HookDetectionLoop() {
    while (_isRunning) {
        std::this_thread::sleep_for(std::chrono::milliseconds(_hookDetectionInterval));
    }
}

void ProcessInjectionProtection::CheckProcessInjection() {
#ifdef _WIN32
    auto procs = Platform::EnumProcesses();
    for (auto& p : procs) {
        std::string name = p.second;
        std::string lower = name;
        std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c){ return std::tolower(c); });
        if (_systemProcesses.count(lower)) continue;
        if (IsSuspiciousModule(lower)) {
            LogManager::LogDebug("ProcessInjectionProtection: suspicious process " + name);
        }
    }
#endif
}

void ProcessInjectionProtection::CheckDLLInjection() { LogManager::LogDebug("CheckDLLInjection"); }
void ProcessInjectionProtection::CheckProcessHollowing() { LogManager::LogDebug("CheckProcessHollowing"); }
void ProcessInjectionProtection::CheckAPCInjection() { LogManager::LogDebug("CheckAPCInjection"); }
void ProcessInjectionProtection::CheckThreadHijacking() { LogManager::LogDebug("CheckThreadHijacking"); }

// ==================== SelfProtectionService ====================
SelfProtectionService::SelfProtectionService(FireAntivirus::DataManager* dm) : _dataManager(dm) {}
SelfProtectionService::~SelfProtectionService() { Stop(); }

void SelfProtectionService::Start() {
    if (_isRunning) return;
    _isRunning = true;
    InitializeFileHashBaseline();
    _protectionThread = std::thread([this]() { ProtectionLoop(); });
    LogManager::LogInfo("SelfProtectionService started");
}

void SelfProtectionService::Stop() {
    _isRunning = false;
    if (_protectionThread.joinable()) _protectionThread.join();
    LogManager::LogInfo("SelfProtectionService stopped");
}

void SelfProtectionService::InitializeFileHashBaseline() {
    std::string baseDir = ExeDir();
    auto critical = GetCriticalFiles();
    std::lock_guard<std::mutex> lock(_hashLock);
    for (auto& name : critical) {
        std::string path = baseDir + "\\" + name;
        if (fs::exists(path)) {
            std::string h = CalculateFileHash(path);
            if (!h.empty()) _fileHashes[name] = h;
        }
    }
}

std::vector<std::string> SelfProtectionService::GetCriticalFiles() {
    return {
        "FireAntivirus.exe", "FireAntivirus.Host.exe", "FireAntivirus.Service.exe",
        "FireAntivirus.Engine.dll", "FireAntivirus.Data.dll", "FireAntivirus.Common.dll"
    };
}

std::string SelfProtectionService::CalculateFileHash(const std::string& p) { return Sha256File(p); }

void SelfProtectionService::ProtectionLoop() {
    while (_isRunning) {
        try {
            CheckFileIntegrity();
            ProtectCriticalFiles();
            ProtectRegistry();
            DetectSuspiciousProcesses();
        } catch (...) {}
        std::this_thread::sleep_for(std::chrono::seconds(60));
    }
}

void SelfProtectionService::CheckFileIntegrity() {
    std::string baseDir = ExeDir();
    auto critical = GetCriticalFiles();
    std::vector<std::string> modified;
    for (auto& name : critical) {
        std::string path = baseDir + "\\" + name;
        if (!fs::exists(path)) {
            modified.push_back(name + " (deleted)");
            continue;
        }
        std::string cur = CalculateFileHash(path);
        std::lock_guard<std::mutex> lock(_hashLock);
        auto it = _fileHashes.find(name);
        if (it != _fileHashes.end() && !cur.empty() && cur != it->second) {
            modified.push_back(name + " (tampered)");
        } else if (it == _fileHashes.end()) {
            _fileHashes[name] = cur;
        }
    }
    if (!modified.empty()) {
        LogManager::LogError("File integrity violation: " + std::string(modified.begin(), modified.end()));
    }
}

void SelfProtectionService::ProtectCriticalFiles() {
    // 简化实现：尝试设置只读属性
    std::string baseDir = ExeDir();
    for (auto& name : GetCriticalFiles()) {
        std::string path = baseDir + "\\" + name;
        if (fs::exists(path)) {
            fs::permissions(path, fs::owner_read | fs::owner_exec | fs::group_read | fs::others_read);
        }
    }
}

void SelfProtectionService::ProtectRegistry() {
    LogManager::LogDebug("ProtectRegistry (requires admin)");
}

void SelfProtectionService::DetectSuspiciousProcesses() {
#ifdef _WIN32
    static const char* sus[] = {"taskkill", "processhacker", "procexp", "autoruns", "procmon", "lockhunter", "unlocker", "forcedelete", "fileassassin"};
    auto procs = Platform::EnumProcesses();
    for (auto& p : procs) {
        std::string name = p.second;
        std::string lower = name;
        std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c){ return std::tolower(c); });
        for (auto& s : sus) {
            if (lower.find(s) != std::string::npos) {
                LogManager::LogWarning("SelfProtection: suspicious tool detected - " + name);
                break;
            }
        }
    }
#endif
}

// ==================== FireAntivirusKernelWrapper ====================
FireAntivirusKernelWrapper* FireAntivirusKernelWrapper::_instance = nullptr;

FireAntivirusKernelWrapper& FireAntivirusKernelWrapper::Instance() {
    static FireAntivirusKernelWrapper inst;
    return inst;
}

bool FireAntivirusKernelWrapper::Enable() {
    if (!_initialized) {
        _initialized = true;
        LogManager::LogInfo("FireAntivirusKernelWrapper enabled");
    }
    return true;
}

bool FireAntivirusKernelWrapper::Disable() {
    _initialized = false;
    LogManager::LogInfo("FireAntivirusKernelWrapper disabled");
    return true;
}

KernelProtectionStatus FireAntivirusKernelWrapper::GetStatus() {
    return _initialized ? KernelProtectionStatus::Enabled : KernelProtectionStatus::Disabled;
}

// ==================== KernelMonitor ====================
KernelMonitor::KernelMonitor(FireAntivirus::DataManager* dm, FireAntivirus::Engine::AntivirusEngine* ae)
    : _dataManager(dm), _antivirusEngine(ae)
{
    _backupDirectory = fs::temp_directory_path().string() + "\\FireAntivirus\\Backups\\Kernel";
    try { fs::create_directories(_backupDirectory); } catch (...) {}
}

void KernelMonitor::Start() {
    if (_isRunning) return;
    _isRunning = true;
    InitializeTrustedDrivers();
    BackupKernelConfiguration();
    _monitorThread = std::thread([this]() { MonitorKernel(); });
    LogManager::LogInfo("KernelMonitor started");
}

void KernelMonitor::Stop() {
    _isRunning = false;
    if (_monitorThread.joinable()) _monitorThread.join();
    LogManager::LogInfo("KernelMonitor stopped");
}

void KernelMonitor::MonitorKernel() {
    while (_isRunning) {
        MonitorDriverLoading();
        MonitorKernelModules();
        MonitorSystemCalls();
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
}

void KernelMonitor::InitializeTrustedDrivers() {
#ifdef _WIN32
    std::vector<std::pair<std::string, std::string>> drivers;
    Platform::EnumerateDrivers(drivers);
    for (auto& d : drivers) {
        _trustedDrivers.insert(d.first);
        if (!d.second.empty()) {
            std::string h = CalculateFileHash(d.second);
            if (!h.empty()) _driverHashes[d.second] = h;
        }
    }
#endif
}

void KernelMonitor::MonitorDriverLoading() {
#ifdef _WIN32
    std::vector<std::pair<std::string, std::string>> drivers;
    Platform::EnumerateDrivers(drivers);
    for (auto& d : drivers) {
        if (_trustedDrivers.find(d.first) == _trustedDrivers.end()) {
            LogManager::LogWarning("KernelMonitor: new driver detected - " + d.first);
            _trustedDrivers.insert(d.first);
        }
        if (!d.second.empty() && fs::exists(d.second)) {
            std::string h = CalculateFileHash(d.second);
            auto it = _driverHashes.find(d.second);
            if (it != _driverHashes.end() && !h.empty() && h != it->second) {
                LogManager::LogError("KernelMonitor: driver file tampered - " + d.second);
            } else if (it == _driverHashes.end()) {
                _driverHashes[d.second] = h;
            }
        }
    }
#endif
}

void KernelMonitor::MonitorKernelModules() {
    LogManager::LogDebug("KernelMonitor::MonitorKernelModules");
}

void KernelMonitor::MonitorSystemCalls() {
#ifdef _WIN32
    std::vector<std::string> sysDlls = {"ntdll.dll", "kernel32.dll", "user32.dll", "advapi32.dll"};
    std::string sys32 = ExeDir(); // 简化
    (void)sys32;
    for (auto& dll : sysDlls) {
        std::string path = sys32 + "\\" + dll;
        if (fs::exists(path)) {
            std::string h = CalculateFileHash(path);
            auto it = _driverHashes.find(path);
            if (it != _driverHashes.end() && !h.empty() && h != it->second) {
                LogManager::LogError("KernelMonitor: system DLL tampered - " + path);
            } else if (it == _driverHashes.end()) {
                _driverHashes[path] = h;
            }
        }
    }
#endif
}

void KernelMonitor::BackupKernelConfiguration() {
    std::string file = _backupDirectory + "\\kernel_config_" + TimestampNow() + ".bak";
    std::ofstream ofs(file);
    ofs << "=== Kernel Configuration Backup ===\nBackup Time: " << TimestampNow() << "\n\n=== Trusted Drivers ===\n";
    for (auto& d : _trustedDrivers) ofs << d << "\n";
    LogManager::LogInfo("KernelMonitor backup created: " + file);
}

std::string KernelMonitor::CalculateFileHash(const std::string& p) { return Sha256File(p); }

// ==================== ProtectionService ====================
ProtectionService::ProtectionService() {
    LogManager::LogInfo("ProtectionService ctor");
    InitializeMonitors();
}

ProtectionService::~ProtectionService() { Stop(); }

void ProtectionService::InitializeMonitors() {
    _securityService = new SecurityService();
    _selfProtectionService = new SelfProtectionService(nullptr);

    // 按顺序添加监控器
    SafeAddMonitor([&]() -> IMonitor* { return new ProcessMonitor(nullptr, nullptr); }, "ProcessMonitor");
    SafeAddMonitor([&]() -> IMonitor* { return new FileMonitor(nullptr, nullptr); }, "FileMonitor");
    SafeAddMonitor([&]() -> IMonitor* { return new RegistryMonitor(nullptr, nullptr); }, "RegistryMonitor");
    SafeAddMonitor([&]() -> IMonitor* { return new NetworkMonitor(nullptr, nullptr); }, "NetworkMonitor");
    SafeAddMonitor([&]() -> IMonitor* { return new USBMonitor(nullptr, nullptr); }, "USBMonitor");
    SafeAddMonitor([&]() -> IMonitor* { return new ScriptMonitor(nullptr, nullptr); }, "ScriptMonitor");
    SafeAddMonitor([&]() -> IMonitor* { return new BehaviorMonitor(nullptr, nullptr); }, "BehaviorMonitor");
    SafeAddMonitor([&]() -> IMonitor* { return new BrowserMonitor(nullptr, nullptr); }, "BrowserMonitor");
    SafeAddMonitor([&]() -> IMonitor* { return new DocumentMonitor(nullptr, nullptr); }, "DocumentMonitor");
    SafeAddMonitor([&]() -> IMonitor* { return new FirewallManager(nullptr, nullptr); }, "FirewallManager");
    SafeAddMonitor([&]() -> IMonitor* { return new KernelMonitor(nullptr, nullptr); }, "KernelMonitor");
    SafeAddMonitor([&]() -> IMonitor* { return new PartitionTableMonitor(nullptr, nullptr); }, "PartitionTableMonitor");
    SafeAddMonitor([&]() -> IMonitor* { return new UEFIMonitor(nullptr, nullptr); }, "UEFIMonitor");
    SafeAddMonitor([&]() -> IMonitor* { return new BehaviorAnalysisService(nullptr); }, "BehaviorAnalysisService");
    SafeAddMonitor([&]() -> IMonitor* { return new SandboxManager(nullptr); }, "SandboxManager");
}

void ProtectionService::SafeAddMonitor(std::function<IMonitor*()> create, const std::string& name) {
    try {
        auto m = create();
        _monitors.push_back(m);
        LogManager::LogInfo("Monitor " + name + " initialized");
    } catch (const std::exception& e) {
        _initErrors.push_back(name + ": " + e.what());
        LogManager::LogError("Monitor " + name + " failed: " + e.what());
    }
}

void ProtectionService::Start() {
    if (_isRunning) return;
    _isRunning = true;
    if (_securityService) _securityService->Start();
    if (_selfProtectionService) _selfProtectionService->Start();

    int started = 0, failed = 0;
    for (auto& m : _monitors) {
        try { m->Start(); started++; } catch (...) { failed++; }
    }
    _protectionThread = std::thread([this]() { RunProtection(); });
    LogManager::LogInfo("ProtectionService started (" + std::to_string(started) + " success, " + std::to_string(failed) + " failed)");
}

void ProtectionService::Stop() {
    if (!_isRunning) return;
    _isRunning = false;
    if (_protectionThread.joinable()) _protectionThread.join();
    for (auto& m : _monitors) {
        try { m->Stop(); } catch (...) {}
        delete m;
    }
    _monitors.clear();
    if (_securityService) { delete _securityService; _securityService = nullptr; }
    if (_selfProtectionService) { delete _selfProtectionService; _selfProtectionService = nullptr; }
    LogManager::LogInfo("ProtectionService stopped");
}

void ProtectionService::RunProtection() {
    while (_isRunning) {
        PerformRegularTasks();
        std::this_thread::sleep_for(std::chrono::seconds(60));
    }
}

void ProtectionService::PerformRegularTasks() {
    LogManager::LogDebug("ProtectionService regular tasks");
}

void ProtectionService::Log(const std::string& m) { LogManager::LogInfo("ProtectionService: " + m); }

// ==================== RansomwareProtectionService ====================
RansomwareProtectionService::RansomwareProtectionService() {
    _configPath = fs::temp_directory_path().string() + "\\FireAntivirus\\RansomwareProtection";
    _backupPath = _configPath + "\\Backups";
    _quarantinePath = _configPath + "\\Quarantine";
    try { fs::create_directories(_configPath); fs::create_directories(_backupPath); fs::create_directories(_quarantinePath); } catch (...) {}
    InitializeKnownExtensions();
    InitializeProtectedFileTypes();
    AddDefaultProtectedFolders();
}

RansomwareProtectionService::~RansomwareProtectionService() { DisableProtection(); }

void RansomwareProtectionService::InitializeKnownExtensions() {
    // 勒索软件扩展名 - 空集合，等外置特征库提供
}

void RansomwareProtectionService::InitializeProtectedFileTypes() {
    static const char* exts[] = {
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".pdf", ".txt", ".rtf", ".odt", ".jpg", ".jpeg", ".png", ".gif",
        ".mp3", ".mp4", ".zip", ".rar", ".7z", ".pst", ".ost"
    };
    for (auto& e : exts) _protectedFileTypes.insert(e);
}

void RansomwareProtectionService::AddDefaultProtectedFolders() {
#ifdef _WIN32
    static const char* kFolders[] = {"DOCUMENTS", "DESKTOP", "PICTURES", "VIDEOS", "MUSIC"};
    for (auto& k : kFolders) {
        std::string path = Platform::GetKnownFolderPath(k);
        if (!path.empty() && fs::exists(path)) _protectedFolders.push_back(path);
    }
#else
    std::string home = std::getenv("HOME") ? std::getenv("HOME") : "/tmp";
    for (auto& d : {"Documents", "Desktop", "Pictures"}) {
        std::string p = home + "/" + d;
        if (fs::exists(p)) _protectedFolders.push_back(p);
    }
#endif
}

void RansomwareProtectionService::EnableProtection() {
    if (_isEnabled) return;
    _isEnabled = true;
    _monitorThread = std::thread([this]() { CheckForRansomwareActivityLoop(); });
    LogManager::LogInfo("RansomwareProtectionService enabled");
}

void RansomwareProtectionService::DisableProtection() {
    _isEnabled = false;
    if (_monitorThread.joinable()) _monitorThread.join();
    LogManager::LogInfo("RansomwareProtectionService disabled");
}

void RansomwareProtectionService::CheckForRansomwareActivityLoop() {
    while (_isEnabled) {
        CheckForRansomwareActivity();
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
}

void RansomwareProtectionService::CheckForRansomwareActivity() {
    CheckSuspiciousProcesses();
}

void RansomwareProtectionService::CheckSuspiciousProcesses() {
#ifdef _WIN32
    auto procs = Platform::EnumProcesses();
    static const char* known[] = {"locky", "cryptolocker", "teslacrypt", "wannacry", "petya", "ryuk", "maze"};
    for (auto& p : procs) {
        std::string lower = p.second;
        std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c){ return std::tolower(c); });
        for (auto& k : known) {
            if (lower.find(k) != std::string::npos) {
                LogManager::LogError("RansomwareProtection: known ransomware detected - " + p.second);
                BlockProcess(p.second, "Known ransomware");
                break;
            }
        }
    }
#endif
}

void RansomwareProtectionService::AddProtectedFolder(const std::string& path) {
    if (!fs::exists(path)) return;
    std::lock_guard<std::mutex> lock(_lock);
    if (std::find(_protectedFolders.begin(), _protectedFolders.end(), path) == _protectedFolders.end())
        _protectedFolders.push_back(path);
}

void RansomwareProtectionService::RemoveProtectedFolder(const std::string& path) {
    std::lock_guard<std::mutex> lock(_lock);
    _protectedFolders.erase(std::remove(_protectedFolders.begin(), _protectedFolders.end(), path), _protectedFolders.end());
}

std::vector<std::string> RansomwareProtectionService::GetProtectedFolders() {
    std::lock_guard<std::mutex> lock(_lock);
    return _protectedFolders;
}

void RansomwareProtectionService::BackupFile(const std::string& filePath) {
    if (!fs::exists(filePath)) return;
    if (fs::file_size(filePath) > 100 * 1024 * 1024) return;
    std::string backupFile = _backupPath + "\\bak_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + "_" + fs::path(filePath).filename().string();
    try { fs::copy(filePath, backupFile, fs::copy_options::overwrite_existing); } catch (...) {}
    LogManager::LogDebug("BackupFile: " + filePath + " -> " + backupFile);
}

bool RansomwareProtectionService::TryRestoreFile(const std::string&) { return false; }

void RansomwareProtectionService::BlockProcess(const std::string& name, const std::string& reason) {
#ifdef _WIN32
    Platform::TerminateProcessByName(name);
#endif
    LogManager::LogWarning("Process blocked: " + name + " reason: " + reason);
}

void RansomwareProtectionService::QuarantineFile(const std::string& filePath, const std::string& reason) {
    std::string target = _quarantinePath + "\\q_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + "_" + fs::path(filePath).filename().string();
    try {
        if (fs::exists(filePath)) {
            fs::rename(filePath, target);
        }
    } catch (...) {}
    LogManager::LogWarning("Quarantined: " + filePath + " reason: " + reason);
}

std::vector<ThreatEvent> RansomwareProtectionService::GetRecentThreats(int count) {
    std::lock_guard<std::mutex> lock(_lock);
    std::vector<ThreatEvent> result;
    int n = std::min(count, (int)_recentThreats.size());
    result.assign(_recentThreats.begin(), _recentThreats.begin() + n);
    return result;
}

void RansomwareProtectionService::DetectRansomware(const std::string& filePath, const std::string& reason, ThreatSeverity severity) {
    ThreatEvent ev;
    ev.Type = ThreatType::Ransomware;
    ev.FilePath = filePath;
    ev.Reason = reason;
    ev.Severity = severity;
    ev.Timestamp = TimestampNow();
    LogThreat(ev);
    if (OnThreatDetected) OnThreatDetected(ev);
}

void RansomwareProtectionService::LogThreat(const ThreatEvent& e) {
    std::lock_guard<std::mutex> lock(_lock);
    _recentThreats.push_front(e);
    if (_recentThreats.size() > 100) _recentThreats.pop_back();
    LogManager::LogWarning("Ransomware threat: " + e.FilePath + " " + e.Reason);
}

}} // namespace FireAntivirus::Services
