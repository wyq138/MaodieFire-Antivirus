#include "../include/FireAntivirus/Services/CoreServices.h"

#include <chrono>
#include <ctime>
#include <filesystem>
#include <sstream>
#include <algorithm>
#include <condition_variable>

namespace FireAntivirus { namespace Services {

namespace fs = std::filesystem;

// ==================== 辅助函数 ====================
static std::string GetTimestamp() {
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

static std::string GetExeDirectory() {
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

static std::string AppConfigToJson(const AppConfig& cfg) {
    std::ostringstream os;
    os << "{\n";
    auto write = [&](const char* k, bool v, bool& first) {
        if (!first) os << ",\n";
        os << "  \"" << k << "\": " << (v ? "true" : "false");
        first = false;
    };
    bool first = true;
    write("FileProtectionEnabled", cfg.FileProtectionEnabled, first);
    write("ProcessProtectionEnabled", cfg.ProcessProtectionEnabled, first);
    write("DeviceProtectionEnabled", cfg.DeviceProtectionEnabled, first);
    write("RegistryProtectionEnabled", cfg.RegistryProtectionEnabled, first);
    write("BrowserProtectionEnabled", cfg.BrowserProtectionEnabled, first);
    write("ScriptProtectionEnabled", cfg.ScriptProtectionEnabled, first);
    write("ActiveDefenseEnabled", cfg.ActiveDefenseEnabled, first);
    write("DiskProtectionEnabled", cfg.DiskProtectionEnabled, first);
    write("UEFIProtectionEnabled", cfg.UEFIProtectionEnabled, first);
    write("KernelProtectionEnabled", cfg.KernelProtectionEnabled, first);
    write("DocumentProtectionEnabled", cfg.DocumentProtectionEnabled, first);
    write("NetworkProtectionEnabled", cfg.NetworkProtectionEnabled, first);
    write("PopupBlockerEnabled", cfg.PopupBlockerEnabled, first);
    write("RansomwareProtectionEnabled", cfg.RansomwareProtectionEnabled, first);
    write("PrivacyProtectionEnabled", cfg.PrivacyProtectionEnabled, first);
    write("WebProtectionEnabled", cfg.WebProtectionEnabled, first);
    write("EmailSecurityEnabled", cfg.EmailSecurityEnabled, first);
    write("PasswordManagerEnabled", cfg.PasswordManagerEnabled, first);
    write("NetworkFirewallEnabled", cfg.NetworkFirewallEnabled, first);
    write("DeviceControlEnabled", cfg.DeviceControlEnabled, first);
    write("VulnerabilityScannerEnabled", cfg.VulnerabilityScannerEnabled, first);
    write("CloudScanEnabled", cfg.CloudScanEnabled, first);
    write("SecureBrowserEnabled", cfg.SecureBrowserEnabled, first);
    write("MobileSecurityEnabled", cfg.MobileSecurityEnabled, first);
    write("SystemOptimizerEnabled", cfg.SystemOptimizerEnabled, first);
    write("BackupRecoveryEnabled", cfg.BackupRecoveryEnabled, first);
    write("SecurityScoreEnabled", cfg.SecurityScoreEnabled, first);
    write("NetworkTrafficEnabled", cfg.NetworkTrafficEnabled, first);
    write("ApplicationMonitorEnabled", cfg.ApplicationMonitorEnabled, first);
    write("StartupManagerEnabled", cfg.StartupManagerEnabled, first);
    write("SecurityReportEnabled", cfg.SecurityReportEnabled, first);
    write("BehaviorAnalysisEnabled", cfg.BehaviorAnalysisEnabled, first);
    write("SystemToolsEnabled", cfg.SystemToolsEnabled, first);
    write("SystemInfoEnabled", cfg.SystemInfoEnabled, first);
    write("QuarantineEnabled", cfg.QuarantineEnabled, first);
    write("TrustZoneEnabled", cfg.TrustZoneEnabled, first);
    write("LogCenterEnabled", cfg.LogCenterEnabled, first);
    os << "\n}";
    return os.str();
}

static bool ParseJsonBool(const std::string& json, const char* key) {
    std::string search = std::string("\"") + key + "\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return false;
    pos = json.find(':', pos);
    if (pos == std::string::npos) return false;
    pos++;
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) pos++;
    if (pos >= json.size()) return false;
    if (json.substr(pos, 4) == "true") return true;
    if (json.substr(pos, 5) == "false") return false;
    return false;
}

static AppConfig JsonToAppConfig(const std::string& json) {
    AppConfig cfg;
    cfg.FileProtectionEnabled = ParseJsonBool(json, "FileProtectionEnabled");
    cfg.ProcessProtectionEnabled = ParseJsonBool(json, "ProcessProtectionEnabled");
    cfg.DeviceProtectionEnabled = ParseJsonBool(json, "DeviceProtectionEnabled");
    cfg.RegistryProtectionEnabled = ParseJsonBool(json, "RegistryProtectionEnabled");
    cfg.BrowserProtectionEnabled = ParseJsonBool(json, "BrowserProtectionEnabled");
    cfg.ScriptProtectionEnabled = ParseJsonBool(json, "ScriptProtectionEnabled");
    cfg.ActiveDefenseEnabled = ParseJsonBool(json, "ActiveDefenseEnabled");
    cfg.DiskProtectionEnabled = ParseJsonBool(json, "DiskProtectionEnabled");
    cfg.UEFIProtectionEnabled = ParseJsonBool(json, "UEFIProtectionEnabled");
    cfg.KernelProtectionEnabled = ParseJsonBool(json, "KernelProtectionEnabled");
    cfg.DocumentProtectionEnabled = ParseJsonBool(json, "DocumentProtectionEnabled");
    cfg.NetworkProtectionEnabled = ParseJsonBool(json, "NetworkProtectionEnabled");
    cfg.PopupBlockerEnabled = ParseJsonBool(json, "PopupBlockerEnabled");
    cfg.RansomwareProtectionEnabled = ParseJsonBool(json, "RansomwareProtectionEnabled");
    cfg.PrivacyProtectionEnabled = ParseJsonBool(json, "PrivacyProtectionEnabled");
    cfg.WebProtectionEnabled = ParseJsonBool(json, "WebProtectionEnabled");
    cfg.EmailSecurityEnabled = ParseJsonBool(json, "EmailSecurityEnabled");
    cfg.PasswordManagerEnabled = ParseJsonBool(json, "PasswordManagerEnabled");
    cfg.NetworkFirewallEnabled = ParseJsonBool(json, "NetworkFirewallEnabled");
    cfg.DeviceControlEnabled = ParseJsonBool(json, "DeviceControlEnabled");
    cfg.VulnerabilityScannerEnabled = ParseJsonBool(json, "VulnerabilityScannerEnabled");
    cfg.CloudScanEnabled = ParseJsonBool(json, "CloudScanEnabled");
    cfg.SecureBrowserEnabled = ParseJsonBool(json, "SecureBrowserEnabled");
    cfg.MobileSecurityEnabled = ParseJsonBool(json, "MobileSecurityEnabled");
    cfg.SystemOptimizerEnabled = ParseJsonBool(json, "SystemOptimizerEnabled");
    cfg.BackupRecoveryEnabled = ParseJsonBool(json, "BackupRecoveryEnabled");
    cfg.SecurityScoreEnabled = ParseJsonBool(json, "SecurityScoreEnabled");
    cfg.NetworkTrafficEnabled = ParseJsonBool(json, "NetworkTrafficEnabled");
    cfg.ApplicationMonitorEnabled = ParseJsonBool(json, "ApplicationMonitorEnabled");
    cfg.StartupManagerEnabled = ParseJsonBool(json, "StartupManagerEnabled");
    cfg.SecurityReportEnabled = ParseJsonBool(json, "SecurityReportEnabled");
    cfg.BehaviorAnalysisEnabled = ParseJsonBool(json, "BehaviorAnalysisEnabled");
    cfg.SystemToolsEnabled = ParseJsonBool(json, "SystemToolsEnabled");
    cfg.SystemInfoEnabled = ParseJsonBool(json, "SystemInfoEnabled");
    cfg.QuarantineEnabled = ParseJsonBool(json, "QuarantineEnabled");
    cfg.TrustZoneEnabled = ParseJsonBool(json, "TrustZoneEnabled");
    cfg.LogCenterEnabled = ParseJsonBool(json, "LogCenterEnabled");
    return cfg;
}

// ==================== ConfigManager ====================
ConfigManager* ConfigManager::_instance = nullptr;

ConfigManager& ConfigManager::Instance() {
    static ConfigManager inst;
    return inst;
}

void ConfigManager::Initialize() {
    auto& inst = Instance();
    std::lock_guard<std::mutex> lock(inst._lock);
    if (inst._initialized) return;

    std::string baseDir = GetExeDirectory();
    std::string configDir = baseDir + "\\Config";
    try { fs::create_directories(configDir); } catch (...) {}

    inst._configFile = configDir + "\\appsettings.json";
    inst.LoadConfig();
    inst._initialized = true;
}

void ConfigManager::LoadConfig() {
    if (fs::exists(_configFile)) {
        std::ifstream ifs(_configFile);
        std::string json((std::istreambuf_iterator<char>(ifs)),
                        std::istreambuf_iterator<char>());
        if (!json.empty()) {
            _config = JsonToAppConfig(json);
        } else {
            SaveConfig();
        }
    } else {
        SaveConfig();
    }
}

void ConfigManager::SaveConfig() {
    std::lock_guard<std::mutex> lock(Instance()._lock);
    std::string json = AppConfigToJson(Instance()._config);
    std::ofstream ofs(Instance()._configFile, std::ios::trunc);
    ofs << json;
    LogManager::LogInfo("Config saved");
}

AppConfig& ConfigManager::Config() {
    auto& inst = Instance();
    if (!inst._initialized) Initialize();
    return inst._config;
}

const std::string& ConfigManager::ConfigFile() {
    return Instance()._configFile;
}

// ==================== Logger ====================
void Logger::Info(const std::string& message) {
    std::cout << "[INFO] " << GetTimestamp() << ": " << message << std::endl;
}
void Logger::Warning(const std::string& message) {
    std::cout << "[WARNING] " << GetTimestamp() << ": " << message << std::endl;
}
void Logger::Error(const std::string& message) {
    std::cerr << "[ERROR] " << GetTimestamp() << ": " << message << std::endl;
}

// ==================== LogManager ====================
LogManager* LogManager::_instance = nullptr;
std::mutex LogManager::_lock;
std::string LogManager::_logDirectory;
std::string LogManager::_logFile;
bool LogManager::_initialized = false;

void LogManager::Initialize() {
    std::lock_guard<std::mutex> lock(_lock);
    if (_initialized) return;

    std::string baseDir = GetExeDirectory();
    _logDirectory = baseDir + "\\Logs";
    try { fs::create_directories(_logDirectory); } catch (...) {}

    std::string date = GetTimestamp();
    date = date.substr(0, 10); // 截取 YYYY-MM-DD
    _logFile = _logDirectory + "\\fireantivirus_" + date + ".log";
    _initialized = true;
    LogInfo("Log manager initialized");
}

std::string LogManager::LevelToString(LogLevel level) {
    switch (level) {
        case LogLevel::Trace: return "TRACE";
        case LogLevel::Debug: return "DEBUG";
        case LogLevel::Info: return "INFO";
        case LogLevel::Warning: return "WARNING";
        case LogLevel::Error: return "ERROR";
        case LogLevel::Critical: return "CRITICAL";
        case LogLevel::Fatal: return "FATAL";
    }
    return "UNKNOWN";
}

std::string LogManager::FormatTimestamp() { return GetTimestamp(); }

void LogManager::CheckLogFileSize() {
    try {
        if (!_logFile.empty() && fs::exists(_logFile)) {
            auto sz = fs::file_size(_logFile);
            if (sz > 10 * 1024 * 1024) {
                // 重命名旧日志
                auto newPath = _logDirectory + "\\fireantivirus_" + GetTimestamp() + ".log";
                fs::rename(_logFile, newPath);
            }
        }
    } catch (...) {}
}

void LogManager::Log(LogLevel level, const std::string& message) {
    if (!_initialized) Initialize();

    std::lock_guard<std::mutex> lock(_lock);
    CheckLogFileSize();

    std::string ts = GetTimestamp();
    std::string levelStr = LevelToString(level);
    std::string fullMsg = "[" + ts + "] [" + levelStr + "] " + message;

    try {
        std::ofstream ofs(_logFile, std::ios::app);
        ofs << fullMsg << "\n";
    } catch (...) {}

    std::cout << fullMsg << std::endl;
}

void LogManager::LogDebug(const std::string& m) { Log(LogLevel::Debug, m); }
void LogManager::LogInfo(const std::string& m) { Log(LogLevel::Info, m); }
void LogManager::LogWarning(const std::string& m) { Log(LogLevel::Warning, m); }
void LogManager::LogError(const std::string& m) { Log(LogLevel::Error, m); }
void LogManager::LogFatal(const std::string& m) { Log(LogLevel::Fatal, m); }
const std::string& LogManager::LogDirectory() { return _logDirectory; }
const std::string& LogManager::LogFile() { return _logFile; }

// ==================== EnterpriseManager ====================
EnterpriseManager::EnterpriseManager(const std::string& databasePath, const std::string& serverUrl)
    : _serverUrl(serverUrl.empty() ? "http://localhost:8080" : serverUrl)
{
    std::string defaultPath = fs::temp_directory_path().string() + "\\FireAntivirus\\enterprise";
    _databasePath = databasePath.empty() ? defaultPath : databasePath;
    try { fs::create_directories(_databasePath); } catch (...) {}
}

DeviceInfo EnterpriseManager::RegisterDevice(const DeviceInfo& deviceInfo) {
    std::lock_guard<std::mutex> lock(_managerLock);
    DeviceInfo info = deviceInfo;
    if (info.DeviceId.empty()) {
        info.DeviceId = "dev_" + GetTimestamp();
    }
    info.LastSeen = GetTimestamp();

    bool found = false;
    for (auto& d : _devices) {
        if (d.DeviceId == info.DeviceId) {
            d = info;
            found = true;
            break;
        }
    }
    if (!found) _devices.push_back(info);

    RaiseEvent(EnterpriseEventArgs(EnterpriseEventType::DeviceRegistered, "Device registered: " + info.Name));
    return info;
}

ScanRecord EnterpriseManager::AddScanRecord(const ScanRecord& rec) {
    std::lock_guard<std::mutex> lock(_managerLock);
    ScanRecord r = rec;
    if (r.RecordId.empty()) r.RecordId = "rec_" + GetTimestamp();
    _scanRecords.push_back(r);
    RaiseEvent(EnterpriseEventArgs(EnterpriseEventType::ScanRecordAdded, "Scan record added: " + r.RecordId));
    return r;
}

Threat EnterpriseManager::AddThreat(const Threat& threat) {
    std::lock_guard<std::mutex> lock(_managerLock);
    Threat t = threat;
    if (t.ThreatId.empty()) t.ThreatId = "thr_" + GetTimestamp();
    t.DetectionTime = GetTimestamp();
    _threats.push_back(t);
    RaiseEvent(EnterpriseEventArgs(EnterpriseEventType::ThreatDetected, "Threat added: " + t.ThreatName));
    return t;
}

Policy EnterpriseManager::CreatePolicy(const Policy& policy) {
    std::lock_guard<std::mutex> lock(_managerLock);
    Policy p = policy;
    if (p.PolicyId.empty()) p.PolicyId = "pol_" + GetTimestamp();
    p.CreatedDate = GetTimestamp();
    p.LastModifiedDate = GetTimestamp();
    _policies.push_back(p);
    RaiseEvent(EnterpriseEventArgs(EnterpriseEventType::PolicyCreated, "Policy created: " + p.PolicyName));
    return p;
}

Group EnterpriseManager::CreateGroup(const Group& group) {
    std::lock_guard<std::mutex> lock(_managerLock);
    Group g = group;
    if (g.GroupId.empty()) g.GroupId = "grp_" + GetTimestamp();
    _groups.push_back(g);
    RaiseEvent(EnterpriseEventArgs(EnterpriseEventType::GroupCreated, "Group created: " + g.GroupName));
    return g;
}

std::vector<DeviceInfo> EnterpriseManager::GetDevices() {
    std::lock_guard<std::mutex> lock(_managerLock);
    auto copy = _devices;
    std::sort(copy.begin(), copy.end(), [](const DeviceInfo& a, const DeviceInfo& b) {
        return a.LastSeen > b.LastSeen;
    });
    return copy;
}

std::vector<ScanRecord> EnterpriseManager::GetScanRecords(const std::string& deviceId) {
    std::lock_guard<std::mutex> lock(_managerLock);
    std::vector<ScanRecord> result;
    for (auto& r : _scanRecords) {
        if (deviceId.empty() || r.DeviceId == deviceId) {
            result.push_back(r);
        }
    }
    std::sort(result.begin(), result.end(), [](const ScanRecord& a, const ScanRecord& b) {
        return a.StartTime > b.StartTime;
    });
    return result;
}

std::vector<Threat> EnterpriseManager::GetThreats(const std::string& deviceId, const std::string& scanRecordId) {
    std::lock_guard<std::mutex> lock(_managerLock);
    std::vector<Threat> result;
    for (auto& t : _threats) {
        if ((deviceId.empty() || t.DeviceId == deviceId) &&
            (scanRecordId.empty() || t.ScanRecordId == scanRecordId)) {
            result.push_back(t);
        }
    }
    return result;
}

std::vector<Policy> EnterpriseManager::GetPolicies() {
    std::lock_guard<std::mutex> lock(_managerLock);
    return _policies;
}

std::vector<Group> EnterpriseManager::GetGroups() {
    std::lock_guard<std::mutex> lock(_managerLock);
    return _groups;
}

Report EnterpriseManager::GenerateReport(const ReportOptions& options) {
    Report r;
    r.ReportId = "rep_" + GetTimestamp();
    r.ReportName = options.ReportName;
    r.ReportType = options.ReportType;
    r.GeneratedDate = GetTimestamp();

    auto devices = GetDevices();
    if (!options.GroupId.empty()) {
        devices.erase(std::remove_if(devices.begin(), devices.end(),
            [&](const DeviceInfo& d) { return d.GroupId != options.GroupId; }), devices.end());
    }
    r.TotalDevices = static_cast<int>(devices.size());

    for (auto& dev : devices) {
        DeviceReport dr;
        dr.DeviceId = dev.DeviceId;
        dr.Name = dev.Name;
        dr.IPAddress = dev.IPAddress;
        dr.OSVersion = dev.OSVersion;
        dr.Status = dev.Status;

        auto records = GetScanRecords(dev.DeviceId);
        if (records.size() > 10) records.resize(10);
        dr.ScanRecords = records;

        auto threats = GetThreats(dev.DeviceId);
        if (threats.size() > 20) threats.resize(20);
        dr.Threats = threats;

        r.TotalScans += static_cast<int>(dr.ScanRecords.size());
        r.TotalThreats += static_cast<int>(dr.Threats.size());
        for (auto& t : dr.Threats) {
            if (t.Severity == "Critical") r.CriticalThreats++;
            else if (t.Severity == "High") r.HighThreats++;
            else if (t.Severity == "Medium") r.MediumThreats++;
            else r.LowThreats++;
        }

        r.Devices.push_back(dr);
    }

    RaiseEvent(EnterpriseEventArgs(EnterpriseEventType::ReportGenerated, "Report generated: " + r.ReportName));
    return r;
}

void EnterpriseManager::Enable() { _enabled = true; }
void EnterpriseManager::Disable() { _enabled = false; }
bool EnterpriseManager::IsEnabled() { return _enabled; }
void EnterpriseManager::SetServerUrl(const std::string& url) { _serverUrl = url; }
std::string EnterpriseManager::GetServerUrl() { return _serverUrl; }

void EnterpriseManager::SyncDeviceToServer(const DeviceInfo&) {}
void EnterpriseManager::SyncScanRecordToServer(const ScanRecord&) {}
void EnterpriseManager::SyncThreatToServer(const Threat&) {}
void EnterpriseManager::SyncPolicyToServer(const Policy&) {}
void EnterpriseManager::SyncGroupToServer(const Group&) {}

void EnterpriseManager::InitializeDatabase() {
    try { fs::create_directories(_databasePath); } catch (...) {}
}

void EnterpriseManager::EnsureDirectory(const std::string& path) {
    try { fs::create_directories(path); } catch (...) {}
}

void EnterpriseManager::RaiseEvent(const EnterpriseEventArgs& e) {
    if (OnEvent) OnEvent(e);
}

// ==================== ServiceManager ====================
const std::string ServiceManager::ServiceName = "FireAntivirusService";
const std::string ServiceManager::ServiceDisplayName = "Fire Antivirus Service";

static int RunCommand(const std::string& cmd) {
#ifdef _WIN32
    std::string fullCmd = "cmd.exe /c " + cmd;
    return std::system(fullCmd.c_str());
#else
    return std::system(cmd.c_str());
#endif
}

static std::string GetServiceExePath() {
    return GetExeDirectory() + "\\FireAntivirus.Service.exe";
}

bool ServiceManager::InstallService() {
    std::string serviceExe = GetServiceExePath();
    if (!fs::exists(serviceExe)) {
        LogManager::LogError("Service executable not found: " + serviceExe);
        return false;
    }
    if (IsServiceInstalled()) {
        LogManager::LogWarning("Service is already installed");
        return true;
    }
    int ret = RunCommand(serviceExe + " -install");
    if (ret == 0) {
        LogManager::LogInfo("Service installed successfully");
        return true;
    }
    LogManager::LogError("Failed to install service (exit code: " + std::to_string(ret) + ")");
    return false;
}

bool ServiceManager::UninstallService() {
    if (!IsServiceInstalled()) {
        LogManager::LogWarning("Service is not installed");
        return true;
    }
    StopService();
    std::string serviceExe = GetServiceExePath();
    if (!fs::exists(serviceExe)) return false;
    int ret = RunCommand(serviceExe + " -uninstall");
    if (ret == 0) {
        LogManager::LogInfo("Service uninstalled successfully");
        return true;
    }
    LogManager::LogError("Failed to uninstall service");
    return false;
}

bool ServiceManager::StartService() {
    if (!IsServiceInstalled()) {
        LogManager::LogError("Service is not installed");
        return false;
    }
    if (IsServiceRunning()) {
        LogManager::LogWarning("Service is already running");
        return true;
    }
    int ret = RunCommand("net start \"" + ServiceName + "\"");
    if (ret == 0) {
        LogManager::LogInfo("Service started successfully");
        return true;
    }
    LogManager::LogError("Failed to start service");
    return false;
}

bool ServiceManager::StopService() {
    if (!IsServiceInstalled()) {
        LogManager::LogWarning("Service is not installed");
        return true;
    }
    if (!IsServiceRunning()) {
        LogManager::LogWarning("Service is not running");
        return true;
    }
    int ret = RunCommand("net stop \"" + ServiceName + "\"");
    if (ret == 0) {
        LogManager::LogInfo("Service stopped successfully");
        return true;
    }
    LogManager::LogError("Failed to stop service");
    return false;
}

bool ServiceManager::IsServiceInstalled() {
#ifdef _WIN32
    // 用 sc query 来检查服务是否存在
    std::string cmd = "sc query \"" + ServiceName + "\"";
    std::array<char, 512> buffer;
    std::string result;
    FILE* pipe = _popen(cmd.c_str(), "r");
    if (!pipe) return false;
    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        result += buffer.data();
    }
    _pclose(pipe);
    return result.find("1060") == std::string::npos; // 1060 = 服务不存在
#else
    return false;
#endif
}

bool ServiceManager::IsServiceRunning() {
#ifdef _WIN32
    std::string cmd = "sc query \"" + ServiceName + "\"";
    std::array<char, 512> buffer;
    std::string result;
    FILE* pipe = _popen(cmd.c_str(), "r");
    if (!pipe) return false;
    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        result += buffer.data();
    }
    _pclose(pipe);
    return result.find("RUNNING") != std::string::npos;
#else
    return false;
#endif
}

ServiceStatus ServiceManager::GetServiceStatus() {
#ifdef _WIN32
    if (!IsServiceInstalled()) return ServiceStatus::Unknown;
    if (IsServiceRunning()) return ServiceStatus::Running;
    return ServiceStatus::Stopped;
#else
    return ServiceStatus::Unknown;
#endif
}

void ServiceManager::RunServiceInConsole() {
    std::string serviceExe = GetServiceExePath();
    if (!fs::exists(serviceExe)) {
        LogManager::LogError("Service executable not found");
        return;
    }
    RunCommand("\"" + serviceExe + "\" -run");
}

// ==================== NotificationService ====================
NotificationService* NotificationService::_instance = nullptr;
std::mutex NotificationService::_instanceLock;

NotificationService::NotificationService() = default;

NotificationService& NotificationService::Instance() {
    std::lock_guard<std::mutex> lock(_instanceLock);
    static NotificationService inst;
    return inst;
}

void NotificationService::Start() {
    if (_isRunning) return;
    _isRunning = true;
    _notificationThread = std::thread([this]() { RunNotificationService(); });
    LogManager::LogInfo("Notification service started");
}

void NotificationService::Stop() {
    _isRunning = false;
    if (_notificationThread.joinable()) _notificationThread.join();
    LogManager::LogInfo("Notification service stopped");
}

void NotificationService::ShowNotification(const std::string& title, const std::string& message, NotificationType type) {
    std::string typeStr = (type == NotificationType::Warning) ? "[WARNING]"
                         : (type == NotificationType::Error) ? "[ERROR]"
                         : "[INFO]";
    LogManager::LogInfo(std::string("NOTIFICATION ") + typeStr + " " + title + ": " + message);
    std::lock_guard<std::mutex> lock(_logLock);
    LogEntry e;
    e.Id = "notif_" + GetTimestamp();
    e.Time = GetTimestamp();
    e.Type = (type == NotificationType::Error || type == NotificationType::Warning) ? "SecurityNotification" : "Notification";
    e.Message = title;
    e.Details = message;
    _recentLogs.push_back(e);
}

void NotificationService::RunNotificationService() {
    while (_isRunning) {
        CheckSecurityEvents();
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
}

void NotificationService::CheckSecurityEvents() {
    std::lock_guard<std::mutex> lock(_logLock);
    // 简单实现：检查最近日志中的真正威胁
    auto cutoff = std::chrono::system_clock::now() - std::chrono::seconds(10);
    (void)cutoff; // 简化实现，依赖 ShowNotification 直接推送
}

bool NotificationService::IsRealThreat(const std::string& logType) {
    static const std::set<std::string> realThreatTypes = {
        "MalwareDetected", "RansomwareDetected", "TrojanDetected", "WormDetected", "VirusDetected"
    };
    static const std::vector<std::string> ignoreTypes = {
        "PopupBlocked", "NetworkAttack", "SuspiciousProcess", "ScriptDetected", "SecurityAlert", "Alert", "Warning", "Threat"
    };
    for (auto& t : ignoreTypes) {
        if (logType.find(t) != std::string::npos) return false;
    }
    for (auto& t : realThreatTypes) {
        if (logType.find(t) != std::string::npos) return true;
    }
    return false;
}

// ==================== SidebarServices ====================
SidebarServices::SidebarServices(SecurityService* securityService, FireAntivirus::DataManager* dataManager)
    : _securityService(securityService), _dataManager(dataManager)
{
    NetworkProtection = SidebarNetworkProtectionService(securityService);
    PopupBlocker = SidebarPopupBlockerService(securityService);
    RansomwareProtection = SidebarRansomwareProtectionService(securityService);
    PrivacyProtection = SidebarPrivacyProtectionService(securityService);
    WebProtection = SidebarWebProtectionService(securityService);
    EmailSecurity = SidebarEmailSecurityService(securityService);
    PasswordManager = SidebarPasswordManagerService(securityService);
    NetworkFirewall = SidebarNetworkFirewallService(securityService);
    DeviceControl = SidebarDeviceControlService(dataManager);
    VulnerabilityScanner = SidebarVulnerabilityScannerService(securityService);
    CloudScan = SidebarCloudScanService(securityService);
    SecureBrowser = SidebarSecureBrowserService(securityService);
    MobileSecurity = SidebarMobileSecurityService(securityService);
    SystemOptimizer = SidebarSystemOptimizerService(securityService);
    BackupRecovery = SidebarBackupRecoveryService(securityService);
    SecurityScore = SidebarSecurityScoreService(securityService);
    NetworkTraffic = SidebarNetworkTrafficService(securityService);
    ApplicationMonitor = SidebarApplicationMonitorService(securityService);
    StartupManager = SidebarStartupManagerService(securityService);
    SecurityReport = SidebarSecurityReportService(securityService);
    BehaviorAnalysis = SidebarBehaviorAnalysisService(dataManager);
    SystemTools = SidebarSystemToolsService(securityService);
    SystemInfo = SidebarSystemInfoService(securityService);
    Quarantine = SidebarQuarantineService(securityService);
    TrustZone = SidebarTrustZoneService(securityService);
    LogCenter = SidebarLogCenterService(securityService);
}

void SidebarServices::Initialize() {
    LogManager::LogInfo("Sidebar services initialized");
}

// Sidebar 服务 Enable/IsEnabled 实现（委托给 SecurityService）
bool SidebarNetworkProtectionService::Enable(bool e) {
    bool r = _s ? _s->EnableNetworkProtection(e) : false;
    if (r) { ConfigManager::Config().NetworkProtectionEnabled = e; ConfigManager::SaveConfig(); }
    return r;
}
bool SidebarNetworkProtectionService::IsEnabled() { return _s ? _s->IsNetworkProtectionEnabled() : ConfigManager::Config().NetworkProtectionEnabled; }

bool SidebarPopupBlockerService::Enable(bool e) {
    bool r = _s ? _s->EnablePopupBlocker(e) : false;
    if (r) { ConfigManager::Config().PopupBlockerEnabled = e; ConfigManager::SaveConfig(); }
    return r;
}
bool SidebarPopupBlockerService::IsEnabled() { return _s ? _s->IsPopupBlockerEnabled() : ConfigManager::Config().PopupBlockerEnabled; }

bool SidebarRansomwareProtectionService::Enable(bool e) {
    bool r = _s ? _s->EnableRansomwareProtection(e) : false;
    if (r) { ConfigManager::Config().RansomwareProtectionEnabled = e; ConfigManager::SaveConfig(); }
    return r;
}
bool SidebarRansomwareProtectionService::IsEnabled() { return _s ? _s->IsRansomwareProtectionEnabled() : ConfigManager::Config().RansomwareProtectionEnabled; }

bool SidebarPrivacyProtectionService::Enable(bool e) {
    bool r = _s ? _s->EnablePrivacyProtection(e) : false;
    if (r) { ConfigManager::Config().PrivacyProtectionEnabled = e; ConfigManager::SaveConfig(); }
    return r;
}
bool SidebarPrivacyProtectionService::IsEnabled() { return _s ? _s->IsPrivacyProtectionEnabled() : ConfigManager::Config().PrivacyProtectionEnabled; }

bool SidebarWebProtectionService::Enable(bool e) {
    bool r = _s ? _s->EnableWebProtection(e) : false;
    if (r) { ConfigManager::Config().WebProtectionEnabled = e; ConfigManager::SaveConfig(); }
    return r;
}
bool SidebarWebProtectionService::IsEnabled() { return _s ? _s->IsWebProtectionEnabled() : ConfigManager::Config().WebProtectionEnabled; }

bool SidebarEmailSecurityService::Enable(bool e) {
    bool r = _s ? _s->EnableEmailSecurity(e) : false;
    if (r) { ConfigManager::Config().EmailSecurityEnabled = e; ConfigManager::SaveConfig(); }
    return r;
}
bool SidebarEmailSecurityService::IsEnabled() { return _s ? _s->IsEmailSecurityEnabled() : ConfigManager::Config().EmailSecurityEnabled; }

bool SidebarPasswordManagerService::Enable(bool e) {
    bool r = _s ? _s->EnablePasswordManager(e) : false;
    if (r) { ConfigManager::Config().PasswordManagerEnabled = e; ConfigManager::SaveConfig(); }
    return r;
}
bool SidebarPasswordManagerService::IsEnabled() { return _s ? _s->IsPasswordManagerEnabled() : ConfigManager::Config().PasswordManagerEnabled; }

bool SidebarNetworkFirewallService::Enable(bool e) {
    bool r = _s ? _s->EnableNetworkFirewall(e) : false;
    if (r) { ConfigManager::Config().NetworkFirewallEnabled = e; ConfigManager::SaveConfig(); }
    return r;
}
bool SidebarNetworkFirewallService::IsEnabled() { return _s ? _s->IsNetworkFirewallEnabled() : ConfigManager::Config().NetworkFirewallEnabled; }

bool SidebarDeviceControlService::Enable(bool e) {
    ConfigManager::Config().DeviceControlEnabled = e;
    ConfigManager::SaveConfig();
    return true;
}
bool SidebarDeviceControlService::IsEnabled() { return ConfigManager::Config().DeviceControlEnabled; }

bool SidebarVulnerabilityScannerService::Enable(bool e) {
    bool r = _s ? _s->EnableVulnerabilityScanner(e) : false;
    if (r) { ConfigManager::Config().VulnerabilityScannerEnabled = e; ConfigManager::SaveConfig(); }
    return r;
}
bool SidebarVulnerabilityScannerService::IsEnabled() { return _s ? _s->IsVulnerabilityScannerEnabled() : ConfigManager::Config().VulnerabilityScannerEnabled; }

bool SidebarCloudScanService::Enable(bool e) {
    bool r = _s ? _s->EnableCloudScan(e) : false;
    if (r) { ConfigManager::Config().CloudScanEnabled = e; ConfigManager::SaveConfig(); }
    return r;
}
bool SidebarCloudScanService::IsEnabled() { return _s ? _s->IsCloudScanEnabled() : ConfigManager::Config().CloudScanEnabled; }

bool SidebarSecureBrowserService::Enable(bool e) {
    bool r = _s ? _s->EnableSecureBrowser(e) : false;
    if (r) { ConfigManager::Config().SecureBrowserEnabled = e; ConfigManager::SaveConfig(); }
    return r;
}
bool SidebarSecureBrowserService::IsEnabled() { return _s ? _s->IsSecureBrowserEnabled() : ConfigManager::Config().SecureBrowserEnabled; }

bool SidebarMobileSecurityService::Enable(bool e) {
    bool r = _s ? _s->EnableMobileSecurity(e) : false;
    if (r) { ConfigManager::Config().MobileSecurityEnabled = e; ConfigManager::SaveConfig(); }
    return r;
}
bool SidebarMobileSecurityService::IsEnabled() { return _s ? _s->IsMobileSecurityEnabled() : ConfigManager::Config().MobileSecurityEnabled; }

bool SidebarSystemOptimizerService::Enable(bool e) {
    bool r = _s ? _s->EnableSystemOptimizer(e) : false;
    if (r) { ConfigManager::Config().SystemOptimizerEnabled = e; ConfigManager::SaveConfig(); }
    return r;
}
bool SidebarSystemOptimizerService::IsEnabled() { return _s ? _s->IsSystemOptimizerEnabled() : ConfigManager::Config().SystemOptimizerEnabled; }

bool SidebarBackupRecoveryService::Enable(bool e) {
    bool r = _s ? _s->EnableBackupRecovery(e) : false;
    if (r) { ConfigManager::Config().BackupRecoveryEnabled = e; ConfigManager::SaveConfig(); }
    return r;
}
bool SidebarBackupRecoveryService::IsEnabled() { return _s ? _s->IsBackupRecoveryEnabled() : ConfigManager::Config().BackupRecoveryEnabled; }

bool SidebarSecurityScoreService::Enable(bool e) {
    bool r = _s ? _s->EnableSecurityScore(e) : false;
    if (r) { ConfigManager::Config().SecurityScoreEnabled = e; ConfigManager::SaveConfig(); }
    return r;
}
bool SidebarSecurityScoreService::IsEnabled() { return _s ? _s->IsSecurityScoreEnabled() : ConfigManager::Config().SecurityScoreEnabled; }

bool SidebarNetworkTrafficService::Enable(bool e) {
    bool r = _s ? _s->EnableNetworkTraffic(e) : false;
    if (r) { ConfigManager::Config().NetworkTrafficEnabled = e; ConfigManager::SaveConfig(); }
    return r;
}
bool SidebarNetworkTrafficService::IsEnabled() { return _s ? _s->IsNetworkTrafficEnabled() : ConfigManager::Config().NetworkTrafficEnabled; }

bool SidebarApplicationMonitorService::Enable(bool e) {
    bool r = _s ? _s->EnableApplicationMonitor(e) : false;
    if (r) { ConfigManager::Config().ApplicationMonitorEnabled = e; ConfigManager::SaveConfig(); }
    return r;
}
bool SidebarApplicationMonitorService::IsEnabled() { return _s ? _s->IsApplicationMonitorEnabled() : ConfigManager::Config().ApplicationMonitorEnabled; }

bool SidebarStartupManagerService::Enable(bool e) {
    bool r = _s ? _s->EnableStartupManager(e) : false;
    if (r) { ConfigManager::Config().StartupManagerEnabled = e; ConfigManager::SaveConfig(); }
    return r;
}
bool SidebarStartupManagerService::IsEnabled() { return _s ? _s->IsStartupManagerEnabled() : ConfigManager::Config().StartupManagerEnabled; }

bool SidebarSecurityReportService::Enable(bool e) {
    bool r = _s ? _s->EnableSecurityReport(e) : false;
    if (r) { ConfigManager::Config().SecurityReportEnabled = e; ConfigManager::SaveConfig(); }
    return r;
}
bool SidebarSecurityReportService::IsEnabled() { return _s ? _s->IsSecurityReportEnabled() : ConfigManager::Config().SecurityReportEnabled; }

bool SidebarBehaviorAnalysisService::Enable(bool e) {
    ConfigManager::Config().BehaviorAnalysisEnabled = e;
    ConfigManager::SaveConfig();
    return true;
}
bool SidebarBehaviorAnalysisService::IsEnabled() { return ConfigManager::Config().BehaviorAnalysisEnabled; }

bool SidebarSystemToolsService::Enable(bool e) {
    bool r = _s ? _s->EnableSystemTools(e) : false;
    if (r) { ConfigManager::Config().SystemToolsEnabled = e; ConfigManager::SaveConfig(); }
    return r;
}
bool SidebarSystemToolsService::IsEnabled() { return _s ? _s->IsSystemToolsEnabled() : ConfigManager::Config().SystemToolsEnabled; }

bool SidebarSystemInfoService::Enable(bool e) {
    bool r = _s ? _s->EnableSystemInfo(e) : false;
    if (r) { ConfigManager::Config().SystemInfoEnabled = e; ConfigManager::SaveConfig(); }
    return r;
}
bool SidebarSystemInfoService::IsEnabled() { return _s ? _s->IsSystemInfoEnabled() : ConfigManager::Config().SystemInfoEnabled; }

bool SidebarQuarantineService::Enable(bool e) {
    bool r = _s ? _s->EnableQuarantine(e) : false;
    if (r) { ConfigManager::Config().QuarantineEnabled = e; ConfigManager::SaveConfig(); }
    return r;
}
bool SidebarQuarantineService::IsEnabled() { return _s ? _s->IsQuarantineEnabled() : ConfigManager::Config().QuarantineEnabled; }

bool SidebarTrustZoneService::Enable(bool e) {
    bool r = _s ? _s->EnableTrustZone(e) : false;
    if (r) { ConfigManager::Config().TrustZoneEnabled = e; ConfigManager::SaveConfig(); }
    return r;
}
bool SidebarTrustZoneService::IsEnabled() { return _s ? _s->IsTrustZoneEnabled() : ConfigManager::Config().TrustZoneEnabled; }

bool SidebarLogCenterService::Enable(bool e) {
    bool r = _s ? _s->EnableLogCenter(e) : false;
    if (r) { ConfigManager::Config().LogCenterEnabled = e; ConfigManager::SaveConfig(); }
    return r;
}
bool SidebarLogCenterService::IsEnabled() { return _s ? _s->IsLogCenterEnabled() : ConfigManager::Config().LogCenterEnabled; }

// ==================== UserExperienceManager ====================
UserExperienceManager::UserExperienceManager(FireAntivirus::DataManager* dataManager)
    : _dataManager(dataManager), _isRunning(false)
{
    InitializeDefaultSettings();
}

void UserExperienceManager::InitializeDefaultSettings() {
    _userConfig.NotificationLevel = NotificationLevel::Normal;
    _userConfig.AutoLearnEnabled = true;
    _userConfig.FeedbackCollection = true;
    _userConfig.LogDetailLevel = LogDetail::Medium;
    _userConfig.SecurityConfirmation = SecurityLevel::Medium;
    _userConfig.UiTheme = ThemeType::SystemDefault;
    _userConfig.Language = "zh-CN";
}

void UserExperienceManager::LoadUserConfiguration() {
    // 简化：从 DataManager 或本地文件加载
}

void UserExperienceManager::SaveUserConfiguration() {
    // 简化：序列化到本地
}

void UserExperienceManager::Start() {
    _isRunning = true;
    _userFeedbackThread = std::thread([this]() { UserFeedbackLoop(); });
    _learningThread = std::thread([this]() { MachineLearningLoop(); });
    LogManager::LogInfo("UserExperienceManager started");
}

void UserExperienceManager::Stop() {
    _isRunning = false;
    if (_userFeedbackThread.joinable()) _userFeedbackThread.join();
    if (_learningThread.joinable()) _learningThread.join();
    SaveUserConfiguration();
    LogManager::LogInfo("UserExperienceManager stopped");
}

void UserExperienceManager::UserFeedbackLoop() {
    while (_isRunning) {
        std::this_thread::sleep_for(std::chrono::seconds(30));
    }
}

void UserExperienceManager::MachineLearningLoop() {
    while (_isRunning) {
        std::this_thread::sleep_for(std::chrono::minutes(5));
    }
}

void UserExperienceManager::ShowCustomizedNotification(const std::string&, const std::string&, NotificationType, NotificationSeverity) {
    // 简化：输出日志
}

UserConfig UserExperienceManager::GetCurrentConfiguration() {
    return _userConfig.Clone();
}

void UserExperienceManager::UpdateConfiguration(const UserConfig& newConfig) {
    _userConfig = newConfig;
    SaveUserConfiguration();
}

void UserExperienceManager::CollectUserFeedback(const std::string& feedbackType, const std::string& message, int rating) {
    if (!_userConfig.FeedbackCollection) return;
    LogManager::LogInfo("UserFeedback [" + feedbackType + "] rating=" + std::to_string(rating) + ": " + message);
}

}} // namespace FireAntivirus::Services
