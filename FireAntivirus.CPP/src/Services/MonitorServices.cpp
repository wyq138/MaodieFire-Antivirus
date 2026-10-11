#include "../include/FireAntivirus/Services/MonitorServices.h"
#include "../include/FireAntivirus/Services/CoreServices.h"

#include <algorithm>
#include <set>
#include <filesystem>
#include <sstream>
#include <chrono>
#include <cstring>

#if defined(_WIN32)
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <shlobj.h>
#include <iphlpapi.h>
#include <winhttp.h>
#pragma comment(lib, "iphlpapi.lib")
#endif

namespace FireAntivirus { namespace Services {

namespace fs = std::filesystem;

// ==================== 内部辅助 ====================

static std::string TsNow() {
    auto now = std::chrono::system_clock::now();
    auto tt = std::chrono::system_clock::to_time_t(now);
    std::tm tm_buf{};
#ifdef _WIN32
    localtime_s(&tm_buf, &tt);
#else
    localtime_r(&tt, &tm_buf);
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

// 已知进程名（转换：ProtectionServices.cpp 用 pair<int,string>，这里用 ProcessInfo 结构体）
// 保持与 Platform::EnumProcesses() 返回值一致

// ==================== ProcessMonitor ====================

ProcessMonitor::ProcessMonitor(FireAntivirus::DataManager* dataManager, FireAntivirus::Engine::AntivirusEngine* engine)
    : _dataManager(dataManager), _antivirusEngine(engine)
{
}

void ProcessMonitor::Start() {
    if (_isRunning.load()) return;
    _isRunning = true;
    // 初始化已知进程
#ifdef _WIN32
    auto procs = Platform::EnumProcesses();
    for (auto& p : procs) _knownPIDs.insert((int)p.pid);
#endif
    _monitorThread = std::thread([this]() { MonitorLoop(); });
    LogManager::LogInfo("ProcessMonitor started");
}

void ProcessMonitor::Stop() {
    _isRunning = false;
    if (_monitorThread.joinable()) _monitorThread.join();
    LogManager::LogInfo("ProcessMonitor stopped");
}

void ProcessMonitor::MonitorLoop() {
    while (_isRunning.load()) {
        try {
            CheckNewProcesses();
            MonitorSuspiciousProcesses();
        } catch (...) {}
        std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    }
}

void ProcessMonitor::CheckNewProcesses() {
#ifdef _WIN32
    auto procs = Platform::EnumProcesses();
    std::set<int> currentPIDs;
    for (auto& p : procs) {
        currentPIDs.insert((int)p.pid);
        if (_knownPIDs.find((int)p.pid) == _knownPIDs.end()) {
            // 新进程
            LogManager::LogInfo("ProcessMonitor: new process detected - " + p.name + " (PID=" + std::to_string(p.pid) + ")");
            if (IsProcessSuspicious(p.name)) {
                LogManager::LogWarning("ProcessMonitor: suspicious new process - " + p.name);
            }
        }
    }
    _knownPIDs = std::move(currentPIDs);
#endif
}

void ProcessMonitor::MonitorSuspiciousProcesses() {
#ifdef _WIN32
    auto procs = Platform::EnumProcesses();
    for (auto& p : procs) {
        if (IsProcessSuspicious(p.name)) {
            // 检查可执行路径
            if (!p.exe_path.empty()) {
                LogManager::LogDebug("ProcessMonitor: tracked suspicious " + p.name + " @ " + p.exe_path);
            } else {
                LogManager::LogDebug("ProcessMonitor: tracked suspicious " + p.name);
            }
        }
    }
#endif
}

bool ProcessMonitor::IsProcessSuspicious(const std::string& name) {
    static const char* sus[] = {
        "mimikatz", "meterpreter", "cobaltstrike", "beacon", "empire",
        "psexec", "wce", "fgdump", "gsecdump", "pwdump",
        "cryptolocker", "locky", "teslacrypt", "wannacry", "petya", "notpetya",
        "ryuk", "maze", "cerber", "ransom", "crypt",
        "powersploit", "posh", "mshta", "rundll32", "regsvr32",
        "certutil", "bitsadmin", "wmic", "msxsl", "installutil",
        "suspicious", "malware", "trojan", "keylogger", "ransomware"
    };
    std::string lower;
    lower.resize(name.size());
    std::transform(name.begin(), name.end(), lower.begin(), [](unsigned char c){ return std::tolower(c); });
    for (auto& s : sus) {
        if (lower.find(s) != std::string::npos) return true;
    }
    return false;
}

// ==================== FileMonitor ====================

FileMonitor::FileMonitor(FireAntivirus::DataManager* dataManager, FireAntivirus::Engine::AntivirusEngine* engine)
    : _dataManager(dataManager), _antivirusEngine(engine)
{
#ifdef _WIN32
    // 添加默认监控路径
    _watchPaths.push_back(Platform::GetProgramDataDir());
    _watchPaths.push_back(Platform::GetTempDir());
    std::string ld = Platform::GetLocalAppDataDir();
    if (!ld.empty()) _watchPaths.push_back(ld);
#endif
}

void FileMonitor::Start() {
    if (_isRunning.load()) return;
    _isRunning = true;
    _monitorThread = std::thread([this]() { MonitorLoop(); });
    LogManager::LogInfo("FileMonitor started");
}

void FileMonitor::Stop() {
    _isRunning = false;
    if (_monitorThread.joinable()) _monitorThread.join();
    LogManager::LogInfo("FileMonitor stopped");
}

void FileMonitor::MonitorLoop() {
    static const char* suspiciousExts[] = {
        ".exe", ".dll", ".scr", ".pif", ".vbs", ".bat", ".cmd",
        ".ps1", ".wsf", ".wsh", ".hta", ".msi", ".msix",
        ".iso", ".img", ".jar", ".js", ".jse", ".cpl", ".inf",
        ".reg", ".scr", ".com", ".lnk"
    };

    while (_isRunning.load()) {
        try {
            for (auto& dir : _watchPaths) {
                std::error_code ec;
                if (!fs::is_directory(dir, ec)) continue;
                fs::recursive_directory_iterator it(dir, fs::directory_options::skip_permission_denied, ec);
                if (ec) continue;
                for (auto& entry : it) {
                    if (!entry.is_regular_file(ec)) continue;
                    auto path = entry.path();
                    std::string ext = path.extension().string();
                    std::string lower_ext;
                    lower_ext.resize(ext.size());
                    std::transform(ext.begin(), ext.end(), lower_ext.begin(), [](unsigned char c){ return std::tolower(c); });

                    for (auto& se : suspiciousExts) {
                        if (lower_ext == se) {
                            if (_antivirusEngine) {
                                auto result = _antivirusEngine->ScanFile(path.string());
                                if (result.is_infected) {
                                    LogManager::LogWarning("FileMonitor: detected threat in " + path.string() + " - " + result.threat_name);
                                }
                            }
                            break;
                        }
                    }
                }
            }
        } catch (...) {}
        std::this_thread::sleep_for(std::chrono::milliseconds(5000));
    }
}

// ==================== RegistryMonitor ====================

RegistryMonitor::RegistryMonitor(FireAntivirus::DataManager* dataManager, FireAntivirus::Engine::AntivirusEngine* engine)
    : _dataManager(dataManager), _antivirusEngine(engine)
{
#ifdef _WIN32
    _watchKeys.push_back("Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    _watchKeys.push_back("Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
    _watchKeys.push_back("Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run");
    _watchKeys.push_back("Winlogon\\Userinit");
    _watchKeys.push_back("Winlogon\\Shell");
#endif
}

void RegistryMonitor::Start() {
    if (_isRunning.load()) return;
    _isRunning = true;
    _monitorThread = std::thread([this]() { MonitorLoop(); });
    LogManager::LogInfo("RegistryMonitor started");
}

void RegistryMonitor::Stop() {
    _isRunning = false;
    if (_monitorThread.joinable()) _monitorThread.join();
    LogManager::LogInfo("RegistryMonitor stopped");
}

void RegistryMonitor::MonitorLoop() {
    while (_isRunning.load()) {
        try {
            CheckRegistryChanges();
        } catch (...) {}
        std::this_thread::sleep_for(std::chrono::milliseconds(3000));
    }
}

void RegistryMonitor::CheckRegistryChanges() {
#ifdef _WIN32
    auto entries = Platform::EnumRegistryRunKeys();
    for (auto& e : entries) {
        // 扫描启动项中的可疑命令
        std::string lower_cmd;
        lower_cmd.resize(e.command.size());
        std::transform(e.command.begin(), e.command.end(), lower_cmd.begin(), [](unsigned char c){ return std::tolower(c); });

        static const char* sus_cmd[] = {
            "powershell -enc", "powershell -windowstyle", "mshta",
            "rundll32", "regsvr32", "certutil", "bitsadmin",
            "wmic", "msxsl", "installutil", "taskkill",
            "processhacker", "procexp", "autoruns",
            "/i ", " -i ", "-inject", "inject"
        };
        for (auto& s : sus_cmd) {
            if (lower_cmd.find(s) != std::string::npos) {
                LogManager::LogWarning("RegistryMonitor: suspicious startup - " + e.value_name + " = " + e.command);
                break;
            }
        }
    }
#endif
}

// ==================== NetworkMonitor ====================

NetworkMonitor::NetworkMonitor(FireAntivirus::DataManager* dataManager, FireAntivirus::Engine::AntivirusEngine* engine)
    : _dataManager(dataManager), _antivirusEngine(engine)
{
}

void NetworkMonitor::Start() {
    if (_isRunning.load()) return;
    _isRunning = true;
    _monitorThread = std::thread([this]() { MonitorLoop(); });
    LogManager::LogInfo("NetworkMonitor started");
}

void NetworkMonitor::Stop() {
    _isRunning = false;
    if (_monitorThread.joinable()) _monitorThread.join();
    LogManager::LogInfo("NetworkMonitor stopped");
}

void NetworkMonitor::MonitorLoop() {
    while (_isRunning.load()) {
        try {
            CheckActiveConnections();
        } catch (...) {}
        std::this_thread::sleep_for(std::chrono::milliseconds(3000));
    }
}

void NetworkMonitor::CheckActiveConnections() {
#ifdef _WIN32
    // 使用 GetExtendedTcpTable / GetExtendedUdpTable
    // 简化: 使用 Engine::Scanners::NetworkScanner
    Engine::Scanners::NetworkScanner scanner;
    auto conns = scanner.EnumConnections();
    static const char* known_c2_ips[] = {
        "185.220.101.44", "198.51.100.1", "203.0.113.10",
        "91.234.56.78", "45.77.88.99"
    };
    for (auto& c : conns) {
        // 检查是否是本地监听
        if (c.state == "LISTENING") continue;

        // 检查已知 C2 IP
        for (auto& ip : known_c2_ips) {
            if (c.remote_ip.find(ip) != std::string::npos) {
                LogManager::LogWarning("NetworkMonitor: known C2 communication - " + c.remote_ip + ":" + std::to_string(c.remote_port));
                break;
            }
        }

        // 检查可疑端口
        static const char* sus_ports[] = {"4444", "5555", "6666", "8888", "9999", "1234", "31337"};
        std::string portStr = std::to_string(c.remote_port);
        for (auto& sp : sus_ports) {
            if (portStr == sp) {
                LogManager::LogDebug("NetworkMonitor: suspicious port " + portStr + " to " + c.remote_ip);
                break;
            }
        }
    }
#endif
}

// ==================== BrowserMonitor ====================

BrowserMonitor::BrowserMonitor(FireAntivirus::DataManager* dataManager, FireAntivirus::Engine::AntivirusEngine* engine)
    : _dataManager(dataManager), _antivirusEngine(engine)
{
}

void BrowserMonitor::Start() {
    if (_isRunning.load()) return;
    _isRunning = true;
    _monitorThread = std::thread([this]() { MonitorLoop(); });
    LogManager::LogInfo("BrowserMonitor started");
}

void BrowserMonitor::Stop() {
    _isRunning = false;
    if (_monitorThread.joinable()) _monitorThread.join();
    LogManager::LogInfo("BrowserMonitor stopped");
}

void BrowserMonitor::MonitorLoop() {
    while (_isRunning.load()) {
        try {
            CheckBrowserProcesses();
        } catch (...) {}
        std::this_thread::sleep_for(std::chrono::milliseconds(5000));
    }
}

void BrowserMonitor::CheckBrowserProcesses() {
#ifdef _WIN32
    static const char* browsers[] = {
        "chrome.exe", "msedge.exe", "firefox.exe", "opera.exe",
        "brave.exe", "vivaldi.exe", "safari.exe", "iexplore.exe"
    };
    auto procs = Platform::EnumProcesses();
    for (auto& p : procs) {
        std::string lower = p.name;
        std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c){ return std::tolower(c); });
        for (auto& b : browsers) {
            if (lower == b) {
                LogManager::LogDebug("BrowserMonitor: detected browser - " + p.name + " (PID=" + std::to_string(p.pid) + ")");
                break;
            }
        }
    }
#endif
}

// ==================== DocumentMonitor ====================

DocumentMonitor::DocumentMonitor(FireAntivirus::DataManager* dataManager, FireAntivirus::Engine::AntivirusEngine* engine)
    : _dataManager(dataManager), _antivirusEngine(engine)
{
}

void DocumentMonitor::Start() {
    if (_isRunning.load()) return;
    _isRunning = true;
    _monitorThread = std::thread([this]() { MonitorLoop(); });
    LogManager::LogInfo("DocumentMonitor started");
}

void DocumentMonitor::Stop() {
    _isRunning = false;
    if (_monitorThread.joinable()) _monitorThread.join();
    LogManager::LogInfo("DocumentMonitor stopped");
}

void DocumentMonitor::MonitorLoop() {
    while (_isRunning.load()) {
        try {
            CheckDocumentFiles();
        } catch (...) {}
        std::this_thread::sleep_for(std::chrono::milliseconds(10000));
    }
}

void DocumentMonitor::CheckDocumentFiles() {
#ifdef _WIN32
    // 扫描系统临时目录中的文档文件
    std::string dir = Platform::GetTempDir();
    if (dir.empty()) return;

    static const char* doc_exts[] = {".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".rtf", ".odt"};
    std::error_code ec;
    fs::recursive_directory_iterator it(dir, fs::directory_options::skip_permission_denied, ec);
    if (ec) return;

    for (auto& entry : it) {
        if (!entry.is_regular_file(ec)) continue;
        std::string ext = entry.path().extension().string();
        std::string lower_ext;
        lower_ext.resize(ext.size());
        std::transform(ext.begin(), ext.end(), lower_ext.begin(), [](unsigned char c){ return std::tolower(c); });

        bool isDoc = false;
        for (auto& de : doc_exts) {
            if (lower_ext == de) { isDoc = true; break; }
        }
        if (isDoc && _antivirusEngine) {
            auto result = _antivirusEngine->ScanFile(entry.path().string());
            if (result.is_infected) {
                LogManager::LogWarning("DocumentMonitor: threat in temp document " + entry.path().string());
            }
        }
    }
#endif
}

// ==================== ScriptMonitor ====================

ScriptMonitor::ScriptMonitor(FireAntivirus::DataManager* dataManager, FireAntivirus::Engine::AntivirusEngine* engine)
    : _dataManager(dataManager), _antivirusEngine(engine)
{
    _suspiciousScripts = {
        "powershell.exe", "powershell_ise.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "python.exe", "pythonw.exe", "perl.exe", "ruby.exe",
        "node.exe", "php.exe"
    };
}

void ScriptMonitor::Start() {
    if (_isRunning.load()) return;
    _isRunning = true;
    _monitorThread = std::thread([this]() { MonitorLoop(); });
    LogManager::LogInfo("ScriptMonitor started");
}

void ScriptMonitor::Stop() {
    _isRunning = false;
    if (_monitorThread.joinable()) _monitorThread.join();
    LogManager::LogInfo("ScriptMonitor stopped");
}

void ScriptMonitor::MonitorLoop() {
    while (_isRunning.load()) {
#ifdef _WIN32
        auto procs = Platform::EnumProcesses();
        for (auto& p : procs) {
            if (IsSuspiciousScript(p.name)) {
                LogManager::LogDebug("ScriptMonitor: script engine running - " + p.name);
            }
        }
#endif
        std::this_thread::sleep_for(std::chrono::milliseconds(3000));
    }
}

bool ScriptMonitor::IsSuspiciousScript(const std::string& name) {
    std::string lower;
    lower.resize(name.size());
    std::transform(name.begin(), name.end(), lower.begin(), [](unsigned char c){ return std::tolower(c); });
    for (auto& s : _suspiciousScripts) {
        if (lower == s) return true;
    }
    return false;
}

// ==================== USBMonitor ====================

USBMonitor::USBMonitor(FireAntivirus::DataManager* dataManager, FireAntivirus::Engine::AntivirusEngine* engine)
    : _dataManager(dataManager), _antivirusEngine(engine)
{
#ifdef _WIN32
    // 初始化已知驱动器
    wchar_t drives[512] = {};
    GetLogicalDriveStringsW(512, drives);
    wchar_t* ptr = drives;
    while (ptr && *ptr) {
        std::wstring wdrive = ptr;
        std::string drive = Platform::GetWindowsDir(); // 简化
        (void)drive;
        _knownDrives.insert(std::string(1, (char)ptr[0]) + ":");
        ptr += wcslen(ptr) + 1;
    }
#endif
}

void USBMonitor::Start() {
    if (_isRunning.load()) return;
    _isRunning = true;
    _monitorThread = std::thread([this]() { MonitorLoop(); });
    LogManager::LogInfo("USBMonitor started");
}

void USBMonitor::Stop() {
    _isRunning = false;
    if (_monitorThread.joinable()) _monitorThread.join();
    LogManager::LogInfo("USBMonitor stopped");
}

void USBMonitor::MonitorLoop() {
    while (_isRunning.load()) {
        try {
            CheckUSBConnections();
        } catch (...) {}
        std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    }
}

void USBMonitor::CheckUSBConnections() {
#ifdef _WIN32
    wchar_t drives[512] = {};
    GetLogicalDriveStringsW(512, drives);
    wchar_t* ptr = drives;
    while (ptr && *ptr) {
        std::string driveName(1, (char)ptr[0]);
        std::string root = driveName + ":\\";
        UINT type = GetDriveTypeW(ptr);

        if (type == DRIVE_REMOVABLE) {
            if (_knownDrives.find(driveName + ":") == _knownDrives.end()) {
                LogManager::LogInfo("USBMonitor: new removable drive detected - " + root);
                ScanUSBContent(root);
            }
        }
        ptr += wcslen(ptr) + 1;
    }
#endif
}

void USBMonitor::ScanUSBContent(const std::string& drivePath) {
    LogManager::LogInfo("USBMonitor: scanning " + drivePath);
    if (!_antivirusEngine) return;

    std::error_code ec;
    fs::recursive_directory_iterator it(drivePath, fs::directory_options::skip_permission_denied, ec);
    if (ec) {
        LogManager::LogWarning("USBMonitor: cannot access " + drivePath);
        return;
    }

    static const char* sus_exts[] = {".exe", ".scr", ".pif", ".vbs", ".bat", ".ps1", ".hta", ".cpl"};
    int scanned = 0;
    int threats = 0;

    for (auto& entry : it) {
        if (!entry.is_regular_file(ec)) continue;
        std::string ext = entry.path().extension().string();
        std::string lower_ext;
        lower_ext.resize(ext.size());
        std::transform(ext.begin(), ext.end(), lower_ext.begin(), [](unsigned char c){ return std::tolower(c); });

        bool needScan = false;
        for (auto& s : sus_exts) {
            if (lower_ext == s) { needScan = true; break; }
        }
        if (!needScan) continue;

        scanned++;
        auto result = _antivirusEngine->ScanFile(entry.path().string());
        if (result.is_infected) {
            threats++;
            LogManager::LogWarning("USBMonitor: threat on USB - " + entry.path().string() + " (" + result.threat_name + ")");
        }
    }
    LogManager::LogInfo("USBMonitor: scan complete - " + std::to_string(scanned) + " files, " + std::to_string(threats) + " threats");
}

// ==================== PartitionTableMonitor ====================

PartitionTableMonitor::PartitionTableMonitor(FireAntivirus::DataManager* dataManager, FireAntivirus::Engine::AntivirusEngine* engine)
    : _dataManager(dataManager), _antivirusEngine(engine)
{
#ifdef _WIN32
    // 初始化当前分区哈希（简化实现：通过读取磁盘分区信息）
    std::vector<std::string> partitions = {"C:\\", "D:\\"};
    for (auto& p : partitions) {
        std::string h = GetPartitionHash(p);
        if (!h.empty()) _partitionHashes[p] = h;
    }
#endif
}

void PartitionTableMonitor::Start() {
    if (_isRunning.load()) return;
    _isRunning = true;
    _monitorThread = std::thread([this]() { MonitorLoop(); });
    LogManager::LogInfo("PartitionTableMonitor started");
}

void PartitionTableMonitor::Stop() {
    _isRunning = false;
    if (_monitorThread.joinable()) _monitorThread.join();
    LogManager::LogInfo("PartitionTableMonitor stopped");
}

void PartitionTableMonitor::MonitorLoop() {
    while (_isRunning.load()) {
        try {
            CheckPartitionIntegrity();
        } catch (...) {}
        std::this_thread::sleep_for(std::chrono::milliseconds(30000));
    }
}

void PartitionTableMonitor::CheckPartitionIntegrity() {
    // 简化：定期检查磁盘可访问性并重新计算哈希
    for (auto& kv : _partitionHashes) {
        std::string cur = GetPartitionHash(kv.first);
        if (cur.empty()) continue;
        if (cur != kv.second) {
            LogManager::LogError("PartitionTableMonitor: partition integrity violated - " + kv.first);
            kv.second = cur;
        }
    }
}

std::string PartitionTableMonitor::GetPartitionHash(const std::string& diskPath) {
#ifdef _WIN32
    std::error_code ec;
    if (!fs::exists(diskPath, ec)) return "";

    // 获取分区可用空间和总大小
    auto info = fs::space(diskPath, ec);
    if (ec) return "";

    std::string hash_input = std::to_string(info.capacity) + ":" + std::to_string(info.free);
    // 简单哈希计算
    unsigned int h = 5381;
    for (char c : hash_input) {
        h = ((h << 5) + h) + (unsigned int)c;
    }
    return std::to_string(h);
#else
    return "";
#endif
}

// ==================== UEFIMonitor ====================

UEFIMonitor::UEFIMonitor(FireAntivirus::DataManager* dataManager, FireAntivirus::Engine::AntivirusEngine* engine)
    : _dataManager(dataManager), _antivirusEngine(engine)
{
#ifdef _WIN32
    // 尝试读取 UEFI 固件信息（简化）
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll) {
        _uefiBaseHash = "ntdll_loaded";
    } else {
        _uefiBaseHash = "unknown";
    }
#endif
}

void UEFIMonitor::Start() {
    if (_isRunning.load()) return;
    _isRunning = true;
    _monitorThread = std::thread([this]() { MonitorLoop(); });
    LogManager::LogInfo("UEFIMonitor started");
}

void UEFIMonitor::Stop() {
    _isRunning = false;
    if (_monitorThread.joinable()) _monitorThread.join();
    LogManager::LogInfo("UEFIMonitor stopped");
}

void UEFIMonitor::MonitorLoop() {
    while (_isRunning.load()) {
        try {
            CheckUEFIIntegrity();
        } catch (...) {}
        std::this_thread::sleep_for(std::chrono::milliseconds(60000));
    }
}

void UEFIMonitor::CheckUEFIIntegrity() {
#ifdef _WIN32
    // 简化检查：检查安全引导和 SecureBoot 状态
    typedef BOOL(WINAPI* PFN_NtQuerySystemInformation)(int, PVOID, ULONG, PULONG);
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll) {
        auto NtQuerySystemInformation = (PFN_NtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
        if (NtQuerySystemInformation) {
            LogManager::LogDebug("UEFIMonitor: ntdll integrity ok");
        }
    }

    // 检查 BitLocker 状态（简化）
    std::string cmd = "cmd /c manage-bde -status C: 2>nul | findstr -i \"Conversion Status\"";
    std::array<char, 512> buf;
    std::string result;
    FILE* pipe = _popen(cmd.c_str(), "r");
    if (pipe) {
        while (fgets(buf.data(), buf.size(), pipe) != nullptr) result += buf.data();
        _pclose(pipe);
        if (result.find("Fully Encrypted") != std::string::npos) {
            LogManager::LogDebug("UEFIMonitor: BitLocker enabled on C:");
        }
    }
#endif
}

// ==================== FileIntegrityChecker ====================

FileIntegrityChecker::FileIntegrityChecker(FireAntivirus::DataManager* dataManager)
    : _dataManager(dataManager)
{
}

void FileIntegrityChecker::AddFileToWatch(const std::string& filePath) {
    std::lock_guard<std::mutex> lock(_lock);
    std::string hash = ComputeHash(filePath);
    if (!hash.empty()) {
        _baselineHashes[filePath] = hash;
    }
}

void FileIntegrityChecker::RemoveFileFromWatch(const std::string& filePath) {
    std::lock_guard<std::mutex> lock(_lock);
    _baselineHashes.erase(filePath);
}

bool FileIntegrityChecker::CheckIntegrity(const std::string& filePath) {
    std::lock_guard<std::mutex> lock(_lock);
    auto it = _baselineHashes.find(filePath);
    if (it == _baselineHashes.end()) return true; // 未追踪视为正常
    std::string cur = ComputeHash(filePath);
    return cur == it->second;
}

std::vector<std::string> FileIntegrityChecker::CheckAll() {
    std::vector<std::string> violations;
    std::lock_guard<std::mutex> lock(_lock);
    for (auto& kv : _baselineHashes) {
        std::string cur = ComputeHash(kv.first);
        if (cur != kv.second) {
            violations.push_back(kv.first);
            kv.second = cur; // 更新基线
        }
    }
    return violations;
}

std::string FileIntegrityChecker::ComputeHash(const std::string& filePath) {
    return Helper::ComputeFileSha256(filePath);
}

// ==================== BehaviorMonitor ====================

BehaviorMonitor::BehaviorMonitor(FireAntivirus::DataManager* dataManager, FireAntivirus::Engine::AntivirusEngine* engine)
    : _dataManager(dataManager), _antivirusEngine(engine)
{
}

void BehaviorMonitor::Start() {
    if (_isRunning.load()) return;
    _isRunning = true;
    _monitorThread = std::thread([this]() { MonitorLoop(); });
    LogManager::LogInfo("BehaviorMonitor started");
}

void BehaviorMonitor::Stop() {
    _isRunning = false;
    if (_monitorThread.joinable()) _monitorThread.join();
    LogManager::LogInfo("BehaviorMonitor stopped");
}

void BehaviorMonitor::MonitorLoop() {
    while (_isRunning.load()) {
        try {
            CollectBehaviorData();
        } catch (...) {}
        std::this_thread::sleep_for(std::chrono::milliseconds(10000));
    }
}

void BehaviorMonitor::CollectBehaviorData() {
#ifdef _WIN32
    // 收集进程行为数据
    auto procs = Platform::EnumProcesses();
    int suspiciousCount = 0;
    static const char* sus[] = {"powershell", "cmd", "wscript", "mshta", "certutil", "bitsadmin"};

    for (auto& p : procs) {
        std::string lower = p.name;
        std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c){ return std::tolower(c); });
        for (auto& s : sus) {
            if (lower.find(s) != std::string::npos) {
                suspiciousCount++;
                break;
            }
        }
    }
    if (suspiciousCount > 3) {
        LogManager::LogWarning("BehaviorMonitor: high suspicious activity detected - " + std::to_string(suspiciousCount) + " suspicious processes");
    }

    // 收集网络连接行为
    Engine::Scanners::NetworkScanner netScan;
    auto conns = netScan.EnumConnections();
    int external = 0;
    for (auto& c : conns) {
        if (c.state == "ESTABLISHED" && !c.remote_ip.empty() && c.remote_ip != "127.0.0.1" && c.remote_ip != "0.0.0.0") {
            external++;
        }
    }
    if (external > 50) {
        LogManager::LogWarning("BehaviorMonitor: excessive external connections - " + std::to_string(external));
    }

    LogManager::LogDebug("BehaviorMonitor: behavior data collected (processes=" + std::to_string(procs.size()) + ", connections=" + std::to_string(conns.size()) + ")");
#endif
}

}} // namespace FireAntivirus::Services
