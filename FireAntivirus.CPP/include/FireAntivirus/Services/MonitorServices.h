#pragma once

#include "CoreServices.h"
#include "../Engine/AntivirusEngine.h"
#include "../Platform/Windows.h"
#include "../Helper.h"

namespace FireAntivirus { namespace Services {

// ============ ProcessMonitor ============
class ProcessMonitor : public IMonitor {
public:
    ProcessMonitor(FireAntivirus::DataManager* dataManager, FireAntivirus::Engine::AntivirusEngine* antivirusEngine);
    void Start() override;
    void Stop() override;

private:
    FireAntivirus::DataManager* _dataManager;
    FireAntivirus::Engine::AntivirusEngine* _antivirusEngine;
    std::atomic<bool> _isRunning{false};
    std::thread _monitorThread;
    std::set<int> _knownPIDs;

    void MonitorLoop();
    void CheckNewProcesses();
    void MonitorSuspiciousProcesses();
    bool IsProcessSuspicious(const std::string& name);
};

// ============ FileMonitor ============
class FileMonitor : public IMonitor {
public:
    FileMonitor(FireAntivirus::DataManager* dataManager, FireAntivirus::Engine::AntivirusEngine* antivirusEngine);
    void Start() override;
    void Stop() override;

private:
    FireAntivirus::DataManager* _dataManager;
    FireAntivirus::Engine::AntivirusEngine* _antivirusEngine;
    std::atomic<bool> _isRunning{false};
    std::thread _monitorThread;
    std::vector<std::string> _watchPaths;
    void MonitorLoop();
};

// ============ RegistryMonitor ============
class RegistryMonitor : public IMonitor {
public:
    RegistryMonitor(FireAntivirus::DataManager* dataManager, FireAntivirus::Engine::AntivirusEngine* antivirusEngine);
    void Start() override;
    void Stop() override;

private:
    FireAntivirus::DataManager* _dataManager;
    FireAntivirus::Engine::AntivirusEngine* _antivirusEngine;
    std::atomic<bool> _isRunning{false};
    std::thread _monitorThread;
    std::vector<std::string> _watchKeys;
    void MonitorLoop();
    void CheckRegistryChanges();
};

// ============ NetworkMonitor ============
class NetworkMonitor : public IMonitor {
public:
    NetworkMonitor(FireAntivirus::DataManager* dataManager, FireAntivirus::Engine::AntivirusEngine* antivirusEngine);
    void Start() override;
    void Stop() override;

private:
    FireAntivirus::DataManager* _dataManager;
    FireAntivirus::Engine::AntivirusEngine* _antivirusEngine;
    std::atomic<bool> _isRunning{false};
    std::thread _monitorThread;
    void MonitorLoop();
    void CheckActiveConnections();
};

// ============ BrowserMonitor ============
class BrowserMonitor : public IMonitor {
public:
    BrowserMonitor(FireAntivirus::DataManager* dataManager, FireAntivirus::Engine::AntivirusEngine* antivirusEngine);
    void Start() override;
    void Stop() override;

private:
    FireAntivirus::DataManager* _dataManager;
    FireAntivirus::Engine::AntivirusEngine* _antivirusEngine;
    std::atomic<bool> _isRunning{false};
    std::thread _monitorThread;
    void MonitorLoop();
    void CheckBrowserProcesses();
};

// ============ DocumentMonitor ============
class DocumentMonitor : public IMonitor {
public:
    DocumentMonitor(FireAntivirus::DataManager* dataManager, FireAntivirus::Engine::AntivirusEngine* antivirusEngine);
    void Start() override;
    void Stop() override;

private:
    FireAntivirus::DataManager* _dataManager;
    FireAntivirus::Engine::AntivirusEngine* _antivirusEngine;
    std::atomic<bool> _isRunning{false};
    std::thread _monitorThread;
    void MonitorLoop();
    void CheckDocumentFiles();
};

// ============ ScriptMonitor ============
class ScriptMonitor : public IMonitor {
public:
    ScriptMonitor(FireAntivirus::DataManager* dataManager, FireAntivirus::Engine::AntivirusEngine* antivirusEngine);
    void Start() override;
    void Stop() override;

private:
    FireAntivirus::DataManager* _dataManager;
    FireAntivirus::Engine::AntivirusEngine* _antivirusEngine;
    std::atomic<bool> _isRunning{false};
    std::thread _monitorThread;
    std::vector<std::string> _suspiciousScripts;
    void MonitorLoop();
    bool IsSuspiciousScript(const std::string& name);
};

// ============ USBMonitor ============
class USBMonitor : public IMonitor {
public:
    USBMonitor(FireAntivirus::DataManager* dataManager, FireAntivirus::Engine::AntivirusEngine* antivirusEngine);
    void Start() override;
    void Stop() override;

private:
    FireAntivirus::DataManager* _dataManager;
    FireAntivirus::Engine::AntivirusEngine* _antivirusEngine;
    std::atomic<bool> _isRunning{false};
    std::thread _monitorThread;
    std::set<std::string> _knownDrives;
    void MonitorLoop();
    void CheckUSBConnections();
    void ScanUSBContent(const std::string& drivePath);
};

// ============ PartitionTableMonitor ============
class PartitionTableMonitor : public IMonitor {
public:
    PartitionTableMonitor(FireAntivirus::DataManager* dataManager, FireAntivirus::Engine::AntivirusEngine* antivirusEngine);
    void Start() override;
    void Stop() override;

private:
    FireAntivirus::DataManager* _dataManager;
    FireAntivirus::Engine::AntivirusEngine* _antivirusEngine;
    std::atomic<bool> _isRunning{false};
    std::thread _monitorThread;
    std::unordered_map<std::string, std::string> _partitionHashes;
    void MonitorLoop();
    void CheckPartitionIntegrity();
    std::string GetPartitionHash(const std::string& diskPath);
};

// ============ UEFIMonitor ============
class UEFIMonitor : public IMonitor {
public:
    UEFIMonitor(FireAntivirus::DataManager* dataManager, FireAntivirus::Engine::AntivirusEngine* antivirusEngine);
    void Start() override;
    void Stop() override;

private:
    FireAntivirus::DataManager* _dataManager;
    FireAntivirus::Engine::AntivirusEngine* _antivirusEngine;
    std::atomic<bool> _isRunning{false};
    std::thread _monitorThread;
    std::string _uefiBaseHash;
    void MonitorLoop();
    void CheckUEFIIntegrity();
};

// ============ FileIntegrityChecker ============
class FileIntegrityChecker {
public:
    explicit FileIntegrityChecker(FireAntivirus::DataManager* dataManager);
    void AddFileToWatch(const std::string& filePath);
    void RemoveFileFromWatch(const std::string& filePath);
    bool CheckIntegrity(const std::string& filePath);
    std::vector<std::string> CheckAll();

private:
    FireAntivirus::DataManager* _dataManager;
    std::unordered_map<std::string, std::string> _baselineHashes;
    std::mutex _lock;
    std::string ComputeHash(const std::string& filePath);
};

// ============ BehaviorMonitor ============
class BehaviorMonitor : public IMonitor {
public:
    BehaviorMonitor(FireAntivirus::DataManager* dataManager, FireAntivirus::Engine::AntivirusEngine* antivirusEngine);
    void Start() override;
    void Stop() override;

private:
    FireAntivirus::DataManager* _dataManager;
    FireAntivirus::Engine::AntivirusEngine* _antivirusEngine;
    std::atomic<bool> _isRunning{false};
    std::thread _monitorThread;
    void MonitorLoop();
    void CollectBehaviorData();
};

}} // namespace FireAntivirus::Services
