// FireAntivirus.CPP - Windows 服务宿主
// 移植自 FireAntivirus.ServiceHost (ServiceMonitor + ServiceManager + ServiceInstaller)
#pragma once

#include <string>
#include <cstdint>
#include <atomic>
#include <thread>
#include <functional>

#if defined(_WIN32)
    #include <windows.h>
    #include <winsvc.h>
#endif

namespace FireAntivirus {
namespace Service {

// ==================== Win32 服务类 ====================

/// <summary>真正的 Windows 服务,通过 sc.exe install FireAntivirusService 注册</summary>
class FireAntivirusService {
public:
    static FireAntivirusService& Instance();

    // 由 ServiceMain 调用
    void ServiceMain(int argc, char** argv);

    // 命令处理 (Handler)
    static void Handler(DWORD control, DWORD event_type, LPVOID event_data, LPVOID context);

    // 对外查询
    bool IsRunning()  const { return running_.load(); }
    bool IsPaused()   const { return paused_.load(); }

    // 内部
    void StartInternal();
    void StopInternal();
    void PauseInternal();
    void ContinueInternal();

private:
    FireAntivirusService() = default;
    std::atomic<bool> running_{false};
    std::atomic<bool> paused_{false};
    std::thread worker_;
#if defined(_WIN32)
    SERVICE_STATUS_HANDLE status_handle_ = nullptr;
    SERVICE_STATUS        status_{};
#endif
};

// ==================== ServiceInstaller ====================

class ServiceInstaller {
public:
    static bool Install(const std::string& service_name,
                        const std::string& display_name,
                        const std::string& exe_path);
    static bool Uninstall(const std::string& service_name);
    static bool Start(const std::string& service_name);
    static bool Stop(const std::string& service_name);
    static bool IsInstalled(const std::string& service_name);
};

// ==================== ServiceManager (UI 层控制) ====================

class ServiceManager {
public:
    struct ServiceInfo {
        std::string name;
        std::string display_name;
        std::string status;   // "Stopped"/"Running"/"Paused"
        std::string start_type;
    };
    static ServiceInfo GetInfo(const std::string& service_name);
    static bool Start(const std::string& service_name);
    static bool Stop(const std::string& service_name);
    static bool Pause(const std::string& service_name);
    static bool Resume(const std::string& service_name);
};

// ==================== ServiceMonitor (守护主进程) ====================

class ServiceMonitor {
public:
    /// <summary>守护 Watchdog: 主进程崩溃自动重启</summary>
    void Start();
    void Stop();
    bool IsRunning();

    void SetTargetProcess(const std::string& name);
    void SetInterval(int seconds) { interval_seconds_ = seconds; }

private:
    std::atomic<bool> running_{false};
    std::thread t_;
    std::string target_;
    int interval_seconds_ = 5;
};

} // namespace Service
} // namespace FireAntivirus
