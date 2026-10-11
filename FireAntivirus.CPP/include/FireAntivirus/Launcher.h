// FireAntivirus.CPP - Host 启动器 (Launcher + Watchdog)
// 移植自 FireAntivirus.Launcher.Program + FireAntivirus.Host.Program + ServiceMonitor
#pragma once

#include <string>
#include <thread>
#include <atomic>
#include <chrono>
#include <cstdint>

#if defined(_WIN32)
    #include <windows.h>
#endif

namespace FireAntivirus {
namespace Host {

// ==================== Launcher ====================

/// <summary>启动器: 负责启动 WinUI3 UI 或后台服务, 并做依赖检查</summary>
class Launcher {
public:
    enum Mode {
        StartUI,           // 启动 WinUI3 界面进程
        StartService,       // 启动后台服务 (sc start)
        InstallService,     // 安装服务
        UninstallService,
        RunAsCLI,           // 命令行模式
        SelfTest            // 自检所有模块
    };

    static int Run(int argc, char** argv);

private:
    static void PrintBanner();
    static int  RunSelfTest();
    static int  RunCLI(int argc, char** argv);
    static bool CheckDependencies();
};

// ==================== Watchdog ====================

/// <summary>Watchdog: 后台守护, 监控 UI + Service 进程, 崩溃自动拉起</summary>
class Watchdog {
public:
    void Start();
    void Stop();
    bool IsRunning();

    void WatchProcess(const std::string& exe_name);   // 守护的进程名(如 FireAntivirusUI.exe)
    void SetPollIntervalMs(int ms) { interval_ms_ = ms; }

private:
    std::atomic<bool> running_{false};
    std::thread t_;
    std::vector<std::string> watchlist_;
    int interval_ms_ = 5000;

    void Loop();
};

} // namespace Host
} // namespace FireAntivirus
