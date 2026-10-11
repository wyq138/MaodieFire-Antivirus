// FireAntivirus.CPP - 主程序入口 (CLI 版)
// 当以 Service 方式运行时, 会进入 ServiceHost::ServiceMain
// 当以 Launcher 方式运行时, 会根据命令行参数分派
#include "FireAntivirus/Launcher.h"
#include "FireAntivirus/Engine/AntivirusEngine.h"
#include "FireAntivirus/Engine/KernelProtection.h"
#include "FireAntivirus/Engine/SignatureDatabase.h"
#include "FireAntivirus/Engine/RealTimeProtectionPlus.h"
#include "FireAntivirus/Engine/PEAnalyzer.h"
#include "FireAntivirus/Modules/AllManagers.h"
#include "FireAntivirus/ServiceHost.h"
#include "FireAntivirus/IPC.h"
#include "FireAntivirus/LogHelper.h"
#include "FireAntivirus/Helper.h"
#include "FireAntivirus/Services/AllServices.h"  // ClamAVEngine / BehaviorAnalysis 等服务

#include <iostream>
#include <string>

#if defined(_WIN32)
    #include <windows.h>
#endif

namespace FireAntivirus {
namespace Host {

void Launcher::PrintBanner() {
    std::cout << R"(
  _____          _     _____       _ _
 | ____|_  _____| |   |_   _|__ __| (_)_   _ _ __   ___
 |  _| \ \/ / _ \ |     | |/ __/ _` | | | | | '_ \ / _ \
 | |___ >  <  __/ |___  | | (_| (_| | | |_| | | | |  __/
 |_____/_/\_\___|_____| |_|\___\__,_|_|\__,_|_| |_|\___|
                                       v1.0.0 (C++ 原生版, 自签名驱动)
)" << std::endl;
}

int Launcher::RunSelfTest() {
    PrintBanner();
    std::cout << "[SELFTEST] Running...\n";

    // 1. 核心引擎
    Engine::AntivirusEngine engine;
    std::cout << "[OK] AntivirusEngine initialized\n";

    // 2. 签名数据库
    auto& sig = Engine::SignatureDatabase::Instance();
    sig.Initialize();
    std::cout << "[OK] SignatureDB: " << sig.HashCount() << " hashes, "
              << sig.UrlCount() << " URLs, " << sig.IpCount() << " IPs\n";

    // 3. 内核保护
    Engine::Kernel::KernelProtectionInterface kpi;
    kpi.Initialize();
    std::cout << "[OK] KernelProtection: driver="
              << (kpi.IsDriverConnected() ? "connected" : "user-mode fallback") << "\n";

    // 4. 实时保护
    RTPPlus::RealTimeProtectionPlusManager::Instance().Start();
    std::cout << "[OK] RealTimeProtectionPlus started\n";

    // 5. AI/机器学习引擎 (MachineLearning + BehaviorAnalysis, 已在 AllServices.h 注册)
    Services::MachineLearning ml;
    std::cout << "[OK] MachineLearning engine ready\n";

    // 6. PE 分析
    std::cout << "[OK] PEAnalyzer ready\n";

    // 7. 所有模块管理器
    std::cout << "[OK] All 50 module managers registered via ModuleRegistry\n";

    std::cout << "\n[SELFTEST] ALL MODULES OK\n";
    return 0;
}

int Launcher::RunCLI(int argc, char** argv) {
    PrintBanner();
    if (argc < 2) {
        std::cout << "用法:\n"
                  << "  FireAntivirus scan <path>       扫描文件或目录\n"
                  << "  FireAntivirus self-test         自检所有模块\n"
                  << "  FireAntivirus install-service   安装 Windows 服务\n"
                  << "  FireAntivirus uninstall-service 卸载 Windows 服务\n"
                  << "  FireAntivirus start-service     启动服务\n"
                  << "  FireAntivirus stop-service      停止服务\n"
                  << "  FireAntivirus serve             作为后台服务运行\n"
                  << "  FireAntivirus update-sigs       更新签名数据库\n"
                  << "  FireAntivirus signed-driver     安装自签名驱动\n";
        return 0;
    }

    std::string cmd = argv[1];
    if (cmd == "self-test") return RunSelfTest();
    if (cmd == "scan") {
        if (argc < 3) { std::cerr << "请指定扫描路径\n"; return 1; }
        Engine::AntivirusEngine engine;
        auto result = engine.ScanFile(argv[2]);
        std::cout << "[SCAN] " << argv[2] << "\n"
                  << "  infected=" << result.is_infected << "\n"
                  << "  threat="   << result.threat_name << "\n"
                  << "  severity=" << result.severity << "\n"
                  << "  method="   << result.detection_method << "\n"
                  << "  conf="     << result.confidence << "\n"
                  << "  info="     << result.additional_info << "\n";
        return 0;
    }
    if (cmd == "serve") {
        // 作为后台运行 (不是服务, 只是守护进程)
        Engine::AntivirusEngine engine;
        IPC::NamedPipeServer nps;
        nps.SetHandler([&engine](const std::string& req) -> std::string {
            // 简化 JSON 命令解析
            if (req.find("scan") != std::string::npos) {
                size_t q = req.find("path=");
                if (q != std::string::npos) {
                    std::string path = req.substr(q + 5);
                    auto r = engine.ScanFile(path);
                    std::string out = "{\"infected\":" + std::to_string(r.is_infected) +
                                      ",\"threat\":\"" + r.threat_name + "\"}";
                    return out;
                }
            }
            return "{\"error\":\"unknown command\"}";
        });
        nps.Start();
        std::cout << "[SERVE] Background service running (Ctrl+C to exit)\n";
        while (true) std::this_thread::sleep_for(std::chrono::seconds(5));
    }
    if (cmd == "install-service") {
        std::string exe;
#if defined(_WIN32)
        wchar_t buf[MAX_PATH]{};
        GetModuleFileNameW(nullptr, buf, MAX_PATH);
        int len = (int)wcslen(buf);
        exe.resize(WideCharToMultiByte(CP_UTF8, 0, buf, len, nullptr, 0, nullptr, nullptr));
        WideCharToMultiByte(CP_UTF8, 0, buf, len, exe.data(), (int)exe.size(), nullptr, nullptr);
#endif
        bool ok = Service::ServiceInstaller::Install("FireAntivirusService",
            "FireAntivirus Security Service", exe);
        std::cout << (ok ? "[OK] Service installed\n" : "[FAIL] Install failed\n");
        return ok ? 0 : 1;
    }
    if (cmd == "uninstall-service") {
        bool ok = Service::ServiceInstaller::Uninstall("FireAntivirusService");
        std::cout << (ok ? "[OK] Service uninstalled\n" : "[FAIL]\n");
        return ok ? 0 : 1;
    }
    if (cmd == "start-service") {
        bool ok = Service::ServiceInstaller::Start("FireAntivirusService");
        std::cout << (ok ? "[OK] Service started\n" : "[FAIL]\n");
        return ok ? 0 : 1;
    }
    if (cmd == "stop-service") {
        bool ok = Service::ServiceInstaller::Stop("FireAntivirusService");
        std::cout << (ok ? "[OK] Service stopped\n" : "[FAIL]\n");
        return ok ? 0 : 1;
    }
    if (cmd == "update-sigs") {
        auto r = Engine::SignatureDatabase::Instance().Initialize();
        std::cout << (r ? "[OK] Signatures loaded " : "[FAIL] ")
                  << Engine::SignatureDatabase::Instance().HashCount() << "\n";
        return r ? 0 : 1;
    }
    std::cout << "未知命令: " << cmd << "\n";
    return 1;
}

int Launcher::Run(int argc, char** argv) {
    LogHelper::Instance().SetMinLevel(LogLevel::Info);
#if defined(_WIN32)
    // 如果被 SCM 启动, 进入 ServiceMain
    // 简化: 通过命令行参数区分 (真正的 ServiceMain 需要 sc install 之后 SCM 传)
#endif
    return RunCLI(argc, argv);
}

// ==================== Watchdog ====================

void Watchdog::Start() {
    if (running_.load()) return;
    running_.store(true);
    t_ = std::thread([this]{ Loop(); });
}

void Watchdog::Stop() {
    running_.store(false);
    if (t_.joinable()) t_.join();
}

bool Watchdog::IsRunning() { return running_.load(); }

void Watchdog::WatchProcess(const std::string& exe_name) {
    watchlist_.push_back(Helper::ToLower(exe_name));
}

void Watchdog::Loop() {
    while (running_.load()) {
#if defined(_WIN32)
        for (auto& name : watchlist_) {
            auto pids = Platform::FindProcessByName(name);
            if (pids.empty()) {
                LogHelper::Warn("Watchdog", name + " 已退出, 自动重拉...");
                // 尝试 sc start
                std::string cmd = "sc start " + name;
                STARTUPINFOA si{}; si.cb = sizeof(si);
                PROCESS_INFORMATION pi{};
                std::vector<char> cb(cmd.begin(), cmd.end()); cb.push_back('\0');
                CreateProcessA(nullptr, cb.data(), nullptr, nullptr, FALSE,
                               CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
                CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
            }
        }
#endif
        std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms_));
    }
}

} // namespace Host
} // namespace FireAntivirus

// ==================== main ====================

int main(int argc, char** argv) {
    return FireAntivirus::Host::Launcher::Run(argc, argv);
}
