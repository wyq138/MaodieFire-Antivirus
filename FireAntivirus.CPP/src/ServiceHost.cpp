// FireAntivirus.CPP - ServiceHost 实现
#include "FireAntivirus/ServiceHost.h"
#include "FireAntivirus/LogHelper.h"
#include "FireAntivirus/Engine/AntivirusEngine.h"
#include "FireAntivirus/Engine/KernelProtection.h"
#include "FireAntivirus/NativeIntegration.h"
#include "FireAntivirus/Platform/Windows.h"

#if defined(_WIN32)
#include <windows.h>
#include <winsvc.h>
#include <tlhelp32.h>
#endif

#include <chrono>

namespace FireAntivirus {
namespace Service {

// ==================== FireAntivirusService ====================

FireAntivirusService& FireAntivirusService::Instance() {
    static FireAntivirusService inst;
    return inst;
}

#if defined(_WIN32)
// 前向声明: 全局实例
static FireAntivirusService* g_svc = nullptr;

void WINAPI ServiceMain(DWORD argc, LPTSTR* argv) {
    UNREFERENCED_PARAMETER(argc); UNREFERENCED_PARAMETER(argv);
    FireAntivirusService::Instance().ServiceMain((int)argc, (char**)argv);
}

void WINAPI FireAntivirusService::Handler(DWORD control, DWORD event_type, LPVOID event_data, LPVOID context) {
    UNREFERENCED_PARAMETER(event_type); UNREFERENCED_PARAMETER(event_data); UNREFERENCED_PARAMETER(context);
    auto& svc = FireAntivirusService::Instance();
    switch (control) {
        case SERVICE_CONTROL_STOP:
            svc.StopInternal(); break;
        case SERVICE_CONTROL_PAUSE:
            svc.PauseInternal(); break;
        case SERVICE_CONTROL_CONTINUE:
            svc.ContinueInternal(); break;
        case SERVICE_CONTROL_INTERROGATE: break;
        default: break;
    }
    // 报告状态
    if (svc.status_handle_) {
        SERVICE_STATUS st{};
        st.dwServiceType             = SERVICE_WIN32_OWN_PROCESS;
        st.dwCurrentState           = svc.IsPaused() ? SERVICE_PAUSED : (svc.IsRunning() ? SERVICE_RUNNING : SERVICE_STOPPED);
        st.dwControlsAccepted       = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE;
        st.dwWaitHint               = 0;
        SetServiceStatus(svc.status_handle_, &st);
    }
}

#define SVC_NAME L"FireAntivirusService"
#endif

void FireAntivirusService::ServiceMain(int, char**) {
    FireAntivirus::LogHelper::Info("Service", "FireAntivirusService started");

#if defined(_WIN32)
    // 注册到 SCM
    status_handle_ = RegisterServiceCtrlHandlerW(SVC_NAME, &FireAntivirusService::Handler);
    if (!status_handle_) {
        FireAntivirus::LogHelper::Error("Service", "RegisterServiceCtrlHandlerW failed");
        return;
    }
    // 初始状态
    SERVICE_STATUS st{};
    st.dwServiceType       = SERVICE_WIN32_OWN_PROCESS;
    st.dwCurrentState      = SERVICE_START_PENDING;
    st.dwControlsAccepted  = 0;
    st.dwWaitHint          = 3000;
    SetServiceStatus(status_handle_, &st);
#endif

    // 启动内部
    StartInternal();

#if defined(_WIN32)
    SERVICE_STATUS running{};
    running.dwServiceType      = SERVICE_WIN32_OWN_PROCESS;
    running.dwCurrentState     = SERVICE_RUNNING;
    running.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE;
    SetServiceStatus(status_handle_, &running);
#endif

    // 主循环
    while (running_.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }

#if defined(_WIN32)
    SERVICE_STATUS stopped{};
    stopped.dwServiceType  = SERVICE_WIN32_OWN_PROCESS;
    stopped.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(status_handle_, &stopped);
#endif
}

void FireAntivirusService::StartInternal() {
    running_.store(true);
    Native::NativeSecurityCoreWrapper::Initialize();
    FireAntivirus::LogHelper::Info("Service", "Engine initialized");
}

void FireAntivirusService::StopInternal() {
    running_.store(false);
    Native::NativeSecurityCoreWrapper::Shutdown();
    FireAntivirus::LogHelper::Info("Service", "Service stopped");
}
void FireAntivirusService::PauseInternal()  { paused_.store(true); }
void FireAntivirusService::ContinueInternal(){ paused_.store(false); }

// ==================== ServiceInstaller ====================

bool ServiceInstaller::Install(const std::string& service_name,
                               const std::string& display_name,
                               const std::string& exe_path) {
#if defined(_WIN32)
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scm) return false;

    std::wstring wpath(exe_path.begin(), exe_path.end());
    std::wstring wname(service_name.begin(), service_name.end());
    std::wstring wdisp(display_name.begin(), display_name.end());

    SC_HANDLE svc = CreateServiceW(scm, wname.c_str(), wdisp.c_str(),
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS,
        SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, wpath.c_str(),
        nullptr, nullptr, nullptr, nullptr, nullptr);
    CloseServiceHandle(scm);
    if (!svc) return false;
    CloseServiceHandle(svc);
    FireAntivirus::LogHelper::Info("ServiceInstaller", "Service installed: " + service_name);
    return true;
#else return false;
#endif
}

bool ServiceInstaller::Uninstall(const std::string& service_name) {
#if defined(_WIN32)
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;
    std::wstring wname(service_name.begin(), service_name.end());
    SC_HANDLE svc = OpenServiceW(scm, wname.c_str(), SERVICE_STOP | DELETE);
    if (!svc) { CloseServiceHandle(scm); return false; }
    ControlService(svc, SERVICE_CONTROL_STOP, nullptr);
    bool ok = (DeleteService(svc) == TRUE);
    CloseServiceHandle(svc); CloseServiceHandle(scm);
    return ok;
#else return false;
#endif
}

bool ServiceInstaller::Start(const std::string& service_name) {
#if defined(_WIN32)
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;
    std::wstring wname(service_name.begin(), service_name.end());
    SC_HANDLE svc = OpenServiceW(scm, wname.c_str(), SERVICE_START);
    if (!svc) { CloseServiceHandle(scm); return false; }
    bool ok = (StartServiceW(svc, 0, nullptr) == TRUE);
    CloseServiceHandle(svc); CloseServiceHandle(scm);
    return ok;
#else return false;
#endif
}

bool ServiceInstaller::Stop(const std::string& service_name) {
#if defined(_WIN32)
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;
    std::wstring wname(service_name.begin(), service_name.end());
    SC_HANDLE svc = OpenServiceW(scm, wname.c_str(), SERVICE_STOP);
    if (!svc) { CloseServiceHandle(scm); return false; }
    SERVICE_STATUS st{};
    bool ok = (ControlService(svc, SERVICE_CONTROL_STOP, &st) == TRUE);
    CloseServiceHandle(svc); CloseServiceHandle(scm);
    return ok;
#else return false;
#endif
}

bool ServiceInstaller::IsInstalled(const std::string& service_name) {
#if defined(_WIN32)
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) return false;
    std::wstring wname(service_name.begin(), service_name.end());
    SC_HANDLE svc = OpenServiceW(scm, wname.c_str(), SERVICE_QUERY_STATUS);
    bool ok = (svc != nullptr);
    if (svc) CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ok;
#else return false;
#endif
}

// ==================== ServiceManager ====================

ServiceManager::ServiceInfo ServiceManager::GetInfo(const std::string& service_name) {
    ServiceInfo info; info.name = service_name;
#if defined(_WIN32)
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return info;
    std::wstring wname(service_name.begin(), service_name.end());
    SC_HANDLE svc = OpenServiceW(scm, wname.c_str(),
                                  SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
    if (!svc) { CloseServiceHandle(scm); return info; }
    SERVICE_STATUS st{};
    if (QueryServiceStatus(svc, &st)) {
        switch (st.dwCurrentState) {
            case SERVICE_STOPPED: info.status = "Stopped"; break;
            case SERVICE_START_PENDING: info.status = "Starting"; break;
            case SERVICE_STOP_PENDING:  info.status = "Stopping"; break;
            case SERVICE_RUNNING:       info.status = "Running"; break;
            case SERVICE_PAUSED:        info.status = "Paused"; break;
            default: info.status = "Unknown"; break;
        }
    }
    CloseServiceHandle(svc); CloseServiceHandle(scm);
#endif
    return info;
}

bool ServiceManager::Start(const std::string& s) { return ServiceInstaller::Start(s); }
bool ServiceManager::Stop(const std::string& s)  { return ServiceInstaller::Stop(s); }
bool ServiceManager::Pause(const std::string& service_name) {
#if defined(_WIN32)
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;
    std::wstring wname(service_name.begin(), service_name.end());
    SC_HANDLE svc = OpenServiceW(scm, wname.c_str(), SERVICE_PAUSE_CONTINUE);
    if (!svc) { CloseServiceHandle(scm); return false; }
    SERVICE_STATUS st{};
    bool ok = (ControlService(svc, SERVICE_CONTROL_PAUSE, &st) == TRUE);
    CloseServiceHandle(svc); CloseServiceHandle(scm);
    return ok;
#else return false;
#endif
}
bool ServiceManager::Resume(const std::string& service_name) {
#if defined(_WIN32)
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;
    std::wstring wname(service_name.begin(), service_name.end());
    SC_HANDLE svc = OpenServiceW(scm, wname.c_str(), SERVICE_PAUSE_CONTINUE);
    if (!svc) { CloseServiceHandle(scm); return false; }
    SERVICE_STATUS st{};
    bool ok = (ControlService(svc, SERVICE_CONTROL_CONTINUE, &st) == TRUE);
    CloseServiceHandle(svc); CloseServiceHandle(scm);
    return ok;
#else return false;
#endif
}

// ==================== ServiceMonitor (Watchdog) ====================

void ServiceMonitor::Start() {
    if (running_.load()) return;
    running_.store(true);
    t_ = std::thread([this]{
        while (running_.load()) {
            if (!target_.empty()) {
                auto pids = FireAntivirus::Platform::FindProcessByName(target_);
                if (pids.empty()) {
                    FireAntivirus::LogHelper::Warn("ServiceMonitor", target_ + " 已退出, 正在重新启动...");
                    // 简化: 调用 ServiceManager 启动
                    ServiceManager::Start(target_);
                }
            }
            std::this_thread::sleep_for(std::chrono::seconds(interval_seconds_));
        }
    });
}

void ServiceMonitor::Stop() {
    running_.store(false);
    if (t_.joinable()) t_.join();
}
bool ServiceMonitor::IsRunning() { return running_.load(); }
void ServiceMonitor::SetTargetProcess(const std::string& name) { target_ = name; }

} // namespace Service
} // namespace FireAntivirus
