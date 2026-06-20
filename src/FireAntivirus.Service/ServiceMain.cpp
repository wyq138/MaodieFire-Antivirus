// ServiceMain.cpp

#include "pch.h"
#include "ServiceMain.h"
#include "ProcessProtection.h"
#include "InterprocessCommunication.h"

// 初始化静态成员
ServiceMain* ServiceMain::instance = nullptr;
std::mutex ServiceMain::instanceMutex;

// 私有构造函数
ServiceMain::ServiceMain() : 
    currentState(ServiceState::STOPPED),
    stopEvent(nullptr),
    isMonitoring(false),
    processProtection(nullptr),
    ipc(nullptr),
    watchdogGuardian(nullptr) {
    // 初始化服务状态
    ZeroMemory(&serviceStatus, sizeof(SERVICE_STATUS));
    serviceStatusHandle = nullptr;
    
    // 创建停止事件
    stopEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
}

// 析构函数
ServiceMain::~ServiceMain() {
    Stop();
    
    if (stopEvent) {
        CloseHandle(stopEvent);
        stopEvent = nullptr;
    }
    
    if (processProtection) {
        delete processProtection;
        processProtection = nullptr;
    }
    
    if (ipc) {
        delete ipc;
        ipc = nullptr;
    }
    
    if (watchdogGuardian) {
        delete watchdogGuardian;
        watchdogGuardian = nullptr;
    }
}

// 获取单例实例
ServiceMain* ServiceMain::GetInstance() {
    if (instance == nullptr) {
        std::lock_guard<std::mutex> lock(instanceMutex);
        if (instance == nullptr) {
            instance = new ServiceMain();
        }
    }
    return instance;
}

// 初始化服务
bool ServiceMain::Initialize() {
    try {
        // 初始化进程保护
        processProtection = new ProcessProtection();
        if (!processProtection->Initialize()) {
            return false;
        }
        
        // 初始化进程间通信
        ipc = new InterprocessCommunication();
        if (!ipc->Initialize()) {
            return false;
        }
        
        // 初始化看门狗守护
        watchdogGuardian = new WatchdogGuardian();
        
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error initializing service: " << e.what() << std::endl;
        return false;
    }
}

// 运行服务
void ServiceMain::Run(int argc, char* argv[]) {
    // 检查命令行参数
    if (argc > 1) {
        std::string arg = argv[1];
        if (arg == "-install") {
            InstallService();
        } else if (arg == "-uninstall") {
            UninstallService();
        } else if (arg == "-run" || arg == "-console") {
            RunService();
        } else {
            ShowHelp();
        }
    } else {
        // 作为服务运行
        SERVICE_TABLE_ENTRY serviceTable[] = {
            { (LPWSTR)SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)ServiceMainFunction },
            { nullptr, nullptr }
        };
        
        if (!StartServiceCtrlDispatcher(serviceTable)) {
            std::cerr << "Error starting service dispatcher: " << GetLastError() << std::endl;
        }
    }
}

// 启动服务
bool ServiceMain::Start() {
    return StartServiceInternal();
}

// 停止服务
void ServiceMain::Stop() {
    StopServiceInternal();
}

// 检查服务状态
ServiceState ServiceMain::GetState() const {
    return currentState;
}

// 发送服务状态
void ServiceMain::SetServiceStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint) {
    serviceStatus.dwCurrentState = dwCurrentState;
    serviceStatus.dwWin32ExitCode = dwWin32ExitCode;
    serviceStatus.dwWaitHint = dwWaitHint;
    
    if (dwCurrentState == SERVICE_START_PENDING) {
        serviceStatus.dwControlsAccepted = 0;
    } else {
        serviceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    }
    
    if (serviceStatusHandle) {
        ::SetServiceStatus(serviceStatusHandle, &serviceStatus);
    }
}

// 服务主函数
void WINAPI ServiceMain::ServiceMainFunction(DWORD argc, LPTSTR* argv) {
    ServiceMain* service = GetInstance();
    
    // 注册服务控制处理函数
    service->serviceStatusHandle = RegisterServiceCtrlHandlerEx(SERVICE_NAME, ServiceControlHandler, nullptr);
    if (!service->serviceStatusHandle) {
        std::cerr << "Error registering service control handler: " << GetLastError() << std::endl;
        return;
    }
    
    // 初始化服务状态
    service->serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    service->serviceStatus.dwServiceSpecificExitCode = 0;
    
    // 发送启动状态
    service->SetServiceStatus(SERVICE_START_PENDING, NO_ERROR, 3000);
    
    // 启动服务
    if (service->StartServiceInternal()) {
        // 发送运行状态
        service->SetServiceStatus(SERVICE_RUNNING, NO_ERROR, 0);
        
        // 等待停止事件
        WaitForSingleObject(service->stopEvent, INFINITE);
        
        // 发送停止状态
        service->SetServiceStatus(SERVICE_STOPPED, NO_ERROR, 0);
    } else {
        // 发送停止状态
        service->SetServiceStatus(SERVICE_STOPPED, ERROR_SERVICE_CANNOT_ACCEPT_CTRL, 0);
    }
}

// 服务控制处理函数
DWORD WINAPI ServiceMain::ServiceControlHandler(DWORD control, DWORD eventType, LPVOID eventData, LPVOID context) {
    ServiceMain* service = GetInstance();
    
    switch (control) {
    case SERVICE_CONTROL_STOP:
        service->SetServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 3000);
        service->StopServiceInternal();
        service->SetServiceStatus(SERVICE_STOPPED, NO_ERROR, 0);
        return NO_ERROR;
    
    case SERVICE_CONTROL_SHUTDOWN:
        service->SetServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 3000);
        service->StopServiceInternal();
        service->SetServiceStatus(SERVICE_STOPPED, NO_ERROR, 0);
        return NO_ERROR;
    
    default:
        return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

// 启动服务
bool ServiceMain::StartServiceInternal() {
    try {
        currentState = ServiceState::STARTING;
        
        // 初始化服务
        if (!Initialize()) {
            return false;
        }
        
        // 启动监控线程
        isMonitoring = true;
        monitoringThread = std::thread(&ServiceMain::MonitoringThread, this);
        
        // 启动进程保护
        if (processProtection) {
            processProtection->Enable(true);
        }
        
        // 启动进程间通信
        if (ipc) {
            ipc->Start();
        }
        
        // 启动看门狗守护
        if (watchdogGuardian) {
            watchdogGuardian->Start();
            std::cout << "[ServiceMain] Watchdog guardian started" << std::endl;
        }
        
        currentState = ServiceState::RUNNING;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error starting service: " << e.what() << std::endl;
        return false;
    }
}

// 停止服务
void ServiceMain::StopServiceInternal() {
    try {
        currentState = ServiceState::STOPPING;
        
        // 停止看门狗守护
        if (watchdogGuardian) {
            watchdogGuardian->Stop();
        }
        
        // 停止进程间通信
        if (ipc) {
            ipc->Stop();
        }
        
        // 停止进程保护
        if (processProtection) {
            processProtection->Enable(false);
        }
        
        // 停止监控线程
        isMonitoring = false;
        if (monitoringThread.joinable()) {
            monitoringThread.join();
        }
        
        // 触发停止事件
        if (stopEvent) {
            SetEvent(stopEvent);
        }
        
        currentState = ServiceState::STOPPED;
    } catch (const std::exception& e) {
        std::cerr << "Error stopping service: " << e.what() << std::endl;
    }
}

// 监控线程函数
void ServiceMain::MonitoringThread() {
    while (isMonitoring) {
        try {
            // 监控系统状态
            // 这里可以添加各种监控逻辑
            
            // 检查进程保护状态
            if (processProtection) {
                processProtection->Update();
            }
            
            // 检查看门狗状态
            if (watchdogGuardian && !watchdogGuardian->IsMainProcessRunning()) {
                // 主进程不在运行，看门狗会自动重启
            }
            
            // 休眠一段时间
            std::this_thread::sleep_for(std::chrono::seconds(5));
        } catch (const std::exception& e) {
            std::cerr << "Error in monitoring thread: " << e.what() << std::endl;
        }
    }
}

// 安装服务
bool ServiceMain::InstallService() {
    SC_HANDLE schSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!schSCManager) {
        std::cerr << "Error opening service manager: " << GetLastError() << std::endl;
        return false;
    }
    
    // 获取可执行文件路径
    WCHAR szPath[MAX_PATH];
    if (!GetModuleFileName(nullptr, szPath, MAX_PATH)) {
        std::cerr << "Error getting module file name: " << GetLastError() << std::endl;
        CloseServiceHandle(schSCManager);
        return false;
    }
    
    // 创建服务
    SC_HANDLE schService = CreateService(
        schSCManager,
        SERVICE_NAME,
        SERVICE_DISPLAY_NAME,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        szPath,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr
    );
    
    if (!schService) {
        std::cerr << "Error creating service: " << GetLastError() << std::endl;
        CloseServiceHandle(schSCManager);
        return false;
    }
    
    std::cout << "Service installed successfully." << std::endl;
    
    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
    return true;
}

// 卸载服务
bool ServiceMain::UninstallService() {
    SC_HANDLE schSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!schSCManager) {
        std::cerr << "Error opening service manager: " << GetLastError() << std::endl;
        return false;
    }
    
    SC_HANDLE schService = OpenService(schSCManager, SERVICE_NAME, SERVICE_STOP | DELETE);
    if (!schService) {
        std::cerr << "Error opening service: " << GetLastError() << std::endl;
        CloseServiceHandle(schSCManager);
        return false;
    }
    
    // 停止服务
    SERVICE_STATUS serviceStatus;
    if (ControlService(schService, SERVICE_CONTROL_STOP, &serviceStatus)) {
        std::cout << "Service stopped." << std::endl;
        Sleep(1000);
    }
    
    // 删除服务
    if (DeleteService(schService)) {
        std::cout << "Service uninstalled successfully." << std::endl;
    } else {
        std::cerr << "Error deleting service: " << GetLastError() << std::endl;
        CloseServiceHandle(schService);
        CloseServiceHandle(schSCManager);
        return false;
    }
    
    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
    return true;
}

// 运行服务
void ServiceMain::RunService() {
    ServiceMain* service = GetInstance();
    service->Initialize();
    service->Start();
    
    // 等待停止事件，而不是等待用户输入
    // 这样可以在后台无窗口运行
    std::cout << "Service running in background mode." << std::endl;
    std::cout << "Watchdog guardian is active, protecting main process." << std::endl;
    
    // 等待停止事件
    WaitForSingleObject(service->stopEvent, INFINITE);
    
    service->Stop();
}

// 显示帮助信息
void ServiceMain::ShowHelp() {
    std::cout << "Fire Antivirus Service" << std::endl;
    std::cout << "Usage: FireAntivirus.Service.exe [options]" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -install    Install the service" << std::endl;
    std::cout << "  -uninstall  Uninstall the service" << std::endl;
    std::cout << "  -run        Run the service in console mode" << std::endl;
    std::cout << "  -console    Run the service in background mode" << std::endl;
}
