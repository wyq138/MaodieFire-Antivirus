// FireAntivirus.CPP - NamedPipe 服务端/客户端
// 移植自 FireAntivirus.Services.NamedPipeServer.cs + FireAntivirus.Host.NamedPipeClient.cs
// UI(WinUI3) <-> 后台服务 的 IPC 通道
#pragma once

#include <string>
#include <functional>
#include <atomic>
#include <thread>

#if defined(_WIN32)
    #include <windows.h>
#endif

namespace FireAntivirus {
namespace IPC {

constexpr const wchar_t* kPipeName = L"\\\\.\\pipe\\FireAntivirusIPC";

/// <summary>服务端: 监听 UI 发来的请求</summary>
class NamedPipeServer {
public:
    using HandlerFn = std::function<std::string(const std::string& request_json)>;

    bool Start();
    void Stop();
    bool IsRunning() const { return running_.load(); }

    // 注册请求处理器 (JSON in -> JSON out)
    void SetHandler(HandlerFn fn) { handler_ = std::move(fn); }

private:
    void AcceptLoop();
    void HandleClient(HANDLE pipe);

    std::atomic<bool> running_{false};
    std::thread accept_thread_;
    HandlerFn handler_;
};

/// <summary>客户端: UI 向后台发请求</summary>
class NamedPipeClient {
public:
    bool Connect();
    void Disconnect();
    bool IsConnected() const { return connected_.load(); }
    std::string SendRequest(const std::string& request_json);

private:
    std::atomic<bool> connected_{false};
#if defined(_WIN32)
    HANDLE pipe_ = nullptr;
#endif
};

} // namespace IPC
} // namespace FireAntivirus
