// FireAntivirus.CPP - NamedPipe 实现
#include "FireAntivirus/IPC.h"
#include "FireAntivirus/LogHelper.h"

#if defined(_WIN32)
#include <windows.h>
#endif

namespace FireAntivirus {
namespace IPC {

// ==================== NamedPipeServer ====================

bool NamedPipeServer::Start() {
    if (running_.load()) return true;
    running_.store(true);
    accept_thread_ = std::thread([this]{ AcceptLoop(); });
    return true;
}

void NamedPipeServer::Stop() {
    running_.store(false);
    if (accept_thread_.joinable()) accept_thread_.join();
}

void NamedPipeServer::AcceptLoop() {
#if defined(_WIN32)
    while (running_.load()) {
        HANDLE pipe = CreateNamedPipeW(
            kPipeName,
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES, 65536, 65536, 0, nullptr);

        if (pipe == INVALID_HANDLE_VALUE) {
            FireAntivirus::LogHelper::Error("NamedPipe", "CreateNamedPipe failed, retrying...");
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }

        if (ConnectNamedPipe(pipe, nullptr) == TRUE || GetLastError() == ERROR_PIPE_CONNECTED) {
            HandleClient(pipe);
        }
        CloseHandle(pipe);
    }
#endif
}

void NamedPipeServer::HandleClient(HANDLE pipe) {
#if defined(_WIN32)
    char buf[32768]{};
    DWORD read = 0;
    if (ReadFile(pipe, buf, sizeof(buf) - 1, &read, nullptr) && read > 0) {
        std::string request(buf, read);
        std::string response;
        if (handler_) {
            try { response = handler_(request); }
            catch (std::exception& e) { response = std::string("{\"error\":\"") + e.what() + "\"}"; }
        } else {
            response = "{\"error\":\"No handler registered\"}";
        }
        DWORD written = 0;
        WriteFile(pipe, response.c_str(), (DWORD)response.size(), &written, nullptr);
    }
    FlushFileBuffers(pipe);
    DisconnectNamedPipe(pipe);
#endif
}

// ==================== NamedPipeClient ====================

bool NamedPipeClient::Connect() {
#if defined(_WIN32)
    if (connected_.load()) return true;
    while (!connected_.load()) {
        HANDLE h = CreateFileW(kPipeName, GENERIC_READ | GENERIC_WRITE,
            0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            pipe_ = h;
            connected_.store(true);
            return true;
        }
        // 服务端还没起来,再等一下
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
#endif
    return false;
}

void NamedPipeClient::Disconnect() {
#if defined(_WIN32)
    if (pipe_ && pipe_ != INVALID_HANDLE_VALUE) { CloseHandle(pipe_); pipe_ = nullptr; }
#endif
    connected_.store(false);
}

std::string NamedPipeClient::SendRequest(const std::string& request_json) {
#if defined(_WIN32)
    if (!connected_.load()) return {};
    DWORD written = 0;
    WriteFile(pipe_, request_json.c_str(), (DWORD)request_json.size(), &written, nullptr);
    char buf[32768]{};
    DWORD read = 0;
    if (ReadFile(pipe_, buf, sizeof(buf) - 1, &read, nullptr)) {
        return std::string(buf, read);
    }
#endif
    return {};
}

} // namespace IPC
} // namespace FireAntivirus
