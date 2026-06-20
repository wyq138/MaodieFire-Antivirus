// InterprocessCommunication.cpp

#include "pch.h"
#include "InterprocessCommunication.h"

InterprocessCommunication::InterprocessCommunication() : 
    isInitialized(false),
    isRunning(false),
    hPipe(nullptr),
    isListening(false) {
}

InterprocessCommunication::~InterprocessCommunication() {
    Cleanup();
}

// 初始化
bool InterprocessCommunication::Initialize() {
    if (isInitialized) {
        return true;
    }
    
    isInitialized = true;
    return true;
}

// 清理
void InterprocessCommunication::Cleanup() {
    if (!isInitialized) {
        return;
    }
    
    // 停止通信
    Stop();
    
    isInitialized = false;
}

// 启动
bool InterprocessCommunication::Start() {
    if (!isInitialized || isRunning) {
        return false;
    }
    
    // 启动监听线程
    isListening = true;
    listenThread = std::thread(&InterprocessCommunication::ListenThread, this);
    
    isRunning = true;
    return true;
}

// 停止
void InterprocessCommunication::Stop() {
    if (!isRunning) {
        return;
    }
    
    // 停止监听线程
    isListening = false;
    if (listenThread.joinable()) {
        listenThread.join();
    }
    
    // 关闭管道
    if (hPipe) {
        CloseHandle(hPipe);
        hPipe = nullptr;
    }
    
    isRunning = false;
}

// 检查是否初始化
bool InterprocessCommunication::IsInitialized() const {
    return isInitialized;
}

// 检查是否运行
bool InterprocessCommunication::IsRunning() const {
    return isRunning;
}

// 设置消息回调函数
void InterprocessCommunication::SetMessageCallback(std::function<void(const std::wstring&)> callback) {
    messageCallback = callback;
}

// 发送消息
bool InterprocessCommunication::SendMessage(const std::wstring& message) {
    try {
        // 连接到管道
        HANDLE hClient = CreateFile(
            PIPE_NAME,
            GENERIC_READ | GENERIC_WRITE,
            0,
            nullptr,
            OPEN_EXISTING,
            0,
            nullptr
        );
        
        if (hClient == INVALID_HANDLE_VALUE) {
            std::cerr << "Error connecting to pipe: " << GetLastError() << std::endl;
            return false;
        }
        
        // 发送消息
        bool result = SendMessage(hClient, message);
        
        // 关闭管道
        CloseHandle(hClient);
        
        return result;
    } catch (const std::exception& e) {
        std::cerr << "Error sending message: " << e.what() << std::endl;
        return false;
    }
}

// 监听线程函数
void InterprocessCommunication::ListenThread() {
    while (isListening) {
        try {
            // 创建命名管道
            hPipe = CreateNamedPipe(
                PIPE_NAME,
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                1024,
                1024,
                0,
                nullptr
            );
            
            if (hPipe == INVALID_HANDLE_VALUE) {
                std::cerr << "Error creating named pipe: " << GetLastError() << std::endl;
                std::this_thread::sleep_for(std::chrono::seconds(1));
                continue;
            }
            
            // 等待客户端连接
            bool connected = ConnectNamedPipe(hPipe, nullptr) ? true : (GetLastError() == ERROR_PIPE_CONNECTED);
            
            if (connected) {
                // 处理客户端连接
                HandleClient(hPipe);
            }
            
            // 关闭管道
            CloseHandle(hPipe);
            hPipe = nullptr;
        } catch (const std::exception& e) {
            std::cerr << "Error in listen thread: " << e.what() << std::endl;
            
            // 关闭管道
            if (hPipe) {
                CloseHandle(hPipe);
                hPipe = nullptr;
            }
            
            // 休眠一段时间
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
}

// 处理客户端连接
void InterprocessCommunication::HandleClient(HANDLE hClient) {
    try {
        // 读取消息
        std::wstring message = ReadMessage(hClient);
        if (!message.empty()) {
            std::cout << "Received message: " << message << std::endl;
            
            // 调用回调函数
            if (messageCallback) {
                messageCallback(message);
            }
            
            // 发送响应
            SendMessage(hClient, L"Message received: " + message);
        }
    } catch (const std::exception& e) {
        std::cerr << "Error handling client: " << e.what() << std::endl;
    }
}

// 读取消息
std::wstring InterprocessCommunication::ReadMessage(HANDLE hClient) {
    std::wstring message;
    DWORD bytesRead;
    WCHAR buffer[1024];
    
    while (true) {
        if (!ReadFile(hClient, buffer, sizeof(buffer), &bytesRead, nullptr)) {
            if (GetLastError() == ERROR_BROKEN_PIPE) {
                break;
            }
            std::cerr << "Error reading from pipe: " << GetLastError() << std::endl;
            break;
        }
        
        if (bytesRead == 0) {
            break;
        }
        
        message.append(buffer, bytesRead / sizeof(WCHAR));
        
        // 检查是否是完整消息
        if (message.back() == L'\0') {
            message.pop_back(); // 移除 null 终止符
            break;
        }
    }
    
    return message;
}

// 发送消息
bool InterprocessCommunication::SendMessage(HANDLE hClient, const std::wstring& message) {
    DWORD bytesWritten;
    std::wstring messageWithNull = message + L'\0';
    
    if (!WriteFile(hClient, messageWithNull.c_str(), messageWithNull.size() * sizeof(WCHAR), &bytesWritten, nullptr)) {
        std::cerr << "Error writing to pipe: " << GetLastError() << std::endl;
        return false;
    }
    
    return true;
}