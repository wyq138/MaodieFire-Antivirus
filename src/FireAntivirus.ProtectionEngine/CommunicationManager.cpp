#include "pch.h"
#include "CommunicationManager.h"

CommunicationManager::CommunicationManager() : isInitialized(false), isRunning(false), hPipe(INVALID_HANDLE_VALUE) {
}

CommunicationManager::~CommunicationManager() {
    Cleanup();
}

bool CommunicationManager::Initialize() {
    Log(L"Initializing communication manager...");
    
    // Start server thread
    isRunning = true;
    serverThread = std::thread(&CommunicationManager::ServerThread, this);
    
    isInitialized = true;
    Log(L"Communication manager initialized successfully.");
    return true;
}

void CommunicationManager::Update() {
    // Process message queue
    while (!messageQueue.empty()) {
        Message message = messageQueue.front();
        messageQueue.pop();
        
        // Process the message
        // Note: This would be implemented based on the message type
        Log(L"Processing message...");
    }
}

void CommunicationManager::Cleanup() {
    Log(L"Cleaning up communication manager...");
    
    // Stop running
    isRunning = false;
    
    // Wait for server thread to finish
    if (serverThread.joinable()) {
        serverThread.join();
    }
    
    // Close pipe
    if (hPipe != INVALID_HANDLE_VALUE) {
        CloseHandle(hPipe);
        hPipe = INVALID_HANDLE_VALUE;
    }
    
    // Clear message queue
    std::lock_guard<std::mutex> lock(queueMutex);
    while (!messageQueue.empty()) {
        messageQueue.pop();
    }
    
    isInitialized = false;
    Log(L"Communication manager cleaned up successfully.");
}

bool CommunicationManager::IsInitialized() const {
    return isInitialized;
}

void CommunicationManager::SendMessage(const Message& message) {
    std::lock_guard<std::mutex> lock(queueMutex);
    messageQueue.push(message);
    queueCondition.notify_one();
}

void CommunicationManager::SendThreatAlert(const ThreatInfo& threatInfo) {
    Message message;
    message.type = 1; // 威胁告警消息类型
    message.threatInfo = threatInfo;
    message.action = ThreatAction::BLOCK; // 默认操作为阻止
    
    // 发送消息到客户端
    if (hPipe != INVALID_HANDLE_VALUE) {
        SendMessageToClient(hPipe, message);
    } else {
        // 如果管道未连接，将消息加入队列
        std::lock_guard<std::mutex> lock(queueMutex);
        messageQueue.push(message);
        queueCondition.notify_one();
    }
}

Message CommunicationManager::ReceiveMessage() {
    std::unique_lock<std::mutex> lock(queueMutex);
    queueCondition.wait(lock, [this] { return !messageQueue.empty(); });
    
    Message message = messageQueue.front();
    messageQueue.pop();
    return message;
}

void CommunicationManager::ServerThread() {
    Log(L"Communication server thread started.");
    
    while (isRunning) {
        try {
            // Create named pipe
            hPipe = CreateNamedPipe(
                PIPE_NAME,
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                MAX_MESSAGE_SIZE,
                MAX_MESSAGE_SIZE,
                0,
                NULL
            );
            
            if (hPipe == INVALID_HANDLE_VALUE) {
                LogError(L"Failed to create named pipe.");
                std::this_thread::sleep_for(std::chrono::milliseconds(1000));
                continue;
            }
            
            // Wait for client connection
            Log(L"Waiting for client connection...");
            bool connected = ConnectNamedPipe(hPipe, NULL) ? true : (GetLastError() == ERROR_PIPE_CONNECTED);
            
            if (connected) {
                Log(L"Client connected.");
                HandleClientConnection(hPipe);
            }
            
            // Close pipe
            CloseHandle(hPipe);
            hPipe = INVALID_HANDLE_VALUE;
        }
        catch (const std::exception& e) {
            std::string errorMsg = e.what();
            std::wstring wideErrorMsg(errorMsg.begin(), errorMsg.end());
            LogError(L"Communication server thread exception: " + wideErrorMsg);
        }
    }
    
    Log(L"Communication server thread stopped.");
}

void CommunicationManager::HandleClientConnection(HANDLE hClient) {
    while (isRunning) {
        try {
            // Receive message from client
            Message message;
            if (!ReceiveMessageFromClient(hClient, message)) {
                break;
            }
            
            // Process message
            Log(L"Received message from client.");
            
            // Handle different message types
            if (message.type == 3) { // Threat response message
                // Process threat response
                Log(L"Received threat response message.");
            } else if (message.type == 4) { // Protection control message
                // Process protection control message
                Log(L"Received protection control message.");
                
                // Get protection manager instance
                auto protectionManager = ProtectionManager::GetInstance();
                if (protectionManager) {
                    // Enable or disable protection based on the message
                    bool enable = (message.action == ThreatAction::ALLOW);
                    
                    // Get threat type
                    ThreatType threatType = message.threatInfo.type;
                    
                    // Enable or disable the corresponding protection module
                    switch (threatType) {
                        case ThreatType::FILE_MALICIOUS:
                            protectionManager->SetProtectionEnabled("FileProtection", enable);
                            break;
                        case ThreatType::PROCESS_MALICIOUS:
                            protectionManager->SetProtectionEnabled("ProcessProtection", enable);
                            break;
                        case ThreatType::REGISTRY_MALICIOUS:
                            protectionManager->SetProtectionEnabled("RegistryProtection", enable);
                            break;
                        case ThreatType::SCRIPT_MALICIOUS:
                            protectionManager->SetProtectionEnabled("ScriptProtection", enable);
                            break;
                        case ThreatType::DEVICE_MALICIOUS:
                            protectionManager->SetProtectionEnabled("DeviceProtection", enable);
                            break;
                        case ThreatType::BEHAVIOR_MALICIOUS:
                            protectionManager->SetProtectionEnabled("ActiveDefense", enable);
                            break;
                        case ThreatType::DOCUMENT_MALICIOUS:
                            protectionManager->SetProtectionEnabled("DocumentProtection", enable);
                            break;
                        case ThreatType::DISK_MALICIOUS:
                            protectionManager->SetProtectionEnabled("DiskProtection", enable);
                            break;
                        default:
                            break;
                    }
                } else if (message.type == 5) { // Language change message
                    // Process language change message
                    Log(L"Received language change message.");
                    
                    // Get language manager instance
                    auto languageManager = LanguageManager::GetInstance();
                    if (languageManager) {
                        // Get language code from message
                        std::string language = message.threatInfo.name;
                        languageManager->SetCurrentLanguage(language);
                        Log(L"Language changed to: " + std::wstring(language.begin(), language.end()));
                    }
                }
            }
            
            // Send response
            Message response;
            response.type = 2; // Response type
            if (!SendMessageToClient(hClient, response)) {
                break;
            }
        } catch (const std::exception& e) {
            std::string errorMsg = e.what();
            std::wstring wideErrorMsg(errorMsg.begin(), errorMsg.end());
            LogError(L"Handle client connection exception: " + wideErrorMsg);
            break;
        }
    }
    
    Log(L"Client disconnected.");
}

bool CommunicationManager::SendMessageToClient(HANDLE hClient, const Message& message) {
    DWORD bytesWritten;
    return WriteFile(hClient, &message, sizeof(Message), &bytesWritten, NULL) && (bytesWritten == sizeof(Message));
}

bool CommunicationManager::ReceiveMessageFromClient(HANDLE hClient, Message& message) {
    DWORD bytesRead;
    return ReadFile(hClient, &message, sizeof(Message), &bytesRead, NULL) && (bytesRead == sizeof(Message));
}
