#pragma once

class CommunicationManager {
private:
    std::atomic<bool> isInitialized;
    std::thread serverThread;
    std::atomic<bool> isRunning;
    HANDLE hPipe;
    std::queue<Message> messageQueue;
    std::mutex queueMutex;
    std::condition_variable queueCondition;

public:
    CommunicationManager();
    ~CommunicationManager();

    bool Initialize();
    void Update();
    void Cleanup();

    bool IsInitialized() const;
    void SendMessage(const Message& message);
    void SendThreatAlert(const ThreatInfo& threatInfo);
    Message ReceiveMessage();

private:
    void ServerThread();
    void HandleClientConnection(HANDLE hClient);
    bool SendMessageToClient(HANDLE hClient, const Message& message);
    bool ReceiveMessageFromClient(HANDLE hClient, Message& message);
};
