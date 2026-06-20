#pragma once

class Main {
private:
    static std::atomic<bool> isRunning;
    static std::thread protectionThread;
    static std::thread communicationThread;
    static std::thread guardThread;
    static std::shared_ptr<ProtectionManager> protectionManager;
    static std::shared_ptr<CommunicationManager> communicationManager;
    static std::shared_ptr<ProcessGuard> processGuard;

public:
    static int Run(int argc, char* argv[]);
    static void Stop();
    static bool IsRunning();

private:
    static void ProtectionThread();
    static void CommunicationThread();
    static void GuardThread();
    static void Initialize();
    static void Cleanup();
};
