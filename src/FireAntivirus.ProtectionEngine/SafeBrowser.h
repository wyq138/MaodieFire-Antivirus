#pragma once

class SafeBrowser {
private:
    std::atomic<bool> isInitialized;
    std::atomic<bool> isEnabled;

public:
    SafeBrowser();
    ~SafeBrowser();

    bool Initialize();
    void Update();
    void Cleanup();

    bool IsEnabled() const;
    void SetEnabled(bool enabled);

    // 恶意页面检测
    bool DetectMaliciousPages();
};