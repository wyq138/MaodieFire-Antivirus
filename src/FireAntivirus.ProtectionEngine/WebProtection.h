#pragma once

class WebProtection {
private:
    std::atomic<bool> isInitialized;
    std::atomic<bool> isEnabled;

public:
    WebProtection();
    ~WebProtection();

    bool Initialize();
    void Update();
    void Cleanup();

    bool IsEnabled() const;
    void SetEnabled(bool enabled);

    // 恶意URL检测
    bool DetectMaliciousUrls();
    
    // 钓鱼/挂马页面检测
    bool DetectPhishingPages();
};