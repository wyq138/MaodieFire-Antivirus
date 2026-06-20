#pragma once

class SecurityScore {
private:
    std::atomic<bool> isInitialized;
    std::atomic<bool> isEnabled;

public:
    SecurityScore();
    ~SecurityScore();

    bool Initialize();
    void Update();
    void Cleanup();

    bool IsEnabled() const;
    void SetEnabled(bool enabled);

    // 设备安全评分计算
    int CalculateSecurityScore();
};