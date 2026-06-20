#pragma once

class SecurityReport {
private:
    std::atomic<bool> isInitialized;
    std::atomic<bool> isEnabled;

public:
    SecurityReport();
    ~SecurityReport();

    bool Initialize();
    void Update();
    void Cleanup();

    bool IsEnabled() const;
    void SetEnabled(bool enabled);

    // 生成安全报告
    bool GenerateSecurityReport();
};