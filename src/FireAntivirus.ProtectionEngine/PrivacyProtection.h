#pragma once

class PrivacyProtection {
private:
    std::atomic<bool> isInitialized;
    std::atomic<bool> isEnabled;

public:
    PrivacyProtection();
    ~PrivacyProtection();

    bool Initialize();
    void Update();
    void Cleanup();

    bool IsEnabled() const;
    void SetEnabled(bool enabled);

    // 敏感文件扫描
    bool ScanSensitiveFiles();
    
    // 程序隐私权限检测
    bool CheckProgramPrivacyPermissions();
    
    // 上网痕迹清理
    bool CleanupBrowsingTraces();
};