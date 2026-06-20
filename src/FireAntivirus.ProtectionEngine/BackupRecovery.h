#pragma once

class BackupRecovery {
private:
    std::atomic<bool> isInitialized;
    std::atomic<bool> isEnabled;

public:
    BackupRecovery();
    ~BackupRecovery();

    bool Initialize();
    void Update();
    void Cleanup();

    bool IsEnabled() const;
    void SetEnabled(bool enabled);

    // 文件备份
    bool BackupFiles();
    
    // 文件恢复
    bool RecoverFiles();
};