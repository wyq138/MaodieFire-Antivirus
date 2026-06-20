#pragma once

class PasswordManager {
private:
    std::atomic<bool> isInitialized;
    std::atomic<bool> isEnabled;

public:
    PasswordManager();
    ~PasswordManager();

    bool Initialize();
    void Update();
    void Cleanup();

    bool IsEnabled() const;
    void SetEnabled(bool enabled);

    // 密码加密
    std::string EncryptPassword(const std::string& password);
    
    // 密码解密
    std::string DecryptPassword(const std::string& encryptedPassword);
    
    // 弱密码检测
    bool CheckWeakPassword(const std::string& password);
};