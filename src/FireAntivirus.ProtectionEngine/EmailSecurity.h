#pragma once

class EmailSecurity {
private:
    std::atomic<bool> isInitialized;
    std::atomic<bool> isEnabled;

public:
    EmailSecurity();
    ~EmailSecurity();

    bool Initialize();
    void Update();
    void Cleanup();

    bool IsEnabled() const;
    void SetEnabled(bool enabled);

    // 邮件附件查杀
    bool ScanEmailAttachments();
    
    // 钓鱼邮件识别
    bool IdentifyPhishingEmails();
};