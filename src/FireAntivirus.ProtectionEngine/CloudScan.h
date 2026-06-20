#pragma once

class CloudScan {
private:
    std::atomic<bool> isInitialized;
    std::atomic<bool> isEnabled;

public:
    CloudScan();
    ~CloudScan();

    bool Initialize();
    void Update();
    void Cleanup();

    bool IsEnabled() const;
    void SetEnabled(bool enabled);

    // 文件特征提取
    bool ExtractFileFeatures();
    
    // 本地扫描
    bool LocalScan();
};