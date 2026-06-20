#pragma once

class SystemOptimization {
private:
    std::atomic<bool> isInitialized;
    std::atomic<bool> isEnabled;

public:
    SystemOptimization();
    ~SystemOptimization();

    bool Initialize();
    void Update();
    void Cleanup();

    bool IsEnabled() const;
    void SetEnabled(bool enabled);

    // 垃圾清理
    bool CleanupJunk();
    
    // 启动项优化
    bool OptimizeStartupItems();
};