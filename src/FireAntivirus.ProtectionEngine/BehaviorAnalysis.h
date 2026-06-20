#pragma once

class BehaviorAnalysis {
private:
    std::atomic<bool> isInitialized;
    std::atomic<bool> isEnabled;

public:
    BehaviorAnalysis();
    ~BehaviorAnalysis();

    bool Initialize();
    void Update();
    void Cleanup();

    bool IsEnabled() const;
    void SetEnabled(bool enabled);

    // 程序行为基线比对
    bool CompareBehaviorBaseline();
};