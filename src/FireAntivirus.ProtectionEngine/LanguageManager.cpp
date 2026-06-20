#include "LanguageManager.h"
#include <fstream>
#include <iostream>

LanguageManager* LanguageManager::instance = nullptr;

LanguageManager::LanguageManager() : currentLanguage("zh-CN") {
    LoadBuiltInResources();
    LoadLanguageFromConfig();
}

LanguageManager::~LanguageManager() {
    SaveLanguageToConfig();
}

LanguageManager* LanguageManager::GetInstance() {
    if (!instance) {
        instance = new LanguageManager();
    }
    return instance;
}

void LanguageManager::LoadBuiltInResources() {
    // 简体中文
    languageResources["zh-CN"]["PrivacyProtection"] = "隐私保护";
    languageResources["zh-CN"]["ParentalControl"] = "家长控制";
    languageResources["zh-CN"]["WebProtection"] = "网页防护";
    languageResources["zh-CN"]["EmailSecurity"] = "邮件安全";
    languageResources["zh-CN"]["PasswordManager"] = "密码管理";
    languageResources["zh-CN"]["SystemOptimization"] = "系统优化";
    languageResources["zh-CN"]["BackupRecovery"] = "备份恢复";
    languageResources["zh-CN"]["NetworkFirewall"] = "网络防火墙";
    languageResources["zh-CN"]["DeviceControl"] = "设备控制";
    languageResources["zh-CN"]["VulnerabilityScan"] = "漏洞扫描";
    languageResources["zh-CN"]["CloudScan"] = "云查杀";
    languageResources["zh-CN"]["SafeBrowser"] = "安全浏览器";
    languageResources["zh-CN"]["SecurityScore"] = "安全评分";
    languageResources["zh-CN"]["NetworkTraffic"] = "网络流量";
    languageResources["zh-CN"]["ApplicationMonitor"] = "应用监控";
    languageResources["zh-CN"]["StartupManager"] = "启动管理";
    languageResources["zh-CN"]["SecurityReport"] = "安全报告";
    languageResources["zh-CN"]["BehaviorAnalysis"] = "行为分析";
    languageResources["zh-CN"]["MobileSecurity"] = "移动安全";
    languageResources["zh-CN"]["ScanStarted"] = "扫描已开始";
    languageResources["zh-CN"]["CleanupStarted"] = "清理已开始";
    languageResources["zh-CN"]["SettingsOpened"] = "设置已打开";
    languageResources["zh-CN"]["MonitoringStarted"] = "监控已开始";

    // 英语
    languageResources["en-US"]["PrivacyProtection"] = "Privacy Protection";
    languageResources["en-US"]["ParentalControl"] = "Parental Control";
    languageResources["en-US"]["WebProtection"] = "Web Protection";
    languageResources["en-US"]["EmailSecurity"] = "Email Security";
    languageResources["en-US"]["PasswordManager"] = "Password Manager";
    languageResources["en-US"]["SystemOptimization"] = "System Optimization";
    languageResources["en-US"]["BackupRecovery"] = "Backup Recovery";
    languageResources["en-US"]["NetworkFirewall"] = "Network Firewall";
    languageResources["en-US"]["DeviceControl"] = "Device Control";
    languageResources["en-US"]["VulnerabilityScan"] = "Vulnerability Scan";
    languageResources["en-US"]["CloudScan"] = "Cloud Scan";
    languageResources["en-US"]["SafeBrowser"] = "Safe Browser";
    languageResources["en-US"]["SecurityScore"] = "Security Score";
    languageResources["en-US"]["NetworkTraffic"] = "Network Traffic";
    languageResources["en-US"]["ApplicationMonitor"] = "Application Monitor";
    languageResources["en-US"]["StartupManager"] = "Startup Manager";
    languageResources["en-US"]["SecurityReport"] = "Security Report";
    languageResources["en-US"]["BehaviorAnalysis"] = "Behavior Analysis";
    languageResources["en-US"]["MobileSecurity"] = "Mobile Security";
    languageResources["en-US"]["ScanStarted"] = "Scan started";
    languageResources["en-US"]["CleanupStarted"] = "Cleanup started";
    languageResources["en-US"]["SettingsOpened"] = "Settings opened";
    languageResources["en-US"]["MonitoringStarted"] = "Monitoring started";
}

std::string LanguageManager::GetString(const std::string& key) {
    std::lock_guard<std::mutex> lock(mutex);
    if (languageResources.count(currentLanguage) && languageResources[currentLanguage].count(key)) {
        return languageResources[currentLanguage][key];
    }
    return key; // 返回键本身作为默认值
}

std::string LanguageManager::GetCurrentLanguage() const {
    return currentLanguage;
}

void LanguageManager::SetCurrentLanguage(const std::string& language) {
    std::lock_guard<std::mutex> lock(mutex);
    if (languageResources.count(language)) {
        currentLanguage = language;
        SaveLanguageToConfig();
    }
}

void LanguageManager::LoadLanguageFromConfig() {
    // 从配置文件加载语言设置
    // 这里简化实现，实际应该从配置文件读取
}

void LanguageManager::SaveLanguageToConfig() {
    // 保存语言设置到配置文件
    // 这里简化实现，实际应该保存到配置文件
}
