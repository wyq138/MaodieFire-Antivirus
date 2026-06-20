// NativeSecurityCore.h

#pragma once

#include "pch.h"

// 导出宏
#ifdef NATIVESECURITYCORE_EXPORTS
#define NATIVESECURITYCORE_API __declspec(dllexport)
#else
#define NATIVESECURITYCORE_API __declspec(dllimport)
#endif

// 威胁类型
enum class ThreatType {
    MALWARE,         // 恶意软件
    VIRUS,           // 病毒
    TROJAN,          // 木马
    RANSOMWARE,      // 勒索软件
    SPYWARE,         // 间谍软件
    ADWARE,          // 广告软件
    PHISHING,        // 钓鱼
    MALICIOUS_SCRIPT, // 恶意脚本
    SUSPICIOUS_PROCESS, // 可疑进程
    UNAUTHORIZED_ACCESS, // 未授权访问
    NETWORK_ATTACK,  // 网络攻击
    REGISTRY_MODIFICATION, // 注册表修改
    BROWSER_HIJACK,  // 浏览器劫持
    DEVICE_INFECTION, // 设备感染
    DISK_PARTITION_MODIFICATION, // 分区表修改
    UEFI_BIOS_ATTACK, // UEFI/BIOS攻击
    KERNEL_TAMPERING, // 内核篡改
    DOCUMENT_INFECTION, // 文档感染
    NETWORK_TRAFFIC_ANOMALY, // 网络流量异常
    POPUP_SPAM,      // 弹窗垃圾
    PRIVACY_VIOLATION, // 隐私侵犯
    WEB_THREAT,      // 网页威胁
    EMAIL_THREAT,    // 邮件威胁
    PASSWORD_THEFT,  // 密码盗窃
    FIREWALL_BYPASS, // 防火墙绕过
    DEVICE_CONTROL_VIOLATION, // 设备控制违规
    VULNERABILITY_EXPLOIT, // 漏洞利用
    CLOUD_STORAGE_THREAT, // 云存储威胁
    BROWSER_SECURITY_VIOLATION, // 浏览器安全违规
    MOBILE_DEVICE_THREAT, // 移动设备威胁
    SYSTEM_PERFORMANCE_ANOMALY, // 系统性能异常
    BACKUP_FAILURE,  // 备份失败
    SECURITY_SCORE_LOW, // 安全评分低
    APPLICATION_BEHAVIOR_ANOMALY, // 应用行为异常
    STARTUP_ITEM_VIOLATION, // 启动项违规
    SECURITY_REPORT_ERROR, // 安全报告错误
    BEHAVIORAL_THREAT, // 行为威胁
    SYSTEM_TOOL_MISUSE, // 系统工具滥用
    SYSTEM_INFORMATION_LEAK, // 系统信息泄露
    QUARANTINE_ACCESS_VIOLATION, // 隔离区访问违规
    TRUST_ZONE_VIOLATION, // 信任区违规
    LOG_CENTER_ERROR // 日志中心错误
};

// 防护操作
enum class ProtectionAction {
    BLOCK,       // 阻止
    ALLOW,       // 允许
    QUARANTINE,  // 隔离
    DELETE,      // 删除
    IGNORE,      // 忽略
    REPORT       // 报告
};

// 防护状态
enum class ProtectionStatus {
    DISABLED,    // 已禁用
    ENABLED,     // 已启用
    WARNING,     // 警告
    ERROR,       // 错误
    PROTECTING   // 正在防护
};

// 威胁信息结构体
typedef struct {
    ThreatType type;         // 威胁类型
    wchar_t target[1024];    // 目标（文件路径、进程名等）
    wchar_t description[1024]; // 威胁描述
    int severity;            // 严重程度（1-5）
    SYSTEMTIME timestamp;    // 发现时间
} ThreatInfo;

// 核心库主类
class NATIVESECURITYCORE_API NativeSecurityCore {
private:
    static NativeSecurityCore* instance;
    std::mutex instanceMutex;
    bool isInitialized;
    bool isRunning;
    
    // 各种防护模块的指针
    class FileProtection* fileProtection;
    class ProcessProtection* processProtection;
    class DeviceProtection* deviceProtection;
    class RegistryProtection* registryProtection;
    class BrowserProtection* browserProtection;
    class ScriptProtection* scriptProtection;
    class ActiveDefense* activeDefense;
    class DiskProtection* diskProtection;
    class UEFIProtection* uefiProtection;
    class KernelProtection* kernelProtection;
    class DocumentProtection* documentProtection;
    class NetworkProtection* networkProtection;
    class PopupBlocker* popupBlocker;
    class RansomwareProtection* ransomwareProtection;
    class PrivacyProtection* privacyProtection;
    class WebProtection* webProtection;
    class EmailSecurity* emailSecurity;
    class PasswordManager* passwordManager;
    class NetworkFirewall* networkFirewall;
    class DeviceControl* deviceControl;
    class VulnerabilityScanner* vulnerabilityScanner;
    class CloudScan* cloudScan;
    class SecureBrowser* secureBrowser;
    class MobileSecurity* mobileSecurity;
    class SystemOptimizer* systemOptimizer;
    class BackupRecovery* backupRecovery;
    class SecurityScore* securityScore;
    class NetworkTraffic* networkTraffic;
    class ApplicationMonitor* applicationMonitor;
    class StartupManager* startupManager;
    class SecurityReport* securityReport;
    class BehaviorAnalysis* behaviorAnalysis;
    class SystemTools* systemTools;
    class SystemInfo* systemInfo;
    class Quarantine* quarantine;
    class TrustZone* trustZone;
    class LogCenter* logCenter;
    
    // 监控线程
    std::thread monitoringThread;
    std::mutex statusMutex;
    ProtectionStatus currentStatus;
    
    // 回调函数
    std::function<void(const ThreatInfo&)> threatCallback;
    std::function<void(const ProtectionStatus&)> statusCallback;
    
    // 私有构造函数
    NativeSecurityCore();
    ~NativeSecurityCore();
    
    // 初始化所有模块
    bool InitializeModules();
    
    // 清理所有模块
    void CleanupModules();
    
    // 监控线程函数
    void MonitoringThread();
    
public:
    // 获取单例实例
    static NativeSecurityCore* GetInstance();
    
    // 初始化核心库
    bool Initialize();
    
    // 启动保护
    bool StartProtection();
    
    // 停止保护
    void StopProtection();
    
    // 检查是否初始化
    bool IsInitialized() const;
    
    // 检查是否正在运行
    bool IsRunning() const;
    
    // 获取当前防护状态
    ProtectionStatus GetProtectionStatus();
    
    // 设置威胁回调函数
    void SetThreatCallback(std::function<void(const ThreatInfo&)> callback);
    
    // 设置状态回调函数
    void SetStatusCallback(std::function<void(const ProtectionStatus&)> callback);
    
    // 处理威胁
    void HandleThreat(const ThreatInfo& threat, ProtectionAction action);
    
    // 文件防护
    bool EnableFileProtection(bool enable);
    bool IsFileProtectionEnabled() const;
    
    // 进程防护
    bool EnableProcessProtection(bool enable);
    bool IsProcessProtectionEnabled() const;
    
    // U盘防护
    bool EnableDeviceProtection(bool enable);
    bool IsDeviceProtectionEnabled() const;
    
    // 注册表防护
    bool EnableRegistryProtection(bool enable);
    bool IsRegistryProtectionEnabled() const;
    
    // 浏览器防护
    bool EnableBrowserProtection(bool enable);
    bool IsBrowserProtectionEnabled() const;
    
    // 脚本防护
    bool EnableScriptProtection(bool enable);
    bool IsScriptProtectionEnabled() const;
    
    // 主动防御
    bool EnableActiveDefense(bool enable);
    bool IsActiveDefenseEnabled() const;
    
    // 分区表防护
    bool EnableDiskProtection(bool enable);
    bool IsDiskProtectionEnabled() const;
    
    // UEFI/BIOS防护
    bool EnableUEFIProtection(bool enable);
    bool IsUEFIProtectionEnabled() const;
    
    // 内核防护
    bool EnableKernelProtection(bool enable);
    bool IsKernelProtectionEnabled() const;
    
    // 文档防护
    bool EnableDocumentProtection(bool enable);
    bool IsDocumentProtectionEnabled() const;
    
    // 网络防护
    bool EnableNetworkProtection(bool enable);
    bool IsNetworkProtectionEnabled() const;
    
    // 弹窗拦截
    bool EnablePopupBlocker(bool enable);
    bool IsPopupBlockerEnabled() const;
    
    // 勒索防护
    bool EnableRansomwareProtection(bool enable);
    bool IsRansomwareProtectionEnabled() const;
    
    // 隐私保护
    bool EnablePrivacyProtection(bool enable);
    bool IsPrivacyProtectionEnabled() const;
    
    // 网页防护
    bool EnableWebProtection(bool enable);
    bool IsWebProtectionEnabled() const;
    
    // 邮件安全
    bool EnableEmailSecurity(bool enable);
    bool IsEmailSecurityEnabled() const;
    
    // 密码管理
    bool EnablePasswordManager(bool enable);
    bool IsPasswordManagerEnabled() const;
    
    // 网络防火墙
    bool EnableNetworkFirewall(bool enable);
    bool IsNetworkFirewallEnabled() const;
    
    // 设备控制
    bool EnableDeviceControl(bool enable);
    bool IsDeviceControlEnabled() const;
    
    // 漏洞扫描
    bool EnableVulnerabilityScanner(bool enable);
    bool IsVulnerabilityScannerEnabled() const;
    
    // 云查杀
    bool EnableCloudScan(bool enable);
    bool IsCloudScanEnabled() const;
    
    // 安全浏览器
    bool EnableSecureBrowser(bool enable);
    bool IsSecureBrowserEnabled() const;
    
    // 移动安全
    bool EnableMobileSecurity(bool enable);
    bool IsMobileSecurityEnabled() const;
    
    // 系统优化
    bool EnableSystemOptimizer(bool enable);
    bool IsSystemOptimizerEnabled() const;
    
    // 备份恢复
    bool EnableBackupRecovery(bool enable);
    bool IsBackupRecoveryEnabled() const;
    
    // 安全评分
    bool EnableSecurityScore(bool enable);
    bool IsSecurityScoreEnabled() const;
    
    // 网络流量
    bool EnableNetworkTraffic(bool enable);
    bool IsNetworkTrafficEnabled() const;
    
    // 应用监控
    bool EnableApplicationMonitor(bool enable);
    bool IsApplicationMonitorEnabled() const;
    
    // 启动管理
    bool EnableStartupManager(bool enable);
    bool IsStartupManagerEnabled() const;
    
    // 安全报告
    bool EnableSecurityReport(bool enable);
    bool IsSecurityReportEnabled() const;
    
    // 行为分析
    bool EnableBehaviorAnalysis(bool enable);
    bool IsBehaviorAnalysisEnabled() const;
    
    // 系统工具
    bool EnableSystemTools(bool enable);
    bool IsSystemToolsEnabled() const;
    
    // 系统信息
    bool EnableSystemInfo(bool enable);
    bool IsSystemInfoEnabled() const;
    
    // 隔离区
    bool EnableQuarantine(bool enable);
    bool IsQuarantineEnabled() const;
    
    // 信任区
    bool EnableTrustZone(bool enable);
    bool IsTrustZoneEnabled() const;
    
    // 日志中心
    bool EnableLogCenter(bool enable);
    bool IsLogCenterEnabled() const;
};

// 导出函数
extern "C" {
    NATIVESECURITYCORE_API NativeSecurityCore* GetInstance();
    NATIVESECURITYCORE_API bool Initialize(NativeSecurityCore* instance);
    NATIVESECURITYCORE_API bool StartProtection(NativeSecurityCore* instance);
    NATIVESECURITYCORE_API void StopProtection(NativeSecurityCore* instance);
    NATIVESECURITYCORE_API bool IsInitialized(NativeSecurityCore* instance);
    NATIVESECURITYCORE_API bool IsRunning(NativeSecurityCore* instance);
    NATIVESECURITYCORE_API ProtectionStatus GetProtectionStatus(NativeSecurityCore* instance);
    NATIVESECURITYCORE_API void SetThreatCallback(NativeSecurityCore* instance, void(*callback)(const ThreatInfo&));
    NATIVESECURITYCORE_API void SetStatusCallback(NativeSecurityCore* instance, void(*callback)(const ProtectionStatus&));
    NATIVESECURITYCORE_API void HandleThreat(NativeSecurityCore* instance, const ThreatInfo& threat, ProtectionAction action);
    NATIVESECURITYCORE_API bool EnableFileProtection(NativeSecurityCore* instance, bool enable);
    NATIVESECURITYCORE_API bool IsFileProtectionEnabled(NativeSecurityCore* instance);
    NATIVESECURITYCORE_API bool EnableProcessProtection(NativeSecurityCore* instance, bool enable);
    NATIVESECURITYCORE_API bool IsProcessProtectionEnabled(NativeSecurityCore* instance);
    NATIVESECURITYCORE_API bool EnableDeviceProtection(NativeSecurityCore* instance, bool enable);
    NATIVESECURITYCORE_API bool IsDeviceProtectionEnabled(NativeSecurityCore* instance);
    NATIVESECURITYCORE_API bool EnableRegistryProtection(NativeSecurityCore* instance, bool enable);
    NATIVESECURITYCORE_API bool IsRegistryProtectionEnabled(NativeSecurityCore* instance);
    NATIVESECURITYCORE_API bool EnableBrowserProtection(NativeSecurityCore* instance, bool enable);
    NATIVESECURITYCORE_API bool IsBrowserProtectionEnabled(NativeSecurityCore* instance);
    NATIVESECURITYCORE_API bool EnableScriptProtection(NativeSecurityCore* instance, bool enable);
    NATIVESECURITYCORE_API bool IsScriptProtectionEnabled(NativeSecurityCore* instance);
    NATIVESECURITYCORE_API bool EnableActiveDefense(NativeSecurityCore* instance, bool enable);
    NATIVESECURITYCORE_API bool IsActiveDefenseEnabled(NativeSecurityCore* instance);
    NATIVESECURITYCORE_API bool EnableDiskProtection(NativeSecurityCore* instance, bool enable);
    NATIVESECURITYCORE_API bool IsDiskProtectionEnabled(NativeSecurityCore* instance);
    NATIVESECURITYCORE_API bool EnableUEFIProtection(NativeSecurityCore* instance, bool enable);
    NATIVESECURITYCORE_API bool IsUEFIProtectionEnabled(NativeSecurityCore* instance);
    NATIVESECURITYCORE_API bool EnableKernelProtection(NativeSecurityCore* instance, bool enable);
    NATIVESECURITYCORE_API bool IsKernelProtectionEnabled(NativeSecurityCore* instance);
    NATIVESECURITYCORE_API bool EnableDocumentProtection(NativeSecurityCore* instance, bool enable);
    NATIVESECURITYCORE_API bool IsDocumentProtectionEnabled(NativeSecurityCore* instance);
    NATIVESECURITYCORE_API bool EnableNetworkProtection(NativeSecurityCore* instance, bool enable);
    NATIVESECURITYCORE_API bool IsNetworkProtectionEnabled(NativeSecurityCore* instance);
    NATIVESECURITYCORE_API bool EnablePopupBlocker(NativeSecurityCore* instance, bool enable);
    NATIVESECURITYCORE_API bool IsPopupBlockerEnabled(NativeSecurityCore* instance);
    NATIVESECURITYCORE_API bool EnableRansomwareProtection(NativeSecurityCore* instance, bool enable);
    NATIVESECURITYCORE_API bool IsRansomwareProtectionEnabled(NativeSecurityCore* instance);
    NATIVESECURITYCORE_API bool EnablePrivacyProtection(NativeSecurityCore* instance, bool enable);
    NATIVESECURITYCORE_API bool IsPrivacyProtectionEnabled(NativeSecurityCore* instance);
    NATIVESECURITYCORE_API bool EnableWebProtection(NativeSecurityCore* instance, bool enable);
    NATIVESECURITYCORE_API bool IsWebProtectionEnabled(NativeSecurityCore* instance);
    NATIVESECURITYCORE_API bool EnableEmailSecurity(NativeSecurityCore* instance, bool enable);
    NATIVESECURITYCORE_API bool IsEmailSecurityEnabled(NativeSecurityCore* instance);
    NATIVESECURITYCORE_API bool EnablePasswordManager(NativeSecurityCore* instance, bool enable);
    NATIVESECURITYCORE_API bool IsPasswordManagerEnabled(NativeSecurityCore* instance);
    NATIVESECURITYCORE_API bool EnableNetworkFirewall(NativeSecurityCore* instance, bool enable);
    NATIVESECURITYCORE_API bool IsNetworkFirewallEnabled(NativeSecurityCore* instance);
    NATIVESECURITYCORE_API bool EnableDeviceControl(NativeSecurityCore* instance, bool enable);
    NATIVESECURITYCORE_API bool IsDeviceControlEnabled(NativeSecurityCore* instance);
    NATIVESECURITYCORE_API bool EnableVulnerabilityScanner(NativeSecurityCore* instance, bool enable);
    NATIVESECURITYCORE_API bool IsVulnerabilityScannerEnabled(NativeSecurityCore* instance);
    NATIVESECURITYCORE_API bool EnableCloudScan(NativeSecurityCore* instance, bool enable);
    NATIVESECURITYCORE_API bool IsCloudScanEnabled(NativeSecurityCore* instance);
    NATIVESECURITYCORE_API bool EnableSecureBrowser(NativeSecurityCore* instance, bool enable);
    NATIVESECURITYCORE_API bool IsSecureBrowserEnabled(NativeSecurityCore* instance);
    NATIVESECURITYCORE_API bool EnableMobileSecurity(NativeSecurityCore* instance, bool enable);
    NATIVESECURITYCORE_API bool IsMobileSecurityEnabled(NativeSecurityCore* instance);
    NATIVESECURITYCORE_API bool EnableSystemOptimizer(NativeSecurityCore* instance, bool enable);
    NATIVESECURITYCORE_API bool IsSystemOptimizerEnabled(NativeSecurityCore* instance);
    NATIVESECURITYCORE_API bool EnableBackupRecovery(NativeSecurityCore* instance, bool enable);
    NATIVESECURITYCORE_API bool IsBackupRecoveryEnabled(NativeSecurityCore* instance);
    NATIVESECURITYCORE_API bool EnableSecurityScore(NativeSecurityCore* instance, bool enable);
    NATIVESECURITYCORE_API bool IsSecurityScoreEnabled(NativeSecurityCore* instance);
    NATIVESECURITYCORE_API bool EnableNetworkTraffic(NativeSecurityCore* instance, bool enable);
    NATIVESECURITYCORE_API bool IsNetworkTrafficEnabled(NativeSecurityCore* instance);
    NATIVESECURITYCORE_API bool EnableApplicationMonitor(NativeSecurityCore* instance, bool enable);
    NATIVESECURITYCORE_API bool IsApplicationMonitorEnabled(NativeSecurityCore* instance);
    NATIVESECURITYCORE_API bool EnableStartupManager(NativeSecurityCore* instance, bool enable);
    NATIVESECURITYCORE_API bool IsStartupManagerEnabled(NativeSecurityCore* instance);
    NATIVESECURITYCORE_API bool EnableSecurityReport(NativeSecurityCore* instance, bool enable);
    NATIVESECURITYCORE_API bool IsSecurityReportEnabled(NativeSecurityCore* instance);
    NATIVESECURITYCORE_API bool EnableBehaviorAnalysis(NativeSecurityCore* instance, bool enable);
    NATIVESECURITYCORE_API bool IsBehaviorAnalysisEnabled(NativeSecurityCore* instance);
    NATIVESECURITYCORE_API bool EnableSystemTools(NativeSecurityCore* instance, bool enable);
    NATIVESECURITYCORE_API bool IsSystemToolsEnabled(NativeSecurityCore* instance);
    NATIVESECURITYCORE_API bool EnableSystemInfo(NativeSecurityCore* instance, bool enable);
    NATIVESECURITYCORE_API bool IsSystemInfoEnabled(NativeSecurityCore* instance);
    NATIVESECURITYCORE_API bool EnableQuarantine(NativeSecurityCore* instance, bool enable);
    NATIVESECURITYCORE_API bool IsQuarantineEnabled(NativeSecurityCore* instance);
    NATIVESECURITYCORE_API bool EnableTrustZone(NativeSecurityCore* instance, bool enable);
    NATIVESECURITYCORE_API bool IsTrustZoneEnabled(NativeSecurityCore* instance);
    NATIVESECURITYCORE_API bool EnableLogCenter(NativeSecurityCore* instance, bool enable);
    NATIVESECURITYCORE_API bool IsLogCenterEnabled(NativeSecurityCore* instance);
}