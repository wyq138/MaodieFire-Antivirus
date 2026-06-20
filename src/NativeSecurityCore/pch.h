// pch.h: 这是预编译头文件

#pragma once

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <thread>
#include <mutex>
#include <chrono>
#include <functional>
#include <Windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <Tlhelp32.h>
#include <Psapi.h>
#include <Wtsapi32.h>
#include <ShlObj.h>
#include <SetupAPI.h>
#include <Dbt.h>
#include <comdef.h>
#include <Wbemidl.h>
#include <winternl.h>
#include <strsafe.h>
#include <bcrypt.h>
#include <Aclapi.h>
#include <Sddl.h>
#include <mstask.h>
#include <taskschd.h>
#include <wincrypt.h>
#include <msxml6.h>
#include <msi.h>
#include <winhttp.h>
#include <vss.h>
#include <vswriter.h>
#include <fwpmu.h>

// 链接必要的库
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "msxml6.lib")
#pragma comment(lib, "msi.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "vssapi.lib")
#pragma comment(lib, "fwpuclnt.lib")

// 定义导出宏
#ifdef NATIVESECURITYCORE_EXPORTS
#define NATIVESECURITYCORE_API __declspec(dllexport)
#else
#define NATIVESECURITYCORE_API __declspec(dllimport)
#endif

// 威胁类型定义
enum class ThreatType {
    FILE_MALICIOUS,
    PROCESS_MALICIOUS,
    DEVICE_UNAUTHORIZED,
    REGISTRY_TAMPERING,
    BROWSER_TAMPERING,
    SCRIPT_MALICIOUS,
    BEHAVIOR_MALICIOUS,
    DISK_TAMPERING,
    UEFI_TAMPERING,
    KERNEL_TAMPERING,
    DOCUMENT_ENCRYPTION,
    NETWORK_MALICIOUS,
    POPUP_AD,
    RANSOMWARE_ACTIVITY,
    PRIVACY_VIOLATION,
    WEB_MALICIOUS,
    EMAIL_PHISHING,
    PASSWORD_WEAK,
    FIREWALL_BLOCKED,
    DEVICE_BLOCKED,
    VULNERABILITY_FOUND,
    CLOUD_THREAT_FOUND,
    BROWSER_VULNERABILITY,
    MOBILE_THREAT,
    SYSTEM_OPTIMIZATION,
    BACKUP_REQUIRED,
    SECURITY_SCORE_LOW,
    NETWORK_TRAFFIC_ANOMALY,
    APPLICATION_ABUSE,
    STARTUP_ITEM_UNAUTHORIZED,
    SECURITY_EVENT,
    BEHAVIOR_SUSPICIOUS,
    SYSTEM_TOOL_OPERATION,
    SYSTEM_INFO_CHANGED,
    QUARANTINE_ITEM,
    TRUST_ZONE_ITEM,
    LOG_EVENT
};

// 威胁信息结构体
struct ThreatInfo {
    ThreatType type;
    WCHAR processPath[MAX_PATH];
    WCHAR targetPath[MAX_PATH];
    WCHAR threatDescription[MAX_PATH];
    DWORD processId;
    DWORD threadId;
};

// 防护状态结构体
struct ProtectionStatus {
    bool fileProtectionEnabled;
    bool processProtectionEnabled;
    bool deviceProtectionEnabled;
    bool registryProtectionEnabled;
    bool browserProtectionEnabled;
    bool scriptProtectionEnabled;
    bool activeDefenseEnabled;
    bool diskProtectionEnabled;
    bool uefiProtectionEnabled;
    bool kernelProtectionEnabled;
    bool documentProtectionEnabled;
    bool networkProtectionEnabled;
    bool popupBlockerEnabled;
    bool ransomwareProtectionEnabled;
    bool privacyProtectionEnabled;
    bool webProtectionEnabled;
    bool emailSecurityEnabled;
    bool passwordManagerEnabled;
    bool networkFirewallEnabled;
    bool deviceControlEnabled;
    bool vulnerabilityScannerEnabled;
    bool cloudScanEnabled;
    bool secureBrowserEnabled;
    bool mobileSecurityEnabled;
    bool systemOptimizerEnabled;
    bool backupRecoveryEnabled;
    bool securityScoreEnabled;
    bool networkTrafficEnabled;
    bool applicationMonitorEnabled;
    bool startupManagerEnabled;
    bool securityReportEnabled;
    bool behaviorAnalysisEnabled;
    bool systemToolsEnabled;
    bool systemInfoEnabled;
    bool quarantineEnabled;
    bool trustZoneEnabled;
    bool logCenterEnabled;
};

// 防护操作枚举
enum class ProtectionAction {
    BLOCK,
    ALLOW,
    QUARANTINE,
    DELETE,
    IGNORE,
    REPORT
};