#pragma once

#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <thread>
#include <mutex>
#include <queue>
#include <atomic>
#include <functional>
#include <filesystem>
#include <algorithm>
#include <condition_variable>
#include <sstream>
#include <iomanip>
#include <memory>

// Windows SDK headers
#include <winbase.h>
#include <winnt.h>
#include <winternl.h>
#include <winsvc.h>
#include <setupapi.h>
#include <devguid.h>
#include <cfgmgr32.h>
#include <winioctl.h>
#include <Tlhelp32.h>
#include <psapi.h>
#include <detours.h>

// ETW headers
#include <evntcons.h>
#include <evntprov.h>

// STL headers
#include <string_view>
#include <optional>
#include <variant>

// Project headers
#include "ProtectionManager.h"
#include "FileProtection.h"
#include "ProcessProtection.h"
#include "RegistryProtection.h"
#include "ScriptProtection.h"
#include "DeviceProtection.h"
#include "ActiveDefense.h"
#include "DocumentProtection.h"
#include "DiskProtection.h"
#include "CommunicationManager.h"
#include "ProcessGuard.h"

// Define constants
#define MAX_PATH_LENGTH 260
#define MAX_THREADS 16
#define MAX_QUEUE_SIZE 1024
#define PIPE_NAME L"\\\\.\\pipe\\FireAntivirusPipe"
#define GUARD_PIPE_NAME L"\\\\.\\pipe\\FireAntivirusGuardPipe"
#define MAX_MESSAGE_SIZE 4096
#define HEARTBEAT_INTERVAL 5000 // 5 seconds

// Define error codes
#define ERROR_SUCCESS 0
#define ERROR_FAILURE 1
#define ERROR_INVALID_PARAMETER 2
#define ERROR_OUT_OF_MEMORY 3
#define ERROR_PIPE_CONNECTION 4
#define ERROR_PROCESS_TERMINATED 5

// Define threat types
enum class ThreatType {
    FILE_MALICIOUS,
    PROCESS_MALICIOUS,
    REGISTRY_MALICIOUS,
    SCRIPT_MALICIOUS,
    DEVICE_MALICIOUS,
    BEHAVIOR_MALICIOUS,
    DOCUMENT_MALICIOUS,
    DISK_MALICIOUS
};

// Define threat action
enum class ThreatAction {
    ALLOW,
    BLOCK
};

// Define threat structure
#pragma pack(push, 1)
struct ThreatInfo {
    ThreatType type;
    wchar_t processPath[260];
    wchar_t targetPath[260];
    wchar_t threatDescription[260];
    DWORD processId;
    DWORD threadId;
};
#pragma pack(pop)

// Define message structure
#pragma pack(push, 1)
struct Message {
    DWORD type;
    ThreatInfo threatInfo;
    ThreatAction action;
};
#pragma pack(pop)

// Define utility functions
std::wstring GetProcessPath(DWORD processId);
std::wstring GetProcessName(DWORD processId);
DWORD GetParentProcessId(DWORD processId);
bool IsProcessRunning(DWORD processId);
bool TerminateProcessById(DWORD processId);
std::wstring GetCurrentDirectory();
std::wstring GetSystemDirectory();
std::wstring GetWindowsDirectory();
bool IsPathProtected(const std::wstring& path);
bool IsProcessProtected(DWORD processId);
void Log(const std::wstring& message);
void LogError(const std::wstring& message);
void LogWarning(const std::wstring& message);
