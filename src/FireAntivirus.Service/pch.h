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
#include <winsvc.h>
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

// 链接必要的库
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "bcrypt.lib")

// 服务名称
#define SERVICE_NAME L"FireAntivirusService"
#define SERVICE_DISPLAY_NAME L"Fire Antivirus Service"

// 互斥体名称
#define MUTEX_NAME L"Global\\FireAntivirusServiceMutex"
#define PROTECTION_MUTEX_NAME L"Global\\FireAntivirusProtectionMutex"

// 管道名称
#define PIPE_NAME L"\\\\.\\pipe\\FireAntivirusServicePipe"

// 错误代码
#define ERROR_SERVICE_ALREADY_RUNNING 1056

// 服务状态
enum class ServiceState {
    STOPPED,
    STARTING,
    RUNNING,
    STOPPING
};

// 进程信息
struct ProcessInfo {
    DWORD processId;
    std::wstring processName;
    std::wstring processPath;
    bool isProtected;
};