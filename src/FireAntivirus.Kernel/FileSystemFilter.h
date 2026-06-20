// FileSystemFilter.h

#pragma once

#include <Windows.h>
#include <vector>
#include <string>

class FileSystemFilter {
private:
    static FileSystemFilter* instance;
    bool isInitialized;
    bool isFilterEnabled;

public:
    static FileSystemFilter* GetInstance();

    bool Initialize();
    void Shutdown();
    bool IsInitialized();

    // 过滤器管理
    bool EnableFilter();
    bool DisableFilter();
    bool IsFilterEnabled();

    // 文件操作监控
    bool MonitorFileCreation();
    bool UnmonitorFileCreation();
    bool MonitorFileDeletion();
    bool UnmonitorFileDeletion();
    bool MonitorFileModification();
    bool UnmonitorFileModification();
    bool MonitorFileAccess();
    bool UnmonitorFileAccess();

    // 文件路径过滤
    bool AddFilepathToBlocklist(const wchar_t* filepath);
    bool RemoveFilepathFromBlocklist(const wchar_t* filepath);
    bool IsFilepathBlocked(const wchar_t* filepath);
    bool AddFilepathToAllowlist(const wchar_t* filepath);
    bool RemoveFilepathFromAllowlist(const wchar_t* filepath);
    bool IsFilepathAllowed(const wchar_t* filepath);

    // 文件类型过滤
    bool AddFileExtensionToBlocklist(const wchar_t* extension);
    bool RemoveFileExtensionFromBlocklist(const wchar_t* extension);
    bool IsFileExtensionBlocked(const wchar_t* extension);

    // 回调函数类型
    typedef bool (*FileOperationCallback)(
        const wchar_t* filepath,
        DWORD operationType,
        DWORD processId,
        const wchar_t* processName
    );

    // 设置回调函数
    void SetFileOperationCallback(FileOperationCallback callback);

private:
    FileSystemFilter();
    ~FileSystemFilter();

    // 回调函数
    static FileOperationCallback fileOperationCallback;

    // 辅助方法
    bool InitializeFilterDriver();
    bool ShutdownFilterDriver();
    bool RegisterFilterCallbacks();
    bool UnregisterFilterCallbacks();
};
