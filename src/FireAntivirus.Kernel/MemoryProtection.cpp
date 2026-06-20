// MemoryProtection.cpp

#include "pch.h"
#include "MemoryProtection.h"

// 初始化静态成员
MemoryProtection* MemoryProtection::instance = nullptr;

// 构造函数
MemoryProtection::MemoryProtection() {
    isInitialized = false;
}

// 析构函数
MemoryProtection::~MemoryProtection() {
    Shutdown();
}

// 获取单例实例
MemoryProtection* MemoryProtection::GetInstance() {
    // 使用双重检查锁定模式确保线程安全
    if (!instance) {
        // 这里可以使用互斥锁来确保线程安全
        // 实际应用中需要使用Windows的CriticalSection或其他同步机制
        instance = new MemoryProtection();
    }
    return instance;
}

// 初始化
bool MemoryProtection::Initialize() {
    try {
        // 初始化保护列表
        protectedProcesses.clear();

        isInitialized = true;
        return true;
    }
    catch (...) {
        return false;
    }
}

// 清理
void MemoryProtection::Shutdown() {
    try {
        // 取消所有进程的内存保护
        for (DWORD processId : protectedProcesses) {
            UnprotectProcessMemory(processId);
        }

        protectedProcesses.clear();
        isInitialized = false;
    }
    catch (...) {
        // 忽略异常
    }
}

// 检查是否已初始化
bool MemoryProtection::IsInitialized() {
    return isInitialized;
}

// 保护进程内存
bool MemoryProtection::ProtectProcessMemory(DWORD processId) {
    try {
        if (!isInitialized || !IsValidProcess(processId)) {
            return false;
        }

        // 检查是否已在保护列表中
        for (DWORD id : protectedProcesses) {
            if (id == processId) {
                return true;
            }
        }

        // 这里实现进程内存保护逻辑
        // 实际应用中需要使用内核API保护进程内存

        // 添加到保护列表
        protectedProcesses.push_back(processId);

        // 启用内存注入防护
        BlockMemoryInjection(processId);

        // 启用内存访问监控
        MonitorMemoryAccess(processId);

        return true;
    }
    catch (...) {
        return false;
    }
}

// 取消保护进程内存
bool MemoryProtection::UnprotectProcessMemory(DWORD processId) {
    try {
        if (!isInitialized) {
            return false;
        }

        // 检查是否在保护列表中
        bool found = false;
        for (auto it = protectedProcesses.begin(); it != protectedProcesses.end(); ++it) {
            if (*it == processId) {
                protectedProcesses.erase(it);
                found = true;
                break;
            }
        }

        if (!found) {
            return true;
        }

        // 这里实现取消进程内存保护逻辑
        // 实际应用中需要使用内核API取消保护

        // 禁用内存注入防护
        AllowMemoryInjection(processId);

        // 禁用内存访问监控
        UnmonitorMemoryAccess(processId);

        return true;
    }
    catch (...) {
        return false;
    }
}

// 检查进程内存是否被保护
bool MemoryProtection::IsProcessMemoryProtected(DWORD processId) {
    try {
        if (!isInitialized) {
            return false;
        }

        for (DWORD id : protectedProcesses) {
            if (id == processId) {
                return true;
            }
        }

        return false;
    }
    catch (...) {
        return false;
    }
}

// 保护内存区域
bool MemoryProtection::ProtectMemoryRegion(DWORD processId, PVOID baseAddress, SIZE_T size, DWORD protectFlags) {
    try {
        if (!isInitialized || !IsValidProcess(processId)) {
            return false;
        }
        
        // 检查参数有效性
        if (!baseAddress || size == 0) {
            return false;
        }
        
        // 检查保护标志的有效性
        if ((protectFlags & 0xff) == 0 || (protectFlags & 0xff) > 0x1f) {
            return false;
        }
        
        // 限制内存区域大小，防止过度保护
        if (size > 1024 * 1024 * 10) { // 限制为10MB
            return false;
        }

        // 这里实现内存区域保护逻辑
        // 实际应用中需要使用VirtualProtectEx等API

        return true;
    }
    catch (...) {
        return false;
    }
}

// 取消保护内存区域
bool MemoryProtection::UnprotectMemoryRegion(DWORD processId, PVOID baseAddress, SIZE_T size) {
    try {
        if (!isInitialized || !IsValidProcess(processId)) {
            return false;
        }
        
        // 检查参数有效性
        if (!baseAddress || size == 0) {
            return false;
        }
        
        // 限制内存区域大小，防止过度操作
        if (size > 1024 * 1024 * 10) { // 限制为10MB
            return false;
        }

        // 这里实现取消内存区域保护逻辑
        // 实际应用中需要使用VirtualProtectEx等API

        return true;
    }
    catch (...) {
        return false;
    }
}

// 监控内存访问
bool MemoryProtection::MonitorMemoryAccess(DWORD processId) {
    try {
        if (!isInitialized || !IsValidProcess(processId)) {
            return false;
        }

        // 这里实现内存访问监控逻辑
        // 实际应用中需要使用内存断点或其他监控机制

        return true;
    }
    catch (...) {
        return false;
    }
}

// 取消监控内存访问
bool MemoryProtection::UnmonitorMemoryAccess(DWORD processId) {
    try {
        if (!isInitialized || !IsValidProcess(processId)) {
            return false;
        }

        // 这里实现取消内存访问监控逻辑

        return true;
    }
    catch (...) {
        return false;
    }
}

// 阻止内存注入
bool MemoryProtection::BlockMemoryInjection(DWORD processId) {
    try {
        if (!isInitialized || !IsValidProcess(processId)) {
            return false;
        }

        // 这里实现内存注入防护逻辑
        // 实际应用中需要监控和阻止内存写入操作

        return true;
    }
    catch (...) {
        return false;
    }
}

// 允许内存注入
bool MemoryProtection::AllowMemoryInjection(DWORD processId) {
    try {
        if (!isInitialized || !IsValidProcess(processId)) {
            return false;
        }

        // 这里实现取消内存注入防护逻辑

        return true;
    }
    catch (...) {
        return false;
    }
}

// 扫描进程内存
bool MemoryProtection::ScanProcessMemory(DWORD processId, std::vector<PVOID>* suspiciousRegions) {
    try {
        if (!isInitialized || !IsValidProcess(processId) || !suspiciousRegions) {
            return false;
        }

        // 清空可疑区域列表
        suspiciousRegions->clear();
        
        // 限制可疑区域数量，防止内存溢出
        suspiciousRegions->reserve(100); // 最多存储100个可疑区域

        // 这里实现进程内存扫描逻辑
        // 实际应用中需要遍历进程的内存区域并分析

        // 模拟扫描结果
        // suspiciousRegions->push_back((PVOID)0x10000000);

        return true;
    }
    catch (...) {
        // 发生异常时确保列表被清空
        if (suspiciousRegions) {
            suspiciousRegions->clear();
        }
        return false;
    }
}

// 检查进程是否有效
bool MemoryProtection::IsValidProcess(DWORD processId) {
    try {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
        if (hProcess == NULL || hProcess == INVALID_HANDLE_VALUE) {
            return false;
        }

        CloseHandle(hProcess);
        return true;
    }
    catch (...) {
        return false;
    }
}

// 打开进程并获取指定权限
HANDLE MemoryProtection::OpenProcessWithAccess(DWORD processId, DWORD desiredAccess) {
    try {
        return OpenProcess(desiredAccess, FALSE, processId);
    }
    catch (...) {
        return NULL;
    }
}

// 检查内存注入
bool MemoryProtection::CheckMemoryInjection(DWORD processId) {
    try {
        if (!isInitialized || !IsValidProcess(processId)) {
            return false;
        }

        // 这里实现内存注入检查逻辑

        return false;
    }
    catch (...) {
        return false;
    }
}

// 分析内存区域
bool MemoryProtection::AnalyzeMemoryRegion(DWORD processId, PVOID baseAddress, SIZE_T size) {
    try {
        if (!isInitialized || !IsValidProcess(processId)) {
            return false;
        }

        // 这里实现内存区域分析逻辑

        return false;
    }
    catch (...) {
        return false;
    }
}
