// ProcessProtection.cpp

#include "pch.h"
#include "ProcessProtection.h"

// 初始化静态成员
bool ProcessProtection::isInitialized = false;
ProcessProtectionPolicy ProcessProtection::currentPolicy;
std::vector<DWORD> ProcessProtection::protectedProcesses;
std::map<DWORD, HANDLE> ProcessProtection::processHandles;

// 初始化
bool ProcessProtection::Initialize() {
    try {
        // 初始化默认策略
        currentPolicy.blockUnsignedProcesses = true;
        currentPolicy.blockRemoteThreads = true;
        currentPolicy.blockDllInjection = true;
        currentPolicy.blockProcessHollowing = true;
        currentPolicy.monitorProcessCreation = true;
        currentPolicy.monitorProcessTermination = true;

        // 清空保护列表
        protectedProcesses.clear();
        processHandles.clear();

        isInitialized = true;
        return true;
    }
    catch (...) {
        return false;
    }
}

// 清理
void ProcessProtection::Shutdown() {
    try {
        // 释放所有进程句柄
        for (auto& pair : processHandles) {
            if (pair.second != NULL && pair.second != INVALID_HANDLE_VALUE) {
                CloseHandle(pair.second);
            }
        }
        processHandles.clear();

        // 清空保护列表
        protectedProcesses.clear();

        isInitialized = false;
    }
    catch (...) {
        // 忽略异常
    }
}

// 检查是否已初始化
bool ProcessProtection::IsInitialized() {
    return isInitialized;
}

// 设置策略
void ProcessProtection::SetPolicy(const ProcessProtectionPolicy& policy) {
    currentPolicy = policy;
}

// 获取策略
ProcessProtectionPolicy ProcessProtection::GetPolicy() {
    return currentPolicy;
}

// 保护进程
bool ProcessProtection::ProtectProcess(DWORD processId) {
    try {
        if (!isInitialized) {
            return false;
        }

        // 检查进程是否已在保护列表中
        for (DWORD id : protectedProcesses) {
            if (id == processId) {
                return true;  // 已经在保护列表中
            }
        }

        // 获取进程句柄
        HANDLE hProcess = GetProcessHandle(processId);
        if (hProcess == NULL || hProcess == INVALID_HANDLE_VALUE) {
            return false;
        }

        // 添加到保护列表
        protectedProcesses.push_back(processId);
        processHandles[processId] = hProcess;

        return true;
    }
    catch (...) {
        return false;
    }
}

// 取消保护进程
bool ProcessProtection::UnprotectProcess(DWORD processId) {
    try {
        if (!isInitialized) {
            return false;
        }

        // 从保护列表中移除
        for (auto it = protectedProcesses.begin(); it != protectedProcesses.end(); ++it) {
            if (*it == processId) {
                protectedProcesses.erase(it);
                break;
            }
        }

        // 释放进程句柄
        ReleaseProcessHandle(processId);

        return true;
    }
    catch (...) {
        return false;
    }
}

// 检查进程是否被保护
bool ProcessProtection::IsProcessProtected(DWORD processId) {
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

// 阻止未签名进程
bool ProcessProtection::BlockUnsignedProcess(DWORD processId) {
    try {
        if (!currentPolicy.blockUnsignedProcesses) {
            return false;
        }

        // 检查进程是否已签名
        if (!IsProcessSigned(processId)) {
            // 阻止未签名进程
            // 实际应用中需要实现具体的阻止逻辑
            return true;
        }

        return false;
    }
    catch (...) {
        return false;
    }
}

// 阻止远程线程注入
bool ProcessProtection::BlockRemoteThreadInjection(DWORD targetProcessId, DWORD sourceProcessId) {
    try {
        if (!currentPolicy.blockRemoteThreads) {
            return false;
        }

        // 检查目标进程是否被保护
        if (IsProcessProtected(targetProcessId)) {
            // 阻止远程线程注入
            // 实际应用中需要实现具体的阻止逻辑
            return true;
        }

        return false;
    }
    catch (...) {
        return false;
    }
}

// 阻止DLL注入
bool ProcessProtection::BlockDllInjection(DWORD processId, const wchar_t* dllPath) {
    try {
        if (!currentPolicy.blockDllInjection) {
            return false;
        }

        // 检查进程是否被保护
        if (IsProcessProtected(processId)) {
            // 阻止DLL注入
            // 实际应用中需要实现具体的阻止逻辑
            return true;
        }

        return false;
    }
    catch (...) {
        return false;
    }
}

// 阻止进程空洞攻击
bool ProcessProtection::BlockProcessHollowing(DWORD processId) {
    try {
        if (!currentPolicy.blockProcessHollowing) {
            return false;
        }

        // 检查进程是否被保护
        if (IsProcessProtected(processId)) {
            // 阻止进程空洞攻击
            // 实际应用中需要实现具体的阻止逻辑
            return true;
        }

        return false;
    }
    catch (...) {
        return false;
    }
}

// 检查进程是否已签名
bool ProcessProtection::IsProcessSigned(DWORD processId) {
    try {
        // 这里实现进程签名检查逻辑
        // 实际应用中需要使用Windows API检查数字签名
        
        // 模拟检查结果
        return true;
    }
    catch (...) {
        return false;
    }
}

// 获取进程句柄
HANDLE ProcessProtection::GetProcessHandle(DWORD processId) {
    try {
        HANDLE hProcess = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            FALSE,
            processId
        );

        return hProcess;
    }
    catch (...) {
        return NULL;
    }
}

// 释放进程句柄
void ProcessProtection::ReleaseProcessHandle(DWORD processId) {
    try {
        auto it = processHandles.find(processId);
        if (it != processHandles.end()) {
            if (it->second != NULL && it->second != INVALID_HANDLE_VALUE) {
                CloseHandle(it->second);
            }
            processHandles.erase(it);
        }
    }
    catch (...) {
        // 忽略异常
    }
}
