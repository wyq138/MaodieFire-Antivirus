// InterprocessCommunication.h

#pragma once

#include "pch.h"

class InterprocessCommunication {
private:
    bool isInitialized;
    bool isRunning;
    
    // 管道句柄
    HANDLE hPipe;
    
    // 监听线程
    std::thread listenThread;
    std::atomic<bool> isListening;
    
    // 回调函数
    std::function<void(const std::wstring&)> messageCallback;
    
    // 监听线程函数
    void ListenThread();
    
    // 处理客户端连接
    void HandleClient(HANDLE hClient);
    
    // 读取消息
    std::wstring ReadMessage(HANDLE hClient);
    
    // 发送消息
    bool SendMessage(HANDLE hClient, const std::wstring& message);
    
public:
    InterprocessCommunication();
    ~InterprocessCommunication();
    
    // 初始化
    bool Initialize();
    
    // 清理
    void Cleanup();
    
    // 启动
    bool Start();
    
    // 停止
    void Stop();
    
    // 检查是否初始化
    bool IsInitialized() const;
    
    // 检查是否运行
    bool IsRunning() const;
    
    // 设置消息回调函数
    void SetMessageCallback(std::function<void(const std::wstring&)> callback);
    
    // 发送消息
    bool SendMessage(const std::wstring& message);
};