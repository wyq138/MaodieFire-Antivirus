// FireAntivirus.CPP - 日志辅助工具
// 移植自 FireAntivirus.Common.Helper / LogHelper
#pragma once

#include "FireAntivirus/Types.h"
#include <string>
#include <fstream>
#include <mutex>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <cstdio>

namespace FireAntivirus {

/// <summary>简单线程安全日志器</summary>
class LogHelper {
public:
    static LogHelper& Instance() {
        static LogHelper inst;
        return inst;
    }

    void SetLogFile(const std::string& path) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (file_.is_open()) file_.close();
        file_.open(path, std::ios::app);
    }

    void SetMinLevel(LogLevel level) { min_level_ = level; }

    void Log(LogLevel level, const std::string& tag, const std::string& message) {
        if (level < min_level_) return;
        std::lock_guard<std::mutex> lock(mutex_);
        std::string ts = now_str();
        std::string lvl = level_str(level);
        std::string line = "[" + ts + "] [" + lvl + "] [" + tag + "] " + message + "\n";
        if (file_.is_open()) {
            file_ << line;
            file_.flush();
        }
        // 同时输出到 stderr
        std::fputs(line.c_str(), stderr);
    }

    // 便捷重载,支持两个字符串(模拟 C# 的 Log(tag, msg, detail) 三参数)
    void Log(LogLevel level, const std::string& tag, const std::string& message, const std::string& detail) {
        Log(level, tag, message + " | " + detail);
    }

    static void Debug(const std::string& tag, const std::string& msg) { Instance().Log(LogLevel::Debug, tag, msg); }
    static void Info (const std::string& tag, const std::string& msg) { Instance().Log(LogLevel::Info,  tag, msg); }
    static void Warn (const std::string& tag, const std::string& msg) { Instance().Log(LogLevel::Warn,  tag, msg); }
    static void Error(const std::string& tag, const std::string& msg) { Instance().Log(LogLevel::Error, tag, msg); }
    static void Fatal(const std::string& tag, const std::string& msg) { Instance().Log(LogLevel::Fatal, tag, msg); }

private:
    LogHelper() = default;
    LogHelper(const LogHelper&) = delete;
    LogHelper& operator=(const LogHelper&) = delete;

    static const char* level_str(LogLevel l) {
        switch (l) {
            case LogLevel::Debug: return "DEBUG";
            case LogLevel::Info:  return "INFO";
            case LogLevel::Warn:  return "WARN";
            case LogLevel::Error: return "ERROR";
            case LogLevel::Fatal: return "FATAL";
        }
        return "?";
    }

    static std::string now_str() {
        auto now = std::chrono::system_clock::now();
        auto t = std::chrono::system_clock::to_time_t(now);
        std::tm tm_buf{};
#if defined(_WIN32)
        localtime_s(&tm_buf, &t);
#else
        localtime_r(&t, &tm_buf);
#endif
        char buf[64];
        std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_buf);
        return buf;
    }

    std::mutex    mutex_;
    std::ofstream file_;
    LogLevel      min_level_ = LogLevel::Info;
};

// 方便外部直接使用的宏/简写
#define FA_LOG_D(tag, msg) FireAntivirus::LogHelper::Debug(tag, msg)
#define FA_LOG_I(tag, msg) FireAntivirus::LogHelper::Info (tag, msg)
#define FA_LOG_W(tag, msg) FireAntivirus::LogHelper::Warn (tag, msg)
#define FA_LOG_E(tag, msg) FireAntivirus::LogHelper::Error(tag, msg)

} // namespace FireAntivirus
