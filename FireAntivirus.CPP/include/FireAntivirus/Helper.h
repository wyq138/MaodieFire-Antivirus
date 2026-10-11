// FireAntivirus.CPP - 杂项辅助工具
// 移植自 FireAntivirus.Common.Helper / 加密 / 文件操作辅助
#pragma once

#include "FireAntivirus/Types.h"
#include "FireAntivirus/LogHelper.h"

#include <string>
#include <vector>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>
#include <filesystem>

#if defined(_WIN32)
    #include <windows.h>
    #include <shlwapi.h>
    #include <psapi.h>
    #pragma comment(lib, "shlwapi.lib")
    #pragma comment(lib, "psapi.lib")
#endif

namespace FireAntivirus {
namespace Helper {

// ==================== 字符串工具 ====================

inline std::string ToLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c){ return std::tolower(c); });
    return s;
}

inline std::string ToUpper(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c){ return std::toupper(c); });
    return s;
}

inline std::string Trim(std::string s) {
    auto not_space = [](unsigned char c){ return !std::isspace(c); };
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), not_space));
    s.erase(std::find_if(s.rbegin(), s.rend(), not_space).base(), s.end());
    return s;
}

inline bool StartsWithCI(const std::string& s, const std::string& prefix) {
    if (s.size() < prefix.size()) return false;
    for (size_t i = 0; i < prefix.size(); ++i) {
        if (std::tolower((unsigned char)s[i]) != std::tolower((unsigned char)prefix[i]))
            return false;
    }
    return true;
}

inline bool EndsWithCI(const std::string& s, const std::string& suffix) {
    if (s.size() < suffix.size()) return false;
    size_t start = s.size() - suffix.size();
    for (size_t i = 0; i < suffix.size(); ++i) {
        if (std::tolower((unsigned char)s[start + i]) != std::tolower((unsigned char)suffix[i]))
            return false;
    }
    return true;
}

inline bool ContainsCI(const std::string& haystack, const std::string& needle) {
    auto it = std::search(
        haystack.begin(), haystack.end(),
        needle.begin(), needle.end(),
        [](unsigned char a, unsigned char b){
            return std::tolower(a) == std::tolower(b);
        });
    return it != haystack.end();
}

// ==================== 文件操作 ====================

inline std::vector<uint8_t> ReadFileAllBytes(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    f.unsetf(std::ios::skipws);
    std::streampos size;
    f.seekg(0, std::ios::end);
    size = f.tellg();
    f.seekg(0, std::ios::beg);
    std::vector<uint8_t> buffer(static_cast<size_t>(size));
    if (size > 0) f.read(reinterpret_cast<char*>(buffer.data()), size);
    return buffer;
}

inline std::string ReadFileAllText(const std::string& path) {
    std::ifstream f(path);
    if (!f) return {};
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

inline bool FileExists(const std::string& path) {
    std::error_code ec;
    return std::filesystem::exists(path, ec);
}

inline bool DirectoryExists(const std::string& path) {
    std::error_code ec;
    return std::filesystem::is_directory(path, ec);
}

inline bool DirectoryCreate(const std::string& path) {
    std::error_code ec;
    return std::filesystem::create_directories(path, ec);
}

inline std::filesystem::file_status GetFileStatus(const std::string& path) {
    std::error_code ec;
    return std::filesystem::status(path, ec);
}

inline uintmax_t GetFileSize(const std::string& path) {
    std::error_code ec;
    auto s = std::filesystem::file_size(path, ec);
    if (ec) return 0;
    return s;
}

/// <summary>递归枚举目录下文件,过滤大小</summary>
inline std::vector<std::string> EnumerateFiles(
    const std::string& dir,
    uintmax_t max_size_bytes = (uintmax_t)-1)
{
    std::vector<std::string> results;
    std::error_code ec;
    std::filesystem::recursive_directory_iterator it(dir, ec);
    if (ec) return results;
    for (auto& entry : it) {
        if (entry.is_regular_file(ec)) {
            auto size = entry.file_size(ec);
            if (!ec && size <= max_size_bytes) {
                results.push_back(entry.path().string());
            }
        }
    }
    return results;
}

/// <summary>根据路径取出扩展名,不带点</summary>
inline std::string GetExtensionNoDot(const std::string& path) {
    auto pos = path.find_last_of('.');
    if (pos == std::string::npos) return {};
    std::string ext = path.substr(pos + 1);
    return ToLower(ext);
}

/// <summary>取出文件名(含扩展名)</summary>
inline std::string GetFileName(const std::string& path) {
    auto sep = path.find_last_of("\\/");
    if (sep == std::string::npos) return path;
    return path.substr(sep + 1);
}

/// <summary>取出文件名(不含扩展名)</summary>
inline std::string GetFileNameNoExt(const std::string& path) {
    std::string name = GetFileName(path);
    auto dot = name.find_last_of('.');
    if (dot == std::string::npos) return name;
    return name.substr(0, dot);
}

/// <summary>取出目录名</summary>
inline std::string GetDirectory(const std::string& path) {
    auto sep = path.find_last_of("\\/");
    if (sep == std::string::npos) return {};
    return path.substr(0, sep);
}

inline bool PathIsSystemFile(const std::string& path) {
    std::string lower = ToLower(path);
    return lower.find("\\windows\\system32\\") != std::string::npos ||
           lower.find("\\windows\\syswow64\\") != std::string::npos;
}

// ==================== 十六进制转换 ====================

inline std::string BytesToHex(const std::vector<uint8_t>& bytes) {
    std::stringstream ss;
    for (auto b : bytes) {
        ss << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<int>(b);
    }
    return ToLower(ss.str());
}

inline std::vector<uint8_t> HexToBytes(const std::string& hex) {
    if (hex.size() % 2 != 0) return {};
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        unsigned int byte;
        std::stringstream ss(hex.substr(i, 2));
        ss >> std::hex >> byte;
        out.push_back(static_cast<uint8_t>(byte));
    }
    return out;
}

// ==================== SHA256 (纯C++实现,Windows下也可选用 BCrypt/CryptoAPI) ====================
// 注: 此处提供一个简化 SHA256 实现的声明, 具体实现见 Hash.cpp

/// <summary>计算文件 SHA256 哈希,返回小写十六进制字符串</summary>
std::string ComputeFileSha256(const std::string& path);

/// <summary>计算内存缓冲区 SHA256</summary>
std::string ComputeBytesSha256(const uint8_t* data, size_t len);

} // namespace Helper
} // namespace FireAntivirus
