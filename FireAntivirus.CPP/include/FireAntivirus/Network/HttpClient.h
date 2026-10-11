// FireAntivirus.CPP - 简单 HTTP 客户端 (WinHTTP 封装)
// 用于云查杀 / 特征库更新等场景
#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <map>
#include <functional>

namespace FireAntivirus {
namespace Network {

/// <summary>HTTP 请求响应</summary>
struct HttpResponse {
    int         status_code = 0;
    std::string body;
    std::map<std::string, std::string> headers;
    std::string error;
    bool        ok() const { return status_code >= 200 && status_code < 300 && error.empty(); }
};

/// <summary>HTTP 客户端 (WinHTTP 实现, 可选 libcurl)</summary>
class HttpClient {
public:
    HttpClient();
    ~HttpClient();

    void SetTimeout(int seconds) { timeout_seconds_ = seconds; }
    void SetHeader(const std::string& name, const std::string& value) { headers_[name] = value; }

    HttpResponse Get(const std::string& url);
    HttpResponse Post(const std::string& url,
                      const std::string& body,
                      const std::string& content_type = "application/x-www-form-urlencoded");

    // Multipart (MalwareBazaar 用到)
    HttpResponse PostMultipart(const std::string& url,
                               const std::string& field_name,
                               const std::string& field_value);

private:
    int timeout_seconds_ = 15;
    std::map<std::string, std::string> headers_;
};

} // namespace Network
} // namespace FireAntivirus
