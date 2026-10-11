// FireAntivirus.CPP - HTTP 客户端实现 (WinHTTP)
#include "FireAntivirus/Network/HttpClient.h"
#include "FireAntivirus/Helper.h"
#include <algorithm>

#if defined(_WIN32)
#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")
#endif

namespace FireAntivirus {
namespace Network {

HttpClient::HttpClient() = default;
HttpClient::~HttpClient() = default;

#if defined(_WIN32)

static std::pair<std::string, std::string> parse_url(const std::string& url) {
    // 拆分 host + path
    std::string host, path = "/";
    size_t scheme = url.find("://");
    if (scheme == std::string::npos) return { url, "/" };
    size_t rest = scheme + 3;
    size_t slash = url.find('/', rest);
    if (slash == std::string::npos) { host = url.substr(rest); path = "/"; }
    else { host = url.substr(rest, slash - rest); path = url.substr(slash); }
    // 拆分 host:port
    size_t colon = host.find(':');
    if (colon != std::string::npos) host = host.substr(0, colon);
    return { host, path };
}

HttpResponse HttpClient::Get(const std::string& url) {
    HttpResponse resp;
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG proxy{};
    WinHttpGetIEProxyConfigForCurrentUser(&proxy);

    HINTERNET session = WinHttpOpen(L"FireAntivirusCPP/1.0",
                                    WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) { resp.error = "WinHttpOpen failed"; return resp; }

    auto [host, path] = parse_url(url);
    std::wstring whost(host.begin(), host.end());
    std::wstring wpath(path.begin(), path.end());
    std::wstring wscheme = (url.find("https") == 0) ? L"https" : L"http";

    HINTERNET connect = WinHttpConnect(session, whost.c_str(),
                                       wscheme == L"https" ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT,
                                       0);
    if (!connect) { resp.error = "WinHttpConnect failed"; WinHttpCloseHandle(session); return resp; }

    DWORD flags = (wscheme == L"https") ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET req = WinHttpOpenRequest(connect, L"GET", wpath.c_str(), nullptr,
                                       WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!req) { resp.error = "WinHttpOpenRequest failed"; WinHttpCloseHandle(connect); WinHttpCloseHandle(session); return resp; }

    for (auto& [k, v] : headers_) {
        std::wstring h = std::wstring(k.begin(), k.end()) + L": " + std::wstring(v.begin(), v.end());
        WinHttpAddRequestHeaders(req, h.c_str(), (DWORD)h.size(), WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
    }

    if (!WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(req, nullptr)) {
        resp.error = "WinHttp send/receive failed";
        WinHttpCloseHandle(req); WinHttpCloseHandle(connect); WinHttpCloseHandle(session);
        return resp;
    }

    DWORD status = 0, sz = sizeof(status);
    WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &status, &sz, WINHTTP_NO_HEADER_INDEX);
    resp.status_code = (int)status;

    // 读 body
    for (;;) {
        DWORD avail = 0;
        if (!WinHttpQueryDataAvailable(req, &avail)) break;
        if (avail == 0) break;
        resp.body.resize(resp.body.size() + avail);
        DWORD read = 0;
        WinHttpReadData(req, (LPVOID)(resp.body.data() + resp.body.size() - avail), avail, &read);
        if (read < avail) resp.body.resize(resp.body.size() - (avail - read));
    }

    WinHttpCloseHandle(req); WinHttpCloseHandle(connect); WinHttpCloseHandle(session);
    return resp;
}

HttpResponse HttpClient::Post(const std::string& url, const std::string& body, const std::string& content_type) {
    HttpResponse resp;
    HINTERNET session = WinHttpOpen(L"FireAntivirusCPP/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) { resp.error = "WinHttpOpen failed"; return resp; }

    auto [host, path] = parse_url(url);
    std::wstring whost(host.begin(), host.end());
    std::wstring wpath(path.begin(), path.end());
    std::wstring wscheme = (url.find("https") == 0) ? L"https" : L"http";

    HINTERNET connect = WinHttpConnect(session, whost.c_str(),
                                       wscheme == L"https" ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT, 0);
    if (!connect) { resp.error = "WinHttpConnect failed"; WinHttpCloseHandle(session); return resp; }

    DWORD flags = (wscheme == L"https") ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET req = WinHttpOpenRequest(connect, L"POST", wpath.c_str(), nullptr,
                                       WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!req) { resp.error = "WinHttpOpenRequest failed"; WinHttpCloseHandle(connect); WinHttpCloseHandle(session); return resp; }

    std::wstring ct = std::wstring(content_type.begin(), content_type.end());
    WinHttpAddRequestHeaders(req, (L"Content-Type: " + ct).c_str(), (DWORD)(ct.size() + 14), WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);

    for (auto& [k, v] : headers_) {
        std::wstring h = std::wstring(k.begin(), k.end()) + L": " + std::wstring(v.begin(), v.end());
        WinHttpAddRequestHeaders(req, h.c_str(), (DWORD)h.size(), WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
    }

    BOOL ok = WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                  (LPVOID)body.c_str(), (DWORD)body.size(), (DWORD)body.size(), 0);
    if (!ok || !WinHttpReceiveResponse(req, nullptr)) {
        resp.error = "WinHttp send/receive failed";
        WinHttpCloseHandle(req); WinHttpCloseHandle(connect); WinHttpCloseHandle(session);
        return resp;
    }

    DWORD status = 0, sz = sizeof(status);
    WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &status, &sz, WINHTTP_NO_HEADER_INDEX);
    resp.status_code = (int)status;

    for (;;) {
        DWORD avail = 0;
        if (!WinHttpQueryDataAvailable(req, &avail)) break;
        if (avail == 0) break;
        resp.body.resize(resp.body.size() + avail);
        DWORD read = 0;
        WinHttpReadData(req, (LPVOID)(resp.body.data() + resp.body.size() - avail), avail, &read);
        if (read < avail) resp.body.resize(resp.body.size() - (avail - read));
    }

    WinHttpCloseHandle(req); WinHttpCloseHandle(connect); WinHttpCloseHandle(session);
    return resp;
}

HttpResponse HttpClient::PostMultipart(const std::string& url, const std::string& field_name, const std::string& field_value) {
    std::string boundary = "----FireAntivirusBoundaryC" + std::to_string(GetTickCount());
    std::string body =
        "--" + boundary + "\r\n"
        "Content-Disposition: form-data; name=\"" + field_name + "\"\r\n\r\n" + field_value + "\r\n"
        "--" + boundary + "--\r\n";
    return Post(url, body, "multipart/form-data; boundary=" + boundary);
}

#else

HttpResponse HttpClient::Get(const std::string&) {
    HttpResponse r; r.error = "HTTP not supported on this platform"; return r;
}
HttpResponse HttpClient::Post(const std::string&, const std::string&, const std::string&) {
    HttpResponse r; r.error = "HTTP not supported on this platform"; return r;
}
HttpResponse HttpClient::PostMultipart(const std::string&, const std::string&, const std::string&) {
    HttpResponse r; r.error = "HTTP not supported on this platform"; return r;
}

#endif // _WIN32

} // namespace Network
} // namespace FireAntivirus
