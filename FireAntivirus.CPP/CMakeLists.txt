# 耄耋安全软件 C++ 版本 - 构建系统
# FireAntivirus.CPP - Windows C++ Antivirus Engine
# 全功能移植版 (53 模块)

cmake_minimum_required(VERSION 3.18)
project(FireAntivirusCPP VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(WIN32)
    add_definitions(-DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN -DNOMINMAX)
    add_compile_options(/W4 /permissive- /Zc:__cplusplus)
    add_compile_definitions(_WIN32_WINNT=0x0A00)
endif()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# ==================== 第三方 ====================
find_package(nlohmann_json CONFIG QUIET)
if(NOT nlohmann_json_FOUND) include_directories(${CMAKE_SOURCE_DIR}/third_party) endif()
find_package(OpenSSL QUIET)

# ==================== 源码 glob ====================
file(GLOB_RECURSE FA_COMMON_SOURCES
    "src/Common/*.cpp" "include/FireAntivirus/Common/*.h"
)
file(GLOB_RECURSE FA_ENGINE_SOURCES
    "src/Engine/*.cpp"                  "include/FireAntivirus/Engine/*.h"
    "src/Engine/Analyzers/*.cpp"        "include/FireAntivirus/Engine/Analyzers/*.h"
    "src/Engine/Scanners/*.cpp"         "include/FireAntivirus/Engine/Scanners/*.h"
    "src/Engine/Detectors/*.cpp"        "include/FireAntivirus/Engine/Detectors/*.h"
    "src/Engine/Protection/*.cpp"       "include/FireAntivirus/Engine/Protection/*.h"
)
file(GLOB_RECURSE FA_MODULES_SOURCES
    "src/Modules/*.cpp" "include/FireAntivirus/Modules/*.h"
)
file(GLOB_RECURSE FA_PLATFORM_SOURCES
    "src/Platform/*.cpp" "include/FireAntivirus/Platform/*.h"
)
file(GLOB_RECURSE FA_NETWORK_SOURCES
    "src/Network/*.cpp" "include/FireAntivirus/Network/*.h"
)
file(GLOB_RECURSE FA_SERVICES_SOURCES
    "src/Services/*.cpp" "include/FireAntivirus/Services/*.h"
)
# 额外的全局单文件模块
set(FA_EXTRA_SOURCES
    "src/IPC.cpp"
    "src/DataManager.cpp"
    "src/ServiceHost.cpp"
)

# ==================== 静态库 ====================
add_library(FireAntivirusCore STATIC
    ${FA_COMMON_SOURCES}
    ${FA_ENGINE_SOURCES}
    ${FA_MODULES_SOURCES}
    ${FA_PLATFORM_SOURCES}
    ${FA_NETWORK_SOURCES}
    ${FA_SERVICES_SOURCES}
    ${FA_EXTRA_SOURCES}
)

target_include_directories(FireAntivirusCore PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/third_party
)

if(WIN32)
    target_link_libraries(FireAntivirusCore PUBLIC
        ws2_32 mswsock advapi32 crypt32 winhttp shlwapi psapi
        setupapi cfgmgr32 ole32 oleaut32 iphlpapi netfw shell32
        wbemUuid.lib
    )
endif()
if(nlohmann_json_FOUND)
    target_link_libraries(FireAntivirusCore PUBLIC nlohmann_json::nlohmann_json)
endif()
if(OpenSSL_FOUND)
    target_link_libraries(FireAntivirusCore PUBLIC OpenSSL::SSL OpenSSL::Crypto)
    target_compile_definitions(FireAntivirusCore PUBLIC FA_HAS_OPENSSL=1)
endif()

# ==================== 可执行文件 ====================
option(FA_BUILD_MAIN     "Build FireAntivirus main launcher" ON)
option(FA_BUILD_SERVICE  "Build FireAntivirus Windows Service" ON)

if(FA_BUILD_MAIN)
    add_executable(FireAntivirusCLI src/UI/main.cpp)
    target_link_libraries(FireAntivirusCLI PRIVATE FireAntivirusCore)
    if(WIN32) set_target_properties(FireAntivirusCLI PROPERTIES WIN32_EXECUTABLE FALSE) endif()
endif()

# 真正的 Windows 服务: 用相同入口但链接 SERVICE_TABLE_ENTRY
if(FA_BUILD_SERVICE AND WIN32)
    # Service 需要一个单独的 main + ServiceMain 转发
    file(WRITE ${CMAKE_BINARY_DIR}/service_stub.cpp "
    #include \"FireAntivirus/ServiceHost.h\"
    #include <windows.h>
    // ServiceMain 由 SCM 调用, 这里用 FireAntivirusService 处理
    VOID WINAPI SvcMain(DWORD, LPTSTR*) {
        FireAntivirus::Service::FireAntivirusService::Instance().ServiceMain(0, nullptr);
    }
    int main() {
        SERVICE_TABLE_ENTRYW table[] = {
            {const_cast<LPWSTR>(L\"FireAntivirusService\"), SvcMain},
            {nullptr, nullptr}
        };
        StartServiceCtrlDispatcherW(table);
        return 0;
    }
    ")
    add_executable(FireAntivirusService WIN32 ${CMAKE_BINARY_DIR}/service_stub.cpp)
    target_link_libraries(FireAntivirusService PRIVATE FireAntivirusCore)
endif()

# ==================== 安装 ====================
install(TARGETS FireAntivirusCore ARCHIVE DESTINATION lib)
install(DIRECTORY include/FireAntivirus DESTINATION include)

message(STATUS "")
message(STATUS "========================================")
message(STATUS " FireAntivirus.CPP Build Config (全功能版)")
message(STATUS "========================================")
message(STATUS "  C++ Standard:     C++17")
message(STATUS "  Platform:         ${CMAKE_SYSTEM_NAME}")
message(STATUS "  nlohmann_json:    ${nlohmann_json_FOUND}")
message(STATUS "  OpenSSL:          ${OpenSSL_FOUND}")
message(STATUS "  Build CLI:        ${FA_BUILD_MAIN}")
message(STATUS "  Build Service:    ${FA_BUILD_SERVICE}")
message(STATUS "========================================")
