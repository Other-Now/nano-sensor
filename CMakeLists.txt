cmake_minimum_required(VERSION 3.20)

project(nano_sensor
    VERSION 0.1.0
    DESCRIPTION "Cross-platform security sensor: asset inventory, CVE matching, spooled mTLS telemetry"
    LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Single-config generators default to an unoptimised, symbol-less build, which
# makes every "how expensive is this collector?" measurement meaningless.
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Build type" FORCE)
endif()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# ---------------------------------------------------------------------------
# ns_core -- everything except main(), so tests can link it directly.
# ---------------------------------------------------------------------------
set(NS_SOURCES
    src/json.cpp
    src/log.cpp
    src/inventory.cpp
    src/vercmp.cpp
    src/cve.cpp
    src/spool.cpp
)

# Exactly one platform backend is compiled. The other is not #ifdef'd out from
# inside -- it is simply not in the build. Keeping the OS-specific code in
# whole files rather than in #ifdef blocks is the point of the platform layer.
if(WIN32)
    list(APPEND NS_SOURCES src/platform/platform_windows.cpp src/service_windows.cpp)
elseif(UNIX AND NOT APPLE)
    list(APPEND NS_SOURCES src/platform/platform_linux.cpp src/service_linux.cpp)
else()
    message(FATAL_ERROR
        "nano-sensor targets Windows and Linux only. macOS would need a third "
        "backend (sysctl KERN_PROC / libproc) that is deliberately out of scope.")
endif()

# The TLS transport, chosen the same way: one backend per platform, whole files.
#
# Windows uses WinHTTP rather than a bundled OpenSSL because it is already
# present on every host and inherits the machine's proxy configuration (PAC,
# WPAD, authenticated CONNECT) for free -- which is most of the proxy-traversal
# requirement, unwritten.
set(NS_TLS_BACKEND "none")
if(WIN32)
    list(APPEND NS_SOURCES src/transport.cpp src/transport_winhttp.cpp)
    set(NS_TLS_BACKEND "winhttp")
else()
    find_package(OpenSSL)
    if(OpenSSL_FOUND)
        list(APPEND NS_SOURCES src/transport.cpp src/transport_openssl.cpp)
        set(NS_TLS_BACKEND "openssl")
    else()
        # Degrades rather than failing the build: inventory and CVE matching are
        # still useful without a transport, and the stub reports its own absence
        # instead of silently dropping telemetry.
        list(APPEND NS_SOURCES src/transport.cpp src/transport_none.cpp)
        message(WARNING "OpenSSL not found -- building without a TLS transport")
    endif()
endif()

add_library(ns_core STATIC ${NS_SOURCES})
target_include_directories(ns_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

if(WIN32)
    target_compile_definitions(ns_core PUBLIC
        WIN32_LEAN_AND_MEAN
        NOMINMAX
        UNICODE
        _UNICODE)
    # Advapi32: registry (OS version, installed-software enumeration).
    # Iphlpapi: GetAdaptersAddresses / GetExtendedTcpTable.
    # Ws2_32:   address formatting for socket inventory.
    # Winhttp:  the HTTPS/mTLS transport.
    # Crypt32:  PKCS#12 client-certificate loading.
    # Bcrypt:   SHA-256 for the server-certificate pin.
    target_link_libraries(ns_core PUBLIC Advapi32 Iphlpapi Ws2_32 Winhttp Crypt32 Bcrypt)
elseif(NS_TLS_BACKEND STREQUAL "openssl")
    target_link_libraries(ns_core PUBLIC OpenSSL::SSL OpenSSL::Crypto)
endif()

if(MSVC)
    target_compile_options(ns_core PRIVATE /W4 /permissive-)
else()
    target_compile_options(ns_core PRIVATE -Wall -Wextra -Wpedantic)
endif()

# ---------------------------------------------------------------------------
# The agent binary.
# ---------------------------------------------------------------------------
add_executable(nano-sensor src/main.cpp)
target_link_libraries(nano-sensor PRIVATE ns_core)

if(MSVC)
    target_compile_options(nano-sensor PRIVATE /W4 /permissive-)
else()
    target_compile_options(nano-sensor PRIVATE -Wall -Wextra -Wpedantic)
endif()

# ---------------------------------------------------------------------------
# Tests. No external framework -- see tests/test_util.hpp for why.
# ---------------------------------------------------------------------------
enable_testing()

add_executable(ns_tests
    tests/main.cpp
    tests/test_json.cpp
    tests/test_vercmp.cpp
    tests/test_cve.cpp
    tests/test_spool.cpp
    tests/test_transport.cpp
)
target_link_libraries(ns_tests PRIVATE ns_core)
target_include_directories(ns_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)

if(MSVC)
    target_compile_options(ns_tests PRIVATE /W4 /permissive-)
else()
    target_compile_options(ns_tests PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(NAME unit COMMAND ns_tests)

message(STATUS "nano-sensor ${PROJECT_VERSION} -- platform: ${CMAKE_SYSTEM_NAME}, "
               "TLS backend: ${NS_TLS_BACKEND}, build type: ${CMAKE_BUILD_TYPE}")
