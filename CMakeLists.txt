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

# AddressSanitizer build (MSVC /fsanitize=address, or -fsanitize=address).
# Use a separate build directory: cmake -B build-asan -DNS_ASAN=ON
# The planted use-after-free (docs/DEBUGGING.md, bug 1) runs silently in an
# ordinary Release build; under ASan it stops at the bad access with the
# allocation and free stacks attached.
option(NS_ASAN "Build with AddressSanitizer" OFF)
if(NS_ASAN)
    if(MSVC)
        add_compile_options(/fsanitize=address /Zi)
        # Incremental linking and /RTC are incompatible with ASan.
        add_link_options(/INCREMENTAL:NO)
        string(REGEX REPLACE "/RTC[^ ]*" "" CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")
    else()
        add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
        add_link_options(-fsanitize=address)
    endif()
endif()

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
    src/agent.cpp
)

# Exactly one platform backend is compiled. The other is not #ifdef'd out from
# inside -- it is simply not in the build. Keeping the OS-specific code in
# whole files rather than in #ifdef blocks is the point of the platform layer.
if(WIN32)
    list(APPEND NS_SOURCES src/platform/platform_windows.cpp src/service_windows.cpp
        # The Windows service split: named-pipe control channel, SQL Server
        # over ODBC, minidumps, process self-inspection.
        src/ipc_windows.cpp src/db_odbc.cpp src/crashdump_windows.cpp
        src/procinfo_windows.cpp)
elseif(UNIX AND NOT APPLE)
    list(APPEND NS_SOURCES src/platform/platform_linux.cpp src/service_linux.cpp
        src/windows_only_stubs.cpp)
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
    # Odbc32:   SQL Server storage.
    # Dbghelp:  MiniDumpWriteDump.
    target_link_libraries(ns_core PUBLIC Advapi32 Iphlpapi Ws2_32 Winhttp Crypt32 Bcrypt
        Odbc32 Dbghelp)
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

# The console client: a separate process that talks to the service over the
# control pipe.
if(WIN32)
    add_executable(nsctl src/nsctl.cpp)
    target_link_libraries(nsctl PRIVATE ns_core)
    target_compile_options(nsctl PRIVATE /W4 /permissive-)

    # SQL Server index benchmark (tools/db/bench_index.ps1 drives it).
    add_executable(ns_dbbench tools/dbbench.cpp)
    target_link_libraries(ns_dbbench PRIVATE ns_core)
    target_compile_options(ns_dbbench PRIVATE /W4 /permissive-)
endif()

# Every binary gets a PDB, Release included. A minidump without the PDB that
# matches it byte-for-byte is a list of addresses; with it, it is a call stack
# with source lines and locals. /Zi + /DEBUG cost nothing at runtime, and the
# PDBs are kept with each build rather than shipped to hosts.
if(MSVC)
    foreach(t ns_core nano-sensor nsctl)
        if(TARGET ${t})
            target_compile_options(${t} PRIVATE /Zi)
        endif()
    endforeach()
    foreach(t nano-sensor nsctl)
        # /DEBUG turns off /OPT:REF and /OPT:ICF unless asked for; ask, in
        # Release, so the shipped binary is the same size it would have been.
        target_link_options(${t} PRIVATE /DEBUG
            $<$<CONFIG:Release>:/OPT:REF> $<$<CONFIG:Release>:/OPT:ICF>)
    endforeach()
endif()

# ---------------------------------------------------------------------------
# Tests: GoogleTest, fetched at configure time and pinned by hash.
# ---------------------------------------------------------------------------
include(FetchContent)
FetchContent_Declare(googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.15.2.tar.gz
    URL_HASH SHA256=7b42b4d6ed48810c5362c265a17faebe90dc2373c885e5216439d37927f02926
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
# Use the same dynamic CRT as everything else; otherwise MSVC links two CRTs
# and allocations cross heaps.
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

enable_testing()

set(NS_TEST_SOURCES
    tests/main.cpp
    tests/test_json.cpp
    tests/test_vercmp.cpp
    tests/test_cve.cpp
    tests/test_spool.cpp
    tests/test_transport.cpp
)
if(WIN32)
    list(APPEND NS_TEST_SOURCES tests/test_ipc.cpp tests/test_db.cpp)
endif()

add_executable(ns_tests ${NS_TEST_SOURCES})
target_link_libraries(ns_tests PRIVATE ns_core GTest::gtest)

if(MSVC)
    target_compile_options(ns_tests PRIVATE /W4 /permissive-)
else()
    target_compile_options(ns_tests PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(NAME unit COMMAND ns_tests)

message(STATUS "nano-sensor ${PROJECT_VERSION} -- platform: ${CMAKE_SYSTEM_NAME}, "
               "TLS backend: ${NS_TLS_BACKEND}, build type: ${CMAKE_BUILD_TYPE}")
