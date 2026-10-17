#include "ns/crashdump.hpp"

#include <windows.h>
// dbghelp.h must follow windows.h.
#include <dbghelp.h>

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <string>

namespace ns::crashdump {

namespace {

// Everything the crash path touches is preallocated. By the time the filter
// runs the heap may be the thing that is corrupt, so the dump path is built in
// a fixed buffer and nothing on that path allocates.
wchar_t g_dir[MAX_PATH] = {};
std::atomic<bool> g_installed{false};
std::atomic<std::uint32_t> g_written{0};

// Only one thread gets to write the crash dump. A second thread faulting while
// the first is mid-write would otherwise interleave two writers on one file.
std::atomic<bool> g_crashing{false};

// A custom code so the dump's exception record says plainly where it came
// from: 0xE0000001 is "terminate / purecall / invalid parameter", raised by
// this file, not by the fault itself. See raise_and_dump().
constexpr DWORD kTerminateCode = 0xE0000001;

// What goes into the dump. Indirectly referenced memory is the important one:
// it captures the heap blocks that stack values point at, which is what lets
// a debugger show the contents of a freed object -- and the 0xDD fill pattern
// that proves it was freed. Full memory would be ~100x larger.
constexpr MINIDUMP_TYPE kDumpType = static_cast<MINIDUMP_TYPE>(
    MiniDumpWithDataSegs | MiniDumpWithHandleData | MiniDumpWithThreadInfo |
    MiniDumpWithUnloadedModules | MiniDumpWithIndirectlyReferencedMemory |
    MiniDumpWithProcessThreadData | MiniDumpWithFullMemoryInfo);

bool write_dump(EXCEPTION_POINTERS* ep, const wchar_t* reason, wchar_t* path,
                size_t path_len, DWORD* error) {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    const unsigned long long unix_ms =
        ((static_cast<unsigned long long>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime) /
            10000ULL -
        11644473600000ULL;

    swprintf_s(path, path_len, L"%s\\nano-sensor-%lu-%llu-%s.dmp", g_dir,
               GetCurrentProcessId(), unix_ms, reason);

    HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        if (error) *error = GetLastError();
        return false;
    }

    MINIDUMP_EXCEPTION_INFORMATION mei{};
    mei.ThreadId = GetCurrentThreadId();
    mei.ExceptionPointers = ep;
    mei.ClientPointers = FALSE;

    const BOOL ok = MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), file,
                                      kDumpType, ep ? &mei : nullptr, nullptr, nullptr);
    if (!ok && error) *error = GetLastError();
    CloseHandle(file);
    if (ok) g_written.fetch_add(1);
    return ok != FALSE;
}

void announce(const wchar_t* what, const wchar_t* path, bool ok) {
    // stderr, not the structured logger: the logger allocates and takes a lock,
    // and either can be what just broke.
    fwprintf(stderr, L"{\"level\":\"error\",\"msg\":\"%s\",\"dump\":\"%s\",\"written\":%s}\n",
             what, ok ? path : L"", ok ? L"true" : L"false");
    fflush(stderr);
}

LONG WINAPI unhandled_filter(EXCEPTION_POINTERS* ep) {
    if (g_crashing.exchange(true)) {
        // Another thread is already writing the crash dump; let it finish.
        Sleep(INFINITE);
    }
    wchar_t path[MAX_PATH * 2];
    const bool ok = write_dump(ep, L"crash", path, MAX_PATH * 2, nullptr);
    announce(L"unhandled exception; process terminating", path, ok);
    // The dump is the whole point; let the default handling (WER, then exit)
    // proceed so the SCM sees a failure and applies the restart policy.
    return EXCEPTION_CONTINUE_SEARCH;
}

// Raises a real SEH exception from inside the handler and writes the dump from
// its __except filter. That gives the dump an exception record and a context
// record, so `.ecxr` in WinDbg lands on this thread's stack. A plain
// MiniDumpWriteDump(nullptr) from here would produce a dump with no exception
// at all, and the reader would have to hunt for the thread that died.
//
// No C++ objects in this function: __try cannot share a frame with unwinding.
int dump_filter(EXCEPTION_POINTERS* ep, const wchar_t* reason) {
    wchar_t path[MAX_PATH * 2];
    const bool ok = write_dump(ep, reason, path, MAX_PATH * 2, nullptr);
    announce(L"fatal runtime error; process terminating", path, ok);
    return EXCEPTION_EXECUTE_HANDLER;
}

[[noreturn]] void raise_and_dump(const wchar_t* reason) {
    if (g_crashing.exchange(true)) Sleep(INFINITE);
    __try {
        RaiseException(kTerminateCode, EXCEPTION_NONCONTINUABLE, 0, nullptr);
    } __except (dump_filter(GetExceptionInformation(), reason)) {
    }
    // Same exit as an unhandled crash as far as the SCM is concerned.
    TerminateProcess(GetCurrentProcess(), kTerminateCode);
    for (;;) {}
}

void log_current_exception() {
    // Best effort. MSVC calls terminate() for an exception that has no handler
    // BEFORE unwinding, so the exception is still current here and the
    // throwing frame is still on this thread's stack -- in the dump too.
    try {
        if (auto e = std::current_exception()) std::rethrow_exception(e);
    } catch (const std::exception& ex) {
        std::fprintf(stderr,
                     "{\"level\":\"error\",\"msg\":\"uncaught C++ exception\",\"what\":\"%s\"}\n",
                     ex.what());
    } catch (...) {
        std::fprintf(stderr, "{\"level\":\"error\",\"msg\":\"uncaught non-std exception\"}\n");
    }
    std::fflush(stderr);
}

void terminate_handler() {
    log_current_exception();
    raise_and_dump(L"terminate");
}

void purecall_handler() { raise_and_dump(L"purecall"); }

void invalid_parameter_handler(const wchar_t*, const wchar_t*, const wchar_t*, unsigned,
                               uintptr_t) {
    raise_and_dump(L"invalid-parameter");
}

} // namespace

bool install(const std::string& dir) {
    const int n = MultiByteToWideChar(CP_UTF8, 0, dir.c_str(), -1, g_dir, MAX_PATH);
    if (n <= 0) return false;
    CreateDirectoryW(g_dir, nullptr);  // fine if it already exists

    // Preload dbghelp now. Loading a DLL from inside a crash handler takes the
    // loader lock, which the faulting thread may already hold.
    LoadLibraryW(L"dbghelp.dll");

    SetUnhandledExceptionFilter(unhandled_filter);
    _set_purecall_handler(purecall_handler);
    _set_invalid_parameter_handler(invalid_parameter_handler);
    on_thread_start();
    g_installed.store(true);
    return true;
}

void on_thread_start() { std::set_terminate(terminate_handler); }

bool write_now(const std::string& reason, std::string& path_out, std::string& error) {
    if (!g_installed.load()) {
        error = "crash dumps are not enabled (no --state-dir)";
        return false;
    }
    std::wstring wreason(reason.begin(), reason.end());
    wchar_t path[MAX_PATH * 2];
    DWORD err = 0;
    if (!write_dump(nullptr, wreason.c_str(), path, MAX_PATH * 2, &err)) {
        error = "MiniDumpWriteDump failed, error " + std::to_string(err);
        return false;
    }
    char narrow[MAX_PATH * 4];
    WideCharToMultiByte(CP_UTF8, 0, path, -1, narrow, sizeof(narrow), nullptr, nullptr);
    path_out = narrow;
    return true;
}

std::uint32_t dumps_written() { return g_written.load(); }

} // namespace ns::crashdump
