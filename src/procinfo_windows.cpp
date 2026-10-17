#include "ns/procinfo.hpp"

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>

#include <vector>

namespace ns {

namespace {

std::string narrow(const std::wstring& s) {
    if (s.empty()) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string out(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, out.data(), n, nullptr, nullptr);
    out.pop_back();
    return out;
}

std::uint32_t thread_count() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    std::uint32_t n = 0;
    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    const DWORD self = GetCurrentProcessId();
    for (BOOL ok = Thread32First(snap, &te); ok; ok = Thread32Next(snap, &te)) {
        if (te.th32OwnerProcessID == self) ++n;
    }
    CloseHandle(snap);
    return n;
}

} // namespace

ProcInfo self_info() {
    ProcInfo p;
    p.pid = GetCurrentProcessId();

    HANDLE token = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        std::vector<unsigned char> buf(512);
        DWORD len = 0;
        if (GetTokenInformation(token, TokenUser, buf.data(), static_cast<DWORD>(buf.size()),
                                &len)) {
            const auto* tu = reinterpret_cast<const TOKEN_USER*>(buf.data());
            wchar_t name[256], domain[256];
            DWORD nlen = 256, dlen = 256;
            SID_NAME_USE use;
            if (LookupAccountSidW(nullptr, tu->User.Sid, name, &nlen, domain, &dlen, &use)) {
                p.user = narrow(std::wstring(domain) + L"\\" + name);
            }
        }

        TOKEN_ELEVATION el{};
        if (GetTokenInformation(token, TokenElevation, &el, sizeof(el), &len)) {
            p.elevated = el.TokenIsElevated != 0;
        }

        // Privileges that are present AND enabled. A service configured with
        // a required-privileges list keeps only those; everything else is
        // stripped from its token by the SCM before it starts.
        len = 0;
        GetTokenInformation(token, TokenPrivileges, nullptr, 0, &len);
        std::vector<unsigned char> pbuf(len);
        if (len && GetTokenInformation(token, TokenPrivileges, pbuf.data(), len, &len)) {
            const auto* tp = reinterpret_cast<const TOKEN_PRIVILEGES*>(pbuf.data());
            for (DWORD i = 0; i < tp->PrivilegeCount; ++i) {
                if (tp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) ++p.privileges_enabled;
            }
        }
        CloseHandle(token);
    }

    PROCESS_MEMORY_COUNTERS_EX pmc{};
    if (GetProcessMemoryInfo(GetCurrentProcess(),
                             reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc), sizeof(pmc))) {
        p.private_bytes = pmc.PrivateUsage;
        p.working_set = pmc.WorkingSetSize;
        p.peak_working_set = pmc.PeakWorkingSetSize;
    }

    DWORD handles = 0;
    if (GetProcessHandleCount(GetCurrentProcess(), &handles)) p.handles = handles;
    p.threads = thread_count();
    return p;
}

} // namespace ns
