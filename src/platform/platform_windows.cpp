// Windows backend for the asset collectors.
//
// Stage 0 implements collect_host() for real and leaves the other four as
// declared stubs. The stubs are honest: they report implemented=false so the
// emitted inventory says "not collected" rather than claiming the host has no
// listening sockets.
//
// Planned for stage 1 (see PLAN.md):
//   interfaces -> GetAdaptersAddresses
//   sockets    -> GetExtendedTcpTable / GetExtendedUdpTable (TCP_TABLE_OWNER_PID_LISTENER)
//   processes  -> CreateToolhelp32Snapshot + QueryFullProcessImageNameW
//   packages   -> HKLM/HKCU ...\Uninstall\* (both the 64- and 32-bit views)

#include "ns/platform.hpp"

#include "ns/log.hpp"

#include <windows.h>

#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <string>

namespace ns::platform {

namespace {

std::string utf8_from_wide(const wchar_t* w) {
    if (!w) return {};
    const int need = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (need <= 0) return {};
    std::string out(static_cast<size_t>(need), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, out.data(), need, nullptr, nullptr);
    if (!out.empty() && out.back() == '\0') out.pop_back();  // need includes the NUL
    return out;
}

// Reused verbatim by the stage-1 installed-software collector, which walks the
// Uninstall subkeys and reads DisplayName / DisplayVersion / Publisher out of
// each one. Written here first because the OS version lives in the registry too.
bool reg_read_string(HKEY root, const wchar_t* subkey, const wchar_t* value,
                     std::string& out) {
    DWORD bytes = 0;
    LSTATUS st = RegGetValueW(root, subkey, value, RRF_RT_REG_SZ, nullptr, nullptr, &bytes);
    if (st != ERROR_SUCCESS || bytes == 0) return false;

    std::wstring buf(bytes / sizeof(wchar_t) + 1, L'\0');
    DWORD cap = static_cast<DWORD>(buf.size() * sizeof(wchar_t));
    st = RegGetValueW(root, subkey, value, RRF_RT_REG_SZ, nullptr, buf.data(), &cap);
    if (st != ERROR_SUCCESS) return false;

    buf.resize(wcsnlen(buf.data(), buf.size()));
    out = utf8_from_wide(buf.c_str());
    return true;
}

const wchar_t* kCurrentVersionKey =
    L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";

std::string native_arch() {
    SYSTEM_INFO si{};
    // GetNativeSystemInfo, not GetSystemInfo: under WOW64 the latter reports the
    // emulated 32-bit architecture, which would make every CVE match in stage 4
    // wrong about the platform it is matching against.
    GetNativeSystemInfo(&si);
    switch (si.wProcessorArchitecture) {
    case PROCESSOR_ARCHITECTURE_AMD64: return "x86_64";
    case PROCESSOR_ARCHITECTURE_ARM64: return "arm64";
    case PROCESSOR_ARCHITECTURE_ARM:   return "arm";
    case PROCESSOR_ARCHITECTURE_INTEL: return "x86";
    default:                           return "";
    }
}

} // namespace

const char* name() { return "windows"; }

Status collect_host(HostInfo& out) {
    Status st;

    wchar_t host[256];
    DWORD len = static_cast<DWORD>(std::size(host));
    if (GetComputerNameExW(ComputerNameDnsHostname, host, &len)) {
        out.hostname = utf8_from_wide(host);
    } else {
        st.warn("GetComputerNameExW failed, error " +
                std::to_string(GetLastError()));
    }

    // The registry is the pragmatic source here. GetVersionEx is deprecated and
    // shims the answer unless the binary carries a compatibility manifest;
    // RtlGetVersion is accurate but is a ntdll internal. The registry values are
    // what every inventory tool on Windows actually reads.
    if (!reg_read_string(HKEY_LOCAL_MACHINE, kCurrentVersionKey, L"ProductName",
                         out.os_name)) {
        st.warn("could not read ProductName from the registry");
    }
    if (!reg_read_string(HKEY_LOCAL_MACHINE, kCurrentVersionKey, L"DisplayVersion",
                         out.os_version)) {
        // Pre-20H2 installs use ReleaseId instead.
        reg_read_string(HKEY_LOCAL_MACHINE, kCurrentVersionKey, L"ReleaseId",
                        out.os_version);
    }

    std::string build;
    if (reg_read_string(HKEY_LOCAL_MACHINE, kCurrentVersionKey, L"CurrentBuildNumber",
                        build)) {
        out.kernel = "10.0." + build;

        // ProductName still reads "Windows 10 ..." on every Windows 11 install --
        // Microsoft never updated the value, and the build number is the only
        // reliable discriminator (11 starts at 22000). Left uncorrected this
        // would hand stage 4 the wrong OS CPE and mis-match every OS-level CVE,
        // so the correction happens at the collector, not downstream.
        const long build_no = std::strtol(build.c_str(), nullptr, 10);
        if (build_no >= 22000 && out.os_name.rfind("Windows 10", 0) == 0) {
            out.os_name.replace(0, std::strlen("Windows 10"), "Windows 11");
        }
    } else {
        st.warn("could not read CurrentBuildNumber from the registry");
    }

    out.arch = native_arch();
    if (out.arch.empty()) st.warn("unrecognised processor architecture");

    return st;
}

Status collect_interfaces(std::vector<NetInterface>&) {
    Status st;
    st.implemented = false;  // stage 1: GetAdaptersAddresses
    return st;
}

Status collect_listening_sockets(std::vector<ListeningSocket>&) {
    Status st;
    st.implemented = false;  // stage 1: GetExtendedTcpTable / GetExtendedUdpTable
    return st;
}

Status collect_processes(std::vector<Process>&) {
    Status st;
    st.implemented = false;  // stage 1: CreateToolhelp32Snapshot
    return st;
}

Status collect_packages(std::vector<Package>&) {
    Status st;
    st.implemented = false;  // stage 1: registry Uninstall keys, both views
    return st;
}

} // namespace ns::platform
