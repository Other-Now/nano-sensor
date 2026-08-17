// Windows backend for the asset collectors.
//
//   host       -> GetComputerNameExW + HKLM\...\CurrentVersion
//   interfaces -> GetAdaptersAddresses
//   sockets    -> GetExtendedTcpTable / GetExtendedUdpTable (owner-PID variants)
//   processes  -> CreateToolhelp32Snapshot + QueryFullProcessImageNameW
//   packages   -> the three Uninstall key views (HKLM 64, HKLM WOW64-32, HKCU)

#include "ns/platform.hpp"

#include "ns/log.hpp"

// winsock2 must precede windows.h; iphlpapi and tlhelp32 must follow it.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <tlhelp32.h>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <string>
#include <unordered_map>
#include <vector>

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

std::string last_error_string(const char* api) {
    return std::string(api) + " failed, error " + std::to_string(GetLastError());
}

// ---------------------------------------------------------------------------
// Registry helpers. Used for the OS version and, at much greater length, for
// the installed-software enumeration below.
// ---------------------------------------------------------------------------

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

// Same, but against an already-open key -- the Uninstall walk opens each subkey
// once and reads several values out of it.
bool reg_value_string(HKEY key, const wchar_t* value, std::string& out) {
    DWORD bytes = 0;
    LSTATUS st = RegGetValueW(key, nullptr, value, RRF_RT_REG_SZ, nullptr, nullptr, &bytes);
    if (st != ERROR_SUCCESS || bytes == 0) return false;

    std::wstring buf(bytes / sizeof(wchar_t) + 1, L'\0');
    DWORD cap = static_cast<DWORD>(buf.size() * sizeof(wchar_t));
    st = RegGetValueW(key, nullptr, value, RRF_RT_REG_SZ, nullptr, buf.data(), &cap);
    if (st != ERROR_SUCCESS) return false;

    buf.resize(wcsnlen(buf.data(), buf.size()));
    out = utf8_from_wide(buf.c_str());
    return true;
}

bool reg_value_dword(HKEY key, const wchar_t* value, DWORD& out) {
    DWORD data = 0, cap = sizeof(data);
    if (RegGetValueW(key, nullptr, value, RRF_RT_REG_DWORD, nullptr, &data, &cap) !=
        ERROR_SUCCESS) {
        return false;
    }
    out = data;
    return true;
}

const wchar_t* kCurrentVersionKey = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";

std::string native_arch() {
    SYSTEM_INFO si{};
    // GetNativeSystemInfo, not GetSystemInfo: under WOW64 the latter reports the
    // emulated 32-bit architecture, which would make every CVE match wrong about
    // the platform it is matching against.
    GetNativeSystemInfo(&si);
    switch (si.wProcessorArchitecture) {
    case PROCESSOR_ARCHITECTURE_AMD64: return "x86_64";
    case PROCESSOR_ARCHITECTURE_ARM64: return "arm64";
    case PROCESSOR_ARCHITECTURE_ARM:   return "arm";
    case PROCESSOR_ARCHITECTURE_INTEL: return "x86";
    default:                           return "";
    }
}

// ---------------------------------------------------------------------------
// Socket / address formatting
// ---------------------------------------------------------------------------

std::string ipv4_to_string(DWORD addr_net_order) {
    in_addr a{};
    a.S_un.S_addr = addr_net_order;
    char buf[INET_ADDRSTRLEN] = {};
    if (!inet_ntop(AF_INET, &a, buf, sizeof(buf))) return {};
    return buf;
}

std::string ipv6_to_string(const UCHAR addr[16]) {
    in6_addr a{};
    std::memcpy(&a, addr, 16);
    char buf[INET6_ADDRSTRLEN] = {};
    if (!inet_ntop(AF_INET6, &a, buf, sizeof(buf))) return {};
    return buf;
}

std::string sockaddr_to_string(const SOCKADDR* sa) {
    char buf[INET6_ADDRSTRLEN] = {};
    if (sa->sa_family == AF_INET) {
        const auto* s = reinterpret_cast<const sockaddr_in*>(sa);
        if (!inet_ntop(AF_INET, &s->sin_addr, buf, sizeof(buf))) return {};
    } else if (sa->sa_family == AF_INET6) {
        const auto* s = reinterpret_cast<const sockaddr_in6*>(sa);
        if (!inet_ntop(AF_INET6, &s->sin6_addr, buf, sizeof(buf))) return {};
    } else {
        return {};
    }
    return buf;
}

// A socket bound to the wildcard address is reachable from off-box; one bound to
// loopback is not. Stage 2 joins CVEs against this so "vulnerable" and "actually
// exposed" stay separate columns.
bool is_wildcard(const std::string& addr) {
    return addr == "0.0.0.0" || addr == "::";
}

// The dwLocalPort fields are documented as being in network byte order in the
// low 16 bits of a DWORD -- a classic source of ports like 20480 (0x5000)
// appearing in inventory tools that forget to swap.
std::uint16_t port_from_dword(DWORD p) {
    return ntohs(static_cast<u_short>(p & 0xFFFF));
}

// ---------------------------------------------------------------------------
// Processes
// ---------------------------------------------------------------------------

std::string process_image_path(DWORD pid) {
    // PROCESS_QUERY_LIMITED_INFORMATION rather than PROCESS_QUERY_INFORMATION:
    // the limited right succeeds against protected and higher-integrity
    // processes where the full right is denied, so an unelevated run still
    // resolves most paths instead of losing them all.
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return {};

    wchar_t buf[MAX_PATH * 2];
    DWORD size = static_cast<DWORD>(std::size(buf));
    std::string out;
    if (QueryFullProcessImageNameW(h, 0, buf, &size)) out = utf8_from_wide(buf);
    CloseHandle(h);
    return out;
}

struct ProcSnapshot {
    std::vector<Process> procs;
    std::unordered_map<DWORD, std::string> names;
};

bool take_process_snapshot(ProcSnapshot& snap, std::string& err) {
    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (h == INVALID_HANDLE_VALUE) {
        err = last_error_string("CreateToolhelp32Snapshot");
        return false;
    }

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!Process32FirstW(h, &entry)) {
        err = last_error_string("Process32FirstW");
        CloseHandle(h);
        return false;
    }

    do {
        Process p;
        p.pid = static_cast<std::int64_t>(entry.th32ProcessID);
        p.ppid = static_cast<std::int64_t>(entry.th32ParentProcessID);
        p.name = utf8_from_wide(entry.szExeFile);
        p.exe_path = process_image_path(entry.th32ProcessID);
        snap.names.emplace(entry.th32ProcessID, p.name);
        snap.procs.push_back(std::move(p));
    } while (Process32NextW(h, &entry));

    CloseHandle(h);
    return true;
}

// ---------------------------------------------------------------------------
// Installed software
// ---------------------------------------------------------------------------

struct UninstallView {
    HKEY root;
    const wchar_t* path;
    REGSAM extra;  // KEY_WOW64_* -- see the comment at the call site
    const char* label;
};

void scan_uninstall_view(const UninstallView& view, std::vector<Package>& out,
                         Status& st) {
    HKEY key = nullptr;
    LSTATUS rc = RegOpenKeyExW(view.root, view.path, 0,
                               KEY_READ | KEY_ENUMERATE_SUB_KEYS | view.extra, &key);
    if (rc != ERROR_SUCCESS) {
        // A missing WOW6432Node on a pure-64-bit install is normal, not an error.
        if (rc != ERROR_FILE_NOT_FOUND) {
            st.warn(std::string("could not open the ") + view.label +
                    " uninstall key, status " + std::to_string(rc));
        }
        return;
    }

    for (DWORD i = 0;; ++i) {
        wchar_t sub[512];
        DWORD sub_len = static_cast<DWORD>(std::size(sub));
        rc = RegEnumKeyExW(key, i, sub, &sub_len, nullptr, nullptr, nullptr, nullptr);
        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc != ERROR_SUCCESS) {
            st.warn(std::string("RegEnumKeyExW stopped early in ") + view.label +
                    ", status " + std::to_string(rc));
            break;
        }

        HKEY entry = nullptr;
        if (RegOpenKeyExW(key, sub, 0, KEY_READ | view.extra, &entry) != ERROR_SUCCESS) {
            continue;
        }

        Package p;
        const bool has_name = reg_value_string(entry, L"DisplayName", p.name);

        // Entries with no DisplayName are update stubs and installer bookkeeping;
        // SystemComponent=1 marks things Add/Remove Programs itself hides. Both
        // are noise that would inflate the package count without being software
        // anyone can meaningfully match a CVE against.
        DWORD sys_component = 0;
        const bool hidden = reg_value_dword(entry, L"SystemComponent", sys_component) &&
                            sys_component == 1;

        if (has_name && !p.name.empty() && !hidden) {
            reg_value_string(entry, L"DisplayVersion", p.version);
            reg_value_string(entry, L"Publisher", p.vendor);
            p.source = view.label;
            out.push_back(std::move(p));
        }
        RegCloseKey(entry);
    }
    RegCloseKey(key);
}

} // namespace

const char* name() { return "windows"; }

// ---------------------------------------------------------------------------

Status collect_host(HostInfo& out) {
    Status st;

    wchar_t host[256];
    DWORD len = static_cast<DWORD>(std::size(host));
    if (GetComputerNameExW(ComputerNameDnsHostname, host, &len)) {
        out.hostname = utf8_from_wide(host);
    } else {
        st.warn(last_error_string("GetComputerNameExW"));
    }

    // The registry is the pragmatic source. GetVersionEx is deprecated and shims
    // its answer unless the binary carries a compatibility manifest;
    // RtlGetVersion is accurate but is a ntdll internal. These values are what
    // inventory tools on Windows actually read.
    if (!reg_read_string(HKEY_LOCAL_MACHINE, kCurrentVersionKey, L"ProductName",
                         out.os_name)) {
        st.warn("could not read ProductName from the registry");
    }
    if (!reg_read_string(HKEY_LOCAL_MACHINE, kCurrentVersionKey, L"DisplayVersion",
                         out.os_version)) {
        reg_read_string(HKEY_LOCAL_MACHINE, kCurrentVersionKey, L"ReleaseId",
                        out.os_version);  // pre-20H2 spelling
    }

    std::string build;
    if (reg_read_string(HKEY_LOCAL_MACHINE, kCurrentVersionKey, L"CurrentBuildNumber",
                        build)) {
        out.kernel = "10.0." + build;

        // ProductName still reads "Windows 10 ..." on every Windows 11 install --
        // Microsoft never updated the value, and the build number is the only
        // reliable discriminator (11 starts at 22000). Left uncorrected this
        // would hand the CVE stage the wrong OS CPE and silently mis-match every
        // OS-level advisory, so the fix happens at the platform boundary.
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

Status collect_interfaces(std::vector<NetInterface>& out) {
    Status st;

    // GetAdaptersAddresses wants a caller-sized buffer and reports how much it
    // actually needs. The adapter list can change between the two calls, so this
    // retries rather than trusting the first answer -- a fixed 15KB buffer is the
    // usual bug here.
    ULONG size = 15 * 1024;
    std::vector<unsigned char> buf(size);
    ULONG rc = 0;
    for (int attempt = 0; attempt < 4; ++attempt) {
        rc = GetAdaptersAddresses(
            AF_UNSPEC,
            GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
            nullptr, reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()), &size);
        if (rc != ERROR_BUFFER_OVERFLOW) break;
        buf.assign(size, 0);
    }
    if (rc != NO_ERROR) {
        st.warn("GetAdaptersAddresses failed, status " + std::to_string(rc));
        return st;
    }

    for (auto* a = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()); a; a = a->Next) {
        NetInterface ni;
        ni.name = utf8_from_wide(a->FriendlyName);
        ni.up = (a->OperStatus == IfOperStatusUp);
        ni.loopback = (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK);

        char mac[18] = {};
        if (a->PhysicalAddressLength == 6) {
            std::snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                          a->PhysicalAddress[0], a->PhysicalAddress[1],
                          a->PhysicalAddress[2], a->PhysicalAddress[3],
                          a->PhysicalAddress[4], a->PhysicalAddress[5]);
            ni.mac = mac;
        }

        for (auto* u = a->FirstUnicastAddress; u; u = u->Next) {
            std::string s = sockaddr_to_string(u->Address.lpSockaddr);
            if (s.empty()) continue;
            ni.addresses.push_back(s + "/" + std::to_string(u->OnLinkPrefixLength));
        }
        out.push_back(std::move(ni));
    }
    return st;
}

Status collect_listening_sockets(std::vector<ListeningSocket>& out) {
    Status st;

    ProcSnapshot snap;
    std::string err;
    if (!take_process_snapshot(snap, err)) {
        // Not fatal: report the sockets with pid resolution missing rather than
        // reporting no sockets at all.
        st.warn("process names unavailable (" + err + "); pids reported unresolved");
    }

    auto resolve = [&](DWORD pid, ListeningSocket& s) {
        s.pid = static_cast<std::int64_t>(pid);
        auto it = snap.names.find(pid);
        if (it != snap.names.end()) s.process_name = it->second;
    };

    auto fetch_table = [&](bool ipv6, bool udp, std::vector<unsigned char>& table) -> bool {
        DWORD size = 0;
        const ULONG family = ipv6 ? AF_INET6 : AF_INET;
        DWORD rc = udp ? GetExtendedUdpTable(nullptr, &size, FALSE, family,
                                             UDP_TABLE_OWNER_PID, 0)
                       : GetExtendedTcpTable(nullptr, &size, FALSE, family,
                                             TCP_TABLE_OWNER_PID_LISTENER, 0);
        if (rc != ERROR_INSUFFICIENT_BUFFER) return false;
        table.assign(size, 0);
        rc = udp ? GetExtendedUdpTable(table.data(), &size, FALSE, family,
                                       UDP_TABLE_OWNER_PID, 0)
                 : GetExtendedTcpTable(table.data(), &size, FALSE, family,
                                       TCP_TABLE_OWNER_PID_LISTENER, 0);
        return rc == NO_ERROR;
    };

    std::vector<unsigned char> table;

    if (fetch_table(/*ipv6=*/false, /*udp=*/false, table)) {
        const auto* t = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(table.data());
        for (DWORD i = 0; i < t->dwNumEntries; ++i) {
            const auto& r = t->table[i];
            ListeningSocket s;
            s.proto = "tcp";
            s.local_addr = ipv4_to_string(r.dwLocalAddr);
            s.local_port = port_from_dword(r.dwLocalPort);
            s.world_reachable = is_wildcard(s.local_addr);
            resolve(r.dwOwningPid, s);
            out.push_back(std::move(s));
        }
    } else {
        st.warn("GetExtendedTcpTable(AF_INET) failed");
    }

    if (fetch_table(/*ipv6=*/true, /*udp=*/false, table)) {
        const auto* t = reinterpret_cast<const MIB_TCP6TABLE_OWNER_PID*>(table.data());
        for (DWORD i = 0; i < t->dwNumEntries; ++i) {
            const auto& r = t->table[i];
            ListeningSocket s;
            s.proto = "tcp6";
            s.local_addr = ipv6_to_string(r.ucLocalAddr);
            s.local_port = port_from_dword(r.dwLocalPort);
            s.world_reachable = is_wildcard(s.local_addr);
            resolve(r.dwOwningPid, s);
            out.push_back(std::move(s));
        }
    } else {
        st.warn("GetExtendedTcpTable(AF_INET6) failed");
    }

    // UDP has no listening state, so every bound socket is reported. An open UDP
    // port is still exposure, and omitting them would leave a hole in the report.
    if (fetch_table(/*ipv6=*/false, /*udp=*/true, table)) {
        const auto* t = reinterpret_cast<const MIB_UDPTABLE_OWNER_PID*>(table.data());
        for (DWORD i = 0; i < t->dwNumEntries; ++i) {
            const auto& r = t->table[i];
            ListeningSocket s;
            s.proto = "udp";
            s.local_addr = ipv4_to_string(r.dwLocalAddr);
            s.local_port = port_from_dword(r.dwLocalPort);
            s.world_reachable = is_wildcard(s.local_addr);
            resolve(r.dwOwningPid, s);
            out.push_back(std::move(s));
        }
    } else {
        st.warn("GetExtendedUdpTable(AF_INET) failed");
    }

    if (fetch_table(/*ipv6=*/true, /*udp=*/true, table)) {
        const auto* t = reinterpret_cast<const MIB_UDP6TABLE_OWNER_PID*>(table.data());
        for (DWORD i = 0; i < t->dwNumEntries; ++i) {
            const auto& r = t->table[i];
            ListeningSocket s;
            s.proto = "udp6";
            s.local_addr = ipv6_to_string(r.ucLocalAddr);
            s.local_port = port_from_dword(r.dwLocalPort);
            s.world_reachable = is_wildcard(s.local_addr);
            resolve(r.dwOwningPid, s);
            out.push_back(std::move(s));
        }
    } else {
        st.warn("GetExtendedUdpTable(AF_INET6) failed");
    }

    std::sort(out.begin(), out.end(), [](const ListeningSocket& a, const ListeningSocket& b) {
        if (a.proto != b.proto) return a.proto < b.proto;
        return a.local_port < b.local_port;
    });
    return st;
}

Status collect_processes(std::vector<Process>& out) {
    Status st;
    ProcSnapshot snap;
    std::string err;
    if (!take_process_snapshot(snap, err)) {
        st.warn(err);
        return st;
    }

    std::size_t unresolved = 0;
    for (auto& p : snap.procs) {
        if (p.exe_path.empty()) ++unresolved;
    }
    if (unresolved > 0) {
        // Expected without elevation: protected and SYSTEM-owned processes deny
        // the query. Reported rather than hidden so the cloud can tell an
        // unelevated agent from a host that genuinely has nothing running.
        st.warn(std::to_string(unresolved) +
                " of " + std::to_string(snap.procs.size()) +
                " processes had no readable image path (run elevated for full coverage)");
    }
    out = std::move(snap.procs);
    return st;
}

Status collect_packages(std::vector<Package>& out) {
    Status st;

    // Three views, and all three are needed. A 32-bit application on 64-bit
    // Windows registers under WOW6432Node, and per-user installs (a lot of
    // developer tooling, browsers, Teams) live in HKCU and are invisible to a
    // HKLM-only scan. Reading only HKLM/64 is the single most common way an
    // inventory silently loses half the installed software on a host.
    const UninstallView views[] = {
        {HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
         KEY_WOW64_64KEY, "windows-registry"},
        {HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
         KEY_WOW64_32KEY, "windows-registry-wow64"},
        {HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
         0, "windows-registry-hkcu"},
    };

    for (const auto& v : views) scan_uninstall_view(v, out, st);

    // The 64- and 32-bit views overlap for some products; de-duplicate on
    // (name, version) so the package count is not inflated.
    std::sort(out.begin(), out.end(), [](const Package& a, const Package& b) {
        if (a.name != b.name) return a.name < b.name;
        return a.version < b.version;
    });
    out.erase(std::unique(out.begin(), out.end(),
                          [](const Package& a, const Package& b) {
                              return a.name == b.name && a.version == b.version;
                          }),
              out.end());

    if (out.empty()) st.warn("no installed software found in any registry view");
    return st;
}

} // namespace ns::platform
