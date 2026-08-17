// Linux backend for the asset collectors.
//
//   host       -> gethostname + /etc/os-release + uname
//   interfaces -> getifaddrs
//   sockets    -> /proc/net/{tcp,tcp6,udp,udp6}, joined to owning processes
//                 through the socket inode -> /proc/<pid>/fd/* reverse map
//   processes  -> /proc/<pid>/{comm,stat,status,exe}
//   packages   -> dpkg-query or rpm, whichever database is present
//
// Deliberately NOT netlink INET_DIAG for sockets. Netlink is the better answer
// -- it is what `ss` uses first, it is a single round trip instead of a
// directory walk, and it does not go quadratic on hosts with many processes.
// procfs was chosen because it is a fraction of the code, it is what `ss`
// itself falls back to when netlink is unavailable, and the inode->pid join is
// required either way. The tradeoff is written down rather than hidden: see
// README.md.

#include "ns/platform.hpp"

#include "ns/log.hpp"

#include <arpa/inet.h>
#include <dirent.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pwd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

#if defined(__linux__)
#include <linux/if_packet.h>
#endif

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

namespace ns::platform {

namespace {

std::string strip_quotes(std::string s) {
    if (s.size() >= 2 && s.front() == '"' && s.back() == '"') {
        return s.substr(1, s.size() - 2);
    }
    return s;
}

std::string read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

std::string trim(const std::string& s) {
    const auto b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return {};
    const auto e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

bool is_number(const std::string& s) {
    return !s.empty() && s.find_first_not_of("0123456789") == std::string::npos;
}

// /etc/os-release is the one distro-identification file that is actually
// standardised (systemd's os-release(5)); lsb_release is a Python script half
// the minimal container images do not ship.
bool read_os_release(std::string& name, std::string& version) {
    std::ifstream f("/etc/os-release");
    if (!f) return false;
    std::string line;
    while (std::getline(f, line)) {
        const auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        const std::string key = line.substr(0, eq);
        const std::string val = strip_quotes(trim(line.substr(eq + 1)));
        if (key == "NAME") name = val;
        else if (key == "VERSION_ID") version = val;
    }
    return !name.empty();
}

// ---------------------------------------------------------------------------
// /proc/net/* address decoding
// ---------------------------------------------------------------------------

// procfs prints the address as the raw in_addr/in6_addr words formatted with
// %08X -- i.e. in the host's native word order, not network order. Reading each
// word with strtoul and memcpy'ing it back therefore round-trips correctly on
// little-endian, which is every platform this agent targets. (A big-endian host
// would need the words byte-swapped; noted rather than silently assumed.)
bool parse_hex_addr(const std::string& hex, std::string& out, bool& is_v6) {
    if (hex.size() == 8) {
        is_v6 = false;
        const auto v = static_cast<std::uint32_t>(std::strtoul(hex.c_str(), nullptr, 16));
        in_addr a{};
        std::memcpy(&a, &v, sizeof(a));
        char buf[INET_ADDRSTRLEN] = {};
        if (!inet_ntop(AF_INET, &a, buf, sizeof(buf))) return false;
        out = buf;
        return true;
    }
    if (hex.size() == 32) {
        is_v6 = true;
        std::uint32_t w[4];
        for (int i = 0; i < 4; ++i) {
            w[i] = static_cast<std::uint32_t>(
                std::strtoul(hex.substr(static_cast<size_t>(i) * 8, 8).c_str(), nullptr, 16));
        }
        in6_addr a{};
        std::memcpy(&a, w, sizeof(w));
        char buf[INET6_ADDRSTRLEN] = {};
        if (!inet_ntop(AF_INET6, &a, buf, sizeof(buf))) return false;
        out = buf;
        return true;
    }
    return false;
}

bool is_wildcard(const std::string& addr) {
    return addr == "0.0.0.0" || addr == "::";
}

constexpr int kTcpListen = 0x0A;  // TCP_LISTEN, from include/net/tcp_states.h

struct RawSocket {
    std::string proto;
    std::string addr;
    std::uint16_t port = 0;
    unsigned long inode = 0;
};

// One /proc/net/{tcp,udp}[6] table. Line format (after the header):
//   sl local_address rem_address st tx:rx uid timeout inode ...
bool parse_proc_net(const std::string& path, const char* proto, bool tcp_only_listen,
                    std::vector<RawSocket>& out) {
    std::ifstream f(path);
    if (!f) return false;

    std::string line;
    std::getline(f, line);  // discard the column header
    while (std::getline(f, line)) {
        std::istringstream ls(line);
        std::string sl, local, rem, st, txrx, uid, timeout, inode;
        if (!(ls >> sl >> local >> rem >> st >> txrx >> uid >> timeout >> inode)) continue;

        if (tcp_only_listen) {
            const long state = std::strtol(st.c_str(), nullptr, 16);
            if (state != kTcpListen) continue;
        }

        const auto colon = local.rfind(':');
        if (colon == std::string::npos) continue;

        RawSocket s;
        bool v6 = false;
        if (!parse_hex_addr(local.substr(0, colon), s.addr, v6)) continue;
        s.port = static_cast<std::uint16_t>(
            std::strtoul(local.substr(colon + 1).c_str(), nullptr, 16));
        s.inode = std::strtoul(inode.c_str(), nullptr, 10);
        s.proto = proto;
        out.push_back(std::move(s));
    }
    return true;
}

// Reverse map from socket inode to owning pid, built by walking every process's
// fd directory looking for "socket:[NNN]" symlinks.
//
// This is the part netlink would make cheap. It is O(total open fds), it needs
// to tolerate /proc/<pid> disappearing mid-walk (processes exit while we read),
// and without root it only sees our own processes' fds -- so the pid column is
// best-effort by construction and the code says so instead of pretending.
std::unordered_map<unsigned long, std::int64_t> build_inode_to_pid(std::size_t& denied) {
    std::unordered_map<unsigned long, std::int64_t> map;
    DIR* proc = opendir("/proc");
    if (!proc) return map;

    while (dirent* de = readdir(proc)) {
        const std::string pid_s = de->d_name;
        if (!is_number(pid_s)) continue;

        const std::string fd_dir = "/proc/" + pid_s + "/fd";
        DIR* fds = opendir(fd_dir.c_str());
        if (!fds) {
            if (errno == EACCES) ++denied;
            continue;  // ESRCH: the process exited between readdir and opendir
        }

        while (dirent* fde = readdir(fds)) {
            if (fde->d_name[0] == '.') continue;
            const std::string link = fd_dir + "/" + fde->d_name;
            char target[128];
            const ssize_t n = readlink(link.c_str(), target, sizeof(target) - 1);
            if (n <= 0) continue;
            target[n] = '\0';

            // "socket:[12345]"
            if (std::strncmp(target, "socket:[", 8) != 0) continue;
            const unsigned long inode = std::strtoul(target + 8, nullptr, 10);
            if (inode != 0) {
                map.emplace(inode, std::strtoll(pid_s.c_str(), nullptr, 10));
            }
        }
        closedir(fds);
    }
    closedir(proc);
    return map;
}

std::string process_comm(std::int64_t pid) {
    return trim(read_file("/proc/" + std::to_string(pid) + "/comm"));
}

} // namespace

const char* name() { return "linux"; }

// ---------------------------------------------------------------------------

Status collect_host(HostInfo& out) {
    Status st;

    char host[256];
    if (::gethostname(host, sizeof(host)) == 0) {
        host[sizeof(host) - 1] = '\0';  // POSIX does not promise truncation is terminated
        out.hostname = host;
    } else {
        st.warn(std::string("gethostname failed: ") + std::strerror(errno));
    }

    if (!read_os_release(out.os_name, out.os_version)) {
        st.warn("/etc/os-release unreadable or had no NAME");
    }

    struct utsname u{};
    if (::uname(&u) == 0) {
        out.kernel = u.release;
        out.arch = u.machine;
    } else {
        st.warn(std::string("uname failed: ") + std::strerror(errno));
    }
    return st;
}

Status collect_interfaces(std::vector<NetInterface>& out) {
    Status st;

    ifaddrs* head = nullptr;
    if (getifaddrs(&head) != 0) {
        st.warn(std::string("getifaddrs failed: ") + std::strerror(errno));
        return st;
    }

    // getifaddrs returns one node per (interface, address family), so the same
    // interface appears several times and has to be folded back together.
    std::unordered_map<std::string, std::size_t> index;
    auto slot = [&](const char* ifname) -> NetInterface& {
        auto it = index.find(ifname);
        if (it != index.end()) return out[it->second];
        index.emplace(ifname, out.size());
        out.push_back(NetInterface{});
        out.back().name = ifname;
        return out.back();
    };

    for (ifaddrs* ifa = head; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_name) continue;
        NetInterface& ni = slot(ifa->ifa_name);
        ni.up = (ifa->ifa_flags & IFF_UP) != 0;
        ni.loopback = (ifa->ifa_flags & IFF_LOOPBACK) != 0;
        if (!ifa->ifa_addr) continue;

        const int family = ifa->ifa_addr->sa_family;
        if (family == AF_INET || family == AF_INET6) {
            char buf[INET6_ADDRSTRLEN] = {};
            const void* src = nullptr;
            int prefix = 0;

            if (family == AF_INET) {
                src = &reinterpret_cast<sockaddr_in*>(ifa->ifa_addr)->sin_addr;
                if (ifa->ifa_netmask) {
                    const auto m = ntohl(
                        reinterpret_cast<sockaddr_in*>(ifa->ifa_netmask)->sin_addr.s_addr);
                    while (prefix < 32 && (m & (0x80000000u >> prefix))) ++prefix;
                }
            } else {
                src = &reinterpret_cast<sockaddr_in6*>(ifa->ifa_addr)->sin6_addr;
                if (ifa->ifa_netmask) {
                    const auto* m = reinterpret_cast<const unsigned char*>(
                        &reinterpret_cast<sockaddr_in6*>(ifa->ifa_netmask)->sin6_addr);
                    for (int i = 0; i < 16; ++i) {
                        for (int b = 7; b >= 0; --b) {
                            if (m[i] & (1u << b)) ++prefix; else { i = 16; break; }
                        }
                    }
                }
            }
            if (inet_ntop(family, src, buf, sizeof(buf))) {
                ni.addresses.push_back(std::string(buf) + "/" + std::to_string(prefix));
            }
        }
#if defined(__linux__)
        else if (family == AF_PACKET) {
            const auto* ll = reinterpret_cast<sockaddr_ll*>(ifa->ifa_addr);
            if (ll->sll_halen == 6) {
                char mac[18];
                std::snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                              ll->sll_addr[0], ll->sll_addr[1], ll->sll_addr[2],
                              ll->sll_addr[3], ll->sll_addr[4], ll->sll_addr[5]);
                ni.mac = mac;
            }
        }
#endif
    }
    freeifaddrs(head);
    return st;
}

Status collect_listening_sockets(std::vector<ListeningSocket>& out) {
    Status st;

    std::vector<RawSocket> raw;
    const struct { const char* path; const char* proto; bool listen_only; } tables[] = {
        {"/proc/net/tcp",  "tcp",  true},
        {"/proc/net/tcp6", "tcp6", true},
        // UDP has no listening state, so every bound socket is reported. An open
        // UDP port is still exposure, and omitting them would leave a hole.
        {"/proc/net/udp",  "udp",  false},
        {"/proc/net/udp6", "udp6", false},
    };
    for (const auto& t : tables) {
        if (!parse_proc_net(t.path, t.proto, t.listen_only, raw)) {
            st.warn(std::string("could not read ") + t.path);
        }
    }

    std::size_t denied = 0;
    const auto inode_to_pid = build_inode_to_pid(denied);
    if (denied > 0) {
        st.warn(std::to_string(denied) +
                " processes denied fd enumeration (run as root to resolve every "
                "socket to its owning process)");
    }

    for (auto& r : raw) {
        ListeningSocket s;
        s.proto = std::move(r.proto);
        s.local_addr = std::move(r.addr);
        s.local_port = r.port;
        s.world_reachable = is_wildcard(s.local_addr);

        auto it = inode_to_pid.find(r.inode);
        if (it != inode_to_pid.end()) {
            s.pid = it->second;
            s.process_name = process_comm(s.pid);
        }
        out.push_back(std::move(s));
    }

    std::sort(out.begin(), out.end(), [](const ListeningSocket& a, const ListeningSocket& b) {
        if (a.proto != b.proto) return a.proto < b.proto;
        return a.local_port < b.local_port;
    });
    return st;
}

Status collect_processes(std::vector<Process>& out) {
    Status st;

    DIR* proc = opendir("/proc");
    if (!proc) {
        st.warn(std::string("opendir(/proc) failed: ") + std::strerror(errno));
        return st;
    }

    std::size_t no_exe = 0;
    while (dirent* de = readdir(proc)) {
        const std::string pid_s = de->d_name;
        if (!is_number(pid_s)) continue;

        Process p;
        p.pid = std::strtoll(pid_s.c_str(), nullptr, 10);
        p.name = process_comm(p.pid);

        // The comm field inside /proc/<pid>/stat is parenthesised and may itself
        // contain spaces and parentheses ("(sd-pam)", "(my app)"), so every field
        // after it must be located from the LAST ')' rather than by splitting on
        // whitespace. This is the classic /proc/<pid>/stat parsing bug.
        const std::string stat = read_file("/proc/" + pid_s + "/stat");
        const auto close_paren = stat.rfind(')');
        if (close_paren != std::string::npos && close_paren + 2 < stat.size()) {
            std::istringstream rest(stat.substr(close_paren + 2));
            std::string state, ppid;
            if (rest >> state >> ppid) p.ppid = std::strtoll(ppid.c_str(), nullptr, 10);
        }

        char exe[4096];
        const ssize_t n = readlink(("/proc/" + pid_s + "/exe").c_str(), exe, sizeof(exe) - 1);
        if (n > 0) {
            exe[n] = '\0';
            p.exe_path = exe;
        } else {
            // Kernel threads genuinely have no executable; unprivileged runs are
            // also denied for other users' processes. Both are normal.
            ++no_exe;
        }

        std::ifstream status("/proc/" + pid_s + "/status");
        std::string line;
        while (std::getline(status, line)) {
            if (line.rfind("Uid:", 0) != 0) continue;
            std::istringstream ls(line.substr(4));
            uid_t uid = 0;
            if (ls >> uid) {
                if (const passwd* pw = getpwuid(uid)) p.user = pw->pw_name;
                else p.user = std::to_string(uid);
            }
            break;
        }

        if (!p.name.empty()) out.push_back(std::move(p));
    }
    closedir(proc);

    if (no_exe > 0) {
        st.warn(std::to_string(no_exe) + " of " + std::to_string(out.size() + no_exe) +
                " processes had no readable exe link (kernel threads, or run as "
                "root for full coverage)");
    }
    return st;
}

Status collect_packages(std::vector<Package>& out) {
    Status st;

    // Which package database is present decides the query. Checking for the
    // database rather than for the binary avoids being fooled by a dpkg binary
    // sitting on an rpm-managed host.
    const bool have_dpkg = ::access("/var/lib/dpkg/status", F_OK) == 0;
    const bool have_rpm = ::access("/var/lib/rpm", F_OK) == 0;

    const char* cmd = nullptr;
    const char* source = nullptr;
    if (have_dpkg) {
        // ${db:Status-Status} filters out packages that are removed-but-not-purged;
        // those leave config files behind and would otherwise be reported as
        // installed software, producing CVE findings for things that are gone.
        cmd = "dpkg-query -W -f='${db:Status-Status}\\t${Package}\\t${Version}\\t${Maintainer}\\n' 2>/dev/null";
        source = "dpkg";
    } else if (have_rpm) {
        cmd = "rpm -qa --qf 'installed\\t%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{VENDOR}\\n' 2>/dev/null";
        source = "rpm";
    } else {
        st.implemented = false;
        st.warn("no dpkg or rpm database found; installed software not collected");
        return st;
    }

    FILE* pipe = ::popen(cmd, "r");
    if (!pipe) {
        st.warn(std::string("popen failed for ") + source + ": " + std::strerror(errno));
        return st;
    }

    char line[4096];
    while (std::fgets(line, sizeof(line), pipe)) {
        std::istringstream ls(line);
        std::string status, pkg, version, vendor;
        std::getline(ls, status, '\t');
        std::getline(ls, pkg, '\t');
        std::getline(ls, version, '\t');
        std::getline(ls, vendor, '\n');

        if (trim(status) != "installed" || pkg.empty()) continue;

        Package p;
        p.name = trim(pkg);
        p.version = trim(version);
        p.vendor = trim(vendor);
        p.source = source;
        out.push_back(std::move(p));
    }

    const int rc = ::pclose(pipe);
    if (rc != 0) {
        st.warn(std::string(source) + " query exited with status " + std::to_string(rc));
    }
    if (out.empty()) st.warn("package query returned nothing");

    std::sort(out.begin(), out.end(), [](const Package& a, const Package& b) {
        return a.name < b.name;
    });
    return st;
}

} // namespace ns::platform
