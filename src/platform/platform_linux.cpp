// Linux backend for the asset collectors.
//
// Stage 0 implements collect_host() for real and leaves the other four as
// declared stubs that report implemented=false.
//
// Planned for stage 1 (see PLAN.md):
//   interfaces -> getifaddrs
//   sockets    -> /proc/net/tcp{,6} + /proc/net/udp{,6}, then the socket inode
//                 -> /proc/<pid>/fd/* reverse map for the owning process.
//                 Deliberately NOT netlink INET_DIAG: netlink is the better
//                 answer and a multi-hour detour, and procfs is what `ss`
//                 itself falls back to. The tradeoff is written up in the README
//                 rather than hidden.
//   processes  -> /proc/<pid>/{stat,status,exe,cmdline}
//   packages   -> `dpkg-query -W -f=...` / `rpm -qa --qf=...`, chosen by which
//                 database is present.

#include "ns/platform.hpp"

#include "ns/log.hpp"

#include <sys/utsname.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <fstream>
#include <string>

namespace ns::platform {

namespace {

std::string strip_quotes(std::string s) {
    if (s.size() >= 2 && s.front() == '"' && s.back() == '"') {
        return s.substr(1, s.size() - 2);
    }
    return s;
}

// /etc/os-release is the one distro-identification file that is actually
// standardised (systemd's os-release(5)); lsb_release is a Python script that
// half the minimal container images do not ship.
bool read_os_release(std::string& name, std::string& version) {
    std::ifstream f("/etc/os-release");
    if (!f) return false;

    std::string line;
    while (std::getline(f, line)) {
        const auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        const std::string key = line.substr(0, eq);
        const std::string val = strip_quotes(line.substr(eq + 1));
        if (key == "NAME") name = val;
        else if (key == "VERSION_ID") version = val;
    }
    return !name.empty();
}

} // namespace

const char* name() { return "linux"; }

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

Status collect_interfaces(std::vector<NetInterface>&) {
    Status st;
    st.implemented = false;  // stage 1: getifaddrs
    return st;
}

Status collect_listening_sockets(std::vector<ListeningSocket>&) {
    Status st;
    st.implemented = false;  // stage 1: /proc/net/tcp{,6} + inode -> pid map
    return st;
}

Status collect_processes(std::vector<Process>&) {
    Status st;
    st.implemented = false;  // stage 1: /proc/<pid>
    return st;
}

Status collect_packages(std::vector<Package>&) {
    Status st;
    st.implemented = false;  // stage 1: dpkg-query / rpm
    return st;
}

} // namespace ns::platform
