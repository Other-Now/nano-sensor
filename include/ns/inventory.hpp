#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace ns {

// The OS-neutral asset model.
//
// Every field here has to be fillable from BOTH /proc + netlink and Win32 --
// anything that only one side can produce belongs in a platform-specific extra,
// not in the shared model. That constraint is what keeps the platform layer a
// real abstraction instead of a union of two APIs.
//
// Empty string / 0 means "this platform could not determine it", never "absent".
// The distinction matters downstream: a package with no version cannot be
// CVE-matched, and stage 4 has to skip it explicitly rather than guess.

struct HostInfo {
    std::string hostname;
    std::string os_name;      // "Ubuntu", "Windows 11 Home Single Language"
    std::string os_version;   // "22.04", "10.0.26200"
    std::string kernel;       // uname release / Windows build number
    std::string arch;         // "x86_64", "AMD64"
};

struct NetInterface {
    std::string name;                  // "eth0", "Ethernet 2"
    std::string mac;                   // "aa:bb:cc:dd:ee:ff", lowercase, colon-separated
    std::vector<std::string> addresses;  // "192.168.1.10/24", "fe80::1/64"
    bool up = false;
    bool loopback = false;
};

struct ListeningSocket {
    std::string proto;        // "tcp", "tcp6", "udp", "udp6"
    std::string local_addr;   // "0.0.0.0", "::", "127.0.0.1"
    std::uint16_t local_port = 0;
    std::int64_t pid = -1;    // -1 when the owning process could not be resolved
    std::string process_name; // best-effort; empty when pid is -1 or lookup failed

    // The single most important derived field in the whole model: stage 4 joins
    // CVEs against it so that "vulnerable" and "actually reachable" are
    // different columns in the report.
    bool world_reachable = false;  // bound to 0.0.0.0 / :: rather than loopback
};

struct Process {
    std::int64_t pid = -1;
    std::int64_t ppid = -1;
    std::string name;
    std::string exe_path;
    std::string user;
};

struct Package {
    std::string name;
    std::string version;
    std::string vendor;
    std::string source;  // "dpkg", "rpm", "windows-registry", "msi"
};

struct Inventory {
    std::string agent_name;
    std::string agent_version;
    std::string agent_stage;
    std::string platform;              // "linux", "windows"
    std::int64_t collected_at_unix_ms = 0;
    std::int64_t collect_duration_ms = 0;

    HostInfo host;
    std::vector<NetInterface> interfaces;
    std::vector<ListeningSocket> sockets;
    std::vector<Process> processes;
    std::vector<Package> packages;

    // Partial-failure notes from the collectors. Present in the report on
    // purpose: a sensor that silently under-reports is a security hole, so the
    // cloud side has to be able to see that this host's package list was, say,
    // truncated by a permissions error.
    std::vector<std::string> warnings;
};

std::string to_json(const Inventory& inv, bool pretty);

// Wall-clock milliseconds since the Unix epoch.
std::int64_t unix_time_ms();

} // namespace ns
