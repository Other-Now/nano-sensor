#pragma once

#include "ns/inventory.hpp"

#include <string>
#include <vector>

namespace ns::platform {

// Collectors do not throw, and one unreadable item never aborts the rest.
//
// A sensor that dies because a single /proc/<pid> vanished between readdir and
// open, or because one WMI provider is wedged, is worse than useless -- it goes
// silent on exactly the hosts that are interesting. So each collector fills its
// output as far as it can and appends a note per thing it had to skip. The notes
// travel all the way to the cloud in Inventory::warnings.
struct Status {
    // False while a backend is still a stub, so the report says "not collected
    // on this platform" instead of quietly claiming the host has zero packages.
    bool implemented = true;
    std::vector<std::string> warnings;

    void warn(std::string w) { warnings.push_back(std::move(w)); }
};

Status collect_host(HostInfo& out);
Status collect_interfaces(std::vector<NetInterface>& out);
Status collect_listening_sockets(std::vector<ListeningSocket>& out);
Status collect_processes(std::vector<Process>& out);
Status collect_packages(std::vector<Package>& out);

// "linux" / "windows" -- the compiled-in backend, not a runtime probe.
const char* name();

} // namespace ns::platform

namespace ns {

// Runs every collector into one Inventory, timing the whole pass and folding
// each Status into Inventory::warnings. Shared by both backends.
Inventory collect_inventory();

} // namespace ns
