// Linux builds of the Windows-only pieces: named-pipe IPC, SQL Server over
// ODBC, minidumps. They compile so the agent core stays one codebase, and they
// fail loudly at runtime instead of pretending. The Linux equivalents (a Unix
// socket with SO_PEERCRED, unixODBC, core dumps) are out of scope; see README.

#include "ns/crashdump.hpp"
#include "ns/db.hpp"
#include "ns/ipc.hpp"
#include "ns/procinfo.hpp"

#include <unistd.h>

namespace ns {

namespace crashdump {
bool install(const std::string&) { return false; }
void on_thread_start() {}
bool write_now(const std::string&, std::string&, std::string& error) {
    error = "minidumps are Windows-only; use core dumps on Linux";
    return false;
}
std::uint32_t dumps_written() { return 0; }
} // namespace crashdump

namespace ipc {
std::string default_sddl() { return {}; }
struct Server::Impl {};
Server::Server() : impl_(std::make_unique<Impl>()) {}
Server::~Server() = default;
bool Server::start(const std::string&, const std::string&, Handler, std::string& error) {
    error = "the control pipe is Windows-only";
    return false;
}
void Server::stop() {}
std::uint64_t Server::requests_served() const { return 0; }
bool call(const std::string&, const std::string&, std::string&, std::string& error,
          std::uint32_t) {
    error = "the control pipe is Windows-only";
    return false;
}
std::uint32_t last_call_error() { return 0; }
} // namespace ipc

struct Db::Impl {};
Db::Db() : impl_(std::make_unique<Impl>()) {}
Db::~Db() = default;
bool Db::connect(const std::string&, std::string& error) {
    error = "SQL Server storage is Windows-only";
    return false;
}
void Db::disconnect() {}
bool Db::connected() const { return false; }
bool Db::record_scan(const Inventory&, const std::vector<Finding>&, std::int64_t&,
                     std::string& error) {
    error = "not connected";
    return false;
}
bool Db::host_findings(const std::string&, double, int, std::vector<FindingRow>&,
                       std::string& error) {
    error = "not connected";
    return false;
}
bool Db::hosts_affected(const std::string&, std::vector<FindingRow>&, std::string& error,
                        std::string*) {
    error = "not connected";
    return false;
}
bool Db::exec(const std::string&, std::string& error, std::string*) {
    error = "not connected";
    return false;
}
bool Db::scalar(const std::string&, std::int64_t&, std::string& error) {
    error = "not connected";
    return false;
}
bool Db::column(const std::string&, std::vector<std::string>&, std::string& error) {
    error = "not connected";
    return false;
}

ProcInfo self_info() {
    ProcInfo p;
    p.pid = static_cast<std::uint32_t>(getpid());
    return p;
}

} // namespace ns
