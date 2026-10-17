#pragma once

#include "ns/inventory.hpp"
#include "ns/ipc.hpp"

#include <functional>
#include <memory>
#include <string>
#include <string_view>

namespace ns {

// Deliberate, documented bugs that can be switched back on at runtime, so the
// crash-dump tooling has something real to catch and the debugging write-ups
// in docs/DEBUGGING.md can be reproduced from a clean checkout. Each one is the
// buggy variant of a code path whose fixed variant is what normally runs.
enum class Fault {
    None,
    UseAfterFree,  // `scan` waiter freed on timeout while the worker still holds it
    Deadlock,      // lock-order inversion between the DB lock and the state lock
    WorkerCrash,   // vector::at() past the end on the scan worker thread
};

bool parse_fault(std::string_view name, Fault& out);
const char* fault_name(Fault f);

struct AgentConfig {
    std::string index_path = "data/cve_index.tsv";
    std::string alias_path = "data/cpe_aliases.tsv";
    std::string db_connection;  // empty: run without SQL Server
    std::string pipe_name = ipc::kDefaultPipe;
    std::string pipe_sddl;      // empty: ipc::default_sddl()
    int interval_s = 300;
    int hang_timeout_s = 120;   // a scan or pipe request older than this = hang
    Fault fault = Fault::None;

    // Called on the worker thread with each fresh inventory; `run` wires the
    // spool + mTLS reporter in here when --url is given.
    std::function<void(const Inventory&)> on_inventory;
};

// The service: a scan worker thread, the control pipe, and a hang watchdog.
//
//   worker   collect inventory -> CVE match -> SQL Server -> telemetry hook,
//            every interval_s or on demand (`nsctl scan`)
//   pipe     answers nsctl: status / scan / findings / affected / dump
//   watchdog any scan or request running longer than hang_timeout_s gets a
//            hang dump written and the process killed, so the SCM's restart
//            policy brings back a working agent instead of a wedged one
class Agent {
public:
    explicit Agent(AgentConfig cfg);
    ~Agent();
    Agent(const Agent&) = delete;
    Agent& operator=(const Agent&) = delete;

    bool start(std::string& error);
    void stop();

    // Pipe request handler. Public so tests can drive it without a pipe.
    std::string handle(const std::string& request, const ipc::ClientInfo& who);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace ns
