#include "ns/inventory.hpp"

#include "ns/json.hpp"
#include "ns/log.hpp"
#include "ns/platform.hpp"
#include "ns/version.hpp"

#include <chrono>

namespace ns {

std::int64_t unix_time_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

namespace {

void fold(std::vector<std::string>& into, const char* collector,
          const platform::Status& st) {
    if (!st.implemented) {
        into.push_back(std::string(collector) + ": not implemented on " +
                       platform::name() + " yet");
        return;
    }
    for (const auto& w : st.warnings) {
        into.push_back(std::string(collector) + ": " + w);
    }
}

} // namespace

Inventory collect_inventory() {
    const auto started = std::chrono::steady_clock::now();

    Inventory inv;
    inv.agent_name = kAgentName;
    inv.agent_version = kAgentVersion;
    inv.agent_stage = kAgentStage;
    inv.platform = platform::name();
    inv.collected_at_unix_ms = unix_time_ms();

    fold(inv.warnings, "host",       platform::collect_host(inv.host));
    fold(inv.warnings, "interfaces", platform::collect_interfaces(inv.interfaces));
    fold(inv.warnings, "sockets",    platform::collect_listening_sockets(inv.sockets));
    fold(inv.warnings, "processes",  platform::collect_processes(inv.processes));
    fold(inv.warnings, "packages",   platform::collect_packages(inv.packages));

    inv.collect_duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                  std::chrono::steady_clock::now() - started)
                                  .count();

    log_info("inventory collected",
             {{"platform", inv.platform},
              {"warnings", std::to_string(inv.warnings.size())}});
    return inv;
}

std::string to_json(const Inventory& inv, bool pretty) {
    JsonWriter w(pretty);
    w.begin_object();

    w.begin_object("agent");
    w.field("name", inv.agent_name);
    w.field("version", inv.agent_version);
    w.field("stage", inv.agent_stage);
    w.field("platform", inv.platform);
    w.end_object();

    w.field("collected_at_unix_ms", inv.collected_at_unix_ms);
    w.field("collect_duration_ms", inv.collect_duration_ms);

    w.begin_object("host");
    w.field("hostname", inv.host.hostname);
    w.field("os_name", inv.host.os_name);
    w.field("os_version", inv.host.os_version);
    w.field("kernel", inv.host.kernel);
    w.field("arch", inv.host.arch);
    w.end_object();

    w.begin_array("interfaces");
    for (const auto& i : inv.interfaces) {
        w.begin_object();
        w.field("name", i.name);
        w.field("mac", i.mac);
        w.begin_array("addresses");
        for (const auto& a : i.addresses) w.value(a);
        w.end_array();
        w.field("up", i.up);
        w.field("loopback", i.loopback);
        w.end_object();
    }
    w.end_array();

    w.begin_array("listening_sockets");
    for (const auto& s : inv.sockets) {
        w.begin_object();
        w.field("proto", s.proto);
        w.field("local_addr", s.local_addr);
        w.field("local_port", s.local_port);
        if (s.pid >= 0) w.field("pid", s.pid); else w.field_null("pid");
        w.field("process_name", s.process_name);
        w.field("world_reachable", s.world_reachable);
        w.end_object();
    }
    w.end_array();

    w.begin_array("processes");
    for (const auto& p : inv.processes) {
        w.begin_object();
        w.field("pid", p.pid);
        w.field("ppid", p.ppid);
        w.field("name", p.name);
        w.field("exe_path", p.exe_path);
        w.field("user", p.user);
        w.end_object();
    }
    w.end_array();

    w.begin_array("packages");
    for (const auto& p : inv.packages) {
        w.begin_object();
        w.field("name", p.name);
        w.field("version", p.version);
        w.field("vendor", p.vendor);
        w.field("source", p.source);
        w.end_object();
    }
    w.end_array();

    w.begin_array("warnings");
    for (const auto& x : inv.warnings) w.value(x);
    w.end_array();

    w.end_object();
    return w.str();
}

} // namespace ns
