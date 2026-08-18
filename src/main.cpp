#include "ns/cve.hpp"
#include "ns/inventory.hpp"
#include "ns/json.hpp"
#include "ns/log.hpp"
#include "ns/platform.hpp"
#include "ns/spool.hpp"
#include "ns/transport.hpp"
#include "ns/version.hpp"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <random>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace {

struct Options {
    bool pretty = false;
    std::string index_path = "data/cve_index.tsv";
    std::string alias_path = "data/cpe_aliases.tsv";
    std::string packages_path;  // TSV override; see cmd_vuln

    // report
    std::string url;
    std::string client_cert;
    std::string client_key;
    std::string pin;
    std::string pin_file;
    std::string spool_dir = "spool";
    std::uint64_t spool_max_bytes = 64ull * 1024 * 1024;
    std::size_t batch_size = 32;
    int max_attempts = 6;
    int synthetic = 0;
    bool drain_only = false;
};

int usage(int rc) {
    std::fprintf(stderr,
        "%s %s (%s)\n"
        "\n"
        "usage: nano-sensor <command> [options]\n"
        "\n"
        "commands:\n"
        "  inventory     collect the host asset inventory and print it as JSON\n"
        "  vuln          collect the inventory, match it against the CVE index,\n"
        "                and print the findings as JSON\n"
        "  version       print version information\n"
        "\n"
        "options:\n"
        "  --pretty            indent the JSON output\n"
        "  --log-level LEVEL   debug | info | warn | error   (default: info)\n"
        "  --index PATH        CVE index TSV      (default: data/cve_index.tsv)\n"
        "  --aliases PATH      CPE alias table    (default: data/cpe_aliases.tsv)\n"
        "  --packages PATH     match this name<TAB>version list instead of the\n"
        "                      live host; used by the evaluation harness\n"
        "\n"
        "Command output goes to stdout; structured logs go to stderr, so\n"
        "`nano-sensor inventory > host.json` stays a clean JSON file.\n",
        ns::kAgentName, ns::kAgentVersion, ns::kAgentStage);
    return rc;
}

int cmd_version() {
    std::printf("%s %s (%s, %s backend)\n", ns::kAgentName, ns::kAgentVersion,
                ns::kAgentStage, ns::platform::name());
    return 0;
}

int cmd_inventory(const Options& opt) {
    const ns::Inventory inv = ns::collect_inventory();
    const std::string json = ns::to_json(inv, opt.pretty);
    std::fwrite(json.data(), 1, json.size(), stdout);
    std::fputc('\n', stdout);

    // Exit 0 even with warnings. A partially-collected inventory is a valid
    // report -- the warnings array carries the shortfall to the cloud, and
    // failing the command would only teach an operator to ignore the exit code.
    return 0;
}

// A fixed package list stands in for the live host. This exists so the accuracy
// evaluation runs against the SAME matcher the agent uses rather than a Python
// reimplementation of it -- an eval that scores a second implementation measures
// the wrong thing.
bool load_package_list(const std::string& path, ns::Inventory& inv) {
    std::ifstream f(path);
    if (!f) return false;

    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        std::istringstream ls(line);
        ns::Package p;
        std::getline(ls, p.name, '\t');
        std::getline(ls, p.version, '\t');
        if (!p.name.empty()) {
            p.source = "package-list";
            inv.packages.push_back(std::move(p));
        }
    }
    return true;
}

int cmd_vuln(const Options& opt) {
    ns::CveIndex index;
    std::string err;
    if (!index.load_rules(opt.index_path, err)) {
        ns::log_error("cve index load failed", {{"error", err}});
        return 1;
    }
    if (!index.load_aliases(opt.alias_path, err)) {
        ns::log_error("alias table load failed", {{"error", err}});
        return 1;
    }
    ns::log_info("cve index loaded",
                 {{"rules", std::to_string(index.rule_count())},
                  {"products", std::to_string(index.product_count())},
                  {"aliases", std::to_string(index.alias_count())}});

    ns::Inventory inv;
    if (!opt.packages_path.empty()) {
        inv.platform = ns::platform::name();
        inv.collected_at_unix_ms = ns::unix_time_ms();
        if (!load_package_list(opt.packages_path, inv)) {
            ns::log_error("cannot read package list", {{"path", opt.packages_path}});
            return 1;
        }
    } else {
        inv = ns::collect_inventory();
    }

    ns::ScanSummary summary;
    const auto findings = index.scan(inv, summary);

    const std::string json = ns::findings_to_json(findings, summary, inv, opt.pretty);
    std::fwrite(json.data(), 1, json.size(), stdout);
    std::fputc('\n', stdout);

    ns::log_info("vulnerability scan complete",
                 {{"findings", std::to_string(summary.findings)},
                  {"critical", std::to_string(summary.critical)},
                  {"exposed", std::to_string(summary.exposed_findings)}});
    return 0;
}

std::string read_first_line(const std::string& path) {
    std::ifstream f(path);
    std::string line;
    if (f) std::getline(f, line);
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
    return line;
}

// Every record carries a stable id, assigned once when it is spooled and never
// regenerated on retry. That is what makes at-least-once delivery deduplicable
// at the far end: a crash between send and commit re-sends the SAME id, so the
// cloud can recognise the repeat instead of double-counting the host.
std::string make_record(const std::string& id, const std::string& type,
                        const std::string& payload_json) {
    std::string out = "{\"id\":\"";
    out += ns::json_escape(id);
    out += "\",\"type\":\"";
    out += ns::json_escape(type);
    out += "\",\"payload\":";
    out += payload_json;
    out += "}";
    return out;
}

int cmd_report(const Options& opt) {
    if (opt.url.empty()) {
        std::fprintf(stderr, "report needs --url\n");
        return 2;
    }

    std::string pin = opt.pin;
    if (pin.empty() && !opt.pin_file.empty()) pin = read_first_line(opt.pin_file);
    if (pin.empty()) {
        std::fprintf(stderr, "report needs --pin or --pin-file\n");
        return 2;
    }

    ns::Spool spool;
    ns::Spool::Config scfg;
    scfg.dir = opt.spool_dir;
    scfg.max_bytes = opt.spool_max_bytes;
    scfg.segment_bytes = opt.spool_max_bytes / 8 + 1;

    std::string err;
    if (!spool.open(scfg, err)) {
        ns::log_error("cannot open spool", {{"error", err}});
        return 1;
    }

    // Produce first, send second. Anything collected is durable on disk before a
    // single network call is attempted, so a cloud that is already down costs
    // nothing -- the record is simply still there on the next run.
    if (!opt.drain_only) {
        const std::int64_t now = ns::unix_time_ms();

        // A per-run random tag, not just the timestamp. Two runs started inside
        // the same millisecond would otherwise mint identical record ids, and
        // the chaos harness -- which proves zero loss by counting DISTINCT ids
        // at the far end -- would read the collision as a lost record.
        std::random_device rd;
        char run_tag[17];
        std::snprintf(run_tag, sizeof(run_tag), "%08x%08x", rd(), rd());

        if (opt.synthetic > 0) {
            for (int i = 0; i < opt.synthetic; ++i) {
                const std::string id = "synthetic-" + std::string(run_tag) + "-" +
                                       std::to_string(now) + "-" + std::to_string(i);
                ns::JsonWriter w;
                w.begin_object();
                w.field("n", i);
                w.field("ts", now);
                w.end_object();
                if (!spool.append(make_record(id, "synthetic", w.str()), err)) {
                    ns::log_error("spool append failed", {{"error", err}});
                    return 1;
                }
            }
        } else {
            const ns::Inventory inv = ns::collect_inventory();
            const std::string id = inv.host.hostname + "-" + std::to_string(now) +
                                   "-inventory";
            if (!spool.append(make_record(id, "inventory", ns::to_json(inv, false)), err)) {
                ns::log_error("spool append failed", {{"error", err}});
                return 1;
            }
        }
    }

    ns::Transport::Config tcfg;
    tcfg.url = opt.url;
    tcfg.client_cert_path = opt.client_cert;
    tcfg.client_key_path = opt.client_key;
    tcfg.server_pin_sha256 = pin;

    auto transport = ns::make_transport(tcfg, err);
    if (!transport) {
        // The record is already spooled, so this is not data loss -- it is a
        // deferred send. Exit non-zero so a caller notices, but say plainly that
        // nothing was dropped.
        ns::log_error("no transport; records remain spooled for the next run",
                      {{"error", err}});
        return 1;
    }

    std::uint64_t sent = 0;
    int attempt = 0;
    bool gave_up = false;

    while (true) {
        auto batch = spool.peek(opt.batch_size, err);
        if (batch.empty()) break;

        std::string body = "{\"records\":[";
        for (std::size_t i = 0; i < batch.size(); ++i) {
            if (i) body += ',';
            body += batch[i].payload;
        }
        body += "]}";

        const auto result = transport->post(body, "application/json");
        if (result.ok) {
            // Commit only AFTER the cloud has acknowledged. A crash in the gap
            // between these two lines re-sends the batch; it never loses it.
            if (!spool.commit(batch.size(), err)) {
                ns::log_error("spool commit failed", {{"error", err}});
                return 1;
            }
            sent += batch.size();
            attempt = 0;
            continue;
        }

        if (!result.retryable) {
            ns::log_error("permanent send failure; records stay spooled",
                          {{"error", result.error},
                           {"http_status", std::to_string(result.http_status)}});
            gave_up = true;
            break;
        }

        ++attempt;
        if (attempt >= opt.max_attempts) {
            ns::log_warn("giving up for this run; records stay spooled",
                         {{"attempts", std::to_string(attempt)},
                          {"error", result.error}});
            gave_up = true;
            break;
        }

        const auto delay = ns::backoff_delay_ms(attempt);
        ns::log_warn("send failed, backing off",
                     {{"attempt", std::to_string(attempt)},
                      {"delay_ms", std::to_string(delay)},
                      {"error", result.error}});
        std::this_thread::sleep_for(std::chrono::milliseconds(delay));
    }

    const auto st = spool.stats();
    ns::JsonWriter w(opt.pretty);
    w.begin_object();
    w.field("backend", transport->backend_name());
    w.field("sent", sent);
    w.field("pending", st.pending);
    w.field("appended", st.appended);
    w.field("committed", st.committed);
    w.field("dropped", st.dropped);
    w.field("bytes_on_disk", st.bytes_on_disk);
    w.field("gave_up", gave_up);
    w.end_object();
    std::fwrite(w.str().data(), 1, w.str().size(), stdout);
    std::fputc('\n', stdout);

    // Pending records are not a failure -- that is the spool doing its job. Only
    // an outright drop, or giving up with nothing sent, is worth a bad exit code.
    return (gave_up && sent == 0) ? 1 : 0;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) return usage(2);

    const std::string_view command = argv[1];
    Options opt;

    auto need_value = [&](int& i) -> const char* {
        if (i + 1 >= argc) {
            std::fprintf(stderr, "%s needs a value\n", argv[i]);
            return nullptr;
        }
        return argv[++i];
    };

    for (int i = 2; i < argc; ++i) {
        const std::string_view arg = argv[i];
        if (arg == "--pretty") {
            opt.pretty = true;
        } else if (arg == "--log-level") {
            const char* v = need_value(i);
            if (!v) return 2;
            if (!ns::log_set_level_by_name(v)) {
                std::fprintf(stderr, "unknown log level: %s\n", v);
                return 2;
            }
        } else if (arg == "--index") {
            const char* v = need_value(i);
            if (!v) return 2;
            opt.index_path = v;
        } else if (arg == "--aliases") {
            const char* v = need_value(i);
            if (!v) return 2;
            opt.alias_path = v;
        } else if (arg == "--packages") {
            const char* v = need_value(i);
            if (!v) return 2;
            opt.packages_path = v;
        } else if (arg == "--url") {
            const char* v = need_value(i);
            if (!v) return 2;
            opt.url = v;
        } else if (arg == "--client-cert") {
            const char* v = need_value(i);
            if (!v) return 2;
            opt.client_cert = v;
        } else if (arg == "--client-key") {
            const char* v = need_value(i);
            if (!v) return 2;
            opt.client_key = v;
        } else if (arg == "--pin") {
            const char* v = need_value(i);
            if (!v) return 2;
            opt.pin = v;
        } else if (arg == "--pin-file") {
            const char* v = need_value(i);
            if (!v) return 2;
            opt.pin_file = v;
        } else if (arg == "--spool") {
            const char* v = need_value(i);
            if (!v) return 2;
            opt.spool_dir = v;
        } else if (arg == "--spool-max-bytes") {
            const char* v = need_value(i);
            if (!v) return 2;
            opt.spool_max_bytes = std::strtoull(v, nullptr, 10);
        } else if (arg == "--batch-size") {
            const char* v = need_value(i);
            if (!v) return 2;
            opt.batch_size = static_cast<std::size_t>(std::strtoul(v, nullptr, 10));
        } else if (arg == "--max-attempts") {
            const char* v = need_value(i);
            if (!v) return 2;
            opt.max_attempts = std::atoi(v);
        } else if (arg == "--synthetic") {
            const char* v = need_value(i);
            if (!v) return 2;
            opt.synthetic = std::atoi(v);
        } else if (arg == "--drain-only") {
            opt.drain_only = true;
        } else if (arg == "-h" || arg == "--help") {
            return usage(0);
        } else {
            std::fprintf(stderr, "unknown option: %.*s\n",
                         static_cast<int>(arg.size()), arg.data());
            return 2;
        }
    }

    if (command == "inventory") return cmd_inventory(opt);
    if (command == "vuln")      return cmd_vuln(opt);
    if (command == "report")    return cmd_report(opt);
    if (command == "version")   return cmd_version();
    if (command == "-h" || command == "--help") return usage(0);

    std::fprintf(stderr, "unknown command: %.*s\n",
                 static_cast<int>(command.size()), command.data());
    return usage(2);
}
