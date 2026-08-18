#include "ns/cve.hpp"
#include "ns/inventory.hpp"
#include "ns/log.hpp"
#include "ns/platform.hpp"
#include "ns/version.hpp"

#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace {

struct Options {
    bool pretty = false;
    std::string index_path = "data/cve_index.tsv";
    std::string alias_path = "data/cpe_aliases.tsv";
    std::string packages_path;  // TSV override; see cmd_vuln
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
    if (command == "version")   return cmd_version();
    if (command == "-h" || command == "--help") return usage(0);

    std::fprintf(stderr, "unknown command: %.*s\n",
                 static_cast<int>(command.size()), command.data());
    return usage(2);
}
