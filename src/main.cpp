#include "ns/inventory.hpp"
#include "ns/log.hpp"
#include "ns/platform.hpp"
#include "ns/version.hpp"

#include <cstdio>
#include <string>
#include <string_view>
#include <vector>

namespace {

int usage(int rc) {
    std::fprintf(stderr,
        "%s %s (%s)\n"
        "\n"
        "usage: nano-sensor <command> [options]\n"
        "\n"
        "commands:\n"
        "  inventory     collect the host asset inventory and print it as JSON\n"
        "  version       print version information\n"
        "\n"
        "options:\n"
        "  --pretty            indent the JSON output\n"
        "  --log-level LEVEL   debug | info | warn | error   (default: info)\n"
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

int cmd_inventory(bool pretty) {
    const ns::Inventory inv = ns::collect_inventory();
    const std::string json = ns::to_json(inv, pretty);
    std::fwrite(json.data(), 1, json.size(), stdout);
    std::fputc('\n', stdout);

    // Exit 0 even with warnings. A partially-collected inventory is a valid
    // report -- the warnings array carries the shortfall to the cloud, and
    // failing the command would only teach an operator to ignore the exit code.
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) return usage(2);

    const std::string_view command = argv[1];
    bool pretty = false;

    for (int i = 2; i < argc; ++i) {
        const std::string_view arg = argv[i];
        if (arg == "--pretty") {
            pretty = true;
        } else if (arg == "--log-level") {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "--log-level needs a value\n");
                return 2;
            }
            if (!ns::log_set_level_by_name(argv[++i])) {
                std::fprintf(stderr, "unknown log level: %s\n", argv[i]);
                return 2;
            }
        } else if (arg == "-h" || arg == "--help") {
            return usage(0);
        } else {
            std::fprintf(stderr, "unknown option: %.*s\n",
                         static_cast<int>(arg.size()), arg.data());
            return 2;
        }
    }

    if (command == "inventory") return cmd_inventory(pretty);
    if (command == "version")   return cmd_version();
    if (command == "-h" || command == "--help") return usage(0);

    std::fprintf(stderr, "unknown command: %.*s\n",
                 static_cast<int>(command.size()), command.data());
    return usage(2);
}
