// nsctl -- the console client for the nano-sensor service.
//
// A separate process on purpose. The service runs as a low-privilege virtual
// account and owns the scanner, the database connection and the crash
// handling; this client owns nothing and can be killed, crash, or be run by
// the wrong user without affecting the service. All it can do is send the
// requests the pipe's DACL lets its caller send.

#include "ns/ipc.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>

namespace {

int usage(int rc) {
    std::fprintf(stderr,
        "usage: nsctl <command> [args] [--pipe NAME] [--timeout MS]\n"
        "\n"
        "commands:\n"
        "  ping                       is the service there?\n"
        "  status                     identity, memory, last scan, database\n"
        "  scan [wait_ms]             scan now; wait up to wait_ms for the result\n"
        "  findings [min_cvss] [n]    this host's latest findings, worst first\n"
        "  affected CVE-YYYY-NNNN     every host whose latest scan has this CVE\n"
        "  dump                       write a minidump of the running service\n"
        "\n"
        "The pipe admits SYSTEM, elevated Administrators and the service itself.\n");
    return rc;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) return usage(2);

    std::string pipe = ns::ipc::kDefaultPipe;
    std::uint32_t timeout_ms = 10000;
    std::string request;

    for (int i = 1; i < argc; ++i) {
        const std::string_view a = argv[i];
        if (a == "--pipe" && i + 1 < argc) {
            pipe = argv[++i];
        } else if (a == "--timeout" && i + 1 < argc) {
            timeout_ms = static_cast<std::uint32_t>(std::strtoul(argv[++i], nullptr, 10));
        } else if (a == "-h" || a == "--help") {
            return usage(0);
        } else {
            if (!request.empty()) request += ' ';
            request += a;
        }
    }

    // A scan can legitimately take as long as the caller asked to wait.
    if (request.rfind("scan", 0) == 0) {
        const auto sp = request.find(' ');
        const unsigned long wait = sp == std::string::npos
                                       ? 30000
                                       : std::strtoul(request.c_str() + sp + 1, nullptr, 10);
        if (wait + 5000 > timeout_ms) timeout_ms = static_cast<std::uint32_t>(wait + 5000);
    }

    std::string response, error;
    if (!ns::ipc::call(pipe, request, response, error, timeout_ms)) {
        std::fprintf(stderr, "nsctl: %s\n", error.c_str());
        if (ns::ipc::last_call_error() == 5) {
            std::fprintf(stderr,
                         "nsctl: the service only answers SYSTEM, elevated Administrators "
                         "and itself -- run from an elevated prompt.\n");
        }
        return 1;
    }
    std::fwrite(response.data(), 1, response.size(), stdout);
    std::fputc('\n', stdout);
    return response.rfind("{\"error\"", 0) == 0 ? 1 : 0;
}
