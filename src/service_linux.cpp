#include "ns/service.hpp"

#include "ns/log.hpp"

#include <csignal>
#include <cstring>

namespace ns::service {

namespace {

// sig_atomic_t, not bool or std::atomic<bool>: this is written from a signal
// handler, and volatile sig_atomic_t is the only type the C++ standard says a
// handler may touch. std::atomic is lock-free in practice here but is not
// formally async-signal-safe.
volatile std::sig_atomic_t g_stop = 0;

extern "C" void handle_signal(int) {
    // Nothing but a flag store. Logging from a signal handler means calling
    // malloc and stdio, neither of which is async-signal-safe, and a sensor that
    // deadlocks in its own shutdown path is a support call nobody can diagnose.
    g_stop = 1;
}

} // namespace

const char* name() { return "nano-sensor"; }

bool stop_requested() { return g_stop != 0; }
void request_stop() { g_stop = 1; }

int run(const std::function<int()>& body) {
    struct sigaction sa {};
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    // No SA_RESTART: a blocking read in the middle of a collection should return
    // EINTR so the loop notices the stop promptly, rather than restarting the
    // syscall and making shutdown wait for it.
    sa.sa_flags = 0;

    // SIGTERM is what systemd sends on `systemctl stop`. SIGINT is Ctrl+C.
    ::sigaction(SIGTERM, &sa, nullptr);
    ::sigaction(SIGINT, &sa, nullptr);

    // SIGPIPE would otherwise kill the process outright the first time the cloud
    // closes a connection mid-write -- a routine event during an outage, and one
    // the transport already reports as a retryable error.
    struct sigaction ignore {};
    ignore.sa_handler = SIG_IGN;
    sigemptyset(&ignore.sa_mask);
    ::sigaction(SIGPIPE, &ignore, nullptr);

    return body();
}

bool install(const std::string&, const std::string&, std::string& error) {
    // Deliberately not implemented. On Linux the unit file is packaging's job
    // (deploy/nano-sensor.service), not the binary's -- an agent that writes
    // into /etc/systemd/system at runtime is doing the package manager's work
    // badly and cannot be cleanly uninstalled.
    error = "install the systemd unit from deploy/nano-sensor.service instead";
    return false;
}

bool uninstall(std::string& error) {
    error = "remove the systemd unit with systemctl disable --now nano-sensor";
    return false;
}

} // namespace ns::service
