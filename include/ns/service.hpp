#pragma once

#include <functional>
#include <string>

namespace ns {

// Long-running-service plumbing, kept behind one small interface so the agent
// loop itself contains no platform code.
//
// The two platforms disagree about what a service IS. systemd runs an ordinary
// foreground process and signals it; the Windows SCM requires the process to
// call StartServiceCtrlDispatcher, hand over its main thread, and then report
// state transitions back. The shape below is the smaller of the two, with the
// Windows side adapting to it.
namespace service {

// True once a stop has been requested -- SIGTERM/SIGINT on Linux,
// SERVICE_CONTROL_STOP from the SCM on Windows. The agent loop polls this and
// finishes the current cycle rather than dying mid-write, which matters: a
// service killed between spool append and state save re-sends a batch, and a
// service killed during collection wastes the cycle.
bool stop_requested();

// Requests a stop from inside the process (used by tests and by the Windows
// control handler).
void request_stop();

// Runs `body` under whatever supervisor is present.
//
// On Linux this installs signal handlers and calls body() directly. On Windows
// it first tries to attach to the SCM; if that fails with
// ERROR_FAILED_SERVICE_CONTROLLER_CONNECT -- which is what happens when the
// binary is started from a console rather than by the SCM -- it falls back to
// running body() in the foreground. That is what lets ONE binary be both the
// service and the interactive command without a separate service host.
int run(const std::function<int()>& body);

// Windows service registration. Both need Administrator; both are no-ops that
// report failure on Linux, where packaging owns the unit file instead.
bool install(const std::string& exe_path, const std::string& arguments,
             std::string& error);
bool uninstall(std::string& error);

// Name under which the service registers.
const char* name();

} // namespace service
} // namespace ns
