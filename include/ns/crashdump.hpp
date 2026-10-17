#pragma once

#include <cstdint>
#include <string>

namespace ns::crashdump {

// Post-mortem evidence for a process nobody is watching.
//
// A service that crashes at 3am on a customer's host leaves nothing behind
// except "the service terminated unexpectedly" in the event log. A minidump
// plus the matching PDB turns that into a call stack, locals and the faulting
// instruction, which is the difference between a fix and a guess.
//
// install() routes every way this process can die into one dump writer:
//   - an SEH exception nobody handled, on ANY thread (access violation, ...)
//   - std::terminate (an exception escaping a thread or a noexcept function)
//   - a pure virtual call and a CRT invalid-parameter abort
//
// Dumps are written to <dir>/nano-sensor-<pid>-<unix_ms>-<reason>.dmp.
// Windows only; a no-op that returns false elsewhere.
bool install(const std::string& dir);

// MSVC keeps the terminate handler per thread, so a std::thread started after
// install() still has the CRT default -- abort() -- and dies without a dump.
// Every thread this agent starts calls this first. See docs/DEBUGGING.md, bug 3,
// for how that was found.
void on_thread_start();

// Writes a dump of this process right now without killing it. Used by the
// hang watchdog and by `nsctl dump`. Returns the path written.
bool write_now(const std::string& reason, std::string& path_out, std::string& error);

// Number of dumps written by this process so far.
std::uint32_t dumps_written();

} // namespace ns::crashdump
