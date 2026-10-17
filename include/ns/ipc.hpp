#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>

namespace ns::ipc {

// Local control channel between the service and `nsctl`: a Windows named pipe.
//
// Why a named pipe and not a localhost TCP port: a pipe has a security
// descriptor, so the kernel enforces who may connect before the service reads
// a byte; a TCP port is open to every local process, and authenticating on it
// would be the service's own (and probably buggier) job.
//
// Protocol: message-mode pipe, one request message, one response message.
// Requests are short text commands ("status", "findings 7.0 20"); responses
// are JSON.

inline constexpr const char* kDefaultPipe = R"(\\.\pipe\nano-sensor)";

// The DACL every pipe instance gets, in SDDL:
//
//   D:P                 protected DACL, nothing inherited
//   (D;;GA;;;NU)        deny anyone holding the NETWORK logon SID
//   (A;;GA;;;SY)        allow LocalSystem
//   (A;;GA;;;BA)        allow BUILTIN\Administrators -- an *elevated* admin;
//                       an unelevated one has this SID as deny-only
//   (A;;GA;;;OW)        allow OWNER RIGHTS, i.e. whoever created the pipe --
//                       the service's own virtual account in production
//
// Everyone else -- standard users, unelevated admins, other services, a
// sandboxed browser -- is refused by the kernel with ERROR_ACCESS_DENIED.
// The OW entry is not decoration: creating the second pipe instance needs
// FILE_CREATE_PIPE_INSTANCE on this same DACL, so without it the service
// could create exactly one instance and then lock itself out.
std::string default_sddl();

struct ClientInfo {
    std::uint32_t pid = 0;
    std::string user;  // DOMAIN\name, read by impersonating the caller
};

using Handler = std::function<std::string(const std::string& request, const ClientInfo&)>;

class Server {
public:
    Server();
    ~Server();
    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;

    // Creates the first pipe instance synchronously, so a name clash or bad
    // SDDL fails here rather than later on a background thread. The first
    // instance is created with FILE_FLAG_FIRST_PIPE_INSTANCE: if any process
    // already owns this pipe name -- a squatter waiting to read requests
    // meant for the service -- start() fails instead of quietly joining it.
    bool start(const std::string& pipe_name, const std::string& sddl, Handler handler,
               std::string& error);

    // Stops accepting, cancels blocked I/O, joins every thread.
    void stop();

    std::uint64_t requests_served() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// Sends one request and waits for the response.
//
// The client opens the pipe at SECURITY_IDENTIFICATION impersonation level:
// the server may learn who the caller is (and does, to log it) but cannot act
// as the caller. If something else squats the pipe name, it gets an identity,
// not the admin's token.
bool call(const std::string& pipe_name, const std::string& request, std::string& response,
          std::string& error, std::uint32_t timeout_ms = 5000);

// Win32 error code of the last failed call() on this thread (0 if none).
// Tests use it to assert "access denied" specifically, not just "failed".
std::uint32_t last_call_error();

} // namespace ns::ipc
