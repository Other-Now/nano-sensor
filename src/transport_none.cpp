// Fallback transport for builds with no TLS library available.
//
// It exists so that `nano-sensor inventory` and `nano-sensor vuln` still build
// and run on a machine without OpenSSL headers, rather than the whole agent
// failing to compile. It never sends anything, and it says so loudly instead of
// pretending to succeed -- a transport that silently discards telemetry is the
// worst possible failure for a security sensor.

#include "ns/transport.hpp"

namespace ns {

namespace {

class NoTransport : public Transport {
public:
    std::string backend_name() const override { return "none"; }

    Result post(const std::string&, const std::string&) override {
        Result r;
        r.ok = false;
        r.error = "this build has no TLS backend: OpenSSL was not found at configure time";
        r.retryable = false;  // rebuilding is the fix; retrying is not
        return r;
    }
};

} // namespace

bool transport_available() { return false; }

std::unique_ptr<Transport> make_transport(const Transport::Config&, std::string& error) {
    error = "no TLS backend compiled in (install libssl-dev and reconfigure)";
    return std::make_unique<NoTransport>();
}

} // namespace ns
