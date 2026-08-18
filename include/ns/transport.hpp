#pragma once

#include <memory>
#include <string>

namespace ns {

// HTTPS transport with mutual TLS.
//
// Server identity is established by PINNING the SHA-256 of the server's
// certificate, not by walking a chain to a platform trust store. That choice is
// deliberate and it is the same on both platforms:
//
//   * A sensor talks to exactly one cloud endpoint whose certificate its
//     operator controls. Pinning states that directly instead of trusting every
//     one of the ~150 CAs a stock OS ships with -- any of which can mint a
//     certificate for the endpoint's name.
//   * It needs no installation step. Chain validation against a private CA
//     means mutating the machine's trust store, which is an invasive thing for
//     an agent installer to do and a genuinely bad thing for a test harness to
//     do to a developer's laptop.
//   * It behaves identically under WinHTTP and OpenSSL, so the two backends
//     have one security model between them rather than two.
//
// The cost, stated plainly: certificate rotation requires shipping a new pin.
// That is the standard pinning tradeoff. Production agents usually pin the
// issuing CA's key rather than the leaf for exactly this reason; pinning the
// leaf here keeps the test harness to one generated certificate.
class Transport {
public:
    struct Config {
        std::string url;               // https://host:port/path
        std::string client_cert_path;  // PKCS#12 (.pfx) on Windows, PEM on Linux
        std::string client_key_path;   // PEM key (Linux only; the .pfx carries it)
        std::string server_pin_sha256; // hex SHA-256 of the server certificate (DER)
        int timeout_ms = 15000;
    };

    struct Result {
        bool ok = false;         // transport succeeded AND the status was 2xx
        int http_status = 0;
        std::string body;
        std::string error;

        // True for conditions where retrying the same payload later is sensible
        // -- connection refused, timeout, 5xx, proxy failure. False for a 4xx,
        // which will fail again identically and must not spin forever.
        bool retryable = false;
    };

    virtual ~Transport() = default;
    virtual Result post(const std::string& body, const std::string& content_type) = 0;
    virtual std::string backend_name() const = 0;
};

// Returns nullptr and sets `error` when the platform backend cannot be built
// (missing certificate file, unparseable URL, TLS library absent at build time).
std::unique_ptr<Transport> make_transport(const Transport::Config& cfg, std::string& error);

// Whether this build has a working TLS backend compiled in at all.
bool transport_available();

struct ParsedUrl {
    std::string scheme;
    std::string host;
    int port = 443;
    std::string path = "/";
};
bool parse_url(const std::string& url, ParsedUrl& out, std::string& error);

// Exponential backoff with full jitter, capped.
//
// Full jitter rather than plain doubling because every sensor in a fleet
// reconnects at once after a shared outage. Without jitter the fleet
// synchronises and the cloud gets a thundering herd on a doubling schedule --
// the retry logic becomes the second outage.
std::int64_t backoff_delay_ms(int attempt, std::int64_t base_ms = 1000,
                              std::int64_t cap_ms = 300000);

} // namespace ns
