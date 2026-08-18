#include "ns/transport.hpp"

#include <algorithm>
#include <cstdlib>
#include <random>

namespace ns {

bool parse_url(const std::string& url, ParsedUrl& out, std::string& error) {
    const auto scheme_end = url.find("://");
    if (scheme_end == std::string::npos) {
        error = "url has no scheme: " + url;
        return false;
    }
    out.scheme = url.substr(0, scheme_end);
    if (out.scheme != "https") {
        // Refused rather than supported. An agent that will speak plaintext when
        // told to is one misconfiguration away from shipping a host's full
        // software inventory -- a target list -- over the wire in clear.
        error = "only https is supported, got: " + out.scheme;
        return false;
    }

    std::string rest = url.substr(scheme_end + 3);
    const auto slash = rest.find('/');
    std::string authority = rest;
    if (slash != std::string::npos) {
        authority = rest.substr(0, slash);
        out.path = rest.substr(slash);
    } else {
        out.path = "/";
    }

    const auto colon = authority.rfind(':');
    // rfind, then a digit check, so an IPv6 literal's colons are not mistaken
    // for a port separator.
    if (colon != std::string::npos &&
        authority.find_first_not_of("0123456789", colon + 1) == std::string::npos &&
        colon + 1 < authority.size()) {
        out.host = authority.substr(0, colon);
        out.port = std::atoi(authority.c_str() + colon + 1);
    } else {
        out.host = authority;
        out.port = 443;
    }

    if (out.host.empty()) {
        error = "url has no host: " + url;
        return false;
    }
    return true;
}

std::int64_t backoff_delay_ms(int attempt, std::int64_t base_ms, std::int64_t cap_ms) {
    if (attempt < 0) attempt = 0;
    // Shift rather than pow, and clamp the exponent before shifting: attempt=64
    // on a 64-bit shift is undefined behaviour, and a retry counter climbing
    // that high during a long outage is exactly when it would bite.
    const int exponent = std::min(attempt, 20);
    std::int64_t ceiling = base_ms << exponent;
    if (ceiling > cap_ms || ceiling <= 0) ceiling = cap_ms;

    // Full jitter: uniform in [0, ceiling]. See the header for why plain
    // doubling is the wrong choice for a fleet.
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    std::uniform_int_distribution<std::int64_t> dist(0, ceiling);
    return dist(rng);
}

} // namespace ns
