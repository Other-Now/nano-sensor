#include "test_util.hpp"

#include "ns/transport.hpp"

#include <set>

using ns::backoff_delay_ms;
using ns::parse_url;
using ns::ParsedUrl;

NS_TEST(url_parsing) {
    ParsedUrl u;
    std::string err;

    CHECK(parse_url("https://cloud.example.com/v1/events", u, err));
    CHECK_EQ(u.host, std::string("cloud.example.com"));
    CHECK_EQ(u.port, 443);
    CHECK_EQ(u.path, std::string("/v1/events"));

    CHECK(parse_url("https://127.0.0.1:8443/ingest", u, err));
    CHECK_EQ(u.host, std::string("127.0.0.1"));
    CHECK_EQ(u.port, 8443);
    CHECK_EQ(u.path, std::string("/ingest"));

    // No path given: default to "/", not to empty, or the request line is
    // malformed and the server answers 400.
    CHECK(parse_url("https://host.example", u, err));
    CHECK_EQ(u.path, std::string("/"));
}

NS_TEST(url_rejects_plaintext) {
    ParsedUrl u;
    std::string err;
    // An agent that speaks http when told to is one config typo away from
    // shipping a host's full software inventory -- a target list -- in clear.
    CHECK(!parse_url("http://cloud.example.com/v1/events", u, err));
    CHECK(!err.empty());
    CHECK(!parse_url("cloud.example.com/v1/events", u, err));
}

NS_TEST(url_ipv6_colons_are_not_a_port) {
    ParsedUrl u;
    std::string err;
    CHECK(parse_url("https://[2001:db8::1]/x", u, err));
    CHECK_EQ(u.port, 443);
}

NS_TEST(backoff_is_bounded_and_grows) {
    // Full jitter means any single sample can be small, so the property to test
    // is the CEILING, not the value.
    for (int attempt = 0; attempt < 40; ++attempt) {
        for (int i = 0; i < 50; ++i) {
            const auto d = backoff_delay_ms(attempt, 1000, 300000);
            CHECK(d >= 0);
            CHECK(d <= 300000);
        }
    }
}

NS_TEST(backoff_does_not_overflow_on_long_outages) {
    // A sensor offline for hours reaches high attempt counts. Shifting by 64 is
    // undefined behaviour, and a negative or wrapped delay would either spin the
    // retry loop hot or sleep effectively forever.
    for (int attempt : {50, 63, 64, 100, 1000}) {
        const auto d = backoff_delay_ms(attempt, 1000, 300000);
        CHECK(d >= 0);
        CHECK(d <= 300000);
    }
}

NS_TEST(backoff_is_actually_jittered) {
    // If every sensor in a fleet computed the same delay, a shared outage would
    // be followed by a synchronised thundering herd. Distinct samples are the
    // observable consequence of the jitter that prevents it.
    std::set<std::int64_t> seen;
    for (int i = 0; i < 200; ++i) seen.insert(backoff_delay_ms(8, 1000, 300000));
    CHECK(seen.size() > 50);
}
