#include "test_util.hpp"

#include "ns/cve.hpp"

#include <cstdio>
#include <fstream>
#include <string>

using ns::CveIndex;
using ns::Package;

namespace {

// The tests build their own tiny index rather than loading data/cve_index.tsv.
// A test that depends on the downloaded corpus would change its result whenever
// NVD publishes an advisory, which makes it a monitor of NIST rather than a test
// of this code.
struct TempFile {
    std::string path;
    explicit TempFile(const char* stem, const std::string& contents) {
        path = std::string(stem) + "_" + std::to_string(std::rand()) + ".tsv";
        std::ofstream f(path, std::ios::binary);
        f << contents;
    }
    ~TempFile() { std::remove(path.c_str()); }
};

const char* kHeader =
    "cve_id\tvendor\tproduct\tversion\tupdate\tstart_incl\tstart_excl\t"
    "end_incl\tend_excl\tcvss_score\tcvss_severity\tcvss_version\n";

std::string rules() {
    std::string s = kHeader;
    // A closed range: affects [1.1.1, 1.1.1t)
    s += "CVE-0001\topenssl\topenssl\t*\t*\t1.1.1\t\t\t1.1.1t\t7.5\tHIGH\t3.1\n";
    // An exact-version rule.
    s += "CVE-0002\topenbsd\topenssh\t8.9p1\t*\t\t\t\t\t9.8\tCRITICAL\t3.1\n";
    // Unbounded: every version of the product is affected.
    s += "CVE-0003\tredis\tredis\t*\t*\t\t\t\t\t5.0\tMEDIUM\t3.1\n";
    // Two rules for one CVE, different scores -- the higher must win.
    s += "CVE-0004\tnginx\tnginx\t*\t*\t\t\t\t1.20\t4.0\tMEDIUM\t3.1\n";
    s += "CVE-0004\tnginx\tnginx\t*\t*\t\t\t\t1.25\t8.1\tHIGH\t3.1\n";
    return s;
}

std::string aliases() {
    return "exact\topenssl\topenssl\topenssl\n"
           "prefix\tlibssl\topenssl\topenssl\n"
           "exact\topenssh\topenbsd\topenssh\n"
           "prefix\topenssh-\topenbsd\topenssh\n"
           "exact\tredis\tredis\tredis\n"
           "exact\tnginx\tnginx\tnginx\n";
}

CveIndex make_index(const std::string& rules_path, const std::string& alias_path) {
    CveIndex idx;
    std::string err;
    if (!idx.load_rules(rules_path, err)) ::nstest::fail(__FILE__, __LINE__, err);
    if (!idx.load_aliases(alias_path, err)) ::nstest::fail(__FILE__, __LINE__, err);
    return idx;
}

Package pkg(const char* name, const char* version) {
    Package p;
    p.name = name;
    p.version = version;
    return p;
}

} // namespace

NS_TEST(cve_normalize_windows_display_names) {
    CHECK_EQ(CveIndex::normalize_name("Python 3.12.1 (64-bit)"), std::string("python"));
    CHECK_EQ(CveIndex::normalize_name("7-Zip 23.01 (x64)"), std::string("7-zip"));
    CHECK_EQ(CveIndex::normalize_name("Mozilla Firefox (x64 en-US)"),
             std::string("mozilla firefox"));
    CHECK_EQ(CveIndex::normalize_name("Git"), std::string("git"));
    CHECK_EQ(CveIndex::normalize_name("Oracle VM VirtualBox 7.0.12"),
             std::string("oracle vm virtualbox"));
    // A version token must not eat a product name that merely contains digits.
    CHECK_EQ(CveIndex::normalize_name("7-Zip"), std::string("7-zip"));
}

NS_TEST(cve_resolve_exact_and_prefix) {
    TempFile r("ns_rules", rules()), a("ns_alias", aliases());
    const auto idx = make_index(r.path, a.path);

    std::string vendor, product;
    CHECK(idx.resolve("openssl", vendor, product));
    CHECK_EQ(vendor, std::string("openssl"));
    CHECK_EQ(product, std::string("openssl"));

    // Debian splits the library out as libssl3; the prefix rule has to cover it.
    CHECK(idx.resolve("libssl3", vendor, product));
    CHECK_EQ(product, std::string("openssl"));

    CHECK(idx.resolve("openssh-server", vendor, product));
    CHECK_EQ(product, std::string("openssh"));

    CHECK(!idx.resolve("some-package-nobody-mapped", vendor, product));
}

NS_TEST(cve_range_matching) {
    TempFile r("ns_rules", rules()), a("ns_alias", aliases());
    const auto idx = make_index(r.path, a.path);

    // Inside [1.1.1, 1.1.1t): vulnerable.
    CHECK_EQ(idx.match_package(pkg("openssl", "1.1.1f")).size(), std::size_t(1));
    // At the exclusive upper bound: patched, and must NOT be reported.
    CHECK_EQ(idx.match_package(pkg("openssl", "1.1.1t")).size(), std::size_t(0));
    // Above the range.
    CHECK_EQ(idx.match_package(pkg("openssl", "3.0.2")).size(), std::size_t(0));
    // Below the range.
    CHECK_EQ(idx.match_package(pkg("openssl", "1.0.2k")).size(), std::size_t(0));
}

NS_TEST(cve_exact_version_rule) {
    TempFile r("ns_rules", rules()), a("ns_alias", aliases());
    const auto idx = make_index(r.path, a.path);

    CHECK_EQ(idx.match_package(pkg("openssh", "8.9p1")).size(), std::size_t(1));
    CHECK_EQ(idx.match_package(pkg("openssh", "8.9p2")).size(), std::size_t(0));
    // The Debian packaging revision must be stripped before comparison, or a
    // real match is missed.
    CHECK_EQ(idx.match_package(pkg("openssh-server", "1:8.9p1-3ubuntu0.4")).size(),
             std::size_t(1));
}

NS_TEST(cve_unbounded_rule_matches_every_version) {
    TempFile r("ns_rules", rules()), a("ns_alias", aliases());
    const auto idx = make_index(r.path, a.path);
    CHECK_EQ(idx.match_package(pkg("redis", "0.1")).size(), std::size_t(1));
    CHECK_EQ(idx.match_package(pkg("redis", "99.0")).size(), std::size_t(1));
}

NS_TEST(cve_duplicate_cve_keeps_highest_score) {
    TempFile r("ns_rules", rules()), a("ns_alias", aliases());
    const auto idx = make_index(r.path, a.path);

    const auto found = idx.match_package(pkg("nginx", "1.18"));
    CHECK_EQ(found.size(), std::size_t(1));  // one CVE, not two rows
    if (!found.empty()) {
        CHECK_EQ(found[0].cve_id, std::string("CVE-0004"));
        CHECK_EQ(found[0].cvss_score, 8.1);
        CHECK_EQ(found[0].cvss_severity, std::string("high"));
    }
}

NS_TEST(cve_unversioned_package_is_not_matched) {
    TempFile r("ns_rules", rules()), a("ns_alias", aliases());
    const auto idx = make_index(r.path, a.path);
    // No version means no defensible comparison. Reporting every CVE for the
    // product would be the "confidently wrong" failure mode.
    CHECK_EQ(idx.match_package(pkg("openssl", "")).size(), std::size_t(0));
}

NS_TEST(cve_scan_counts_unmapped_packages) {
    TempFile r("ns_rules", rules()), a("ns_alias", aliases());
    const auto idx = make_index(r.path, a.path);

    ns::Inventory inv;
    inv.packages.push_back(pkg("openssl", "1.1.1f"));
    inv.packages.push_back(pkg("totally-unknown-thing", "1.0"));
    inv.packages.push_back(pkg("redis", ""));  // mapped but unversioned

    ns::ScanSummary s;
    const auto found = idx.scan(inv, s);

    CHECK_EQ(s.packages_total, std::size_t(3));
    CHECK_EQ(s.packages_mapped, std::size_t(2));
    CHECK_EQ(s.packages_unmapped, std::size_t(1));
    CHECK_EQ(s.packages_no_version, std::size_t(1));
    CHECK_EQ(found.size(), std::size_t(1));
}

NS_TEST(cve_exposure_join_uses_listening_sockets) {
    TempFile r("ns_rules", rules()), a("ns_alias", aliases());
    const auto idx = make_index(r.path, a.path);

    ns::Inventory inv;
    inv.packages.push_back(pkg("nginx", "1.18"));

    ns::ListeningSocket loopback;
    loopback.proto = "tcp";
    loopback.local_addr = "127.0.0.1";
    loopback.local_port = 80;
    loopback.process_name = "nginx";
    loopback.world_reachable = false;
    inv.sockets.push_back(loopback);

    ns::ScanSummary s1;
    auto found = idx.scan(inv, s1);
    CHECK_EQ(found.size(), std::size_t(1));
    // Bound to loopback only: vulnerable, but not exposed.
    if (!found.empty()) CHECK(!found[0].network_exposed);
    CHECK_EQ(s1.exposed_findings, std::size_t(0));

    inv.sockets[0].local_addr = "0.0.0.0";
    inv.sockets[0].world_reachable = true;

    ns::ScanSummary s2;
    found = idx.scan(inv, s2);
    if (!found.empty()) CHECK(found[0].network_exposed);
    CHECK_EQ(s2.exposed_findings, std::size_t(1));
}

NS_TEST(cve_rejects_index_with_wrong_header) {
    TempFile bad("ns_bad", "not\ta\tvalid\theader\n");
    CveIndex idx;
    std::string err;
    // A silently-accepted column reordering would shift every field by one and
    // produce a matcher that is confidently wrong, so this must fail loudly.
    CHECK(!idx.load_rules(bad.path, err));
    CHECK(!err.empty());
}
