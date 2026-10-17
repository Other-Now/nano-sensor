#include <gtest/gtest.h>

#include "ns/db.hpp"

#include <cstdlib>
#include <random>
#include <string>

// Runs against a real SQL Server when NS_TEST_DB holds an ODBC connection
// string to a database created by tools/db/schema.sql; skipped otherwise (CI
// has no SQL Server). A mocked ODBC layer would test the mock -- the things
// worth testing here are binding, transactions and Unicode, which only the
// real driver exercises.

namespace {

struct DbTest : ::testing::Test {
    ns::Db db;
    std::string host;

    void SetUp() override {
#pragma warning(suppress : 4996)  // getenv: read once, not retained
        const char* cs = std::getenv("NS_TEST_DB");
        if (!cs || !*cs) GTEST_SKIP() << "NS_TEST_DB not set";
        std::string err;
        ASSERT_TRUE(db.connect(cs, err)) << err;
        std::random_device rd;
        host = "gtest-" + std::to_string(rd()) + std::to_string(rd());
    }

    void TearDown() override {
        if (!db.connected()) return;
        // The agent's own login cannot DELETE; the test login can. Child rows
        // first -- the foreign keys are real.
        std::string err;
        const std::string scans =
            "(SELECT s.scan_id FROM dbo.scans s JOIN dbo.hosts h ON h.host_id = s.host_id "
            "WHERE h.hostname LIKE 'gtest-%')";
        db.exec("DELETE FROM dbo.findings WHERE scan_id IN " + scans, err);
        db.exec("DELETE FROM dbo.packages WHERE scan_id IN " + scans, err);
        db.exec("UPDATE dbo.hosts SET latest_scan_id = NULL WHERE hostname LIKE 'gtest-%'", err);
        db.exec("DELETE FROM dbo.scans WHERE scan_id IN " + scans, err);
        db.exec("DELETE FROM dbo.hosts WHERE hostname LIKE 'gtest-%'", err);
    }

    ns::Inventory inventory() const {
        ns::Inventory inv;
        inv.host.hostname = host;
        inv.host.os_name = "Windows 11";
        inv.host.os_version = "10.0.26200";
        inv.collected_at_unix_ms = 1760000000123;
        return inv;
    }

    static ns::Finding finding(const char* cve, const std::string& pkg, double cvss,
                               const char* sev) {
        ns::Finding f;
        f.cve_id = cve;
        f.package_name = pkg;
        f.package_version = "1.0";
        f.cvss_score = cvss;
        f.cvss_severity = sev;
        return f;
    }
};

} // namespace

// A package name is attacker-influenced data: any installer can write any
// DisplayName into the registry. Bound as a parameter it is stored verbatim;
// concatenated into SQL it would have dropped the table.
TEST_F(DbTest, hostile_and_unicode_names_round_trip_verbatim) {
    const std::string hostile = "x'); DROP TABLE dbo.findings; --";
    const std::string unicode = "Caf\xC3\xA9 Studio\xC2\xAE \xE6\x97\xA5\xE6\x9C\xAC";  // Café Studio® 日本

    auto inv = inventory();
    inv.packages.push_back({hostile, "1.0", "evil", "msi"});
    inv.packages.push_back({unicode, "2.0", "vendor", "windows-registry"});
    std::vector<ns::Finding> fs = {finding("CVE-2099-0001", hostile, 9.8, "CRITICAL"),
                                   finding("CVE-2099-0002", unicode, 5.0, "MEDIUM")};

    std::int64_t scan_id = 0;
    std::string err;
    ASSERT_TRUE(db.record_scan(inv, fs, scan_id, err)) << err;
    EXPECT_GT(scan_id, 0);

    std::vector<ns::FindingRow> rows;
    ASSERT_TRUE(db.host_findings(host, 0.0, 10, rows, err)) << err;
    ASSERT_EQ(rows.size(), 2u);
    EXPECT_EQ(rows[0].package_name, hostile);  // worst first
    EXPECT_EQ(rows[0].cvss, 9.8);
    EXPECT_EQ(rows[1].package_name, unicode);

    std::int64_t tables = 0;
    ASSERT_TRUE(db.scalar("SELECT COUNT(*) FROM sys.tables WHERE name = 'findings'", tables, err));
    EXPECT_EQ(tables, 1);
}

TEST_F(DbTest, only_the_latest_scan_counts) {
    std::int64_t first = 0, second = 0;
    std::string err;
    ASSERT_TRUE(db.record_scan(inventory(),
                               {finding("CVE-2099-0101", "openssl", 7.5, "HIGH"),
                                finding("CVE-2099-0102", "openssl", 9.1, "CRITICAL")},
                               first, err))
        << err;
    // The host patched: the second scan has one of the two left.
    ASSERT_TRUE(db.record_scan(inventory(), {finding("CVE-2099-0101", "openssl", 7.5, "HIGH")},
                               second, err))
        << err;
    EXPECT_GT(second, first);

    std::vector<ns::FindingRow> rows;
    ASSERT_TRUE(db.host_findings(host, 0.0, 10, rows, err)) << err;
    ASSERT_EQ(rows.size(), 1u);
    EXPECT_EQ(rows[0].cve_id, "CVE-2099-0101");

    // And fleet-wide: the patched CVE no longer lists this host.
    rows.clear();
    ASSERT_TRUE(db.hosts_affected("CVE-2099-0102", rows, err)) << err;
    for (const auto& r : rows) EXPECT_NE(r.hostname, host);
    rows.clear();
    ASSERT_TRUE(db.hosts_affected("CVE-2099-0101", rows, err)) << err;
    bool found = false;
    for (const auto& r : rows) found = found || r.hostname == host;
    EXPECT_TRUE(found);
}

TEST_F(DbTest, min_cvss_and_limit_are_applied) {
    std::int64_t id = 0;
    std::string err;
    ASSERT_TRUE(db.record_scan(inventory(),
                               {finding("CVE-2099-0201", "a", 3.1, "LOW"),
                                finding("CVE-2099-0202", "b", 7.0, "HIGH"),
                                finding("CVE-2099-0203", "c", 8.8, "HIGH"),
                                finding("CVE-2099-0204", "d", 10.0, "CRITICAL")},
                               id, err))
        << err;
    std::vector<ns::FindingRow> rows;
    ASSERT_TRUE(db.host_findings(host, 7.0, 2, rows, err)) << err;
    ASSERT_EQ(rows.size(), 2u);
    EXPECT_EQ(rows[0].cvss, 10.0);
    EXPECT_EQ(rows[1].cvss, 8.8);
}

// A failure part-way through must leave nothing behind: the scan row, the
// packages and the findings commit together or not at all.
TEST_F(DbTest, a_failed_scan_rolls_back_completely) {
    auto inv = inventory();
    inv.packages.push_back({"ok", "1", "v", "msi"});
    // cve_id is varchar(32); this one is too long, so the findings insert
    // fails AFTER the host, scan and package rows were written.
    std::vector<ns::Finding> fs = {finding("CVE-2099-0301", "ok", 5.0, "MEDIUM"),
                                   finding("CVE-2099-03020000000000000000000000000000", "ok",
                                           5.0, "MEDIUM")};
    std::int64_t id = 0;
    std::string err;
    EXPECT_FALSE(db.record_scan(inv, fs, id, err));

    std::int64_t n = -1;
    ASSERT_TRUE(db.scalar("SELECT COUNT(*) FROM dbo.hosts WHERE hostname = '" + host + "'", n,
                          err))
        << err;
    EXPECT_EQ(n, 0);  // even the host row was rolled back

    // And the connection is still usable afterwards.
    ASSERT_TRUE(db.record_scan(inventory(), {}, id, err)) << err;
}
