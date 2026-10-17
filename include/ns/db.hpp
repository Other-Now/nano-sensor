#pragma once

#include "ns/cve.hpp"
#include "ns/inventory.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace ns {

// Inventory and findings in SQL Server, through ODBC.
//
// Every statement that carries data is prepared with `?` placeholders and the
// values bound with SQLBindParameter -- package names come from the registry
// of a machine we do not control, and "'; DROP TABLE findings; --" is a legal
// DisplayName. Nothing here builds SQL by concatenating a value. (exec() takes
// raw SQL, and is used only for fixed admin/benchmark statements.)
//
// The schema is NOT created here; tools/db/schema.sql does that, run once by
// an administrator. The service's own database login can SELECT/INSERT/UPDATE
// four tables and nothing else -- no DDL, no DELETE -- so a compromised agent
// cannot drop the evidence it reports into.
//
// Not thread-safe: one connection, one caller at a time. The agent guards it
// with a mutex.

struct FindingRow {
    std::string hostname;
    std::string cve_id;
    std::string package_name;
    std::string package_version;
    double cvss = 0.0;
    std::string severity;
    bool exposed = false;
    std::int64_t scan_id = 0;
};

class Db {
public:
    Db();
    ~Db();
    Db(const Db&) = delete;
    Db& operator=(const Db&) = delete;

    // e.g. "Driver={ODBC Driver 18 for SQL Server};Server=.\SQLEXPRESS;
    //       Database=nanosensor;Trusted_Connection=yes;Encrypt=no"
    bool connect(const std::string& connection_string, std::string& error);
    void disconnect();
    bool connected() const;

    // Writes one scan -- host upsert, scan row, every package, every finding,
    // and the host's latest_scan_id pointer -- in ONE transaction. A reader
    // never sees a scan whose findings are half-written, and a crash mid-write
    // rolls the whole scan back rather than leaving an orphaned partial one.
    bool record_scan(const Inventory& inv, const std::vector<Finding>& findings,
                     std::int64_t& scan_id, std::string& error);

    // Findings from this host's latest scan at or above min_cvss, worst first.
    bool host_findings(const std::string& hostname, double min_cvss, int limit,
                       std::vector<FindingRow>& out, std::string& error);

    // "Which hosts are exposed to CVE-X right now?" -- the fleet-wide question
    // a responder asks the morning an advisory drops. The query the index
    // benchmark measures. `messages`, if given, receives the server's info
    // messages (SET STATISTICS IO output lands there).
    bool hosts_affected(const std::string& cve_id, std::vector<FindingRow>& out,
                        std::string& error, std::string* messages = nullptr);

    // Fixed SQL only (index DDL, SET options). Never pass user data.
    bool exec(const std::string& sql, std::string& error, std::string* messages = nullptr);
    bool scalar(const std::string& sql, std::int64_t& out, std::string& error);
    // First column of every row, as text. Fixed SQL only, like exec().
    bool column(const std::string& sql, std::vector<std::string>& out, std::string& error);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace ns
