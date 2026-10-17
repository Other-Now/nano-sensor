// ns_dbbench -- loads a synthetic fleet into SQL Server and measures the
// "which hosts have CVE-X?" query, so the IX_findings_cve index can be
// measured before and after instead of assumed. Driven by
// tools/db/bench_index.ps1; see docs/SQL_SERVER.md for the results.
//
//   ns_dbbench load    --db CONN --hosts N [--seed S]
//   ns_dbbench measure --db CONN --cves-file F [--queries Q] [--repeat R]
//   ns_dbbench insert  --db CONN --hosts K --tag T
//
// The fleet is synthetic but the findings are not: every host gets a random
// set of real products at versions that appear in the NVD data, and is run
// through the agent's own CveIndex matcher. So the per-host finding counts,
// and how often each CVE occurs, have the skew a real fleet's would.

#include "ns/cve.hpp"
#include "ns/db.hpp"
#include "ns/inventory.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <map>
#include <random>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace {

using Clock = std::chrono::steady_clock;

struct Args {
    std::string cmd, db, index = "data/cve_index.tsv", aliases = "data/cpe_aliases.tsv";
    std::string cves_file, tag = "x";
    int hosts = 1000, queries = 30, repeat = 9;
    unsigned seed = 42;
};

std::vector<std::string> split_tab(const std::string& line) {
    std::vector<std::string> out;
    std::string cur;
    std::istringstream in(line);
    while (std::getline(in, cur, '\t')) out.push_back(cur);
    return out;
}

// Package names the matcher resolves, and versions NVD mentions, per product.
struct Catalog {
    std::vector<std::string> names;                   // one installable name per product
    std::vector<std::vector<std::string>> versions;   // parallel to names
};

Catalog build_catalog(const Args& a) {
    std::map<std::string, std::string> name_for;  // "vendor:product" -> alias name
    {
        std::ifstream f(a.aliases);
        std::string line;
        while (std::getline(f, line)) {
            if (line.empty() || line[0] == '#') continue;
            auto c = split_tab(line);
            if (c.size() >= 4 && c[0] == "exact") name_for.emplace(c[2] + ":" + c[3], c[1]);
        }
    }
    std::map<std::string, std::set<std::string>> vers;
    {
        std::ifstream f(a.index);
        std::string line;
        std::getline(f, line);  // header
        while (std::getline(f, line)) {
            auto c = split_tab(line);
            if (c.size() < 9) continue;
            auto& s = vers[c[1] + ":" + c[2]];
            for (int i : {3, 5, 7, 8}) {
                if (!c[i].empty() && c[i] != "*" && c[i] != "-") s.insert(c[i]);
            }
        }
    }
    Catalog cat;
    for (const auto& [key, name] : name_for) {
        auto it = vers.find(key);
        if (it == vers.end() || it->second.empty()) continue;
        cat.names.push_back(name);
        cat.versions.emplace_back(it->second.begin(), it->second.end());
    }
    return cat;
}

struct Fleet {
    ns::CveIndex index;
    Catalog cat;
    std::mt19937 rng;

    // One host: 6-12 products at random NVD-mentioned versions, matched by
    // the real matcher.
    void make_host(const std::string& hostname, ns::Inventory& inv,
                   std::vector<ns::Finding>& findings) {
        inv = ns::Inventory{};
        findings.clear();
        inv.host.hostname = hostname;
        inv.host.os_name = "Windows 11 Enterprise";
        inv.host.os_version = "10.0.26100";
        inv.collected_at_unix_ms = ns::unix_time_ms();

        std::vector<std::size_t> idx(cat.names.size());
        for (std::size_t i = 0; i < idx.size(); ++i) idx[i] = i;
        std::shuffle(idx.begin(), idx.end(), rng);
        const std::size_t n = std::min<std::size_t>(idx.size(), 6 + rng() % 7);
        for (std::size_t k = 0; k < n; ++k) {
            const auto& vs = cat.versions[idx[k]];
            ns::Package p;
            p.name = cat.names[idx[k]];
            p.version = vs[rng() % vs.size()];
            p.vendor = "bench";
            p.source = "synthetic";
            for (auto& f : index.match_package(p)) findings.push_back(std::move(f));
            inv.packages.push_back(std::move(p));
        }
    }
};

bool open_fleet(const Args& a, Fleet& fl) {
    std::string err;
    if (!fl.index.load_rules(a.index, err) || !fl.index.load_aliases(a.aliases, err)) {
        std::fprintf(stderr, "index: %s\n", err.c_str());
        return false;
    }
    fl.cat = build_catalog(a);
    fl.rng.seed(a.seed);
    std::fprintf(stderr, "catalog: %zu products\n", fl.cat.names.size());
    return true;
}

int write_hosts(const Args& a, const std::string& prefix) {
    Fleet fl;
    if (!open_fleet(a, fl)) return 1;
    ns::Db db;
    std::string err;
    if (!db.connect(a.db, err)) {
        std::fprintf(stderr, "%s\n", err.c_str());
        return 1;
    }

    std::uint64_t pkgs = 0, finds = 0;
    ns::Inventory inv;
    std::vector<ns::Finding> findings;
    double write_s = 0;
    for (int h = 0; h < a.hosts; ++h) {
        char name[64];
        std::snprintf(name, sizeof(name), "%s%06d", prefix.c_str(), h);
        fl.make_host(name, inv, findings);
        const auto t0 = Clock::now();
        std::int64_t scan_id = 0;
        if (!db.record_scan(inv, findings, scan_id, err)) {
            std::fprintf(stderr, "record_scan: %s\n", err.c_str());
            return 1;
        }
        write_s += std::chrono::duration<double>(Clock::now() - t0).count();
        pkgs += inv.packages.size();
        finds += findings.size();
        if ((h + 1) % 500 == 0) {
            std::fprintf(stderr, "  %d hosts, %llu findings, %.0f rows/s\n", h + 1,
                         static_cast<unsigned long long>(finds), (pkgs + finds) / write_s);
        }
    }
    // Time spent in record_scan only -- generation and matching excluded.
    std::printf("{\"hosts\":%d,\"packages\":%llu,\"findings\":%llu,\"write_s\":%.2f,"
                "\"rows_per_s\":%.0f,\"ms_per_scan\":%.3f}\n",
                a.hosts, static_cast<unsigned long long>(pkgs),
                static_cast<unsigned long long>(finds), write_s, (pkgs + finds) / write_s,
                write_s * 1000.0 / a.hosts);
    return 0;
}

// Sum of "logical reads N" over every table in a STATISTICS IO message block.
std::int64_t logical_reads(const std::string& messages) {
    static const std::regex re(R"(logical reads (\d+))");
    std::int64_t total = 0;
    for (auto it = std::sregex_iterator(messages.begin(), messages.end(), re);
         it != std::sregex_iterator(); ++it) {
        total += std::stoll((*it)[1].str());
    }
    return total;
}

int measure(const Args& a) {
    ns::Db db;
    std::string err;
    if (!db.connect(a.db, err)) {
        std::fprintf(stderr, "%s\n", err.c_str());
        return 1;
    }

    // The same CVEs before and after: chosen once, at evenly spaced ranks of
    // "how many latest-scan findings mention it", so the set runs from rare
    // CVEs (a few hosts) to the most widespread one.
    std::vector<std::string> cves;
    {
        std::ifstream f(a.cves_file);
        std::string line;
        while (std::getline(f, line)) {
            if (!line.empty()) cves.push_back(line);
        }
    }
    if (cves.empty()) {
        // Every distinct CVE, rarest first; then take evenly spaced ranks.
        // Chosen once and saved, so its cost is part of no measurement.
        std::vector<std::string> all;
        if (!db.column("SELECT cve_id FROM dbo.findings GROUP BY cve_id "
                       "ORDER BY COUNT(*), cve_id",
                       all, err) ||
            all.empty()) {
            std::fprintf(stderr, "cannot list CVEs: %s\n", err.c_str());
            return 1;
        }
        std::ofstream out(a.cves_file);
        for (int q = 0; q < a.queries; ++q) {
            const std::size_t rank = (all.size() - 1) * q / std::max(1, a.queries - 1);
            cves.push_back(all[rank]);
            out << all[rank] << "\n";
        }
    }

    std::int64_t rows_total = 0, pages = 0;
    db.scalar("SELECT COUNT_BIG(*) FROM dbo.findings", rows_total, err);
    db.scalar("SELECT SUM(used_page_count) FROM sys.dm_db_partition_stats "
              "WHERE object_id = OBJECT_ID('dbo.findings')",
              pages, err);

    if (!db.exec("SET STATISTICS IO ON", err)) {
        std::fprintf(stderr, "%s\n", err.c_str());
        return 1;
    }

    std::vector<double> medians;
    std::vector<std::int64_t> reads;
    std::int64_t rows_returned = 0;
    std::fprintf(stderr, "%-18s %8s %14s %10s\n", "cve", "hosts", "logical_reads", "median_ms");
    for (const auto& cve : cves) {
        std::vector<ns::FindingRow> rows;
        std::string messages;
        // Warm-up run: also the one whose STATISTICS IO is recorded. Logical
        // reads do not depend on cache state, so one sample is exact.
        if (!db.hosts_affected(cve, rows, err, &messages)) {
            std::fprintf(stderr, "%s: %s\n", cve.c_str(), err.c_str());
            return 1;
        }
        const std::int64_t lr = logical_reads(messages);

        std::vector<double> ms;
        for (int r = 0; r < a.repeat; ++r) {
            rows.clear();
            const auto t0 = Clock::now();
            db.hosts_affected(cve, rows, err);
            ms.push_back(std::chrono::duration<double, std::milli>(Clock::now() - t0).count());
        }
        std::sort(ms.begin(), ms.end());
        const double med = ms[ms.size() / 2];
        medians.push_back(med);
        reads.push_back(lr);
        rows_returned += static_cast<std::int64_t>(rows.size());
        std::fprintf(stderr, "%-18s %8zu %14lld %10.3f\n", cve.c_str(), rows.size(),
                     static_cast<long long>(lr), med);
    }

    auto sorted_m = medians;
    std::sort(sorted_m.begin(), sorted_m.end());
    auto sorted_r = reads;
    std::sort(sorted_r.begin(), sorted_r.end());
    double sum_m = 0;
    for (double m : medians) sum_m += m;
    std::printf("{\"findings_rows\":%lld,\"findings_pages\":%lld,\"queries\":%zu,"
                "\"repeat\":%d,\"rows_returned\":%lld,"
                "\"median_ms\":%.3f,\"p90_ms\":%.3f,\"max_ms\":%.3f,\"mean_ms\":%.3f,"
                "\"median_logical_reads\":%lld,\"max_logical_reads\":%lld}\n",
                static_cast<long long>(rows_total), static_cast<long long>(pages), cves.size(),
                a.repeat, static_cast<long long>(rows_returned),
                sorted_m[sorted_m.size() / 2], sorted_m[sorted_m.size() * 9 / 10],
                sorted_m.back(), sum_m / medians.size(),
                static_cast<long long>(sorted_r[sorted_r.size() / 2]),
                static_cast<long long>(sorted_r.back()));
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: ns_dbbench load|measure|insert --db CONN [...]\n");
        return 2;
    }
    Args a;
    a.cmd = argv[1];
    for (int i = 2; i + 1 < argc; i += 2) {
        const std::string k = argv[i], v = argv[i + 1];
        if (k == "--db") a.db = v;
        else if (k == "--hosts") a.hosts = std::atoi(v.c_str());
        else if (k == "--seed") a.seed = static_cast<unsigned>(std::strtoul(v.c_str(), nullptr, 10));
        else if (k == "--queries") a.queries = std::atoi(v.c_str());
        else if (k == "--repeat") a.repeat = std::atoi(v.c_str());
        else if (k == "--cves-file") a.cves_file = v;
        else if (k == "--tag") a.tag = v;
        else if (k == "--index") a.index = v;
        else if (k == "--aliases") a.aliases = v;
        else {
            std::fprintf(stderr, "unknown option %s\n", k.c_str());
            return 2;
        }
    }
    if (a.cmd == "load") return write_hosts(a, "bench-");
    if (a.cmd == "insert") {
        a.seed += 1000;  // different hosts from the load, same distribution
        return write_hosts(a, "bench-ins-" + a.tag + "-");
    }
    if (a.cmd == "measure") return measure(a);
    std::fprintf(stderr, "unknown command %s\n", a.cmd.c_str());
    return 2;
}
