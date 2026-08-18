#pragma once

#include "ns/inventory.hpp"

#include <string>
#include <unordered_map>
#include <vector>

namespace ns {

// One (CVE, affected-CPE) rule, as extracted from NVD by tools/nvd_build_index.py.
struct CveRule {
    std::string cve_id;
    std::string vendor;
    std::string product;
    std::string version;  // exact affected version, or "*" for a range rule
    std::string start_incl, start_excl, end_incl, end_excl;
    double cvss_score = 0.0;
    std::string cvss_severity;
    std::string cvss_version;
};

struct Finding {
    std::string cve_id;
    std::string package_name;
    std::string package_version;
    std::string matched_version;  // the upstream part actually compared
    std::string vendor, product;
    double cvss_score = 0.0;
    std::string cvss_severity;
    std::string cvss_version;

    // True when a world-reachable listening socket is owned by a process whose
    // name resolves to this same product. Best-effort by construction -- see the
    // note on CveIndex::scan.
    bool network_exposed = false;
};

struct ScanSummary {
    std::size_t packages_total = 0;
    std::size_t packages_mapped = 0;    // resolved to a CPE product
    std::size_t packages_unmapped = 0;  // no alias; cannot be matched at all
    std::size_t packages_no_version = 0;
    std::size_t findings = 0;
    std::size_t critical = 0, high = 0, medium = 0, low = 0;
    std::size_t exposed_findings = 0;
    std::vector<std::string> unmapped_names;
};

// The CVE index and the package-name -> CPE alias table.
//
// Both are loaded from checked-in TSV rather than embedded, so the data can be
// refreshed without a rebuild and reviewed in a diff.
class CveIndex {
public:
    bool load_rules(const std::string& path, std::string& error);
    bool load_aliases(const std::string& path, std::string& error);

    std::size_t rule_count() const { return rule_count_; }
    std::size_t product_count() const { return by_product_.size(); }
    std::size_t alias_count() const { return exact_.size() + prefixes_.size(); }

    // Resolve a raw package/process name to a CPE vendor:product pair.
    // Returns false when nothing in the alias table covers it.
    bool resolve(const std::string& raw_name, std::string& vendor,
                 std::string& product) const;

    std::vector<Finding> match_package(const Package& pkg) const;

    // Full scan of an inventory. The exposure join is deliberately conservative:
    // a finding is flagged exposed only when a world-reachable socket's owning
    // process name resolves to the SAME CPE product as the package. That catches
    // the cases that matter (nginx, sshd, postgres listening on 0.0.0.0) and
    // will miss a vulnerable library reached through some other daemon. Claiming
    // more than that would be guessing, and a wrong exposure flag is worse than
    // an absent one -- it changes what a responder patches first.
    std::vector<Finding> scan(const Inventory& inv, ScanSummary& summary) const;

    // Exposed for testing and for the evaluation harness.
    static std::string normalize_name(const std::string& raw);

private:
    std::unordered_map<std::string, std::vector<CveRule>> by_product_;
    std::unordered_map<std::string, std::string> exact_;    // normalized -> "vendor:product"
    std::vector<std::pair<std::string, std::string>> prefixes_;  // prefix -> "vendor:product"
    std::size_t rule_count_ = 0;
};

std::string findings_to_json(const std::vector<Finding>& findings,
                             const ScanSummary& summary, const Inventory& inv,
                             bool pretty);

} // namespace ns
