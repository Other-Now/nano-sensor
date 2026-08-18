#include "ns/cve.hpp"

#include "ns/json.hpp"
#include "ns/log.hpp"
#include "ns/vercmp.hpp"
#include "ns/version.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <set>
#include <sstream>
#include <unordered_set>

namespace ns {

namespace {

std::vector<std::string> split_tabs(const std::string& line) {
    std::vector<std::string> out;
    std::string cur;
    std::istringstream ss(line);
    while (std::getline(ss, cur, '\t')) out.push_back(cur);
    return out;
}

std::string trim(const std::string& s) {
    const auto b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return {};
    const auto e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

bool token_is_version(const std::string& t) {
    bool digit = false;
    std::size_t i = 0;
    if (t.size() > 1 && (t[0] == 'v')) i = 1;
    for (; i < t.size(); ++i) {
        if (std::isdigit(static_cast<unsigned char>(t[i]))) digit = true;
        else if (t[i] != '.' && t[i] != ',') return false;
    }
    return digit;
}

bool token_is_noise(const std::string& t) {
    static const std::unordered_set<std::string> kNoise = {
        "x64", "x86", "amd64", "arm64", "win32", "win64", "64-bit", "32-bit",
        "(64-bit)", "(32-bit)", "en-us", "en_us", "bit", "edition", "-",
    };
    return kNoise.count(t) > 0;
}

std::string severity_bucket(const std::string& sev, double score) {
    if (!sev.empty()) {
        std::string s;
        for (char c : sev) s += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        return s;
    }
    // CVSS v2 rows sometimes arrive without a severity label; bucket by the v3
    // thresholds so one report does not mix two vocabularies.
    if (score >= 9.0) return "critical";
    if (score >= 7.0) return "high";
    if (score >= 4.0) return "medium";
    if (score > 0.0) return "low";
    return "none";
}

} // namespace

std::string CveIndex::normalize_name(const std::string& raw) {
    // Windows DisplayName strings are marketing text ("Python 3.12.1 (64-bit)"),
    // Linux package names are identifiers ("python3.10"). Both have to reduce to
    // something an alias table can key on, and the reduction has to be
    // conservative: dropping a token that carries product identity turns two
    // different products into the same one.
    std::string lowered;
    int depth = 0;
    for (char c : raw) {
        if (c == '(' || c == '[') { ++depth; continue; }
        if (c == ')' || c == ']') { if (depth > 0) --depth; continue; }
        if (depth > 0) continue;
        lowered += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }

    std::istringstream ss(lowered);
    std::string tok;
    std::vector<std::string> keep;
    while (ss >> tok) {
        if (token_is_version(tok) || token_is_noise(tok)) continue;
        keep.push_back(tok);
    }

    std::string out;
    for (std::size_t i = 0; i < keep.size(); ++i) {
        if (i) out += ' ';
        out += keep[i];
    }
    return trim(out);
}

bool CveIndex::load_rules(const std::string& path, std::string& error) {
    std::ifstream f(path);
    if (!f) {
        error = "cannot open CVE index: " + path;
        return false;
    }

    std::string line;
    if (!std::getline(f, line)) {
        error = "CVE index is empty: " + path;
        return false;
    }
    // The header is checked, not skipped blindly: a column reordering in the
    // builder would otherwise silently shift every field by one and produce a
    // matcher that is confidently wrong.
    if (line.rfind("cve_id\tvendor\tproduct\tversion", 0) != 0) {
        error = "unexpected CVE index header in " + path;
        return false;
    }

    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        const auto c = split_tabs(line);
        if (c.size() < 12) continue;

        CveRule r;
        r.cve_id = c[0];
        r.vendor = c[1];
        r.product = c[2];
        r.version = c[3];
        r.start_incl = c[5];
        r.start_excl = c[6];
        r.end_incl = c[7];
        r.end_excl = c[8];
        r.cvss_score = c[9].empty() ? 0.0 : std::strtod(c[9].c_str(), nullptr);
        r.cvss_severity = c[10];
        r.cvss_version = c[11];

        by_product_[r.vendor + ":" + r.product].push_back(std::move(r));
        ++rule_count_;
    }
    return true;
}

bool CveIndex::load_aliases(const std::string& path, std::string& error) {
    std::ifstream f(path);
    if (!f) {
        error = "cannot open alias table: " + path;
        return false;
    }

    std::string line;
    while (std::getline(f, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        const auto c = split_tabs(line);
        if (c.size() < 4) continue;

        const std::string kind = trim(c[0]);
        const std::string pattern = trim(c[1]);
        const std::string target = trim(c[2]) + ":" + trim(c[3]);
        if (kind == "exact") exact_[pattern] = target;
        else if (kind == "prefix") prefixes_.emplace_back(pattern, target);
    }

    // Longest prefix first, so "libssl" beats "lib" and the more specific rule
    // wins regardless of the order someone wrote them in the file.
    std::sort(prefixes_.begin(), prefixes_.end(),
              [](const auto& a, const auto& b) { return a.first.size() > b.first.size(); });
    return true;
}

bool CveIndex::resolve(const std::string& raw_name, std::string& vendor,
                       std::string& product) const {
    const std::string norm = normalize_name(raw_name);
    if (norm.empty()) return false;

    auto split_target = [&](const std::string& target) {
        const auto colon = target.find(':');
        vendor = target.substr(0, colon);
        product = target.substr(colon + 1);
        return true;
    };

    if (auto it = exact_.find(norm); it != exact_.end()) return split_target(it->second);

    for (const auto& [prefix, target] : prefixes_) {
        if (norm.rfind(prefix, 0) == 0) return split_target(target);
    }

    // Last resort: drop trailing words one at a time. "mozilla firefox esr"
    // should still resolve via the "mozilla firefox" rule, but "microsoft visual
    // studio" must never collapse all the way to "microsoft".
    std::string trimmed = norm;
    while (true) {
        const auto space = trimmed.rfind(' ');
        if (space == std::string::npos) break;
        trimmed = trimmed.substr(0, space);
        if (auto it = exact_.find(trimmed); it != exact_.end()) return split_target(it->second);
    }
    return false;
}

std::vector<Finding> CveIndex::match_package(const Package& pkg) const {
    std::vector<Finding> out;

    std::string vendor, product;
    if (!resolve(pkg.name, vendor, product)) return out;
    if (pkg.version.empty()) return out;

    auto it = by_product_.find(vendor + ":" + product);
    if (it == by_product_.end()) return out;

    const std::string v = version_upstream_part(pkg.version);
    if (v.empty()) return out;

    // One CVE can appear as several rules for the same product (different
    // version ranges). Keep the highest-scoring hit per CVE so a report never
    // lists the same advisory twice.
    std::unordered_map<std::string, Finding> best;

    for (const CveRule& r : it->second) {
        bool hit = false;
        const bool has_range = !r.start_incl.empty() || !r.start_excl.empty() ||
                               !r.end_incl.empty() || !r.end_excl.empty();

        if (r.version != "*" && r.version != "-" && !r.version.empty()) {
            // An exact-version CPE. NVD writes these for advisories that name
            // specific releases rather than a range.
            hit = version_compare(v, r.version) == 0;
        } else if (has_range) {
            hit = version_in_range(v, r.start_incl, r.start_excl, r.end_incl, r.end_excl);
        } else {
            // version "*" with no bounds means every version of the product is
            // affected. Rare, and real.
            hit = true;
        }
        if (!hit) continue;

        Finding fnd;
        fnd.cve_id = r.cve_id;
        fnd.package_name = pkg.name;
        fnd.package_version = pkg.version;
        fnd.matched_version = v;
        fnd.vendor = vendor;
        fnd.product = product;
        fnd.cvss_score = r.cvss_score;
        fnd.cvss_severity = severity_bucket(r.cvss_severity, r.cvss_score);
        fnd.cvss_version = r.cvss_version;

        auto existing = best.find(r.cve_id);
        if (existing == best.end() || fnd.cvss_score > existing->second.cvss_score) {
            best[r.cve_id] = std::move(fnd);
        }
    }

    out.reserve(best.size());
    for (auto& [id, f] : best) out.push_back(std::move(f));
    return out;
}

std::vector<Finding> CveIndex::scan(const Inventory& inv, ScanSummary& summary) const {
    // Which CPE products own a world-reachable listening socket on this host.
    std::set<std::string> exposed_products;
    for (const auto& s : inv.sockets) {
        if (!s.world_reachable || s.process_name.empty()) continue;
        std::string vendor, product;
        if (resolve(s.process_name, vendor, product)) {
            exposed_products.insert(vendor + ":" + product);
        }
    }

    std::vector<Finding> all;
    summary.packages_total = inv.packages.size();

    for (const auto& pkg : inv.packages) {
        std::string vendor, product;
        if (!resolve(pkg.name, vendor, product)) {
            ++summary.packages_unmapped;
            if (summary.unmapped_names.size() < 50) summary.unmapped_names.push_back(pkg.name);
            continue;
        }
        ++summary.packages_mapped;
        if (pkg.version.empty()) {
            // Mapped but unmatchable. Counted separately because it is a
            // collector gap, not a clean bill of health.
            ++summary.packages_no_version;
            continue;
        }

        auto found = match_package(pkg);
        const bool exposed = exposed_products.count(vendor + ":" + product) > 0;
        for (auto& f : found) {
            f.network_exposed = exposed;
            all.push_back(std::move(f));
        }
    }

    std::sort(all.begin(), all.end(), [](const Finding& a, const Finding& b) {
        if (a.cvss_score != b.cvss_score) return a.cvss_score > b.cvss_score;
        return a.cve_id > b.cve_id;
    });

    summary.findings = all.size();
    for (const auto& f : all) {
        if (f.cvss_severity == "critical") ++summary.critical;
        else if (f.cvss_severity == "high") ++summary.high;
        else if (f.cvss_severity == "medium") ++summary.medium;
        else if (f.cvss_severity == "low") ++summary.low;
        if (f.network_exposed) ++summary.exposed_findings;
    }
    return all;
}

std::string findings_to_json(const std::vector<Finding>& findings,
                             const ScanSummary& summary, const Inventory& inv,
                             bool pretty) {
    JsonWriter w(pretty);
    w.begin_object();

    w.begin_object("agent");
    w.field("name", kAgentName);
    w.field("version", kAgentVersion);
    w.field("stage", kAgentStage);
    w.field("platform", inv.platform);
    w.end_object();

    w.field("hostname", inv.host.hostname);
    w.field("os_name", inv.host.os_name);
    w.field("collected_at_unix_ms", inv.collected_at_unix_ms);

    w.begin_object("summary");
    w.field("packages_total", summary.packages_total);
    w.field("packages_mapped", summary.packages_mapped);
    w.field("packages_unmapped", summary.packages_unmapped);
    w.field("packages_no_version", summary.packages_no_version);
    w.field("findings", summary.findings);
    w.field("critical", summary.critical);
    w.field("high", summary.high);
    w.field("medium", summary.medium);
    w.field("low", summary.low);
    w.field("network_exposed_findings", summary.exposed_findings);
    w.end_object();

    w.begin_array("findings");
    for (const auto& f : findings) {
        w.begin_object();
        w.field("cve", f.cve_id);
        w.field("package", f.package_name);
        w.field("installed_version", f.package_version);
        w.field("matched_version", f.matched_version);
        w.field("cpe_vendor", f.vendor);
        w.field("cpe_product", f.product);
        w.field("cvss_score", f.cvss_score);
        w.field("cvss_severity", f.cvss_severity);
        w.field("cvss_version", f.cvss_version);
        w.field("network_exposed", f.network_exposed);
        w.end_object();
    }
    w.end_array();

    // Shipped in the report on purpose: a package the matcher could not map is a
    // blind spot, and the cloud side has to be able to see the size of it rather
    // than read "0 findings" as "0 risk".
    w.begin_array("unmapped_packages");
    for (const auto& n : summary.unmapped_names) w.value(n);
    w.end_array();

    w.end_object();
    return w.str();
}

} // namespace ns
