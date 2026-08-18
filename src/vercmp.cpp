#include "ns/vercmp.hpp"

#include <algorithm>
#include <cctype>
#include <vector>

namespace ns {

namespace {

enum class Kind { Tilde, Alpha, Numeric };

struct Token {
    Kind kind;
    std::string text;      // for Alpha
    unsigned long long num = 0;  // for Numeric
};

bool is_digit(char c) { return c >= '0' && c <= '9'; }
bool is_alpha(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

char lower(char c) {
    return static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
}

// rc/alpha/beta/pre/dev/snapshot mark a build that comes BEFORE the release it
// is named for. Everything else -- OpenSSL's letter suffixes, "p" patch
// markers, "post" -- comes after.
bool is_prerelease_word(const std::string& s) {
    static const char* kWords[] = {"rc", "alpha", "beta", "pre", "dev",
                                   "preview", "snapshot", "nightly", "a1"};
    for (const char* w : kWords) {
        if (s == w) return true;
    }
    return false;
}

std::vector<Token> tokenize(std::string_view v) {
    std::vector<Token> out;
    std::size_t i = 0;
    while (i < v.size()) {
        const char c = v[i];
        if (c == '~') {
            out.push_back({Kind::Tilde, {}, 0});
            ++i;
        } else if (is_digit(c)) {
            std::size_t j = i;
            while (j < v.size() && is_digit(v[j])) ++j;
            // Leading zeros are not significant: "007" and "7" are the same
            // release, and comparing them as strings would say otherwise.
            std::string digits(v.substr(i, j - i));
            const std::size_t first = digits.find_first_not_of('0');
            unsigned long long value = 0;
            if (first != std::string::npos) {
                // Saturate rather than overflow on absurd inputs; a version
                // component that long is malformed, not a number we must model.
                const std::string trimmed = digits.substr(first);
                if (trimmed.size() > 18) {
                    value = ~0ULL;
                } else {
                    for (char d : trimmed) value = value * 10 + static_cast<unsigned>(d - '0');
                }
            }
            out.push_back({Kind::Numeric, {}, value});
            i = j;
        } else if (is_alpha(c)) {
            std::size_t j = i;
            while (j < v.size() && is_alpha(v[j])) ++j;
            std::string word;
            for (std::size_t k = i; k < j; ++k) word += lower(v[k]);
            out.push_back({Kind::Alpha, std::move(word), 0});
            i = j;
        } else {
            ++i;  // separators (. - _ +) are boundaries, not comparable content
        }
    }
    return out;
}

int rank(Kind k) {
    switch (k) {
    case Kind::Tilde:   return 0;
    case Kind::Alpha:   return 1;
    case Kind::Numeric: return 2;
    }
    return 1;
}

int cmp_token(const Token& a, const Token& b) {
    if (a.kind != b.kind) return rank(a.kind) < rank(b.kind) ? -1 : 1;
    switch (a.kind) {
    case Kind::Tilde:
        return 0;
    case Kind::Alpha:
        if (a.text == b.text) return 0;
        return a.text < b.text ? -1 : 1;
    case Kind::Numeric:
        if (a.num == b.num) return 0;
        return a.num < b.num ? -1 : 1;
    }
    return 0;
}

// One side ran out of tokens. Decide whether having more tokens makes a version
// greater or smaller.
int cmp_remainder(const std::vector<Token>& rest, std::size_t from) {
    if (from >= rest.size()) return 0;
    const Token& next = rest[from];
    if (next.kind == Kind::Tilde) return -1;
    if (next.kind == Kind::Alpha && is_prerelease_word(next.text)) return -1;
    return 1;
}

std::string_view strip_epoch(std::string_view v, unsigned long long& epoch) {
    epoch = 0;
    const auto colon = v.find(':');
    if (colon == std::string_view::npos) return v;
    for (std::size_t i = 0; i < colon; ++i) {
        if (!is_digit(v[i])) return v;  // not an epoch, just a stray colon
    }
    for (std::size_t i = 0; i < colon; ++i) {
        epoch = epoch * 10 + static_cast<unsigned>(v[i] - '0');
    }
    return v.substr(colon + 1);
}

} // namespace

int version_compare(std::string_view a, std::string_view b) {
    unsigned long long epoch_a = 0, epoch_b = 0;
    a = strip_epoch(a, epoch_a);
    b = strip_epoch(b, epoch_b);
    if (epoch_a != epoch_b) return epoch_a < epoch_b ? -1 : 1;

    const auto ta = tokenize(a);
    const auto tb = tokenize(b);

    const std::size_t n = std::min(ta.size(), tb.size());
    for (std::size_t i = 0; i < n; ++i) {
        if (const int c = cmp_token(ta[i], tb[i])) return c;
    }
    if (ta.size() > n) return cmp_remainder(ta, n);
    if (tb.size() > n) return -cmp_remainder(tb, n);
    return 0;
}

bool version_in_range(std::string_view v,
                      std::string_view start_including,
                      std::string_view start_excluding,
                      std::string_view end_including,
                      std::string_view end_excluding) {
    if (!start_including.empty() && version_compare(v, start_including) < 0) return false;
    if (!start_excluding.empty() && version_compare(v, start_excluding) <= 0) return false;
    if (!end_including.empty() && version_compare(v, end_including) > 0) return false;
    if (!end_excluding.empty() && version_compare(v, end_excluding) >= 0) return false;
    return true;
}

std::string version_upstream_part(std::string_view v) {
    unsigned long long epoch = 0;
    v = strip_epoch(v, epoch);

    // The LAST '-' introduces the packaging revision; upstream versions may
    // legitimately contain earlier ones ("1.2-beta-3-2ubuntu1").
    const auto dash = v.rfind('-');
    if (dash != std::string_view::npos) v = v.substr(0, dash);

    // "+dfsg", "+deb11u1", "+really1.2.3" are Debian packaging artefacts.
    const auto plus = v.find('+');
    if (plus != std::string_view::npos) v = v.substr(0, plus);

    return std::string(v);
}

} // namespace ns
