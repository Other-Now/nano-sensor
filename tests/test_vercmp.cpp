#include "test_util.hpp"

#include "ns/vercmp.hpp"

using ns::version_compare;
using ns::version_in_range;
using ns::version_upstream_part;

namespace {
// Reads better in failure output than a bare -1/0/1.
const char* rel(int c) { return c < 0 ? "<" : (c > 0 ? ">" : "=="); }

void expect(const char* a, const char* op, const char* b) {
    const char* got = rel(version_compare(a, b));
    if (std::string(got) != op) {
        ::nstest::fail(__FILE__, __LINE__,
                       std::string("version_compare(\"") + a + "\", \"" + b +
                           "\")\n      actual:   " + a + " " + got + " " + b +
                           "\n      expected: " + a + " " + op + " " + b);
    }
}
} // namespace

NS_TEST(version_numeric_not_lexicographic) {
    // The single most damaging bug in naive CVE matching: as strings "1.10"
    // sorts below "1.9", so a patched host gets reported vulnerable.
    expect("1.10", ">", "1.9");
    expect("1.9", "<", "1.10");
    expect("2.0", ">", "1.99");
    expect("1.0.10", ">", "1.0.9");
}

NS_TEST(version_equality_and_separators) {
    expect("1.2.3", "==", "1.2.3");
    expect("1.2.3", "==", "1_2_3");  // separators are boundaries, not content
    expect("007", "==", "7");        // leading zeros are not significant
}

NS_TEST(version_longer_is_greater) {
    expect("1.0.1", ">", "1.0");
    expect("1.0", "<", "1.0.1");
}

NS_TEST(version_prerelease_sorts_before_release) {
    expect("1.0rc1", "<", "1.0");
    expect("1.0-rc1", "<", "1.0");
    expect("1.0beta", "<", "1.0");
    expect("1.0alpha", "<", "1.0beta");
    expect("2.0-dev", "<", "2.0");
}

NS_TEST(version_debian_tilde_sorts_lowest) {
    expect("1.0~rc1", "<", "1.0");
    expect("1.0~", "<", "1.0");
    expect("1.0~rc1", "<", "1.0~rc2");
}

NS_TEST(version_openssl_letter_suffixes) {
    // A letter suffix that is not a pre-release word means a patch release and
    // sorts ABOVE the bare version. OpenSSL's entire 1.0.2 line depends on this.
    expect("1.0.2k", ">", "1.0.2");
    expect("1.0.2k", "<", "1.0.2l");
    expect("1.0.2", "<", "1.0.2a");
    expect("1.1.1w", ">", "1.1.1a");
    expect("1.0.2p", ">", "1.0.2");
}

NS_TEST(version_numeric_outranks_alpha_at_same_position) {
    expect("1.0.1", ">", "1.0a");
}

NS_TEST(version_epoch_dominates) {
    expect("1:1.0", ">", "2.0");
    expect("2:0.1", ">", "1:99.0");
    expect("1:1.0", "==", "1:1.0");
    // A stray colon that is not a numeric epoch must not be treated as one.
    expect("a:1.0", "==", "a:1.0");
}

NS_TEST(version_ranges) {
    // The NVD bound shapes: [start, end), (start, end], and unbounded sides.
    CHECK(version_in_range("1.5", "1.0", "", "", "2.0"));
    CHECK(!version_in_range("2.0", "1.0", "", "", "2.0"));   // end-excluding
    CHECK(version_in_range("2.0", "1.0", "", "2.0", ""));    // end-including
    CHECK(!version_in_range("0.9", "1.0", "", "", "2.0"));
    CHECK(!version_in_range("1.0", "", "1.0", "", ""));      // start-excluding
    CHECK(version_in_range("1.0.1", "", "1.0", "", ""));
    CHECK(version_in_range("anything", "", "", "", ""));     // unbounded
    // The realistic case: fixed in 1.1.1t, host on 1.1.1f.
    CHECK(version_in_range("1.1.1f", "1.1.1", "", "", "1.1.1t"));
    CHECK(!version_in_range("1.1.1t", "1.1.1", "", "", "1.1.1t"));
}

NS_TEST(version_upstream_part_strips_packaging) {
    CHECK_EQ(version_upstream_part("1.2.3-1ubuntu2"), std::string("1.2.3"));
    CHECK_EQ(version_upstream_part("1.2.3-45.el8"), std::string("1.2.3"));
    CHECK_EQ(version_upstream_part("1:8.9p1-3"), std::string("8.9p1"));
    CHECK_EQ(version_upstream_part("2.4.52+dfsg-1"), std::string("2.4.52"));
    CHECK_EQ(version_upstream_part("1.2.3"), std::string("1.2.3"));
    // Upstream versions may contain their own dashes; only the last one is
    // the packaging revision.
    CHECK_EQ(version_upstream_part("1.2-beta-3-2ubuntu1"), std::string("1.2-beta-3"));
}
