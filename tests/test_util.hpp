#pragma once

// A ~70-line test harness, deliberately not GoogleTest.
//
// The agent has to build on a bare Windows box with nothing but MSVC and in a
// minimal Linux container. Adding a test framework would mean vendoring it or
// bolting a package-manager step onto both platforms -- a real cost, paid for
// assertions and a runner, both of which fit in this file.

#include <cstdio>
#include <functional>
#include <sstream>
#include <string>
#include <vector>

namespace nstest {

// Rendering for assertion failure messages. Without this a failing CHECK_EQ
// tells you only that two things differed, which means re-running under a
// debugger to learn anything -- the single most useful feature of a real test
// framework and the cheapest to reproduce.
inline std::string show(const std::string& s) { return "\"" + s + "\""; }
inline std::string show(const char* s) { return std::string("\"") + s + "\""; }
inline std::string show(bool b) { return b ? "true" : "false"; }

template <class T>
std::string show(const T& v) {
    std::ostringstream os;
    os << v;
    return os.str();
}

struct Case {
    const char* name;
    std::function<void()> fn;
};

inline std::vector<Case>& registry() {
    static std::vector<Case> cases;
    return cases;
}

inline int& failures() {
    static int n = 0;
    return n;
}

inline std::string& current() {
    static std::string s;
    return s;
}

struct Register {
    Register(const char* name, std::function<void()> fn) {
        registry().push_back({name, std::move(fn)});
    }
};

inline void fail(const char* file, int line, const std::string& what) {
    ++failures();
    std::fprintf(stderr, "  FAIL %s\n    %s:%d: %s\n", current().c_str(), file, line,
                 what.c_str());
}

inline int run_all() {
    for (auto& c : registry()) {
        current() = c.name;
        const int before = failures();
        c.fn();
        if (failures() == before) std::printf("  ok   %s\n", c.name);
    }
    std::printf("\n");
    if (failures() == 0) {
        std::printf("all %zu tests passed\n", registry().size());
        return 0;
    }
    std::printf("%d assertion(s) failed across %zu tests\n", failures(),
                registry().size());
    return 1;
}

} // namespace nstest

#define NS_TEST(name)                                                        \
    static void name();                                                      \
    static ::nstest::Register reg_##name(#name, name);                       \
    static void name()

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (!(cond)) ::nstest::fail(__FILE__, __LINE__, "CHECK(" #cond ")");  \
    } while (0)

#define CHECK_EQ(a, b)                                                       \
    do {                                                                     \
        const auto& ns_a = (a);                                              \
        const auto& ns_b = (b);                                              \
        if (!(ns_a == ns_b)) {                                               \
            ::nstest::fail(__FILE__, __LINE__,                               \
                           "CHECK_EQ(" #a ", " #b ")\n      actual:   " +    \
                               ::nstest::show(ns_a) +                        \
                               "\n      expected: " + ::nstest::show(ns_b)); \
        }                                                                    \
    } while (0)
