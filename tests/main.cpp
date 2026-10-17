#include <gtest/gtest.h>

#if defined(_MSC_VER) && defined(_DEBUG)
#include <crtdbg.h>

// Per-test leak check on the MSVC debug heap.
//
// Debug builds route every allocation through the CRT debug heap, which can
// snapshot what is live. A test that ends with more _NORMAL_BLOCK bytes live
// than it started with leaked them. Run the Debug build of ns_tests to get
// this; Release builds skip it.
//
// Reported per test, so a leak points at the code under test rather than at
// "somewhere in the binary". Not an EXPECT inside the test: by OnTestEnd the
// test's result is sealed, so leaks are counted here and fail the run at exit.
//
// Two sources of false positives, both handled rather than filtered by name:
//  - function-local statics (e.g. the noise-word set in cve.cpp) allocate on
//    first use and live until exit. So the suite runs twice and only the
//    second pass is checked: by then every lazy static already exists.
//  - gtest stores the messages of failed and skipped tests on the heap. Those
//    tests are not leak-checked; they already fail or say why they skipped.
class LeakCheck : public ::testing::EmptyTestEventListener {
public:
    int leaking_tests = 0;
    int checked_tests = 0;

private:
    _CrtMemState before_{};
    bool checking_ = false;

    void OnTestIterationStart(const ::testing::UnitTest&, int iteration) override {
        checking_ = iteration > 0;
    }

    void OnTestStart(const ::testing::TestInfo&) override { _CrtMemCheckpoint(&before_); }

    void OnTestEnd(const ::testing::TestInfo& info) override {
        if (!checking_ || info.result()->Failed() || info.result()->Skipped()) return;
        ++checked_tests;
        _CrtMemState after{}, diff{};
        _CrtMemCheckpoint(&after);
        if (_CrtMemDifference(&diff, &before_, &after) && diff.lSizes[_NORMAL_BLOCK] > 0) {
            ++leaking_tests;
            std::printf("[  LEAK    ] %s.%s: %zu bytes in %zu blocks still live\n",
                        info.test_suite_name(), info.name(), diff.lSizes[_NORMAL_BLOCK],
                        diff.lCounts[_NORMAL_BLOCK]);
        }
    }
};
#endif

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
#if defined(_MSC_VER) && defined(_DEBUG)
    if (GTEST_FLAG_GET(repeat) == 1) GTEST_FLAG_SET(repeat, 2);
    auto* leaks = new LeakCheck;  // owned by gtest once appended
    ::testing::UnitTest::GetInstance()->listeners().Append(leaks);
    const int rc = RUN_ALL_TESTS();
    if (leaks->leaking_tests) {
        std::printf("%d test(s) leaked memory\n", leaks->leaking_tests);
        return rc ? rc : 1;
    }
    std::printf("debug-heap leak check: %d tests checked, 0 leaked\n", leaks->checked_tests);
    return rc;
#else
    return RUN_ALL_TESTS();
#endif
}
