#include <gtest/gtest.h>

#include "ns/spool.hpp"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>

namespace fs = std::filesystem;
using ns::Spool;

namespace {

struct TempDir {
    fs::path path;
    explicit TempDir(const char* stem) {
        path = fs::temp_directory_path() /
               (std::string("ns_spool_") + stem + "_" + std::to_string(std::rand()));
        fs::remove_all(path);
        fs::create_directories(path);
    }
    ~TempDir() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
};

Spool::Config cfg(const TempDir& d, std::uint64_t max_bytes = 64 * 1024,
                  std::uint64_t seg_bytes = 4 * 1024) {
    Spool::Config c;
    c.dir = d.path.string();
    c.max_bytes = max_bytes;
    c.segment_bytes = seg_bytes;
    return c;
}

} // namespace

TEST(Spool, spool_roundtrip) {
    TempDir d("rt");
    Spool s;
    std::string err;
    EXPECT_TRUE(s.open(cfg(d), err));

    EXPECT_TRUE(s.append("alpha", err));
    EXPECT_TRUE(s.append("beta", err));
    EXPECT_TRUE(s.append("gamma", err));

    auto got = s.peek(10, err);
    EXPECT_EQ(got.size(), std::size_t(3));
    if (got.size() == 3) {
        EXPECT_EQ(got[0].payload, std::string("alpha"));
        EXPECT_EQ(got[1].payload, std::string("beta"));
        EXPECT_EQ(got[2].payload, std::string("gamma"));
    }
}

TEST(Spool, spool_commit_releases_only_acknowledged_records) {
    TempDir d("commit");
    Spool s;
    std::string err;
    EXPECT_TRUE(s.open(cfg(d), err));
    for (const char* p : {"a", "b", "c", "d"}) EXPECT_TRUE(s.append(p, err));

    EXPECT_TRUE(s.commit(2, err));
    auto got = s.peek(10, err);
    EXPECT_EQ(got.size(), std::size_t(2));
    if (got.size() == 2) {
        EXPECT_EQ(got[0].payload, std::string("c"));
        EXPECT_EQ(got[1].payload, std::string("d"));
    }
}

TEST(Spool, spool_survives_reopen) {
    TempDir d("reopen");
    std::string err;
    {
        Spool s;
        EXPECT_TRUE(s.open(cfg(d), err));
        for (const char* p : {"one", "two", "three"}) EXPECT_TRUE(s.append(p, err));
        EXPECT_TRUE(s.commit(1, err));
    }
    // A new process attaches to the same directory and must resume exactly where
    // the cursor was left, not at the beginning and not at the end.
    {
        Spool s;
        EXPECT_TRUE(s.open(cfg(d), err));
        auto got = s.peek(10, err);
        EXPECT_EQ(got.size(), std::size_t(2));
        if (got.size() == 2) EXPECT_EQ(got[0].payload, std::string("two"));
    }
}

TEST(Spool, spool_torn_tail_is_discarded_not_fatal) {
    TempDir d("torn");
    std::string err;
    {
        Spool s;
        EXPECT_TRUE(s.open(cfg(d), err));
        EXPECT_TRUE(s.append("intact-one", err));
        EXPECT_TRUE(s.append("intact-two", err));
    }

    // Simulate a process killed mid-append: a complete frame header followed by
    // fewer payload bytes than it promises.
    const fs::path seg = d.path / "seg-00000001.log";
    {
        std::ofstream f(seg, std::ios::binary | std::ios::app);
        const char header[12] = {0x31, 0x50, 0x53, 0x4E,  // magic, little-endian
                                 0x40, 0x00, 0x00, 0x00,  // claims 64 payload bytes
                                 0x00, 0x00, 0x00, 0x00};
        f.write(header, sizeof(header));
        f.write("only-a-few-bytes", 16);  // ...but writes 16
    }

    Spool s;
    EXPECT_TRUE(s.open(cfg(d), err));
    auto got = s.peek(10, err);
    // The two complete records survive; the torn one is dropped rather than
    // taking the whole queue down with it.
    EXPECT_EQ(got.size(), std::size_t(2));
    if (got.size() == 2) EXPECT_EQ(got[1].payload, std::string("intact-two"));
}

TEST(Spool, spool_corrupt_payload_is_detected_by_crc) {
    TempDir d("crc");
    std::string err;
    {
        Spool s;
        EXPECT_TRUE(s.open(cfg(d), err));
        EXPECT_TRUE(s.append("good-record", err));
        EXPECT_TRUE(s.append("will-be-corrupted", err));
    }

    // Flip a byte inside the SECOND record's payload. The frame length still
    // agrees, so only the checksum can catch it.
    const fs::path seg = d.path / "seg-00000001.log";
    {
        std::fstream f(seg, std::ios::binary | std::ios::in | std::ios::out);
        f.seekp(12 + 11 + 12 + 2);  // into the second payload
        f.put('X');
    }

    Spool s;
    EXPECT_TRUE(s.open(cfg(d), err));
    auto got = s.peek(10, err);
    EXPECT_EQ(got.size(), std::size_t(1));
    if (!got.empty()) EXPECT_EQ(got[0].payload, std::string("good-record"));
}

TEST(Spool, spool_bounded_size_drops_oldest_and_counts_it) {
    TempDir d("bounded");
    std::string err;
    Spool s;
    // Tiny budget so eviction happens quickly and deterministically.
    EXPECT_TRUE(s.open(cfg(d, /*max_bytes=*/4 * 1024, /*seg_bytes=*/1024), err));

    const std::string payload(200, 'x');
    for (int i = 0; i < 100; ++i) EXPECT_TRUE(s.append(payload, err));

    const auto st = s.stats();
    // The budget is honoured...
    EXPECT_TRUE(st.bytes_on_disk <= 4 * 1024 + 1024);
    // ...records were genuinely lost...
    EXPECT_TRUE(st.dropped > 0);
    // ...and the loss is counted rather than silent, which is the whole point.
    EXPECT_EQ(st.appended, std::uint64_t(100));
    EXPECT_TRUE(st.pending < 100);
}

TEST(Spool, spool_empty_directory_is_valid) {
    TempDir d("empty");
    Spool s;
    std::string err;
    EXPECT_TRUE(s.open(cfg(d), err));
    EXPECT_EQ(s.peek(10, err).size(), std::size_t(0));
    EXPECT_TRUE(s.commit(0, err));  // committing nothing must not be an error
}
