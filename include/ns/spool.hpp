#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace ns {

// An on-disk, bounded, crash-safe event queue.
//
// This is what makes "the sensor lost connectivity for six hours and lost
// nothing" true rather than aspirational. Everything the agent wants to send
// goes here first and is removed only once the cloud has acknowledged it, so a
// process kill, a power cut, or a week-long outage costs at most the records the
// OS had not yet flushed.
//
// Layout: a directory of append-only segment files plus one small state file.
//
//   seg-00000001.log   records, oldest segment first
//   seg-00000002.log
//   state              read cursor + counters, rewritten atomically
//
// Each record is framed:
//
//   u32 magic | u32 payload_length | u32 crc32(payload) | payload bytes
//
// The frame is what makes a torn tail survivable. A process killed mid-write
// leaves a partial record; on open the reader walks forward, stops at the first
// frame that is short or fails its CRC, and truncates there. Without the length
// AND the checksum you cannot tell a partial write from a valid record that
// happens to start with plausible bytes.
class Spool {
public:
    struct Config {
        std::string dir;
        // Total on-disk budget. When exceeded, the OLDEST segment is deleted --
        // see the note on drop policy in the .cpp. Default 64 MiB.
        std::uint64_t max_bytes = 64ull * 1024 * 1024;
        // Roll to a new segment past this size. Segments are the unit of
        // deletion, so this also sets how coarse eviction is. Default 4 MiB.
        std::uint64_t segment_bytes = 4ull * 1024 * 1024;
        // fsync each append. Correct and slow. Off by default: the agent's
        // durability requirement is "survive a process crash", which the OS page
        // cache already provides, not "survive a power cut mid-record".
        bool fsync_on_append = false;
    };

    struct Record {
        std::uint64_t sequence = 0;
        std::string payload;
    };

    struct Stats {
        std::uint64_t appended = 0;      // records accepted, this process
        std::uint64_t committed = 0;     // records acknowledged and released
        std::uint64_t dropped = 0;       // records evicted unsent under pressure
        std::uint64_t pending = 0;       // records waiting to be sent
        std::uint64_t bytes_on_disk = 0;
        std::uint64_t segments = 0;
    };

    ~Spool();

    bool open(const Config& cfg, std::string& error);
    void close();

    bool append(const std::string& payload, std::string& error);

    // Up to `max_records` of the oldest unacknowledged records. Non-destructive:
    // nothing is released until commit() says the cloud took them.
    std::vector<Record> peek(std::size_t max_records, std::string& error) const;

    // Release the oldest `count` records. Called only after the cloud has
    // acknowledged them, which is what makes delivery at-least-once: a crash
    // between send and commit re-sends, it never loses.
    bool commit(std::size_t count, std::string& error);

    Stats stats() const;
    const Config& config() const { return cfg_; }

private:
    bool load_state(std::string& error);
    bool save_state(std::string& error) const;
    bool scan_segments(std::string& error);
    bool enforce_bounds(std::string& error);
    std::string segment_path(std::uint64_t id) const;
    std::uint64_t total_bytes() const;

    Config cfg_;
    bool open_ = false;

    std::vector<std::uint64_t> segments_;  // ascending segment ids present
    std::uint64_t read_segment_ = 0;       // segment holding the next unsent record
    std::uint64_t read_offset_ = 0;        // byte offset within it
    std::uint64_t next_sequence_ = 1;

    mutable Stats stats_;
};

} // namespace ns
