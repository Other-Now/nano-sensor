#include "ns/spool.hpp"

#include "ns/log.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>

#if defined(_WIN32)
#include <io.h>
#else
#include <unistd.h>
#endif

namespace fs = std::filesystem;

namespace ns {

namespace {

constexpr std::uint32_t kMagic = 0x4E535031;  // "NSP1"
constexpr std::size_t kHeaderBytes = 12;      // magic + length + crc

std::uint32_t crc32(const void* data, std::size_t len) {
    static std::array<std::uint32_t, 256> table = [] {
        std::array<std::uint32_t, 256> t{};
        for (std::uint32_t i = 0; i < 256; ++i) {
            std::uint32_t c = i;
            for (int k = 0; k < 8; ++k) c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            t[i] = c;
        }
        return t;
    }();

    const auto* p = static_cast<const unsigned char*>(data);
    std::uint32_t c = 0xFFFFFFFFu;
    for (std::size_t i = 0; i < len; ++i) c = table[(c ^ p[i]) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

void put_u32(char* dst, std::uint32_t v) {
    // Little-endian explicitly rather than memcpy of the native representation:
    // a spool directory written on one host and inspected on another must not
    // depend on both having the same endianness.
    dst[0] = static_cast<char>(v & 0xFF);
    dst[1] = static_cast<char>((v >> 8) & 0xFF);
    dst[2] = static_cast<char>((v >> 16) & 0xFF);
    dst[3] = static_cast<char>((v >> 24) & 0xFF);
}

std::uint32_t get_u32(const char* src) {
    return static_cast<std::uint32_t>(static_cast<unsigned char>(src[0])) |
           (static_cast<std::uint32_t>(static_cast<unsigned char>(src[1])) << 8) |
           (static_cast<std::uint32_t>(static_cast<unsigned char>(src[2])) << 16) |
           (static_cast<std::uint32_t>(static_cast<unsigned char>(src[3])) << 24);
}

std::string zero_pad(std::uint64_t id) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "seg-%08llu.log", static_cast<unsigned long long>(id));
    return buf;
}

} // namespace

Spool::~Spool() { close(); }

std::string Spool::segment_path(std::uint64_t id) const {
    return (fs::path(cfg_.dir) / zero_pad(id)).string();
}

bool Spool::open(const Config& cfg, std::string& error) {
    cfg_ = cfg;
    std::error_code ec;
    fs::create_directories(cfg_.dir, ec);
    if (ec) {
        error = "cannot create spool directory " + cfg_.dir + ": " + ec.message();
        return false;
    }
    if (!scan_segments(error)) return false;
    if (!load_state(error)) return false;
    open_ = true;

    stats_.pending = 0;
    std::string ignored;
    stats_.pending = peek(SIZE_MAX, ignored).size();
    log_info("spool opened",
             {{"dir", cfg_.dir},
              {"segments", std::to_string(segments_.size())},
              {"pending", std::to_string(stats_.pending)}});
    return true;
}

void Spool::close() { open_ = false; }

bool Spool::scan_segments(std::string& error) {
    segments_.clear();
    std::error_code ec;
    for (const auto& entry : fs::directory_iterator(cfg_.dir, ec)) {
        if (ec) break;
        const std::string name = entry.path().filename().string();
        if (name.rfind("seg-", 0) != 0 || name.size() < 8) continue;
        const std::uint64_t id = std::strtoull(name.substr(4).c_str(), nullptr, 10);
        if (id > 0) segments_.push_back(id);
    }
    if (ec) {
        error = "cannot scan spool directory: " + ec.message();
        return false;
    }
    std::sort(segments_.begin(), segments_.end());
    return true;
}

bool Spool::load_state(std::string& error) {
    const fs::path state = fs::path(cfg_.dir) / "state";
    read_segment_ = segments_.empty() ? 1 : segments_.front();
    read_offset_ = 0;
    next_sequence_ = 1;

    std::ifstream f(state);
    if (f) {
        std::uint64_t seg = 0, off = 0, seq = 1, committed = 0, dropped = 0;
        f >> seg >> off >> seq >> committed >> dropped;
        if (f.good() || f.eof()) {
            read_segment_ = seg;
            read_offset_ = off;
            next_sequence_ = seq ? seq : 1;
            stats_.committed = committed;
            stats_.dropped = dropped;
        }
    }

    // The state file can name a segment that eviction has since removed, or that
    // never existed if the file is from a wiped directory. Snapping forward to
    // the oldest surviving segment is the only safe recovery: reading from a
    // missing segment would silently report an empty queue.
    if (!segments_.empty() && read_segment_ < segments_.front()) {
        read_segment_ = segments_.front();
        read_offset_ = 0;
    }
    (void)error;
    return true;
}

bool Spool::save_state(std::string& error) const {
    const fs::path final_path = fs::path(cfg_.dir) / "state";
    const fs::path tmp = fs::path(cfg_.dir) / "state.tmp";

    {
        std::ofstream f(tmp, std::ios::trunc);
        if (!f) {
            error = "cannot write spool state";
            return false;
        }
        f << read_segment_ << ' ' << read_offset_ << ' ' << next_sequence_ << ' '
          << stats_.committed << ' ' << stats_.dropped << '\n';
        if (!f) {
            error = "failed writing spool state";
            return false;
        }
    }

    // Write-then-rename. A crash during the rewrite must leave either the old
    // cursor or the new one, never a half-written cursor -- a truncated state
    // file would reset the queue to the beginning and re-send everything, or
    // worse, parse as a garbage offset.
    std::error_code ec;
    fs::rename(tmp, final_path, ec);
    if (ec) {
        // Windows rename onto an existing file fails on some filesystems; fall
        // back to remove-then-rename, which is a smaller window but still
        // better than leaving the temp file behind.
        fs::remove(final_path, ec);
        fs::rename(tmp, final_path, ec);
        if (ec) {
            error = "cannot commit spool state: " + ec.message();
            return false;
        }
    }
    return true;
}

std::uint64_t Spool::total_bytes() const {
    std::uint64_t total = 0;
    std::error_code ec;
    for (std::uint64_t id : segments_) {
        const auto size = fs::file_size(segment_path(id), ec);
        if (!ec) total += size;
    }
    return total;
}

bool Spool::append(const std::string& payload, std::string& error) {
    if (!open_) {
        error = "spool is not open";
        return false;
    }
    if (payload.size() > 0xFFFFFFFFull) {
        error = "record too large for the frame length field";
        return false;
    }

    if (segments_.empty()) segments_.push_back(1);

    std::uint64_t active = segments_.back();
    std::error_code ec;
    auto size = fs::file_size(segment_path(active), ec);
    if (ec) size = 0;
    if (size >= cfg_.segment_bytes) {
        active = active + 1;
        segments_.push_back(active);
    }

    std::string frame(kHeaderBytes, '\0');
    put_u32(&frame[0], kMagic);
    put_u32(&frame[4], static_cast<std::uint32_t>(payload.size()));
    put_u32(&frame[8], crc32(payload.data(), payload.size()));

    std::ofstream f(segment_path(active), std::ios::binary | std::ios::app);
    if (!f) {
        error = "cannot open spool segment for append";
        return false;
    }
    f.write(frame.data(), static_cast<std::streamsize>(frame.size()));
    f.write(payload.data(), static_cast<std::streamsize>(payload.size()));
    f.flush();
    if (!f) {
        error = "spool append failed";
        return false;
    }

    if (cfg_.fsync_on_append) {
        f.close();
        // std::ofstream has no fsync; reopen at the descriptor level. Only worth
        // doing when the caller has asked for power-cut durability -- flush()
        // above already covers the far more common process-crash case.
        const std::string path = segment_path(active);
#if defined(_WIN32)
        FILE* raw = nullptr;
        if (fopen_s(&raw, path.c_str(), "rb") == 0 && raw) {
            _commit(_fileno(raw));
            std::fclose(raw);
        }
#else
        FILE* raw = std::fopen(path.c_str(), "rb");
        if (raw) {
            ::fsync(fileno(raw));
            std::fclose(raw);
        }
#endif
    }

    ++stats_.appended;
    ++stats_.pending;
    ++next_sequence_;

    if (!enforce_bounds(error)) return false;
    return save_state(error);
}

bool Spool::enforce_bounds(std::string& error) {
    // Drop policy: OLDEST FIRST.
    //
    // The alternative -- refusing new records once full -- keeps a stale
    // snapshot of a host and discards the current one, which for a security
    // sensor is exactly backwards: the newest inventory is the one describing
    // the machine as it is now. Losing the oldest is a real loss and is counted
    // and reported, never silent.
    while (total_bytes() > cfg_.max_bytes && segments_.size() > 1) {
        const std::uint64_t victim = segments_.front();

        std::uint64_t lost = 0;
        if (victim >= read_segment_) {
            std::string ignored;
            const auto pending_in_victim = peek(SIZE_MAX, ignored);
            lost = pending_in_victim.size();
        }

        std::error_code ec;
        fs::remove(segment_path(victim), ec);
        segments_.erase(segments_.begin());

        if (read_segment_ <= victim) {
            read_segment_ = segments_.empty() ? victim + 1 : segments_.front();
            read_offset_ = 0;
            std::string ignored;
            const auto still = peek(SIZE_MAX, ignored).size();
            const std::uint64_t dropped = lost > still ? lost - still : 0;
            stats_.dropped += dropped;
            stats_.pending = still;
            if (dropped > 0) {
                log_warn("spool over budget, dropped oldest records",
                         {{"dropped", std::to_string(dropped)},
                          {"max_bytes", std::to_string(cfg_.max_bytes)}});
            }
        }
    }
    (void)error;
    return true;
}

std::vector<Spool::Record> Spool::peek(std::size_t max_records, std::string& error) const {
    std::vector<Record> out;
    if (segments_.empty()) return out;

    std::uint64_t seq = 0;
    for (std::uint64_t id : segments_) {
        if (id < read_segment_) continue;

        std::ifstream f(segment_path(id), std::ios::binary);
        if (!f) continue;
        if (id == read_segment_) f.seekg(static_cast<std::streamoff>(read_offset_));

        while (out.size() < max_records) {
            char header[kHeaderBytes];
            f.read(header, kHeaderBytes);
            if (f.gcount() != static_cast<std::streamsize>(kHeaderBytes)) break;

            if (get_u32(header) != kMagic) {
                error = "spool frame magic mismatch; stopping at the damaged record";
                break;
            }
            const std::uint32_t len = get_u32(header + 4);
            const std::uint32_t want_crc = get_u32(header + 8);

            std::string payload(len, '\0');
            f.read(payload.data(), static_cast<std::streamsize>(len));
            if (f.gcount() != static_cast<std::streamsize>(len)) {
                // A short tail is the normal signature of a process killed
                // mid-append. Everything before it is intact and is returned.
                break;
            }
            if (crc32(payload.data(), payload.size()) != want_crc) {
                error = "spool record failed CRC; stopping at the damaged record";
                break;
            }

            Record r;
            r.sequence = ++seq;
            r.payload = std::move(payload);
            out.push_back(std::move(r));
        }
        if (out.size() >= max_records) break;
    }
    return out;
}

bool Spool::commit(std::size_t count, std::string& error) {
    if (!open_) {
        error = "spool is not open";
        return false;
    }
    if (count == 0) return true;

    std::size_t remaining = count;

    while (remaining > 0 && !segments_.empty()) {
        const std::uint64_t id = read_segment_;
        std::ifstream f(segment_path(id), std::ios::binary);
        if (!f) {
            // The segment is gone (evicted). Move to the next one.
            auto it = std::upper_bound(segments_.begin(), segments_.end(), id);
            if (it == segments_.end()) break;
            read_segment_ = *it;
            read_offset_ = 0;
            continue;
        }

        f.seekg(static_cast<std::streamoff>(read_offset_));
        bool advanced = false;
        while (remaining > 0) {
            char header[kHeaderBytes];
            f.read(header, kHeaderBytes);
            if (f.gcount() != static_cast<std::streamsize>(kHeaderBytes)) break;
            if (get_u32(header) != kMagic) break;
            const std::uint32_t len = get_u32(header + 4);

            f.seekg(static_cast<std::streamoff>(len), std::ios::cur);
            if (!f) break;

            read_offset_ += kHeaderBytes + len;
            --remaining;
            ++stats_.committed;
            if (stats_.pending > 0) --stats_.pending;
            advanced = true;
        }

        if (remaining == 0) break;
        if (!advanced) break;

        // Exhausted this segment. Retire it and continue in the next.
        auto it = std::upper_bound(segments_.begin(), segments_.end(), id);
        if (it == segments_.end()) break;
        const std::uint64_t next = *it;
        std::error_code ec;
        fs::remove(segment_path(id), ec);
        segments_.erase(std::remove(segments_.begin(), segments_.end(), id),
                        segments_.end());
        read_segment_ = next;
        read_offset_ = 0;
    }

    return save_state(error);
}

Spool::Stats Spool::stats() const {
    stats_.bytes_on_disk = total_bytes();
    stats_.segments = segments_.size();
    std::string ignored;
    stats_.pending = peek(SIZE_MAX, ignored).size();
    return stats_;
}

} // namespace ns
