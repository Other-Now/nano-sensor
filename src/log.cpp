#include "ns/log.hpp"

#include "ns/json.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <mutex>
#include <string>

namespace ns {

namespace {

std::atomic<LogLevel> g_level{LogLevel::Info};

// Interleaved half-lines in a support bundle are worse than a lock. This is not
// a hot path -- the collectors run on a schedule measured in minutes.
std::mutex g_mutex;

const char* level_name(LogLevel lvl) {
    switch (lvl) {
    case LogLevel::Debug: return "debug";
    case LogLevel::Info:  return "info";
    case LogLevel::Warn:  return "warn";
    case LogLevel::Error: return "error";
    }
    return "info";
}

std::string utc_timestamp() {
    using namespace std::chrono;
    const auto now = system_clock::now();
    const auto secs = time_point_cast<seconds>(now);
    const auto ms = duration_cast<milliseconds>(now - secs).count();
    const std::time_t t = system_clock::to_time_t(secs);

    std::tm tm{};
#if defined(_WIN32)
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif

    char buf[40];
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
                  tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                  tm.tm_hour, tm.tm_min, tm.tm_sec, static_cast<int>(ms));
    return buf;
}

} // namespace

void log_set_level(LogLevel lvl) { g_level.store(lvl, std::memory_order_relaxed); }
LogLevel log_get_level() { return g_level.load(std::memory_order_relaxed); }

bool log_set_level_by_name(std::string_view name) {
    if (name == "debug") { log_set_level(LogLevel::Debug); return true; }
    if (name == "info")  { log_set_level(LogLevel::Info);  return true; }
    if (name == "warn")  { log_set_level(LogLevel::Warn);  return true; }
    if (name == "error") { log_set_level(LogLevel::Error); return true; }
    return false;
}

void log_event(LogLevel lvl, std::string_view msg, std::initializer_list<LogField> fields) {
    if (static_cast<int>(lvl) < static_cast<int>(log_get_level())) return;

    JsonWriter w(/*pretty=*/false);
    w.begin_object();
    w.field("ts", utc_timestamp());
    w.field("level", level_name(lvl));
    w.field("msg", msg);
    for (const auto& [k, v] : fields) w.field(k, v);
    w.end_object();

    const std::string line = w.str();
    std::lock_guard<std::mutex> lock(g_mutex);
    std::fwrite(line.data(), 1, line.size(), stderr);
    std::fputc('\n', stderr);
}

} // namespace ns
