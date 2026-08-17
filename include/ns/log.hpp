#pragma once

#include <initializer_list>
#include <string_view>
#include <utility>

namespace ns {

enum class LogLevel { Debug = 0, Info = 1, Warn = 2, Error = 3 };

void log_set_level(LogLevel lvl);
LogLevel log_get_level();
bool log_set_level_by_name(std::string_view name);  // "debug"/"info"/"warn"/"error"

using LogField = std::pair<std::string_view, std::string_view>;

// One JSON object per line, written to *stderr*.
//
// stderr, not stdout, because stdout carries command output -- `nano-sensor
// inventory > host.json` has to produce a parseable file even when the run
// emitted warnings. Structured rather than free text because stage 6's
// diagnostics bundle greps these, and a human reading a support bundle at 2am
// should not have to reverse-engineer a printf format.
void log_event(LogLevel lvl, std::string_view msg,
               std::initializer_list<LogField> fields = {});

inline void log_debug(std::string_view m, std::initializer_list<LogField> f = {}) {
    log_event(LogLevel::Debug, m, f);
}
inline void log_info(std::string_view m, std::initializer_list<LogField> f = {}) {
    log_event(LogLevel::Info, m, f);
}
inline void log_warn(std::string_view m, std::initializer_list<LogField> f = {}) {
    log_event(LogLevel::Warn, m, f);
}
inline void log_error(std::string_view m, std::initializer_list<LogField> f = {}) {
    log_event(LogLevel::Error, m, f);
}

} // namespace ns
