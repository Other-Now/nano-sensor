#pragma once

namespace ns {

inline constexpr const char* kAgentName = "nano-sensor";
inline constexpr const char* kAgentVersion = "0.1.0";

// Bumped as the staged ladder in PLAN.md advances, so a report received by the
// cloud says which capabilities the sending agent actually had.
inline constexpr const char* kAgentStage = "stage0-scaffold";

} // namespace ns
