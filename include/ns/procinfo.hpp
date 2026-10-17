#pragma once

#include <cstdint>
#include <string>

namespace ns {

// What this process is running as and how much it is using. Reported by
// `nsctl status`, so "the service runs unprivileged" and "memory is flat
// across cycles" are things anyone can check on a live install.
struct ProcInfo {
    std::uint32_t pid = 0;
    std::string user;        // DOMAIN\name of the process token
    bool elevated = false;   // full admin token (UAC "elevated")
    std::uint32_t privileges_enabled = 0;  // count of enabled token privileges
    std::uint64_t private_bytes = 0;
    std::uint64_t working_set = 0;
    std::uint64_t peak_working_set = 0;
    std::uint32_t handles = 0;
    std::uint32_t threads = 0;
};

ProcInfo self_info();

} // namespace ns
