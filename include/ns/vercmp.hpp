#pragma once

#include <string>
#include <string_view>

namespace ns {

// Software version comparison, which is the load-bearing piece of CVE matching
// and the piece naive scanners get wrong.
//
// The failure mode is specific: compare versions as strings and "1.10" sorts
// below "1.9", so a host running 1.10 is reported vulnerable to everything fixed
// in 1.9 -- a false positive that looks completely plausible in a report. Do it
// purely numerically and "1.0.2k" fails to parse at all.
//
// The rules implemented here are a deliberate hybrid of Debian's and RPM's,
// which is what a cross-distro, cross-platform inventory actually needs:
//
//   * A leading "N:" is an epoch and dominates everything after it.
//   * Versions split into alternating runs of digits and letters; separators
//     (. - _ +) are boundaries and are not themselves compared.
//   * Digit runs compare numerically ("10" > "9"), letter runs lexicographically.
//   * A digit run outranks a letter run at the same position, so 1.0.1 > 1.0a.
//   * '~' sorts before everything, including the end of the string, so
//     1.0~rc1 < 1.0. This is Debian's pre-release marker.
//   * When one version runs out of tokens, the longer one is normally greater
//     ("1.0.1" > "1.0"), EXCEPT when its next token is a pre-release word --
//     rc, alpha, beta, pre, dev, snapshot -- in which case it is smaller.
//     That is what makes 1.0rc1 < 1.0 while 1.0p2 > 1.0, and OpenSSL depends on
//     exactly that distinction.
//
// Returns -1 if a < b, 0 if equal, 1 if a > b.
int version_compare(std::string_view a, std::string_view b);

// True when `v` falls in the half-open/closed range described by the four NVD
// bound fields. Empty bound strings mean "unbounded on that side".
bool version_in_range(std::string_view v,
                      std::string_view start_including,
                      std::string_view start_excluding,
                      std::string_view end_including,
                      std::string_view end_excluding);

// Strips distro packaging noise that is never present in an NVD version string:
// a Debian revision ("1.2.3-1ubuntu2" -> "1.2.3") or an RPM release
// ("1.2.3-45.el8" -> "1.2.3").
//
// This is lossy on purpose. A distro backports a security fix into
// 1.2.3-1ubuntu2 while leaving the upstream version at 1.2.3, so comparing the
// upstream part alone will report a CVE the distro has already patched. That
// over-reporting is a known and accepted limitation -- resolving it needs
// per-distro security trackers (Debian DSA, Ubuntu USN, RHEL OVAL), not NVD.
// The README says so rather than letting the numbers imply otherwise.
std::string version_upstream_part(std::string_view v);

} // namespace ns
