// Loop Guard - version and build identity.
//
// The runtime reports a single compile-time version. Every durable format and
// every wire frame carries its own format version; neither is derived from this
// value, and a version bump here never silently reinterprets durable bytes.
#pragma once

#include <cstdint>
#include <string>

namespace loop_guard {

inline constexpr std::uint32_t kVersionMajor = 1;
inline constexpr std::uint32_t kVersionMinor = 0;
inline constexpr std::uint32_t kVersionPatch = 0;

/// Human readable semantic version, e.g. "1.0.0".
[[nodiscard]] const std::string& version_string();

/// Semantic version as a packed integer: major << 16 | minor << 8 | patch.
[[nodiscard]] constexpr std::uint32_t version_packed() noexcept {
  return (kVersionMajor << 16U) | (kVersionMinor << 8U) | kVersionPatch;
}

/// Compiler and build-mode identity of the binary that is answering. This is
/// diagnostic metadata only; it is never part of an authority decision.
[[nodiscard]] const std::string& build_identity();

}  // namespace loop_guard
