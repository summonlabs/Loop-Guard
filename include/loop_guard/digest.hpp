// Loop Guard - integrity digests.
//
// Loop Guard uses SHA-256 as an *integrity* primitive: it detects corruption and
// accidental truncation of durable documents and wire frames. It is explicitly NOT
// an authentication mechanism, no keyed mode is used, and no claim of authenticity
// or confidentiality is made anywhere in this runtime.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace loop_guard {

inline constexpr std::size_t kDigestBytes = 32;

/// A 256-bit integrity digest with canonical hexadecimal rendering.
struct Digest {
  std::array<std::uint8_t, kDigestBytes> bytes{};

  friend bool operator==(const Digest& lhs, const Digest& rhs) noexcept {
    return lhs.bytes == rhs.bytes;
  }
  friend bool operator!=(const Digest& lhs, const Digest& rhs) noexcept {
    return !(lhs.bytes == rhs.bytes);
  }
  friend bool operator<(const Digest& lhs, const Digest& rhs) noexcept {
    return lhs.bytes < rhs.bytes;
  }

  [[nodiscard]] bool is_zero() const noexcept;
  [[nodiscard]] std::string to_hex() const;
  /// Parses exactly 64 lowercase or uppercase hex characters. Rejects any other length
  /// or character, including whitespace and the "0x" prefix.
  [[nodiscard]] static std::optional<Digest> from_hex(std::string_view text) noexcept;
};

/// Streaming SHA-256.
class Sha256 {
 public:
  Sha256() noexcept;
  void update(std::span<const std::uint8_t> data) noexcept;
  void update(const std::uint8_t* data, std::size_t size) noexcept;
  void update(std::string_view text) noexcept;
  void update(std::uint8_t byte) noexcept;
  /// Ends the hash. Further update() calls are ignored; callers must not rely on that
  /// behaviour, and the runtime never does.
  [[nodiscard]] Digest finish() noexcept;

 private:
  /// Compresses exactly one 64 byte block. The extent is part of the type so that a
  /// static analyser can prove every call site is in bounds.
  void compress(std::span<const std::uint8_t, 64> block) noexcept;

  std::array<std::uint32_t, 8> state_{};
  std::array<std::uint8_t, 64> buffer_{};
  std::uint64_t total_bytes_ = 0;
  std::size_t buffered_ = 0;
  bool finished_ = false;
};

[[nodiscard]] Digest sha256(std::span<const std::uint8_t> data) noexcept;
[[nodiscard]] Digest sha256(std::string_view text) noexcept;

/// Digests a sequence of segments as if they were concatenated, without allocating a
/// joined buffer. Used by the wire codec to hash a header and payload in one pass.
[[nodiscard]] Digest sha256_segments(std::span<const std::span<const std::uint8_t>> segments) noexcept;

}  // namespace loop_guard
