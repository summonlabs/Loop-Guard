#include "loop_guard/digest.hpp"

#include <cstring>

namespace loop_guard {
namespace {

constexpr std::uint32_t kInitialState[8] = {0x6A09E667U, 0xBB67AE85U, 0x3C6EF372U, 0xA54FF53AU,
                                            0x510E527FU, 0x9B05688CU, 0x1F83D9ABU, 0x5BE0CD19U};

constexpr std::uint32_t kRoundConstants[64] = {
    0x428A2F98U, 0x71374491U, 0xB5C0FBCFU, 0xE9B5DBA5U, 0x3956C25BU, 0x59F111F1U, 0x923F82A4U,
    0xAB1C5ED5U, 0xD807AA98U, 0x12835B01U, 0x243185BEU, 0x550C7DC3U, 0x72BE5D74U, 0x80DEB1FEU,
    0x9BDC06A7U, 0xC19BF174U, 0xE49B69C1U, 0xEFBE4786U, 0x0FC19DC6U, 0x240CA1CCU, 0x2DE92C6FU,
    0x4A7484AAU, 0x5CB0A9DCU, 0x76F988DAU, 0x983E5152U, 0xA831C66DU, 0xB00327C8U, 0xBF597FC7U,
    0xC6E00BF3U, 0xD5A79147U, 0x06CA6351U, 0x14292967U, 0x27B70A85U, 0x2E1B2138U, 0x4D2C6DFCU,
    0x53380D13U, 0x650A7354U, 0x766A0ABBU, 0x81C2C92EU, 0x92722C85U, 0xA2BFE8A1U, 0xA81A664BU,
    0xC24B8B70U, 0xC76C51A3U, 0xD192E819U, 0xD6990624U, 0xF40E3585U, 0x106AA070U, 0x19A4C116U,
    0x1E376C08U, 0x2748774CU, 0x34B0BCB5U, 0x391C0CB3U, 0x4ED8AA4AU, 0x5B9CCA4FU, 0x682E6FF3U,
    0x748F82EEU, 0x78A5636FU, 0x84C87814U, 0x8CC70208U, 0x90BEFFFAU, 0xA4506CEBU, 0xBEF9A3F7U,
    0xC67178F2U};

constexpr std::uint32_t rotr(std::uint32_t value, std::uint32_t bits) noexcept {
  return (value >> bits) | (value << (32U - bits));
}

}  // namespace

bool Digest::is_zero() const noexcept {
  for (const std::uint8_t byte : bytes) {
    if (byte != 0U) {
      return false;
    }
  }
  return true;
}

std::string Digest::to_hex() const {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(kDigestBytes * 2U);
  for (const std::uint8_t byte : bytes) {
    out.push_back(kHex[(byte >> 4U) & 0x0FU]);
    out.push_back(kHex[byte & 0x0FU]);
  }
  return out;
}

std::optional<Digest> Digest::from_hex(std::string_view text) noexcept {
  if (text.size() != kDigestBytes * 2U) {
    return std::nullopt;
  }
  auto nibble = [](char character) -> int {
    if (character >= '0' && character <= '9') {
      return character - '0';
    }
    if (character >= 'a' && character <= 'f') {
      return character - 'a' + 10;
    }
    if (character >= 'A' && character <= 'F') {
      return character - 'A' + 10;
    }
    return -1;
  };
  Digest digest;
  for (std::size_t index = 0; index < kDigestBytes; ++index) {
    const int high = nibble(text[index * 2U]);
    const int low = nibble(text[index * 2U + 1U]);
    if (high < 0 || low < 0) {
      return std::nullopt;
    }
    digest.bytes[index] = static_cast<std::uint8_t>((high << 4) | low);
  }
  return digest;
}

Sha256::Sha256() noexcept {
  for (std::size_t index = 0; index < state_.size(); ++index) {
    state_[index] = kInitialState[index];
  }
}

void Sha256::compress(std::span<const std::uint8_t, 64> block) noexcept {
  std::uint32_t schedule[64];
  for (std::size_t index = 0; index < 16; ++index) {
    schedule[index] = (static_cast<std::uint32_t>(block[index * 4U]) << 24U) |
                      (static_cast<std::uint32_t>(block[index * 4U + 1U]) << 16U) |
                      (static_cast<std::uint32_t>(block[index * 4U + 2U]) << 8U) |
                      static_cast<std::uint32_t>(block[index * 4U + 3U]);
  }
  for (std::size_t index = 16; index < 64; ++index) {
    const std::uint32_t s0 = rotr(schedule[index - 15], 7U) ^ rotr(schedule[index - 15], 18U) ^
                             (schedule[index - 15] >> 3U);
    const std::uint32_t s1 = rotr(schedule[index - 2], 17U) ^ rotr(schedule[index - 2], 19U) ^
                             (schedule[index - 2] >> 10U);
    schedule[index] = schedule[index - 16] + s0 + schedule[index - 7] + s1;
  }

  std::uint32_t a = state_[0];
  std::uint32_t b = state_[1];
  std::uint32_t c = state_[2];
  std::uint32_t d = state_[3];
  std::uint32_t e = state_[4];
  std::uint32_t f = state_[5];
  std::uint32_t g = state_[6];
  std::uint32_t h = state_[7];

  for (std::size_t index = 0; index < 64; ++index) {
    const std::uint32_t s1 = rotr(e, 6U) ^ rotr(e, 11U) ^ rotr(e, 25U);
    const std::uint32_t choice = (e & f) ^ ((~e) & g);
    const std::uint32_t temp1 = h + s1 + choice + kRoundConstants[index] + schedule[index];
    const std::uint32_t s0 = rotr(a, 2U) ^ rotr(a, 13U) ^ rotr(a, 22U);
    const std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
    const std::uint32_t temp2 = s0 + majority;

    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  state_[0] += a;
  state_[1] += b;
  state_[2] += c;
  state_[3] += d;
  state_[4] += e;
  state_[5] += f;
  state_[6] += g;
  state_[7] += h;
}

void Sha256::update(std::span<const std::uint8_t> data) noexcept {
  if (finished_) {
    return;
  }
  total_bytes_ += static_cast<std::uint64_t>(data.size());
  std::size_t offset = 0;
  if (buffered_ != 0U) {
    while (offset < data.size() && buffered_ < buffer_.size()) {
      buffer_[buffered_] = data[offset];
      ++buffered_;
      ++offset;
    }
    if (buffered_ == buffer_.size()) {
      compress(std::span<const std::uint8_t, 64>(buffer_));
      buffered_ = 0;
    }
  }
  while (data.size() - offset >= buffer_.size()) {
    compress(std::span<const std::uint8_t, 64>(data.data() + offset, 64));
    offset += buffer_.size();
  }
  while (offset < data.size()) {
    // buffered_ is always strictly below the block size here: the loop above drained
    // every complete block, and the branch above reset it when the block filled.
    if (buffered_ >= buffer_.size()) {
      break;
    }
    buffer_[buffered_] = data[offset];
    ++buffered_;
    ++offset;
  }
}

void Sha256::update(const std::uint8_t* data, std::size_t size) noexcept {
  update(std::span<const std::uint8_t>(data, size));
}

void Sha256::update(std::string_view text) noexcept {
  update(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(text.data()),
                                       text.size()));
}

void Sha256::update(std::uint8_t byte) noexcept { update(std::span<const std::uint8_t>(&byte, 1)); }

Digest Sha256::finish() noexcept {
  if (!finished_) {
    const std::uint64_t bit_length = total_bytes_ * 8U;
    // The padding is built arithmetically rather than appended byte by byte, so how much
    // padding there is follows in closed form from the buffered remainder and every
    // access is provably inside a fixed size buffer. One 0x80 byte, zeros, then the
    // 64-bit big-endian message length in bits.
    const std::size_t remainder = static_cast<std::size_t>(total_bytes_ % 64U);
    const std::size_t pad_size = remainder < 56U ? 56U - remainder : 120U - remainder;
    std::array<std::uint8_t, 128> padding{};
    padding[0] = 0x80U;
    for (std::size_t index = 0; index < 8U; ++index) {
      padding[pad_size + index] =
          static_cast<std::uint8_t>((bit_length >> ((7U - index) * 8U)) & 0xFFU);
    }
    update(std::span<const std::uint8_t>(padding.data(), pad_size + 8U));
    finished_ = true;
  }

  Digest digest;
  for (std::size_t index = 0; index < state_.size(); ++index) {
    digest.bytes[index * 4U] = static_cast<std::uint8_t>((state_[index] >> 24U) & 0xFFU);
    digest.bytes[index * 4U + 1U] = static_cast<std::uint8_t>((state_[index] >> 16U) & 0xFFU);
    digest.bytes[index * 4U + 2U] = static_cast<std::uint8_t>((state_[index] >> 8U) & 0xFFU);
    digest.bytes[index * 4U + 3U] = static_cast<std::uint8_t>(state_[index] & 0xFFU);
  }
  return digest;
}

Digest sha256(std::span<const std::uint8_t> data) noexcept {
  Sha256 hasher;
  hasher.update(data);
  return hasher.finish();
}

Digest sha256(std::string_view text) noexcept { return sha256(std::span<const std::uint8_t>(
    reinterpret_cast<const std::uint8_t*>(text.data()), text.size())); }

Digest sha256_segments(std::span<const std::span<const std::uint8_t>> segments) noexcept {
  Sha256 hasher;
  for (const auto segment : segments) {
    hasher.update(segment);
  }
  return hasher.finish();
}

}  // namespace loop_guard
