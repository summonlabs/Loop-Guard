// Loop Guard - shared primitives: fence vectors, checked arithmetic, explanation
// documents and deterministic pseudo-randomness.
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "loop_guard/digest.hpp"
#include "loop_guard/enums.hpp"
#include "loop_guard/id.hpp"

namespace loop_guard {

// ---------------------------------------------------------------------------
// Checked arithmetic. Every accumulation that could overflow uses these helpers and
// treats overflow as an explicit failure rather than wraparound.
// ---------------------------------------------------------------------------
[[nodiscard]] bool checked_add_u64(std::uint64_t lhs, std::uint64_t rhs,
                                   std::uint64_t& out) noexcept;
[[nodiscard]] bool checked_mul_u64(std::uint64_t lhs, std::uint64_t rhs,
                                   std::uint64_t& out) noexcept;
/// Narrowing conversion that fails instead of truncating.
[[nodiscard]] bool narrow_u32(std::uint64_t value, std::uint32_t& out) noexcept;
[[nodiscard]] bool checked_add_u32(std::uint32_t lhs, std::uint32_t rhs,
                                   std::uint32_t& out) noexcept;

// ---------------------------------------------------------------------------
// Fence vector.
//
// Every externally visible decision binds a fence vector: the exact generation of
// every authority-bearing dependency the decision relied on. A decision is current
// only while all six components still compare equal. Matching identity is not
// matching generation: a ResourceId that survives a topology reload does not make an
// old finding current.
// ---------------------------------------------------------------------------
struct FenceVector {
  TopologyGeneration topology;
  ForwardingGeneration forwarding;
  PolicyGeneration policy;
  FabricEpoch fabric_epoch;
  CoordinatorEpoch epoch;
  BootId boot;

  friend bool operator==(const FenceVector& lhs, const FenceVector& rhs) noexcept {
    return lhs.topology == rhs.topology && lhs.forwarding == rhs.forwarding &&
           lhs.policy == rhs.policy && lhs.fabric_epoch == rhs.fabric_epoch &&
           lhs.epoch == rhs.epoch && lhs.boot == rhs.boot;
  }
  friend bool operator!=(const FenceVector& lhs, const FenceVector& rhs) noexcept {
    return !(lhs == rhs);
  }
  /// Total order used for canonical ordering of decision records.
  friend bool operator<(const FenceVector& lhs, const FenceVector& rhs) noexcept;

  [[nodiscard]] bool is_zero() const noexcept;
  [[nodiscard]] Digest digest() const;
  /// Canonical textual rendering, e.g. "t1/f1/p1/e1/c1/b1".
  [[nodiscard]] std::string to_string() const;
};

/// First component in which p candidate differs from p current, expressed as the
/// cause that fences a decision bound to p candidate. Returns FenceCause::None when
/// the two vectors are equal.
[[nodiscard]] FenceCause fence_cause(const FenceVector& candidate, const FenceVector& current) noexcept;

/// Process/incarnation identity. Every restart mints a new incarnation and advances
/// the coordinator epoch, so no pre-restart authority can be mistaken for current.
struct ProcessIdentity {
  BootId boot;
  IncarnationId incarnation;
  CoordinatorEpoch epoch;
  ProducerId producer;  ///< Stable identity of this deployment; survives restart.

  friend bool operator==(const ProcessIdentity&, const ProcessIdentity&) noexcept = default;
  [[nodiscard]] std::string to_string() const;
};

// ---------------------------------------------------------------------------
// Explanation.
//
// Explanations are bounded documents. They never grow without limit and they are the
// only place where human-readable text about a decision is produced.
// ---------------------------------------------------------------------------
struct ExplanationReason {
  ReasonCode code = ReasonCode::RequestAccepted;
  std::string subject;  ///< Canonical identifier of what the reason is about. Bounded.
  std::string detail;   ///< Bounded supplementary text. Never contains untrusted unbounded input.

  friend bool operator==(const ExplanationReason&, const ExplanationReason&) noexcept = default;
  friend bool operator<(const ExplanationReason& lhs, const ExplanationReason& rhs) noexcept;
  [[nodiscard]] std::string to_string() const;
};

/// A bounded, canonically ordered list of reasons. Insertion order never affects the
/// document, so two runs that reach the same decision produce byte-identical output.
class Explanation {
 public:
  Explanation() = default;
  explicit Explanation(std::uint32_t max_reasons) : max_reasons_(max_reasons) {}

  /// Adds a reason. Returns false when the document is already at capacity; the
  /// runtime counts the omission rather than growing the document.
  bool add(ReasonCode code, std::string subject = {}, std::string detail = {});
  void add_unique(ReasonCode code, std::string subject = {}, std::string detail = {});

  [[nodiscard]] const std::vector<ExplanationReason>& reasons() const noexcept { return reasons_; }
  [[nodiscard]] std::uint32_t dropped() const noexcept { return dropped_; }
  [[nodiscard]] bool empty() const noexcept { return reasons_.empty(); }
  [[nodiscard]] bool contains(ReasonCode code) const noexcept;
  [[nodiscard]] Severity severity() const noexcept;
  [[nodiscard]] bool at_capacity() const noexcept {
    return reasons_.size() >= static_cast<std::size_t>(max_reasons_);
  }
  [[nodiscard]] std::uint32_t capacity() const noexcept { return max_reasons_; }

  /// Canonical rendering: one line per reason, sorted by (code, subject, detail).
  [[nodiscard]] std::string to_text() const;
  [[nodiscard]] Digest digest() const;

 private:
  void sort_and_truncate();

  std::vector<ExplanationReason> reasons_;
  std::uint32_t max_reasons_ = 64;
  std::uint32_t dropped_ = 0;
  bool sorted_ = true;
};

/// Severity of the most severe reason present, used by tools for exit codes.
[[nodiscard]] Severity severity_of(ReasonCode code) noexcept;

/// Maps a specific reason code onto the operation outcome that best describes it. Used
/// where a decoder must report a structured failure without inventing an outcome.
[[nodiscard]] Outcome outcome_of(ReasonCode code) noexcept;

/// Truncates text at the largest UTF-8 boundary not exceeding max_bytes and appends an
/// ellipsis marker when truncation happened. The result is therefore at most
/// max_bytes + 3 bytes, and that bound is what callers rely on. Used for every string
/// that originates outside the library.
[[nodiscard]] std::string bounded_text(std::string_view text, std::size_t max_bytes);

/// Derives a strongly typed identity from a content digest. Identities produced this
/// way are content addressed: two runs that derive the same facts derive the same
/// identity, which is what makes canonical ordering and reproducible replays possible.
/// The zero value is never produced.
template <class Id>
[[nodiscard]] Id content_addressed_id(const Digest& digest) noexcept {
  std::uint64_t value = 0;
  for (std::size_t index = 0; index < 8; ++index) {
    value = (value << 8U) | static_cast<std::uint64_t>(digest.bytes[index]);
  }
  if (value == 0U) {
    value = 1U;
  }
  return Id::from_value(value);
}

// ---------------------------------------------------------------------------
// Deterministic pseudo-randomness. Every property and adversarial suite seeds this
// generator explicitly and prints the seed on failure, so a counterexample is always
// reproducible. The generator is never used to make a decision.
// ---------------------------------------------------------------------------
class Rng {
 public:
  explicit Rng(std::uint64_t seed) noexcept
      : state_(seed == 0U ? 0x9E3779B97F4A7C15ULL : seed), seed_(seed) {}

  [[nodiscard]] std::uint64_t next_u64() noexcept;
  /// Uniform value in [0, bound). Precondition: bound > 0.
  [[nodiscard]] std::uint64_t next_below(std::uint64_t bound) noexcept;
  [[nodiscard]] bool next_bool() noexcept { return (next_u64() >> 63U) != 0U; }
  [[nodiscard]] std::uint64_t seed() const noexcept { return seed_; }

 private:
  std::uint64_t state_;
  std::uint64_t seed_;
};

}  // namespace loop_guard
