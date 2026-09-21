// Loop Guard - strongly typed identities and generations.
//
// Every identity in this runtime is a distinct C++ type. There is no implicit
// conversion between identities, and no identity is interchangeable with a plain
// integer. The zero value is never a valid identity or generation; it is the
// "absent" sentinel.
//
// Generations are never inferred from matching identifiers. Two records that
// carry the same ResourceId are not the same generation of that resource unless
// their generation fields also compare equal. This is enforced at the API level:
// every binding decision takes a generation, never a bare identity.
#pragma once

#include <compare>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace loop_guard {

enum class IdClass : std::uint8_t {
  Identifier = 0,  ///< Valid values are >= 1.
  Generation = 1,  ///< Valid values are >= 1; monotonic and non-wrapping.
};

/// Strongly typed 64-bit identity. Tag selects a distinct type, Kind selects validity rules.
template <class Tag, IdClass Kind = IdClass::Identifier>
class StrongId {
 public:
  using value_type = std::uint64_t;
  static constexpr IdClass id_class = Kind;

  constexpr StrongId() noexcept = default;
  explicit constexpr StrongId(std::uint64_t raw) noexcept : raw_(raw) {}

  [[nodiscard]] static constexpr StrongId from_value(std::uint64_t raw) noexcept {
    return StrongId(raw);
  }

  [[nodiscard]] constexpr std::uint64_t value() const noexcept { return raw_; }
  [[nodiscard]] constexpr bool valid() const noexcept { return raw_ != 0; }
  [[nodiscard]] constexpr explicit operator bool() const noexcept { return raw_ != 0; }

  /// Checked successor. Returns nullopt instead of wrapping at the 64-bit boundary so
  /// that "generations never wrap" is enforced by construction rather than convention.
  [[nodiscard]] constexpr std::optional<StrongId> try_next() const noexcept {
    if (raw_ == kMax) {
      return std::nullopt;
    }
    return StrongId(raw_ + 1);
  }

  [[nodiscard]] std::string to_string() const { return std::to_string(raw_); }

  /// Parses a canonical base-10 representation. Rejects empty input, sign characters,
  /// surrounding whitespace, non-digits, overflow and the invalid zero value.
  [[nodiscard]] static std::optional<StrongId> parse(std::string_view text) noexcept {
    if (text.empty() || text.size() > 20) {
      return std::nullopt;
    }
    std::uint64_t value = 0;
    for (const char ch : text) {
      if (ch < '0' || ch > '9') {
        return std::nullopt;
      }
      const std::uint64_t digit = static_cast<std::uint64_t>(ch - '0');
      if (value > (kMax - digit) / 10U) {
        return std::nullopt;
      }
      value = value * 10U + digit;
    }
    if (value == 0) {
      return std::nullopt;
    }
    return StrongId(value);
  }

  friend constexpr bool operator==(StrongId, StrongId) noexcept = default;
  friend constexpr std::strong_ordering operator<=>(StrongId, StrongId) noexcept = default;

 private:
  static constexpr std::uint64_t kMax = 0xFFFF'FFFF'FFFF'FFFFULL;
  std::uint64_t raw_ = 0;
};

#define LG_DECLARE_ID(name, kind)   \
  struct name##Tag;                 \
  using name = StrongId<name##Tag, kind>

// ---------------------------------------------------------------------------
// Identities owned by Loop Guard.
// ---------------------------------------------------------------------------
LG_DECLARE_ID(ResourceId, IdClass::Identifier);
LG_DECLARE_ID(DomainId, IdClass::Identifier);
LG_DECLARE_ID(ForwardingEdgeId, IdClass::Identifier);
LG_DECLARE_ID(TrafficSelectorId, IdClass::Identifier);
LG_DECLARE_ID(ObservationId, IdClass::Identifier);
LG_DECLARE_ID(WitnessId, IdClass::Identifier);
LG_DECLARE_ID(AssessmentId, IdClass::Identifier);
LG_DECLARE_ID(FindingId, IdClass::Identifier);
LG_DECLARE_ID(ContainmentPlanId, IdClass::Identifier);
LG_DECLARE_ID(ContainmentIntentId, IdClass::Identifier);
LG_DECLARE_ID(ContainmentGrantId, IdClass::Identifier);
LG_DECLARE_ID(LineageRecordId, IdClass::Identifier);
LG_DECLARE_ID(SessionId, IdClass::Identifier);
LG_DECLARE_ID(BootRecordId, IdClass::Identifier);

// ---------------------------------------------------------------------------
// Generations owned by Loop Guard.
// ---------------------------------------------------------------------------
LG_DECLARE_ID(TopologyGeneration, IdClass::Generation);
LG_DECLARE_ID(ForwardingGeneration, IdClass::Generation);
LG_DECLARE_ID(PolicyGeneration, IdClass::Generation);
LG_DECLARE_ID(EvidenceGeneration, IdClass::Generation);
LG_DECLARE_ID(WitnessGeneration, IdClass::Generation);
LG_DECLARE_ID(FindingGeneration, IdClass::Generation);
LG_DECLARE_ID(CoordinatorEpoch, IdClass::Generation);
LG_DECLARE_ID(BootId, IdClass::Generation);
LG_DECLARE_ID(IncarnationId, IdClass::Generation);
LG_DECLARE_ID(AttemptSequence, IdClass::Generation);
LG_DECLARE_ID(ProducerSequence, IdClass::Generation);
LG_DECLARE_ID(FabricEpoch, IdClass::Generation);

// ---------------------------------------------------------------------------
// Identities and generations owned by neighbouring authorities. Loop Guard only
// ever binds these; it never mints them and never validates them on the owner's
// behalf. A Loop Guard decision that binds a neighbouring generation is stale the
// moment the owner advances it.
// ---------------------------------------------------------------------------
LG_DECLARE_ID(ProducerId, IdClass::Identifier);
LG_DECLARE_ID(LinkStateGeneration, IdClass::Generation);
LG_DECLARE_ID(PortGeneration, IdClass::Generation);
LG_DECLARE_ID(PathGeneration, IdClass::Generation);
LG_DECLARE_ID(RouteGeneration, IdClass::Generation);
LG_DECLARE_ID(PlannerGeneration, IdClass::Generation);

#undef LG_DECLARE_ID

/// Logical monotonic tick used for lease and expiry arithmetic. Loop Guard never
/// reads a wall clock in the library: time is supplied by the caller so that every
/// decision is reproducible from its recorded inputs.
using Tick = std::uint64_t;

}  // namespace loop_guard
