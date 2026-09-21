// Loop Guard - authority vectors for containment.
//
// Loop Guard keeps six authority stages strictly separate and never lets one stand in
// for the next:
//
//   Observation      - a producer says a hop is open or closed. Evidence, not authority.
//   Eligibility      - policy says a resource may be a containment target.
//   Recommendation   - a planner suggests targets. No permission to act.
//   Authorization    - a grant permits a bounded, time-limited intent.
//   Acknowledgement  - an applier says it received the intent. It is not an effect.
//   VerifiedEffect   - an independent observation confirms the target is contained.
//
// A finding reaches ContainmentVerified only when every target carries a
// VerifiedEffect observation at the finding's own fence.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "loop_guard/containment.hpp"
#include "loop_guard/core.hpp"
#include "loop_guard/digest.hpp"
#include "loop_guard/enums.hpp"
#include "loop_guard/id.hpp"
#include "loop_guard/limits.hpp"
#include "loop_guard/result.hpp"

namespace loop_guard {

/// A bounded authorization to contain a specific resource set.
struct ContainmentGrant {
  ContainmentGrantId id;
  PolicyGeneration policy_generation;
  /// The fence in force when the grant was issued. The grant stops being active the
  /// moment any component of it moves.
  FenceVector fence;
  /// Resources the grant may authorize. Sorted, duplicate free. A target outside this
  /// scope is refused, not silently clamped.
  std::vector<ResourceId> scope;
  std::uint32_t max_targets = 1;
  std::uint64_t max_total_cost = 1;
  Tick issued_at = 0;
  Tick expires_at = 0;
  ProducerId issued_by;
  GrantState state = GrantState::Active;

  [[nodiscard]] Digest content_digest() const;
  [[nodiscard]] FenceCause fence_cause_if_not_current(const FenceVector& current) const noexcept;
  [[nodiscard]] bool is_active(const FenceVector& current, Tick now) const noexcept;
  /// Checks a requested target set against scope, cardinality and cost.
  [[nodiscard]] Status authorize(const std::vector<ResourceId>& targets, std::uint64_t total_cost,
                                 const FenceVector& current, Tick now) const;
};

/// An applier's acknowledgement that it received an intent. Not an effect.
struct ContainmentAcknowledgement {
  ContainmentIntentId intent;
  SessionId session;
  ProcessIdentity applier;
  ProducerSequence sequence;
  Tick acknowledged_at = 0;
  Digest intent_digest;

  friend bool operator==(const ContainmentAcknowledgement&,
                         const ContainmentAcknowledgement&) noexcept = default;
};

/// An independently observed proof that one target is contained.
struct VerifiedEffect {
  ResourceId target;
  /// The observation that proves containment. It must resolve at the finding's fence.
  ObservationId observation;
  FenceVector fence;
  Tick verified_at = 0;
  EvidenceOrigin origin = EvidenceOrigin::Synthetic;

  friend bool operator==(const VerifiedEffect&, const VerifiedEffect&) noexcept = default;
  friend bool operator<(const VerifiedEffect& lhs, const VerifiedEffect& rhs) noexcept {
    return lhs.target < rhs.target;
  }
};

/// The full record of what happened to one intent, kept bounded and canonical.
struct ContainmentApplication {
  ContainmentIntentId intent;
  ContainmentPlanId plan;
  FindingId finding;
  FenceVector fence;
  ProcessIdentity applier;
  /// The intent's target set, canonical order. A verified effect for a resource that is
  /// not in this set is ignored rather than credited.
  std::vector<ResourceId> targets;
  std::vector<ContainmentAcknowledgement> acknowledgements;
  std::vector<VerifiedEffect> effects;
  Explanation explanation;

  [[nodiscard]] bool has_acknowledgement() const noexcept { return !acknowledgements.empty(); }
  [[nodiscard]] std::vector<ResourceId> verified_targets() const;
  [[nodiscard]] std::vector<ResourceId> unverified_targets() const;
  /// True only when every target of the intent carries an independent verified effect.
  /// An acknowledgement alone never makes this true.
  [[nodiscard]] bool fully_verified() const;
  [[nodiscard]] Digest content_digest() const;
};

/// One line of the durable authority lineage: an append-only, ordered record of every
/// decision that changed what the runtime was permitted or known to have done.
struct LineageRecord {
  LineageRecordId id;
  AttemptSequence sequence;
  Tick recorded_at = 0;
  AuthorityKind kind = AuthorityKind::Observation;
  FindingId finding;
  ContainmentPlanId plan;
  ContainmentIntentId intent;
  FenceVector fence;
  Digest subject_digest;
  ReasonCode reason = ReasonCode::RequestAccepted;
  Severity severity = Severity::Info;

  friend bool operator==(const LineageRecord&, const LineageRecord&) noexcept = default;
  friend bool operator<(const LineageRecord& lhs, const LineageRecord& rhs) noexcept {
    return lhs.sequence < rhs.sequence;
  }
  [[nodiscard]] Digest content_digest() const;
  [[nodiscard]] std::string to_text() const;
};

}  // namespace loop_guard
