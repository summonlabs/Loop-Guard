// Loop Guard - findings and their lifecycle.
//
// A finding is the runtime's externally visible statement that a forwarding loop
// exists, which resources and traffic it implicates, and what containment is
// authorized. It binds the assessment, the fence and the evidence it was derived from.
//
// A finding is never silently upgraded, never silently withdrawn and never allowed to
// outlive the generations that made it legal. When any authority-bearing dependency
// moves, the finding is fenced with an explicit cause and becomes Stale or Fenced.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "loop_guard/authority.hpp"
#include "loop_guard/containment.hpp"
#include "loop_guard/core.hpp"
#include "loop_guard/detect.hpp"
#include "loop_guard/digest.hpp"
#include "loop_guard/enums.hpp"
#include "loop_guard/id.hpp"
#include "loop_guard/limits.hpp"
#include "loop_guard/result.hpp"

namespace loop_guard {

struct Finding {
  FindingId id;
  FindingGeneration generation;
  AssessmentId assessment;
  Digest assessment_digest;
  FenceVector fence;
  FindingState state = FindingState::Proposed;
  /// The component that fenced this finding, when it was fenced.
  FenceCause fence_cause = FenceCause::None;
  LoopOutcome assessment_outcome = LoopOutcome::Invalid;
  AssessmentFlags assessment_flags = kAssessmentNone;
  /// Confirmed witnesses, canonical order.
  std::vector<WitnessId> witnesses;
  std::vector<ResourceId> implicated_resources;
  std::vector<TrafficSelectorId> implicated_selectors;
  ContainmentPlanId plan;
  ContainmentIntentId intent;
  Tick created_at = 0;
  Tick updated_at = 0;
  EvidenceOrigin origin = EvidenceOrigin::Synthetic;
  Explanation explanation;

  [[nodiscard]] bool is_terminal() const noexcept;
  [[nodiscard]] bool is_current(const FenceVector& current) const noexcept {
    return fence == current && state != FindingState::Fenced && state != FindingState::Stale;
  }
  [[nodiscard]] bool permits_action() const noexcept {
    return state == FindingState::ContainmentAuthorized || state == FindingState::ContainmentRequested;
  }
  [[nodiscard]] Digest content_digest() const;
  [[nodiscard]] std::string to_text() const;
};

/// Bounded registry of findings.
///
/// Retention policy is explicit: while the registry holds fewer than the configured
/// maximum, findings accumulate. At capacity, the oldest *terminal* finding
/// (Withdrawn, Stale, Fenced or Rejected) is evicted. If every retained finding is
/// still live, registration is refused with Outcome::Exhausted rather than evicting a
/// live finding or growing without bound.
class FindingRegistry {
 public:
  explicit FindingRegistry(const Limits& limits = default_limits());

  [[nodiscard]] Result<FindingId> register_finding(Finding finding);
  [[nodiscard]] Status update_state(FindingId id, FindingState state, FenceCause cause, Tick now,
                                    ReasonCode reason, std::string detail = {});
  [[nodiscard]] Status attach_plan(FindingId id, ContainmentPlanId plan, Tick now);
  [[nodiscard]] Status attach_intent(FindingId id, ContainmentIntentId intent, Tick now);

  [[nodiscard]] const Finding* find(FindingId id) const noexcept;
  [[nodiscard]] const std::vector<Finding>& findings() const noexcept { return findings_; }
  [[nodiscard]] std::size_t count(FindingState state) const noexcept;
  [[nodiscard]] std::size_t live_count() const noexcept;

  /// Fences every non-terminal finding whose fence no longer equals \p current.
  /// Returns the identifiers that changed, in canonical order.
  [[nodiscard]] std::vector<FindingId> fence_stale(const FenceVector& current, Tick now);
  /// Fences every non-terminal finding because the process restarted.
  [[nodiscard]] std::vector<FindingId> fence_restart(const FenceVector& current, Tick now);
  /// Fences every finding bound to an older boot or epoch, regardless of state.
  [[nodiscard]] std::vector<FindingId> fence_boot(const FenceVector& current, Tick now);

  void clear() noexcept;
  [[nodiscard]] Digest digest() const;

 private:
  Limits limits_;
  std::vector<Finding> findings_;  ///< Canonical order by FindingId.
};

/// Compact, human-auditable projection of a finding used by the tools and the wire
/// protocol. It is derived from the finding and never carries extra authority.
struct FindingSummary {
  FindingId id;
  FindingGeneration generation;
  FindingState state;
  FenceCause fence_cause;
  LoopOutcome assessment_outcome;
  AssessmentFlags assessment_flags;
  std::size_t witness_count = 0;
  std::size_t implicated_resource_count = 0;
  ContainmentOutcome containment_outcome = ContainmentOutcome::NotRequired;
  std::size_t target_count = 0;
  Digest content_digest;

  friend bool operator==(const FindingSummary&, const FindingSummary&) noexcept = default;
};

[[nodiscard]] FindingSummary summarize(const Finding& finding);
[[nodiscard]] std::string to_string(const FindingSummary& summary);

}  // namespace loop_guard
