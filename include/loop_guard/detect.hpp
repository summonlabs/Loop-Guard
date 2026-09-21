// Loop Guard - forwarding-loop detection.
//
// The detector answers one question exactly: given a topology definition, a set of
// generation-bound forwarding observations and a fence vector, does traffic provably
// revisit a governed resource right now?
//
// The supported problem class is stated precisely in README.md. In short:
//   * the cycle must exist in the graph of hops whose forwarding state is PROVEN OPEN
//     by exactly-bound evidence at the current fence - a topology adjacency alone is
//     never enough;
//   * every hop must admit at least one common traffic selector;
//   * NO_LOOP is emitted only when cycle absence is proved exactly for every candidate
//     selector, never merely because a bounded search stopped;
//   * UNKNOWN, CONFLICT, STALE, INVALID and INDETERMINATE are returned as themselves.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "loop_guard/core.hpp"
#include "loop_guard/digest.hpp"
#include "loop_guard/enums.hpp"
#include "loop_guard/evidence.hpp"
#include "loop_guard/id.hpp"
#include "loop_guard/limits.hpp"
#include "loop_guard/result.hpp"
#include "loop_guard/topology.hpp"
#include "loop_guard/witness.hpp"

namespace loop_guard {

/// Work actually performed while answering one question. Counters make bounded
/// behaviour observable instead of implicit.
struct SearchCounters {
  std::uint64_t scc_runs = 0;
  std::uint64_t nodes_examined = 0;
  std::uint64_t edges_examined = 0;
  std::uint64_t steps_used = 0;
  std::uint64_t cycles_enumerated = 0;
  std::uint64_t selectors_considered = 0;
  std::uint64_t witnesses_retained = 0;
  std::uint64_t witnesses_dropped = 0;
  /// Witnesses re-derived by the independent validator, and witnesses the validator
  /// refused. A refusal is an internal invariant violation, never a silent drop.
  std::uint64_t witnesses_validated = 0;
  std::uint64_t witnesses_rejected = 0;
  bool length_bound_reached = false;
  bool steps_exhausted = false;
  bool cycles_exhausted = false;
  bool selectors_exhausted = false;
  bool witnesses_truncated = false;

  [[nodiscard]] bool any_exhausted() const noexcept {
    return steps_exhausted || cycles_exhausted || selectors_exhausted || witnesses_truncated;
  }
};

struct DetectionRequest {
  const TopologyDefinition* topology = nullptr;
  const EvidenceLedger* ledger = nullptr;
  FenceVector fence;
  Tick now = 0;
  /// Optional restriction. Empty means "every selector declared by the definition".
  std::vector<TrafficSelectorId> selector_scope;
};

/// The complete, self-describing answer to one detection question.
struct LoopAssessment {
  AssessmentId id;
  FenceVector fence;
  LoopOutcome outcome = LoopOutcome::Invalid;
  AssessmentFlags flags = kAssessmentNone;
  /// Confirmed witnesses, in canonical order. Empty unless the outcome is
  /// LoopConfirmed; when the outcome is Unknown or Indeterminate this stays empty
  /// precisely because nothing was proved.
  std::vector<LoopWitness> witnesses;
  /// Per-hop resolution used for the decision, in canonical edge order.
  std::vector<HopResolutionRecord> hops;
  SearchCounters counters;
  Explanation explanation;
  EvidenceOrigin origin = EvidenceOrigin::Synthetic;

  [[nodiscard]] bool is_affirmative() const noexcept {
    return outcome == LoopOutcome::LoopConfirmed;
  }
  [[nodiscard]] bool is_conclusive() const noexcept {
    return outcome == LoopOutcome::LoopConfirmed || outcome == LoopOutcome::NoLoop;
  }
  [[nodiscard]] Digest digest() const;
  [[nodiscard]] Digest witness_set_digest() const;
  [[nodiscard]] std::vector<ResourceId> implicated_resources() const;
  [[nodiscard]] std::vector<TrafficSelectorId> implicated_selectors() const;
  [[nodiscard]] std::string to_text() const;
};

class LoopDetector {
 public:
  explicit LoopDetector(const Limits& limits = default_limits()) : limits_(limits) {}

  [[nodiscard]] const Limits& limits() const noexcept { return limits_; }

  /// Answers the detection question. The returned Result reports whether the *request*
  /// was answerable at all; the LoopOutcome inside reports the answer. In particular a
  /// request whose evidence is entirely stale yields Ok(assessment with outcome
  /// Unknown) rather than a failure.
  [[nodiscard]] Result<LoopAssessment> assess(const DetectionRequest& request) const;

  /// Re-checks a previously produced witness against the current fence.
  [[nodiscard]] Result<WitnessValidation> revalidate(const LoopWitness& witness,
                                                     const TopologyDefinition& topology,
                                                     const EvidenceLedger& ledger,
                                                     const FenceVector& current, Tick now) const;

 private:
  Limits limits_;
};

/// Deterministic digest over a hop-resolution table. Used to compare two assessments
/// for evidence equality without comparing explanations.
[[nodiscard]] Digest hop_table_digest(const std::vector<HopResolutionRecord>& hops);

}  // namespace loop_guard
