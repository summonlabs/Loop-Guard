// Loop Guard - canonical loop witnesses.
//
// A witness is the proof object that answers "does traffic actually revisit a governed
// resource". It is an ordered cycle of resources, with every hop backed by exactly
// generation-bound forwarding evidence, plus the traffic selectors for which that
// cycle is traversable.
//
// Canonical form: the cycle is rotated so that the smallest ResourceId comes first,
// hops follow the cycle order, and selectors are sorted. Two witnesses built from the
// same governed facts are byte-identical regardless of insertion, discovery or
// container order.
#pragma once

#include <cstddef>
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

namespace loop_guard {

/// A proved forwarding loop.
struct LoopWitness {
  WitnessId id;
  /// Distinct resources of the cycle, in canonical rotation. Hop i traverses
  /// cycle[i] -> cycle[(i + 1) % cycle.size()].
  std::vector<ResourceId> cycle;
  /// Edge identifiers parallel to \ref cycle.
  std::vector<ForwardingEdgeId> hops;
  /// Selectors for which every hop of the cycle is open. Sorted, non-empty.
  std::vector<TrafficSelectorId> selectors;
  FenceVector fence;
  EvidenceOrigin origin = EvidenceOrigin::Synthetic;
  bool crosses_domains = false;
  /// Digest over the contributing observations, in canonical order.
  Digest evidence_digest;
  /// Bounded rationale produced by the detector.
  Explanation note;

  [[nodiscard]] std::size_t hop_count() const noexcept { return cycle.size(); }
  [[nodiscard]] Digest content_digest() const;
  [[nodiscard]] std::string to_text() const;

  /// Total order over witnesses: shorter cycles first, then lexicographic resource
  /// order, then selector order, then fence.
  friend bool operator<(const LoopWitness& lhs, const LoopWitness& rhs) noexcept;
  friend bool operator==(const LoopWitness& lhs, const LoopWitness& rhs) noexcept;
};

/// Rotates \p cycle so that the smallest resource id is first, preserving cyclic
/// order. Returns the input unchanged when it is empty. Rejects nothing: a cycle with
/// duplicates is a caller bug that the validator catches.
[[nodiscard]] std::vector<ResourceId> canonicalize_cycle(std::vector<ResourceId> cycle);

/// Rotates a cycle carried together with its parallel hop sequence. The hop sequence
/// is rotated with the resources so hop i still traverses cycle[i] -> cycle[i+1].
void canonicalize_cycle_with_hops(std::vector<ResourceId>& cycle, std::vector<ForwardingEdgeId>& hops);

/// Outcome of independently re-deriving a witness from raw inputs.
struct WitnessValidation {
  bool valid = false;
  LoopOutcome outcome = LoopOutcome::Invalid;
  std::vector<ReasonCode> reasons;
  Explanation explanation;

  [[nodiscard]] bool is_affirmative() const noexcept {
    return valid && outcome == LoopOutcome::LoopConfirmed;
  }
};

/// Independent witness validator.
///
/// This is deliberately a separate implementation from the detector: it consumes only
/// the topology definition, the evidence ledger, the current fence and the tick, and
/// re-derives every hop rather than trusting anything the witness carries beyond its
/// resource and selector sets. A detector bug that fabricates a cycle is therefore
/// caught here rather than being laundered into authority.
class WitnessValidator {
 public:
  [[nodiscard]] static Result<WitnessValidation> validate(const LoopWitness& witness,
                                                          const TopologyDefinition& topology,
                                                          const EvidenceLedger& ledger,
                                                          const FenceVector& current, Tick now,
                                                          const Limits& limits = default_limits());
};

}  // namespace loop_guard
