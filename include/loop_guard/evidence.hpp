// Loop Guard - forwarding evidence.
//
// An observation is an authoritative producer's statement about one forwarding hop,
// bound to the exact generations it was made against and carrying its own liveness
// window. Observations are dynamic: they are never restored across restart, and an
// observation whose generations no longer match is not evidence for the current
// question. Observation is not authority, and a stale observation is not an
// observation.
#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "loop_guard/core.hpp"
#include "loop_guard/digest.hpp"
#include "loop_guard/enums.hpp"
#include "loop_guard/id.hpp"
#include "loop_guard/limits.hpp"
#include "loop_guard/result.hpp"
#include "loop_guard/topology.hpp"

namespace loop_guard {

/// Liveness window of an observation. The window is expressed in logical ticks
/// supplied by the caller, never in wall-clock time, so every decision is replayable.
struct EvidenceLease {
  BootId boot;
  CoordinatorEpoch epoch;
  FabricEpoch fabric_epoch;
  Tick valid_from = 0;
  Tick valid_until = 0;

  friend bool operator==(const EvidenceLease&, const EvidenceLease&) noexcept = default;
  [[nodiscard]] bool is_live(Tick now) const noexcept {
    return now >= valid_from && now <= valid_until;
  }
  [[nodiscard]] std::string to_string() const;
};

/// A single authoritative statement about one hop.
struct ForwardingObservation {
  ObservationId id;
  ForwardingEdgeId edge;
  ResourceId from;
  ResourceId to;
  DomainId domain;
  EvidenceClass klass = EvidenceClass::Unknown;
  /// Canonically ordered, duplicate-free selector set.
  ///   Present: must be non-empty - the producer names what it saw traverse the hop.
  ///   Absent : may be empty - the hop carries no traffic for any selector.
  ///   Unknown: must be empty - an unknown statement cannot name a selector set.
  std::vector<TrafficSelectorId> selectors;
  TopologyGeneration topology_generation;
  ForwardingGeneration forwarding_generation;
  ProducerId producer;
  ProducerKind producer_kind = ProducerKind::SyntheticFixture;
  ProducerSequence sequence;
  EvidenceOrigin origin = EvidenceOrigin::Synthetic;
  EvidenceLease lease;
  /// The producer's own digest of the raw telemetry it summarised. Diagnostic; Loop
  /// Guard never treats it as proof and never recomputes it from producer data.
  Digest payload_digest;

  friend bool operator==(const ForwardingObservation&, const ForwardingObservation&) noexcept = default;
  /// Canonical order: (producer, sequence, id).
  friend bool operator<(const ForwardingObservation& lhs,
                        const ForwardingObservation& rhs) noexcept;
};

/// The resolved state of one hop after every observation for it has been classified
/// against the current fence.
struct HopResolutionRecord {
  std::size_t edge_index = 0;
  ForwardingEdgeId edge;
  ResourceId from;
  ResourceId to;
  DomainId domain;
  HopResolution resolution = HopResolution::Unproven;
  EvidenceBinding binding = EvidenceBinding::NoEvidence;
  /// Selectors for which this hop is usable. Sorted. Empty unless the resolution is
  /// ProvenOpen or UnprovenOpen.
  std::vector<TrafficSelectorId> effective_selectors;
  /// Observations that produced the resolution, in canonical order.
  std::vector<ObservationId> contributing;
  Explanation note;

  friend bool operator==(const HopResolutionRecord&, const HopResolutionRecord&) noexcept = default;
};

/// Canonical ordering key of an observation. Producers are ordered by identity, then
/// by their own monotonic sequence, then by observation identity, so the ledger's
/// iteration order is fully determined by the observations themselves.
struct ObservationKey {
  ProducerId producer;
  ProducerSequence sequence;
  ObservationId id;

  friend bool operator==(const ObservationKey&, const ObservationKey&) noexcept = default;
  friend bool operator<(const ObservationKey& lhs, const ObservationKey& rhs) noexcept {
    if (lhs.producer != rhs.producer) {
      return lhs.producer < rhs.producer;
    }
    if (lhs.sequence != rhs.sequence) {
      return lhs.sequence < rhs.sequence;
    }
    return lhs.id < rhs.id;
  }
};

/// Deterministic digest over a set of observations, in canonical order. Both the
/// detector and the independent witness validator compute it the same way, so a
/// witness carrying a different digest is rejected rather than trusted.
[[nodiscard]] Digest observations_digest(std::vector<const ForwardingObservation*> observations);

/// Bounded, deterministic evidence store.
class EvidenceLedger {
 public:
  struct Stats {
    std::uint64_t accepted = 0;
    std::uint64_t duplicate = 0;
    std::uint64_t regressed = 0;
    std::uint64_t rejected = 0;
    std::uint64_t evicted = 0;
  };

  explicit EvidenceLedger(const Limits& limits = default_limits());

  /// Validates and stores an observation.
  ///
  /// Rejections are explicit:
  ///   Invalid  - structural violation (unknown identifiers, non-canonical selector
  ///              sets, invalid lease, zero generations).
  ///   AlreadyExists - the same ObservationId is already stored.
  ///   Stale    - the producer's sequence regressed.
  ///   Exhausted - the ledger is at its global bound; the observation is refused
  ///               rather than silently dropped.
  Status submit(const ForwardingObservation& observation);

  [[nodiscard]] std::size_t size() const noexcept { return observations_.size(); }
  [[nodiscard]] bool empty() const noexcept { return observations_.empty(); }
  [[nodiscard]] const Stats& stats() const noexcept { return stats_; }
  [[nodiscard]] const Limits& limits() const noexcept { return limits_; }

  [[nodiscard]] const ForwardingObservation* find(ObservationId id) const noexcept;
  [[nodiscard]] std::size_t observation_count_for_edge(ForwardingEdgeId edge) const noexcept;

  /// Observations in canonical order. Never mutated by the caller.
  [[nodiscard]] const std::map<ObservationKey, ForwardingObservation>& observations() const noexcept {
    return observations_;
  }

  /// Resolves one hop against the current fence.
  [[nodiscard]] Result<HopResolutionRecord> resolve(const TopologyDefinition& topology,
                                                    std::size_t edge_index,
                                                    const FenceVector& current,
                                                    Tick now) const;

  /// Resolves every hop of the topology in canonical edge order.
  [[nodiscard]] Result<std::vector<HopResolutionRecord>> resolve_all(
      const TopologyDefinition& topology, const FenceVector& current, Tick now) const;

  /// Drops all dynamic evidence. Called on restart: no pre-restart observation is
  /// ever promoted to current authority.
  void clear_dynamic_state() noexcept;

  [[nodiscard]] Digest digest() const;
  /// Number of observations that would resolve to a non-exact binding at the given fence.
  [[nodiscard]] std::size_t non_exact_count(const FenceVector& current, Tick now) const noexcept;
  /// How the retained evidence was produced. REAL when any retained observation comes
  /// from a real producer, SYNTHETIC otherwise, UNSUPPORTED only when every observation
  /// is explicitly labelled unsupported. This label is carried onto every decision so a
  /// reader can never mistake a fixture-derived answer for a hardware-derived one.
  [[nodiscard]] EvidenceOrigin origin() const noexcept;

 private:
  struct ProducerKey {
    ProducerId producer;
    BootId boot;
    CoordinatorEpoch epoch;

    friend bool operator<(const ProducerKey& lhs, const ProducerKey& rhs) noexcept {
      if (lhs.producer != rhs.producer) {
        return lhs.producer < rhs.producer;
      }
      if (lhs.boot != rhs.boot) {
        return lhs.boot < rhs.boot;
      }
      return lhs.epoch < rhs.epoch;
    }
  };

  Limits limits_;
  /// Node-based so that the pointers held by the per-edge index stay valid across
  /// insertion, and so that canonical iteration needs no sorting.
  std::map<ObservationKey, ForwardingObservation> observations_;
  std::unordered_map<std::uint64_t, const ForwardingObservation*> by_id_;
  std::unordered_map<std::uint64_t, std::vector<const ForwardingObservation*>> by_edge_;
  std::map<ProducerKey, std::uint64_t> producer_high_sequence_;
  Stats stats_;
};

/// Deterministically resolves a single hop from an already-filtered observation set.
/// Exposed so the witness validator can re-derive a hop without going through the
/// detector's code path.
[[nodiscard]] Result<HopResolutionRecord> resolve_hop_from_observations(
    const TopologyDefinition& topology, std::size_t edge_index,
    const std::vector<const ForwardingObservation*>& candidates, const FenceVector& current,
    Tick now, const Limits& limits);

}  // namespace loop_guard
