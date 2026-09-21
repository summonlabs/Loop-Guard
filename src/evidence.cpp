#include "loop_guard/evidence.hpp"

#include <algorithm>
#include <iterator>
#include <map>
#include <set>
#include <tuple>

namespace loop_guard {
namespace {

/// Reporting priority for a non-exact binding. Smaller is reported first. The order is
/// fixed so that the same observation set always yields the same narrative.
int binding_priority(EvidenceBinding binding) noexcept {
  switch (binding) {
    case EvidenceBinding::Exact:
      return 0;
    case EvidenceBinding::EpochFenced:
      return 1;
    case EvidenceBinding::GenerationMismatch:
      return 2;
    case EvidenceBinding::LeaseExpired:
      return 3;
    case EvidenceBinding::Superseded:
      return 4;
    case EvidenceBinding::NoEvidence:
      return 5;
  }
  return 6;
}

void hash_u64(Sha256& hasher, std::uint64_t value) {
  hasher.update(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(&value),
                                              sizeof(value)));
}

/// Hashes one observation in a canonical field order. Any producer-visible field that
/// participates in a decision is covered, so two observation sets that differ in any
/// decision-relevant way produce different digests.
void hash_observation(Sha256& hasher, const ForwardingObservation& observation) {
  hash_u64(hasher, observation.id.value());
  hash_u64(hasher, observation.edge.value());
  hash_u64(hasher, observation.from.value());
  hash_u64(hasher, observation.to.value());
  hash_u64(hasher, observation.domain.value());
  hasher.update(static_cast<std::uint8_t>(observation.klass));
  hasher.update(static_cast<std::uint8_t>(observation.producer_kind));
  hasher.update(static_cast<std::uint8_t>(observation.origin));
  hash_u64(hasher, observation.producer.value());
  hash_u64(hasher, observation.sequence.value());
  hash_u64(hasher, observation.topology_generation.value());
  hash_u64(hasher, observation.forwarding_generation.value());
  hash_u64(hasher, observation.lease.boot.value());
  hash_u64(hasher, observation.lease.epoch.value());
  hash_u64(hasher, observation.lease.fabric_epoch.value());
  hash_u64(hasher, observation.lease.valid_from);
  hash_u64(hasher, observation.lease.valid_until);
  hasher.update(observation.payload_digest.bytes.data(), kDigestBytes);
  for (const TrafficSelectorId selector : observation.selectors) {
    hash_u64(hasher, selector.value());
  }
  hasher.update(static_cast<std::uint8_t>(0xFE));
}

}  // namespace

std::string EvidenceLease::to_string() const {
  return "boot" + boot.to_string() + "/epoch" + epoch.to_string() + "/fab" + fabric_epoch.to_string() +
         "/[" + std::to_string(valid_from) + "," + std::to_string(valid_until) + "]";
}

bool operator<(const ForwardingObservation& lhs, const ForwardingObservation& rhs) noexcept {
  if (lhs.producer != rhs.producer) {
    return lhs.producer < rhs.producer;
  }
  if (lhs.sequence != rhs.sequence) {
    return lhs.sequence < rhs.sequence;
  }
  return lhs.id < rhs.id;
}

Digest observations_digest(std::vector<const ForwardingObservation*> observations) {
  std::sort(observations.begin(), observations.end(),
            [](const ForwardingObservation* lhs, const ForwardingObservation* rhs) {
              return *lhs < *rhs;
            });
  Sha256 hasher;
  for (const ForwardingObservation* observation : observations) {
    hash_observation(hasher, *observation);
  }
  return hasher.finish();
}

// ---------------------------------------------------------------------------
// Hop resolution.
// ---------------------------------------------------------------------------
Result<HopResolutionRecord> resolve_hop_from_observations(
    const TopologyDefinition& topology, std::size_t edge_index,
    const std::vector<const ForwardingObservation*>& candidates, const FenceVector& current, Tick now,
    const Limits& limits) {
  if (edge_index >= topology.edges().size()) {
    return Result<HopResolutionRecord>::failure(Outcome::Invalid, "edge index out of range");
  }
  const ForwardingEdge& edge = topology.edges()[edge_index];

  HopResolutionRecord record;
  record.edge_index = edge_index;
  record.edge = edge.id;
  record.from = edge.from;
  record.to = edge.to;
  record.domain = edge.domain;
  record.note = Explanation(limits.max_explanation_reasons);

  const ResourceRecord* from = topology.find_resource(edge.from);
  const ResourceRecord* to = topology.find_resource(edge.to);
  if (from == nullptr || to == nullptr) {
    record.resolution = HopResolution::Unsupported;
    record.binding = EvidenceBinding::NoEvidence;
    record.note.add(ReasonCode::WitnessResourceUnknown, edge.id.to_string(),
                    "edge endpoint is not a governed resource");
    return Result<HopResolutionRecord>::ok(std::move(record));
  }
  if (!(from->domain == edge.domain) || !(to->domain == edge.domain)) {
    record.resolution = HopResolution::Unsupported;
    record.binding = EvidenceBinding::NoEvidence;
    record.note.add(ReasonCode::WitnessResourceUnknown, edge.id.to_string(),
                    "edge and endpoints disagree about the governed domain");
    return Result<HopResolutionRecord>::ok(std::move(record));
  }

  for (const ForwardingObservation* observation : candidates) {
    record.contributing.push_back(observation->id);
  }
  std::sort(record.contributing.begin(), record.contributing.end());

  // A definition can close a hop without any observation: an administratively disabled
  // endpoint or a down link is an authoritative statement that traffic cannot traverse
  // it. An unknown state is not: it cannot prove openness, so the hop stays unproven.
  if (from->admin == AdministrativeState::Disabled || to->admin == AdministrativeState::Disabled ||
      edge.link == LinkState::Down) {
    record.resolution = HopResolution::ProvenClosed;
    record.binding = EvidenceBinding::NoEvidence;
    record.note.add(ReasonCode::CycleBrokenByAbsentEvidence, edge.id.to_string(),
                    "definition closes the hop: admin disabled or link down");
    return Result<HopResolutionRecord>::ok(std::move(record));
  }
  const bool definition_unknown = from->admin == AdministrativeState::Unknown ||
                                  to->admin == AdministrativeState::Unknown ||
                                  edge.link == LinkState::Unknown;

  // Resolve supersession per (producer, boot, epoch): only a producer's own newest
  // statement about this hop counts as its current statement.
  std::map<std::tuple<std::uint64_t, std::uint64_t, std::uint64_t>, std::uint64_t> newest;
  for (const ForwardingObservation* observation : candidates) {
    const auto key = std::make_tuple(observation->producer.value(), observation->lease.boot.value(),
                                     observation->lease.epoch.value());
    const auto position = newest.find(key);
    const std::uint64_t sequence = observation->sequence.value();
    if (position == newest.end() || position->second < sequence) {
      newest[key] = sequence;
    }
  }

  bool have_exact_present = false;
  bool have_exact_absent = false;
  bool have_unproven_present = false;
  bool have_any_exact = false;
  EvidenceBinding best_non_exact = EvidenceBinding::NoEvidence;
  std::vector<TrafficSelectorId> exact_present_selectors;
  std::vector<TrafficSelectorId> unproven_present_selectors;

  for (const ForwardingObservation* observation : candidates) {
    const auto key = std::make_tuple(observation->producer.value(), observation->lease.boot.value(),
                                     observation->lease.epoch.value());
    EvidenceBinding binding = EvidenceBinding::Exact;
    if (!(observation->lease.boot == current.boot) || !(observation->lease.epoch == current.epoch) ||
        !(observation->lease.fabric_epoch == current.fabric_epoch)) {
      binding = EvidenceBinding::EpochFenced;
    } else if (!(observation->topology_generation == current.topology) ||
               !(observation->forwarding_generation == current.forwarding)) {
      binding = EvidenceBinding::GenerationMismatch;
    } else if (!observation->lease.is_live(now)) {
      binding = EvidenceBinding::LeaseExpired;
    } else if (const auto position = newest.find(key);
               position != newest.end() && position->second > observation->sequence.value()) {
      binding = EvidenceBinding::Superseded;
    }

    if (binding == EvidenceBinding::Exact) {
      have_any_exact = true;
      if (observation->klass == EvidenceClass::Present) {
        have_exact_present = true;
        exact_present_selectors.insert(exact_present_selectors.end(), observation->selectors.begin(),
                                       observation->selectors.end());
      } else if (observation->klass == EvidenceClass::Absent) {
        have_exact_absent = true;
      }
    } else {
      if (binding_priority(binding) < binding_priority(best_non_exact)) {
        best_non_exact = binding;
      }
      // A superseded observation has been withdrawn by its own producer. It is neither
      // evidence of openness nor evidence of closure, and it must not create a
      // "possibly open" hop, because that would resurrect a statement its author retracted.
      if (binding != EvidenceBinding::Superseded && observation->klass == EvidenceClass::Present) {
        have_unproven_present = true;
        unproven_present_selectors.insert(unproven_present_selectors.end(),
                                          observation->selectors.begin(),
                                          observation->selectors.end());
      }
    }
  }

  auto canonical_intersection = [&edge](std::vector<TrafficSelectorId> selectors) {
    std::sort(selectors.begin(), selectors.end());
    selectors.erase(std::unique(selectors.begin(), selectors.end()), selectors.end());
    std::vector<TrafficSelectorId> result;
    std::set_intersection(selectors.begin(), selectors.end(), edge.admitted_selectors.begin(),
                          edge.admitted_selectors.end(), std::back_inserter(result));
    return result;
  };

  if (have_exact_present && have_exact_absent) {
    record.resolution = HopResolution::Conflicted;
    record.binding = EvidenceBinding::Exact;
    record.note.add(ReasonCode::HopConflictsWithItself, edge.id.to_string(),
                    "exactly bound authoritative evidence asserts both directions");
    return Result<HopResolutionRecord>::ok(std::move(record));
  }
  if (have_exact_present) {
    record.effective_selectors = canonical_intersection(std::move(exact_present_selectors));
    if (record.effective_selectors.empty()) {
      record.resolution = HopResolution::Unproven;
      record.binding = EvidenceBinding::Exact;
      record.note.add(ReasonCode::WitnessSelectorNotAdmitted, edge.id.to_string(),
                      "evidence names selectors the edge does not admit");
      return Result<HopResolutionRecord>::ok(std::move(record));
    }
    record.resolution = HopResolution::ProvenOpen;
    record.binding = EvidenceBinding::Exact;
    record.note.add(ReasonCode::WitnessSuccessfullyValidated, edge.id.to_string(),
                    "exactly bound evidence proves the hop open");
    return Result<HopResolutionRecord>::ok(std::move(record));
  }
  if (have_exact_absent) {
    record.resolution = HopResolution::ProvenClosed;
    record.binding = EvidenceBinding::Exact;
    record.note.add(ReasonCode::CycleBrokenByAbsentEvidence, edge.id.to_string(),
                    "exactly bound evidence proves the hop closed");
    return Result<HopResolutionRecord>::ok(std::move(record));
  }
  if (have_unproven_present) {
    record.effective_selectors = canonical_intersection(std::move(unproven_present_selectors));
    record.binding = best_non_exact;
    if (!record.effective_selectors.empty()) {
      record.resolution = HopResolution::UnprovenOpen;
      record.note.add(ReasonCode::CycleRequiresUnprovenHop, edge.id.to_string(),
                      std::string("hop was open under an earlier binding: ") +
                          std::string(to_string(best_non_exact)));
      return Result<HopResolutionRecord>::ok(std::move(record));
    }
  }

  record.resolution = HopResolution::Unproven;
  record.binding = candidates.empty() ? EvidenceBinding::NoEvidence : best_non_exact;
  if (candidates.empty()) {
    record.note.add(ReasonCode::NoObservationForHop, edge.id.to_string(),
                    "no observation was ever submitted for this hop");
  }
  if (definition_unknown && candidates.empty()) {
    record.note.add(ReasonCode::WitnessResourceUnknown, edge.id.to_string(),
                    "definition itself is in an unknown administrative or link state");
  }
  return Result<HopResolutionRecord>::ok(std::move(record));
}

// ---------------------------------------------------------------------------
// EvidenceLedger.
// ---------------------------------------------------------------------------
EvidenceLedger::EvidenceLedger(const Limits& limits) : limits_(limits) {}

Status EvidenceLedger::submit(const ForwardingObservation& observation) {
  if (!observation.id.valid() || !observation.edge.valid() || !observation.from.valid() ||
      !observation.to.valid() || !observation.domain.valid() || !observation.producer.valid() ||
      !observation.sequence.valid()) {
    ++stats_.rejected;
    return Status::failure(Outcome::Invalid, "observation identity, endpoints or sequence is invalid");
  }
  if (!observation.topology_generation.valid() || !observation.forwarding_generation.valid()) {
    ++stats_.rejected;
    return Status::failure(Outcome::Invalid, "observation must bind a valid generation pair");
  }
  if (!observation.lease.boot.valid() || !observation.lease.epoch.valid() ||
      !observation.lease.fabric_epoch.valid()) {
    ++stats_.rejected;
    return Status::failure(Outcome::Invalid, "observation lease must bind boot, epoch and fabric epoch");
  }
  if (observation.lease.valid_until < observation.lease.valid_from) {
    ++stats_.rejected;
    return Status::failure(Outcome::Invalid, "observation lease window is inverted");
  }
  if (observation.selectors.size() > limits_.max_selectors) {
    ++stats_.rejected;
    return Status::failure(Outcome::Exhausted, "observation carries more selectors than the limit");
  }
  for (std::size_t index = 1; index < observation.selectors.size(); ++index) {
    if (!(observation.selectors[index - 1] < observation.selectors[index])) {
      ++stats_.rejected;
      return Status::failure(Outcome::Invalid,
                             "observation selectors must be strictly increasing and duplicate free");
    }
  }
  if (observation.klass == EvidenceClass::Present && observation.selectors.empty()) {
    ++stats_.rejected;
    return Status::failure(Outcome::Invalid, "a Present observation must name at least one selector");
  }
  if (observation.klass == EvidenceClass::Unknown && !observation.selectors.empty()) {
    ++stats_.rejected;
    return Status::failure(Outcome::Invalid, "an Unknown observation cannot name selectors");
  }

  if (by_id_.find(observation.id.value()) != by_id_.end()) {
    ++stats_.duplicate;
    return Status::failure(Outcome::AlreadyExists, "observation identity is already present");
  }

  const ProducerKey producer_key{observation.producer, observation.lease.boot, observation.lease.epoch};
  const auto high = producer_high_sequence_.find(producer_key);
  if (high != producer_high_sequence_.end() && high->second >= observation.sequence.value()) {
    ++stats_.regressed;
    return Status::failure(Outcome::Stale, "producer sequence regressed for this boot and epoch");
  }

  if (observations_.size() >= limits_.max_observations) {
    ++stats_.rejected;
    return Status::failure(Outcome::Exhausted, "evidence ledger is at its global bound");
  }

  // Bounded per-edge retention: the oldest statement of the lowest producer identity is
  // evicted deterministically before the new one is inserted, and the eviction is counted.
  auto& edge_bucket = by_edge_[observation.edge.value()];
  while (edge_bucket.size() >= limits_.max_observations_per_edge) {
    std::size_t victim = 0;
    for (std::size_t index = 1; index < edge_bucket.size(); ++index) {
      if (*edge_bucket[index] < *edge_bucket[victim]) {
        victim = index;
      }
    }
    const ForwardingObservation* doomed = edge_bucket[victim];
    by_id_.erase(doomed->id.value());
    observations_.erase(ObservationKey{doomed->producer, doomed->sequence, doomed->id});
    edge_bucket.erase(edge_bucket.begin() + static_cast<std::ptrdiff_t>(victim));
    ++stats_.evicted;
  }

  const ObservationKey key{observation.producer, observation.sequence, observation.id};
  const auto inserted = observations_.emplace(key, observation);
  const ForwardingObservation* stored = &inserted.first->second;
  by_id_[observation.id.value()] = stored;
  edge_bucket.push_back(stored);
  std::sort(edge_bucket.begin(), edge_bucket.end(),
            [](const ForwardingObservation* lhs, const ForwardingObservation* rhs) {
              return *lhs < *rhs;
            });
  producer_high_sequence_[producer_key] = observation.sequence.value();
  ++stats_.accepted;
  return Status::ok();
}

const ForwardingObservation* EvidenceLedger::find(ObservationId id) const noexcept {
  const auto position = by_id_.find(id.value());
  if (position == by_id_.end()) {
    return nullptr;
  }
  return position->second;
}

std::size_t EvidenceLedger::observation_count_for_edge(ForwardingEdgeId edge) const noexcept {
  const auto position = by_edge_.find(edge.value());
  if (position == by_edge_.end()) {
    return 0;
  }
  return position->second.size();
}

Result<HopResolutionRecord> EvidenceLedger::resolve(const TopologyDefinition& topology,
                                                    std::size_t edge_index,
                                                    const FenceVector& current, Tick now) const {
  if (edge_index >= topology.edges().size()) {
    return Result<HopResolutionRecord>::failure(Outcome::Invalid, "edge index out of range");
  }
  std::vector<const ForwardingObservation*> candidates;
  const auto position = by_edge_.find(topology.edges()[edge_index].id.value());
  if (position != by_edge_.end()) {
    candidates = position->second;
  }
  return resolve_hop_from_observations(topology, edge_index, candidates, current, now, limits_);
}

Result<std::vector<HopResolutionRecord>> EvidenceLedger::resolve_all(
    const TopologyDefinition& topology, const FenceVector& current, Tick now) const {
  std::vector<HopResolutionRecord> records;
  records.reserve(topology.edges().size());
  for (std::size_t index = 0; index < topology.edges().size(); ++index) {
    auto resolved = resolve(topology, index, current, now);
    if (!resolved.has_value()) {
      return Result<std::vector<HopResolutionRecord>>::failure(resolved.outcome(), resolved.detail());
    }
    records.push_back(std::move(resolved).value());
  }
  return Result<std::vector<HopResolutionRecord>>::ok(std::move(records));
}

void EvidenceLedger::clear_dynamic_state() noexcept {
  observations_.clear();
  by_id_.clear();
  by_edge_.clear();
  producer_high_sequence_.clear();
}

Digest EvidenceLedger::digest() const {
  std::vector<const ForwardingObservation*> all;
  all.reserve(observations_.size());
  for (const auto& entry : observations_) {
    all.push_back(&entry.second);
  }
  return observations_digest(std::move(all));
}

EvidenceOrigin EvidenceLedger::origin() const noexcept {
  bool saw_synthetic = false;
  bool saw_real = false;
  for (const auto& entry : observations_) {
    switch (entry.second.origin) {
      case EvidenceOrigin::Real:
        saw_real = true;
        break;
      case EvidenceOrigin::Synthetic:
        saw_synthetic = true;
        break;
      case EvidenceOrigin::Unsupported:
        break;
    }
  }
  if (saw_real) {
    return EvidenceOrigin::Real;
  }
  if (saw_synthetic) {
    return EvidenceOrigin::Synthetic;
  }
  return observations_.empty() ? EvidenceOrigin::Synthetic : EvidenceOrigin::Unsupported;
}

std::size_t EvidenceLedger::non_exact_count(const FenceVector& current, Tick now) const noexcept {
  std::size_t count = 0;
  for (const auto& entry : observations_) {
    const ForwardingObservation& observation = entry.second;
    if (!(observation.lease.boot == current.boot) || !(observation.lease.epoch == current.epoch) ||
        !(observation.lease.fabric_epoch == current.fabric_epoch) ||
        !(observation.topology_generation == current.topology) ||
        !(observation.forwarding_generation == current.forwarding) || !observation.lease.is_live(now)) {
      ++count;
    }
  }
  return count;
}

}  // namespace loop_guard
