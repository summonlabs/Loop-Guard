#include "loop_guard/witness.hpp"

#include <algorithm>
#include <map>
#include <set>

namespace loop_guard {
namespace {

void hash_u64(Sha256& hasher, std::uint64_t value) {
  hasher.update(
      std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(&value), sizeof(value)));
}

}  // namespace

std::vector<ResourceId> canonicalize_cycle(std::vector<ResourceId> cycle) {
  if (cycle.size() < 2) {
    return cycle;
  }
  std::size_t best = 0;
  for (std::size_t index = 1; index < cycle.size(); ++index) {
    if (cycle[index] < cycle[best]) {
      best = index;
    }
  }
  if (best == 0) {
    return cycle;
  }
  std::rotate(cycle.begin(), cycle.begin() + static_cast<std::ptrdiff_t>(best), cycle.end());
  return cycle;
}

void canonicalize_cycle_with_hops(std::vector<ResourceId>& cycle,
                                  std::vector<ForwardingEdgeId>& hops) {
  if (cycle.size() < 2 || hops.size() != cycle.size()) {
    return;
  }
  std::size_t best = 0;
  for (std::size_t index = 1; index < cycle.size(); ++index) {
    if (cycle[index] < cycle[best]) {
      best = index;
    }
  }
  if (best == 0) {
    return;
  }
  std::rotate(cycle.begin(), cycle.begin() + static_cast<std::ptrdiff_t>(best), cycle.end());
  std::rotate(hops.begin(), hops.begin() + static_cast<std::ptrdiff_t>(best), hops.end());
}

bool operator<(const LoopWitness& lhs, const LoopWitness& rhs) noexcept {
  if (lhs.cycle.size() != rhs.cycle.size()) {
    return lhs.cycle.size() < rhs.cycle.size();
  }
  if (lhs.cycle != rhs.cycle) {
    return std::lexicographical_compare(lhs.cycle.begin(), lhs.cycle.end(), rhs.cycle.begin(),
                                        rhs.cycle.end());
  }
  if (lhs.hops != rhs.hops) {
    return std::lexicographical_compare(lhs.hops.begin(), lhs.hops.end(), rhs.hops.begin(),
                                        rhs.hops.end());
  }
  if (lhs.selectors != rhs.selectors) {
    return std::lexicographical_compare(lhs.selectors.begin(), lhs.selectors.end(),
                                        rhs.selectors.begin(), rhs.selectors.end());
  }
  return lhs.fence < rhs.fence;
}

bool operator==(const LoopWitness& lhs, const LoopWitness& rhs) noexcept {
  return lhs.cycle == rhs.cycle && lhs.hops == rhs.hops && lhs.selectors == rhs.selectors &&
         lhs.fence == rhs.fence && lhs.crosses_domains == rhs.crosses_domains &&
         lhs.evidence_digest == rhs.evidence_digest;
}

Digest LoopWitness::content_digest() const {
  Sha256 hasher;
  hash_u64(hasher, id.value());
  for (const ResourceId resource : cycle) {
    hash_u64(hasher, resource.value());
  }
  hasher.update(static_cast<std::uint8_t>(0xFD));
  for (const ForwardingEdgeId hop : hops) {
    hash_u64(hasher, hop.value());
  }
  hasher.update(static_cast<std::uint8_t>(0xFD));
  for (const TrafficSelectorId selector : selectors) {
    hash_u64(hasher, selector.value());
  }
  hasher.update(static_cast<std::uint8_t>(0xFD));
  hash_u64(hasher, fence.topology.value());
  hash_u64(hasher, fence.forwarding.value());
  hash_u64(hasher, fence.policy.value());
  hash_u64(hasher, fence.fabric_epoch.value());
  hash_u64(hasher, fence.epoch.value());
  hash_u64(hasher, fence.boot.value());
  hasher.update(static_cast<std::uint8_t>(origin));
  hasher.update(static_cast<std::uint8_t>(crosses_domains ? 1 : 0));
  hasher.update(evidence_digest.bytes.data(), kDigestBytes);
  const Digest note_digest = note.digest();
  hasher.update(note_digest.bytes.data(), kDigestBytes);
  return hasher.finish();
}

std::string LoopWitness::to_text() const {
  std::string out = "witness " + id.to_string() + " hops=" + std::to_string(cycle.size()) + " cycle=";
  for (std::size_t index = 0; index < cycle.size(); ++index) {
    if (index != 0U) {
      out += "->";
    }
    out += cycle[index].to_string();
  }
  if (!cycle.empty()) {
    out += "->";
    out += cycle.front().to_string();
  }
  out += " selectors=";
  for (std::size_t index = 0; index < selectors.size(); ++index) {
    if (index != 0U) {
      out.push_back(',');
    }
    out += selectors[index].to_string();
  }
  out += " fence=" + fence.to_string();
  out += crosses_domains ? " cross-domain" : " single-domain";
  out += " origin=" + std::string(to_string(origin));
  return out;
}

// ---------------------------------------------------------------------------
// Independent witness validator.
// ---------------------------------------------------------------------------
Result<WitnessValidation> WitnessValidator::validate(const LoopWitness& witness,
                                                     const TopologyDefinition& topology,
                                                     const EvidenceLedger& ledger,
                                                     const FenceVector& current, Tick now,
                                                     const Limits& limits) {
  WitnessValidation validation;
  validation.explanation = Explanation(limits.max_explanation_reasons);
  const auto reject = [&validation](ReasonCode code, std::string subject,
                                    std::string detail) -> Result<WitnessValidation> {
    validation.valid = false;
    validation.outcome = LoopOutcome::Invalid;
    validation.reasons.push_back(code);
    validation.explanation.add(code, std::move(subject), std::move(detail));
    return Result<WitnessValidation>::ok(std::move(validation));
  };

  if (witness.cycle.empty()) {
    return reject(ReasonCode::WitnessRejectedByValidator, "witness", "cycle is empty");
  }
  if (witness.hop_count() > limits.max_witness_hops) {
    return reject(ReasonCode::WitnessRejectedByValidator, "witness",
                  "cycle exceeds the configured witness length bound");
  }
  if (witness.hops.size() != witness.cycle.size()) {
    return reject(ReasonCode::WitnessRejectedByValidator, "witness",
                  "hop sequence length disagrees with the cycle length");
  }
  if (witness.selectors.empty()) {
    return reject(ReasonCode::WitnessRejectedByValidator, "witness",
                  "a witness must name at least one selector");
  }
  {
    std::set<TrafficSelectorId> distinct(witness.selectors.begin(), witness.selectors.end());
    if (distinct.size() != witness.selectors.size()) {
      return reject(ReasonCode::WitnessRejectedByValidator, "witness",
                    "selector set contains duplicates");
    }
    if (!std::is_sorted(witness.selectors.begin(), witness.selectors.end())) {
      return reject(ReasonCode::WitnessRejectedByValidator, "witness",
                    "selector set is not in canonical order");
    }
  }
  {
    std::set<ResourceId> distinct(witness.cycle.begin(), witness.cycle.end());
    if (distinct.size() != witness.cycle.size()) {
      return reject(ReasonCode::WitnessRejectedByValidator, "witness",
                    "cycle revisits a resource within one rotation");
    }
  }
  if (canonicalize_cycle(witness.cycle) != witness.cycle) {
    return reject(ReasonCode::WitnessRejectedByValidator, "witness",
                  "cycle is not in canonical rotation");
  }
  if (witness.fence != current) {
    validation.valid = false;
    validation.outcome = LoopOutcome::Stale;
    validation.reasons.push_back(ReasonCode::WitnessRequiresExactGenerations);
    validation.explanation.add(ReasonCode::WitnessRequiresExactGenerations, "witness",
                               "witness fence " + witness.fence.to_string() +
                                   " is not the current fence " + current.to_string());
    return Result<WitnessValidation>::ok(std::move(validation));
  }

  std::vector<const ForwardingObservation*> contributing;
  std::set<DomainId> domains;
  const std::size_t count = witness.cycle.size();

  for (std::size_t index = 0; index < count; ++index) {
    const ResourceId from = witness.cycle[index];
    const ResourceId to = witness.cycle[(index + 1U) % count];
    const ForwardingEdgeId hop = witness.hops[index];

    const ResourceRecord* from_record = topology.find_resource(from);
    const ResourceRecord* to_record = topology.find_resource(to);
    if (from_record == nullptr || to_record == nullptr) {
      return reject(ReasonCode::WitnessResourceUnknown, hop.to_string(),
                    "cycle names a resource the definition does not contain");
    }
    if (from_record->admin != AdministrativeState::Enabled ||
        to_record->admin != AdministrativeState::Enabled) {
      return reject(ReasonCode::WitnessResourceAdministrativelyDown, hop.to_string(),
                    "cycle traverses a resource that is not administratively enabled");
    }
    const ForwardingEdge* edge = topology.find_edge(hop);
    if (edge == nullptr) {
      return reject(ReasonCode::WitnessHopGenerationsDisagree, hop.to_string(),
                    "hop is not an edge of the definition");
    }
    if (!(edge->from == from) || !(edge->to == to)) {
      return reject(ReasonCode::WitnessHopGenerationsDisagree, hop.to_string(),
                    "hop does not traverse the resource pair the cycle claims");
    }
    if (edge->link != LinkState::Up) {
      return reject(ReasonCode::WitnessResourceAdministrativelyDown, hop.to_string(),
                    "hop link is not up");
    }

    // Re-derive the hop from raw evidence: the validator never reuses the detector's
    // hop table, so a detector that fabricates an open hop is caught here.
    const auto edge_position = topology.edge_index(hop);
    if (!edge_position.has_value()) {
      return reject(ReasonCode::WitnessHopGenerationsDisagree, hop.to_string(),
                    "hop index could not be re-derived");
    }
    auto resolved = ledger.resolve(topology, *edge_position, current, now);
    if (!resolved.has_value()) {
      return reject(ReasonCode::WitnessRejectedByValidator, hop.to_string(),
                    "hop resolution failed: " + resolved.detail());
    }
    const HopResolutionRecord& record = resolved.value();
    if (record.resolution == HopResolution::Conflicted) {
      validation.valid = false;
      validation.outcome = LoopOutcome::Conflict;
      validation.reasons.push_back(ReasonCode::HopConflictsWithItself);
      validation.explanation.add(ReasonCode::HopConflictsWithItself, hop.to_string(),
                                 "exactly bound evidence contradicts itself on this hop");
      return Result<WitnessValidation>::ok(std::move(validation));
    }
    if (record.resolution != HopResolution::ProvenOpen) {
      return reject(ReasonCode::WitnessRejectedByValidator, hop.to_string(),
                    "hop is not proven open by exactly bound evidence");
    }
    if (!(record.from == from) || !(record.to == to)) {
      return reject(ReasonCode::WitnessHopGenerationsDisagree, hop.to_string(),
                    "resolved hop endpoints disagree with the cycle");
    }
    for (const TrafficSelectorId selector : witness.selectors) {
      if (!std::binary_search(edge->admitted_selectors.begin(), edge->admitted_selectors.end(),
                              selector)) {
        return reject(ReasonCode::WitnessSelectorNotAdmitted, hop.to_string(),
                      "selector " + selector.to_string() + " is not admitted by the edge");
      }
      if (!std::binary_search(record.effective_selectors.begin(), record.effective_selectors.end(),
                              selector)) {
        return reject(ReasonCode::WitnessSelectorNotAdmitted, hop.to_string(),
                      "selector " + selector.to_string() + " is not proven open on the hop");
      }
    }
    domains.insert(from_record->domain);
  }

  {
    const std::set<ForwardingEdgeId> hop_set(witness.hops.begin(), witness.hops.end());
    for (const auto& entry : ledger.observations()) {
      if (hop_set.find(entry.second.edge) != hop_set.end()) {
        contributing.push_back(&entry.second);
      }
    }
  }

  const Digest recomputed = observations_digest(contributing);
  if (!(recomputed == witness.evidence_digest)) {
    return reject(ReasonCode::WitnessRejectedByValidator, "witness",
                  "evidence digest does not match the observations the witness claims");
  }
  const bool crosses = domains.size() > 1;
  if (crosses != witness.crosses_domains) {
    return reject(ReasonCode::WitnessRejectedByValidator, "witness",
                  "cross-domain classification disagrees with the definition");
  }

  validation.valid = true;
  validation.outcome = LoopOutcome::LoopConfirmed;
  validation.reasons.push_back(ReasonCode::WitnessSuccessfullyValidated);
  validation.explanation.add(ReasonCode::WitnessSuccessfullyValidated, "witness",
                             "every hop re-derived as proven open at the current fence");
  return Result<WitnessValidation>::ok(std::move(validation));
}

}  // namespace loop_guard
