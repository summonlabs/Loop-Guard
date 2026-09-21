#include "loop_guard/detect.hpp"

#include <algorithm>
#include <cstdint>
#include <map>
#include <set>
#include <vector>

namespace loop_guard {
namespace {

void hash_u64(Sha256& hasher, std::uint64_t value) {
  hasher.update(
      std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(&value), sizeof(value)));
}

/// Hop classes used by the exact existence proof. Each traversable hop has exactly one
/// class, and every probe is a prefix of the class order, so one adjacency build serves
/// all three questions.
enum class HopClass : std::uint8_t {
  Proven = 0,     ///< Exactly bound evidence proves the hop open.
  Unproven = 1,   ///< The hop might be open: no exact evidence, or only an earlier binding.
  Conflicted = 2, ///< Authoritative evidence contradicts itself about this hop.
};

/// Exact cycle-existence test.
///
/// Kahn's algorithm is used rather than a recursive depth-first search: it is iterative,
/// so a large adversarial graph cannot overflow the stack, and it is exact, so a negative
/// answer is a proof of absence rather than the absence of a bounded search result.
class CycleProbe {
 public:
  explicit CycleProbe(std::size_t node_count) : node_count_(node_count), indegree_(node_count, 0U) {}

  void reserve(std::size_t edges) { edges_.reserve(edges); }

  void clear() {
    edges_.clear();
    std::fill(indegree_.begin(), indegree_.end(), 0U);
  }

  void add_edge(std::size_t from, std::size_t to, HopClass klass) {
    edges_.push_back(Edge{from, to, klass});
    indegree_[to] += 1U;
  }

  /// True when a cycle exists using only hops whose class is at most \p highest.
  [[nodiscard]] bool has_cycle(HopClass highest) {
    std::vector<std::size_t> offsets(node_count_ + 1U, 0U);
    std::size_t usable = 0;
    for (const Edge& edge : edges_) {
      if (static_cast<std::uint8_t>(edge.klass) <= static_cast<std::uint8_t>(highest)) {
        offsets[edge.from + 1U] += 1U;
        ++usable;
      }
    }
    if (usable == 0U) {
      return false;
    }
    for (std::size_t index = 0; index < node_count_; ++index) {
      offsets[index + 1U] += offsets[index];
    }
    out_list_.assign(usable, 0U);
    cursor_ = offsets;
    std::vector<std::uint32_t> indegree(node_count_, 0U);
    for (const Edge& edge : edges_) {
      if (static_cast<std::uint8_t>(edge.klass) > static_cast<std::uint8_t>(highest)) {
        continue;
      }
      out_list_[cursor_[edge.from]] = edge.to;
      cursor_[edge.from] += 1U;
      indegree[edge.to] += 1U;
    }

    removed_.assign(node_count_, 0U);
    queue_.clear();
    queue_.reserve(node_count_);
    for (std::size_t index = 0; index < node_count_; ++index) {
      if (indegree[index] == 0U) {
        queue_.push_back(index);
      }
    }
    std::size_t processed = 0;
    std::size_t head = 0;
    while (head < queue_.size()) {
      const std::size_t node = queue_[head];
      ++head;
      if (removed_[node] != 0U) {
        continue;
      }
      removed_[node] = 1U;
      ++processed;
      for (std::size_t index = offsets[node]; index < offsets[node + 1U]; ++index) {
        const std::size_t target = out_list_[index];
        if (removed_[target] != 0U) {
          continue;
        }
        if (indegree[target] > 0U) {
          indegree[target] -= 1U;
          if (indegree[target] == 0U) {
            queue_.push_back(target);
          }
        }
      }
    }
    return processed != node_count_;
  }

 private:
  struct Edge {
    std::size_t from;
    std::size_t to;
    HopClass klass;
  };

  std::size_t node_count_;
  std::vector<Edge> edges_;
  std::vector<std::uint32_t> indegree_;
  std::vector<std::size_t> out_list_;
  std::vector<std::size_t> cursor_;
  std::vector<std::uint8_t> removed_;
  std::vector<std::size_t> queue_;
};

bool mask_empty(const std::vector<std::uint64_t>& mask) {
  for (const std::uint64_t word : mask) {
    if (word != 0U) {
      return false;
    }
  }
  return true;
}

void mask_and_into(std::vector<std::uint64_t>& out, const std::vector<std::uint64_t>& lhs,
                   const std::vector<std::uint64_t>& rhs) {
  for (std::size_t index = 0; index < out.size(); ++index) {
    out[index] = lhs[index] & rhs[index];
  }
}

struct HopView {
  std::size_t from_node = 0;
  std::size_t to_node = 0;
  HopClass klass = HopClass::Unproven;
  bool traversable = false;
  /// Bitset over the candidate selector list for the class this hop belongs to.
  std::vector<std::uint64_t> mask;
};

}  // namespace

Digest hop_table_digest(const std::vector<HopResolutionRecord>& hops) {
  Sha256 hasher;
  for (const HopResolutionRecord& hop : hops) {
    hash_u64(hasher, hop.edge.value());
    hash_u64(hasher, hop.from.value());
    hash_u64(hasher, hop.to.value());
    hash_u64(hasher, hop.domain.value());
    hasher.update(static_cast<std::uint8_t>(hop.resolution));
    hasher.update(static_cast<std::uint8_t>(hop.binding));
    for (const TrafficSelectorId selector : hop.effective_selectors) {
      hash_u64(hasher, selector.value());
    }
    hasher.update(static_cast<std::uint8_t>(0xFC));
    for (const ObservationId observation : hop.contributing) {
      hash_u64(hasher, observation.value());
    }
    hasher.update(static_cast<std::uint8_t>(0xFC));
  }
  return hasher.finish();
}

// ---------------------------------------------------------------------------
// LoopAssessment helpers.
// ---------------------------------------------------------------------------
Digest LoopAssessment::digest() const {
  Sha256 hasher;
  hash_u64(hasher, id.value());
  hash_u64(hasher, fence.topology.value());
  hash_u64(hasher, fence.forwarding.value());
  hash_u64(hasher, fence.policy.value());
  hash_u64(hasher, fence.fabric_epoch.value());
  hash_u64(hasher, fence.epoch.value());
  hash_u64(hasher, fence.boot.value());
  hasher.update(static_cast<std::uint8_t>(outcome));
  hash_u64(hasher, flags);
  hasher.update(static_cast<std::uint8_t>(origin));
  const Digest witnesses_digest = witness_set_digest();
  hasher.update(witnesses_digest.bytes.data(), kDigestBytes);
  const Digest hops_digest = hop_table_digest(hops);
  hasher.update(hops_digest.bytes.data(), kDigestBytes);
  return hasher.finish();
}

Digest LoopAssessment::witness_set_digest() const {
  Sha256 hasher;
  for (const LoopWitness& witness : witnesses) {
    const Digest content = witness.content_digest();
    hasher.update(content.bytes.data(), kDigestBytes);
  }
  return hasher.finish();
}

std::vector<ResourceId> LoopAssessment::implicated_resources() const {
  std::vector<ResourceId> resources;
  for (const LoopWitness& witness : witnesses) {
    resources.insert(resources.end(), witness.cycle.begin(), witness.cycle.end());
  }
  std::sort(resources.begin(), resources.end());
  resources.erase(std::unique(resources.begin(), resources.end()), resources.end());
  return resources;
}

std::vector<TrafficSelectorId> LoopAssessment::implicated_selectors() const {
  std::vector<TrafficSelectorId> selectors;
  for (const LoopWitness& witness : witnesses) {
    selectors.insert(selectors.end(), witness.selectors.begin(), witness.selectors.end());
  }
  std::sort(selectors.begin(), selectors.end());
  selectors.erase(std::unique(selectors.begin(), selectors.end()), selectors.end());
  return selectors;
}

std::string LoopAssessment::to_text() const {
  std::string out = "assessment " + id.to_string() + " outcome=" + std::string(to_string(outcome)) +
                    " flags=" + assessment_flags_to_string(flags) + " fence=" + fence.to_string() +
                    " witnesses=" + std::to_string(witnesses.size()) +
                    " hops=" + std::to_string(hops.size()) +
                    " origin=" + std::string(to_string(origin)) + "\n";
  for (const LoopWitness& witness : witnesses) {
    out += "  ";
    out += witness.to_text();
    out.push_back('\n');
  }
  out += "counters scc_runs=" + std::to_string(counters.scc_runs) +
         " steps=" + std::to_string(counters.steps_used) +
         " cycles=" + std::to_string(counters.cycles_enumerated) +
         " validated=" + std::to_string(counters.witnesses_validated) +
         " rejected=" + std::to_string(counters.witnesses_rejected) + "\n";
  out += explanation.to_text();
  return out;
}

// ---------------------------------------------------------------------------
// Detection.
// ---------------------------------------------------------------------------
Result<LoopAssessment> LoopDetector::assess(const DetectionRequest& request) const {
  const auto finalize = [](LoopAssessment& value) -> Result<LoopAssessment> {
    value.id = content_addressed_id<AssessmentId>(value.digest());
    return Result<LoopAssessment>::ok(std::move(value));
  };

  if (request.topology == nullptr || request.ledger == nullptr) {
    return Result<LoopAssessment>::failure(
        Outcome::Invalid, "a detection request needs a topology and an evidence ledger");
  }
  if (!limits_are_sane(limits_)) {
    return Result<LoopAssessment>::failure(Outcome::Unsupported, "limit set is not sane");
  }
  const TopologyDefinition& topology = *request.topology;
  const EvidenceLedger& ledger = *request.ledger;

  LoopAssessment assessment;
  assessment.fence = request.fence;
  assessment.explanation = Explanation(limits_.max_explanation_reasons);
  assessment.origin = EvidenceOrigin::Synthetic;

  if (request.fence.is_zero()) {
    assessment.outcome = LoopOutcome::Invalid;
    assessment.explanation.add(ReasonCode::RequestRejectedStructural, "fence",
                               "detection requires a fully populated fence vector");
    return finalize(assessment);
  }
  if (!(topology.generation() == request.fence.topology)) {
    assessment.outcome = LoopOutcome::Stale;
    assessment.explanation.add(ReasonCode::ObservationGenerationMismatch, "topology",
                               "definition generation " + topology.generation().to_string() +
                                   " is not the generation the request binds");
    return finalize(assessment);
  }

  auto resolved = ledger.resolve_all(topology, request.fence, request.now);
  if (!resolved.has_value()) {
    return Result<LoopAssessment>::failure(resolved.outcome(), resolved.detail());
  }
  assessment.hops = std::move(resolved).value();

  const std::size_t node_count = topology.resources().size();
  const std::size_t edge_count = topology.edges().size();

  std::map<std::uint64_t, std::size_t> node_index_by_resource;
  for (std::size_t index = 0; index < node_count; ++index) {
    node_index_by_resource[topology.resources()[index].id.value()] = index;
  }

  // --- Candidate selector set -------------------------------------------------
  std::set<TrafficSelectorId> candidate_set;
  bool any_conflict = false;
  bool any_unproven = false;
  for (const HopResolutionRecord& hop : assessment.hops) {
    const ForwardingEdge* edge = topology.find_edge(hop.edge);
    switch (hop.resolution) {
      case HopResolution::ProvenOpen:
      case HopResolution::UnprovenOpen:
        candidate_set.insert(hop.effective_selectors.begin(), hop.effective_selectors.end());
        break;
      case HopResolution::Conflicted:
        any_conflict = true;
        if (edge != nullptr) {
          candidate_set.insert(edge->admitted_selectors.begin(), edge->admitted_selectors.end());
        }
        break;
      case HopResolution::Unproven:
        any_unproven = true;
        if (edge != nullptr) {
          candidate_set.insert(edge->admitted_selectors.begin(), edge->admitted_selectors.end());
        }
        break;
      case HopResolution::ProvenClosed:
      case HopResolution::Unsupported:
        break;
    }
  }

  std::vector<TrafficSelectorId> candidates(candidate_set.begin(), candidate_set.end());
  if (!request.selector_scope.empty()) {
    if (!std::is_sorted(request.selector_scope.begin(), request.selector_scope.end()) ||
        std::adjacent_find(request.selector_scope.begin(), request.selector_scope.end()) !=
            request.selector_scope.end()) {
      assessment.outcome = LoopOutcome::Invalid;
      assessment.explanation.add(ReasonCode::RequestRejectedStructural, "selector_scope",
                                 "selector scope must be strictly increasing");
      return finalize(assessment);
    }
    for (const TrafficSelectorId selector : request.selector_scope) {
      if (topology.find_selector(selector) == nullptr) {
        assessment.outcome = LoopOutcome::Invalid;
        assessment.explanation.add(ReasonCode::RequestRejectedStructural, selector.to_string(),
                                   "selector scope names a selector the definition does not declare");
        return finalize(assessment);
      }
    }
    std::vector<TrafficSelectorId> restricted;
    for (const TrafficSelectorId selector : candidates) {
      if (std::binary_search(request.selector_scope.begin(), request.selector_scope.end(), selector)) {
        restricted.push_back(selector);
      }
    }
    candidates = std::move(restricted);
  }

  if (ledger.empty()) {
    assessment.flags |= kAssessmentNoEvidenceAtAll;
  }
  if (any_conflict) {
    assessment.flags |= kAssessmentConflictsPresent;
  }
  if (any_unproven) {
    assessment.flags |= kAssessmentUnprovenHopsPresent;
  }
  if (ledger.non_exact_count(request.fence, request.now) != 0U) {
    assessment.flags |= kAssessmentStaleEvidencePresent;
  }

  if (edge_count == 0U || node_count == 0U) {
    assessment.outcome = LoopOutcome::NoLoop;
    assessment.flags |= kAssessmentNoEvidenceAtAll;
    assessment.explanation.add(ReasonCode::SearchCompletedExhaustively, "topology",
                               "the definition contains no adjacency to traverse");
    return finalize(assessment);
  }

  if (candidates.size() > limits_.max_candidate_selectors) {
    assessment.outcome = LoopOutcome::Indeterminate;
    assessment.flags |= kAssessmentSearchLimitReached;
    assessment.counters.selectors_exhausted = true;
    assessment.explanation.add(
        ReasonCode::SearchBudgetExhausted, "selectors",
        "candidate selector count " + std::to_string(candidates.size()) +
            " exceeds the configured bound; absence of a loop cannot be proved");
    return finalize(assessment);
  }
  assessment.counters.selectors_considered = candidates.size();

  // --- Per-hop view -----------------------------------------------------------
  const std::size_t words = (candidates.size() + 63U) / 64U;
  const std::uint64_t memory_estimate = static_cast<std::uint64_t>(edge_count) *
                                        static_cast<std::uint64_t>(words) * 8ULL;
  if (memory_estimate > (256ULL << 20U)) {
    assessment.outcome = LoopOutcome::Indeterminate;
    assessment.flags |= kAssessmentSearchLimitReached;
    assessment.explanation.add(ReasonCode::ResourceBudgetExhausted, "selector-mask",
                               "selector-mask working set would exceed the in-memory ceiling");
    return finalize(assessment);
  }

  std::map<std::uint64_t, std::size_t> candidate_index;
  for (std::size_t index = 0; index < candidates.size(); ++index) {
    candidate_index[candidates[index].value()] = index;
  }

  std::vector<HopView> hops(edge_count);
  for (std::size_t index = 0; index < edge_count; ++index) {
    const HopResolutionRecord& record = assessment.hops[index];
    const ForwardingEdge& edge = topology.edges()[index];
    HopView& view = hops[index];
    view.mask.assign(words, 0U);

    const auto from_node = node_index_by_resource.find(edge.from.value());
    const auto to_node = node_index_by_resource.find(edge.to.value());
    if (from_node == node_index_by_resource.end() || to_node == node_index_by_resource.end()) {
      view.traversable = false;
      continue;
    }
    view.from_node = from_node->second;
    view.to_node = to_node->second;

    const std::vector<TrafficSelectorId>* selector_source = &record.effective_selectors;
    switch (record.resolution) {
      case HopResolution::ProvenOpen:
        view.klass = HopClass::Proven;
        view.traversable = true;
        break;
      case HopResolution::UnprovenOpen:
      case HopResolution::Unproven:
        view.klass = HopClass::Unproven;
        view.traversable = true;
        selector_source = record.resolution == HopResolution::UnprovenOpen
                              ? &record.effective_selectors
                              : &edge.admitted_selectors;
        break;
      case HopResolution::Conflicted:
        view.klass = HopClass::Conflicted;
        view.traversable = true;
        selector_source = &edge.admitted_selectors;
        break;
      case HopResolution::ProvenClosed:
      case HopResolution::Unsupported:
        view.traversable = false;
        continue;
    }
    for (const TrafficSelectorId selector : *selector_source) {
      const auto position = candidate_index.find(selector.value());
      if (position == candidate_index.end()) {
        continue;
      }
      view.mask[position->second / 64U] |= (1ULL << (position->second % 64U));
    }
    if (mask_empty(view.mask)) {
      view.traversable = false;
    }
  }

  // --- Exact existence phase --------------------------------------------------
  bool proven_cycle_exists = false;
  bool unproven_cycle_exists = false;
  bool conflict_only_cycle_exists = false;
  bool steps_exhausted = false;
  std::uint64_t steps = 0;

  CycleProbe probe(node_count);
  probe.reserve(edge_count);
  for (std::size_t selector_index = 0; selector_index < candidates.size() && !steps_exhausted;
       ++selector_index) {
    const std::size_t word = selector_index / 64U;
    const std::uint64_t bit = 1ULL << (selector_index % 64U);
    probe.clear();
    bool touched = false;
    for (const HopView& view : hops) {
      ++steps;
      if (!view.traversable || (view.mask[word] & bit) == 0U) {
        continue;
      }
      touched = true;
      probe.add_edge(view.from_node, view.to_node, view.klass);
    }
    if (steps > limits_.max_search_steps) {
      steps_exhausted = true;
      break;
    }
    if (!touched) {
      continue;
    }
    ++assessment.counters.scc_runs;
    if (probe.has_cycle(HopClass::Proven)) {
      proven_cycle_exists = true;
      continue;
    }
    if (probe.has_cycle(HopClass::Unproven)) {
      unproven_cycle_exists = true;
      continue;
    }
    if (probe.has_cycle(HopClass::Conflicted)) {
      conflict_only_cycle_exists = true;
    }
  }

  assessment.counters.steps_used = steps;
  assessment.counters.edges_examined = steps;
  assessment.counters.steps_exhausted = steps_exhausted;
  if (steps_exhausted) {
    assessment.flags |= kAssessmentSearchLimitReached;
    assessment.explanation.add(ReasonCode::SearchBudgetExhausted, "existence",
                               "the per-selector existence proof reached the step budget");
  }

  // --- Witness enumeration ----------------------------------------------------
  std::vector<LoopWitness> witnesses;
  bool cycles_exhausted = false;
  bool length_bound_reached = false;
  std::uint64_t cycles_enumerated = 0;
  std::uint64_t enumeration_steps = 0;

  if (proven_cycle_exists && !steps_exhausted) {
    std::vector<std::vector<std::size_t>> proven_out(node_count);
    for (std::size_t index = 0; index < edge_count; ++index) {
      if (hops[index].traversable && hops[index].klass == HopClass::Proven) {
        proven_out[hops[index].from_node].push_back(index);
      }
    }

    const std::size_t max_depth = std::min<std::size_t>(limits_.max_witness_hops, node_count);
    std::vector<std::vector<std::uint64_t>> masks(max_depth + 1U,
                                                  std::vector<std::uint64_t>(words, 0ULL));
    std::vector<std::uint64_t> scratch(words, 0ULL);
    std::vector<std::size_t> path_nodes;
    std::vector<std::size_t> path_edges;
    std::vector<std::uint8_t> on_path(node_count, 0U);
    path_nodes.reserve(max_depth + 1U);
    path_edges.reserve(max_depth + 1U);

    struct Frame {
      std::size_t node = 0;
      std::size_t cursor = 0;
      std::size_t start = 0;
    };

    for (std::size_t start = 0; start < node_count; ++start) {
      if (cycles_exhausted || steps_exhausted) {
        break;
      }
      if (proven_out[start].empty()) {
        continue;
      }
      for (std::size_t word = 0; word < words; ++word) {
        masks[0][word] = ~0ULL;
      }
      if (words != 0U && candidates.size() % 64U != 0U) {
        masks[0][words - 1U] = (1ULL << (candidates.size() % 64U)) - 1ULL;
      }

      std::vector<Frame> stack;
      stack.push_back(Frame{start, 0U, start});
      path_nodes.assign(1U, start);
      path_edges.clear();
      on_path[start] = 1U;

      while (!stack.empty()) {
        Frame& frame = stack.back();
        if (frame.cursor >= proven_out[frame.node].size()) {
          on_path[frame.node] = 0U;
          stack.pop_back();
          path_nodes.pop_back();
          if (!path_edges.empty()) {
            path_edges.pop_back();
          }
          continue;
        }
        const std::size_t edge_index = proven_out[frame.node][frame.cursor];
        ++frame.cursor;
        ++enumeration_steps;
        if (enumeration_steps > limits_.max_search_steps) {
          steps_exhausted = true;
          break;
        }

        const HopView& view = hops[edge_index];
        const std::size_t depth = path_nodes.size();
        mask_and_into(scratch, masks[depth - 1U], view.mask);
        if (mask_empty(scratch)) {
          continue;
        }
        const std::size_t next = view.to_node;

        if (next == frame.start) {
          ++cycles_enumerated;
          if (cycles_enumerated > limits_.max_cycles_enumerated) {
            cycles_exhausted = true;
            break;
          }
          LoopWitness witness;
          witness.fence = request.fence;
          witness.origin = assessment.origin;
          std::set<DomainId> domains;
          for (const std::size_t node : path_nodes) {
            witness.cycle.push_back(topology.resources()[node].id);
            domains.insert(topology.resources()[node].domain);
          }
          for (const std::size_t hop : path_edges) {
            witness.hops.push_back(topology.edges()[hop].id);
          }
          witness.hops.push_back(topology.edges()[edge_index].id);
          canonicalize_cycle_with_hops(witness.cycle, witness.hops);
          for (std::size_t selector_index = 0; selector_index < candidates.size(); ++selector_index) {
            if ((scratch[selector_index / 64U] & (1ULL << (selector_index % 64U))) != 0U) {
              witness.selectors.push_back(candidates[selector_index]);
            }
          }
          witness.crosses_domains = domains.size() > 1;
          witness.note = Explanation(limits_.max_explanation_reasons);
          witness.note.add(ReasonCode::WitnessRequiresExactGenerations, "witness",
                           "every hop carries exactly bound forwarding evidence");
          witnesses.push_back(std::move(witness));
          if (witnesses.size() >= limits_.max_witnesses_per_assessment) {
            cycles_exhausted = true;
            break;
          }
          continue;
        }

        if (next <= frame.start || on_path[next] != 0U) {
          continue;
        }
        if (path_nodes.size() >= max_depth) {
          length_bound_reached = true;
          continue;
        }
        for (std::size_t word = 0; word < words; ++word) {
          masks[path_nodes.size()][word] = scratch[word];
        }
        on_path[next] = 1U;
        path_nodes.push_back(next);
        path_edges.push_back(edge_index);
        stack.push_back(Frame{next, 0U, frame.start});
      }
      on_path[start] = 0U;
    }
  }

  assessment.counters.cycles_enumerated = cycles_enumerated;
  assessment.counters.steps_used = steps + enumeration_steps;
  assessment.counters.cycles_exhausted = cycles_exhausted;
  assessment.counters.length_bound_reached = length_bound_reached;
  if (cycles_exhausted || length_bound_reached) {
    assessment.flags |= kAssessmentSearchLimitReached;
  }

  // --- Independent validation of every produced witness -----------------------
  std::sort(witnesses.begin(), witnesses.end());
  witnesses.erase(std::unique(witnesses.begin(), witnesses.end()), witnesses.end());
  if (witnesses.size() > limits_.max_witnesses_per_assessment) {
    witnesses.resize(limits_.max_witnesses_per_assessment);
    cycles_exhausted = true;
    assessment.flags |= kAssessmentSearchLimitReached;
  }

  const std::uint64_t validation_budget = 4000000ULL;
  std::uint64_t validation_cost = 0;
  std::vector<LoopWitness> accepted;
  accepted.reserve(witnesses.size());
  std::uint64_t rejected = 0;
  for (LoopWitness& witness : witnesses) {
    const std::uint64_t cost = static_cast<std::uint64_t>(witness.hop_count()) *
                               static_cast<std::uint64_t>(edge_count + 1U);
    if (!accepted.empty() && validation_cost + cost > validation_budget) {
      assessment.counters.witnesses_dropped += 1U;
      continue;
    }
    validation_cost += cost;
    std::vector<const ForwardingObservation*> contributing;
    const std::set<ForwardingEdgeId> hop_set(witness.hops.begin(), witness.hops.end());
    for (const auto& entry : ledger.observations()) {
      if (hop_set.find(entry.second.edge) != hop_set.end()) {
        contributing.push_back(&entry.second);
      }
    }
    witness.evidence_digest = observations_digest(contributing);
    auto validation =
        WitnessValidator::validate(witness, topology, ledger, request.fence, request.now, limits_);
    if (!validation.has_value() || !validation.value().valid) {
      ++rejected;
      assessment.explanation.add(ReasonCode::InternalInvariantViolated, "witness",
                                 "the detector produced a witness the independent validator "
                                 "refused: " +
                                     witness.to_text());
      continue;
    }
    ++assessment.counters.witnesses_validated;
    accepted.push_back(std::move(witness));
  }
  witnesses = std::move(accepted);
  assessment.witnesses = witnesses;
  assessment.counters.witnesses_rejected = rejected;
  assessment.counters.witnesses_retained = witnesses.size();

  // --- Outcome ----------------------------------------------------------------
  if (proven_cycle_exists && !witnesses.empty()) {
    assessment.outcome = LoopOutcome::LoopConfirmed;
    assessment.explanation.add(ReasonCode::WitnessSuccessfullyValidated, "assessment",
                               "a forwarding loop was proved and independently validated");
  } else if (proven_cycle_exists) {
    assessment.outcome = LoopOutcome::Indeterminate;
    assessment.flags |= kAssessmentSearchLimitReached;
    assessment.explanation.add(ReasonCode::SearchBudgetExhausted, "witnesses",
                               "a proven cycle exists but no witness could be produced within the "
                               "enumeration budget; the question is not answered");
  } else if (steps_exhausted) {
    assessment.outcome = LoopOutcome::Indeterminate;
    assessment.explanation.add(ReasonCode::SearchBudgetExhausted, "existence",
                               "the proof budget was reached before cycle absence could be proved");
  } else if (conflict_only_cycle_exists) {
    assessment.outcome = LoopOutcome::Conflict;
    assessment.explanation.add(ReasonCode::HopConflictsWithItself, "topology",
                               "a cycle exists only by traversing a hop whose authoritative "
                               "evidence contradicts itself");
  } else if (unproven_cycle_exists) {
    assessment.outcome = LoopOutcome::Unknown;
    assessment.explanation.add(
        ReasonCode::CycleRequiresUnprovenHop, "topology",
        "a cycle exists in the adjacency graph, but at least one hop on it is not proved open");
  } else {
    assessment.outcome = LoopOutcome::NoLoop;
    assessment.explanation.add(ReasonCode::SearchCompletedExhaustively, "topology",
                               "no cycle exists in the proven or possibly-open forwarding graph "
                               "for any candidate selector");
  }

  if (!witnesses.empty() && (cycles_exhausted || length_bound_reached)) {
    assessment.flags |= kAssessmentAdditionalCyclesPossible;
  }

  assessment.origin = ledger.origin();
  return finalize(assessment);
}

Result<WitnessValidation> LoopDetector::revalidate(const LoopWitness& witness,
                                                   const TopologyDefinition& topology,
                                                   const EvidenceLedger& ledger,
                                                   const FenceVector& current, Tick now) const {
  return WitnessValidator::validate(witness, topology, ledger, current, now, limits_);
}

}  // namespace loop_guard
