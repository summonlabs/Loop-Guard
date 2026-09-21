#include "loop_guard/containment.hpp"

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

bool objective_better(const std::vector<ResourceId>& candidate, std::uint64_t candidate_cost,
                      const std::vector<ResourceId>& incumbent, std::uint64_t incumbent_cost,
                      bool have_incumbent) {
  if (!have_incumbent) {
    return true;
  }
  if (candidate_cost != incumbent_cost) {
    return candidate_cost < incumbent_cost;
  }
  if (candidate.size() != incumbent.size()) {
    return candidate.size() < incumbent.size();
  }
  return std::lexicographical_compare(candidate.begin(), candidate.end(), incumbent.begin(),
                                      incumbent.end());
}

/// Exhaustive branch-and-bound search over the hitting-set instance.
///
/// Completeness: every hitting set must contain at least one element of any uncovered
/// set, so branching over the elements of a chosen uncovered set enumerates a superset of
/// all solutions. Optimality: the search explores every branch that could still beat the
/// incumbent, because a branch is pruned only when its running cost already exceeds the
/// incumbent's cost, and costs are positive.
///
/// Determinism: the branch set is the uncovered set with the fewest hit options, ties
/// broken by the lowest set index; options are visited in ascending resource identity.
/// The objective is minimum cost, then fewest targets, then lexicographically smallest
/// sorted target sequence.
class HittingSetSearch {
 public:
  HittingSetSearch(const HittingSetInstance& instance, std::uint64_t budget)
      : instance_(instance), budget_(budget) {
    const std::size_t option_count = instance_.options.size();
    const std::size_t set_count = instance_.sets.size();
    set_options_.assign(set_count, {});
    option_sets_.assign(option_count, {});
    cover_count_.assign(set_count, 0U);

    std::map<std::uint64_t, std::size_t> option_index;
    for (std::size_t index = 0; index < option_count; ++index) {
      option_index[instance_.options[index].first.value()] = index;
    }
    for (std::size_t set_index = 0; set_index < set_count; ++set_index) {
      for (const ResourceId resource : instance_.sets[set_index]) {
        const auto position = option_index.find(resource.value());
        if (position == option_index.end()) {
          continue;
        }
        set_options_[set_index].push_back(position->second);
        option_sets_[position->second].push_back(set_index);
      }
      auto& list = set_options_[set_index];
      std::sort(list.begin(), list.end());
      list.erase(std::unique(list.begin(), list.end()), list.end());
    }
    for (std::size_t set_index = 0; set_index < set_count; ++set_index) {
      if (set_options_[set_index].empty()) {
        unhittable_ = true;
        unhittable_set_ = set_index;
        return;
      }
    }
    if (set_count == 0U) {
      empty_instance_ = true;
    }
  }

  [[nodiscard]] bool unhittable() const noexcept { return unhittable_; }
  [[nodiscard]] std::size_t unhittable_set() const noexcept { return unhittable_set_; }
  [[nodiscard]] bool empty_instance() const noexcept { return empty_instance_; }

  void run() {
    if (unhittable_ || empty_instance_) {
      return;
    }
    search();
  }

  [[nodiscard]] const std::vector<ResourceId>& best() const noexcept { return best_; }
  [[nodiscard]] std::uint64_t best_cost() const noexcept { return best_cost_; }
  [[nodiscard]] bool have_best() const noexcept { return have_best_; }
  [[nodiscard]] std::uint64_t nodes() const noexcept { return nodes_; }
  [[nodiscard]] bool exhausted() const noexcept { return exhausted_; }

 private:
  void apply(std::size_t option, bool add) {
    for (const std::size_t set_index : option_sets_[option]) {
      if (add) {
        cover_count_[set_index] += 1U;
      } else if (cover_count_[set_index] > 0U) {
        cover_count_[set_index] -= 1U;
      }
    }
  }

  [[nodiscard]] std::optional<std::size_t> choose_branch_set() const {
    std::size_t chosen = 0;
    std::size_t chosen_size = 0;
    bool found = false;
    for (std::size_t set_index = 0; set_index < cover_count_.size(); ++set_index) {
      if (cover_count_[set_index] != 0U) {
        continue;
      }
      const std::size_t size = set_options_[set_index].size();
      if (!found || size < chosen_size || (size == chosen_size && set_index < chosen)) {
        chosen = set_index;
        chosen_size = size;
        found = true;
      }
    }
    if (!found) {
      return std::nullopt;
    }
    return chosen;
  }

  void search() {
    if (exhausted_) {
      return;
    }
    if (++nodes_ > budget_) {
      exhausted_ = true;
      return;
    }
    const auto branch = choose_branch_set();
    if (!branch.has_value()) {
      std::vector<ResourceId> candidate;
      candidate.reserve(current_.size());
      for (const std::size_t option : current_) {
        candidate.push_back(instance_.options[option].first);
      }
      std::sort(candidate.begin(), candidate.end());
      if (objective_better(candidate, running_cost_, best_, best_cost_, have_best_)) {
        best_ = std::move(candidate);
        best_cost_ = running_cost_;
        have_best_ = true;
      }
      return;
    }
    for (const std::size_t option : set_options_[*branch]) {
      if (have_best_ && running_cost_ + instance_.options[option].second > best_cost_) {
        continue;
      }
      apply(option, true);
      current_.push_back(option);
      running_cost_ += instance_.options[option].second;
      search();
      running_cost_ -= instance_.options[option].second;
      current_.pop_back();
      apply(option, false);
      if (exhausted_) {
        return;
      }
    }
  }

  const HittingSetInstance& instance_;
  std::uint64_t budget_;
  std::vector<std::vector<std::size_t>> set_options_;
  std::vector<std::vector<std::size_t>> option_sets_;
  std::vector<std::uint32_t> cover_count_;
  std::vector<std::size_t> current_;
  std::vector<ResourceId> best_;
  std::uint64_t best_cost_ = 0;
  std::uint64_t running_cost_ = 0;
  std::uint64_t nodes_ = 0;
  bool have_best_ = false;
  bool exhausted_ = false;
  bool unhittable_ = false;
  bool empty_instance_ = false;
  std::size_t unhittable_set_ = 0;
};

/// Deterministic greedy recommendation. It is advisory only: it never authorizes
/// anything, and the runtime records it as a recommendation rather than as a plan.
std::vector<ResourceId> greedy_recommendation(const HittingSetInstance& instance) {
  const std::size_t set_count = instance.sets.size();
  std::vector<std::uint8_t> covered(set_count, 0U);
  std::vector<ResourceId> chosen;
  std::size_t remaining = set_count;
  while (remaining != 0U) {
    std::size_t best_option = 0;
    std::size_t best_cover = 0;
    std::uint32_t best_cost = 0;
    bool found = false;
    for (std::size_t option = 0; option < instance.options.size(); ++option) {
      std::size_t count = 0;
      for (std::size_t set_index = 0; set_index < set_count; ++set_index) {
        if (covered[set_index] != 0U) {
          continue;
        }
        const auto& set = instance.sets[set_index];
        if (std::binary_search(set.begin(), set.end(), instance.options[option].first)) {
          ++count;
        }
      }
      if (count == 0U) {
        continue;
      }
      const std::uint32_t cost = instance.options[option].second;
      const bool better = !found || count > best_cover ||
                          (count == best_cover && cost < best_cost) ||
                          (count == best_cover && cost == best_cost &&
                           instance.options[option].first < instance.options[best_option].first);
      if (better) {
        found = true;
        best_option = option;
        best_cover = count;
        best_cost = cost;
      }
    }
    if (!found) {
      break;
    }
    chosen.push_back(instance.options[best_option].first);
    for (std::size_t set_index = 0; set_index < set_count; ++set_index) {
      if (covered[set_index] != 0U) {
        continue;
      }
      const auto& set = instance.sets[set_index];
      if (std::binary_search(set.begin(), set.end(), instance.options[best_option].first)) {
        covered[set_index] = 1U;
        --remaining;
      }
    }
  }
  std::sort(chosen.begin(), chosen.end());
  return chosen;
}

}  // namespace

// ---------------------------------------------------------------------------
// ContainmentPolicy.
// ---------------------------------------------------------------------------
bool ContainmentPolicy::kind_eligible(ResourceKind kind) const noexcept {
  return std::binary_search(eligible_kinds.begin(), eligible_kinds.end(), kind);
}

bool ContainmentPolicy::domain_eligible(DomainId domain) const noexcept {
  if (eligible_domains.empty()) {
    return true;
  }
  return std::binary_search(eligible_domains.begin(), eligible_domains.end(), domain);
}

Digest ContainmentPolicy::digest() const {
  Sha256 hasher;
  hash_u64(hasher, generation.value());
  hash_u64(hasher, max_targets);
  hash_u64(hasher, max_total_cost);
  hasher.update(static_cast<std::uint8_t>(allow_cross_domain ? 1 : 0));
  hash_u64(hasher, max_search_nodes);
  for (const ResourceKind kind : eligible_kinds) {
    hasher.update(static_cast<std::uint8_t>(kind));
  }
  hasher.update(static_cast<std::uint8_t>(0xFB));
  for (const DomainId domain : eligible_domains) {
    hash_u64(hasher, domain.value());
  }
  hasher.update(static_cast<std::uint8_t>(0xFB));
  return hasher.finish();
}

std::string ContainmentPolicy::to_text() const {
  std::string out = "policy generation=" + generation.to_string() +
                    " max_targets=" + std::to_string(max_targets) +
                    " max_total_cost=" + std::to_string(max_total_cost) +
                    " allow_cross_domain=" + (allow_cross_domain ? "true" : "false") + " kinds=";
  if (eligible_kinds.empty()) {
    out += "none";
  }
  for (std::size_t index = 0; index < eligible_kinds.size(); ++index) {
    if (index != 0U) {
      out.push_back(',');
    }
    out += std::string(to_string(eligible_kinds[index]));
  }
  out += " domains=";
  if (eligible_domains.empty()) {
    out += "all";
  }
  for (std::size_t index = 0; index < eligible_domains.size(); ++index) {
    if (index != 0U) {
      out.push_back(',');
    }
    out += eligible_domains[index].to_string();
  }
  return out;
}

// ---------------------------------------------------------------------------
// Hitting-set solvers.
// ---------------------------------------------------------------------------
HittingSetSolution solve_hitting_set(const HittingSetInstance& instance) {
  HittingSetSolution solution;
  HittingSetSearch search(instance, instance.max_search_nodes == 0U
                                        ? default_limits().max_containment_search_nodes
                                        : instance.max_search_nodes);
  if (search.unhittable()) {
    solution.outcome = ContainmentOutcome::ProvenInfeasible;
    solution.proved_infeasible = true;
    solution.has_unhittable_set = true;
    solution.unhittable_set_index = search.unhittable_set();
    return solution;
  }
  if (search.empty_instance()) {
    solution.outcome = ContainmentOutcome::PlanOptimal;
    solution.proved_minimum = true;
    return solution;
  }
  search.run();
  solution.nodes_expanded = search.nodes();
  if (search.have_best()) {
    solution.targets = search.best();
    solution.total_cost = search.best_cost();
    solution.proved_minimum = !search.exhausted();
    solution.outcome = search.exhausted() ? ContainmentOutcome::PlanFeasible
                                          : ContainmentOutcome::PlanOptimal;
  } else if (search.exhausted()) {
    solution.outcome = ContainmentOutcome::SearchLimitReached;
  } else {
    solution.outcome = ContainmentOutcome::ProvenInfeasible;
    solution.proved_infeasible = true;
  }
  return solution;
}

HittingSetSolution solve_hitting_set_reference(const HittingSetInstance& instance) {
  HittingSetSolution solution;
  const std::size_t option_count = instance.options.size();
  if (option_count > 24U) {
    solution.outcome = ContainmentOutcome::Unsupported;
    return solution;
  }
  std::vector<ResourceId> best;
  std::uint64_t best_cost = 0;
  bool have_best = false;
  std::size_t unhittable = 0;
  bool any_unhittable = false;

  const std::uint64_t total_subsets = 1ULL << option_count;
  for (std::uint64_t mask = 0; mask < total_subsets; ++mask) {
    std::vector<ResourceId> chosen;
    std::uint64_t cost = 0;
    for (std::size_t index = 0; index < option_count; ++index) {
      if ((mask & (1ULL << index)) != 0U) {
        chosen.push_back(instance.options[index].first);
        cost += instance.options[index].second;
      }
    }
    std::sort(chosen.begin(), chosen.end());
    bool hits_all = true;
    for (std::size_t set_index = 0; set_index < instance.sets.size(); ++set_index) {
      const auto& set = instance.sets[set_index];
      bool hit = false;
      for (const ResourceId resource : set) {
        if (std::binary_search(chosen.begin(), chosen.end(), resource)) {
          hit = true;
          break;
        }
      }
      if (!hit) {
        hits_all = false;
        if (set.empty()) {
          any_unhittable = true;
          unhittable = set_index;
        }
        break;
      }
    }
    if (!hits_all) {
      continue;
    }
    if (objective_better(chosen, cost, best, best_cost, have_best)) {
      best = std::move(chosen);
      best_cost = cost;
      have_best = true;
    }
  }

  if (have_best) {
    solution.targets = std::move(best);
    solution.total_cost = best_cost;
    solution.proved_minimum = true;
    solution.outcome = ContainmentOutcome::PlanOptimal;
    return solution;
  }
  solution.proved_infeasible = true;
  solution.outcome = ContainmentOutcome::ProvenInfeasible;
  solution.has_unhittable_set = any_unhittable;
  solution.unhittable_set_index = unhittable;
  return solution;
}

// ---------------------------------------------------------------------------
// ContainmentPlan helpers.
// ---------------------------------------------------------------------------
Digest ContainmentPlan::content_digest() const {
  Sha256 hasher;
  hash_u64(hasher, id.value());
  hash_u64(hasher, assessment.value());
  hasher.update(assessment_digest.bytes.data(), kDigestBytes);
  hash_u64(hasher, fence.topology.value());
  hash_u64(hasher, fence.forwarding.value());
  hash_u64(hasher, fence.policy.value());
  hash_u64(hasher, fence.fabric_epoch.value());
  hash_u64(hasher, fence.epoch.value());
  hash_u64(hasher, fence.boot.value());
  hash_u64(hasher, policy_generation.value());
  hasher.update(static_cast<std::uint8_t>(outcome));
  hash_u64(hasher, flags);
  hasher.update(static_cast<std::uint8_t>(within_policy_budget ? 1 : 0));
  for (const ContainmentTarget& target : targets) {
    hash_u64(hasher, target.resource.value());
    hash_u64(hasher, target.domain.value());
    hash_u64(hasher, target.cost);
    hasher.update(static_cast<std::uint8_t>(target.reason));
    for (const WitnessId witness : target.witnesses_broken) {
      hash_u64(hasher, witness.value());
    }
    hasher.update(static_cast<std::uint8_t>(0xFA));
    for (const TrafficSelectorId selector : target.selectors) {
      hash_u64(hasher, selector.value());
    }
    hasher.update(static_cast<std::uint8_t>(0xFA));
    for (const ForwardingEdgeId hop : target.affected_hops) {
      hash_u64(hasher, hop.value());
    }
    hasher.update(static_cast<std::uint8_t>(0xFA));
  }
  hasher.update(static_cast<std::uint8_t>(0xF9));
  hash_u64(hasher, total_cost);
  hash_u64(hasher, witness_count);
  hash_u64(hasher, witnesses_covered);
  hasher.update(static_cast<std::uint8_t>(origin));
  return hasher.finish();
}

std::vector<ResourceId> ContainmentPlan::target_resources() const {
  std::vector<ResourceId> resources;
  resources.reserve(targets.size());
  for (const ContainmentTarget& target : targets) {
    resources.push_back(target.resource);
  }
  std::sort(resources.begin(), resources.end());
  return resources;
}

std::string ContainmentPlan::to_text() const {
  std::string out = "plan " + id.to_string() + " assessment=" + assessment.to_string() +
                    " outcome=" + std::string(to_string(outcome)) +
                    " flags=" + plan_flags_to_string(flags) +
                    " targets=" + std::to_string(targets.size()) +
                    " cost=" + std::to_string(total_cost) +
                    " witnesses=" + std::to_string(witnesses_covered) + "/" +
                    std::to_string(witness_count) +
                    " within_budget=" + (within_policy_budget ? "true" : "false") + "\n";
  for (const ContainmentTarget& target : targets) {
    out += "  target " + target.resource.to_string() + " cost=" + std::to_string(target.cost) +
           " reason=" + std::string(to_string(target.reason)) + " breaks=";
    for (std::size_t index = 0; index < target.witnesses_broken.size(); ++index) {
      if (index != 0U) {
        out.push_back(',');
      }
      out += target.witnesses_broken[index].to_string();
    }
    out.push_back('\n');
  }
  for (const ContainmentTarget& target : greedy_recommendation) {
    out += "  recommendation " + target.resource.to_string() + " cost=" +
           std::to_string(target.cost) + " (advisory, carries no authority)\n";
  }
  if (certificate.has_value()) {
    out += "  certificate " + std::string(to_string(certificate->code)) + " witness=" +
           certificate->witness.to_string() + " cycle=";
    for (const ResourceId resource : certificate->non_containable_cycle) {
      out += resource.to_string();
      out.push_back(' ');
    }
    out += certificate->detail + "\n";
  }
  out += explanation.to_text();
  return out;
}

Digest ContainmentIntent::content_digest() const {
  Sha256 hasher;
  hash_u64(hasher, id.value());
  hash_u64(hasher, plan.value());
  hash_u64(hasher, finding.value());
  hash_u64(hasher, assessment.value());
  hash_u64(hasher, fence.topology.value());
  hash_u64(hasher, fence.forwarding.value());
  hash_u64(hasher, fence.policy.value());
  hash_u64(hasher, fence.fabric_epoch.value());
  hash_u64(hasher, fence.epoch.value());
  hash_u64(hasher, fence.boot.value());
  hash_u64(hasher, issued_by.producer.value());
  hash_u64(hasher, issued_by.boot.value());
  hash_u64(hasher, issued_by.incarnation.value());
  hash_u64(hasher, issued_by.epoch.value());
  for (const ResourceId target : targets) {
    hash_u64(hasher, target.value());
  }
  hasher.update(static_cast<std::uint8_t>(0xF8));
  for (const TrafficSelectorId selector : selectors) {
    hash_u64(hasher, selector.value());
  }
  hash_u64(hasher, issued_at);
  hash_u64(hasher, expires_at);
  hasher.update(plan_digest.bytes.data(), kDigestBytes);
  return hasher.finish();
}

// ---------------------------------------------------------------------------
// Planner.
// ---------------------------------------------------------------------------
Result<ContainmentPlan> ContainmentPlanner::plan(const LoopAssessment& assessment,
                                                 const TopologyDefinition& topology,
                                                 const ContainmentPolicy& policy, Tick now) const {
  (void)now;
  if (!limits_are_sane(limits_)) {
    return Result<ContainmentPlan>::failure(Outcome::Unsupported, "limit set is not sane");
  }
  if (!policy.generation.valid()) {
    return Result<ContainmentPlan>::failure(Outcome::Invalid,
                                            "containment policy generation must be non-zero");
  }
  if (!(policy.generation == assessment.fence.policy)) {
    return Result<ContainmentPlan>::failure(
        Outcome::Stale, "containment policy generation " + policy.generation.to_string() +
                            " is not the generation the assessment binds");
  }
  if (!std::is_sorted(policy.eligible_kinds.begin(), policy.eligible_kinds.end()) ||
      std::adjacent_find(policy.eligible_kinds.begin(), policy.eligible_kinds.end()) !=
          policy.eligible_kinds.end()) {
    return Result<ContainmentPlan>::failure(
        Outcome::Invalid, "eligible policy kinds must be sorted and duplicate free");
  }
  if (!std::is_sorted(policy.eligible_domains.begin(), policy.eligible_domains.end()) ||
      std::adjacent_find(policy.eligible_domains.begin(), policy.eligible_domains.end()) !=
          policy.eligible_domains.end()) {
    return Result<ContainmentPlan>::failure(
        Outcome::Invalid, "eligible policy domains must be sorted and duplicate free");
  }
  if (policy.max_targets > limits_.max_plan_targets) {
    return Result<ContainmentPlan>::failure(Outcome::Exhausted,
                                            "policy target budget exceeds the configured ceiling");
  }

  ContainmentPlan plan;
  plan.assessment = assessment.id;
  plan.assessment_digest = assessment.digest();
  plan.fence = assessment.fence;
  plan.policy_generation = policy.generation;
  plan.origin = assessment.origin;
  plan.explanation = Explanation(limits_.max_explanation_reasons);

  const auto finalize = [&plan]() -> Result<ContainmentPlan> {
    plan.id = content_addressed_id<ContainmentPlanId>(plan.content_digest());
    return Result<ContainmentPlan>::ok(std::move(plan));
  };

  if (assessment.outcome != LoopOutcome::LoopConfirmed) {
    plan.outcome = ContainmentOutcome::NotRequired;
    plan.explanation.add(ReasonCode::ContainmentNotRequired, "assessment",
                         std::string("no confirmed forwarding loop: outcome is ") +
                             std::string(to_string(assessment.outcome)));
    return finalize();
  }
  if (assessment.witnesses.empty()) {
    plan.outcome = ContainmentOutcome::Invalid;
    plan.explanation.add(ReasonCode::ContainmentPlanInvalid, "assessment",
                         "an affirmative assessment without a witness cannot be contained");
    return finalize();
  }

  // Eligibility is derived from the definition and the policy, never from the plan.
  const auto eligible = [&topology, &policy](ResourceId resource) -> const ResourceRecord* {
    const ResourceRecord* record = topology.find_resource(resource);
    if (record == nullptr || !record->containable) {
      return nullptr;
    }
    if (!policy.kind_eligible(record->kind)) {
      return nullptr;
    }
    if (!policy.domain_eligible(record->domain)) {
      return nullptr;
    }
    if (record->containment_cost == 0U) {
      return nullptr;
    }
    return record;
  };

  HittingSetInstance instance;
  instance.max_search_nodes =
      policy.max_search_nodes == 0U ? limits_.max_containment_search_nodes : policy.max_search_nodes;
  std::map<std::uint64_t, std::uint32_t> option_cost;
  std::size_t unhittable_witness = 0;
  bool have_unhittable_witness = false;

  for (std::size_t index = 0; index < assessment.witnesses.size(); ++index) {
    const LoopWitness& witness = assessment.witnesses[index];
    std::vector<ResourceId> set;
    const bool witness_admissible = policy.allow_cross_domain || !witness.crosses_domains;
    if (witness_admissible) {
      for (const ResourceId resource : witness.cycle) {
        const ResourceRecord* record = eligible(resource);
        if (record == nullptr) {
          continue;
        }
        set.push_back(resource);
        option_cost[resource.value()] = record->containment_cost;
      }
    }
    std::sort(set.begin(), set.end());
    set.erase(std::unique(set.begin(), set.end()), set.end());
    if (set.empty() && !have_unhittable_witness) {
      have_unhittable_witness = true;
      unhittable_witness = index;
    }
    instance.sets.push_back(std::move(set));
  }
  for (const auto& entry : option_cost) {
    instance.options.emplace_back(ResourceId::from_value(entry.first), entry.second);
  }
  std::sort(instance.options.begin(), instance.options.end());

  plan.witness_count = static_cast<std::uint32_t>(assessment.witnesses.size());
  const HittingSetSolution solution = solve_hitting_set(instance);
  plan.counters.nodes_expanded = solution.nodes_expanded;

  const auto build_targets = [&](const std::vector<ResourceId>& resources,
                                 TargetReason reason) -> std::vector<ContainmentTarget> {
    std::vector<ContainmentTarget> targets;
    for (const ResourceId resource : resources) {
      const ResourceRecord* record = topology.find_resource(resource);
      if (record == nullptr) {
        continue;
      }
      ContainmentTarget target;
      target.resource = resource;
      target.domain = record->domain;
      target.cost = record->containment_cost;
      target.reason = reason;
      std::set<TrafficSelectorId> selectors;
      std::set<ForwardingEdgeId> hops;
      for (const LoopWitness& witness : assessment.witnesses) {
        if (!std::binary_search(witness.cycle.begin(), witness.cycle.end(), resource)) {
          continue;
        }
        target.witnesses_broken.push_back(witness.id);
        selectors.insert(witness.selectors.begin(), witness.selectors.end());
        for (std::size_t index = 0; index < witness.cycle.size(); ++index) {
          if (witness.cycle[index] == resource ||
              witness.cycle[(index + 1U) % witness.cycle.size()] == resource) {
            hops.insert(witness.hops[index]);
          }
        }
      }
      std::sort(target.witnesses_broken.begin(), target.witnesses_broken.end());
      target.selectors.assign(selectors.begin(), selectors.end());
      target.affected_hops.assign(hops.begin(), hops.end());
      if (target.witnesses_broken.size() == 1U && reason != TargetReason::GreedyRecommendation) {
        target.reason = TargetReason::SoleBreakOfWitness;
      }
      targets.push_back(std::move(target));
    }
    std::sort(targets.begin(), targets.end());
    return targets;
  };

  switch (solution.outcome) {
    case ContainmentOutcome::PlanOptimal:
    case ContainmentOutcome::PlanFeasible: {
      plan.outcome = solution.outcome;
      plan.targets = build_targets(solution.targets, solution.proved_minimum
                                                          ? TargetReason::MinimumCostHittingSet
                                                          : TargetReason::FeasibleHittingSet);
      plan.total_cost = solution.total_cost;
      std::uint64_t recomputed_cost = 0;
      for (const ContainmentTarget& target : plan.targets) {
        recomputed_cost += target.cost;
      }
      if (recomputed_cost != plan.total_cost) {
        plan.outcome = ContainmentOutcome::Invalid;
        plan.targets.clear();
        plan.explanation.add(ReasonCode::InternalInvariantViolated, "plan",
                             "target costs do not add up to the reported total");
        return finalize();
      }
      if (solution.proved_minimum) {
        plan.flags |= kPlanProvedMinimum;
        plan.explanation.add(ReasonCode::ContainmentTargetsProvedMinimum, "plan",
                             "the search completed exhaustively and proved the target set minimal");
      } else {
        plan.flags |= kPlanSearchLimitReached;
        plan.explanation.add(ReasonCode::ContainmentTargetsFeasibleOnly, "plan",
                             "a feasible target set was found, but its optimality is not proved");
      }
      plan.within_policy_budget = plan.targets.size() <= policy.max_targets &&
                                  plan.total_cost <= policy.max_total_cost;
      if (!plan.within_policy_budget) {
        plan.flags |= kPlanCostBudgetExceeded;
        plan.explanation.add(ReasonCode::ContainmentCostBudgetExceeded, "plan",
                             "the proved minimum exceeds the policy budget; the plan is reported "
                             "but is not authorized");
      }
      break;
    }
    case ContainmentOutcome::ProvenInfeasible: {
      plan.outcome = ContainmentOutcome::ProvenInfeasible;
      plan.flags |= kPlanCertificateAttached;
      ContainmentCertificate certificate;
      certificate.code = ReasonCode::ContainmentProvedInfeasible;
      if (solution.has_unhittable_set) {
        certificate.witness = assessment.witnesses[solution.unhittable_set_index].id;
        certificate.non_containable_cycle = assessment.witnesses[solution.unhittable_set_index].cycle;
        certificate.detail =
            "the witness contains no resource the policy declares eligible, so no admissible "
            "target set can break it";
        plan.explanation.add(ReasonCode::ContainmentCertificateNonContainableCycle, "plan",
                             certificate.detail);
      } else {
        certificate.witness = assessment.witnesses.front().id;
        certificate.non_containable_cycle = assessment.witnesses.front().cycle;
        certificate.detail =
            "the exhaustive search proved that no combination of eligible resources breaks "
            "every confirmed witness";
      }
      plan.certificate = std::move(certificate);
      plan.explanation.add(ReasonCode::ContainmentProvedInfeasible, "plan",
                           "containment is impossible within the policy's eligibility rules");
      if (have_unhittable_witness) {
        plan.explanation.add(ReasonCode::ContainmentPolicyRefusedTargets,
                             assessment.witnesses[unhittable_witness].id.to_string(),
                             "no resource on this witness is eligible for containment");
      }
      break;
    }
    case ContainmentOutcome::SearchLimitReached: {
      plan.outcome = ContainmentOutcome::SearchLimitReached;
      plan.flags |= kPlanSearchLimitReached;
      plan.explanation.add(ReasonCode::ContainmentTargetsFeasibleOnly, "plan",
                           "the containment search reached its node budget without proving either "
                           "optimality or infeasibility");
      break;
    }
    default:
      plan.outcome = ContainmentOutcome::Unsupported;
      plan.explanation.add(ReasonCode::ContainmentPlanInvalid, "plan",
                           "the containment search reported an unusable outcome");
      break;
  }

  if (plan.outcome == ContainmentOutcome::SearchLimitReached ||
      (plan.flags & kPlanSearchLimitReached) != 0U) {
    const std::vector<ResourceId> advisory = greedy_recommendation(instance);
    if (!advisory.empty()) {
      plan.greedy_recommendation = build_targets(advisory, TargetReason::GreedyRecommendation);
      plan.flags |= kPlanGreedyRecommendationPresent;
      plan.explanation.add(ReasonCode::ContainmentGreedyRecommendationOnly, "plan",
                           "a deterministic greedy recommendation is attached for operators; it "
                           "carries no authority");
    }
  }

  // Validate before publishing: a plan that cannot be re-derived is not a plan.
  auto validation = PlanValidator::validate(plan, assessment, topology, policy, limits_);
  if (!validation.has_value() || !validation.value().valid) {
    plan.outcome = ContainmentOutcome::Invalid;
    plan.targets.clear();
    plan.within_policy_budget = false;
    plan.explanation.add(ReasonCode::ContainmentPlanInvalid, "plan",
                         "the planner produced a plan its own independent validator refused");
  } else {
    plan.flags |= kPlanUnrelatedForwardingUntouched;
    plan.affected_hops.clear();
    std::set<ForwardingEdgeId> affected;
    for (const ContainmentTarget& target : plan.targets) {
      affected.insert(target.affected_hops.begin(), target.affected_hops.end());
    }
    plan.affected_hops.assign(affected.begin(), affected.end());
    plan.witnesses_covered = 0;
    for (const LoopWitness& witness : assessment.witnesses) {
      const bool broken = std::any_of(
          plan.targets.begin(), plan.targets.end(), [&witness](const ContainmentTarget& target) {
            return std::find(target.witnesses_broken.begin(), target.witnesses_broken.end(),
                             witness.id) != target.witnesses_broken.end();
          });
      if (broken) {
        ++plan.witnesses_covered;
      } else {
        plan.uncovered_witnesses.push_back(witness.id);
      }
    }
  }
  return finalize();
}

// ---------------------------------------------------------------------------
// Plan validation.
// ---------------------------------------------------------------------------
Result<PlanValidation> PlanValidator::validate(const ContainmentPlan& plan,
                                               const LoopAssessment& assessment,
                                               const TopologyDefinition& topology,
                                               const ContainmentPolicy& policy,
                                               const Limits& limits) {
  PlanValidation validation;
  validation.explanation = Explanation(limits.max_explanation_reasons);
  validation.outcome = plan.outcome;

  const auto reject = [&validation](ReasonCode code, std::string subject,
                                    std::string detail) -> Result<PlanValidation> {
    validation.valid = false;
    validation.explanation.add(code, std::move(subject), std::move(detail));
    return Result<PlanValidation>::ok(std::move(validation));
  };

  if (!(plan.fence == assessment.fence)) {
    return reject(ReasonCode::ContainmentPlanInvalid, "plan",
                  "the plan binds a different fence than the assessment it claims to contain");
  }
  if (!(plan.assessment == assessment.id)) {
    return reject(ReasonCode::ContainmentPlanInvalid, "plan",
                  "the plan references a different assessment");
  }
  if (!(plan.policy_generation == policy.generation)) {
    return reject(ReasonCode::ContainmentPlanInvalid, "plan",
                  "the plan was computed under a different policy generation");
  }

  if (plan.outcome == ContainmentOutcome::NotRequired) {
    if (!plan.targets.empty()) {
      return reject(ReasonCode::ContainmentPlanInvalid, "plan",
                    "a NotRequired plan must not carry targets");
    }
    validation.valid = true;
    validation.explanation.add(ReasonCode::ContainmentNotRequired, "plan",
                               "no confirmed loop, so nothing is proposed or authorized");
    return Result<PlanValidation>::ok(std::move(validation));
  }

  if (plan.outcome == ContainmentOutcome::ProvenInfeasible) {
    if (!plan.certificate.has_value()) {
      return reject(ReasonCode::ContainmentPlanInvalid, "certificate",
                    "an infeasibility claim without a certificate is not a proof");
    }
    if (!plan.targets.empty()) {
      return reject(ReasonCode::ContainmentPlanInvalid, "plan",
                    "an infeasible plan must not carry targets");
    }
    const LoopWitness* witness = nullptr;
    for (const LoopWitness& candidate : assessment.witnesses) {
      if (candidate.id == plan.certificate->witness) {
        witness = &candidate;
        break;
      }
    }
    if (witness == nullptr) {
      return reject(ReasonCode::ContainmentPlanInvalid, "certificate",
                    "the certificate references a witness the assessment does not contain");
    }
    bool any_eligible = false;
    for (const ResourceId resource : witness->cycle) {
      const ResourceRecord* record = topology.find_resource(resource);
      if (record != nullptr && record->containable && policy.kind_eligible(record->kind) &&
          policy.domain_eligible(record->domain)) {
        any_eligible = true;
        break;
      }
    }
    if (any_eligible) {
      return reject(ReasonCode::ContainmentPlanInvalid, "certificate",
                    "the certificate names a witness that does contain an eligible resource");
    }
    validation.valid = true;
    validation.explanation.add(ReasonCode::ContainmentCertificateNonContainableCycle, "plan",
                               "the certificate was re-derived and holds");
    return Result<PlanValidation>::ok(std::move(validation));
  }

  if (plan.outcome == ContainmentOutcome::SearchLimitReached ||
      plan.outcome == ContainmentOutcome::Unsupported ||
      plan.outcome == ContainmentOutcome::Invalid) {
    validation.valid = plan.targets.empty();
    validation.explanation.add(ReasonCode::ContainmentTargetsFeasibleOnly, "plan",
                               "no authoritative target set is claimed");
    return Result<PlanValidation>::ok(std::move(validation));
  }

  // Affirmative plans: every claim is re-derived here.
  if (plan.targets.empty()) {
    return reject(ReasonCode::ContainmentPlanInvalid, "targets",
                  "an affirmative plan must carry at least one target");
  }
  if (!std::is_sorted(plan.targets.begin(), plan.targets.end())) {
    return reject(ReasonCode::ContainmentPlanInvalid, "targets",
                  "targets are not in canonical order");
  }
  for (std::size_t index = 1; index < plan.targets.size(); ++index) {
    if (plan.targets[index - 1].resource == plan.targets[index].resource) {
      return reject(ReasonCode::ContainmentPlanInvalid, "targets", "duplicate target resource");
    }
  }

  std::uint64_t total_cost = 0;
  for (const ContainmentTarget& target : plan.targets) {
    const ResourceRecord* record = topology.find_resource(target.resource);
    if (record == nullptr) {
      return reject(ReasonCode::ContainmentPlanInvalid, target.resource.to_string(),
                    "target is not a resource of the definition");
    }
    if (!record->containable || !policy.kind_eligible(record->kind) ||
        !policy.domain_eligible(record->domain)) {
      return reject(ReasonCode::ContainmentPolicyRefusedTargets, target.resource.to_string(),
                    "target is not eligible under the policy in force");
    }
    if (target.cost != record->containment_cost) {
      return reject(ReasonCode::ContainmentPlanInvalid, target.resource.to_string(),
                    "target cost disagrees with the definition");
    }
    total_cost += record->containment_cost;

    bool on_a_witness = false;
    for (const LoopWitness& witness : assessment.witnesses) {
      if (std::binary_search(witness.cycle.begin(), witness.cycle.end(), target.resource)) {
        on_a_witness = true;
        break;
      }
    }
    if (!on_a_witness) {
      validation.unrelated_resources_touched.push_back(target.resource);
    }
  }
  if (!validation.unrelated_resources_touched.empty()) {
    return reject(ReasonCode::ContainmentPlanInvalid, "targets",
                  "the plan touches resources that are not implicated by any confirmed witness");
  }
  if (total_cost != plan.total_cost) {
    return reject(ReasonCode::ContainmentPlanInvalid, "cost",
                  "the reported total cost disagrees with the target costs");
  }

  std::vector<ResourceId> chosen = plan.target_resources();
  for (const LoopWitness& witness : assessment.witnesses) {
    bool hit = false;
    for (const ResourceId resource : witness.cycle) {
      if (std::binary_search(chosen.begin(), chosen.end(), resource)) {
        hit = true;
        break;
      }
    }
    if (!hit) {
      validation.witnesses_not_broken.push_back(witness.id);
    }
  }
  if (!validation.witnesses_not_broken.empty()) {
    return reject(ReasonCode::ContainmentPlanInvalid, "coverage",
                  "the plan does not break every confirmed witness");
  }

  validation.valid = true;
  validation.explanation.add(ReasonCode::ContainmentUnrelatedForwardingUntouched, "plan",
                             "every target lies on a confirmed witness and every witness is broken");
  return Result<PlanValidation>::ok(std::move(validation));
}

// ---------------------------------------------------------------------------
// Shadow application.
// ---------------------------------------------------------------------------
Result<TopologyDefinition> apply_containment_shadow(const TopologyDefinition& topology,
                                                    const ContainmentPlan& plan,
                                                    const Limits& limits) {
  std::vector<ForwardingEdge> edges = topology.edges();
  std::map<std::uint64_t, std::size_t> index_by_id;
  for (std::size_t index = 0; index < edges.size(); ++index) {
    index_by_id[edges[index].id.value()] = index;
  }

  for (const ContainmentTarget& target : plan.targets) {
    if (target.selectors.empty()) {
      return Result<TopologyDefinition>::failure(
          Outcome::Invalid, "a target without selectors would disable unrelated forwarding");
    }
    for (const ForwardingEdgeId hop : target.affected_hops) {
      const auto position = index_by_id.find(hop.value());
      if (position == index_by_id.end()) {
        return Result<TopologyDefinition>::failure(Outcome::NotFound,
                                                   "affected hop is not an edge of the definition");
      }
      ForwardingEdge& edge = edges[position->second];
      for (const TrafficSelectorId selector : target.selectors) {
        if (!std::binary_search(edge.admitted_selectors.begin(), edge.admitted_selectors.end(),
                                selector)) {
          continue;
        }
        edge.admitted_selectors.erase(
            std::lower_bound(edge.admitted_selectors.begin(), edge.admitted_selectors.end(),
                             selector));
      }
    }
  }

  // Rebuild through the ordinary canonical path so the shadow definition carries exactly
  // the same invariants - including the CSR adjacency - as any other definition.
  TopologyBuilder builder(limits);
  builder.set_generation(topology.generation());
  for (const TrafficSelector& selector : topology.selectors()) {
    const Status status = builder.add_selector(selector);
    if (!status.is_ok()) {
      return Result<TopologyDefinition>::failure(status.outcome(), status.detail());
    }
  }
  for (const ResourceRecord& record : topology.resources()) {
    const Status status = builder.add_resource(record);
    if (!status.is_ok()) {
      return Result<TopologyDefinition>::failure(status.outcome(), status.detail());
    }
  }
  for (const ForwardingEdge& edge : edges) {
    const Status status = builder.add_edge(edge);
    if (!status.is_ok()) {
      return Result<TopologyDefinition>::failure(status.outcome(), status.detail());
    }
  }
  return builder.build();
}

}  // namespace loop_guard
