// Loop Guard - bounded containment intent.
//
// Loop Guard owns containment *intent*, not containment *effect*. It selects a
// bounded, deterministic target set that provably breaks the confirmed witnesses,
// validates that the selection touches nothing else, and hands the intent to an
// applier through an explicit grant. Whether the applier applied it is a separate,
// independently observed fact.
//
// Containment semantics:
//   * the selected target set is a hitting set over the confirmed witness cycles,
//     restricted to resources the policy declares eligible (containable);
//   * the objective is a deterministic total order: minimum total cost, then fewest
//     targets, then lexicographically smallest sorted target sequence;
//   * the search is bounded. A bound that is reached yields PlanFeasible,
//     SearchLimitReached or an explicit indeterminate outcome - never a claim of
//     optimality and never a claim of infeasibility;
//   * PROVEN_INFEASIBLE requires a certificate: a confirmed witness none of whose
//     resources is eligible, so no admissible target set can exist;
//   * the plan carries the exact set of hops it affects, and a validator re-derives
//     that no unrelated forwarding is disabled.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "loop_guard/core.hpp"
#include "loop_guard/detect.hpp"
#include "loop_guard/digest.hpp"
#include "loop_guard/enums.hpp"
#include "loop_guard/id.hpp"
#include "loop_guard/limits.hpp"
#include "loop_guard/result.hpp"
#include "loop_guard/topology.hpp"
#include "loop_guard/witness.hpp"

namespace loop_guard {

/// Explicit containment policy. Everything the planner may do is stated here; the
/// planner never invents scope, cost headroom or eligibility.
struct ContainmentPolicy {
  PolicyGeneration generation;
  std::uint32_t max_targets = 8;
  std::uint64_t max_total_cost = 64;
  /// Eligible resource kinds, sorted and duplicate free. Empty means "no kind is eligible".
  std::vector<ResourceKind> eligible_kinds;
  /// Eligible domains, sorted. Empty means "every domain".
  std::vector<DomainId> eligible_domains;
  /// When false, a witness that spans several domains has no admissible containment.
  bool allow_cross_domain = false;
  /// Additional node budget for the containment search. Zero means "use default_limits()".
  std::uint64_t max_search_nodes = 0;

  [[nodiscard]] bool kind_eligible(ResourceKind kind) const noexcept;
  [[nodiscard]] bool domain_eligible(DomainId domain) const noexcept;
  [[nodiscard]] Digest digest() const;
  [[nodiscard]] std::string to_text() const;
  friend bool operator==(const ContainmentPolicy&, const ContainmentPolicy&) noexcept = default;
};

/// One selected containment target.
struct ContainmentTarget {
  ResourceId resource;
  DomainId domain;
  std::uint32_t cost = 1;
  TargetReason reason = TargetReason::MinimumCostHittingSet;
  /// Witnesses this target breaks, sorted.
  std::vector<WitnessId> witnesses_broken;
  /// Selectors whose traffic is stopped by containing this resource, sorted.
  std::vector<TrafficSelectorId> selectors;
  /// Hops of the confirmed witnesses that pass through this resource, canonical order.
  std::vector<ForwardingEdgeId> affected_hops;

  friend bool operator==(const ContainmentTarget&, const ContainmentTarget&) noexcept = default;
  friend bool operator<(const ContainmentTarget& lhs, const ContainmentTarget& rhs) noexcept {
    return lhs.resource < rhs.resource;
  }
};

/// Certificate backing a PROVEN_INFEASIBLE outcome.
struct ContainmentCertificate {
  ReasonCode code = ReasonCode::ContainmentProvedInfeasible;
  /// A confirmed witness whose resources contain no eligible target.
  WitnessId witness;
  std::vector<ResourceId> non_containable_cycle;
  std::string detail;

  friend bool operator==(const ContainmentCertificate&, const ContainmentCertificate&) noexcept = default;
};

struct ContainmentPlan {
  ContainmentPlanId id;
  AssessmentId assessment;
  Digest assessment_digest;
  FenceVector fence;
  PolicyGeneration policy_generation;
  ContainmentOutcome outcome = ContainmentOutcome::Invalid;
  PlanFlags flags = kPlanNone;
  /// Authoritative targets, canonical order. Empty for every non-affirmative outcome.
  std::vector<ContainmentTarget> targets;
  /// Advisory recommendation carrying no authority. Present only when the exact search
  /// could not complete, so that an operator still sees an option.
  std::vector<ContainmentTarget> greedy_recommendation;
  std::uint64_t total_cost = 0;
  std::uint32_t witness_count = 0;
  std::uint32_t witnesses_covered = 0;
  std::vector<WitnessId> uncovered_witnesses;
  std::optional<ContainmentCertificate> certificate;
  /// Hops the plan would affect, canonical order. Every one of them belongs to a
  /// confirmed witness.
  std::vector<ForwardingEdgeId> affected_hops;
  /// True only when the plan fits the policy's target count and cost budgets. A plan
  /// that is mathematically optimal but exceeds the budgets carries its targets for
  /// auditability and is explicitly not authorized.
  bool within_policy_budget = false;

  struct Counters {
    std::uint64_t nodes_expanded = 0;
    std::uint64_t candidates_evaluated = 0;
    std::uint64_t pruned_by_bound = 0;
    std::uint64_t best_updates = 0;
    bool budget_exhausted = false;
  } counters;

  Explanation explanation;
  EvidenceOrigin origin = EvidenceOrigin::Synthetic;

  [[nodiscard]] bool authorizes_action() const noexcept {
    return outcome == ContainmentOutcome::PlanOptimal && within_policy_budget && !targets.empty();
  }
  [[nodiscard]] Digest content_digest() const;
  [[nodiscard]] std::vector<ResourceId> target_resources() const;
  [[nodiscard]] std::string to_text() const;
};

/// The bounded, time-limited intent handed to an applier. An intent is not an effect.
struct ContainmentIntent {
  ContainmentIntentId id;
  ContainmentPlanId plan;
  FindingId finding;
  AssessmentId assessment;
  FenceVector fence;
  ProcessIdentity issued_by;
  std::vector<ResourceId> targets;  ///< Canonical order, a subset of the plan's targets.
  std::vector<TrafficSelectorId> selectors;
  Tick issued_at = 0;
  Tick expires_at = 0;
  Digest plan_digest;

  [[nodiscard]] bool is_expired(Tick now) const noexcept { return now > expires_at; }
  [[nodiscard]] Digest content_digest() const;
};

class ContainmentPlanner {
 public:
  explicit ContainmentPlanner(const Limits& limits = default_limits()) : limits_(limits) {}

  /// Computes a containment plan for \p assessment under \p policy.
  ///
  /// \p assessment must be an affirmative assessment produced by LoopDetector; a
  /// non-affirmative assessment yields ContainmentOutcome::NotRequired and no targets.
  [[nodiscard]] Result<ContainmentPlan> plan(const LoopAssessment& assessment,
                                             const TopologyDefinition& topology,
                                             const ContainmentPolicy& policy, Tick now) const;

 private:
  Limits limits_;
};

/// What an independent re-derivation of a plan concluded.
struct PlanValidation {
  bool valid = false;
  ContainmentOutcome outcome = ContainmentOutcome::Invalid;
  /// Resources the plan touches that are not on any confirmed witness. Must be empty
  /// for every accepted plan.
  std::vector<ResourceId> unrelated_resources_touched;
  /// Witnesses the plan fails to break. Must be empty for an affirmative plan.
  std::vector<WitnessId> witnesses_not_broken;
  Explanation explanation;

  [[nodiscard]] bool is_affirmative() const noexcept {
    return valid && (outcome == ContainmentOutcome::PlanOptimal ||
                     outcome == ContainmentOutcome::PlanFeasible);
  }
};

class PlanValidator {
 public:
  /// Re-derives the plan's claims from the assessment, the topology and the policy.
  /// It never trusts the plan's own coverage accounting.
  [[nodiscard]] static Result<PlanValidation> validate(const ContainmentPlan& plan,
                                                       const LoopAssessment& assessment,
                                                       const TopologyDefinition& topology,
                                                       const ContainmentPolicy& policy,
                                                       const Limits& limits = default_limits());
};

/// Produces a shadow topology in which the plan's targets are administratively
/// disabled. Used to prove containment effectiveness without claiming that anything
/// was actually programmed on a device.
[[nodiscard]] Result<TopologyDefinition> apply_containment_shadow(
    const TopologyDefinition& topology, const ContainmentPlan& plan,
    const Limits& limits = default_limits());

/// Input to the hitting-set solver: the witness cycles to break, and the admissible
/// candidate resources with their costs.
struct HittingSetInstance {
  /// Resource sets to hit, canonical within each set, sets in canonical order.
  std::vector<std::vector<ResourceId>> sets;
  /// Candidate resources with costs, sorted by resource id.
  std::vector<std::pair<ResourceId, std::uint32_t>> options;
  std::uint64_t max_search_nodes = 0;
};

struct HittingSetSolution {
  ContainmentOutcome outcome = ContainmentOutcome::Invalid;
  std::vector<ResourceId> targets;
  std::uint64_t total_cost = 0;
  std::uint64_t nodes_expanded = 0;
  bool proved_minimum = false;
  bool proved_infeasible = false;
  std::size_t unhittable_set_index = 0;
  bool has_unhittable_set = false;
};

/// Exhaustive branch-and-bound hitting-set solver with an explicit node budget.
/// Deterministic objective: minimum total cost, then fewest targets, then
/// lexicographically smallest sorted target sequence.
[[nodiscard]] HittingSetSolution solve_hitting_set(const HittingSetInstance& instance);

/// Slow, deliberately naive reference solver: enumerates every subset in increasing
/// cardinality order. Used only to differential-test the branch-and-bound solver on
/// small instances. It is not on any production path.
[[nodiscard]] HittingSetSolution solve_hitting_set_reference(const HittingSetInstance& instance);

}  // namespace loop_guard
