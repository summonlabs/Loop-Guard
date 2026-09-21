#include <algorithm>
#include <set>

#include "fixtures.hpp"
#include "harness.hpp"
#include "reference.hpp"

namespace {

using namespace lg_test;
using namespace loop_guard;

ContainmentPolicy make_policy(PolicyGeneration generation, std::uint32_t max_targets,
                              std::uint64_t max_cost) {
  ContainmentPolicy policy;
  policy.generation = generation;
  policy.max_targets = max_targets;
  policy.max_total_cost = max_cost;
  policy.eligible_kinds = {ResourceKind::Switch};
  return policy;
}

}  // namespace

LG_TEST(containment, hitting_set_prefers_minimum_cost) {
  HittingSetInstance instance;
  instance.sets = {{ResourceId::from_value(1), ResourceId::from_value(2)},
                   {ResourceId::from_value(2), ResourceId::from_value(3)}};
  instance.options = {{ResourceId::from_value(1), 10},
                      {ResourceId::from_value(2), 3},
                      {ResourceId::from_value(3), 10}};
  const HittingSetSolution solution = solve_hitting_set(instance);
  LG_CHECK_EQ(solution.outcome, ContainmentOutcome::PlanOptimal);
  LG_CHECK(solution.proved_minimum);
  LG_REQUIRE(solution.targets.size() == 1U);
  LG_CHECK_EQ(solution.targets.front(), ResourceId::from_value(2));
  LG_CHECK_EQ(solution.total_cost, std::uint64_t{3});
}

LG_TEST(containment, hitting_set_breaks_ties_deterministically) {
  HittingSetInstance instance;
  instance.sets = {{ResourceId::from_value(1)}, {ResourceId::from_value(2)}};
  instance.options = {{ResourceId::from_value(1), 1}, {ResourceId::from_value(2), 1}};
  const HittingSetSolution solution = solve_hitting_set(instance);
  LG_CHECK_EQ(solution.outcome, ContainmentOutcome::PlanOptimal);
  LG_CHECK_EQ(solution.targets.size(), std::size_t{2});
  LG_CHECK_EQ(solution.targets[0], ResourceId::from_value(1));
  LG_CHECK_EQ(solution.targets[1], ResourceId::from_value(2));
}

LG_TEST(containment, infeasibility_requires_an_unhittable_set) {
  HittingSetInstance instance;
  instance.sets = {{ResourceId::from_value(1)}};
  instance.options = {{ResourceId::from_value(9), 1}};
  const HittingSetSolution solution = solve_hitting_set(instance);
  LG_CHECK_EQ(solution.outcome, ContainmentOutcome::ProvenInfeasible);
  LG_CHECK(solution.proved_infeasible);
  LG_CHECK(solution.has_unhittable_set);
}

LG_TEST(containment, budget_limits_yield_feasible_or_search_limit_never_optimal) {
  HittingSetInstance instance;
  for (std::uint64_t index = 0; index < 8; ++index) {
    instance.sets.push_back({ResourceId::from_value(1 + index), ResourceId::from_value(1 + ((index + 1U) % 8U))});
  }
  for (std::uint64_t index = 0; index < 8; ++index) {
    instance.options.emplace_back(ResourceId::from_value(1 + index), 1);
  }
  instance.max_search_nodes = 1;
  const HittingSetSolution solution = solve_hitting_set(instance);
  LG_CHECK(solution.outcome != ContainmentOutcome::PlanOptimal);
  LG_CHECK(!solution.proved_minimum);
  LG_CHECK(!solution.proved_infeasible);
}

LG_TEST(containment, plan_for_confirmed_loop_is_minimal_and_validated) {
  RingScenario ring = make_ring(3, 1, 5);
  Scenario& scenario = ring.scenario;
  const TrafficSelectorId selector = scenario.selector_id(0);
  for (const ForwardingEdgeId edge : ring.edges) {
    (void)scenario.observe_present(edge, {selector});
  }
  const auto assessment = scenario.assess();
  LG_REQUIRE(assessment.has_value());
  LG_REQUIRE(assessment.value().outcome == LoopOutcome::LoopConfirmed);
  const ContainmentPolicy policy = make_policy(scenario.fence().policy, 4, 100);
  const ContainmentPlanner planner;
  const auto plan = planner.plan(assessment.value(), scenario.topology(), policy, scenario.now());
  LG_REQUIRE(plan.has_value());
  LG_CHECK_EQ(plan.value().outcome, ContainmentOutcome::PlanOptimal);
  LG_CHECK(plan.value().authorizes_action());
  LG_REQUIRE(plan.value().targets.size() == 1U);
  LG_CHECK_EQ(plan.value().total_cost, std::uint64_t{5});
  LG_CHECK((plan.value().flags & kPlanProvedMinimum) != 0U);
  LG_CHECK((plan.value().flags & kPlanUnrelatedForwardingUntouched) != 0U);
  LG_CHECK(!plan.value().affected_hops.empty());

  const auto validation = PlanValidator::validate(plan.value(), assessment.value(),
                                                  scenario.topology(), policy);
  LG_REQUIRE(validation.has_value());
  LG_CHECK(validation.value().valid);
  LG_CHECK(validation.value().is_affirmative());
  LG_CHECK(validation.value().unrelated_resources_touched.empty());
  LG_CHECK(validation.value().witnesses_not_broken.empty());
}

LG_TEST(containment, not_required_for_a_non_affirmative_assessment) {
  RingScenario ring = make_ring(3);
  const auto assessment = ring.scenario.assess();
  LG_REQUIRE(assessment.has_value());
  LG_CHECK_EQ(assessment.value().outcome, LoopOutcome::Unknown);
  const ContainmentPolicy policy = make_policy(ring.scenario.fence().policy, 4, 100);
  const ContainmentPlanner planner;
  const auto plan = planner.plan(assessment.value(), ring.scenario.topology(), policy,
                                 ring.scenario.now());
  LG_REQUIRE(plan.has_value());
  LG_CHECK_EQ(plan.value().outcome, ContainmentOutcome::NotRequired);
  LG_CHECK(plan.value().targets.empty());
  LG_CHECK(!plan.value().authorizes_action());
  LG_CHECK(plan.value().explanation.contains(ReasonCode::ContainmentNotRequired));
}

LG_TEST(containment, policy_generation_must_match_the_assessment) {
  RingScenario ring = make_ring(3);
  Scenario& scenario = ring.scenario;
  const auto assessment = scenario.assess();
  LG_REQUIRE(assessment.has_value());
  const ContainmentPolicy stale = make_policy(PolicyGeneration::from_value(42), 4, 100);
  const ContainmentPlanner planner;
  const auto plan = planner.plan(assessment.value(), scenario.topology(), stale, scenario.now());
  LG_CHECK(!plan.has_value());
  LG_CHECK_EQ(plan.outcome(), Outcome::Stale);
}

LG_TEST(containment, non_containable_cycle_proves_infeasibility) {
  RingScenario ring = make_ring(3, 1, 1);
  Scenario& scenario = ring.scenario;
  // Rebuild with no containable resource on the cycle.
  Scenario fresh;
  const DomainId domain = DomainId::from_value(1);
  std::vector<ResourceId> nodes;
  for (int index = 0; index < 3; ++index) {
    nodes.push_back(fresh.add_resource(domain, false, 1));
  }
  const TrafficSelectorId selector = fresh.add_selector();
  for (std::size_t index = 0; index < 3; ++index) {
    (void)fresh.add_edge(nodes[index], nodes[(index + 1U) % 3U], LinkState::Up, {selector});
  }
  (void)fresh.install();
  for (const ForwardingEdge& edge : fresh.topology().edges()) {
    (void)fresh.observe_present(edge.id, {selector});
  }
  const auto assessment = fresh.assess();
  LG_REQUIRE(assessment.has_value());
  LG_REQUIRE(assessment.value().outcome == LoopOutcome::LoopConfirmed);
  const ContainmentPolicy policy = make_policy(fresh.fence().policy, 4, 100);
  const ContainmentPlanner planner;
  const auto plan = planner.plan(assessment.value(), fresh.topology(), policy, fresh.now());
  LG_REQUIRE(plan.has_value());
  LG_CHECK_EQ(plan.value().outcome, ContainmentOutcome::ProvenInfeasible);
  LG_REQUIRE(plan.value().certificate.has_value());
  LG_CHECK(plan.value().targets.empty());
  LG_CHECK(!plan.value().authorizes_action());
  const auto validation =
      PlanValidator::validate(plan.value(), assessment.value(), fresh.topology(), policy);
  LG_REQUIRE(validation.has_value());
  LG_CHECK(validation.value().valid);
  (void)ring;
  (void)scenario;
}

LG_TEST(containment, cost_budget_refusal_is_explicit) {
  RingScenario ring = make_ring(3, 1, 50);
  Scenario& scenario = ring.scenario;
  const TrafficSelectorId selector = scenario.selector_id(0);
  for (const ForwardingEdgeId edge : ring.edges) {
    (void)scenario.observe_present(edge, {selector});
  }
  const auto assessment = scenario.assess();
  LG_REQUIRE(assessment.has_value());
  const ContainmentPolicy policy = make_policy(scenario.fence().policy, 4, 10);
  const ContainmentPlanner planner;
  const auto plan = planner.plan(assessment.value(), scenario.topology(), policy, scenario.now());
  LG_REQUIRE(plan.has_value());
  LG_CHECK_EQ(plan.value().outcome, ContainmentOutcome::PlanOptimal);
  LG_CHECK(!plan.value().within_policy_budget);
  LG_CHECK(!plan.value().authorizes_action());
  LG_CHECK((plan.value().flags & kPlanCostBudgetExceeded) != 0U);
}

LG_TEST(containment, plan_validator_rejects_tampering) {
  RingScenario ring = make_ring(4, 1, 1);
  Scenario& scenario = ring.scenario;
  const TrafficSelectorId selector = scenario.selector_id(0);
  for (const ForwardingEdgeId edge : ring.edges) {
    (void)scenario.observe_present(edge, {selector});
  }
  const auto assessment = scenario.assess();
  LG_REQUIRE(assessment.has_value());
  const ContainmentPolicy policy = make_policy(scenario.fence().policy, 4, 100);
  const ContainmentPlanner planner;
  auto plan = planner.plan(assessment.value(), scenario.topology(), policy, scenario.now());
  LG_REQUIRE(plan.has_value());
  LG_REQUIRE(plan.value().outcome == ContainmentOutcome::PlanOptimal);

  ContainmentPlan tampered = plan.value();
  tampered.targets.clear();
  auto validation = PlanValidator::validate(tampered, assessment.value(), scenario.topology(), policy);
  LG_REQUIRE(validation.has_value());
  LG_CHECK(!validation.value().valid);

  tampered = plan.value();
  if (!tampered.targets.empty()) {
    tampered.targets.front().cost += 1U;
  }
  validation = PlanValidator::validate(tampered, assessment.value(), scenario.topology(), policy);
  LG_REQUIRE(validation.has_value());
  LG_CHECK(!validation.value().valid);

  tampered = plan.value();
  tampered.fence.boot = BootId::from_value(99);
  validation = PlanValidator::validate(tampered, assessment.value(), scenario.topology(), policy);
  LG_REQUIRE(validation.has_value());
  LG_CHECK(!validation.value().valid);

  tampered = plan.value();
  tampered.targets.push_back(ContainmentTarget{});
  validation = PlanValidator::validate(tampered, assessment.value(), scenario.topology(), policy);
  LG_REQUIRE(validation.has_value());
  LG_CHECK(!validation.value().valid);
}

LG_TEST(containment, shadow_application_removes_the_loop_and_spares_other_forwarding) {
  Scenario scenario;
  const DomainId domain = DomainId::from_value(1);
  const ResourceId a = scenario.add_resource(domain, true, 4);
  const ResourceId b = scenario.add_resource(domain, true, 9);
  const ResourceId c = scenario.add_resource(domain, true, 9);
  const ResourceId outside = scenario.add_resource(domain, true, 1);
  const TrafficSelectorId selector = scenario.add_selector();
  const TrafficSelectorId other = scenario.add_selector();
  const ForwardingEdgeId ab = scenario.add_edge(a, b, LinkState::Up, {selector, other});
  const ForwardingEdgeId bc = scenario.add_edge(b, c, LinkState::Up, {selector, other});
  const ForwardingEdgeId ca = scenario.add_edge(c, a, LinkState::Up, {selector, other});
  const ForwardingEdgeId spare = scenario.add_edge(c, outside, LinkState::Up, {selector, other});
  (void)scenario.install();
  // Only the implicated selector is proven open on the cycle; the other selector stays
  // unproven and must therefore not be implicated by containment.
  for (const ForwardingEdgeId hop : {ab, bc, ca, spare}) {
    (void)scenario.observe_present(hop, {selector});
  }
  const auto assessment = scenario.assess();
  LG_REQUIRE(assessment.has_value());
  LG_REQUIRE(assessment.value().outcome == LoopOutcome::LoopConfirmed);
  LG_REQUIRE(assessment.value().witnesses.size() == 1U);
  LG_CHECK_EQ(assessment.value().witnesses.front().selectors.size(), std::size_t{1});

  const ContainmentPolicy policy = make_policy(scenario.fence().policy, 4, 100);
  const ContainmentPlanner planner;
  const auto plan = planner.plan(assessment.value(), scenario.topology(), policy, scenario.now());
  LG_REQUIRE(plan.has_value());
  LG_REQUIRE(plan.value().outcome == ContainmentOutcome::PlanOptimal);
  LG_REQUIRE(plan.value().targets.size() == 1U);
  LG_CHECK_EQ(plan.value().targets.front().resource, a);

  const auto shadow = apply_containment_shadow(scenario.topology(), plan.value());
  LG_REQUIRE(shadow.has_value());

  // The spare edge keeps every selector it had: no unrelated forwarding was disabled.
  const ForwardingEdge* spare_after = shadow->find_edge(spare);
  LG_REQUIRE(spare_after != nullptr);
  LG_CHECK_EQ(spare_after->admitted_selectors.size(), std::size_t{2});

  // Every hop of the contained cycle lost exactly the implicated selector, and kept the
  // other one: the containment is bounded to the traffic that was implicated.
  for (const ForwardingEdgeId hop : plan.value().affected_hops) {
    const ForwardingEdge* after = shadow->find_edge(hop);
    LG_REQUIRE(after != nullptr);
    LG_CHECK_EQ(after->admitted_selectors.size(), std::size_t{1});
    LG_CHECK_EQ(after->admitted_selectors.front(), other);
  }

  // Re-detecting against the shadow model proves the loop is gone for the implicated
  // selector while the unrelated selector's graph is untouched.
  DetectionRequest request;
  request.topology = &shadow.value();
  request.ledger = &scenario.ledger();
  request.fence = scenario.fence();
  request.now = scenario.now();
  const LoopDetector detector;
  const auto after = detector.assess(request);
  LG_REQUIRE(after.has_value());
  LG_CHECK(after.value().outcome == LoopOutcome::NoLoop ||
           after.value().outcome == LoopOutcome::Unknown);
  for (const LoopWitness& witness : after.value().witnesses) {
    LG_CHECK(std::find(witness.selectors.begin(), witness.selectors.end(), selector) ==
             witness.selectors.end());
  }
}

LG_TEST(containment, overlapping_loops_share_one_target_when_optimal) {
  Scenario scenario;
  const DomainId domain = DomainId::from_value(1);
  const ResourceId shared = scenario.add_resource(domain, true, 1);
  const ResourceId left = scenario.add_resource(domain, true, 1);
  const ResourceId right = scenario.add_resource(domain, true, 1);
  const TrafficSelectorId selector = scenario.add_selector();
  (void)scenario.add_edge(shared, left, LinkState::Up, {selector});
  (void)scenario.add_edge(left, shared, LinkState::Up, {selector});
  (void)scenario.add_edge(shared, right, LinkState::Up, {selector});
  (void)scenario.add_edge(right, shared, LinkState::Up, {selector});
  (void)scenario.install();
  scenario.observe_all_present();
  const auto assessment = scenario.assess();
  LG_REQUIRE(assessment.has_value());
  LG_REQUIRE(assessment.value().outcome == LoopOutcome::LoopConfirmed);
  LG_CHECK(assessment.value().witnesses.size() >= 2U);

  const ContainmentPolicy policy = make_policy(scenario.fence().policy, 4, 100);
  const ContainmentPlanner planner;
  const auto plan = planner.plan(assessment.value(), scenario.topology(), policy, scenario.now());
  LG_REQUIRE(plan.has_value());
  LG_CHECK_EQ(plan.value().outcome, ContainmentOutcome::PlanOptimal);
  LG_REQUIRE(plan.value().targets.size() == 1U);
  LG_CHECK_EQ(plan.value().targets.front().resource, shared);
  LG_CHECK_EQ(plan.value().witnesses_covered, plan.value().witness_count);
  LG_CHECK(plan.value().uncovered_witnesses.empty());
}
