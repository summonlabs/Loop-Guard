#include <algorithm>
#include <set>

#include "fixtures.hpp"
#include "harness.hpp"
#include "loop_guard/containment.hpp"
#include "reference.hpp"

namespace {

using namespace lg_test;
using namespace loop_guard;

/// Deterministic differential run: the branch-and-bound solver and the naive reference
/// solver must agree exactly on outcome, targets and cost.
std::uint64_t differential(std::uint64_t seed, std::size_t rounds, bool& ok) {
  Rng rng(seed);
  ok = true;
  std::uint64_t feasible_cases = 0;
  for (std::size_t round = 0; round < rounds; ++round) {
    const std::size_t set_count = 1U + static_cast<std::size_t>(rng.next_below(6));
    const std::size_t universe = 1U + static_cast<std::size_t>(rng.next_below(7));
    const std::size_t option_count = universe;
    HittingSetInstance instance;
    instance.max_search_nodes = 0;
    const auto sets = random_cycles(rng, set_count, universe, 4);
    std::vector<std::vector<ResourceId>> normalised;
    for (const auto& set : sets) {
      std::vector<ResourceId> subset;
      for (const ResourceId resource : set) {
        if (resource <= ResourceId::from_value(universe)) {
          subset.push_back(resource);
        }
      }
      if (subset.empty()) {
        continue;
      }
      normalised.push_back(subset);
    }
    if (normalised.empty()) {
      continue;
    }
    std::sort(normalised.begin(), normalised.end());
    instance.sets = normalised;
    for (std::size_t index = 0; index < option_count; ++index) {
      instance.options.emplace_back(ResourceId::from_value(1U + index),
                                    static_cast<std::uint32_t>(1U + rng.next_below(5)));
    }

    const HittingSetSolution fast = solve_hitting_set(instance);
    bool feasible = false;
    const std::vector<ResourceId> slow =
        reference_min_hitting_set(instance.sets, instance.options, feasible);

    if (feasible) {
      ++feasible_cases;
      if (fast.outcome != ContainmentOutcome::PlanOptimal) {
        ok = false;
        return round;
      }
      if (fast.targets != slow) {
        ok = false;
        return round;
      }
    } else if (fast.outcome != ContainmentOutcome::ProvenInfeasible) {
      ok = false;
      return round;
    }
  }
  return rounds;
}

}  // namespace

LG_TEST(oracle, hitting_set_matches_the_reference_solver) {
  bool ok = false;
  for (std::uint64_t seed : {1ULL, 7ULL, 99ULL, 20260101ULL}) {
    const std::uint64_t rounds = differential(seed, 400, ok);
    LG_CHECK(ok);
    if (!ok) {
      // The seed is printed so a counterexample is reproducible.
      LG_CHECK_EQ(seed, std::uint64_t{0});
      break;
    }
    LG_CHECK_EQ(rounds, std::uint64_t{400});
  }
}

LG_TEST(oracle, greedy_is_not_optimal_on_a_deliberately_adversarial_instance) {
  // Two witnesses, three candidates. Candidate 3 hits both witnesses at cost 3, so a
  // greedy rule that maximises coverage first stops there. The optimum is the two cheap
  // candidates at cost 2. The exact solver must find the optimum, not the greedy answer.
  HittingSetInstance instance;
  instance.sets = {{ResourceId::from_value(1), ResourceId::from_value(3)},
                   {ResourceId::from_value(2), ResourceId::from_value(3)}};
  instance.options = {{ResourceId::from_value(1), 1},
                      {ResourceId::from_value(2), 1},
                      {ResourceId::from_value(3), 3}};
  const HittingSetSolution solution = solve_hitting_set(instance);
  LG_CHECK_EQ(solution.outcome, ContainmentOutcome::PlanOptimal);
  LG_CHECK(solution.proved_minimum);
  LG_CHECK_EQ(solution.total_cost, std::uint64_t{2});
  LG_CHECK_EQ(solution.targets.size(), std::size_t{2});
  LG_CHECK_EQ(solution.targets[0], ResourceId::from_value(1));
  LG_CHECK_EQ(solution.targets[1], ResourceId::from_value(2));
  bool feasible = false;
  const auto reference = reference_min_hitting_set(instance.sets, instance.options, feasible);
  LG_CHECK(feasible);
  LG_CHECK_EQ(solution.targets, reference);

  // A single candidate that covers everything at higher cost is still not chosen when
  // the cheaper pair exists, and the pair is chosen when it is cheaper.
  HittingSetInstance second;
  second.sets = {{ResourceId::from_value(1), ResourceId::from_value(5)}};
  second.options = {{ResourceId::from_value(1), 4}, {ResourceId::from_value(5), 4}};
  const HittingSetSolution single = solve_hitting_set(second);
  LG_CHECK_EQ(single.total_cost, std::uint64_t{4});
  LG_CHECK_EQ(single.targets.size(), std::size_t{1});
  LG_CHECK_EQ(single.targets.front(), ResourceId::from_value(1));
}

LG_TEST(oracle, reference_cycle_enumerator_agrees_with_detection) {
  // A 4-node digraph with a chord. Enumerate cycles naively and compare with what the
  // detector reports for an all-open topology.
  Scenario scenario;
  const DomainId domain = DomainId::from_value(1);
  const ResourceId a = scenario.add_resource(domain);
  const ResourceId b = scenario.add_resource(domain);
  const ResourceId c = scenario.add_resource(domain);
  const ResourceId d = scenario.add_resource(domain);
  const TrafficSelectorId selector = scenario.add_selector();
  (void)scenario.add_edge(a, b, LinkState::Up, {selector});
  (void)scenario.add_edge(b, c, LinkState::Up, {selector});
  (void)scenario.add_edge(c, d, LinkState::Up, {selector});
  (void)scenario.add_edge(d, a, LinkState::Up, {selector});
  (void)scenario.add_edge(c, a, LinkState::Up, {selector});
  (void)scenario.install();
  scenario.observe_all_present();

  std::vector<std::vector<bool>> adjacency(4, std::vector<bool>(4, false));
  std::vector<ResourceId> nodes = {a, b, c, d};
  std::sort(nodes.begin(), nodes.end());
  for (const ForwardingEdge& edge : scenario.topology().edges()) {
    const auto from = static_cast<std::size_t>(
        std::lower_bound(nodes.begin(), nodes.end(), edge.from) - nodes.begin());
    const auto to = static_cast<std::size_t>(
        std::lower_bound(nodes.begin(), nodes.end(), edge.to) - nodes.begin());
    adjacency[from][to] = true;
  }
  const auto reference_cycles = reference_simple_cycles(adjacency, 4);
  LG_CHECK_EQ(reference_cycles.size(), std::size_t{2});

  const auto assessment = scenario.assess();
  LG_REQUIRE(assessment.has_value());
  LG_REQUIRE(assessment.value().outcome == LoopOutcome::LoopConfirmed);
  LG_CHECK_EQ(assessment.value().witnesses.size(), reference_cycles.size());
  std::vector<std::vector<std::size_t>> detected;
  for (const LoopWitness& witness : assessment.value().witnesses) {
    std::vector<std::size_t> mapped;
    for (const ResourceId resource : witness.cycle) {
      mapped.push_back(static_cast<std::size_t>(
          std::lower_bound(nodes.begin(), nodes.end(), resource) - nodes.begin()));
    }
    detected.push_back(mapped);
  }
  std::sort(detected.begin(), detected.end());
  LG_CHECK_EQ(detected, reference_cycles);
}

LG_TEST(oracle, exhaustive_small_cycle_counts) {
  // Every directed graph on three nodes: the detector must agree with a naive enumeration
  // about whether a cycle exists, when all hops are proven open.
  const std::size_t nodes = 3;
  const std::size_t possible = nodes * (nodes - 1U);
  std::uint64_t checked = 0;
  for (std::uint64_t mask = 0; mask < (1ULL << possible); ++mask) {
    Scenario scenario;
    const DomainId domain = DomainId::from_value(1);
    std::vector<ResourceId> resources;
    for (std::size_t index = 0; index < nodes; ++index) {
      resources.push_back(scenario.add_resource(domain));
    }
    const TrafficSelectorId selector = scenario.add_selector();
    std::vector<std::vector<bool>> adjacency(nodes, std::vector<bool>(nodes, false));
    std::size_t bit = 0;
    for (std::size_t from = 0; from < nodes; ++from) {
      for (std::size_t to = 0; to < nodes; ++to) {
        if (from == to) {
          continue;
        }
        if ((mask & (1ULL << bit)) != 0U) {
          (void)scenario.add_edge(resources[from], resources[to], LinkState::Up, {selector});
          adjacency[from][to] = true;
        }
        ++bit;
      }
    }
    (void)scenario.install();
    scenario.observe_all_present();
    const auto assessment = scenario.assess();
    LG_REQUIRE(assessment.has_value());
    const bool expected = !reference_simple_cycles(adjacency, nodes).empty();
    if (expected) {
      if (assessment.value().outcome != LoopOutcome::LoopConfirmed) {
        LG_CHECK_EQ(assessment.value().outcome, LoopOutcome::LoopConfirmed);
        return;
      }
    } else if (assessment.value().outcome != LoopOutcome::NoLoop) {
      LG_CHECK_EQ(assessment.value().outcome, LoopOutcome::NoLoop);
      return;
    }
    ++checked;
  }
  LG_CHECK_EQ(checked, std::uint64_t{1} << possible);
}
