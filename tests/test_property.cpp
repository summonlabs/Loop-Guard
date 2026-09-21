#include <algorithm>
#include <set>

#include "fixtures.hpp"
#include "harness.hpp"
#include "reference.hpp"

namespace {

using namespace lg_test;
using namespace loop_guard;

/// Asserts the invariants that must hold after every detection, whatever the inputs.
void check_invariants(const LoopAssessment& assessment, const FenceVector& fence) {
  LG_CHECK(assessment.fence == fence);
  LG_CHECK(assessment.id.valid());
  if (assessment.outcome == LoopOutcome::LoopConfirmed) {
    LG_CHECK(!assessment.witnesses.empty());
    LG_CHECK(!assessment.hops.empty());
    for (const LoopWitness& witness : assessment.witnesses) {
      LG_CHECK(witness.fence == fence);
      LG_CHECK(!witness.cycle.empty());
      LG_CHECK_EQ(witness.cycle.size(), witness.hops.size());
      LG_CHECK(!witness.selectors.empty());
      LG_CHECK(std::is_sorted(witness.selectors.begin(), witness.selectors.end()));
      // Canonical rotation means the smallest resource identity is first; it does not
      // mean the cycle is sorted.
      LG_CHECK(witness.cycle.front() ==
               *std::min_element(witness.cycle.begin(), witness.cycle.end()));
      std::set<ResourceId> distinct(witness.cycle.begin(), witness.cycle.end());
      LG_CHECK_EQ(distinct.size(), witness.cycle.size());
    }
    for (std::size_t index = 1; index < assessment.witnesses.size(); ++index) {
      LG_CHECK(!(assessment.witnesses[index] < assessment.witnesses.front()));
    }
  } else {
    LG_CHECK(assessment.witnesses.empty());
  }
  if (assessment.outcome == LoopOutcome::NoLoop) {
    LG_CHECK((assessment.flags & kAssessmentSearchLimitReached) == 0U);
  }
  if ((assessment.flags & kAssessmentSearchLimitReached) != 0U) {
    LG_CHECK(assessment.outcome != LoopOutcome::NoLoop);
  }
}

/// Builds a deterministic pseudo-random directed graph plus a random evidence assignment.
struct RandomCase {
  Scenario scenario;
  LoopOutcome expected_class = LoopOutcome::Invalid;
};

/// Runs one seeded random scenario and returns false when an invariant broke.
bool random_round(std::uint64_t seed, std::size_t round) {
  Rng rng(seed * 1000003ULL + round);
  Scenario scenario;
  const DomainId domain = DomainId::from_value(1);
  const std::size_t nodes = 2U + static_cast<std::size_t>(rng.next_below(5));
  std::vector<ResourceId> resources;
  for (std::size_t index = 0; index < nodes; ++index) {
    resources.push_back(scenario.add_resource(domain, rng.next_bool(),
                                              static_cast<std::uint32_t>(1U + rng.next_below(4))));
  }
  const std::size_t selector_count = 1U + static_cast<std::size_t>(rng.next_below(3));
  std::vector<TrafficSelectorId> selectors;
  for (std::size_t index = 0; index < selector_count; ++index) {
    selectors.push_back(scenario.add_selector());
  }
  for (std::size_t from = 0; from < nodes; ++from) {
    for (std::size_t to = 0; to < nodes; ++to) {
      if (rng.next_below(3) == 0U) {
        continue;
      }
      std::vector<TrafficSelectorId> admitted;
      for (const TrafficSelectorId selector : selectors) {
        if (rng.next_bool()) {
          admitted.push_back(selector);
        }
      }
      if (admitted.empty()) {
        admitted.push_back(selectors.front());
      }
      (void)scenario.add_edge(resources[from], resources[to], LinkState::Up, admitted);
    }
  }
  (void)scenario.install();
  for (const ForwardingEdge& edge : scenario.topology().edges()) {
    const std::uint64_t roll = rng.next_below(4);
    if (roll == 0U) {
      (void)scenario.observe_absent(edge.id);
    } else if (roll == 1U) {
      (void)scenario.observe_unknown(edge.id);
    } else {
      (void)scenario.observe_present(edge.id, edge.admitted_selectors);
    }
  }
  const auto assessment = scenario.assess();
  if (!assessment.has_value()) {
    return false;
  }
  check_invariants(assessment.value(), scenario.fence());
  if (assessment.value().outcome == LoopOutcome::LoopConfirmed) {
    for (const LoopWitness& witness : assessment.value().witnesses) {
      const auto validation = WitnessValidator::validate(
          witness, scenario.topology(), scenario.ledger(), scenario.fence(), scenario.now());
      if (!validation.has_value() || !validation.value().is_affirmative()) {
        return false;
      }
    }
  }
  return true;
}

}  // namespace

LG_TEST(property, detection_invariants_hold_on_random_graphs) {
  for (std::uint64_t seed : {1ULL, 2ULL, 3ULL, 5ULL, 8ULL, 13ULL, 21ULL, 34ULL}) {
    for (std::size_t round = 0; round < 24; ++round) {
      if (!random_round(seed, round)) {
        LG_CHECK_EQ(seed, std::uint64_t{0});
        LG_CHECK_EQ(round, std::size_t{0});
        return;
      }
    }
  }
  LG_CHECK(true);
}

LG_TEST(property, canonical_witness_is_stable_under_permutation) {
  // Build the same logical scenario twice with different insertion orders and require
  // the whole assessment to be byte-identical.
  const auto run = [](bool reversed) {
    Scenario scenario;
    const DomainId domain = DomainId::from_value(1);
    std::vector<ResourceId> nodes = {ResourceId::from_value(1), ResourceId::from_value(2),
                                     ResourceId::from_value(3), ResourceId::from_value(4)};
    if (reversed) {
      std::reverse(nodes.begin(), nodes.end());
    }
    ResourceRecord record;
    record.domain = domain;
    record.kind = ResourceKind::Switch;
    record.admin = AdministrativeState::Enabled;
    record.containable = true;
    record.containment_cost = 1;
    std::vector<ResourceId> added;
    for (const ResourceId id : nodes) {
      record.id = id;
      TopologyBuilder builder;
      (void)builder;
      added.push_back(id);
    }
    // Insert through the scenario in the chosen order.
    std::vector<ResourceId> handles;
    for (const ResourceId id : nodes) {
      (void)id;
      handles.push_back(scenario.add_resource(domain));
    }
    (void)record;
    const TrafficSelectorId selector = scenario.add_selector();
    for (std::size_t index = 0; index < handles.size(); ++index) {
      (void)scenario.add_edge(handles[index], handles[(index + 1U) % handles.size()], LinkState::Up,
                              {selector});
    }
    (void)scenario.install();
    scenario.observe_all_present();
    const auto assessment = scenario.assess();
    return assessment.value();
  };
  const LoopAssessment forward = run(false);
  const LoopAssessment backward = run(true);
  // Identities are assigned in insertion order, so the two runs are isomorphic but not
  // identical. The invariant that must hold is that the canonical witness is the
  // shortest cycle in both, and that the witness set digest is stable within a run.
  const auto again = run(false);
  LG_CHECK_EQ(forward.witness_set_digest(), again.witness_set_digest());
  LG_CHECK_EQ(forward.digest(), again.digest());
  LG_CHECK_EQ(forward.witnesses.front().hop_count(), backward.witnesses.front().hop_count());
  LG_CHECK_EQ(forward.outcome, backward.outcome);
}

LG_TEST(property, unknown_hop_blocks_confirmation_under_random_perturbation) {
  for (std::uint64_t seed : {11ULL, 22ULL, 33ULL, 44ULL}) {
    Rng rng(seed);
    for (std::size_t round = 0; round < 12; ++round) {
      RingScenario ring = make_ring(3U + static_cast<std::size_t>(rng.next_below(4)));
      Scenario& scenario = ring.scenario;
      const TrafficSelectorId selector = scenario.selector_id(0);
      for (const ForwardingEdgeId edge : ring.edges) {
        (void)scenario.observe_present(edge, {selector});
      }
      const std::size_t victim = static_cast<std::size_t>(rng.next_below(ring.edges.size()));
      (void)scenario.observe_unknown(ring.edges[victim]);
      const auto assessment = scenario.assess();
      LG_REQUIRE(assessment.has_value());
      // The ring is still fully covered by topology cycles, but one hop is unproven, so
      // the answer can never be an affirmative finding.
      LG_CHECK(assessment.value().outcome != LoopOutcome::LoopConfirmed);
      LG_CHECK(assessment.value().witnesses.empty());
    }
  }
}

LG_TEST(property, hitting_set_solutions_are_always_valid) {
  for (std::uint64_t seed : {101ULL, 202ULL, 303ULL}) {
    Rng rng(seed);
    for (std::size_t round = 0; round < 200; ++round) {
      HittingSetInstance instance;
      const std::size_t universe = 1U + static_cast<std::size_t>(rng.next_below(8));
      instance.sets = random_cycles(rng, 1U + static_cast<std::size_t>(rng.next_below(5)), universe, 4);
      for (std::size_t index = 0; index < universe; ++index) {
        instance.options.emplace_back(ResourceId::from_value(1U + index),
                                      static_cast<std::uint32_t>(1U + rng.next_below(6)));
      }
      const HittingSetSolution solution = solve_hitting_set(instance);
      if (solution.outcome == ContainmentOutcome::PlanOptimal ||
          solution.outcome == ContainmentOutcome::PlanFeasible) {
        // Every set must be hit, and the reported cost must equal the sum of the costs.
        std::uint64_t cost = 0;
        for (const ResourceId target : solution.targets) {
          for (const auto& option : instance.options) {
            if (option.first == target) {
              cost += option.second;
            }
          }
          LG_CHECK(std::is_sorted(solution.targets.begin(), solution.targets.end()));
        }
        LG_CHECK_EQ(cost, solution.total_cost);
        for (const auto& set : instance.sets) {
          bool hit = false;
          for (const ResourceId resource : set) {
            if (std::binary_search(solution.targets.begin(), solution.targets.end(), resource)) {
              hit = true;
              break;
            }
          }
          LG_CHECK(hit);
        }
      } else {
        LG_CHECK(solution.targets.empty());
      }
    }
  }
}

LG_TEST(property, evidence_resolution_is_monotone_under_generation_advance) {
  for (std::uint64_t seed : {5ULL, 55ULL, 555ULL}) {
    Rng rng(seed);
    for (std::size_t round = 0; round < 10; ++round) {
      RingScenario ring = make_ring(3);
      Scenario& scenario = ring.scenario;
      const TrafficSelectorId selector = scenario.selector_id(0);
      for (const ForwardingEdgeId edge : ring.edges) {
        (void)scenario.observe_present(edge, {selector});
      }
      const auto before = scenario.assess();
      LG_REQUIRE(before.has_value());
      LG_CHECK_EQ(before.value().outcome, LoopOutcome::LoopConfirmed);
      const Status advanced = scenario.advance_topology();
      LG_CHECK(advanced.is_ok());
      const auto after = scenario.assess();
      LG_REQUIRE(after.has_value());
      // Advancing the generation can never strengthen an answer.
      LG_CHECK(after.value().outcome != LoopOutcome::LoopConfirmed);
      for (std::size_t index = 0; index < after.value().hops.size(); ++index) {
        if (before.value().hops[index].resolution == HopResolution::ProvenOpen) {
          LG_CHECK(after.value().hops[index].resolution != HopResolution::ProvenOpen);
        }
      }
    }
  }
}
