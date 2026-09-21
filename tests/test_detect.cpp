#include <algorithm>
#include <set>

#include "fixtures.hpp"
#include "harness.hpp"

namespace {

using namespace lg_test;
using namespace loop_guard;

/// A ring of \p nodes where every hop is observed exactly as asked.
struct EvidenceSpec {
  EvidenceClass klass = EvidenceClass::Present;
};

RingScenario make_observed_ring(std::size_t nodes, EvidenceClass klass) {
  RingScenario ring = make_ring(nodes);
  for (const ForwardingEdgeId edge : ring.edges) {
    if (klass == EvidenceClass::Present) {
      (void)ring.scenario.observe_present(edge, {ring.scenario.selector_id(0)});
    } else if (klass == EvidenceClass::Absent) {
      (void)ring.scenario.observe_absent(edge);
    } else {
      (void)ring.scenario.observe_unknown(edge);
    }
  }
  return ring;
}

}  // namespace

LG_TEST(detect, topology_cycle_without_forwarding_evidence_is_not_a_loop) {
  RingScenario ring = make_ring(4);
  const auto assessment = ring.scenario.assess();
  LG_REQUIRE(assessment.has_value());
  LG_CHECK_EQ(assessment.value().outcome, LoopOutcome::Unknown);
  LG_CHECK(!assessment.value().is_affirmative());
  LG_CHECK(assessment.value().witnesses.empty());
  LG_CHECK((assessment.value().flags & kAssessmentNoEvidenceAtAll) != 0U);
  LG_CHECK((assessment.value().flags & kAssessmentUnprovenHopsPresent) != 0U);
}

LG_TEST(detect, exactly_bound_open_evidence_confirms_the_loop) {
  RingScenario ring = make_observed_ring(4, EvidenceClass::Present);
  const auto assessment = ring.scenario.assess();
  LG_REQUIRE(assessment.has_value());
  LG_CHECK_EQ(assessment.value().outcome, LoopOutcome::LoopConfirmed);
  LG_REQUIRE(!assessment.value().witnesses.empty());
  const LoopWitness& witness = assessment.value().witnesses.front();
  LG_CHECK_EQ(witness.hop_count(), std::size_t{4});
  LG_CHECK_EQ(witness.selectors.size(), std::size_t{1});
  LG_CHECK(witness.fence == ring.scenario.fence());
  LG_CHECK_EQ(assessment.value().implicated_resources().size(), std::size_t{4});
  LG_CHECK_EQ(assessment.value().counters.witnesses_validated, std::uint64_t{1});
  LG_CHECK_EQ(assessment.value().counters.witnesses_rejected, std::uint64_t{0});
}

LG_TEST(detect, one_proven_closed_hop_proves_no_loop) {
  RingScenario ring = make_observed_ring(4, EvidenceClass::Present);
  (void)ring.scenario.observe_absent(ring.edges[2]);
  const auto assessment = ring.scenario.assess();
  LG_REQUIRE(assessment.has_value());
  LG_CHECK_EQ(assessment.value().outcome, LoopOutcome::NoLoop);
  LG_CHECK(assessment.value().witnesses.empty());
}

LG_TEST(detect, unknown_evidence_never_becomes_a_confirmed_loop) {
  RingScenario ring = make_observed_ring(3, EvidenceClass::Present);
  (void)ring.scenario.observe_unknown(ring.edges[1]);
  const auto assessment = ring.scenario.assess();
  LG_REQUIRE(assessment.has_value());
  LG_CHECK_EQ(assessment.value().outcome, LoopOutcome::Unknown);
  LG_CHECK(assessment.value().witnesses.empty());
  LG_CHECK(!assessment.value().is_affirmative());
}

LG_TEST(detect, conflicted_hop_yields_conflict) {
  RingScenario ring = make_ring(3);
  Scenario& scenario = ring.scenario;
  const TrafficSelectorId selector = scenario.selector_id(0);
  (void)scenario.observe_present(ring.edges[0], {selector});
  (void)scenario.observe_present(ring.edges[1], {selector});
  (void)scenario.observe_present(ring.edges[2], {selector});
  // A second authority contradicts the first at exactly the same generations.
  (void)scenario.observe(ring.edges[2], EvidenceClass::Absent, {}, TopologyGeneration{},
                         ForwardingGeneration{}, 0, 1000000, BootId{}, CoordinatorEpoch{},
                         FabricEpoch{}, ProducerId::from_value(9999));
  const auto assessment = scenario.assess();
  LG_REQUIRE(assessment.has_value());
  LG_CHECK_EQ(assessment.value().outcome, LoopOutcome::Conflict);
  LG_CHECK((assessment.value().flags & kAssessmentConflictsPresent) != 0U);
  LG_CHECK(assessment.value().witnesses.empty());
}

LG_TEST(detect, stale_evidence_does_not_confirm) {
  RingScenario ring = make_observed_ring(3, EvidenceClass::Present);
  Scenario& scenario = ring.scenario;
  const Status advanced = scenario.advance_topology();
  LG_CHECK(advanced.is_ok());
  const auto assessment = scenario.assess();
  LG_REQUIRE(assessment.has_value());
  LG_CHECK_EQ(assessment.value().outcome, LoopOutcome::Unknown);
  LG_CHECK((assessment.value().flags & kAssessmentStaleEvidencePresent) != 0U);
}

LG_TEST(detect, request_fence_must_match_the_definition) {
  RingScenario ring = make_observed_ring(3, EvidenceClass::Present);
  Scenario& scenario = ring.scenario;
  scenario.fence().topology = TopologyGeneration::from_value(9);
  const auto assessment = scenario.assess();
  LG_REQUIRE(assessment.has_value());
  LG_CHECK_EQ(assessment.value().outcome, LoopOutcome::Stale);
}

LG_TEST(detect, budget_exhaustion_yields_indeterminate_never_no_loop) {
  RingScenario ring = make_observed_ring(6, EvidenceClass::Present);
  Scenario& scenario = ring.scenario;
  scenario.limits().max_search_steps = 1;
  const auto assessment = scenario.assess();
  LG_REQUIRE(assessment.has_value());
  // The proof budget is one step, so cycle absence cannot be proved and a witness cannot
  // be enumerated either. The only honest answer is INDETERMINATE.
  LG_CHECK_EQ(assessment.value().outcome, LoopOutcome::Indeterminate);
  LG_CHECK((assessment.value().flags & kAssessmentSearchLimitReached) != 0U);
  LG_CHECK(assessment.value().witnesses.empty());
  LG_CHECK(!assessment.value().is_affirmative());
}

LG_TEST(detect, candidate_selector_ceiling_yields_indeterminate) {
  RingScenario ring = make_ring(3, 4);
  Scenario& scenario = ring.scenario;
  scenario.limits().max_candidate_selectors = 2;
  for (const ForwardingEdgeId edge : ring.edges) {
    (void)scenario.observe_present(
        edge, {scenario.selector_id(0), scenario.selector_id(1), scenario.selector_id(2),
               scenario.selector_id(3)});
  }
  const auto assessment = scenario.assess();
  LG_REQUIRE(assessment.has_value());
  LG_CHECK_EQ(assessment.value().outcome, LoopOutcome::Indeterminate);
  LG_CHECK((assessment.value().flags & kAssessmentSearchLimitReached) != 0U);
}

LG_TEST(detect, selector_scope_restriction_is_honoured) {
  RingScenario ring = make_observed_ring(3, EvidenceClass::Present);
  Scenario& scenario = ring.scenario;
  DetectionRequest request;
  request.topology = &scenario.topology();
  request.ledger = &scenario.ledger();
  request.fence = scenario.fence();
  request.now = scenario.now();
  request.selector_scope = {TrafficSelectorId::from_value(999)};
  const LoopDetector detector;
  const auto assessment = detector.assess(request);
  LG_REQUIRE(assessment.has_value());
  LG_CHECK_EQ(assessment.value().outcome, LoopOutcome::Invalid);
}

LG_TEST(detect, disjoint_selectors_prove_no_loop) {
  Scenario scenario;
  const DomainId domain = DomainId::from_value(1);
  const ResourceId a = scenario.add_resource(domain);
  const ResourceId b = scenario.add_resource(domain);
  const TrafficSelectorId first = scenario.add_selector();
  const TrafficSelectorId second = scenario.add_selector();
  (void)scenario.add_edge(a, b, LinkState::Up, {first});
  (void)scenario.add_edge(b, a, LinkState::Up, {second});
  (void)scenario.install();
  (void)scenario.observe_present(scenario.edge_id(0), {first});
  (void)scenario.observe_present(scenario.edge_id(1), {second});
  const auto assessment = scenario.assess();
  LG_REQUIRE(assessment.has_value());
  LG_CHECK_EQ(assessment.value().outcome, LoopOutcome::NoLoop);
}

LG_TEST(detect, self_loop_is_a_witness_of_length_one) {
  Scenario scenario;
  const DomainId domain = DomainId::from_value(1);
  const ResourceId a = scenario.add_resource(domain);
  const TrafficSelectorId selector = scenario.add_selector();
  (void)scenario.add_edge(a, a, LinkState::Up, {selector});
  (void)scenario.install();
  (void)scenario.observe_present(scenario.edge_id(0), {selector});
  const auto assessment = scenario.assess();
  LG_REQUIRE(assessment.has_value());
  LG_CHECK_EQ(assessment.value().outcome, LoopOutcome::LoopConfirmed);
  LG_REQUIRE(!assessment.value().witnesses.empty());
  LG_CHECK_EQ(assessment.value().witnesses.front().hop_count(), std::size_t{1});
}

LG_TEST(detect, canonical_witness_is_the_shortest_cycle) {
  // A 4-node ring plus a chord that creates a 3-cycle: the 3-cycle is canonical.
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
  const auto assessment = scenario.assess();
  LG_REQUIRE(assessment.has_value());
  LG_CHECK_EQ(assessment.value().outcome, LoopOutcome::LoopConfirmed);
  LG_REQUIRE(!assessment.value().witnesses.empty());
  LG_CHECK_EQ(assessment.value().witnesses.front().hop_count(), std::size_t{3});
  for (std::size_t index = 1; index < assessment.value().witnesses.size(); ++index) {
    LG_CHECK(!(assessment.value().witnesses[index] < assessment.value().witnesses.front()));
  }
}

LG_TEST(detect, harmless_cycles_in_a_dense_graph_prove_no_loop) {
  // A complete digraph on five resources has 84 simple cycles. One resource is proven
  // unable to forward, so no cycle survives: NO_LOOP, not a confirmed loop.
  Scenario scenario;
  const DomainId domain = DomainId::from_value(1);
  std::vector<ResourceId> nodes;
  for (int index = 0; index < 5; ++index) {
    nodes.push_back(scenario.add_resource(domain));
  }
  const TrafficSelectorId selector = scenario.add_selector();
  for (std::size_t from = 0; from < nodes.size(); ++from) {
    for (std::size_t to = 0; to < nodes.size(); ++to) {
      if (from != to) {
        (void)scenario.add_edge(nodes[from], nodes[to], LinkState::Up, {selector});
      }
    }
  }
  (void)scenario.install();
  scenario.observe_all_present();
  // Every hop whose source is not the first resource is proven closed. Many topology
  // cycles remain in the adjacency graph; none of them survives as a forwarding cycle.
  for (const ForwardingEdge& edge : scenario.topology().edges()) {
    if (!(edge.from == nodes.front())) {
      (void)scenario.observe_absent(edge.id);
    }
  }
  const auto assessment = scenario.assess();
  LG_REQUIRE(assessment.has_value());
  LG_CHECK_EQ(assessment.value().outcome, LoopOutcome::NoLoop);
  LG_CHECK(assessment.value().witnesses.empty());
  LG_CHECK(scenario.topology().edges().size() == 20U);
}

LG_TEST(detect, witness_set_is_insertion_order_independent) {
  // The permutation proof is driven through the public canonicalizer, which is the only
  // place insertion order could leak into an answer.
  const auto canonical_of = [](const std::vector<std::uint64_t>& order) {
    TopologyBuilder builder;
    builder.set_generation(TopologyGeneration::from_value(1));
    TrafficSelector selector;
    selector.id = TrafficSelectorId::from_value(1);
    (void)builder.add_selector(selector);
    for (const std::uint64_t id : order) {
      ResourceRecord record;
      record.id = ResourceId::from_value(id);
      record.domain = DomainId::from_value(1);
      record.kind = ResourceKind::Switch;
      record.admin = AdministrativeState::Enabled;
      record.containable = true;
      record.containment_cost = 1;
      (void)builder.add_resource(record);
    }
    for (const std::uint64_t id : order) {
      ForwardingEdge edge;
      edge.id = ForwardingEdgeId::from_value(100 + id);
      edge.from = ResourceId::from_value(id);
      edge.to = ResourceId::from_value((id % 4U) + 1U);
      edge.domain = DomainId::from_value(1);
      edge.link = LinkState::Up;
      edge.admitted_selectors = {TrafficSelectorId::from_value(1)};
      (void)builder.add_edge(edge);
    }
    return builder.build().value();
  };
  const TopologyDefinition forward = canonical_of({1, 2, 3, 4});
  const TopologyDefinition backward = canonical_of({4, 3, 2, 1});
  LG_CHECK_EQ(forward.digest(), backward.digest());
  LG_CHECK_EQ(topology_to_text(forward), topology_to_text(backward));
  LG_CHECK_EQ(forward.edges().size(), std::size_t{4});
}

LG_TEST(detect, empty_topology_is_trivially_no_loop) {
  Scenario scenario;
  (void)scenario.install();
  const auto assessment = scenario.assess();
  LG_REQUIRE(assessment.has_value());
  LG_CHECK_EQ(assessment.value().outcome, LoopOutcome::NoLoop);
}

LG_TEST(detect, assessment_is_deterministic_and_reproducible) {
  RingScenario first = make_observed_ring(4, EvidenceClass::Present);
  RingScenario second = make_observed_ring(4, EvidenceClass::Present);
  const auto left = first.scenario.assess();
  const auto right = second.scenario.assess();
  LG_REQUIRE(left.has_value() && right.has_value());
  LG_CHECK_EQ(left.value().outcome, right.value().outcome);
  LG_CHECK_EQ(left.value().witnesses.size(), right.value().witnesses.size());
  LG_CHECK_EQ(left.value().witness_set_digest(), right.value().witness_set_digest());
  LG_CHECK_EQ(left.value().digest(), right.value().digest());
  LG_CHECK_EQ(left.value().id, right.value().id);
}

LG_TEST(detect, overlapping_loops_are_all_reported) {
  // Two rings sharing one resource produce at least two distinct witnesses.
  Scenario scenario;
  const DomainId domain = DomainId::from_value(1);
  const ResourceId shared = scenario.add_resource(domain);
  const ResourceId left_a = scenario.add_resource(domain);
  const ResourceId left_b = scenario.add_resource(domain);
  const ResourceId right_a = scenario.add_resource(domain);
  const ResourceId right_b = scenario.add_resource(domain);
  const TrafficSelectorId selector = scenario.add_selector();
  const auto connect = [&](ResourceId from, ResourceId to) {
    (void)scenario.add_edge(from, to, LinkState::Up, {selector});
  };
  connect(shared, left_a);
  connect(left_a, left_b);
  connect(left_b, shared);
  connect(shared, right_a);
  connect(right_a, right_b);
  connect(right_b, shared);
  (void)scenario.install();
  scenario.observe_all_present();
  const auto assessment = scenario.assess();
  LG_REQUIRE(assessment.has_value());
  LG_CHECK_EQ(assessment.value().outcome, LoopOutcome::LoopConfirmed);
  LG_CHECK(assessment.value().witnesses.size() >= 2U);
  LG_CHECK_EQ(assessment.value().witnesses.front().hop_count(), std::size_t{3});
}
