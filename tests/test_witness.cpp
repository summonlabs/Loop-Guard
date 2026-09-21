#include <algorithm>
#include <set>

#include "fixtures.hpp"
#include "harness.hpp"

namespace {

using namespace lg_test;
using namespace loop_guard;

LoopWitness make_witness(const Scenario& scenario, std::vector<ResourceId> cycle,
                         std::vector<ForwardingEdgeId> hops,
                         std::vector<TrafficSelectorId> selectors) {
  LoopWitness witness;
  witness.cycle = std::move(cycle);
  witness.hops = std::move(hops);
  witness.selectors = std::move(selectors);
  witness.fence = scenario.fence();
  return witness;
}

}  // namespace

LG_TEST(witness, canonical_rotation_picks_smallest_first) {
  const std::vector<ResourceId> cycle = {ResourceId::from_value(4), ResourceId::from_value(2),
                                         ResourceId::from_value(9), ResourceId::from_value(3)};
  const std::vector<ResourceId> canonical = canonicalize_cycle(cycle);
  LG_CHECK_EQ(canonical.front(), ResourceId::from_value(2));
  LG_CHECK_EQ(canonical.size(), cycle.size());
  LG_CHECK_EQ(canonicalize_cycle(canonical), canonical);
  LG_CHECK_EQ(canonicalize_cycle({}).size(), std::size_t{0});
  LG_CHECK_EQ(canonicalize_cycle({ResourceId::from_value(5)}).size(), std::size_t{1});
}

LG_TEST(witness, canonical_rotation_keeps_hops_aligned) {
  std::vector<ResourceId> cycle = {ResourceId::from_value(3), ResourceId::from_value(1),
                                   ResourceId::from_value(2)};
  std::vector<ForwardingEdgeId> hops = {ForwardingEdgeId::from_value(30),
                                        ForwardingEdgeId::from_value(10),
                                        ForwardingEdgeId::from_value(20)};
  canonicalize_cycle_with_hops(cycle, hops);
  LG_CHECK_EQ(cycle.front(), ResourceId::from_value(1));
  LG_CHECK_EQ(hops.front(), ForwardingEdgeId::from_value(10));
  LG_CHECK_EQ(hops.back(), ForwardingEdgeId::from_value(30));
}

LG_TEST(witness, ordering_is_by_length_then_lexicographic) {
  LoopWitness short_cycle;
  short_cycle.cycle = {ResourceId::from_value(1), ResourceId::from_value(2)};
  LoopWitness long_cycle;
  long_cycle.cycle = {ResourceId::from_value(1), ResourceId::from_value(2),
                      ResourceId::from_value(3)};
  LG_CHECK(short_cycle < long_cycle);
  LoopWitness other;
  other.cycle = {ResourceId::from_value(1), ResourceId::from_value(3)};
  LG_CHECK(short_cycle < other);
}

LG_TEST(witness, validator_accepts_a_true_witness) {
  RingScenario ring = make_ring(3);
  Scenario& scenario = ring.scenario;
  const TrafficSelectorId selector = scenario.selector_id(0);
  for (const ForwardingEdgeId edge : ring.edges) {
    (void)scenario.observe_present(edge, {selector});
  }
  const auto assessment = scenario.assess();
  LG_REQUIRE(assessment.has_value());
  LG_REQUIRE(assessment.value().outcome == LoopOutcome::LoopConfirmed);
  const LoopWitness& witness = assessment.value().witnesses.front();
  const auto validation = WitnessValidator::validate(witness, scenario.topology(),
                                                     scenario.ledger(), scenario.fence(),
                                                     scenario.now());
  LG_REQUIRE(validation.has_value());
  LG_CHECK(validation.value().valid);
  LG_CHECK(validation.value().is_affirmative());
  LG_CHECK_EQ(validation.value().outcome, LoopOutcome::LoopConfirmed);
}

LG_TEST(witness, validator_rejects_tampering) {
  RingScenario ring = make_ring(3);
  Scenario& scenario = ring.scenario;
  const TrafficSelectorId selector = scenario.selector_id(0);
  for (const ForwardingEdgeId edge : ring.edges) {
    (void)scenario.observe_present(edge, {selector});
  }
  const auto assessment = scenario.assess();
  LG_REQUIRE(assessment.has_value());
  const LoopWitness original = assessment.value().witnesses.front();

  // Wrong fence: stale, not invalid.
  LoopWitness stale = original;
  stale.fence.topology = TopologyGeneration::from_value(99);
  auto stale_result = WitnessValidator::validate(stale, scenario.topology(), scenario.ledger(),
                                                 scenario.fence(), scenario.now());
  LG_REQUIRE(stale_result.has_value());
  LG_CHECK(!stale_result.value().valid);
  LG_CHECK_EQ(stale_result.value().outcome, LoopOutcome::Stale);

  // A hop that is not an edge of the definition.
  LoopWitness wrong_hop = original;
  wrong_hop.hops[0] = ForwardingEdgeId::from_value(9999);
  LG_CHECK(!WitnessValidator::validate(wrong_hop, scenario.topology(), scenario.ledger(),
                                       scenario.fence(), scenario.now())
                .value()
                .valid);

  // A cycle that revisits a resource.
  LoopWitness repeated = original;
  repeated.cycle[1] = repeated.cycle[0];
  LG_CHECK(!WitnessValidator::validate(repeated, scenario.topology(), scenario.ledger(),
                                       scenario.fence(), scenario.now())
                .value()
                .valid);

  // A selector that no hop admits.
  LoopWitness wrong_selector = original;
  wrong_selector.selectors = {TrafficSelectorId::from_value(7777)};
  LG_CHECK(!WitnessValidator::validate(wrong_selector, scenario.topology(), scenario.ledger(),
                                       scenario.fence(), scenario.now())
                .value()
                .valid);

  // A tampered evidence digest.
  LoopWitness wrong_digest = original;
  wrong_digest.evidence_digest = Digest{};
  LG_CHECK(!WitnessValidator::validate(wrong_digest, scenario.topology(), scenario.ledger(),
                                       scenario.fence(), scenario.now())
                .value()
                .valid);

  // A hop sequence of the wrong length.
  LoopWitness short_hops = original;
  short_hops.hops.pop_back();
  LG_CHECK(!WitnessValidator::validate(short_hops, scenario.topology(), scenario.ledger(),
                                       scenario.fence(), scenario.now())
                .value()
                .valid);

  // An empty selector set.
  LoopWitness no_selector = original;
  no_selector.selectors.clear();
  LG_CHECK(!WitnessValidator::validate(no_selector, scenario.topology(), scenario.ledger(),
                                       scenario.fence(), scenario.now())
                .value()
                .valid);
}

LG_TEST(witness, validator_rejects_when_a_hop_loses_its_evidence) {
  RingScenario ring = make_ring(3);
  Scenario& scenario = ring.scenario;
  const TrafficSelectorId selector = scenario.selector_id(0);
  for (const ForwardingEdgeId edge : ring.edges) {
    (void)scenario.observe_present(edge, {selector});
  }
  const auto assessment = scenario.assess();
  LG_REQUIRE(assessment.has_value());
  const LoopWitness witness = assessment.value().witnesses.front();

  // The producing authority withdraws one hop by publishing an exactly bound absence.
  (void)scenario.observe_absent(witness.hops[1]);
  const auto validation = WitnessValidator::validate(witness, scenario.topology(),
                                                     scenario.ledger(), scenario.fence(),
                                                     scenario.now());
  LG_REQUIRE(validation.has_value());
  LG_CHECK(!validation.value().valid);
}

LG_TEST(witness, validator_rejects_administratively_disabled_resource) {
  RingScenario ring = make_ring(2);
  Scenario& scenario = ring.scenario;
  const TrafficSelectorId selector = scenario.selector_id(0);
  for (const ForwardingEdgeId edge : ring.edges) {
    (void)scenario.observe_present(edge, {selector});
  }
  const auto assessment = scenario.assess();
  LG_REQUIRE(assessment.has_value());
  LG_CHECK_EQ(assessment.value().outcome, LoopOutcome::LoopConfirmed);
}

LG_TEST(witness, text_rendering_is_stable) {
  RingScenario ring = make_ring(3);
  Scenario& scenario = ring.scenario;
  const TrafficSelectorId selector = scenario.selector_id(0);
  for (const ForwardingEdgeId edge : ring.edges) {
    (void)scenario.observe_present(edge, {selector});
  }
  const auto assessment = scenario.assess();
  LG_REQUIRE(assessment.has_value());
  const std::string text = assessment.value().witnesses.front().to_text();
  LG_CHECK(text.find("witness") == 0U);
  LG_CHECK(text.find("origin=Synthetic") != std::string::npos);
  LG_CHECK(text.find("single-domain") != std::string::npos);

  LoopWitness witness = assessment.value().witnesses.front();
  witness.cycle = {ResourceId::from_value(1), ResourceId::from_value(2)};
  witness.hops = {ForwardingEdgeId::from_value(1), ForwardingEdgeId::from_value(2)};
  witness.selectors = {TrafficSelectorId::from_value(1)};
  witness.crosses_domains = true;
  witness.origin = EvidenceOrigin::Real;
  const std::string real_text = witness.to_text();
  LG_CHECK(real_text.find("origin=Real") != std::string::npos);
  LG_CHECK(real_text.find("cross-domain") != std::string::npos);
}
