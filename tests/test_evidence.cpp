#include "fixtures.hpp"
#include "harness.hpp"

namespace {

using namespace lg_test;
using namespace loop_guard;

struct Pair {
  Scenario scenario;
  ForwardingEdgeId first;
  ForwardingEdgeId second;
  TrafficSelectorId selector;
};

Pair make_pair() {
  Pair pair;
  const DomainId domain = DomainId::from_value(1);
  const ResourceId a = pair.scenario.add_resource(domain);
  const ResourceId b = pair.scenario.add_resource(domain);
  pair.selector = pair.scenario.add_selector();
  pair.first = pair.scenario.add_edge(a, b, LinkState::Up, {pair.selector});
  pair.second = pair.scenario.add_edge(b, a, LinkState::Up, {pair.selector});
  (void)pair.scenario.install();
  return pair;
}

}  // namespace

LG_TEST(evidence, submission_validates_structure) {
  Pair pair = make_pair();
  Scenario& scenario = pair.scenario;

  ForwardingObservation bad = ForwardingObservation{};
  LG_CHECK_EQ(scenario.ledger().submit(bad).outcome(), Outcome::Invalid);

  ForwardingObservation present;
  present.id = ObservationId::from_value(1);
  present.edge = pair.first;
  present.from = ResourceId::from_value(1);
  present.to = ResourceId::from_value(2);
  present.domain = DomainId::from_value(1);
  present.klass = EvidenceClass::Present;
  present.topology_generation = scenario.fence().topology;
  present.forwarding_generation = scenario.fence().forwarding;
  present.producer = scenario.producer();
  present.sequence = ProducerSequence::from_value(1);
  present.lease.boot = scenario.fence().boot;
  present.lease.epoch = scenario.fence().epoch;
  present.lease.fabric_epoch = scenario.fence().fabric_epoch;
  present.lease.valid_from = 0;
  present.lease.valid_until = 1000;
  LG_CHECK_EQ(scenario.ledger().submit(present).outcome(), Outcome::Invalid);  // Present without selectors

  present.selectors = {pair.selector};
  LG_CHECK(scenario.ledger().submit(present).is_ok());
  LG_CHECK_EQ(scenario.ledger().submit(present).outcome(), Outcome::AlreadyExists);

  present.id = ObservationId::from_value(2);
  present.sequence = ProducerSequence::from_value(1);
  LG_CHECK_EQ(scenario.ledger().submit(present).outcome(), Outcome::Stale);

  present.id = ObservationId::from_value(3);
  present.sequence = ProducerSequence::from_value(3);
  present.selectors = {pair.selector, pair.selector};
  LG_CHECK_EQ(scenario.ledger().submit(present).outcome(), Outcome::Invalid);

  present.selectors = {};
  present.klass = EvidenceClass::Unknown;
  LG_CHECK(scenario.ledger().submit(present).is_ok());
  present.id = ObservationId::from_value(4);
  present.klass = EvidenceClass::Present;
  LG_CHECK_EQ(scenario.ledger().submit(present).outcome(), Outcome::Invalid);
}

LG_TEST(evidence, binding_classification_is_total) {
  Pair pair = make_pair();
  Scenario& scenario = pair.scenario;

  auto resolved = [&](std::size_t edge_index) {
    auto result = scenario.ledger().resolve(scenario.topology(), edge_index, scenario.fence(),
                                            scenario.now());
    LG_REQUIRE(result.has_value());
    return result.value();
  };

  const std::size_t first_index = *scenario.topology().edge_index(pair.first);
  LG_CHECK_EQ(resolved(first_index).resolution, HopResolution::Unproven);
  LG_CHECK_EQ(resolved(first_index).binding, EvidenceBinding::NoEvidence);

  // Wrong topology generation: not usable evidence.
  (void)scenario.observe(pair.first, EvidenceClass::Present, {pair.selector},
                         TopologyGeneration::from_value(99));
  LG_CHECK_EQ(resolved(first_index).resolution, HopResolution::UnprovenOpen);
  LG_CHECK_EQ(resolved(first_index).binding, EvidenceBinding::GenerationMismatch);

  // Wrong boot: epoch fenced, which outranks a generation mismatch in the narrative.
  (void)scenario.observe(pair.first, EvidenceClass::Absent, {}, TopologyGeneration{},
                         ForwardingGeneration{}, 0, 1000000, BootId::from_value(77));
  LG_CHECK_EQ(resolved(first_index).binding, EvidenceBinding::EpochFenced);

  // Exactly bound evidence now determines the hop.
  (void)scenario.observe(pair.first, EvidenceClass::Present, {pair.selector});
  const HopResolutionRecord record = resolved(first_index);
  LG_CHECK_EQ(record.resolution, HopResolution::ProvenOpen);
  LG_CHECK_EQ(record.binding, EvidenceBinding::Exact);
  LG_CHECK_EQ(record.effective_selectors.size(), std::size_t{1});

  // Exact absence wins over the earlier unproven presence and closes the hop.
  (void)scenario.observe(pair.first, EvidenceClass::Absent, {});
  LG_CHECK_EQ(resolved(first_index).resolution, HopResolution::ProvenClosed);
}

LG_TEST(evidence, conflicting_exact_evidence_is_conflict) {
  Pair pair = make_pair();
  Scenario& scenario = pair.scenario;
  (void)scenario.observe(pair.first, EvidenceClass::Present, {pair.selector});
  (void)scenario.observe(pair.first, EvidenceClass::Present, {pair.selector},
                         TopologyGeneration{}, ForwardingGeneration{}, 0, 1000000, BootId{},
                         CoordinatorEpoch{}, FabricEpoch{}, ProducerId::from_value(9999));
  (void)scenario.observe(pair.first, EvidenceClass::Absent, {}, TopologyGeneration{},
                         ForwardingGeneration{}, 0, 1000000, BootId{},
                         CoordinatorEpoch{}, FabricEpoch{}, ProducerId::from_value(8888));
  const std::size_t index = *scenario.topology().edge_index(pair.first);
  auto record = scenario.ledger().resolve(scenario.topology(), index, scenario.fence(),
                                          scenario.now());
  LG_REQUIRE(record.has_value());
  LG_CHECK_EQ(record.value().resolution, HopResolution::Conflicted);
  LG_CHECK(record.value().note.contains(ReasonCode::HopConflictsWithItself));
}

LG_TEST(evidence, lease_expiry_downgrades_to_unproven) {
  Pair pair = make_pair();
  Scenario& scenario = pair.scenario;
  (void)scenario.observe(pair.first, EvidenceClass::Present, {pair.selector},
                         TopologyGeneration{}, ForwardingGeneration{}, 0, 50);
  const std::size_t index = *scenario.topology().edge_index(pair.first);
  auto fresh = scenario.ledger().resolve(scenario.topology(), index, scenario.fence(), 10);
  LG_REQUIRE(fresh.has_value());
  LG_CHECK_EQ(fresh.value().resolution, HopResolution::ProvenOpen);
  auto expired = scenario.ledger().resolve(scenario.topology(), index, scenario.fence(), 5000);
  LG_REQUIRE(expired.has_value());
  LG_CHECK_EQ(expired.value().resolution, HopResolution::UnprovenOpen);
  LG_CHECK_EQ(expired.value().binding, EvidenceBinding::LeaseExpired);
}

LG_TEST(evidence, superseded_observations_do_not_prove_openness) {
  Pair pair = make_pair();
  Scenario& scenario = pair.scenario;
  (void)scenario.observe(pair.first, EvidenceClass::Present, {pair.selector});
  // A later statement from the same producer that says nothing replaces the old one.
  (void)scenario.observe(pair.first, EvidenceClass::Unknown, {});
  const std::size_t index = *scenario.topology().edge_index(pair.first);
  auto record = scenario.ledger().resolve(scenario.topology(), index, scenario.fence(),
                                          scenario.now());
  LG_REQUIRE(record.has_value());
  LG_CHECK_EQ(record.value().resolution, HopResolution::Unproven);
  LG_CHECK_EQ(record.value().binding, EvidenceBinding::Superseded);
}

LG_TEST(evidence, definition_closes_hop_without_observation) {
  Scenario scenario;
  const DomainId domain = DomainId::from_value(1);
  const ResourceId a = scenario.add_resource(domain);
  const ResourceId b = scenario.add_resource(domain);
  const TrafficSelectorId selector = scenario.add_selector();
  const ForwardingEdgeId edge = scenario.add_edge(a, b, LinkState::Down, {selector});
  (void)scenario.install();
  const std::size_t index = *scenario.topology().edge_index(edge);
  auto record = scenario.ledger().resolve(scenario.topology(), index, scenario.fence(),
                                          scenario.now());
  LG_REQUIRE(record.has_value());
  LG_CHECK_EQ(record.value().resolution, HopResolution::ProvenClosed);
  LG_CHECK(record.value().note.contains(ReasonCode::CycleBrokenByAbsentEvidence));

  Scenario disabled;
  const ResourceId down = disabled.add_resource(domain, true, 1, ResourceKind::Switch,
                                                AdministrativeState::Disabled);
  const ResourceId up = disabled.add_resource(domain);
  const TrafficSelectorId only = disabled.add_selector();
  const ForwardingEdgeId hop = disabled.add_edge(down, up, LinkState::Up, {only});
  (void)disabled.install();
  auto disabled_record = disabled.ledger().resolve(
      disabled.topology(), *disabled.topology().edge_index(hop), disabled.fence(), disabled.now());
  LG_REQUIRE(disabled_record.has_value());
  LG_CHECK_EQ(disabled_record.value().resolution, HopResolution::ProvenClosed);
}

LG_TEST(evidence, selector_intersection_with_definition) {
  Pair pair = make_pair();
  Scenario& scenario = pair.scenario;
  const TrafficSelectorId undeclared = TrafficSelectorId::from_value(4000);
  // The producer claims openness for a selector the edge does not admit.
  (void)scenario.observe(pair.first, EvidenceClass::Present, {undeclared});
  const std::size_t index = *scenario.topology().edge_index(pair.first);
  auto record = scenario.ledger().resolve(scenario.topology(), index, scenario.fence(),
                                          scenario.now());
  LG_REQUIRE(record.has_value());
  LG_CHECK_EQ(record.value().resolution, HopResolution::Unproven);
  LG_CHECK(record.value().note.contains(ReasonCode::WitnessSelectorNotAdmitted));
}

LG_TEST(evidence, per_edge_retention_is_bounded_and_counted) {
  Limits limits = default_limits();
  limits.max_observations_per_edge = 2;
  Scenario scenario;
  scenario.limits() = limits;
  const DomainId domain = DomainId::from_value(1);
  const ResourceId a = scenario.add_resource(domain);
  const ResourceId b = scenario.add_resource(domain);
  const TrafficSelectorId selector = scenario.add_selector();
  const ForwardingEdgeId edge = scenario.add_edge(a, b, LinkState::Up, {selector});
  (void)scenario.install();
  EvidenceLedger ledger(limits);
  for (std::uint64_t index = 1; index <= 5; ++index) {
    ForwardingObservation observation;
    observation.id = ObservationId::from_value(index);
    observation.edge = edge;
    observation.from = a;
    observation.to = b;
    observation.domain = domain;
    observation.klass = EvidenceClass::Present;
    observation.selectors = {selector};
    observation.topology_generation = scenario.fence().topology;
    observation.forwarding_generation = scenario.fence().forwarding;
    observation.producer = ProducerId::from_value(static_cast<std::uint64_t>(index));
    observation.sequence = ProducerSequence::from_value(1);
    observation.lease.boot = scenario.fence().boot;
    observation.lease.epoch = scenario.fence().epoch;
    observation.lease.fabric_epoch = scenario.fence().fabric_epoch;
    observation.lease.valid_until = 1000;
    LG_CHECK(ledger.submit(observation).is_ok());
  }
  LG_CHECK_EQ(ledger.observation_count_for_edge(edge), std::size_t{2});
  LG_CHECK_EQ(ledger.size(), std::size_t{2});
  LG_CHECK_EQ(ledger.stats().evicted, std::uint64_t{3});
}

LG_TEST(evidence, global_bound_refuses_rather_than_dropping) {
  Limits limits = default_limits();
  limits.max_observations = 2;
  EvidenceLedger ledger(limits);
  const auto make = [](std::uint64_t id) {
    ForwardingObservation observation;
    observation.id = ObservationId::from_value(id);
    observation.edge = ForwardingEdgeId::from_value(id);
    observation.from = ResourceId::from_value(1);
    observation.to = ResourceId::from_value(2);
    observation.domain = DomainId::from_value(1);
    observation.klass = EvidenceClass::Present;
    observation.selectors = {TrafficSelectorId::from_value(1)};
    observation.topology_generation = TopologyGeneration::from_value(1);
    observation.forwarding_generation = ForwardingGeneration::from_value(1);
    observation.producer = ProducerId::from_value(id);
    observation.sequence = ProducerSequence::from_value(1);
    observation.lease.boot = BootId::from_value(1);
    observation.lease.epoch = CoordinatorEpoch::from_value(1);
    observation.lease.fabric_epoch = FabricEpoch::from_value(1);
    observation.lease.valid_until = 1000;
    return observation;
  };
  LG_CHECK(ledger.submit(make(1)).is_ok());
  LG_CHECK(ledger.submit(make(2)).is_ok());
  LG_CHECK_EQ(ledger.submit(make(3)).outcome(), Outcome::Exhausted);
  LG_CHECK_EQ(ledger.size(), std::size_t{2});
  LG_CHECK(ledger.origin() == EvidenceOrigin::Synthetic);
  ledger.clear_dynamic_state();
  LG_CHECK(ledger.empty());
  LG_CHECK_EQ(ledger.digest(), observations_digest({}));
}

LG_TEST(evidence, origin_is_real_when_any_producer_is_real) {
  Pair pair = make_pair();
  Scenario& scenario = pair.scenario;
  (void)scenario.observe(pair.first, EvidenceClass::Present, {pair.selector},
                         TopologyGeneration{}, ForwardingGeneration{}, 0, 1000000, BootId{},
                         CoordinatorEpoch{}, FabricEpoch{}, ProducerId{}, EvidenceOrigin::Real);
  LG_CHECK(scenario.ledger().origin() == EvidenceOrigin::Real);
}
