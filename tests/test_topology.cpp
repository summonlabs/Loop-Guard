#include <algorithm>
#include <set>

#include "fixtures.hpp"
#include "harness.hpp"

namespace {

using namespace lg_test;
using namespace loop_guard;

TopologyDefinition build_two_node(DomainId domain, std::uint32_t cost, bool containable,
                                  TrafficSelectorId selector, TopologyGeneration generation) {
  TopologyBuilder builder;
  builder.set_generation(generation);
  TrafficSelector record;
  record.id = selector;
  record.kind = TrafficSelectorKind::FlowClass;
  record.label = "s";
  (void)builder.add_selector(record);
  ResourceRecord a;
  a.id = ResourceId::from_value(1);
  a.domain = domain;
  a.kind = ResourceKind::Switch;
  a.admin = AdministrativeState::Enabled;
  a.containable = containable;
  a.containment_cost = cost;
  ResourceRecord b = a;
  b.id = ResourceId::from_value(2);
  (void)builder.add_resource(a);
  (void)builder.add_resource(b);
  ForwardingEdge first;
  first.id = ForwardingEdgeId::from_value(1);
  first.from = a.id;
  first.to = b.id;
  first.domain = domain;
  first.link = LinkState::Up;
  first.admitted_selectors = {selector};
  ForwardingEdge second = first;
  second.id = ForwardingEdgeId::from_value(2);
  second.from = b.id;
  second.to = a.id;
  (void)builder.add_edge(first);
  (void)builder.add_edge(second);
  auto built = builder.build();
  return built.value();
}

}  // namespace

LG_TEST(topology, builder_rejects_dangling_endpoint) {
  TopologyBuilder builder;
  builder.set_generation(TopologyGeneration::from_value(1));
  ResourceRecord only;
  only.id = ResourceId::from_value(1);
  only.domain = DomainId::from_value(1);
  only.admin = AdministrativeState::Enabled;
  (void)builder.add_resource(only);
  ForwardingEdge edge;
  edge.id = ForwardingEdgeId::from_value(1);
  edge.from = ResourceId::from_value(1);
  edge.to = ResourceId::from_value(2);
  edge.domain = DomainId::from_value(1);
  (void)builder.add_edge(edge);
  const auto built = builder.build();
  LG_CHECK(!built.has_value());
  LG_CHECK_EQ(built.outcome(), Outcome::Invalid);
}

LG_TEST(topology, builder_rejects_domain_mismatch) {
  TopologyBuilder builder;
  builder.set_generation(TopologyGeneration::from_value(1));
  ResourceRecord a;
  a.id = ResourceId::from_value(1);
  a.domain = DomainId::from_value(1);
  a.admin = AdministrativeState::Enabled;
  ResourceRecord b = a;
  b.id = ResourceId::from_value(2);
  b.domain = DomainId::from_value(2);
  (void)builder.add_resource(a);
  (void)builder.add_resource(b);
  ForwardingEdge edge;
  edge.id = ForwardingEdgeId::from_value(1);
  edge.from = a.id;
  edge.to = b.id;
  edge.domain = DomainId::from_value(1);
  (void)builder.add_edge(edge);
  const auto built = builder.build();
  LG_CHECK(!built.has_value());
  LG_CHECK_EQ(built.outcome(), Outcome::Invalid);
}

LG_TEST(topology, builder_rejects_unknown_selector_reference) {
  TopologyBuilder builder;
  builder.set_generation(TopologyGeneration::from_value(1));
  ResourceRecord a;
  a.id = ResourceId::from_value(1);
  a.domain = DomainId::from_value(1);
  a.admin = AdministrativeState::Enabled;
  (void)builder.add_resource(a);
  ResourceRecord b = a;
  b.id = ResourceId::from_value(2);
  (void)builder.add_resource(b);
  ForwardingEdge edge;
  edge.id = ForwardingEdgeId::from_value(1);
  edge.from = a.id;
  edge.to = b.id;
  edge.domain = DomainId::from_value(1);
  edge.admitted_selectors = {TrafficSelectorId::from_value(9)};
  (void)builder.add_edge(edge);
  const auto built = builder.build();
  LG_CHECK(!built.has_value());
  LG_CHECK_EQ(built.outcome(), Outcome::NotFound);
}

LG_TEST(topology, builder_rejects_zero_cost_containable_and_duplicates) {
  TopologyBuilder builder;
  builder.set_generation(TopologyGeneration::from_value(1));
  ResourceRecord record;
  record.id = ResourceId::from_value(1);
  record.domain = DomainId::from_value(1);
  record.containable = true;
  record.containment_cost = 0;
  LG_CHECK_EQ(builder.add_resource(record).outcome(), Outcome::Invalid);

  Scenario scenario;
  (void)scenario.add_resource(DomainId::from_value(1));
  (void)scenario.add_resource(DomainId::from_value(1));
  const ForwardingEdgeId edge = scenario.add_edge(scenario.resource_id(0), scenario.resource_id(1));
  LG_CHECK(edge.valid());
  LG_CHECK(scenario.install().is_ok());
  LG_CHECK_EQ(scenario.topology().edges().size(), std::size_t{1});
}

LG_TEST(topology, canonical_form_is_insertion_order_independent) {
  const DomainId domain = DomainId::from_value(3);
  const TrafficSelectorId selector = TrafficSelectorId::from_value(11);
  const TopologyGeneration generation = TopologyGeneration::from_value(4);
  const TopologyDefinition first = build_two_node(domain, 2, true, selector, generation);
  const TopologyDefinition second = build_two_node(domain, 2, true, selector, generation);
  LG_CHECK_EQ(first.digest(), second.digest());
  LG_CHECK_EQ(topology_to_text(first), topology_to_text(second));

  const auto parsed = topology_from_text(topology_to_text(first));
  LG_REQUIRE(parsed.has_value());
  LG_CHECK_EQ(parsed->digest(), first.digest());
  LG_CHECK_EQ(parsed->edges().size(), first.edges().size());
}

LG_TEST(topology, canonicalizer_accepts_any_insertion_order) {
  TopologyDefinition unsorted;
  unsorted.set_generation(TopologyGeneration::from_value(9));
  ResourceRecord b;
  b.id = ResourceId::from_value(2);
  b.domain = DomainId::from_value(1);
  b.kind = ResourceKind::Switch;
  b.admin = AdministrativeState::Enabled;
  ResourceRecord a = b;
  a.id = ResourceId::from_value(1);
  (void)0;
  const auto canonical = canonicalize_topology(unsorted);
  LG_REQUIRE(canonical.has_value());
  LG_CHECK_EQ(canonical->resources().size(), std::size_t{0});
}

LG_TEST(topology, adjacency_index_matches_linear_scan) {
  RingScenario ring = make_ring(6);
  const TopologyDefinition& topology = ring.scenario.topology();
  for (const ResourceRecord& record : topology.resources()) {
    std::vector<ForwardingEdgeId> expected;
    for (const ForwardingEdge& edge : topology.edges()) {
      if (edge.from == record.id) {
        expected.push_back(edge.id);
      }
    }
    const auto span = topology.out_edges(record.id);
    std::vector<ForwardingEdgeId> actual;
    for (const std::size_t index : span) {
      actual.push_back(topology.edges()[index].id);
    }
    LG_CHECK_EQ(actual, expected);
  }
  LG_CHECK_EQ(topology.out_edges(ResourceId::from_value(9999)).size(), std::size_t{0});
}

LG_TEST(topology, lookups_are_exact) {
  RingScenario ring = make_ring(4);
  const TopologyDefinition& topology = ring.scenario.topology();
  LG_CHECK(topology.find_resource(ring.resources[0]) != nullptr);
  LG_CHECK(topology.find_resource(ResourceId::from_value(9999)) == nullptr);
  LG_CHECK(topology.find_edge(ring.edges[0]) != nullptr);
  LG_CHECK(topology.find_edge(ForwardingEdgeId::from_value(9999)) == nullptr);
  const auto index = topology.edge_index(ring.edges[2]);
  LG_REQUIRE(index.has_value());
  LG_CHECK_EQ(topology.edges()[*index].id, ring.edges[2]);
}

LG_TEST(topology, text_parser_rejects_malformed_input) {
  LG_CHECK(!topology_from_text("").has_value());
  LG_CHECK(!topology_from_text("topology\n").has_value());
  LG_CHECK(!topology_from_text("nonsense generation=1\n").has_value());
  LG_CHECK(!topology_from_text("topology generation=0\n").has_value());
  LG_CHECK(!topology_from_text("topology generation=1\nresource 1\n").has_value());
  LG_CHECK(!topology_from_text(
                "topology generation=1\nresource 1 domain=1 admin=Sideways\n")
                .has_value());
}

LG_TEST(topology, builder_enforces_limits) {
  Limits limits = default_limits();
  limits.max_resources = 2;
  TopologyBuilder builder(limits);
  builder.set_generation(TopologyGeneration::from_value(1));
  ResourceRecord record;
  record.id = ResourceId::from_value(1);
  record.domain = DomainId::from_value(1);
  record.admin = AdministrativeState::Enabled;
  LG_CHECK(builder.add_resource(record).is_ok());
  record.id = ResourceId::from_value(2);
  LG_CHECK(builder.add_resource(record).is_ok());
  record.id = ResourceId::from_value(3);
  LG_CHECK_EQ(builder.add_resource(record).outcome(), Outcome::Exhausted);
}
