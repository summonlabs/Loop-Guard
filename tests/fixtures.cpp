#include "fixtures.hpp"

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>

namespace lg_test {

using namespace loop_guard;

Scenario::Scenario()
    : fence_{TopologyGeneration::from_value(1), ForwardingGeneration::from_value(1),
             PolicyGeneration::from_value(1), FabricEpoch::from_value(1),
             CoordinatorEpoch::from_value(1), BootId::from_value(1)},
      producer_(ProducerId::from_value(4242)),
      sequence_(ProducerSequence::from_value(0)),
      next_observation_(ObservationId::from_value(0)),
      next_resource_(ResourceId::from_value(0)),
      next_edge_(ForwardingEdgeId::from_value(0)),
      next_selector_(TrafficSelectorId::from_value(0)) {}

ResourceId Scenario::add_resource(DomainId domain, bool containable, std::uint32_t cost,
                                  ResourceKind kind, AdministrativeState admin) {
  ResourceRecord record;
  record.id = ResourceId::from_value(next_resource_.value() + 1U);
  next_resource_ = record.id;
  record.domain = domain;
  record.kind = kind;
  record.admin = admin;
  record.containable = containable;
  record.containment_cost = cost;
  record.label = "r" + record.id.to_string();
  resources_.push_back(std::move(record));
  return resources_.back().id;
}

TrafficSelectorId Scenario::add_selector(TrafficSelectorKind kind) {
  TrafficSelector selector;
  selector.id = TrafficSelectorId::from_value(next_selector_.value() + 1U);
  next_selector_ = selector.id;
  selector.kind = kind;
  selector.label = "s" + selector.id.to_string();
  selectors_.push_back(std::move(selector));
  return selectors_.back().id;
}

ForwardingEdgeId Scenario::add_edge(ResourceId from, ResourceId to, LinkState link,
                                    std::vector<TrafficSelectorId> admitted) {
  ForwardingEdge edge;
  edge.id = ForwardingEdgeId::from_value(next_edge_.value() + 1U);
  next_edge_ = edge.id;
  edge.from = from;
  edge.to = to;
  edge.link = link;
  std::sort(admitted.begin(), admitted.end());
  admitted.erase(std::unique(admitted.begin(), admitted.end()), admitted.end());
  edge.admitted_selectors = std::move(admitted);
  const auto position =
      std::find_if(resources_.begin(), resources_.end(),
                   [from](const ResourceRecord& record) { return record.id == from; });
  edge.domain = position == resources_.end() ? DomainId::from_value(1) : position->domain;
  edges_.push_back(std::move(edge));
  return edges_.back().id;
}

void Scenario::adopt(TopologyDefinition topology) {
  topology_ = std::move(topology);
  fence_.topology = topology_.generation();
}

Status Scenario::install() {
  TopologyBuilder builder(limits_);
  builder.set_generation(fence_.topology);
  for (const TrafficSelector& selector : selectors_) {
    const Status status = builder.add_selector(selector);
    if (!status.is_ok()) {
      return status;
    }
  }
  for (const ResourceRecord& record : resources_) {
    const Status status = builder.add_resource(record);
    if (!status.is_ok()) {
      return status;
    }
  }
  for (const ForwardingEdge& edge : edges_) {
    const Status status = builder.add_edge(edge);
    if (!status.is_ok()) {
      return status;
    }
  }
  auto built = builder.build();
  if (!built.has_value()) {
    return Status::failure(built.outcome(), built.detail());
  }
  topology_ = std::move(built).value();
  return Status::ok();
}

Status Scenario::observe(ForwardingEdgeId edge, EvidenceClass klass,
                         std::vector<TrafficSelectorId> selectors,
                         TopologyGeneration topology_generation,
                         ForwardingGeneration forwarding_generation, Tick valid_from,
                         Tick valid_until, BootId boot, CoordinatorEpoch epoch, FabricEpoch fabric,
                         ProducerId producer, EvidenceOrigin origin) {
  const auto position =
      std::find_if(edges_.begin(), edges_.end(),
                   [edge](const ForwardingEdge& candidate) { return candidate.id == edge; });
  if (position == edges_.end()) {
    return Status::failure(Outcome::NotFound, "the fixture does not know this edge");
  }
  ForwardingObservation observation;
  observation.id = ObservationId::from_value(next_observation_.value() + 1U);
  next_observation_ = observation.id;
  observation.edge = edge;
  observation.from = position->from;
  observation.to = position->to;
  observation.domain = position->domain;
  observation.klass = klass;
  std::sort(selectors.begin(), selectors.end());
  observation.selectors = std::move(selectors);
  observation.topology_generation =
      topology_generation.valid() ? topology_generation : fence_.topology;
  observation.forwarding_generation =
      forwarding_generation.valid() ? forwarding_generation : fence_.forwarding;
  observation.producer = producer.valid() ? producer : producer_;
  observation.producer_kind = ProducerKind::SyntheticFixture;
  sequence_ = ProducerSequence::from_value(sequence_.value() + 1U);
  observation.sequence = sequence_;
  observation.origin = origin;
  observation.lease.boot = boot.valid() ? boot : fence_.boot;
  observation.lease.epoch = epoch.valid() ? epoch : fence_.epoch;
  observation.lease.fabric_epoch = fabric.valid() ? fabric : fence_.fabric_epoch;
  observation.lease.valid_from = valid_from;
  observation.lease.valid_until = valid_until;
  observation.payload_digest = sha256(std::string("synthetic-observation-") +
                                      observation.id.to_string());
  return ledger_.submit(observation);
}

Status Scenario::observe_present(ForwardingEdgeId edge, std::vector<TrafficSelectorId> selectors) {
  return observe(edge, EvidenceClass::Present, std::move(selectors));
}

Status Scenario::observe_absent(ForwardingEdgeId edge) {
  return observe(edge, EvidenceClass::Absent, {});
}

Status Scenario::observe_unknown(ForwardingEdgeId edge) {
  return observe(edge, EvidenceClass::Unknown, {});
}

ForwardingEdgeId Scenario::edge_id(std::size_t index) const { return edges_[index].id; }
ResourceId Scenario::resource_id(std::size_t index) const { return resources_[index].id; }
TrafficSelectorId Scenario::selector_id(std::size_t index) const { return selectors_[index].id; }

Result<LoopAssessment> Scenario::assess(Tick now) {
  DetectionRequest request;
  request.topology = &topology_;
  request.ledger = &ledger_;
  request.fence = fence_;
  request.now = now;
  const LoopDetector detector(limits_);
  return detector.assess(request);
}

Result<LoopAssessment> Scenario::assess() { return assess(now_); }

void Scenario::observe_all_present() {
  for (const ForwardingEdge& edge : topology_.edges()) {
    (void)observe_present(edge.id, edge.admitted_selectors);
  }
}

Status Scenario::advance_topology() {
  const auto next = fence_.topology.try_next();
  if (!next.has_value()) {
    return Status::failure(Outcome::Exhausted, "topology generation space is exhausted");
  }
  fence_.topology = *next;
  return install();
}

RingScenario make_ring(std::size_t nodes, std::size_t selectors, std::uint32_t cost) {
  RingScenario ring;
  const DomainId domain = DomainId::from_value(7);
  std::vector<TrafficSelectorId> admitted;
  for (std::size_t index = 0; index < selectors; ++index) {
    admitted.push_back(ring.scenario.add_selector());
  }
  for (std::size_t index = 0; index < nodes; ++index) {
    ring.resources.push_back(ring.scenario.add_resource(domain, true, cost));
  }
  for (std::size_t index = 0; index < nodes; ++index) {
    ring.edges.push_back(ring.scenario.add_edge(ring.resources[index],
                                                ring.resources[(index + 1U) % nodes],
                                                LinkState::Up, admitted));
  }
  (void)ring.scenario.install();
  return ring;
}

std::vector<std::vector<ResourceId>> random_cycles(Rng& rng, std::size_t set_count,
                                                   std::size_t universe, std::size_t max_size) {
  std::vector<std::vector<ResourceId>> sets;
  sets.reserve(set_count);
  for (std::size_t index = 0; index < set_count; ++index) {
    const std::size_t size = 1U + static_cast<std::size_t>(rng.next_below(max_size));
    std::vector<ResourceId> set;
    for (std::size_t element = 0; element < size; ++element) {
      set.push_back(ResourceId::from_value(1U + rng.next_below(universe)));
    }
    std::sort(set.begin(), set.end());
    set.erase(std::unique(set.begin(), set.end()), set.end());
    if (set.empty()) {
      set.push_back(ResourceId::from_value(1));
    }
    sets.push_back(std::move(set));
  }
  std::sort(sets.begin(), sets.end());
  return sets;
}

std::vector<std::pair<ResourceId, std::uint32_t>> random_options(Rng& rng, std::size_t count,
                                                                 std::uint32_t max_cost) {
  std::vector<std::pair<ResourceId, std::uint32_t>> options;
  for (std::size_t index = 0; index < count; ++index) {
    options.emplace_back(ResourceId::from_value(1U + index),
                         static_cast<std::uint32_t>(1U + rng.next_below(max_cost)));
  }
  std::sort(options.begin(), options.end());
  return options;
}

std::string scratch_path(const std::string& name) {
#ifdef LG_TEST_SCRATCH_DIR
  const std::string directory = LG_TEST_SCRATCH_DIR;
#else
  const std::string directory = "test-scratch";
#endif
  std::error_code error;
  std::filesystem::create_directories(directory, error);
  return directory + "/" + name;
}

void remove_scratch(const std::string& path) {
  std::error_code error;
  std::filesystem::remove(path, error);
}

std::vector<std::uint8_t> read_bytes(const std::string& path) {
  std::ifstream stream(path, std::ios::binary);
  if (!stream) {
    return {};
  }
  return std::vector<std::uint8_t>(std::istreambuf_iterator<char>(stream),
                                   std::istreambuf_iterator<char>());
}

void write_bytes(const std::string& path, const std::vector<std::uint8_t>& bytes) {
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  stream.write(reinterpret_cast<const char*>(bytes.data()),
               static_cast<std::streamsize>(bytes.size()));
}

}  // namespace lg_test
