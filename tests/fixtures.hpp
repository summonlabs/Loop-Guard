// Loop Guard - deterministic synthetic fixtures.
//
// Every artifact produced here is labelled SYNTHETIC. These fixtures exercise the
// runtime deterministically in-process; they are not evidence about any real switch,
// NIC, RDMA fabric or multi-node deployment, and no test claims otherwise.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "loop_guard/core.hpp"
#include "loop_guard/detect.hpp"
#include "loop_guard/evidence.hpp"
#include "loop_guard/id.hpp"
#include "loop_guard/limits.hpp"
#include "loop_guard/result.hpp"
#include "loop_guard/runtime.hpp"
#include "loop_guard/topology.hpp"

namespace lg_test {

// Explicit, narrow imports: the fixture header never re-exports the whole namespace.
using loop_guard::AdministrativeState;
using loop_guard::BootId;
using loop_guard::CoordinatorEpoch;
using loop_guard::Digest;
using loop_guard::DomainId;
using loop_guard::EvidenceClass;
using loop_guard::EvidenceLedger;
using loop_guard::EvidenceOrigin;
using loop_guard::FabricEpoch;
using loop_guard::FenceVector;
using loop_guard::ForwardingEdge;
using loop_guard::ForwardingEdgeId;
using loop_guard::ForwardingGeneration;
using loop_guard::ForwardingObservation;
using loop_guard::Limits;
using loop_guard::LinkState;
using loop_guard::LoopAssessment;
using loop_guard::ObservationId;
using loop_guard::ProducerId;
using loop_guard::ProducerSequence;
using loop_guard::ResourceId;
using loop_guard::ResourceKind;
using loop_guard::ResourceRecord;
using loop_guard::Result;
using loop_guard::Rng;
using loop_guard::Status;
using loop_guard::Tick;
using loop_guard::TopologyBuilder;
using loop_guard::TopologyDefinition;
using loop_guard::TopologyGeneration;
using loop_guard::TrafficSelector;
using loop_guard::TrafficSelectorId;
using loop_guard::TrafficSelectorKind;

/// A scriptable synthetic scenario: resources, edges, selectors, evidence and a fence.
class Scenario {
 public:
  Scenario();

  [[nodiscard]] FenceVector& fence() { return fence_; }
  [[nodiscard]] const FenceVector& fence() const { return fence_; }
  [[nodiscard]] Tick& now() { return now_; }
  [[nodiscard]] Limits& limits() { return limits_; }
  [[nodiscard]] const Limits& limits() const { return limits_; }
  [[nodiscard]] EvidenceLedger& ledger() { return ledger_; }
  [[nodiscard]] const EvidenceLedger& ledger() const { return ledger_; }
  [[nodiscard]] ProducerId producer() const { return producer_; }

  ResourceId add_resource(DomainId domain, bool containable = true, std::uint32_t cost = 1,
                          ResourceKind kind = ResourceKind::Switch,
                          AdministrativeState admin = AdministrativeState::Enabled);
  TrafficSelectorId add_selector(TrafficSelectorKind kind = TrafficSelectorKind::FlowClass);
  ForwardingEdgeId add_edge(ResourceId from, ResourceId to, LinkState link = LinkState::Up,
                            std::vector<TrafficSelectorId> admitted = {});

  /// Adopts an explicit topology (its generation must equal the fence's topology generation).
  void adopt(TopologyDefinition topology);

  /// Builds and installs the topology collected so far.
  [[nodiscard]] Status install();
  [[nodiscard]] const TopologyDefinition& topology() const { return topology_; }

  /// Submits an observation with a fresh identity and a monotonic producer sequence.
  Status observe(ForwardingEdgeId edge, EvidenceClass klass,
                 std::vector<TrafficSelectorId> selectors = {},
                 TopologyGeneration topology_generation = TopologyGeneration{},
                 ForwardingGeneration forwarding_generation = ForwardingGeneration{},
                 Tick valid_from = 0, Tick valid_until = 1000000, BootId boot = BootId{},
                 CoordinatorEpoch epoch = CoordinatorEpoch{}, FabricEpoch fabric = FabricEpoch{},
                 ProducerId producer = ProducerId{}, EvidenceOrigin origin = EvidenceOrigin::Synthetic);

  /// Convenience helpers.
  Status observe_present(ForwardingEdgeId edge, std::vector<TrafficSelectorId> selectors);
  Status observe_absent(ForwardingEdgeId edge);
  Status observe_unknown(ForwardingEdgeId edge);

  [[nodiscard]] ForwardingEdgeId edge_id(std::size_t index) const;
  [[nodiscard]] ResourceId resource_id(std::size_t index) const;
  [[nodiscard]] TrafficSelectorId selector_id(std::size_t index) const;
  [[nodiscard]] std::size_t resource_count() const { return resources_.size(); }
  [[nodiscard]] std::size_t edge_count() const { return edges_.size(); }
  [[nodiscard]] std::size_t selector_count() const { return selectors_.size(); }

  [[nodiscard]] Result<LoopAssessment> assess(Tick now);
  [[nodiscard]] Result<LoopAssessment> assess();

  /// Submits PRESENT evidence for every edge of the topology, for every admitted selector.
  void observe_all_present();

  /// Advances to a fresh topology generation and reinstalls the same definition.
  Status advance_topology();

 private:
  FenceVector fence_;
  Tick now_ = 100;
  Limits limits_;
  std::vector<ResourceRecord> resources_;
  std::vector<ForwardingEdge> edges_;
  std::vector<TrafficSelector> selectors_;
  TopologyDefinition topology_;
  EvidenceLedger ledger_;
  ProducerId producer_;
  ProducerSequence sequence_;
  ObservationId next_observation_;
  ResourceId next_resource_;
  ForwardingEdgeId next_edge_;
  TrafficSelectorId next_selector_;
};

/// Generates a deterministic ring topology of \p nodes resources with \p selectors
/// selectors, and returns the scenario plus the ring edges in order.
struct RingScenario {
  Scenario scenario;
  std::vector<ResourceId> resources;
  std::vector<ForwardingEdgeId> edges;
};

[[nodiscard]] RingScenario make_ring(std::size_t nodes, std::size_t selectors = 1,
                                     std::uint32_t cost = 1);

/// A deterministic pseudo-random generator wrapper used by the property suites.
[[nodiscard]] std::vector<std::vector<loop_guard::ResourceId>> random_cycles(
    loop_guard::Rng& rng, std::size_t set_count, std::size_t universe, std::size_t max_size);
[[nodiscard]] std::vector<std::pair<loop_guard::ResourceId, std::uint32_t>> random_options(
    loop_guard::Rng& rng, std::size_t count, std::uint32_t max_cost);

/// Builds a fresh temporary path inside the configured scratch directory. The path is
/// removed by the caller; the helper never leaves debris behind.
[[nodiscard]] std::string scratch_path(const std::string& name);
/// Removes a scratch file if it exists.
void remove_scratch(const std::string& path);
/// Reads a file as bytes, or returns an empty vector.
[[nodiscard]] std::vector<std::uint8_t> read_bytes(const std::string& path);
/// Writes bytes to a path, replacing it.
void write_bytes(const std::string& path, const std::vector<std::uint8_t>& bytes);

}  // namespace lg_test
