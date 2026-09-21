// Loop Guard tools - shared command line plumbing.
//
// The tools are deliberately thin: they translate command line input into library calls
// and library results into machine-readable lines. No authority decision is made here.
#pragma once

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "loop_guard/net.hpp"
#include "loop_guard/runtime.hpp"
#include "loop_guard/wire.hpp"

namespace lg_tool {

struct Args {
  std::map<std::string, std::string> options;
  std::vector<std::string> positional;

  [[nodiscard]] bool has(const std::string& name) const {
    return options.find(name) != options.end();
  }
  [[nodiscard]] std::string get(const std::string& name, const std::string& fallback = {}) const {
    const auto position = options.find(name);
    return position == options.end() ? fallback : position->second;
  }
  [[nodiscard]] std::uint64_t get_u64(const std::string& name, std::uint64_t fallback = 0) const {
    const auto position = options.find(name);
    if (position == options.end() || position->second.empty()) {
      return fallback;
    }
    return std::strtoull(position->second.c_str(), nullptr, 10);
  }
};

[[nodiscard]] inline Args parse_args(int argc, char** argv, int start) {
  Args args;
  for (int index = start; index < argc; ++index) {
    const std::string token = argv[index];
    if (token.rfind("--", 0) == 0) {
      const std::size_t equals = token.find('=');
      if (equals == std::string::npos) {
        args.options[token.substr(2)] = "";
      } else {
        args.options[token.substr(2, equals - 2)] = token.substr(equals + 1);
      }
    } else {
      args.positional.push_back(token);
    }
    (void)index;
  }
  return args;
}

/// Builds the default synthetic topology used by the tools: a directed ring of
/// \p nodes switches in one domain, all containable at cost 1, carrying one selector.
[[nodiscard]] inline loop_guard::TopologyDefinition synthetic_ring(std::size_t nodes,
                                                                  std::uint64_t generation) {
  using namespace loop_guard;
  TopologyBuilder builder;
  builder.set_generation(TopologyGeneration::from_value(generation));
  TrafficSelector selector;
  selector.id = TrafficSelectorId::from_value(1);
  selector.kind = TrafficSelectorKind::FlowClass;
  selector.label = "synthetic-flow";
  (void)builder.add_selector(selector);
  for (std::size_t index = 0; index < nodes; ++index) {
    ResourceRecord record;
    record.id = ResourceId::from_value(index + 1U);
    record.domain = DomainId::from_value(1);
    record.kind = ResourceKind::Switch;
    record.admin = AdministrativeState::Enabled;
    record.containable = true;
    record.containment_cost = 1;
    record.label = "synthetic-switch-" + record.id.to_string();
    (void)builder.add_resource(record);
  }
  for (std::size_t index = 0; index < nodes; ++index) {
    ForwardingEdge edge;
    edge.id = ForwardingEdgeId::from_value(index + 1U);
    edge.from = ResourceId::from_value(index + 1U);
    edge.to = ResourceId::from_value(((index + 1U) % nodes) + 1U);
    edge.domain = DomainId::from_value(1);
    edge.link = LinkState::Up;
    edge.admitted_selectors = {TrafficSelectorId::from_value(1)};
    (void)builder.add_edge(edge);
  }
  return builder.build().value();
}

[[nodiscard]] inline loop_guard::ContainmentPolicy synthetic_policy(std::uint64_t generation) {
  using namespace loop_guard;
  ContainmentPolicy policy;
  policy.generation = PolicyGeneration::from_value(generation);
  policy.max_targets = 4;
  policy.max_total_cost = 32;
  policy.eligible_kinds = {ResourceKind::Switch, ResourceKind::PortGroup,
                           ResourceKind::NextHopGroup};
  return policy;
}

/// Prints one machine-readable key=value line. Values are never quoted so that the
/// test harness can parse them without a parser of its own.
inline void report(const std::string& key, const std::string& value) {
  std::cout << key << "=" << value << "\n";
  std::cout.flush();
}

inline void report(const std::string& key, std::uint64_t value) {
  report(key, std::to_string(value));
}

/// Emits the forwarding observation that proves a hop present or absent.
[[nodiscard]] inline loop_guard::ForwardingObservation synthetic_observation(
    const loop_guard::TopologyDefinition& topology, loop_guard::ForwardingEdgeId edge,
    loop_guard::EvidenceClass klass, std::uint64_t observation_id, std::uint64_t producer,
    std::uint64_t sequence, const loop_guard::FenceVector& fence, loop_guard::ProducerKind kind,
    loop_guard::EvidenceOrigin origin) {
  using namespace loop_guard;
  ForwardingObservation observation;
  observation.id = ObservationId::from_value(observation_id);
  observation.edge = edge;
  const ForwardingEdge* record = topology.find_edge(edge);
  if (record != nullptr) {
    observation.from = record->from;
    observation.to = record->to;
    observation.domain = record->domain;
    if (klass == EvidenceClass::Present) {
      observation.selectors = record->admitted_selectors;
    }
  }
  observation.klass = klass;
  observation.topology_generation = fence.topology;
  observation.forwarding_generation = fence.forwarding;
  observation.producer = ProducerId::from_value(producer);
  observation.producer_kind = kind;
  observation.sequence = ProducerSequence::from_value(sequence);
  observation.origin = origin;
  observation.lease.boot = fence.boot;
  observation.lease.epoch = fence.epoch;
  observation.lease.fabric_epoch = fence.fabric_epoch;
  observation.lease.valid_from = 0;
  observation.lease.valid_until = 0xFFFF'FFFF'FFFF'FFFFULL;
  observation.payload_digest =
      sha256(std::string("tool-observation-") + std::to_string(observation_id));
  return observation;
}

}  // namespace lg_tool
