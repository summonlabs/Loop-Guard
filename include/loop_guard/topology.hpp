// Loop Guard - governed topology definitions.
//
// A topology definition is the authoritative, generation-bearing description of the
// resources Loop Guard governs, the directed adjacencies between them and the traffic
// selectors each adjacency may carry. It is durable and survives restart because its
// semantics are definitions, not observations.
//
// A definition alone never proves a forwarding loop. It only states that an adjacency
// exists; whether traffic actually traverses it is a forwarding observation, which is
// dynamic and never restored across restart.
#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "loop_guard/core.hpp"
#include "loop_guard/digest.hpp"
#include "loop_guard/enums.hpp"
#include "loop_guard/id.hpp"
#include "loop_guard/limits.hpp"
#include "loop_guard/result.hpp"

namespace loop_guard {

/// One governed resource: a switch, a port group, a next-hop group, a tunnel endpoint,
/// a service-chain stage, a host interface or a virtual switch.
struct ResourceRecord {
  ResourceId id;
  DomainId domain;               ///< The governed forwarding domain this resource belongs to.
  ResourceKind kind = ResourceKind::Unsupported;
  AdministrativeState admin = AdministrativeState::Unknown;
  /// Policy eligibility predicate input. Eligibility is not authorization.
  bool containable = false;
  /// Cost class used by the containment objective. Must be >= 1 for containable resources.
  std::uint32_t containment_cost = 1;
  /// Diagnostic label. Never used for matching, ordering or authority.
  std::string label;

  friend bool operator==(const ResourceRecord&, const ResourceRecord&) noexcept = default;
  friend bool operator<(const ResourceRecord& lhs, const ResourceRecord& rhs) noexcept {
    return lhs.id < rhs.id;
  }
};

/// One directed adjacency in the governed topology.
struct ForwardingEdge {
  ForwardingEdgeId id;
  ResourceId from;
  ResourceId to;
  DomainId domain;               ///< Domain of the adjacency; must match the endpoints.
  LinkState link = LinkState::Unknown;
  /// Canonically sorted, duplicate-free selector set this adjacency may carry.
  std::vector<TrafficSelectorId> admitted_selectors;

  friend bool operator==(const ForwardingEdge&, const ForwardingEdge&) noexcept = default;
  /// Canonical order: (from, to, id). Two definitions that differ only in insertion
  /// order produce the same edge sequence.
  friend bool operator<(const ForwardingEdge& lhs, const ForwardingEdge& rhs) noexcept;
};

struct TrafficSelector {
  TrafficSelectorId id;
  TrafficSelectorKind kind = TrafficSelectorKind::FlowClass;
  std::string label;  ///< Diagnostic only.

  friend bool operator==(const TrafficSelector&, const TrafficSelector&) noexcept = default;
  friend bool operator<(const TrafficSelector& lhs, const TrafficSelector& rhs) noexcept {
    return lhs.id < rhs.id;
  }
};

/// An immutable, canonically ordered topology definition bound to one generation.
class TopologyDefinition {
 public:
  TopologyDefinition() = default;

  [[nodiscard]] TopologyGeneration generation() const noexcept { return generation_; }
  void set_generation(TopologyGeneration generation) noexcept { generation_ = generation; }

  [[nodiscard]] const std::vector<ResourceRecord>& resources() const noexcept { return resources_; }
  [[nodiscard]] const std::vector<ForwardingEdge>& edges() const noexcept { return edges_; }
  [[nodiscard]] const std::vector<TrafficSelector>& selectors() const noexcept { return selectors_; }

  [[nodiscard]] bool empty() const noexcept { return resources_.empty(); }

  [[nodiscard]] const ResourceRecord* find_resource(ResourceId id) const noexcept;
  [[nodiscard]] const ForwardingEdge* find_edge(ForwardingEdgeId id) const noexcept;
  [[nodiscard]] const TrafficSelector* find_selector(TrafficSelectorId id) const noexcept;
  /// Index of an edge in canonical order, or nullopt when absent.
  [[nodiscard]] std::optional<std::size_t> edge_index(ForwardingEdgeId id) const noexcept;

  /// Index of every edge whose source is \p from, in canonical edge order. The span is
  /// backed by the definition and remains valid for its lifetime.
  [[nodiscard]] std::span<const std::size_t> out_edges(ResourceId from) const noexcept;

  /// Canonical content digest over generation, resources, edges and selectors.
  [[nodiscard]] Digest digest() const;

 private:
  friend class TopologyBuilder;
  friend Result<TopologyDefinition> canonicalize_topology(TopologyDefinition definition,
                                                          const Limits& limits);

  TopologyGeneration generation_;
  std::vector<ResourceRecord> resources_;              ///< Sorted by resource id.
  std::vector<ForwardingEdge> edges_;                  ///< Sorted by (from, to, id).
  std::vector<TrafficSelector> selectors_;             ///< Sorted by selector id.
  std::vector<std::size_t> edge_by_id_;                ///< Edge indices sorted by edge id.
  std::vector<std::size_t> adjacency_;                 ///< CSR offsets, size |resources| + 1.
  std::vector<std::size_t> out_edge_list_;             ///< Edge indices grouped by source resource.
};

/// Builder that validates and canonicalises a definition before it becomes usable.
///
/// Validation is total and fail-closed: dangling endpoints, self-referential domains,
/// duplicate identities, unknown selector references, zero cost on a containable
/// resource, out-of-range generations and exhausted limits are all rejected with a
/// specific Outcome instead of being silently repaired.
class TopologyBuilder {
 public:
  explicit TopologyBuilder(const Limits& limits = default_limits()) : limits_(limits) {}

  Status add_resource(ResourceRecord record);
  Status add_edge(ForwardingEdge edge);
  Status add_selector(TrafficSelector selector);
  void set_generation(TopologyGeneration generation) noexcept { generation_ = generation; }

  [[nodiscard]] Result<TopologyDefinition> build() const;

 private:
  Limits limits_;
  TopologyGeneration generation_;
  std::vector<ResourceRecord> resources_;
  std::vector<ForwardingEdge> edges_;
  std::vector<TrafficSelector> selectors_;
};

/// Canonicalises an already-validated definition: sorts records, removes duplicate
/// selector references and rebuilds indices. Exposed so that tests can prove the
/// canonical form is independent of insertion order.
[[nodiscard]] Result<TopologyDefinition> canonicalize_topology(TopologyDefinition definition,
                                                              const Limits& limits = default_limits());

/// Parses a definition from its canonical text rendering. Used by fixtures and tools;
/// it is deliberately strict.
[[nodiscard]] Result<TopologyDefinition> topology_from_text(std::string_view text,
                                                            const Limits& limits = default_limits());
[[nodiscard]] std::string topology_to_text(const TopologyDefinition& topology);

}  // namespace loop_guard
