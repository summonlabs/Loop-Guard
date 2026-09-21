#include "loop_guard/topology.hpp"

#include <algorithm>
#include <charconv>
#include <cstdio>
#include <map>
#include <set>
#include <sstream>
#include <string_view>

namespace loop_guard {
namespace {

bool selectors_strictly_increasing(const std::vector<TrafficSelectorId>& selectors) {
  for (std::size_t index = 1; index < selectors.size(); ++index) {
    if (!(selectors[index - 1] < selectors[index])) {
      return false;
    }
  }
  return true;
}

template <class Id>
bool parse_u64(std::string_view text, Id& out) {
  std::uint64_t value = 0;
  const auto* begin = text.data();
  const auto* end = text.data() + text.size();
  const auto result = std::from_chars(begin, end, value);
  if (result.ec != std::errc{} || result.ptr != end) {
    return false;
  }
  out = Id::from_value(value);
  return true;
}

bool parse_u32(std::string_view text, std::uint32_t& out) {
  std::uint32_t value = 0;
  const auto* begin = text.data();
  const auto* end = text.data() + text.size();
  const auto result = std::from_chars(begin, end, value);
  if (result.ec != std::errc{} || result.ptr != end) {
    return false;
  }
  out = value;
  return true;
}

std::string unquote(std::string_view raw) {
  if (raw.size() >= 2 && raw.front() == '"' && raw.back() == '"') {
    return std::string(raw.substr(1, raw.size() - 2));
  }
  return std::string(raw);
}

std::vector<std::string_view> split_ws(std::string_view line) {
  std::vector<std::string_view> parts;
  std::size_t index = 0;
  while (index < line.size()) {
    while (index < line.size() && (line[index] == ' ' || line[index] == '\t')) {
      ++index;
    }
    const std::size_t start = index;
    while (index < line.size() && line[index] != ' ' && line[index] != '\t') {
      ++index;
    }
    if (index > start) {
      parts.push_back(line.substr(start, index - start));
    }
  }
  return parts;
}

struct KeyValue {
  std::string_view key;
  std::string_view value;
};

std::vector<KeyValue> split_fields(std::string_view line, std::size_t first_token_end) {
  std::vector<KeyValue> fields;
  std::size_t index = first_token_end;
  while (index < line.size()) {
    while (index < line.size() && line[index] == ' ') {
      ++index;
    }
    const std::size_t key_start = index;
    while (index < line.size() && line[index] != '=') {
      ++index;
    }
    if (index >= line.size()) {
      break;
    }
    const std::string_view key = line.substr(key_start, index - key_start);
    ++index;  // consume '='
    const std::size_t value_start = index;
    if (index < line.size() && line[index] == '"') {
      ++index;
      while (index < line.size() && line[index] != '"') {
        ++index;
      }
      if (index < line.size()) {
        ++index;
      }
    } else {
      while (index < line.size() && line[index] != ' ') {
        ++index;
      }
    }
    fields.push_back(KeyValue{key, line.substr(value_start, index - value_start)});
  }
  return fields;
}

const KeyValue* find_field(const std::vector<KeyValue>& fields, std::string_view key) {
  for (const KeyValue& field : fields) {
    if (field.key == key) {
      return &field;
    }
  }
  return nullptr;
}

}  // namespace

// ---------------------------------------------------------------------------
// ForwardingEdge ordering.
// ---------------------------------------------------------------------------
bool operator<(const ForwardingEdge& lhs, const ForwardingEdge& rhs) noexcept {
  if (lhs.from != rhs.from) {
    return lhs.from < rhs.from;
  }
  if (lhs.to != rhs.to) {
    return lhs.to < rhs.to;
  }
  return lhs.id < rhs.id;
}

// ---------------------------------------------------------------------------
// TopologyDefinition.
// ---------------------------------------------------------------------------
const ResourceRecord* TopologyDefinition::find_resource(ResourceId id) const noexcept {
  const auto position =
      std::lower_bound(resources_.begin(), resources_.end(), id,
                       [](const ResourceRecord& record, ResourceId key) { return record.id < key; });
  if (position == resources_.end() || !(position->id == id)) {
    return nullptr;
  }
  return &*position;
}

const TrafficSelector* TopologyDefinition::find_selector(TrafficSelectorId id) const noexcept {
  const auto position =
      std::lower_bound(selectors_.begin(), selectors_.end(), id,
                       [](const TrafficSelector& record, TrafficSelectorId key) {
                         return record.id < key;
                       });
  if (position == selectors_.end() || !(position->id == id)) {
    return nullptr;
  }
  return &*position;
}

std::optional<std::size_t> TopologyDefinition::edge_index(ForwardingEdgeId id) const noexcept {
  const auto position = std::lower_bound(
      edge_by_id_.begin(), edge_by_id_.end(), id, [this](std::size_t index, ForwardingEdgeId key) {
        return edges_[index].id < key;
      });
  if (position == edge_by_id_.end() || !(edges_[*position].id == id)) {
    return std::nullopt;
  }
  return *position;
}

const ForwardingEdge* TopologyDefinition::find_edge(ForwardingEdgeId id) const noexcept {
  const auto index = edge_index(id);
  if (!index.has_value()) {
    return nullptr;
  }
  return &edges_[*index];
}

std::span<const std::size_t> TopologyDefinition::out_edges(ResourceId from) const noexcept {
  if (adjacency_.size() < 2) {
    return {};
  }
  const auto position =
      std::lower_bound(resources_.begin(), resources_.end(), from,
                       [](const ResourceRecord& record, ResourceId key) { return record.id < key; });
  if (position == resources_.end() || !(position->id == from)) {
    return {};
  }
  const std::size_t index = static_cast<std::size_t>(position - resources_.begin());
  if (index + 1U >= adjacency_.size()) {
    return {};
  }
  const std::size_t begin = adjacency_[index];
  const std::size_t end = adjacency_[index + 1U];
  if (end < begin || end > out_edge_list_.size()) {
    return {};
  }
  return std::span<const std::size_t>(out_edge_list_.data() + begin, end - begin);
}

Digest TopologyDefinition::digest() const {
  Sha256 hasher;
  const std::uint64_t generation = generation_.value();
  hasher.update(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(&generation),
                                              sizeof(generation)));
  for (const ResourceRecord& record : resources_) {
    const std::uint64_t id = record.id.value();
    const std::uint64_t domain = record.domain.value();
    hasher.update(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(&id), sizeof(id)));
    hasher.update(
        std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(&domain), sizeof(domain)));
    hasher.update(static_cast<std::uint8_t>(record.kind));
    hasher.update(static_cast<std::uint8_t>(record.admin));
    hasher.update(static_cast<std::uint8_t>(record.containable ? 1 : 0));
    const std::uint32_t cost = record.containment_cost;
    hasher.update(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(&cost), sizeof(cost)));
    hasher.update(record.label);
    hasher.update(static_cast<std::uint8_t>(0));
  }
  for (const ForwardingEdge& edge : edges_) {
    const std::uint64_t id = edge.id.value();
    const std::uint64_t from = edge.from.value();
    const std::uint64_t to = edge.to.value();
    const std::uint64_t domain = edge.domain.value();
    hasher.update(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(&id), sizeof(id)));
    hasher.update(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(&from), sizeof(from)));
    hasher.update(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(&to), sizeof(to)));
    hasher.update(
        std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(&domain), sizeof(domain)));
    hasher.update(static_cast<std::uint8_t>(edge.link));
    for (const TrafficSelectorId selector : edge.admitted_selectors) {
      const std::uint64_t value = selector.value();
      hasher.update(
          std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(&value), sizeof(value)));
    }
    hasher.update(static_cast<std::uint8_t>(0xFF));
  }
  for (const TrafficSelector& selector : selectors_) {
    const std::uint64_t id = selector.id.value();
    hasher.update(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(&id), sizeof(id)));
    hasher.update(static_cast<std::uint8_t>(selector.kind));
    hasher.update(selector.label);
    hasher.update(static_cast<std::uint8_t>(0));
  }
  return hasher.finish();
}

// ---------------------------------------------------------------------------
// TopologyBuilder.
// ---------------------------------------------------------------------------
Status TopologyBuilder::add_resource(ResourceRecord record) {
  if (!record.id.valid()) {
    return Status::failure(Outcome::Invalid, "resource id must be non-zero");
  }
  if (!record.domain.valid()) {
    return Status::failure(Outcome::Invalid, "resource domain must be non-zero");
  }
  if (record.containable && record.containment_cost == 0U) {
    return Status::failure(Outcome::Invalid, "containable resource must have cost >= 1");
  }
  if (resources_.size() >= limits_.max_resources) {
    return Status::failure(Outcome::Exhausted, "resource limit reached");
  }
  record.label = bounded_text(record.label, 128);
  resources_.push_back(std::move(record));
  return Status::ok();
}

Status TopologyBuilder::add_selector(TrafficSelector selector) {
  if (!selector.id.valid()) {
    return Status::failure(Outcome::Invalid, "selector id must be non-zero");
  }
  if (selectors_.size() >= limits_.max_selectors) {
    return Status::failure(Outcome::Exhausted, "selector limit reached");
  }
  selector.label = bounded_text(selector.label, 128);
  selectors_.push_back(std::move(selector));
  return Status::ok();
}

Status TopologyBuilder::add_edge(ForwardingEdge edge) {
  if (!edge.id.valid()) {
    return Status::failure(Outcome::Invalid, "edge id must be non-zero");
  }
  if (!edge.from.valid() || !edge.to.valid()) {
    return Status::failure(Outcome::Invalid, "edge endpoints must be non-zero");
  }
  if (!edge.domain.valid()) {
    return Status::failure(Outcome::Invalid, "edge domain must be non-zero");
  }
  if (!selectors_strictly_increasing(edge.admitted_selectors)) {
    return Status::failure(Outcome::Invalid,
                           "edge selectors must be strictly increasing and duplicate free");
  }
  if (edges_.size() >= limits_.max_edges) {
    return Status::failure(Outcome::Exhausted, "edge limit reached");
  }
  edges_.push_back(std::move(edge));
  return Status::ok();
}

Result<TopologyDefinition> TopologyBuilder::build() const {
  TopologyDefinition definition;
  definition.generation_ = generation_;
  definition.resources_ = resources_;
  definition.edges_ = edges_;
  definition.selectors_ = selectors_;
  return canonicalize_topology(std::move(definition), limits_);
}

// ---------------------------------------------------------------------------
// Canonicalisation and validation.
// ---------------------------------------------------------------------------
Result<TopologyDefinition> canonicalize_topology(TopologyDefinition definition, const Limits& limits) {
  if (!limits_are_sane(limits)) {
    return Result<TopologyDefinition>::failure(Outcome::Unsupported, "limit set is not sane");
  }
  if (!definition.generation_.valid()) {
    return Result<TopologyDefinition>::failure(Outcome::Invalid, "topology generation must be non-zero");
  }
  if (definition.resources_.size() > limits.max_resources) {
    return Result<TopologyDefinition>::failure(Outcome::Exhausted, "resource limit exceeded");
  }
  if (definition.edges_.size() > limits.max_edges) {
    return Result<TopologyDefinition>::failure(Outcome::Exhausted, "edge limit exceeded");
  }
  if (definition.selectors_.size() > limits.max_selectors) {
    return Result<TopologyDefinition>::failure(Outcome::Exhausted, "selector limit exceeded");
  }

  std::sort(definition.resources_.begin(), definition.resources_.end());
  std::sort(definition.selectors_.begin(), definition.selectors_.end());
  std::sort(definition.edges_.begin(), definition.edges_.end());

  for (std::size_t index = 0; index < definition.resources_.size(); ++index) {
    const ResourceRecord& record = definition.resources_[index];
    if (!record.id.valid() || !record.domain.valid()) {
      return Result<TopologyDefinition>::failure(Outcome::Invalid, "resource has an invalid identity");
    }
    if (record.containable && record.containment_cost == 0U) {
      return Result<TopologyDefinition>::failure(Outcome::Invalid,
                                                 "containable resource must have cost >= 1");
    }
    if (index != 0 && definition.resources_[index - 1].id == record.id) {
      return Result<TopologyDefinition>::failure(Outcome::AlreadyExists, "duplicate resource identity");
    }
  }
  for (std::size_t index = 0; index < definition.selectors_.size(); ++index) {
    if (!definition.selectors_[index].id.valid()) {
      return Result<TopologyDefinition>::failure(Outcome::Invalid, "selector has an invalid identity");
    }
    if (index != 0 && definition.selectors_[index - 1].id == definition.selectors_[index].id) {
      return Result<TopologyDefinition>::failure(Outcome::AlreadyExists, "duplicate selector identity");
    }
  }

  const auto resource_lookup = [&definition](ResourceId id) -> const ResourceRecord* {
    const auto position = std::lower_bound(
        definition.resources_.begin(), definition.resources_.end(), id,
        [](const ResourceRecord& record, ResourceId key) { return record.id < key; });
    if (position == definition.resources_.end() || !(position->id == id)) {
      return nullptr;
    }
    return &*position;
  };

  for (std::size_t index = 0; index < definition.edges_.size(); ++index) {
    const ForwardingEdge& edge = definition.edges_[index];
    if (!edge.id.valid() || !edge.from.valid() || !edge.to.valid() || !edge.domain.valid()) {
      return Result<TopologyDefinition>::failure(Outcome::Invalid, "edge has an invalid identity");
    }
    if (index != 0 && definition.edges_[index - 1].id == edge.id) {
      return Result<TopologyDefinition>::failure(Outcome::AlreadyExists, "duplicate edge identity");
    }
    if (!selectors_strictly_increasing(edge.admitted_selectors)) {
      return Result<TopologyDefinition>::failure(
          Outcome::Invalid, "edge selectors must be strictly increasing and duplicate free");
    }
    const ResourceRecord* from = resource_lookup(edge.from);
    const ResourceRecord* to = resource_lookup(edge.to);
    if (from == nullptr || to == nullptr) {
      return Result<TopologyDefinition>::failure(Outcome::Invalid, "edge endpoint is not a resource");
    }
    if (!(from->domain == edge.domain) || !(to->domain == edge.domain)) {
      return Result<TopologyDefinition>::failure(
          Outcome::Invalid, "edge domain must match both endpoint domains");
    }
    for (const TrafficSelectorId selector : edge.admitted_selectors) {
      const auto position = std::lower_bound(
          definition.selectors_.begin(), definition.selectors_.end(), selector,
          [](const TrafficSelector& record, TrafficSelectorId key) { return record.id < key; });
      if (position == definition.selectors_.end() || !(position->id == selector)) {
        return Result<TopologyDefinition>::failure(Outcome::NotFound,
                                                   "edge references an undeclared selector");
      }
    }
  }

  // Build indices: edge-by-id, and a CSR adjacency grouped by source resource.
  definition.edge_by_id_.resize(definition.edges_.size());
  for (std::size_t index = 0; index < definition.edge_by_id_.size(); ++index) {
    definition.edge_by_id_[index] = index;
  }
  std::sort(definition.edge_by_id_.begin(), definition.edge_by_id_.end(),
            [&definition](std::size_t lhs, std::size_t rhs) {
              return definition.edges_[lhs].id < definition.edges_[rhs].id;
            });

  definition.adjacency_.assign(definition.resources_.size() + 1U, 0U);
  for (const ForwardingEdge& edge : definition.edges_) {
    const auto position = std::lower_bound(
        definition.resources_.begin(), definition.resources_.end(), edge.from,
        [](const ResourceRecord& record, ResourceId key) { return record.id < key; });
    const std::size_t resource_index =
        static_cast<std::size_t>(position - definition.resources_.begin());
    definition.adjacency_[resource_index + 1U] += 1U;
  }
  for (std::size_t index = 0; index < definition.resources_.size(); ++index) {
    definition.adjacency_[index + 1U] += definition.adjacency_[index];
  }
  definition.out_edge_list_.assign(definition.edges_.size(), 0U);
  std::vector<std::size_t> cursor = definition.adjacency_;
  for (std::size_t index = 0; index < definition.edges_.size(); ++index) {
    const ForwardingEdge& edge = definition.edges_[index];
    const auto position = std::lower_bound(
        definition.resources_.begin(), definition.resources_.end(), edge.from,
        [](const ResourceRecord& record, ResourceId key) { return record.id < key; });
    const std::size_t resource_index =
        static_cast<std::size_t>(position - definition.resources_.begin());
    definition.out_edge_list_[cursor[resource_index]] = index;
    cursor[resource_index] += 1U;
  }

  return Result<TopologyDefinition>::ok(std::move(definition));
}

std::string topology_to_text(const TopologyDefinition& topology) {
  std::string out;
  out += "topology generation=" + topology.generation().to_string() + "\n";
  for (const TrafficSelector& selector : topology.selectors()) {
    out += "selector " + selector.id.to_string() + " kind=" + std::string(to_string(selector.kind)) +
           " label=\"" + selector.label + "\"\n";
  }
  for (const ResourceRecord& record : topology.resources()) {
    out += "resource " + record.id.to_string() + " domain=" + record.domain.to_string() +
           " kind=" + std::string(to_string(record.kind)) +
           " admin=" + std::string(to_string(record.admin)) +
           " containable=" + (record.containable ? "1" : "0") +
           " cost=" + std::to_string(record.containment_cost) +
           " label=\"" + record.label + "\"\n";
  }
  for (const ForwardingEdge& edge : topology.edges()) {
    out += "edge " + edge.id.to_string() + " from=" + edge.from.to_string() +
           " to=" + edge.to.to_string() + " domain=" + edge.domain.to_string() +
           " link=" + std::string(to_string(edge.link)) + " selectors=";
    for (std::size_t index = 0; index < edge.admitted_selectors.size(); ++index) {
      if (index != 0U) {
        out.push_back(',');
      }
      out += edge.admitted_selectors[index].to_string();
    }
    out += "\n";
  }
  return out;
}

Result<TopologyDefinition> topology_from_text(std::string_view text, const Limits& limits) {
  TopologyBuilder builder(limits);
  bool have_generation = false;
  std::size_t line_number = 0;
  std::size_t start = 0;
  while (start <= text.size()) {
    const std::size_t end = text.find('\n', start);
    const std::string_view line =
        text.substr(start, end == std::string_view::npos ? std::string_view::npos : end - start);
    start = (end == std::string_view::npos) ? text.size() + 1 : end + 1;
    ++line_number;
    const auto parts = split_ws(line);
    if (parts.empty()) {
      continue;
    }
    if (parts[0] == "topology") {
      const auto fields = split_fields(line, parts[0].size());
      const KeyValue* generation = find_field(fields, "generation");
      if (generation == nullptr) {
        return Result<TopologyDefinition>::failure(Outcome::Invalid, "topology line lacks generation");
      }
      TopologyGeneration value;
      if (!parse_u64(generation->value, value) || !value.valid()) {
        return Result<TopologyDefinition>::failure(Outcome::Invalid, "invalid topology generation");
      }
      builder.set_generation(value);
      have_generation = true;
      continue;
    }
    if (parts[0] == "selector") {
      if (parts.size() < 2) {
        return Result<TopologyDefinition>::failure(Outcome::Invalid, "selector line lacks identity");
      }
      TrafficSelector selector;
      if (!parse_u64(parts[1], selector.id) || !selector.id.valid()) {
        return Result<TopologyDefinition>::failure(Outcome::Invalid, "invalid selector identity");
      }
      const auto fields = split_fields(line, parts[0].size() + 1U + parts[1].size());
      if (const KeyValue* kind = find_field(fields, "kind"); kind != nullptr) {
        bool matched = false;
        for (std::uint32_t raw = 0; raw <= 3U; ++raw) {
          const auto candidate = enum_from_u32<TrafficSelectorKind>(raw);
          if (candidate.has_value() && to_string(*candidate) == kind->value) {
            selector.kind = *candidate;
            matched = true;
            break;
          }
        }
        if (!matched) {
          return Result<TopologyDefinition>::failure(Outcome::Invalid, "unknown selector kind");
        }
      }
      if (const KeyValue* label = find_field(fields, "label"); label != nullptr) {
        selector.label = unquote(label->value);
      }
      const Status status = builder.add_selector(std::move(selector));
      if (!status.is_ok()) {
        return Result<TopologyDefinition>::failure(status.outcome(),
                                                   "selector line " + std::to_string(line_number) +
                                                       ": " + status.detail());
      }
      continue;
    }
    if (parts[0] == "resource") {
      if (parts.size() < 2) {
        return Result<TopologyDefinition>::failure(Outcome::Invalid, "resource line lacks identity");
      }
      ResourceRecord record;
      if (!parse_u64(parts[1], record.id) || !record.id.valid()) {
        return Result<TopologyDefinition>::failure(Outcome::Invalid, "invalid resource identity");
      }
      const auto fields = split_fields(line, parts[0].size() + 1U + parts[1].size());
      const KeyValue* domain = find_field(fields, "domain");
      if (domain == nullptr || !parse_u64(domain->value, record.domain) || !record.domain.valid()) {
        return Result<TopologyDefinition>::failure(Outcome::Invalid, "invalid resource domain");
      }
      if (const KeyValue* kind = find_field(fields, "kind"); kind != nullptr) {
        bool matched = false;
        for (std::uint32_t raw = 0; raw <= 7U; ++raw) {
          const auto candidate = enum_from_u32<ResourceKind>(raw);
          if (candidate.has_value() && to_string(*candidate) == kind->value) {
            record.kind = *candidate;
            matched = true;
            break;
          }
        }
        if (!matched) {
          return Result<TopologyDefinition>::failure(Outcome::Invalid, "unknown resource kind");
        }
      }
      if (const KeyValue* admin = find_field(fields, "admin"); admin != nullptr) {
        bool matched = false;
        for (std::uint32_t raw = 0; raw <= 2U; ++raw) {
          const auto candidate = enum_from_u32<AdministrativeState>(raw);
          if (candidate.has_value() && to_string(*candidate) == admin->value) {
            record.admin = *candidate;
            matched = true;
            break;
          }
        }
        if (!matched) {
          return Result<TopologyDefinition>::failure(Outcome::Invalid, "unknown administrative state");
        }
      }
      if (const KeyValue* containable = find_field(fields, "containable"); containable != nullptr) {
        record.containable = containable->value == "1";
      }
      if (const KeyValue* cost = find_field(fields, "cost"); cost != nullptr) {
        if (!parse_u32(cost->value, record.containment_cost)) {
          return Result<TopologyDefinition>::failure(Outcome::Invalid, "invalid resource cost");
        }
      }
      if (const KeyValue* label = find_field(fields, "label"); label != nullptr) {
        record.label = unquote(label->value);
      }
      const Status status = builder.add_resource(std::move(record));
      if (!status.is_ok()) {
        return Result<TopologyDefinition>::failure(status.outcome(),
                                                   "resource line " + std::to_string(line_number) +
                                                       ": " + status.detail());
      }
      continue;
    }
    if (parts[0] == "edge") {
      if (parts.size() < 2) {
        return Result<TopologyDefinition>::failure(Outcome::Invalid, "edge line lacks identity");
      }
      ForwardingEdge edge;
      if (!parse_u64(parts[1], edge.id) || !edge.id.valid()) {
        return Result<TopologyDefinition>::failure(Outcome::Invalid, "invalid edge identity");
      }
      const auto fields = split_fields(line, parts[0].size() + 1U + parts[1].size());
      const KeyValue* from = find_field(fields, "from");
      const KeyValue* to = find_field(fields, "to");
      const KeyValue* domain = find_field(fields, "domain");
      if (from == nullptr || to == nullptr || domain == nullptr) {
        return Result<TopologyDefinition>::failure(Outcome::Invalid, "edge line lacks endpoints");
      }
      if (!parse_u64(from->value, edge.from) || !parse_u64(to->value, edge.to) ||
          !parse_u64(domain->value, edge.domain)) {
        return Result<TopologyDefinition>::failure(Outcome::Invalid, "invalid edge endpoint identity");
      }
      if (const KeyValue* link = find_field(fields, "link"); link != nullptr) {
        bool matched = false;
        for (std::uint32_t raw = 0; raw <= 2U; ++raw) {
          const auto candidate = enum_from_u32<LinkState>(raw);
          if (candidate.has_value() && to_string(*candidate) == link->value) {
            edge.link = *candidate;
            matched = true;
            break;
          }
        }
        if (!matched) {
          return Result<TopologyDefinition>::failure(Outcome::Invalid, "unknown link state");
        }
      }
      if (const KeyValue* selectors = find_field(fields, "selectors"); selectors != nullptr) {
        std::string_view list = selectors->value;
        std::size_t cursor = 0;
        while (cursor <= list.size()) {
          const std::size_t comma = list.find(',', cursor);
          const std::string_view token =
              list.substr(cursor, comma == std::string_view::npos ? std::string_view::npos : comma - cursor);
          if (!token.empty()) {
            TrafficSelectorId selector;
            if (!parse_u64(token, selector) || !selector.valid()) {
              return Result<TopologyDefinition>::failure(Outcome::Invalid, "invalid edge selector");
            }
            edge.admitted_selectors.push_back(selector);
          }
          if (comma == std::string_view::npos) {
            break;
          }
          cursor = comma + 1U;
        }
        std::sort(edge.admitted_selectors.begin(), edge.admitted_selectors.end());
      }
      const Status status = builder.add_edge(std::move(edge));
      if (!status.is_ok()) {
        return Result<TopologyDefinition>::failure(status.outcome(),
                                                   "edge line " + std::to_string(line_number) + ": " +
                                                       status.detail());
      }
      continue;
    }
    return Result<TopologyDefinition>::failure(Outcome::Invalid,
                                               "unknown directive on line " + std::to_string(line_number));
  }

  if (!have_generation) {
    return Result<TopologyDefinition>::failure(Outcome::Invalid, "topology generation was not declared");
  }
  return builder.build();
}

}  // namespace loop_guard
