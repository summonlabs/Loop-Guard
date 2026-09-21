#include "loop_guard/wire.hpp"

#include <algorithm>
#include <cstring>

namespace loop_guard {
namespace {

constexpr std::uint16_t kTopologySchema = 1;
constexpr std::uint16_t kPolicySchema = 1;
constexpr std::uint16_t kObservationSchema = 1;

void write_u16_le(std::uint8_t* out, std::uint16_t value) {
  out[0] = static_cast<std::uint8_t>(value & 0xFFU);
  out[1] = static_cast<std::uint8_t>((value >> 8U) & 0xFFU);
}

void write_u32_le(std::uint8_t* out, std::uint32_t value) {
  for (std::size_t index = 0; index < 4; ++index) {
    out[index] = static_cast<std::uint8_t>((value >> (index * 8U)) & 0xFFU);
  }
}

void write_u64_le(std::uint8_t* out, std::uint64_t value) {
  for (std::size_t index = 0; index < 8; ++index) {
    out[index] = static_cast<std::uint8_t>((value >> (index * 8U)) & 0xFFU);
  }
}

std::uint16_t read_u16_le(const std::uint8_t* data) {
  return static_cast<std::uint16_t>(static_cast<std::uint16_t>(data[0]) |
                                    (static_cast<std::uint16_t>(data[1]) << 8U));
}

std::uint32_t read_u32_le(const std::uint8_t* data) {
  std::uint32_t value = 0;
  for (std::size_t index = 0; index < 4; ++index) {
    value |= static_cast<std::uint32_t>(data[index]) << (index * 8U);
  }
  return value;
}

std::uint64_t read_u64_le(const std::uint8_t* data) {
  std::uint64_t value = 0;
  for (std::size_t index = 0; index < 8; ++index) {
    value |= static_cast<std::uint64_t>(data[index]) << (index * 8U);
  }
  return value;
}

template <class Id>
void write_id(ByteWriter& writer, Id value) {
  writer.u64(value.value());
}

template <class Enum>
bool read_enum(ByteReader& reader, Enum& out) {
  std::uint8_t raw = 0;
  if (!reader.read_u8(raw)) {
    return false;
  }
  const auto value = enum_from_u32<Enum>(raw);
  if (!value.has_value()) {
    return reader.reject(ReasonCode::WireFrameBadEnum, "enum value is out of domain");
  }
  out = *value;
  return true;
}

}  // namespace

// ---------------------------------------------------------------------------
// Canonical byte codec.
// ---------------------------------------------------------------------------
void ByteWriter::u8(std::uint8_t value) { data_.push_back(value); }

void ByteWriter::u16(std::uint16_t value) {
  std::uint8_t buffer[2];
  write_u16_le(buffer, value);
  data_.insert(data_.end(), buffer, buffer + 2);
}

void ByteWriter::u32(std::uint32_t value) {
  std::uint8_t buffer[4];
  write_u32_le(buffer, value);
  data_.insert(data_.end(), buffer, buffer + 4);
}

void ByteWriter::u64(std::uint64_t value) {
  std::uint8_t buffer[8];
  write_u64_le(buffer, value);
  data_.insert(data_.end(), buffer, buffer + 8);
}

void ByteWriter::boolean(bool value) { u8(value ? 1U : 0U); }

void ByteWriter::raw(std::span<const std::uint8_t> bytes) {
  data_.insert(data_.end(), bytes.begin(), bytes.end());
}

void ByteWriter::digest(const Digest& value) { raw(value.bytes); }

void ByteWriter::text(std::string_view value, std::size_t max_bytes) {
  if (value.size() > max_bytes) {
    overflowed_ = true;
    value = value.substr(0, max_bytes);
  }
  u32(static_cast<std::uint32_t>(value.size()));
  raw(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(value.data()),
                                    value.size()));
}

std::size_t ByteWriter::reserve_length() {
  const std::size_t offset = data_.size();
  u32(0U);
  return offset;
}

void ByteWriter::patch_length(std::size_t offset) {
  if (offset + 4U > data_.size()) {
    overflowed_ = true;
    return;
  }
  const std::uint64_t length = static_cast<std::uint64_t>(data_.size() - offset - 4U);
  if (length > 0xFFFF'FFFFULL) {
    overflowed_ = true;
    return;
  }
  write_u32_le(data_.data() + offset, static_cast<std::uint32_t>(length));
}

bool ByteReader::fail(ReasonCode reason, std::string detail) {
  if (ok_) {
    ok_ = false;
    reason_ = reason;
    detail_ = std::move(detail);
  }
  return false;
}

bool ByteReader::read_u8(std::uint8_t& out) {
  if (!ok_) {
    return false;
  }
  if (position_ + 1U > bytes_.size()) {
    return fail(ReasonCode::WireFrameTruncated, "byte stream ended early");
  }
  out = bytes_[position_];
  ++position_;
  return true;
}

bool ByteReader::read_u16(std::uint16_t& out) {
  if (!ok_) {
    return false;
  }
  if (position_ + 2U > bytes_.size()) {
    return fail(ReasonCode::WireFrameTruncated, "byte stream ended early");
  }
  out = read_u16_le(bytes_.data() + position_);
  position_ += 2U;
  return true;
}

bool ByteReader::read_u32(std::uint32_t& out) {
  if (!ok_) {
    return false;
  }
  if (position_ + 4U > bytes_.size()) {
    return fail(ReasonCode::WireFrameTruncated, "byte stream ended early");
  }
  out = read_u32_le(bytes_.data() + position_);
  position_ += 4U;
  return true;
}

bool ByteReader::read_u64(std::uint64_t& out) {
  if (!ok_) {
    return false;
  }
  if (position_ + 8U > bytes_.size()) {
    return fail(ReasonCode::WireFrameTruncated, "byte stream ended early");
  }
  out = read_u64_le(bytes_.data() + position_);
  position_ += 8U;
  return true;
}

bool ByteReader::read_bool(bool& out) {
  std::uint8_t raw = 0;
  if (!read_u8(raw)) {
    return false;
  }
  if (raw > 1U) {
    return fail(ReasonCode::WireFrameBadEnum, "boolean field is not 0 or 1");
  }
  out = raw == 1U;
  return true;
}

bool ByteReader::read_raw(std::vector<std::uint8_t>& out, std::size_t count) {
  if (!ok_) {
    return false;
  }
  if (count > bytes_.size() - position_) {
    return fail(ReasonCode::WireFrameTruncated, "declared byte run exceeds the payload");
  }
  out.assign(bytes_.begin() + static_cast<std::ptrdiff_t>(position_),
             bytes_.begin() + static_cast<std::ptrdiff_t>(position_ + count));
  position_ += count;
  return true;
}

bool ByteReader::read_digest(Digest& out) {
  if (!ok_) {
    return false;
  }
  if (kDigestBytes > bytes_.size() - position_) {
    return fail(ReasonCode::WireFrameTruncated, "digest is truncated");
  }
  std::copy(bytes_.begin() + static_cast<std::ptrdiff_t>(position_),
            bytes_.begin() + static_cast<std::ptrdiff_t>(position_ + kDigestBytes),
            out.bytes.begin());
  position_ += kDigestBytes;
  return true;
}

bool ByteReader::read_text(std::string& out, std::size_t max_bytes) {
  std::uint32_t length = 0;
  if (!read_u32(length)) {
    return false;
  }
  if (length > max_bytes) {
    return fail(ReasonCode::LimitsExceeded, "declared text length exceeds the ceiling");
  }
  if (length > bytes_.size() - position_) {
    return fail(ReasonCode::WireFrameTruncated, "text is truncated");
  }
  out.assign(reinterpret_cast<const char*>(bytes_.data() + position_), length);
  position_ += length;
  return true;
}

bool ByteReader::read_count(std::uint32_t& out, std::uint32_t max_count) {
  std::uint32_t value = 0;
  if (!read_u32(value)) {
    return false;
  }
  if (value > max_count) {
    return fail(ReasonCode::LimitsExceeded, "declared element count exceeds the ceiling");
  }
  out = value;
  return true;
}

void write_process_identity(ByteWriter& writer, const ProcessIdentity& identity) {
  write_id(writer, identity.producer);
  write_id(writer, identity.boot);
  write_id(writer, identity.incarnation);
  write_id(writer, identity.epoch);
}

bool read_process_identity(ByteReader& reader, ProcessIdentity& identity) {
  return reader.read_id(identity.producer) && reader.read_id(identity.boot) &&
         reader.read_id(identity.incarnation) && reader.read_id(identity.epoch);
}

std::vector<std::uint8_t> encode_fence(const FenceVector& fence) {
  ByteWriter writer;
  write_id(writer, fence.topology);
  write_id(writer, fence.forwarding);
  write_id(writer, fence.policy);
  write_id(writer, fence.fabric_epoch);
  write_id(writer, fence.epoch);
  write_id(writer, fence.boot);
  return std::move(writer).take();
}

Result<FenceVector> decode_fence(ByteReader& reader) {
  FenceVector fence;
  if (!reader.read_id(fence.topology) || !reader.read_id(fence.forwarding) ||
      !reader.read_id(fence.policy) || !reader.read_id(fence.fabric_epoch) ||
      !reader.read_id(fence.epoch) || !reader.read_id(fence.boot)) {
    return Result<FenceVector>::failure(Outcome::Invalid, "fence vector is truncated");
  }
  if (fence.is_zero()) {
    return Result<FenceVector>::failure(Outcome::Invalid, "fence vector is all zero");
  }
  return Result<FenceVector>::ok(fence);
}

// ---------------------------------------------------------------------------
// Domain payloads.
// ---------------------------------------------------------------------------
std::vector<std::uint8_t> encode_topology(const TopologyDefinition& topology, const Limits& limits) {
  ByteWriter writer;
  writer.u16(kTopologySchema);
  writer.u64(topology.generation().value());
  writer.u32(static_cast<std::uint32_t>(topology.selectors().size()));
  for (const TrafficSelector& selector : topology.selectors()) {
    writer.u64(selector.id.value());
    writer.u8(static_cast<std::uint8_t>(selector.kind));
    writer.text(selector.label, 128);
  }
  writer.u32(static_cast<std::uint32_t>(topology.resources().size()));
  for (const ResourceRecord& record : topology.resources()) {
    writer.u64(record.id.value());
    writer.u64(record.domain.value());
    writer.u8(static_cast<std::uint8_t>(record.kind));
    writer.u8(static_cast<std::uint8_t>(record.admin));
    writer.boolean(record.containable);
    writer.u32(record.containment_cost);
    writer.text(record.label, 128);
  }
  writer.u32(static_cast<std::uint32_t>(topology.edges().size()));
  for (const ForwardingEdge& edge : topology.edges()) {
    writer.u64(edge.id.value());
    writer.u64(edge.from.value());
    writer.u64(edge.to.value());
    writer.u64(edge.domain.value());
    writer.u8(static_cast<std::uint8_t>(edge.link));
    writer.u32(static_cast<std::uint32_t>(edge.admitted_selectors.size()));
    for (const TrafficSelectorId selector : edge.admitted_selectors) {
      writer.u64(selector.value());
    }
  }
  if (writer.overflowed()) {
    return {};
  }
  (void)limits;
  return std::move(writer).take();
}

Result<TopologyDefinition> decode_topology(std::span<const std::uint8_t> bytes, const Limits& limits) {
  ByteReader reader(bytes);
  std::uint16_t schema = 0;
  if (!reader.read_u16(schema)) {
    return Result<TopologyDefinition>::failure(Outcome::Invalid, "topology schema is truncated");
  }
  if (schema != kTopologySchema) {
    return Result<TopologyDefinition>::failure(Outcome::Unsupported,
                                               "topology schema is not supported");
  }
  TopologyBuilder builder(limits);
  std::uint64_t generation = 0;
  if (!reader.read_u64(generation) || generation == 0U) {
    return Result<TopologyDefinition>::failure(Outcome::Invalid, "topology generation is invalid");
  }
  builder.set_generation(TopologyGeneration::from_value(generation));

  std::uint32_t count = 0;
  if (!reader.read_count(count, limits.max_selectors)) {
    return Result<TopologyDefinition>::failure(reader.reason(), reader.detail());
  }
  for (std::uint32_t index = 0; index < count; ++index) {
    TrafficSelector selector;
    if (!reader.read_id(selector.id) || !read_enum(reader, selector.kind) ||
        !reader.read_text(selector.label, 128)) {
      return Result<TopologyDefinition>::failure(reader.reason(), reader.detail());
    }
    const Status status = builder.add_selector(std::move(selector));
    if (!status.is_ok()) {
      return Result<TopologyDefinition>::failure(status.outcome(), status.detail());
    }
  }
  if (!reader.read_count(count, limits.max_resources)) {
    return Result<TopologyDefinition>::failure(reader.reason(), reader.detail());
  }
  for (std::uint32_t index = 0; index < count; ++index) {
    ResourceRecord record;
    if (!reader.read_id(record.id) || !reader.read_id(record.domain) ||
        !read_enum(reader, record.kind) || !read_enum(reader, record.admin) ||
        !reader.read_bool(record.containable) || !reader.read_u32(record.containment_cost) ||
        !reader.read_text(record.label, 128)) {
      return Result<TopologyDefinition>::failure(reader.reason(), reader.detail());
    }
    const Status status = builder.add_resource(std::move(record));
    if (!status.is_ok()) {
      return Result<TopologyDefinition>::failure(status.outcome(), status.detail());
    }
  }
  if (!reader.read_count(count, limits.max_edges)) {
    return Result<TopologyDefinition>::failure(reader.reason(), reader.detail());
  }
  for (std::uint32_t index = 0; index < count; ++index) {
    ForwardingEdge edge;
    if (!reader.read_id(edge.id) || !reader.read_id(edge.from) || !reader.read_id(edge.to) ||
        !reader.read_id(edge.domain) || !read_enum(reader, edge.link)) {
      return Result<TopologyDefinition>::failure(reader.reason(), reader.detail());
    }
    std::uint32_t selector_count = 0;
    if (!reader.read_count(selector_count, limits.max_selectors)) {
      return Result<TopologyDefinition>::failure(reader.reason(), reader.detail());
    }
    edge.admitted_selectors.reserve(selector_count);
    for (std::uint32_t selector_index = 0; selector_index < selector_count; ++selector_index) {
      TrafficSelectorId selector;
      if (!reader.read_id(selector)) {
        return Result<TopologyDefinition>::failure(reader.reason(), reader.detail());
      }
      edge.admitted_selectors.push_back(selector);
    }
    const Status status = builder.add_edge(std::move(edge));
    if (!status.is_ok()) {
      return Result<TopologyDefinition>::failure(status.outcome(), status.detail());
    }
  }
  if (!reader.at_end()) {
    return Result<TopologyDefinition>::failure(Outcome::Invalid, "topology payload has trailing bytes");
  }
  return builder.build();
}

std::vector<std::uint8_t> encode_policy(const ContainmentPolicy& policy, const Limits& limits) {
  ByteWriter writer;
  writer.u16(kPolicySchema);
  writer.u64(policy.generation.value());
  writer.u32(policy.max_targets);
  writer.u64(policy.max_total_cost);
  writer.boolean(policy.allow_cross_domain);
  writer.u64(policy.max_search_nodes);
  writer.u32(static_cast<std::uint32_t>(policy.eligible_kinds.size()));
  for (const ResourceKind kind : policy.eligible_kinds) {
    writer.u8(static_cast<std::uint8_t>(kind));
  }
  writer.u32(static_cast<std::uint32_t>(policy.eligible_domains.size()));
  for (const DomainId domain : policy.eligible_domains) {
    writer.u64(domain.value());
  }
  if (writer.overflowed()) {
    return {};
  }
  (void)limits;
  return std::move(writer).take();
}

Result<ContainmentPolicy> decode_policy(std::span<const std::uint8_t> bytes, const Limits& limits) {
  ByteReader reader(bytes);
  std::uint16_t schema = 0;
  if (!reader.read_u16(schema)) {
    return Result<ContainmentPolicy>::failure(Outcome::Invalid, "policy schema is truncated");
  }
  if (schema != kPolicySchema) {
    return Result<ContainmentPolicy>::failure(Outcome::Unsupported, "policy schema is not supported");
  }
  ContainmentPolicy policy;
  if (!reader.read_id(policy.generation) || !reader.read_u32(policy.max_targets) ||
      !reader.read_u64(policy.max_total_cost) || !reader.read_bool(policy.allow_cross_domain) ||
      !reader.read_u64(policy.max_search_nodes)) {
    return Result<ContainmentPolicy>::failure(reader.reason(), reader.detail());
  }
  std::uint32_t count = 0;
  if (!reader.read_count(count, limits.max_selectors)) {
    return Result<ContainmentPolicy>::failure(reader.reason(), reader.detail());
  }
  for (std::uint32_t index = 0; index < count; ++index) {
    ResourceKind kind = ResourceKind::Unsupported;
    if (!read_enum(reader, kind)) {
      return Result<ContainmentPolicy>::failure(reader.reason(), reader.detail());
    }
    policy.eligible_kinds.push_back(kind);
  }
  if (!reader.read_count(count, limits.max_selectors)) {
    return Result<ContainmentPolicy>::failure(reader.reason(), reader.detail());
  }
  for (std::uint32_t index = 0; index < count; ++index) {
    DomainId domain;
    if (!reader.read_id(domain)) {
      return Result<ContainmentPolicy>::failure(reader.reason(), reader.detail());
    }
    policy.eligible_domains.push_back(domain);
  }
  if (!reader.at_end()) {
    return Result<ContainmentPolicy>::failure(Outcome::Invalid, "policy payload has trailing bytes");
  }
  if (!std::is_sorted(policy.eligible_kinds.begin(), policy.eligible_kinds.end())) {
    return Result<ContainmentPolicy>::failure(Outcome::Invalid, "policy kinds are not sorted");
  }
  if (!std::is_sorted(policy.eligible_domains.begin(), policy.eligible_domains.end())) {
    return Result<ContainmentPolicy>::failure(Outcome::Invalid, "policy domains are not sorted");
  }
  return Result<ContainmentPolicy>::ok(std::move(policy));
}

std::vector<std::uint8_t> encode_observation(const ForwardingObservation& observation,
                                             const Limits& limits) {
  ByteWriter writer;
  writer.u16(kObservationSchema);
  writer.u64(observation.id.value());
  writer.u64(observation.edge.value());
  writer.u64(observation.from.value());
  writer.u64(observation.to.value());
  writer.u64(observation.domain.value());
  writer.u8(static_cast<std::uint8_t>(observation.klass));
  writer.u32(static_cast<std::uint32_t>(observation.selectors.size()));
  for (const TrafficSelectorId selector : observation.selectors) {
    writer.u64(selector.value());
  }
  writer.u64(observation.topology_generation.value());
  writer.u64(observation.forwarding_generation.value());
  writer.u64(observation.producer.value());
  writer.u8(static_cast<std::uint8_t>(observation.producer_kind));
  writer.u64(observation.sequence.value());
  writer.u8(static_cast<std::uint8_t>(observation.origin));
  writer.u64(observation.lease.boot.value());
  writer.u64(observation.lease.epoch.value());
  writer.u64(observation.lease.fabric_epoch.value());
  writer.u64(observation.lease.valid_from);
  writer.u64(observation.lease.valid_until);
  writer.digest(observation.payload_digest);
  if (writer.overflowed()) {
    return {};
  }
  (void)limits;
  return std::move(writer).take();
}

Result<ForwardingObservation> decode_observation(std::span<const std::uint8_t> bytes,
                                                 const Limits& limits) {
  ByteReader reader(bytes);
  std::uint16_t schema = 0;
  if (!reader.read_u16(schema)) {
    return Result<ForwardingObservation>::failure(Outcome::Invalid, "observation is truncated");
  }
  if (schema != kObservationSchema) {
    return Result<ForwardingObservation>::failure(Outcome::Unsupported,
                                                  "observation schema is not supported");
  }
  ForwardingObservation observation;
  if (!reader.read_id(observation.id) || !reader.read_id(observation.edge) ||
      !reader.read_id(observation.from) || !reader.read_id(observation.to) ||
      !reader.read_id(observation.domain) || !read_enum(reader, observation.klass)) {
    return Result<ForwardingObservation>::failure(reader.reason(), reader.detail());
  }
  std::uint32_t count = 0;
  if (!reader.read_count(count, limits.max_selectors)) {
    return Result<ForwardingObservation>::failure(reader.reason(), reader.detail());
  }
  for (std::uint32_t index = 0; index < count; ++index) {
    TrafficSelectorId selector;
    if (!reader.read_id(selector)) {
      return Result<ForwardingObservation>::failure(reader.reason(), reader.detail());
    }
    observation.selectors.push_back(selector);
  }
  if (!reader.read_id(observation.topology_generation) ||
      !reader.read_id(observation.forwarding_generation) || !reader.read_id(observation.producer) ||
      !read_enum(reader, observation.producer_kind) || !reader.read_id(observation.sequence) ||
      !read_enum(reader, observation.origin) || !reader.read_id(observation.lease.boot) ||
      !reader.read_id(observation.lease.epoch) || !reader.read_id(observation.lease.fabric_epoch) ||
      !reader.read_u64(observation.lease.valid_from) ||
      !reader.read_u64(observation.lease.valid_until) ||
      !reader.read_digest(observation.payload_digest)) {
    return Result<ForwardingObservation>::failure(reader.reason(), reader.detail());
  }
  if (!reader.at_end()) {
    return Result<ForwardingObservation>::failure(Outcome::Invalid,
                                                  "observation payload has trailing bytes");
  }
  return Result<ForwardingObservation>::ok(std::move(observation));
}

// ---------------------------------------------------------------------------
// Frames.
// ---------------------------------------------------------------------------
bool is_valid_message_type(std::uint16_t raw) noexcept {
  return raw <= static_cast<std::uint16_t>(MessageType::ContainAuthorize);
}

std::string_view to_string(MessageType type) noexcept {
  switch (type) {
    case MessageType::Hello:
      return "Hello";
    case MessageType::HelloAck:
      return "HelloAck";
    case MessageType::Bye:
      return "Bye";
    case MessageType::Error:
      return "Error";
    case MessageType::SetTopology:
      return "SetTopology";
    case MessageType::SetPolicy:
      return "SetPolicy";
    case MessageType::ConfigurationAccepted:
      return "ConfigurationAccepted";
    case MessageType::SubmitObservation:
      return "SubmitObservation";
    case MessageType::ObservationAccepted:
      return "ObservationAccepted";
    case MessageType::DetectRequest:
      return "DetectRequest";
    case MessageType::AssessmentReply:
      return "AssessmentReply";
    case MessageType::PlanRequest:
      return "PlanRequest";
    case MessageType::PlanReply:
      return "PlanReply";
    case MessageType::ContainIntent:
      return "ContainIntent";
    case MessageType::ContainAck:
      return "ContainAck";
    case MessageType::EffectReport:
      return "EffectReport";
    case MessageType::FindingQuery:
      return "FindingQuery";
    case MessageType::FindingReply:
      return "FindingReply";
    case MessageType::FindingWithdraw:
      return "FindingWithdraw";
    case MessageType::StateDigestRequest:
      return "StateDigestRequest";
    case MessageType::StateDigestReply:
      return "StateDigestReply";
    case MessageType::FenceAdvance:
      return "FenceAdvance";
    case MessageType::RestartReportRequest:
      return "RestartReportRequest";
    case MessageType::RestartReportReply:
      return "RestartReportReply";
    case MessageType::FindingPublish:
      return "FindingPublish";
    case MessageType::ContainAuthorize:
      return "ContainAuthorize";
  }
  return "Invalid";
}

bool allowed_before_handshake(MessageType type) noexcept {
  // Only the handshake itself may precede a completed handshake. Everything else is
  // refused, so a peer can never act under an unestablished session.
  return type == MessageType::Hello;
}

Digest FrameHeader::header_digest() const {
  std::uint8_t buffer[kWireHeaderBytes];
  write_u32_le(buffer, magic);
  write_u16_le(buffer + 4, version);
  write_u16_le(buffer + 6, static_cast<std::uint16_t>(type));
  write_u32_le(buffer + 8, flags);
  write_u64_le(buffer + 12, session.value());
  write_u64_le(buffer + 20, sequence);
  write_u32_le(buffer + 28, payload_length);
  return sha256(std::span<const std::uint8_t>(buffer, kWireHeaderBytes));
}

Result<std::vector<std::uint8_t>> encode_frame(MessageType type, SessionId session,
                                               std::uint64_t sequence,
                                               std::span<const std::uint8_t> payload,
                                               std::uint32_t flags) {
  if (!is_valid_message_type(static_cast<std::uint16_t>(type))) {
    return Result<std::vector<std::uint8_t>>::failure(Outcome::Unsupported,
                                                      "message type is out of domain");
  }
  if (payload.size() > Maxima::kFramePayload) {
    return Result<std::vector<std::uint8_t>>::failure(Outcome::Exhausted,
                                                      "frame payload exceeds the hard ceiling");
  }
  std::vector<std::uint8_t> frame(kWireHeaderBytes + payload.size() + kDigestBytes, 0U);
  write_u32_le(frame.data(), kWireMagic);
  write_u16_le(frame.data() + 4, kWireVersion);
  write_u16_le(frame.data() + 6, static_cast<std::uint16_t>(type));
  write_u32_le(frame.data() + 8, flags);
  write_u64_le(frame.data() + 12, session.value());
  write_u64_le(frame.data() + 20, sequence);
  write_u32_le(frame.data() + 28, static_cast<std::uint32_t>(payload.size()));
  if (!payload.empty()) {
    std::copy(payload.begin(), payload.end(),
              frame.begin() + static_cast<std::ptrdiff_t>(kWireHeaderBytes));
  }
  const std::uint8_t* body = frame.data();
  const std::size_t body_size = kWireHeaderBytes + payload.size();
  const Digest digest = sha256(std::span<const std::uint8_t>(body, body_size));
  std::copy(digest.bytes.begin(), digest.bytes.end(),
            frame.begin() + static_cast<std::ptrdiff_t>(body_size));
  return Result<std::vector<std::uint8_t>>::ok(std::move(frame));
}

Result<DecodedFrame> decode_frame(std::span<const std::uint8_t> bytes, const Limits& limits) {
  (void)limits;
  if (bytes.size() < kWireHeaderBytes) {
    return Result<DecodedFrame>::failure(Outcome::Invalid, "frame header is truncated");
  }
  const std::uint8_t* header = bytes.data();
  if (read_u32_le(header) != kWireMagic) {
    return Result<DecodedFrame>::failure(Outcome::Invalid, "frame magic mismatch");
  }
  const std::uint16_t version = read_u16_le(header + 4);
  if (version != kWireVersion) {
    return Result<DecodedFrame>::failure(Outcome::Unsupported, "frame version is not supported");
  }
  const std::uint16_t raw_type = read_u16_le(header + 6);
  if (!is_valid_message_type(raw_type)) {
    return Result<DecodedFrame>::failure(Outcome::Unsupported, "frame type is out of domain");
  }
  const std::uint32_t flags = read_u32_le(header + 8);
  if (flags != 0U) {
    return Result<DecodedFrame>::failure(Outcome::Invalid, "frame flags are not understood");
  }
  const std::uint64_t sequence = read_u64_le(header + 20);
  const std::uint32_t declared = read_u32_le(header + 28);
  if (declared > Maxima::kFramePayload) {
    return Result<DecodedFrame>::failure(Outcome::Exhausted,
                                         "declared payload length exceeds the hard ceiling");
  }
  const std::size_t expected = kWireHeaderBytes + declared + kDigestBytes;
  if (bytes.size() < expected) {
    return Result<DecodedFrame>::failure(Outcome::Invalid, "frame payload is truncated");
  }
  if (bytes.size() > expected) {
    return Result<DecodedFrame>::failure(Outcome::Invalid, "frame has trailing bytes");
  }
  const std::uint8_t* body = bytes.data();
  const std::size_t body_size = kWireHeaderBytes + declared;
  const Digest computed = sha256(std::span<const std::uint8_t>(body, body_size));
  Digest claimed;
  std::copy(body + body_size, body + body_size + kDigestBytes, claimed.bytes.begin());
  if (!(computed == claimed)) {
    return Result<DecodedFrame>::failure(Outcome::IntegrityFailure, "frame integrity check failed");
  }
  DecodedFrame frame;
  frame.header.magic = kWireMagic;
  frame.header.version = version;
  frame.header.type = static_cast<MessageType>(raw_type);
  frame.header.flags = flags;
  frame.header.session = SessionId::from_value(read_u64_le(header + 12));
  frame.header.sequence = sequence;
  frame.header.payload_length = declared;
  frame.payload.assign(body + kWireHeaderBytes, body + body_size);
  return Result<DecodedFrame>::ok(std::move(frame));
}

FrameDecoder::FrameDecoder(const Limits& limits) : limits_(limits) {}

Status FrameDecoder::fail(ReasonCode reason, std::string detail) {
  if (!failed_) {
    failed_ = true;
    failure_reason_ = reason;
    failure_detail_ = std::move(detail);
  }
  return Status::failure(Outcome::IntegrityFailure, failure_detail_);
}

Status FrameDecoder::feed(std::span<const std::uint8_t> bytes, std::vector<DecodedFrame>& out) {
  if (failed_) {
    return Status::failure(Outcome::IntegrityFailure, failure_detail_);
  }
  if (finished_) {
    return fail(ReasonCode::WireFrameTruncated, "bytes were fed after the stream was finished");
  }
  if (consumed_ != 0U) {
    buffer_.erase(buffer_.begin(), buffer_.begin() + static_cast<std::ptrdiff_t>(consumed_));
    consumed_ = 0U;
  }
  buffer_.insert(buffer_.end(), bytes.begin(), bytes.end());
  return drain(out);
}

Status FrameDecoder::drain(std::vector<DecodedFrame>& out) {
  for (;;) {
    const std::size_t available = buffer_.size() - consumed_;
    if (available < kWireHeaderBytes) {
      return Status::ok();
    }
    const std::uint8_t* header = buffer_.data() + consumed_;
    if (read_u32_le(header) != kWireMagic) {
      return fail(ReasonCode::WireFrameBadMagic, "frame magic mismatch");
    }
    if (read_u16_le(header + 4) != kWireVersion) {
      return fail(ReasonCode::WireFrameBadVersion, "frame version is not supported");
    }
    const std::uint16_t raw_type = read_u16_le(header + 6);
    if (!is_valid_message_type(raw_type)) {
      return fail(ReasonCode::WireFrameBadEnum, "frame type is out of domain");
    }
    if (read_u32_le(header + 8) != 0U) {
      return fail(ReasonCode::WireFrameBadEnum, "frame flags are not understood");
    }
    const std::uint32_t declared = read_u32_le(header + 28);
    if (declared > Maxima::kFramePayload) {
      // Refused before any allocation proportional to the declared length.
      return fail(ReasonCode::WireFrameOversized, "declared payload length exceeds the hard ceiling");
    }
    const std::size_t total = kWireHeaderBytes + static_cast<std::size_t>(declared) + kDigestBytes;
    if (available < total) {
      return Status::ok();
    }
    auto decoded = decode_frame(std::span<const std::uint8_t>(header, total), limits_);
    if (!decoded.has_value()) {
      return fail(ReasonCode::WireFrameBadIntegrity, decoded.detail());
    }
    out.push_back(std::move(decoded).value());
    consumed_ += total;
  }
}

Status FrameDecoder::finish() {
  if (failed_) {
    return Status::failure(Outcome::IntegrityFailure, failure_detail_);
  }
  finished_ = true;
  if (buffer_.size() != consumed_) {
    return fail(ReasonCode::WireFrameTruncated,
                "the stream ended inside a frame; a truncated frame is never accepted");
  }
  return Status::ok();
}


bool ByteReader::reject(ReasonCode reason, std::string detail) {
  return fail(reason, std::move(detail));
}

// ---------------------------------------------------------------------------
// Message payloads.
// ---------------------------------------------------------------------------
namespace {

void write_summary(ByteWriter& writer, const FindingSummary& summary) {
  writer.u64(summary.id.value());
  writer.u64(summary.generation.value());
  writer.u8(static_cast<std::uint8_t>(summary.state));
  writer.u8(static_cast<std::uint8_t>(summary.fence_cause));
  writer.u8(static_cast<std::uint8_t>(summary.assessment_outcome));
  writer.u64(summary.assessment_flags);
  writer.u32(static_cast<std::uint32_t>(summary.witness_count));
  writer.u32(static_cast<std::uint32_t>(summary.implicated_resource_count));
  writer.u8(static_cast<std::uint8_t>(summary.containment_outcome));
  writer.u32(static_cast<std::uint32_t>(summary.target_count));
  writer.digest(summary.content_digest);
}

bool read_summary(ByteReader& reader, FindingSummary& summary) {
  // Every field width here mirrors write_summary exactly. The reply decoder requires the
  // whole payload to be consumed, so any drift is caught immediately rather than
  // producing a plausible-looking but shifted result.
  std::uint32_t witness_count = 0;
  std::uint32_t resource_count = 0;
  std::uint32_t target_count = 0;
  std::uint64_t flags = 0;
  if (!reader.read_id(summary.id) || !reader.read_id(summary.generation) ||
      !read_enum(reader, summary.state) || !read_enum(reader, summary.fence_cause) ||
      !read_enum(reader, summary.assessment_outcome) || !reader.read_u64(flags) ||
      !reader.read_u32(witness_count) || !reader.read_u32(resource_count) ||
      !read_enum(reader, summary.containment_outcome) || !reader.read_u32(target_count)) {
    return false;
  }
  if (flags > 0xFFFF'FFFFULL) {
    return reader.reject(ReasonCode::WireFrameBadEnum, "assessment flags are out of range");
  }
  summary.assessment_flags = static_cast<AssessmentFlags>(flags);
  summary.witness_count = witness_count;
  summary.implicated_resource_count = resource_count;
  summary.target_count = target_count;
  return reader.read_digest(summary.content_digest);
}

}  // namespace

std::vector<std::uint8_t> encode_hello(const HelloMessage& message) {
  ByteWriter writer;
  writer.u16(message.protocol_version);
  writer.u64(message.session.value());
  write_process_identity(writer, message.identity);
  writer.u8(static_cast<std::uint8_t>(message.kind));
  writer.u8(static_cast<std::uint8_t>(message.origin));
  writer.u64(message.nonce);
  writer.u64(message.requested_lease_ticks);
  return std::move(writer).take();
}

Result<HelloMessage> decode_hello(std::span<const std::uint8_t> bytes, const Limits& limits) {
  (void)limits;
  ByteReader reader(bytes);
  HelloMessage message;
  if (!reader.read_u16(message.protocol_version) || !reader.read_id(message.session) ||
      !read_process_identity(reader, message.identity) || !read_enum(reader, message.kind) ||
      !read_enum(reader, message.origin) || !reader.read_u64(message.nonce) ||
      !reader.read_u64(message.requested_lease_ticks)) {
    return Result<HelloMessage>::failure(reader.reason(), reader.detail());
  }
  if (!reader.at_end()) {
    return Result<HelloMessage>::failure(Outcome::Invalid, "hello payload has trailing bytes");
  }
  return Result<HelloMessage>::ok(std::move(message));
}

std::vector<std::uint8_t> encode_hello_ack(const HelloAckMessage& message) {
  ByteWriter writer;
  writer.u16(message.protocol_version);
  writer.u64(message.session.value());
  write_process_identity(writer, message.coordinator);
  writer.raw(encode_fence(message.fence));
  writer.u64(message.accepted_at);
  writer.u64(message.lease_expires_at);
  writer.u8(static_cast<std::uint8_t>(message.outcome));
  writer.u8(static_cast<std::uint8_t>(message.reason));
  writer.text(message.detail, 256);
  return std::move(writer).take();
}

Result<HelloAckMessage> decode_hello_ack(std::span<const std::uint8_t> bytes, const Limits& limits) {
  (void)limits;
  ByteReader reader(bytes);
  HelloAckMessage message;
  if (!reader.read_u16(message.protocol_version) || !reader.read_id(message.session) ||
      !read_process_identity(reader, message.coordinator)) {
    return Result<HelloAckMessage>::failure(reader.reason(), reader.detail());
  }
  auto fence = decode_fence(reader);
  if (!fence.has_value()) {
    return Result<HelloAckMessage>::failure(fence.outcome(), fence.detail());
  }
  message.fence = std::move(fence).value();
  if (!reader.read_u64(message.accepted_at) || !reader.read_u64(message.lease_expires_at) ||
      !read_enum(reader, message.outcome) || !read_enum(reader, message.reason) ||
      !reader.read_text(message.detail, 256)) {
    return Result<HelloAckMessage>::failure(reader.reason(), reader.detail());
  }
  if (!reader.at_end()) {
    return Result<HelloAckMessage>::failure(Outcome::Invalid, "hello ack payload has trailing bytes");
  }
  return Result<HelloAckMessage>::ok(std::move(message));
}

std::vector<std::uint8_t> encode_error(const ErrorMessage& message) {
  ByteWriter writer;
  writer.u8(static_cast<std::uint8_t>(message.outcome));
  writer.u8(static_cast<std::uint8_t>(message.reason));
  writer.u16(static_cast<std::uint16_t>(message.offending_type));
  writer.text(message.detail, 512);
  return std::move(writer).take();
}

Result<ErrorMessage> decode_error(std::span<const std::uint8_t> bytes, const Limits& limits) {
  (void)limits;
  ByteReader reader(bytes);
  ErrorMessage message;
  std::uint16_t raw_type = 0;
  if (!read_enum(reader, message.outcome) || !read_enum(reader, message.reason) ||
      !reader.read_u16(raw_type)) {
    return Result<ErrorMessage>::failure(reader.reason(), reader.detail());
  }
  if (!is_valid_message_type(raw_type)) {
    return Result<ErrorMessage>::failure(Outcome::Invalid, "offending frame type is out of domain");
  }
  message.offending_type = static_cast<MessageType>(raw_type);
  if (!reader.read_text(message.detail, 512)) {
    return Result<ErrorMessage>::failure(reader.reason(), reader.detail());
  }
  if (!reader.at_end()) {
    return Result<ErrorMessage>::failure(Outcome::Invalid, "error payload has trailing bytes");
  }
  return Result<ErrorMessage>::ok(std::move(message));
}

std::vector<std::uint8_t> encode_detect_request(const DetectRequestMessage& message) {
  ByteWriter writer;
  writer.raw(encode_fence(message.fence));
  writer.u64(message.now);
  writer.u32(static_cast<std::uint32_t>(message.selector_scope.size()));
  for (const TrafficSelectorId selector : message.selector_scope) {
    writer.u64(selector.value());
  }
  return std::move(writer).take();
}

Result<DetectRequestMessage> decode_detect_request(std::span<const std::uint8_t> bytes,
                                                   const Limits& limits) {
  ByteReader reader(bytes);
  DetectRequestMessage message;
  auto fence = decode_fence(reader);
  if (!fence.has_value()) {
    return Result<DetectRequestMessage>::failure(fence.outcome(), fence.detail());
  }
  message.fence = std::move(fence).value();
  if (!reader.read_u64(message.now)) {
    return Result<DetectRequestMessage>::failure(reader.reason(), reader.detail());
  }
  std::uint32_t count = 0;
  if (!reader.read_count(count, limits.max_selectors)) {
    return Result<DetectRequestMessage>::failure(reader.reason(), reader.detail());
  }
  for (std::uint32_t index = 0; index < count; ++index) {
    TrafficSelectorId selector;
    if (!reader.read_id(selector)) {
      return Result<DetectRequestMessage>::failure(reader.reason(), reader.detail());
    }
    message.selector_scope.push_back(selector);
  }
  if (!std::is_sorted(message.selector_scope.begin(), message.selector_scope.end())) {
    return Result<DetectRequestMessage>::failure(Outcome::Invalid,
                                                 "selector scope is not in canonical order");
  }
  if (!reader.at_end()) {
    return Result<DetectRequestMessage>::failure(Outcome::Invalid,
                                                 "detect request payload has trailing bytes");
  }
  return Result<DetectRequestMessage>::ok(std::move(message));
}

std::vector<std::uint8_t> encode_assessment_reply(const AssessmentReplyMessage& message,
                                                  const Limits& limits) {
  ByteWriter writer;
  writer.u64(message.assessment.value());
  writer.raw(encode_fence(message.fence));
  writer.u8(static_cast<std::uint8_t>(message.outcome));
  writer.u64(message.flags);
  writer.u32(static_cast<std::uint32_t>(message.witness_count));
  writer.u32(static_cast<std::uint32_t>(message.hop_count));
  writer.u64(message.counters.scc_runs);
  writer.u64(message.counters.nodes_examined);
  writer.u64(message.counters.edges_examined);
  writer.u64(message.counters.steps_used);
  writer.u64(message.counters.cycles_enumerated);
  writer.u64(message.counters.selectors_considered);
  writer.u64(message.counters.witnesses_retained);
  writer.u64(message.counters.witnesses_dropped);
  writer.u64(message.counters.witnesses_validated);
  writer.u64(message.counters.witnesses_rejected);
  writer.u8(static_cast<std::uint8_t>(message.counters.steps_exhausted ? 1 : 0));
  writer.u8(static_cast<std::uint8_t>(message.counters.cycles_exhausted ? 1 : 0));
  writer.u8(static_cast<std::uint8_t>(message.counters.selectors_exhausted ? 1 : 0));
  writer.u8(static_cast<std::uint8_t>(message.counters.witnesses_truncated ? 1 : 0));
  writer.u8(static_cast<std::uint8_t>(message.counters.length_bound_reached ? 1 : 0));
  writer.digest(message.assessment_digest);
  writer.u8(static_cast<std::uint8_t>(message.origin));
  writer.u32(static_cast<std::uint32_t>(message.witnesses.size()));
  for (const std::string& witness : message.witnesses) {
    writer.text(witness, limits.max_text_line);
  }
  writer.text(message.explanation, 4096);
  return std::move(writer).take();
}

Result<AssessmentReplyMessage> decode_assessment_reply(std::span<const std::uint8_t> bytes,
                                                       const Limits& limits) {
  ByteReader reader(bytes);
  AssessmentReplyMessage message;
  std::uint8_t raw = 0;
  if (!reader.read_id(message.assessment)) {
    return Result<AssessmentReplyMessage>::failure(reader.reason(), reader.detail());
  }
  auto fence = decode_fence(reader);
  if (!fence.has_value()) {
    return Result<AssessmentReplyMessage>::failure(fence.outcome(), fence.detail());
  }
  message.fence = std::move(fence).value();
  std::uint64_t flags = 0;
  // The counts are written as u32 by the encoder; reading them as u64 would desynchronise
  // the whole payload. The round-trip suite covers every message for exactly this reason.
  std::uint32_t witness_count = 0;
  std::uint32_t hop_count = 0;
  if (!read_enum(reader, message.outcome) || !reader.read_u64(flags) ||
      !reader.read_u32(witness_count) || !reader.read_u32(hop_count)) {
    return Result<AssessmentReplyMessage>::failure(reader.reason(), reader.detail());
  }
  message.witness_count = witness_count;
  message.hop_count = hop_count;
  if (flags > 0xFFFF'FFFFULL) {
    return Result<AssessmentReplyMessage>::failure(Outcome::Invalid,
                                                   "assessment flags are out of range");
  }
  message.flags = static_cast<AssessmentFlags>(flags);
  SearchCounters& counters = message.counters;
  if (!reader.read_u64(counters.scc_runs) || !reader.read_u64(counters.nodes_examined) ||
      !reader.read_u64(counters.edges_examined) || !reader.read_u64(counters.steps_used) ||
      !reader.read_u64(counters.cycles_enumerated) ||
      !reader.read_u64(counters.selectors_considered) ||
      !reader.read_u64(counters.witnesses_retained) ||
      !reader.read_u64(counters.witnesses_dropped) ||
      !reader.read_u64(counters.witnesses_validated) ||
      !reader.read_u64(counters.witnesses_rejected)) {
    return Result<AssessmentReplyMessage>::failure(reader.reason(), reader.detail());
  }
  for (bool* flag : {&counters.steps_exhausted, &counters.cycles_exhausted,
                     &counters.selectors_exhausted, &counters.witnesses_truncated,
                     &counters.length_bound_reached}) {
    if (!reader.read_u8(raw)) {
      return Result<AssessmentReplyMessage>::failure(reader.reason(), reader.detail());
    }
    if (raw > 1U) {
      return Result<AssessmentReplyMessage>::failure(Outcome::Invalid, "boolean field is not 0 or 1");
    }
    *flag = raw == 1U;
  }
  if (!reader.read_digest(message.assessment_digest) || !read_enum(reader, message.origin)) {
    return Result<AssessmentReplyMessage>::failure(reader.reason(), reader.detail());
  }
  std::uint32_t count = 0;
  if (!reader.read_count(count, limits.max_witnesses_per_assessment)) {
    return Result<AssessmentReplyMessage>::failure(reader.reason(), reader.detail());
  }
  for (std::uint32_t index = 0; index < count; ++index) {
    std::string witness;
    if (!reader.read_text(witness, limits.max_text_line)) {
      return Result<AssessmentReplyMessage>::failure(reader.reason(), reader.detail());
    }
    message.witnesses.push_back(std::move(witness));
  }
  if (!reader.read_text(message.explanation, 4096)) {
    return Result<AssessmentReplyMessage>::failure(reader.reason(), reader.detail());
  }
  if (!reader.at_end()) {
    return Result<AssessmentReplyMessage>::failure(Outcome::Invalid,
                                                   "assessment reply has trailing bytes");
  }
  return Result<AssessmentReplyMessage>::ok(std::move(message));
}

std::vector<std::uint8_t> encode_plan_reply(const PlanReplyMessage& message, const Limits& limits) {
  ByteWriter writer;
  writer.u64(message.plan.value());
  writer.u64(message.assessment.value());
  writer.raw(encode_fence(message.fence));
  writer.u8(static_cast<std::uint8_t>(message.outcome));
  writer.u64(message.flags);
  writer.u32(static_cast<std::uint32_t>(message.targets.size()));
  for (const ResourceId target : message.targets) {
    writer.u64(target.value());
  }
  writer.u64(message.total_cost);
  writer.u32(message.witness_count);
  writer.u32(message.witnesses_covered);
  writer.digest(message.plan_digest);
  writer.text(message.explanation, limits.max_text_line * 8U);
  return std::move(writer).take();
}

Result<PlanReplyMessage> decode_plan_reply(std::span<const std::uint8_t> bytes,
                                           const Limits& limits) {
  ByteReader reader(bytes);
  PlanReplyMessage message;
  if (!reader.read_id(message.plan) || !reader.read_id(message.assessment)) {
    return Result<PlanReplyMessage>::failure(reader.reason(), reader.detail());
  }
  auto fence = decode_fence(reader);
  if (!fence.has_value()) {
    return Result<PlanReplyMessage>::failure(fence.outcome(), fence.detail());
  }
  message.fence = std::move(fence).value();
  std::uint64_t flags = 0;
  if (!read_enum(reader, message.outcome) || !reader.read_u64(flags)) {
    return Result<PlanReplyMessage>::failure(reader.reason(), reader.detail());
  }
  if (flags > 0xFFFF'FFFFULL) {
    return Result<PlanReplyMessage>::failure(Outcome::Invalid, "plan flags are out of range");
  }
  message.flags = static_cast<PlanFlags>(flags);
  std::uint32_t count = 0;
  if (!reader.read_count(count, limits.max_plan_targets)) {
    return Result<PlanReplyMessage>::failure(reader.reason(), reader.detail());
  }
  for (std::uint32_t index = 0; index < count; ++index) {
    ResourceId target;
    if (!reader.read_id(target)) {
      return Result<PlanReplyMessage>::failure(reader.reason(), reader.detail());
    }
    message.targets.push_back(target);
  }
  if (!reader.read_u64(message.total_cost) || !reader.read_u32(message.witness_count) ||
      !reader.read_u32(message.witnesses_covered) || !reader.read_digest(message.plan_digest) ||
      !reader.read_text(message.explanation, limits.max_text_line * 8U)) {
    return Result<PlanReplyMessage>::failure(reader.reason(), reader.detail());
  }
  if (!reader.at_end()) {
    return Result<PlanReplyMessage>::failure(Outcome::Invalid, "plan reply has trailing bytes");
  }
  return Result<PlanReplyMessage>::ok(std::move(message));
}

std::vector<std::uint8_t> encode_contain_intent(const ContainIntentMessage& message,
                                                const Limits& limits) {
  ByteWriter writer;
  writer.u64(message.intent.value());
  writer.u64(message.plan.value());
  writer.u64(message.finding.value());
  writer.raw(encode_fence(message.fence));
  write_process_identity(writer, message.issued_by);
  writer.u32(static_cast<std::uint32_t>(message.targets.size()));
  for (const ResourceId target : message.targets) {
    writer.u64(target.value());
  }
  writer.u32(static_cast<std::uint32_t>(message.selectors.size()));
  for (const TrafficSelectorId selector : message.selectors) {
    writer.u64(selector.value());
  }
  writer.u64(message.issued_at);
  writer.u64(message.expires_at);
  writer.digest(message.plan_digest);
  (void)limits;
  return std::move(writer).take();
}

Result<ContainIntentMessage> decode_contain_intent(std::span<const std::uint8_t> bytes,
                                                   const Limits& limits) {
  ByteReader reader(bytes);
  ContainIntentMessage message;
  if (!reader.read_id(message.intent) || !reader.read_id(message.plan) ||
      !reader.read_id(message.finding)) {
    return Result<ContainIntentMessage>::failure(reader.reason(), reader.detail());
  }
  auto fence = decode_fence(reader);
  if (!fence.has_value()) {
    return Result<ContainIntentMessage>::failure(fence.outcome(), fence.detail());
  }
  message.fence = std::move(fence).value();
  if (!read_process_identity(reader, message.issued_by)) {
    return Result<ContainIntentMessage>::failure(reader.reason(), reader.detail());
  }
  std::uint32_t count = 0;
  if (!reader.read_count(count, limits.max_plan_targets)) {
    return Result<ContainIntentMessage>::failure(reader.reason(), reader.detail());
  }
  for (std::uint32_t index = 0; index < count; ++index) {
    ResourceId target;
    if (!reader.read_id(target)) {
      return Result<ContainIntentMessage>::failure(reader.reason(), reader.detail());
    }
    message.targets.push_back(target);
  }
  if (!reader.read_count(count, limits.max_selectors)) {
    return Result<ContainIntentMessage>::failure(reader.reason(), reader.detail());
  }
  for (std::uint32_t index = 0; index < count; ++index) {
    TrafficSelectorId selector;
    if (!reader.read_id(selector)) {
      return Result<ContainIntentMessage>::failure(reader.reason(), reader.detail());
    }
    message.selectors.push_back(selector);
  }
  if (!reader.read_u64(message.issued_at) || !reader.read_u64(message.expires_at) ||
      !reader.read_digest(message.plan_digest)) {
    return Result<ContainIntentMessage>::failure(reader.reason(), reader.detail());
  }
  if (message.expires_at < message.issued_at) {
    return Result<ContainIntentMessage>::failure(Outcome::Invalid, "intent lease window is inverted");
  }
  if (!reader.at_end()) {
    return Result<ContainIntentMessage>::failure(Outcome::Invalid, "intent has trailing bytes");
  }
  return Result<ContainIntentMessage>::ok(std::move(message));
}

std::vector<std::uint8_t> encode_contain_ack(const ContainAckMessage& message, const Limits& limits) {
  ByteWriter writer;
  writer.u64(message.intent.value());
  writer.u64(message.session.value());
  write_process_identity(writer, message.applier);
  writer.u64(message.sequence.value());
  writer.u64(message.acknowledged_at);
  writer.digest(message.intent_digest);
  writer.u8(static_cast<std::uint8_t>(message.outcome));
  writer.u8(static_cast<std::uint8_t>(message.reason));
  writer.text(message.detail, limits.max_text_line);
  return std::move(writer).take();
}

Result<ContainAckMessage> decode_contain_ack(std::span<const std::uint8_t> bytes,
                                             const Limits& limits) {
  ByteReader reader(bytes);
  ContainAckMessage message;
  if (!reader.read_id(message.intent) || !reader.read_id(message.session) ||
      !read_process_identity(reader, message.applier) || !reader.read_id(message.sequence) ||
      !reader.read_u64(message.acknowledged_at) || !reader.read_digest(message.intent_digest) ||
      !read_enum(reader, message.outcome) || !read_enum(reader, message.reason) ||
      !reader.read_text(message.detail, limits.max_text_line)) {
    return Result<ContainAckMessage>::failure(reader.reason(), reader.detail());
  }
  if (!reader.at_end()) {
    return Result<ContainAckMessage>::failure(Outcome::Invalid, "acknowledgement has trailing bytes");
  }
  return Result<ContainAckMessage>::ok(std::move(message));
}

std::vector<std::uint8_t> encode_effect_report(const EffectReportMessage& message,
                                               const Limits& limits) {
  ByteWriter writer;
  writer.u64(message.intent.value());
  writer.u64(message.target.value());
  writer.u64(message.observation.value());
  writer.raw(encode_fence(message.fence));
  writer.u64(message.verified_at);
  writer.u8(static_cast<std::uint8_t>(message.origin));
  writer.boolean(message.has_observation);
  if (message.has_observation) {
    const std::vector<std::uint8_t> encoded = encode_observation(message.observation_payload, limits);
    writer.u32(static_cast<std::uint32_t>(encoded.size()));
    writer.raw(encoded);
  }
  return std::move(writer).take();
}

Result<EffectReportMessage> decode_effect_report(std::span<const std::uint8_t> bytes,
                                                 const Limits& limits) {
  ByteReader reader(bytes);
  EffectReportMessage message;
  if (!reader.read_id(message.intent) || !reader.read_id(message.target) ||
      !reader.read_id(message.observation)) {
    return Result<EffectReportMessage>::failure(reader.reason(), reader.detail());
  }
  auto fence = decode_fence(reader);
  if (!fence.has_value()) {
    return Result<EffectReportMessage>::failure(fence.outcome(), fence.detail());
  }
  message.fence = std::move(fence).value();
  if (!reader.read_u64(message.verified_at) || !read_enum(reader, message.origin) ||
      !reader.read_bool(message.has_observation)) {
    return Result<EffectReportMessage>::failure(reader.reason(), reader.detail());
  }
  if (message.has_observation) {
    std::uint32_t size = 0;
    if (!reader.read_u32(size) || size > Maxima::kFramePayload) {
      return Result<EffectReportMessage>::failure(Outcome::Invalid,
                                                  "embedded observation length is out of range");
    }
    std::vector<std::uint8_t> blob;
    if (!reader.read_raw(blob, size)) {
      return Result<EffectReportMessage>::failure(reader.reason(), reader.detail());
    }
    auto decoded = decode_observation(blob, limits);
    if (!decoded.has_value()) {
      return Result<EffectReportMessage>::failure(decoded.outcome(), decoded.detail());
    }
    message.observation_payload = std::move(decoded).value();
  }
  if (!reader.at_end()) {
    return Result<EffectReportMessage>::failure(Outcome::Invalid, "effect report has trailing bytes");
  }
  return Result<EffectReportMessage>::ok(std::move(message));
}

std::vector<std::uint8_t> encode_finding_reply(const FindingReplyMessage& message,
                                               const Limits& limits) {
  ByteWriter writer;
  writer.u32(static_cast<std::uint32_t>(message.findings.size()));
  for (const FindingSummary& summary : message.findings) {
    write_summary(writer, summary);
  }
  writer.digest(message.runtime_state_digest);
  (void)limits;
  return std::move(writer).take();
}

Result<FindingReplyMessage> decode_finding_reply(std::span<const std::uint8_t> bytes,
                                                 const Limits& limits) {
  ByteReader reader(bytes);
  FindingReplyMessage message;
  std::uint32_t count = 0;
  if (!reader.read_count(count, limits.max_retained_findings)) {
    return Result<FindingReplyMessage>::failure(reader.reason(), reader.detail());
  }
  for (std::uint32_t index = 0; index < count; ++index) {
    FindingSummary summary;
    if (!read_summary(reader, summary)) {
      return Result<FindingReplyMessage>::failure(reader.reason(), reader.detail());
    }
    message.findings.push_back(summary);
  }
  if (!reader.read_digest(message.runtime_state_digest)) {
    return Result<FindingReplyMessage>::failure(reader.reason(), reader.detail());
  }
  if (!reader.at_end()) {
    return Result<FindingReplyMessage>::failure(Outcome::Invalid, "finding reply has trailing bytes");
  }
  return Result<FindingReplyMessage>::ok(std::move(message));
}

std::vector<std::uint8_t> encode_state_digest_reply(const StateDigestReplyMessage& message) {
  ByteWriter writer;
  writer.digest(message.store_digest);
  writer.digest(message.fence_digest);
  writer.raw(encode_fence(message.fence));
  writer.u64(message.finding_count);
  writer.u64(message.lineage_count);
  writer.u64(message.observation_count);
  writer.u64(message.retained_attempts);
  return std::move(writer).take();
}

Result<StateDigestReplyMessage> decode_state_digest_reply(std::span<const std::uint8_t> bytes,
                                                          const Limits& limits) {
  (void)limits;
  ByteReader reader(bytes);
  StateDigestReplyMessage message;
  if (!reader.read_digest(message.store_digest) || !reader.read_digest(message.fence_digest)) {
    return Result<StateDigestReplyMessage>::failure(reader.reason(), reader.detail());
  }
  auto fence = decode_fence(reader);
  if (!fence.has_value()) {
    return Result<StateDigestReplyMessage>::failure(fence.outcome(), fence.detail());
  }
  message.fence = std::move(fence).value();
  if (!reader.read_u64(message.finding_count) || !reader.read_u64(message.lineage_count) ||
      !reader.read_u64(message.observation_count) || !reader.read_u64(message.retained_attempts)) {
    return Result<StateDigestReplyMessage>::failure(reader.reason(), reader.detail());
  }
  if (!reader.at_end()) {
    return Result<StateDigestReplyMessage>::failure(Outcome::Invalid,
                                                    "state digest reply has trailing bytes");
  }
  return Result<StateDigestReplyMessage>::ok(std::move(message));
}

std::vector<std::uint8_t> encode_restart_report(const RestartReportMessage& message) {
  ByteWriter writer;
  writer.u64(message.boot.value());
  writer.u64(message.incarnation.value());
  writer.u64(message.epoch.value());
  writer.boolean(message.torn_tail_recovered);
  writer.u32(message.fenced_findings);
  writer.u32(message.dropped_findings);
  writer.u32(message.retained_findings);
  writer.u32(message.lineage_records);
  writer.digest(message.store_digest);
  return std::move(writer).take();
}

Result<RestartReportMessage> decode_restart_report(std::span<const std::uint8_t> bytes,
                                                   const Limits& limits) {
  (void)limits;
  ByteReader reader(bytes);
  RestartReportMessage message;
  if (!reader.read_id(message.boot) || !reader.read_id(message.incarnation) ||
      !reader.read_id(message.epoch) || !reader.read_bool(message.torn_tail_recovered) ||
      !reader.read_u32(message.fenced_findings) || !reader.read_u32(message.dropped_findings) ||
      !reader.read_u32(message.retained_findings) || !reader.read_u32(message.lineage_records) ||
      !reader.read_digest(message.store_digest)) {
    return Result<RestartReportMessage>::failure(reader.reason(), reader.detail());
  }
  if (!reader.at_end()) {
    return Result<RestartReportMessage>::failure(Outcome::Invalid,
                                                 "restart report has trailing bytes");
  }
  return Result<RestartReportMessage>::ok(std::move(message));
}

}  // namespace loop_guard
