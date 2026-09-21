// Loop Guard - bounded framed protocol.
//
// Every frame is magic-prefixed, version-tagged, explicitly typed and explicitly
// length-prefixed. A declared length is refused before any allocation proportional to
// it happens. Decoding is total and sticky: the first violation fails the decoder
// permanently, and a failed decoder never yields another frame.
//
// The frame digest is an integrity check, not authentication. Loop Guard does not
// implement cryptography and does not claim secure transport; the trust boundary is
// stated in README.md.
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "loop_guard/authority.hpp"
#include "loop_guard/containment.hpp"
#include "loop_guard/core.hpp"
#include "loop_guard/detect.hpp"
#include "loop_guard/digest.hpp"
#include "loop_guard/enums.hpp"
#include "loop_guard/evidence.hpp"
#include "loop_guard/finding.hpp"
#include "loop_guard/id.hpp"
#include "loop_guard/limits.hpp"
#include "loop_guard/persistence.hpp"
#include "loop_guard/result.hpp"
#include "loop_guard/topology.hpp"

namespace loop_guard {

inline constexpr std::uint32_t kWireMagic = 0x3147574CU;  // "LWG1"
inline constexpr std::uint16_t kWireVersion = 1;
inline constexpr std::size_t kWireHeaderBytes = 32;
inline constexpr std::size_t kWireFrameOverhead = kWireHeaderBytes + kDigestBytes;

enum class MessageType : std::uint16_t {
  Hello = 0,
  HelloAck = 1,
  Bye = 2,
  Error = 3,
  SetTopology = 4,
  SetPolicy = 5,
  ConfigurationAccepted = 6,
  SubmitObservation = 7,
  ObservationAccepted = 8,
  DetectRequest = 9,
  AssessmentReply = 10,
  PlanRequest = 11,
  PlanReply = 12,
  ContainIntent = 13,
  ContainAck = 14,
  EffectReport = 15,
  FindingQuery = 16,
  FindingReply = 17,
  FindingWithdraw = 18,
  StateDigestRequest = 19,
  StateDigestReply = 20,
  FenceAdvance = 21,
  RestartReportRequest = 22,
  RestartReportReply = 23,
  /// Operator request: publish a finding for the assessment this session last produced.
  FindingPublish = 24,
  /// Operator request: authorize a bounded containment intent for a finding and dispatch
  /// it to the worker sessions. Authorization is not application.
  ContainAuthorize = 25,
};

[[nodiscard]] bool is_valid_message_type(std::uint16_t raw) noexcept;
[[nodiscard]] std::string_view to_string(MessageType type) noexcept;
/// Message types an unauthenticated (pre-handshake) peer is permitted to send.
[[nodiscard]] bool allowed_before_handshake(MessageType type) noexcept;

struct FrameHeader {
  std::uint32_t magic = kWireMagic;
  std::uint16_t version = kWireVersion;
  MessageType type = MessageType::Hello;
  std::uint32_t flags = 0;
  SessionId session;
  std::uint64_t sequence = 0;
  std::uint32_t payload_length = 0;

  [[nodiscard]] Digest header_digest() const;
  friend bool operator==(const FrameHeader&, const FrameHeader&) noexcept = default;
};

struct DecodedFrame {
  FrameHeader header;
  std::vector<std::uint8_t> payload;
};

/// Serialises a frame: header, payload, trailing integrity digest over header+payload.
/// Refuses a payload larger than Maxima::kFramePayload.
[[nodiscard]] Result<std::vector<std::uint8_t>> encode_frame(MessageType type, SessionId session,
                                                             std::uint64_t sequence,
                                                             std::span<const std::uint8_t> payload,
                                                             std::uint32_t flags = 0);

/// Decodes exactly one frame from the front of \p bytes. Trailing bytes after the
/// frame are reported as an error rather than ignored.
[[nodiscard]] Result<DecodedFrame> decode_frame(std::span<const std::uint8_t> bytes,
                                                const Limits& limits = default_limits());

/// Incremental, sticky frame decoder for a stream.
class FrameDecoder {
 public:
  explicit FrameDecoder(const Limits& limits = default_limits());

  /// Feeds bytes and appends every complete frame to \p out. Returns a failure once
  /// the decoder is failed; afterwards every call fails identically.
  [[nodiscard]] Status feed(std::span<const std::uint8_t> bytes, std::vector<DecodedFrame>& out);
  /// Declares the stream finished. Any buffered partial frame is a truncation failure.
  [[nodiscard]] Status finish();

  [[nodiscard]] bool failed() const noexcept { return failed_; }
  [[nodiscard]] ReasonCode failure_reason() const noexcept { return failure_reason_; }
  [[nodiscard]] const std::string& failure_detail() const noexcept { return failure_detail_; }
  [[nodiscard]] std::size_t buffered() const noexcept { return buffer_.size(); }

 private:
  [[nodiscard]] Status fail(ReasonCode reason, std::string detail);
  [[nodiscard]] Status drain(std::vector<DecodedFrame>& out);

  Limits limits_;
  std::vector<std::uint8_t> buffer_;
  std::size_t consumed_ = 0;
  bool failed_ = false;
  bool finished_ = false;
  ReasonCode failure_reason_ = ReasonCode::WireFrameAccepted;
  std::string failure_detail_;
};

// ---------------------------------------------------------------------------
// Canonical byte codec. Little-endian, fixed width, no padding, no varints.
// Every read validates its own bounds; a reader that fails stays failed.
// ---------------------------------------------------------------------------
class ByteWriter {
 public:
  void u8(std::uint8_t value);
  void u16(std::uint16_t value);
  void u32(std::uint32_t value);
  void u64(std::uint64_t value);
  void boolean(bool value);
  void raw(std::span<const std::uint8_t> bytes);
  void digest(const Digest& value);
  /// Writes any strongly typed identity or generation as a fixed-width u64. The type
  /// tag is erased on the wire; the decoder re-applies the expected tag, so an
  /// identity can never be read back as a different kind of identity.
  template <class Id>
  void id(Id value) {
    u64(value.value());
  }
  void text(std::string_view value, std::size_t max_bytes);
  /// Reserves a u32 length slot and returns its offset for a later patch_length().
  [[nodiscard]] std::size_t reserve_length();
  void patch_length(std::size_t offset);
  [[nodiscard]] const std::vector<std::uint8_t>& data() const noexcept { return data_; }
  [[nodiscard]] std::vector<std::uint8_t> take() && { return std::move(data_); }
  [[nodiscard]] std::size_t size() const noexcept { return data_.size(); }
  [[nodiscard]] bool overflowed() const noexcept { return overflowed_; }

 private:
  std::vector<std::uint8_t> data_;
  bool overflowed_ = false;
};

class ByteReader {
 public:
  explicit ByteReader(std::span<const std::uint8_t> bytes) : bytes_(bytes) {}

  [[nodiscard]] bool ok() const noexcept { return ok_; }
  [[nodiscard]] bool at_end() const noexcept { return ok_ && position_ == bytes_.size(); }
  [[nodiscard]] std::size_t remaining() const noexcept {
    return ok_ ? bytes_.size() - position_ : 0;
  }
  [[nodiscard]] std::size_t position() const noexcept { return position_; }
  [[nodiscard]] ReasonCode reason() const noexcept { return reason_; }
  [[nodiscard]] const std::string& detail() const noexcept { return detail_; }

  bool read_u8(std::uint8_t& out);
  bool read_u16(std::uint16_t& out);
  bool read_u32(std::uint32_t& out);
  bool read_u64(std::uint64_t& out);
  bool read_bool(bool& out);
  bool read_raw(std::vector<std::uint8_t>& out, std::size_t max_bytes);
  bool read_digest(Digest& out);
  bool read_text(std::string& out, std::size_t max_bytes);
  /// Reads a length-prefixed element count, refusing counts above the ceiling before any
  /// container is resized.
  bool read_count(std::uint32_t& out, std::uint32_t max_count);
  /// Marks the reader failed with a specific reason. Used by decoders that detect a
  /// domain violation the primitive readers cannot see.
  bool reject(ReasonCode reason, std::string detail);

  template <class Id>
  bool read_id(Id& out) {
    std::uint64_t raw = 0;
    if (!read_u64(raw)) {
      return false;
    }
    out = Id::from_value(raw);
    return true;
  }

 private:
  bool fail(ReasonCode reason, std::string detail);

  std::span<const std::uint8_t> bytes_;
  std::size_t position_ = 0;
  bool ok_ = true;
  ReasonCode reason_ = ReasonCode::WireFrameAccepted;
  std::string detail_;
};

// ---------------------------------------------------------------------------
// Message payloads.
// ---------------------------------------------------------------------------
struct HelloMessage {
  std::uint16_t protocol_version = kWireVersion;
  SessionId session;
  ProcessIdentity identity;
  ProducerKind kind = ProducerKind::RemoteWorker;
  EvidenceOrigin origin = EvidenceOrigin::Real;
  std::uint64_t nonce = 0;
  Tick requested_lease_ticks = 0;
};

struct HelloAckMessage {
  std::uint16_t protocol_version = kWireVersion;
  SessionId session;
  ProcessIdentity coordinator;
  /// The coordinator's fence at handshake time. Any request whose vector disagrees is
  /// refused as Stale rather than reinterpreted.
  FenceVector fence;
  Tick accepted_at = 0;
  Tick lease_expires_at = 0;
  Outcome outcome = Outcome::Ok;
  ReasonCode reason = ReasonCode::WireFrameAccepted;
  std::string detail;
};

struct ErrorMessage {
  Outcome outcome = Outcome::Invalid;
  ReasonCode reason = ReasonCode::RequestRejectedStructural;
  MessageType offending_type = MessageType::Hello;
  std::string detail;
};

struct DetectRequestMessage {
  FenceVector fence;
  Tick now = 0;
  std::vector<TrafficSelectorId> selector_scope;
};

struct AssessmentReplyMessage {
  AssessmentId assessment;
  FenceVector fence;
  LoopOutcome outcome = LoopOutcome::Invalid;
  AssessmentFlags flags = kAssessmentNone;
  std::size_t witness_count = 0;
  std::size_t hop_count = 0;
  SearchCounters counters;
  Digest assessment_digest;
  EvidenceOrigin origin = EvidenceOrigin::Synthetic;
  /// Canonical witness documents, bounded in count and rendered as text so that the
  /// reply stays small and human-auditable.
  std::vector<std::string> witnesses;
  std::string explanation;
};

struct PlanRequestMessage {
  AssessmentId assessment;
  FenceVector fence;
  Tick now = 0;
};

struct PlanReplyMessage {
  ContainmentPlanId plan;
  AssessmentId assessment;
  FenceVector fence;
  ContainmentOutcome outcome = ContainmentOutcome::Invalid;
  PlanFlags flags = kPlanNone;
  std::vector<ResourceId> targets;
  std::uint64_t total_cost = 0;
  std::uint32_t witness_count = 0;
  std::uint32_t witnesses_covered = 0;
  Digest plan_digest;
  std::string explanation;
};

struct ContainIntentMessage {
  ContainmentIntentId intent;
  ContainmentPlanId plan;
  FindingId finding;
  FenceVector fence;
  ProcessIdentity issued_by;
  std::vector<ResourceId> targets;
  std::vector<TrafficSelectorId> selectors;
  Tick issued_at = 0;
  Tick expires_at = 0;
  Digest plan_digest;
};

struct ContainAckMessage {
  ContainmentIntentId intent;
  SessionId session;
  ProcessIdentity applier;
  ProducerSequence sequence;
  Tick acknowledged_at = 0;
  Digest intent_digest;
  Outcome outcome = Outcome::Ok;
  ReasonCode reason = ReasonCode::RequestAccepted;
  std::string detail;
};

struct EffectReportMessage {
  ContainmentIntentId intent;
  ResourceId target;
  ObservationId observation;
  FenceVector fence;
  Tick verified_at = 0;
  EvidenceOrigin origin = EvidenceOrigin::Synthetic;
  ForwardingObservation observation_payload;
  bool has_observation = false;
};

struct FindingQueryMessage {
  bool all = true;
  FindingId id;
};

struct FindingReplyMessage {
  std::vector<FindingSummary> findings;
  Digest runtime_state_digest;
};

struct StateDigestReplyMessage {
  Digest store_digest;
  Digest fence_digest;
  FenceVector fence;
  std::uint64_t finding_count = 0;
  std::uint64_t lineage_count = 0;
  std::uint64_t observation_count = 0;
  std::uint64_t retained_attempts = 0;
};

struct FenceAdvanceMessage {
  FenceVector fence;
  ReasonCode cause = ReasonCode::FindingFencedByGenerationChange;
  Tick now = 0;
};

struct RestartReportMessage {
  BootId boot;
  IncarnationId incarnation;
  CoordinatorEpoch epoch;
  bool torn_tail_recovered = false;
  std::uint32_t fenced_findings = 0;
  std::uint32_t dropped_findings = 0;
  std::uint32_t retained_findings = 0;
  std::uint32_t lineage_records = 0;
  Digest store_digest;
};

// Canonical encode/decode. Decoding validates every enum, range, count and bound.
[[nodiscard]] std::vector<std::uint8_t> encode_hello(const HelloMessage& message);
[[nodiscard]] Result<HelloMessage> decode_hello(std::span<const std::uint8_t> bytes,
                                                const Limits& limits);
[[nodiscard]] std::vector<std::uint8_t> encode_hello_ack(const HelloAckMessage& message);
[[nodiscard]] Result<HelloAckMessage> decode_hello_ack(std::span<const std::uint8_t> bytes,
                                                       const Limits& limits);
[[nodiscard]] std::vector<std::uint8_t> encode_error(const ErrorMessage& message);
[[nodiscard]] Result<ErrorMessage> decode_error(std::span<const std::uint8_t> bytes,
                                                const Limits& limits);
[[nodiscard]] std::vector<std::uint8_t> encode_detect_request(const DetectRequestMessage& message);
[[nodiscard]] Result<DetectRequestMessage> decode_detect_request(std::span<const std::uint8_t> bytes,
                                                                 const Limits& limits);
[[nodiscard]] std::vector<std::uint8_t> encode_assessment_reply(const AssessmentReplyMessage& message,
                                                                const Limits& limits);
[[nodiscard]] Result<AssessmentReplyMessage> decode_assessment_reply(
    std::span<const std::uint8_t> bytes, const Limits& limits);
[[nodiscard]] std::vector<std::uint8_t> encode_plan_reply(const PlanReplyMessage& message,
                                                          const Limits& limits);
[[nodiscard]] Result<PlanReplyMessage> decode_plan_reply(std::span<const std::uint8_t> bytes,
                                                         const Limits& limits);
[[nodiscard]] std::vector<std::uint8_t> encode_contain_intent(const ContainIntentMessage& message,
                                                              const Limits& limits);
[[nodiscard]] Result<ContainIntentMessage> decode_contain_intent(std::span<const std::uint8_t> bytes,
                                                                 const Limits& limits);
[[nodiscard]] std::vector<std::uint8_t> encode_contain_ack(const ContainAckMessage& message,
                                                           const Limits& limits);
[[nodiscard]] Result<ContainAckMessage> decode_contain_ack(std::span<const std::uint8_t> bytes,
                                                           const Limits& limits);
[[nodiscard]] std::vector<std::uint8_t> encode_effect_report(const EffectReportMessage& message,
                                                             const Limits& limits);
[[nodiscard]] Result<EffectReportMessage> decode_effect_report(std::span<const std::uint8_t> bytes,
                                                               const Limits& limits);
[[nodiscard]] std::vector<std::uint8_t> encode_finding_reply(const FindingReplyMessage& message,
                                                             const Limits& limits);
[[nodiscard]] Result<FindingReplyMessage> decode_finding_reply(std::span<const std::uint8_t> bytes,
                                                               const Limits& limits);
[[nodiscard]] std::vector<std::uint8_t> encode_state_digest_reply(
    const StateDigestReplyMessage& message);
[[nodiscard]] Result<StateDigestReplyMessage> decode_state_digest_reply(
    std::span<const std::uint8_t> bytes, const Limits& limits);
[[nodiscard]] std::vector<std::uint8_t> encode_restart_report(const RestartReportMessage& message);
[[nodiscard]] Result<RestartReportMessage> decode_restart_report(
    std::span<const std::uint8_t> bytes, const Limits& limits);
[[nodiscard]] std::vector<std::uint8_t> encode_topology(const TopologyDefinition& topology,
                                                        const Limits& limits);
[[nodiscard]] Result<TopologyDefinition> decode_topology(std::span<const std::uint8_t> bytes,
                                                         const Limits& limits);
[[nodiscard]] std::vector<std::uint8_t> encode_policy(const ContainmentPolicy& policy,
                                                      const Limits& limits);
[[nodiscard]] Result<ContainmentPolicy> decode_policy(std::span<const std::uint8_t> bytes,
                                                      const Limits& limits);
[[nodiscard]] std::vector<std::uint8_t> encode_observation(const ForwardingObservation& observation,
                                                           const Limits& limits);
[[nodiscard]] Result<ForwardingObservation> decode_observation(std::span<const std::uint8_t> bytes,
                                                               const Limits& limits);
[[nodiscard]] std::vector<std::uint8_t> encode_fence(const FenceVector& fence);
[[nodiscard]] Result<FenceVector> decode_fence(ByteReader& reader);

/// Shared helpers used by both the wire and the durable codec so that the two cannot
/// drift apart.
void write_process_identity(ByteWriter& writer, const ProcessIdentity& identity);
[[nodiscard]] bool read_process_identity(ByteReader& reader, ProcessIdentity& identity);

}  // namespace loop_guard
