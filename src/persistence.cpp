#include "loop_guard/persistence.hpp"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <string>
#include <system_error>
#include <vector>

#include "loop_guard/wire.hpp"

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <io.h>
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace loop_guard {
namespace {

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

Status flush_and_sync(std::FILE* handle) {
  if (std::fflush(handle) != 0) {
    return Status::failure(Outcome::IoFailure, "fflush failed");
  }
#if defined(_WIN32)
  const int descriptor = _fileno(handle);
  if (descriptor < 0) {
    return Status::failure(Outcome::IoFailure, "invalid file descriptor");
  }
  if (_commit(descriptor) != 0) {
    return Status::failure(Outcome::IoFailure, "_commit failed");
  }
#else
  const int descriptor = fileno(handle);
  if (descriptor < 0) {
    return Status::failure(Outcome::IoFailure, "invalid file descriptor");
  }
  if (fsync(descriptor) != 0) {
    return Status::failure(Outcome::IoFailure, "fsync failed");
  }
#endif
  return Status::ok();
}

Status truncate_at(std::FILE* handle, std::uint64_t size) {
#if defined(_WIN32)
  const int descriptor = _fileno(handle);
  if (descriptor < 0 || _chsize_s(descriptor, static_cast<__int64>(size)) != 0) {
    return Status::failure(Outcome::IoFailure, "truncate failed");
  }
#else
  const int descriptor = fileno(handle);
  if (descriptor < 0 || ftruncate(descriptor, static_cast<off_t>(size)) != 0) {
    return Status::failure(Outcome::IoFailure, "truncate failed");
  }
#endif
  return Status::ok();
}

Status rename_over(const std::string& from, const std::string& to) {
#if defined(_WIN32)
  if (MoveFileExA(from.c_str(), to.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) ==
      0) {
    return Status::failure(Outcome::IoFailure, "atomic replace failed");
  }
  return Status::ok();
#else
  std::error_code error;
  std::filesystem::rename(from, to, error);
  if (error) {
    return Status::failure(Outcome::IoFailure, "atomic replace failed: " + error.message());
  }
  return Status::ok();
#endif
}

std::string unique_suffix() {
  static std::uint64_t counter = 0;
  ++counter;
  const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
  return std::to_string(static_cast<std::uint64_t>(now)) + "-" + std::to_string(counter);
}

bool write_all(std::FILE* handle, const std::uint8_t* data, std::size_t size) {
  std::size_t written = 0;
  while (written < size) {
    const std::size_t chunk = std::fwrite(data + written, 1, size - written, handle);
    if (chunk == 0U) {
      return false;
    }
    written += chunk;
  }
  return true;
}

void write_blob(ByteWriter& writer, const std::vector<std::uint8_t>& blob) {
  writer.u32(static_cast<std::uint32_t>(blob.size()));
  writer.raw(blob);
}

}  // namespace

// ---------------------------------------------------------------------------
// Small helpers.
// ---------------------------------------------------------------------------
Tick monotonic_tick() noexcept {
  const auto now = std::chrono::steady_clock::now().time_since_epoch();
  return static_cast<Tick>(std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
}

bool is_valid_record_type(std::uint16_t raw) noexcept {
  return raw <= static_cast<std::uint16_t>(RecordType::Note);
}

std::string_view to_string(RecordType type) noexcept {
  switch (type) {
    case RecordType::Snapshot:
      return "Snapshot";
    case RecordType::TopologyDefinition:
      return "TopologyDefinition";
    case RecordType::ContainmentPolicyRecord:
      return "ContainmentPolicy";
    case RecordType::LineageAppend:
      return "LineageAppend";
    case RecordType::FindingUpsert:
      return "FindingUpsert";
    case RecordType::FindingWithdraw:
      return "FindingWithdraw";
    case RecordType::BootAdvance:
      return "BootAdvance";
    case RecordType::FenceAdvance:
      return "FenceAdvance";
    case RecordType::Note:
      return "Note";
  }
  return "Invalid";
}

Digest BootRecord::content_digest() const {
  Sha256 hasher;
  const std::uint64_t fields[7] = {id.value(),   boot.value(),      incarnation.value(),
                                   epoch.value(), producer.value(), started_at,
                                   closed_at};
  for (const std::uint64_t field : fields) {
    hasher.update(
        std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(&field), sizeof(field)));
  }
  hasher.update(static_cast<std::uint8_t>(clean_shutdown ? 1 : 0));
  return hasher.finish();
}

std::string RecoveryReport::to_text() const {
  std::string out = "recovery outcome=" + std::string(to_string(outcome)) +
                    " records=" + std::to_string(records_read) +
                    " applied=" + std::to_string(records_applied) +
                    " bytes=" + std::to_string(bytes_read) +
                    " torn_tail=" + (torn_tail_recovered ? "yes" : "no") +
                    " torn_bytes=" + std::to_string(torn_tail_bytes) +
                    " trailing_garbage=" + (trailing_garbage ? "yes" : "no") +
                    " compacted=" + (snapshot_compacted ? "yes" : "no") + "\n";
  out += explanation.to_text();
  return out;
}

Digest StoreState::digest() const {
  const std::vector<std::uint8_t> encoded = encode_store_state(*this, default_limits());
  return sha256(encoded);
}

// ---------------------------------------------------------------------------
// Record framing.
//
// Fixed 88 byte header, then the payload:
//   0  magic               u32
//   4  record version      u16
//   6  record type         u16
//   8  store generation    u32
//   12 sequence            u64
//   20 declared payload    u32
//   24 payload digest      32 bytes (SHA-256 of the payload)
//   56 reserved            24 bytes (must be zero)
//   80 header digest       8 bytes (leading 8 bytes of SHA-256 over bytes 0..80)
// ---------------------------------------------------------------------------
std::vector<std::uint8_t> frame_record(RecordType type, std::uint64_t sequence,
                                       std::uint32_t store_generation,
                                       std::span<const std::uint8_t> payload) {
  std::vector<std::uint8_t> frame(kRecordHeaderBytes + payload.size(), 0U);
  write_u32_le(frame.data(), kDurableMagic);
  write_u16_le(frame.data() + 4, kDurableRecordVersion);
  write_u16_le(frame.data() + 6, static_cast<std::uint16_t>(type));
  write_u32_le(frame.data() + 8, store_generation);
  write_u64_le(frame.data() + 12, sequence);
  write_u32_le(frame.data() + 20, static_cast<std::uint32_t>(payload.size()));
  const Digest payload_digest = sha256(payload);
  std::copy(payload_digest.bytes.begin(), payload_digest.bytes.end(), frame.begin() + 24);
  if (!payload.empty()) {
    std::copy(payload.begin(), payload.end(),
              frame.begin() + static_cast<std::ptrdiff_t>(kRecordHeaderBytes));
  }
  const Digest header_digest = sha256(std::span<const std::uint8_t>(frame.data(), 80));
  std::copy(header_digest.bytes.begin(), header_digest.bytes.begin() + 8, frame.begin() + 80);
  return frame;
}

RecordDecodeResult decode_record_at(std::span<const std::uint8_t> bytes, std::size_t offset,
                                    const Limits& limits) {
  (void)limits;
  RecordDecodeResult result;
  if (offset == bytes.size()) {
    result.status = RecordDecodeStatus::End;
    return result;
  }
  const std::size_t remaining = bytes.size() - offset;
  if (remaining < kRecordHeaderBytes) {
    const std::uint8_t* tail = bytes.data() + offset;
    const bool magic_prefix = remaining >= 4U
                                  ? read_u32_le(tail) == kDurableMagic
                                  : tail[0] == static_cast<std::uint8_t>(kDurableMagic & 0xFFU);
    if (magic_prefix) {
      result.status = RecordDecodeStatus::TornTail;
      result.reason = ReasonCode::PersistenceTornTailRecovered;
      result.detail = "trailing bytes are a prefix of a record header";
    } else {
      result.status = RecordDecodeStatus::Corrupt;
      result.reason = ReasonCode::PersistenceTrailingGarbage;
      result.detail = "trailing bytes do not begin a record";
    }
    result.next_offset = bytes.size();
    return result;
  }

  const std::uint8_t* header = bytes.data() + offset;
  if (read_u32_le(header) != kDurableMagic) {
    result.status = RecordDecodeStatus::Corrupt;
    result.reason = ReasonCode::PersistenceIntegrityFailure;
    result.detail = "record magic mismatch";
    return result;
  }
  const std::uint16_t version = read_u16_le(header + 4);
  if (version != kDurableRecordVersion) {
    result.status = RecordDecodeStatus::Corrupt;
    result.reason = ReasonCode::PersistenceFormatUnsupported;
    result.detail = "record version " + std::to_string(version) + " is not supported";
    return result;
  }
  const std::uint16_t raw_type = read_u16_le(header + 6);
  if (!is_valid_record_type(raw_type)) {
    result.status = RecordDecodeStatus::Corrupt;
    result.reason = ReasonCode::PersistenceRecordRejected;
    result.detail = "record type is out of domain";
    return result;
  }
  const std::uint32_t store_generation = read_u32_le(header + 8);
  const std::uint64_t sequence = read_u64_le(header + 12);
  if (sequence == 0U) {
    result.status = RecordDecodeStatus::Corrupt;
    result.reason = ReasonCode::PersistenceSequenceRegression;
    result.detail = "record sequence zero is not a valid sequence";
    return result;
  }
  const std::uint32_t declared = read_u32_le(header + 20);
  if (declared > Maxima::kRecordPayload) {
    result.status = RecordDecodeStatus::Corrupt;
    result.reason = ReasonCode::PersistenceIntegrityFailure;
    result.detail = "declared payload length exceeds the hard ceiling";
    return result;
  }
  for (std::size_t index = 56; index < 80; ++index) {
    if (header[index] != 0U) {
      result.status = RecordDecodeStatus::Corrupt;
      result.reason = ReasonCode::PersistenceRecordRejected;
      result.detail = "record reserved bytes are not zero";
      return result;
    }
  }

  Digest header_digest;
  std::copy(header + 80, header + 88, header_digest.bytes.begin());
  const Digest computed_header = sha256(std::span<const std::uint8_t>(header, 80));
  if (!std::equal(header_digest.bytes.begin(), header_digest.bytes.begin() + 8,
                  computed_header.bytes.begin())) {
    result.status = RecordDecodeStatus::Corrupt;
    result.reason = ReasonCode::PersistenceIntegrityFailure;
    result.detail = "record header digest mismatch";
    return result;
  }

  if (remaining < kRecordHeaderBytes + declared) {
    result.status = RecordDecodeStatus::TornTail;
    result.reason = ReasonCode::PersistenceTornTailRecovered;
    result.detail = "record payload is shorter than its declared length";
    result.next_offset = bytes.size();
    return result;
  }

  const std::uint8_t* payload = header + kRecordHeaderBytes;
  Digest payload_digest;
  std::copy(header + 24, header + 56, payload_digest.bytes.begin());
  const Digest computed_payload = sha256(std::span<const std::uint8_t>(payload, declared));
  if (!(computed_payload == payload_digest)) {
    result.status = RecordDecodeStatus::Corrupt;
    result.reason = ReasonCode::PersistenceIntegrityFailure;
    result.detail = "record payload digest mismatch";
    return result;
  }

  result.status = RecordDecodeStatus::Ok;
  result.record.type = static_cast<RecordType>(raw_type);
  result.record.version = version;
  result.record.flags = store_generation;
  result.record.sequence = sequence;
  result.record.payload.assign(payload, payload + declared);
  result.next_offset = offset + kRecordHeaderBytes + declared;
  return result;
}

// ---------------------------------------------------------------------------
// Entity codecs.
// ---------------------------------------------------------------------------
std::vector<std::uint8_t> encode_finding(const Finding& finding, const Limits& limits) {
  ByteWriter writer;
  writer.u64(finding.id.value());
  writer.u64(finding.generation.value());
  writer.u64(finding.assessment.value());
  writer.digest(finding.assessment_digest);
  writer.raw(encode_fence(finding.fence));
  writer.u8(static_cast<std::uint8_t>(finding.state));
  writer.u8(static_cast<std::uint8_t>(finding.fence_cause));
  writer.u8(static_cast<std::uint8_t>(finding.assessment_outcome));
  writer.u64(finding.assessment_flags);
  writer.u32(static_cast<std::uint32_t>(finding.witnesses.size()));
  for (const WitnessId witness : finding.witnesses) {
    writer.u64(witness.value());
  }
  writer.u32(static_cast<std::uint32_t>(finding.implicated_resources.size()));
  for (const ResourceId resource : finding.implicated_resources) {
    writer.u64(resource.value());
  }
  writer.u32(static_cast<std::uint32_t>(finding.implicated_selectors.size()));
  for (const TrafficSelectorId selector : finding.implicated_selectors) {
    writer.u64(selector.value());
  }
  writer.u64(finding.plan.value());
  writer.u64(finding.intent.value());
  writer.u64(finding.created_at);
  writer.u64(finding.updated_at);
  writer.u8(static_cast<std::uint8_t>(finding.origin));
  writer.u32(static_cast<std::uint32_t>(finding.explanation.reasons().size()));
  for (const ExplanationReason& reason : finding.explanation.reasons()) {
    writer.u8(static_cast<std::uint8_t>(reason.code));
    writer.text(reason.subject, Maxima::kStringBytes);
    writer.text(reason.detail, Maxima::kStringBytes);
  }
  if (writer.overflowed()) {
    return {};
  }
  (void)limits;
  return std::move(writer).take();
}

Result<Finding> decode_finding(std::span<const std::uint8_t> bytes, const Limits& limits) {
  ByteReader reader(bytes);
  Finding finding;
  std::uint8_t raw = 0;
  std::uint64_t raw64 = 0;
  std::uint32_t count = 0;

  if (!reader.read_id(finding.id) || !reader.read_id(finding.generation) ||
      !reader.read_id(finding.assessment) || !reader.read_digest(finding.assessment_digest)) {
    return Result<Finding>::failure(Outcome::Invalid, "finding header is truncated");
  }
  auto fence = decode_fence(reader);
  if (!fence.has_value()) {
    return Result<Finding>::failure(fence.outcome(), fence.detail());
  }
  finding.fence = std::move(fence).value();
  if (!reader.read_u8(raw)) {
    return Result<Finding>::failure(Outcome::Invalid, "finding state is truncated");
  }
  const auto state = enum_from_u32<FindingState>(raw);
  if (!state.has_value()) {
    return Result<Finding>::failure(Outcome::Invalid, "finding state is out of domain");
  }
  finding.state = *state;
  if (!reader.read_u8(raw)) {
    return Result<Finding>::failure(Outcome::Invalid, "finding fence cause is truncated");
  }
  const auto cause = enum_from_u32<FenceCause>(raw);
  if (!cause.has_value()) {
    return Result<Finding>::failure(Outcome::Invalid, "finding fence cause is out of domain");
  }
  finding.fence_cause = *cause;
  if (!reader.read_u8(raw)) {
    return Result<Finding>::failure(Outcome::Invalid, "finding outcome is truncated");
  }
  const auto outcome = enum_from_u32<LoopOutcome>(raw);
  if (!outcome.has_value()) {
    return Result<Finding>::failure(Outcome::Invalid, "finding outcome is out of domain");
  }
  finding.assessment_outcome = *outcome;
  {
    std::uint64_t flags = 0;
    if (!reader.read_u64(flags) || flags > 0xFFFF'FFFFULL) {
      return Result<Finding>::failure(Outcome::Invalid, "finding flags are truncated or out of range");
    }
    finding.assessment_flags = static_cast<AssessmentFlags>(flags);
  }
  if (!reader.read_count(count, limits.max_witnesses_per_assessment)) {
    return Result<Finding>::failure(reader.reason(), reader.detail());
  }
  for (std::uint32_t index = 0; index < count; ++index) {
    WitnessId witness;
    if (!reader.read_id(witness)) {
      return Result<Finding>::failure(Outcome::Invalid, "witness list is truncated");
    }
    finding.witnesses.push_back(witness);
  }
  if (!reader.read_count(count, limits.max_resources)) {
    return Result<Finding>::failure(reader.reason(), reader.detail());
  }
  for (std::uint32_t index = 0; index < count; ++index) {
    ResourceId resource;
    if (!reader.read_id(resource)) {
      return Result<Finding>::failure(Outcome::Invalid, "resource list is truncated");
    }
    finding.implicated_resources.push_back(resource);
  }
  if (!reader.read_count(count, limits.max_selectors)) {
    return Result<Finding>::failure(reader.reason(), reader.detail());
  }
  for (std::uint32_t index = 0; index < count; ++index) {
    TrafficSelectorId selector;
    if (!reader.read_id(selector)) {
      return Result<Finding>::failure(Outcome::Invalid, "selector list is truncated");
    }
    finding.implicated_selectors.push_back(selector);
  }
  if (!reader.read_id(finding.plan) || !reader.read_id(finding.intent) ||
      !reader.read_u64(finding.created_at) || !reader.read_u64(finding.updated_at)) {
    return Result<Finding>::failure(Outcome::Invalid, "finding tail is truncated");
  }
  if (!reader.read_u8(raw)) {
    return Result<Finding>::failure(Outcome::Invalid, "finding origin is truncated");
  }
  const auto origin = enum_from_u32<EvidenceOrigin>(raw);
  if (!origin.has_value()) {
    return Result<Finding>::failure(Outcome::Invalid, "finding origin is out of domain");
  }
  finding.origin = *origin;
  if (!reader.read_count(count, limits.max_explanation_reasons)) {
    return Result<Finding>::failure(reader.reason(), reader.detail());
  }
  finding.explanation = Explanation(limits.max_explanation_reasons);
  for (std::uint32_t index = 0; index < count; ++index) {
    std::uint8_t raw_code = 0;
    std::string subject;
    std::string detail;
    if (!reader.read_u8(raw_code) || !reader.read_text(subject, Maxima::kStringBytes) ||
        !reader.read_text(detail, Maxima::kStringBytes)) {
      return Result<Finding>::failure(Outcome::Invalid, "finding explanation is truncated");
    }
    const auto code = enum_from_u32<ReasonCode>(raw_code);
    if (!code.has_value()) {
      return Result<Finding>::failure(Outcome::Invalid, "reason code is out of domain");
    }
    finding.explanation.add(*code, std::move(subject), std::move(detail));
  }
  if (!reader.at_end()) {
    return Result<Finding>::failure(Outcome::Invalid, "finding record has trailing bytes");
  }
  (void)raw64;
  return Result<Finding>::ok(std::move(finding));
}

std::vector<std::uint8_t> encode_lineage(const LineageRecord& record) {
  ByteWriter writer;
  writer.u64(record.id.value());
  writer.u64(record.sequence.value());
  writer.u64(record.recorded_at);
  writer.u8(static_cast<std::uint8_t>(record.kind));
  writer.u64(record.finding.value());
  writer.u64(record.plan.value());
  writer.u64(record.intent.value());
  writer.raw(encode_fence(record.fence));
  writer.digest(record.subject_digest);
  writer.u8(static_cast<std::uint8_t>(record.reason));
  writer.u8(static_cast<std::uint8_t>(record.severity));
  if (writer.overflowed()) {
    return {};
  }
  return std::move(writer).take();
}

Result<LineageRecord> decode_lineage(std::span<const std::uint8_t> bytes, const Limits& limits) {
  (void)limits;
  ByteReader reader(bytes);
  LineageRecord record;
  std::uint8_t raw = 0;
  if (!reader.read_id(record.id) || !reader.read_id(record.sequence) ||
      !reader.read_u64(record.recorded_at) || !reader.read_u8(raw)) {
    return Result<LineageRecord>::failure(Outcome::Invalid, "lineage header is truncated");
  }
  const auto kind = enum_from_u32<AuthorityKind>(raw);
  if (!kind.has_value()) {
    return Result<LineageRecord>::failure(Outcome::Invalid, "authority kind is out of domain");
  }
  record.kind = *kind;
  if (!reader.read_id(record.finding) || !reader.read_id(record.plan) ||
      !reader.read_id(record.intent)) {
    return Result<LineageRecord>::failure(Outcome::Invalid, "lineage references are truncated");
  }
  auto fence = decode_fence(reader);
  if (!fence.has_value()) {
    return Result<LineageRecord>::failure(fence.outcome(), fence.detail());
  }
  record.fence = std::move(fence).value();
  if (!reader.read_digest(record.subject_digest) || !reader.read_u8(raw)) {
    return Result<LineageRecord>::failure(Outcome::Invalid, "lineage digests are truncated");
  }
  const auto reason = enum_from_u32<ReasonCode>(raw);
  if (!reason.has_value()) {
    return Result<LineageRecord>::failure(Outcome::Invalid, "reason code is out of domain");
  }
  record.reason = *reason;
  if (!reader.read_u8(raw)) {
    return Result<LineageRecord>::failure(Outcome::Invalid, "lineage severity is truncated");
  }
  const auto severity = enum_from_u32<Severity>(raw);
  if (!severity.has_value()) {
    return Result<LineageRecord>::failure(Outcome::Invalid, "severity is out of domain");
  }
  record.severity = *severity;
  if (!reader.at_end()) {
    return Result<LineageRecord>::failure(Outcome::Invalid, "lineage record has trailing bytes");
  }
  return Result<LineageRecord>::ok(std::move(record));
}

std::vector<std::uint8_t> encode_boot_record(const BootRecord& record) {
  ByteWriter writer;
  writer.u64(record.id.value());
  writer.u64(record.boot.value());
  writer.u64(record.incarnation.value());
  writer.u64(record.epoch.value());
  writer.u64(record.producer.value());
  writer.u64(record.started_at);
  writer.u64(record.closed_at);
  writer.boolean(record.clean_shutdown);
  return std::move(writer).take();
}

Result<BootRecord> decode_boot_record(std::span<const std::uint8_t> bytes, const Limits& limits) {
  (void)limits;
  ByteReader reader(bytes);
  BootRecord record;
  if (!reader.read_id(record.id) || !reader.read_id(record.boot) ||
      !reader.read_id(record.incarnation) || !reader.read_id(record.epoch) ||
      !reader.read_id(record.producer) || !reader.read_u64(record.started_at) ||
      !reader.read_u64(record.closed_at) || !reader.read_bool(record.clean_shutdown)) {
    return Result<BootRecord>::failure(Outcome::Invalid, "boot record is truncated");
  }
  if (!reader.at_end()) {
    return Result<BootRecord>::failure(Outcome::Invalid, "boot record has trailing bytes");
  }
  return Result<BootRecord>::ok(std::move(record));
}

std::vector<std::uint8_t> encode_shutdown_marker(BootId boot, bool clean, Tick at) {
  ByteWriter writer;
  writer.u64(boot.value());
  writer.boolean(clean);
  writer.u64(at);
  return std::move(writer).take();
}

Result<BootRecord> decode_shutdown_marker(std::span<const std::uint8_t> bytes, const Limits& limits) {
  (void)limits;
  ByteReader reader(bytes);
  BootRecord record;
  if (!reader.read_id(record.boot) || !reader.read_bool(record.clean_shutdown) ||
      !reader.read_u64(record.closed_at)) {
    return Result<BootRecord>::failure(Outcome::Invalid, "shutdown marker is truncated");
  }
  if (!reader.at_end()) {
    return Result<BootRecord>::failure(Outcome::Invalid, "shutdown marker has trailing bytes");
  }
  return Result<BootRecord>::ok(std::move(record));
}

std::vector<std::uint8_t> encode_finding_withdrawal(FindingId id, FenceCause cause, Tick now,
                                                    ReasonCode reason, std::string_view detail) {
  ByteWriter writer;
  writer.u64(id.value());
  writer.u8(static_cast<std::uint8_t>(cause));
  writer.u64(now);
  writer.u8(static_cast<std::uint8_t>(reason));
  writer.text(detail, Maxima::kStringBytes);
  return std::move(writer).take();
}

Result<Finding> decode_finding_withdrawal(std::span<const std::uint8_t> bytes, const Limits& limits) {
  (void)limits;
  ByteReader reader(bytes);
  Finding finding;
  std::uint8_t raw = 0;
  if (!reader.read_id(finding.id)) {
    return Result<Finding>::failure(Outcome::Invalid, "withdrawal identity is truncated");
  }
  if (!reader.read_u8(raw)) {
    return Result<Finding>::failure(Outcome::Invalid, "withdrawal cause is truncated");
  }
  const auto cause = enum_from_u32<FenceCause>(raw);
  if (!cause.has_value()) {
    return Result<Finding>::failure(Outcome::Invalid, "withdrawal cause is out of domain");
  }
  finding.fence_cause = *cause;
  if (!reader.read_u64(finding.updated_at)) {
    return Result<Finding>::failure(Outcome::Invalid, "withdrawal tick is truncated");
  }
  if (!reader.read_u8(raw)) {
    return Result<Finding>::failure(Outcome::Invalid, "withdrawal reason is truncated");
  }
  const auto reason = enum_from_u32<ReasonCode>(raw);
  if (!reason.has_value()) {
    return Result<Finding>::failure(Outcome::Invalid, "withdrawal reason is out of domain");
  }
  std::string detail;
  if (!reader.read_text(detail, Maxima::kStringBytes)) {
    return Result<Finding>::failure(Outcome::Invalid, "withdrawal detail is truncated");
  }
  if (!reader.at_end()) {
    return Result<Finding>::failure(Outcome::Invalid, "withdrawal has trailing bytes");
  }
  finding.state = FindingState::Withdrawn;
  finding.explanation = Explanation(default_limits().max_explanation_reasons);
  finding.explanation.add(*reason, finding.id.to_string(), std::move(detail));
  return Result<Finding>::ok(std::move(finding));
}

// ---------------------------------------------------------------------------
// Whole-document codec.
// ---------------------------------------------------------------------------
std::vector<std::uint8_t> encode_store_state(const StoreState& state, const Limits& limits) {
  ByteWriter writer;
  writer.u16(state.snapshot_schema);
  writer.u16(state.record_version);
  writer.u32(state.store_generation);
  writer.u64(state.topology_generation.value());
  writer.boolean(state.topology.has_value());
  if (state.topology.has_value()) {
    write_blob(writer, encode_topology(*state.topology, limits));
  }
  writer.boolean(state.policy.has_value());
  if (state.policy.has_value()) {
    write_blob(writer, encode_policy(*state.policy, limits));
  }
  writer.u32(static_cast<std::uint32_t>(state.boot_ledger.size()));
  for (const BootRecord& record : state.boot_ledger) {
    write_blob(writer, encode_boot_record(record));
  }
  writer.u32(static_cast<std::uint32_t>(state.lineage.size()));
  for (const LineageRecord& record : state.lineage) {
    write_blob(writer, encode_lineage(record));
  }
  writer.u32(static_cast<std::uint32_t>(state.findings.size()));
  for (const Finding& finding : state.findings) {
    write_blob(writer, encode_finding(finding, limits));
  }
  write_blob(writer, encode_fence(state.committed_fence));
  writer.u64(state.lineage_sequence.value());
  writer.u64(state.finding_sequence.value());
  writer.u64(state.assessment_sequence.value());
  if (writer.overflowed()) {
    return {};
  }
  return std::move(writer).take();
}

Result<StoreState> decode_store_state(std::span<const std::uint8_t> bytes, const Limits& limits) {
  ByteReader reader(bytes);
  StoreState state;
  std::uint16_t raw16 = 0;
  std::uint32_t raw32 = 0;
  std::uint64_t raw64 = 0;
  if (!reader.read_u16(raw16)) {
    return Result<StoreState>::failure(Outcome::Invalid, "snapshot schema is truncated");
  }
  if (raw16 != kDurableSnapshotSchema) {
    return Result<StoreState>::failure(Outcome::Unsupported,
                                       "snapshot schema " + std::to_string(raw16) + " is not supported");
  }
  state.snapshot_schema = raw16;
  if (!reader.read_u16(raw16)) {
    return Result<StoreState>::failure(Outcome::Invalid, "snapshot record version is truncated");
  }
  if (raw16 != kDurableRecordVersion) {
    return Result<StoreState>::failure(Outcome::Unsupported,
                                       "snapshot record version is not supported");
  }
  state.record_version = raw16;
  if (!reader.read_u32(raw32) || raw32 == 0U) {
    return Result<StoreState>::failure(Outcome::Invalid, "store generation must be non-zero");
  }
  state.store_generation = raw32;
  if (!reader.read_u64(raw64)) {
    return Result<StoreState>::failure(Outcome::Invalid, "topology generation is truncated");
  }
  state.topology_generation = TopologyGeneration::from_value(raw64);
  bool present = false;
  if (!reader.read_bool(present)) {
    return Result<StoreState>::failure(Outcome::Invalid, "topology presence flag is truncated");
  }
  if (present) {
    std::uint32_t size = 0;
    if (!reader.read_u32(size) || size > Maxima::kSnapshotPayload) {
      return Result<StoreState>::failure(Outcome::Invalid, "topology blob length is out of range");
    }
    std::vector<std::uint8_t> blob;
    if (!reader.read_raw(blob, size) || blob.size() != size) {
      return Result<StoreState>::failure(Outcome::Invalid, "topology blob is truncated");
    }
    auto decoded = decode_topology(blob, limits);
    if (!decoded.has_value()) {
      return Result<StoreState>::failure(decoded.outcome(), decoded.detail());
    }
    state.topology = std::move(decoded).value();
    if (!(state.topology->generation() == state.topology_generation)) {
      return Result<StoreState>::failure(Outcome::Invalid,
                                         "snapshot topology generation disagrees with the header");
    }
  }
  if (!reader.read_bool(present)) {
    return Result<StoreState>::failure(Outcome::Invalid, "policy presence flag is truncated");
  }
  if (present) {
    std::uint32_t size = 0;
    if (!reader.read_u32(size) || size > Maxima::kSnapshotPayload) {
      return Result<StoreState>::failure(Outcome::Invalid, "policy blob length is out of range");
    }
    std::vector<std::uint8_t> blob;
    if (!reader.read_raw(blob, size) || blob.size() != size) {
      return Result<StoreState>::failure(Outcome::Invalid, "policy blob is truncated");
    }
    auto decoded = decode_policy(blob, limits);
    if (!decoded.has_value()) {
      return Result<StoreState>::failure(decoded.outcome(), decoded.detail());
    }
    state.policy = std::move(decoded).value();
  }

  std::uint32_t count = 0;
  if (!reader.read_count(count, limits.max_boot_records)) {
    return Result<StoreState>::failure(reader.reason(), reader.detail());
  }
  for (std::uint32_t index = 0; index < count; ++index) {
    std::uint32_t size = 0;
    if (!reader.read_u32(size) || size > Maxima::kRecordPayload) {
      return Result<StoreState>::failure(Outcome::Invalid, "boot record length is out of range");
    }
    std::vector<std::uint8_t> blob;
    if (!reader.read_raw(blob, size) || blob.size() != size) {
      return Result<StoreState>::failure(Outcome::Invalid, "boot record is truncated");
    }
    auto decoded = decode_boot_record(blob, limits);
    if (!decoded.has_value()) {
      return Result<StoreState>::failure(decoded.outcome(), decoded.detail());
    }
    state.boot_ledger.push_back(std::move(decoded).value());
  }
  if (!reader.read_count(count, limits.max_retained_lineage)) {
    return Result<StoreState>::failure(reader.reason(), reader.detail());
  }
  for (std::uint32_t index = 0; index < count; ++index) {
    std::uint32_t size = 0;
    if (!reader.read_u32(size) || size > Maxima::kRecordPayload) {
      return Result<StoreState>::failure(Outcome::Invalid, "lineage record length is out of range");
    }
    std::vector<std::uint8_t> blob;
    if (!reader.read_raw(blob, size) || blob.size() != size) {
      return Result<StoreState>::failure(Outcome::Invalid, "lineage record is truncated");
    }
    auto decoded = decode_lineage(blob, limits);
    if (!decoded.has_value()) {
      return Result<StoreState>::failure(decoded.outcome(), decoded.detail());
    }
    state.lineage.push_back(std::move(decoded).value());
  }
  if (!reader.read_count(count, limits.max_retained_findings)) {
    return Result<StoreState>::failure(reader.reason(), reader.detail());
  }
  for (std::uint32_t index = 0; index < count; ++index) {
    std::uint32_t size = 0;
    if (!reader.read_u32(size) || size > Maxima::kRecordPayload) {
      return Result<StoreState>::failure(Outcome::Invalid, "finding record length is out of range");
    }
    std::vector<std::uint8_t> blob;
    if (!reader.read_raw(blob, size) || blob.size() != size) {
      return Result<StoreState>::failure(Outcome::Invalid, "finding record is truncated");
    }
    auto decoded = decode_finding(blob, limits);
    if (!decoded.has_value()) {
      return Result<StoreState>::failure(decoded.outcome(), decoded.detail());
    }
    state.findings.push_back(std::move(decoded).value());
  }

  std::uint32_t fence_size = 0;
  if (!reader.read_u32(fence_size) || fence_size == 0U || fence_size > Maxima::kStringBytes) {
    return Result<StoreState>::failure(Outcome::Invalid, "fence blob length is out of range");
  }
  std::vector<std::uint8_t> fence_blob;
  if (!reader.read_raw(fence_blob, fence_size) || fence_blob.size() != fence_size) {
    return Result<StoreState>::failure(Outcome::Invalid, "fence blob is truncated");
  }
  {
    ByteReader fence_reader(fence_blob);
    auto decoded = decode_fence(fence_reader);
    if (!decoded.has_value()) {
      return Result<StoreState>::failure(decoded.outcome(), decoded.detail());
    }
    state.committed_fence = std::move(decoded).value();
  }
  if (!reader.read_u64(raw64)) {
    return Result<StoreState>::failure(Outcome::Invalid, "lineage sequence is truncated");
  }
  state.lineage_sequence = AttemptSequence::from_value(raw64);
  if (!reader.read_u64(raw64)) {
    return Result<StoreState>::failure(Outcome::Invalid, "finding sequence is truncated");
  }
  state.finding_sequence = AttemptSequence::from_value(raw64);
  if (!reader.read_u64(raw64)) {
    return Result<StoreState>::failure(Outcome::Invalid, "assessment sequence is truncated");
  }
  state.assessment_sequence = AttemptSequence::from_value(raw64);
  if (!reader.at_end()) {
    return Result<StoreState>::failure(Outcome::Invalid, "snapshot has trailing bytes");
  }
  return Result<StoreState>::ok(std::move(state));
}

std::vector<std::uint8_t> encode_record_payload(RecordType type, const StoreState& delta,
                                                const Finding& finding,
                                                const LineageRecord& lineage,
                                                const BootRecord& boot, const Limits& limits) {
  switch (type) {
    case RecordType::Snapshot:
      return encode_store_state(delta, limits);
    case RecordType::TopologyDefinition:
      if (!delta.topology.has_value()) {
        return {};
      }
      return encode_topology(*delta.topology, limits);
    case RecordType::ContainmentPolicyRecord:
      if (!delta.policy.has_value()) {
        return {};
      }
      return encode_policy(*delta.policy, limits);
    case RecordType::LineageAppend:
      return encode_lineage(lineage);
    case RecordType::FindingUpsert:
      return encode_finding(finding, limits);
    case RecordType::FindingWithdraw:
      return encode_finding_withdrawal(finding.id, finding.fence_cause, finding.updated_at,
                                       finding.explanation.reasons().empty()
                                           ? ReasonCode::FindingWithdrawn
                                           : finding.explanation.reasons().front().code,
                                       finding.explanation.reasons().empty()
                                           ? std::string_view{}
                                           : std::string_view(
                                                 finding.explanation.reasons().front().detail));
    case RecordType::BootAdvance:
      return encode_boot_record(boot);
    case RecordType::FenceAdvance:
      return encode_fence(delta.committed_fence);
    case RecordType::Note:
      return encode_shutdown_marker(boot.boot, boot.clean_shutdown, boot.closed_at);
  }
  return {};
}

Result<StoreState> decode_record_payload(RecordType type, std::span<const std::uint8_t> payload,
                                         const Limits& limits) {
  switch (type) {
    case RecordType::Snapshot:
      return decode_store_state(payload, limits);
    case RecordType::TopologyDefinition: {
      auto decoded = decode_topology(payload, limits);
      if (!decoded.has_value()) {
        return Result<StoreState>::failure(decoded.outcome(), decoded.detail());
      }
      StoreState delta;
      delta.topology = std::move(decoded).value();
      delta.topology_generation = delta.topology->generation();
      return Result<StoreState>::ok(std::move(delta));
    }
    case RecordType::ContainmentPolicyRecord: {
      auto decoded = decode_policy(payload, limits);
      if (!decoded.has_value()) {
        return Result<StoreState>::failure(decoded.outcome(), decoded.detail());
      }
      StoreState delta;
      delta.policy = std::move(decoded).value();
      return Result<StoreState>::ok(std::move(delta));
    }
    case RecordType::LineageAppend: {
      auto decoded = decode_lineage(payload, limits);
      if (!decoded.has_value()) {
        return Result<StoreState>::failure(decoded.outcome(), decoded.detail());
      }
      StoreState delta;
      delta.lineage.push_back(std::move(decoded).value());
      delta.lineage_sequence = delta.lineage.front().sequence;
      return Result<StoreState>::ok(std::move(delta));
    }
    case RecordType::FindingUpsert: {
      auto decoded = decode_finding(payload, limits);
      if (!decoded.has_value()) {
        return Result<StoreState>::failure(decoded.outcome(), decoded.detail());
      }
      StoreState delta;
      delta.findings.push_back(std::move(decoded).value());
      return Result<StoreState>::ok(std::move(delta));
    }
    case RecordType::FindingWithdraw: {
      auto decoded = decode_finding_withdrawal(payload, limits);
      if (!decoded.has_value()) {
        return Result<StoreState>::failure(decoded.outcome(), decoded.detail());
      }
      StoreState delta;
      delta.findings.push_back(std::move(decoded).value());
      return Result<StoreState>::ok(std::move(delta));
    }
    case RecordType::BootAdvance: {
      auto decoded = decode_boot_record(payload, limits);
      if (!decoded.has_value()) {
        return Result<StoreState>::failure(decoded.outcome(), decoded.detail());
      }
      StoreState delta;
      delta.boot_ledger.push_back(std::move(decoded).value());
      return Result<StoreState>::ok(std::move(delta));
    }
    case RecordType::FenceAdvance: {
      ByteReader reader(payload);
      auto decoded = decode_fence(reader);
      if (!decoded.has_value() || !reader.at_end()) {
        return Result<StoreState>::failure(Outcome::Invalid, "fence payload is malformed");
      }
      StoreState delta;
      delta.committed_fence = std::move(decoded).value();
      return Result<StoreState>::ok(std::move(delta));
    }
    case RecordType::Note: {
      auto decoded = decode_shutdown_marker(payload, limits);
      if (!decoded.has_value()) {
        return Result<StoreState>::failure(decoded.outcome(), decoded.detail());
      }
      StoreState delta;
      delta.boot_ledger.push_back(std::move(decoded).value());
      return Result<StoreState>::ok(std::move(delta));
    }
  }
  return Result<StoreState>::failure(Outcome::Unsupported, "record type is not supported");
}

// ---------------------------------------------------------------------------
// File helpers.
// ---------------------------------------------------------------------------
Result<std::vector<std::uint8_t>> read_file_bounded(const std::string& path,
                                                    std::uint64_t max_bytes) {
  std::FILE* handle = std::fopen(path.c_str(), "rb");
  if (handle == nullptr) {
    return Result<std::vector<std::uint8_t>>::failure(Outcome::NotFound,
                                                      "cannot open file for reading");
  }
  // The staging buffer is heap allocated: a 64 KiB stack frame is a real resource risk
  // in a runtime that is embedded in services with small thread stacks.
  constexpr std::size_t kChunk = 64U * 1024U;
  std::vector<std::uint8_t> bytes;
  std::vector<std::uint8_t> buffer(kChunk);
  for (;;) {
    const std::size_t chunk = std::fread(buffer.data(), 1, buffer.size(), handle);
    if (chunk == 0U) {
      break;
    }
    if (bytes.size() + chunk > max_bytes) {
      std::fclose(handle);
      return Result<std::vector<std::uint8_t>>::failure(Outcome::Exhausted,
                                                        "file exceeds the configured ceiling");
    }
    bytes.insert(bytes.end(), buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(chunk));
  }
  const bool failed = std::ferror(handle) != 0;
  std::fclose(handle);
  if (failed) {
    return Result<std::vector<std::uint8_t>>::failure(Outcome::IoFailure, "read failed");
  }
  return Result<std::vector<std::uint8_t>>::ok(std::move(bytes));
}

Status write_file_atomic(const std::string& path, std::span<const std::uint8_t> bytes) {
  const std::string temporary = path + ".tmp-" + unique_suffix();
  std::FILE* handle = std::fopen(temporary.c_str(), "wb");
  if (handle == nullptr) {
    return Status::failure(Outcome::IoFailure, "cannot create temporary file");
  }
  if (!write_all(handle, bytes.data(), bytes.size())) {
    std::fclose(handle);
    (void)std::remove(temporary.c_str());
    return Status::failure(Outcome::IoFailure, "temporary write failed");
  }
  Status status = flush_and_sync(handle);
  if (std::fclose(handle) != 0 && status.is_ok()) {
    status = Status::failure(Outcome::IoFailure, "close failed");
  }
  if (!status.is_ok()) {
    (void)std::remove(temporary.c_str());
    return status;
  }
  status = rename_over(temporary, path);
  if (!status.is_ok()) {
    (void)std::remove(temporary.c_str());
    return status;
  }
  return Status::ok();
}

Status remove_file_if_present(const std::string& path) {
  std::error_code error;
  const bool removed = std::filesystem::remove(path, error);
  if (error) {
    return Status::failure(Outcome::IoFailure, "remove failed: " + error.message());
  }
  (void)removed;
  return Status::ok();
}

// ---------------------------------------------------------------------------
// DurableStore.
// ---------------------------------------------------------------------------
DurableStore::~DurableStore() { reset(); }

DurableStore::DurableStore(DurableStore&& other) noexcept { move_from(std::move(other)); }

DurableStore& DurableStore::operator=(DurableStore&& other) noexcept {
  if (this != &other) {
    reset();
    move_from(std::move(other));
  }
  return *this;
}

void DurableStore::move_from(DurableStore&& other) noexcept {
  handle_ = other.handle_;
  other.handle_ = nullptr;
  path_ = std::move(other.path_);
  limits_ = other.limits_;
  state_ = std::move(other.state_);
  recovery_ = std::move(other.recovery_);
  identity_ = other.identity_;
  journal_bytes_ = other.journal_bytes_;
  journal_records_ = other.journal_records_;
  next_sequence_ = other.next_sequence_;
  dirty_ = other.dirty_;
}

void DurableStore::reset() noexcept {
  if (handle_ != nullptr) {
    std::fclose(static_cast<std::FILE*>(handle_));
    handle_ = nullptr;
  }
}

Result<DurableStore> DurableStore::open_or_create(const std::string& path, const Limits& limits,
                                                  ProducerId producer) {
  if (!limits_are_sane(limits)) {
    return Result<DurableStore>::failure(Outcome::Unsupported, "limit set is not sane");
  }
  if (path.empty()) {
    return Result<DurableStore>::failure(Outcome::Invalid, "store path must not be empty");
  }
  if (!producer.valid()) {
    return Result<DurableStore>::failure(Outcome::Invalid, "producer identity must be non-zero");
  }

  DurableStore store;
  store.path_ = path;
  store.limits_ = limits;
  store.recovery_.explanation = Explanation(limits.max_explanation_reasons);

  std::vector<std::uint8_t> bytes;
  std::error_code exists_error;
  const bool present = std::filesystem::exists(path, exists_error);
  if (exists_error) {
    return Result<DurableStore>::failure(Outcome::IoFailure,
                                         "cannot inspect the store path: " + exists_error.message());
  }
  if (present) {
    auto read = read_file_bounded(path, Maxima::kDocumentBytes);
    if (!read.has_value()) {
      return Result<DurableStore>::failure(read.outcome(), read.detail());
    }
    bytes = std::move(read).value();
  }

  std::size_t offset = 0;
  std::size_t good_offset = 0;
  std::uint64_t expected_sequence = 1;
  std::uint32_t generation = 0;
  bool first = true;
  std::vector<DecodedRecord> records;

  while (offset < bytes.size()) {
    RecordDecodeResult decoded = decode_record_at(bytes, offset, limits);
    if (decoded.status == RecordDecodeStatus::TornTail) {
      store.recovery_.torn_tail_recovered = true;
      store.recovery_.torn_tail_bytes = bytes.size() - offset;
      store.recovery_.explanation.add(ReasonCode::PersistenceTornTailRecovered, path, decoded.detail);
      break;
    }
    if (decoded.status == RecordDecodeStatus::Corrupt) {
      store.recovery_.trailing_garbage = decoded.reason == ReasonCode::PersistenceTrailingGarbage;
      store.recovery_.outcome = Outcome::IntegrityFailure;
      store.recovery_.explanation.add(decoded.reason, path, decoded.detail);
      // Corruption is never silently truncated: it may represent tampering.
      return Result<DurableStore>::failure(Outcome::IntegrityFailure,
                                           std::string("durable store refused: ") + decoded.detail);
    }
    if (decoded.status == RecordDecodeStatus::End) {
      break;
    }
    if (first) {
      if (decoded.record.type != RecordType::Snapshot) {
        return Result<DurableStore>::failure(Outcome::IntegrityFailure,
                                             "durable store must begin with a snapshot record");
      }
      if (decoded.record.sequence != 1U) {
        return Result<DurableStore>::failure(Outcome::IntegrityFailure,
                                             "snapshot must be record sequence 1");
      }
      generation = decoded.record.flags;
      if (generation == 0U) {
        return Result<DurableStore>::failure(Outcome::IntegrityFailure,
                                             "store generation zero is not a valid generation");
      }
    } else {
      if (decoded.record.type == RecordType::Snapshot) {
        return Result<DurableStore>::failure(
            Outcome::IntegrityFailure, "a second snapshot record is not allowed in one document");
      }
      if (decoded.record.flags != generation) {
        return Result<DurableStore>::failure(
            Outcome::Stale,
            "record belongs to a superseded store generation and is refused rather than replayed");
      }
      if (decoded.record.sequence != expected_sequence) {
        return Result<DurableStore>::failure(
            Outcome::IntegrityFailure,
            "record sequence " + std::to_string(decoded.record.sequence) + " is not the expected " +
                std::to_string(expected_sequence));
      }
    }
    ++expected_sequence;
    first = false;
    offset = decoded.next_offset;
    good_offset = offset;
    records.push_back(std::move(decoded.record));
    if (records.size() > limits.max_journal_records) {
      return Result<DurableStore>::failure(Outcome::Exhausted,
                                           "durable journal exceeds its record bound");
    }
  }

  store.recovery_.records_read = records.size();
  store.recovery_.bytes_read = good_offset;
  store.state_.store_generation = generation == 0U ? 1U : generation;

  for (const DecodedRecord& record : records) {
    auto payload = decode_record_payload(record.type, record.payload, limits);
    if (!payload.has_value()) {
      return Result<DurableStore>::failure(payload.outcome(), payload.detail());
    }
    const StoreState& delta = payload.value();
    switch (record.type) {
      case RecordType::Snapshot:
        store.state_ = delta;
        break;
      case RecordType::TopologyDefinition:
        store.state_.topology = delta.topology;
        store.state_.topology_generation = delta.topology_generation;
        break;
      case RecordType::ContainmentPolicyRecord:
        store.state_.policy = delta.policy;
        break;
      case RecordType::LineageAppend: {
        if (delta.lineage.empty()) {
          return Result<DurableStore>::failure(Outcome::Invalid, "lineage record carries no payload");
        }
        const LineageRecord& incoming = delta.lineage.front();
        if (store.state_.lineage_sequence.valid() &&
            incoming.sequence <= store.state_.lineage_sequence) {
          return Result<DurableStore>::failure(
              Outcome::IntegrityFailure, "lineage sequence regressed in the durable journal");
        }
        store.state_.lineage.push_back(incoming);
        store.state_.lineage_sequence = incoming.sequence;
        while (store.state_.lineage.size() > limits.max_retained_lineage) {
          store.state_.lineage.erase(store.state_.lineage.begin());
        }
        break;
      }
      case RecordType::FindingUpsert: {
        if (delta.findings.empty()) {
          return Result<DurableStore>::failure(Outcome::Invalid, "finding record carries no payload");
        }
        const Finding& incoming = delta.findings.front();
        bool replaced = false;
        for (Finding& existing : store.state_.findings) {
          if (existing.id == incoming.id) {
            existing = incoming;
            replaced = true;
            break;
          }
        }
        if (!replaced) {
          store.state_.findings.push_back(incoming);
        }
        if (incoming.generation.valid()) {
          store.state_.finding_sequence = AttemptSequence::from_value(incoming.generation.value());
        }
        break;
      }
      case RecordType::FindingWithdraw: {
        if (delta.findings.empty()) {
          return Result<DurableStore>::failure(Outcome::Invalid,
                                               "withdrawal record carries no payload");
        }
        const Finding& incoming = delta.findings.front();
        bool found = false;
        for (Finding& existing : store.state_.findings) {
          if (existing.id == incoming.id) {
            existing.state = FindingState::Withdrawn;
            existing.fence_cause = incoming.fence_cause;
            existing.updated_at = incoming.updated_at;
            for (const ExplanationReason& reason : incoming.explanation.reasons()) {
              existing.explanation.add(reason.code, reason.subject, reason.detail);
            }
            found = true;
            break;
          }
        }
        if (!found) {
          return Result<DurableStore>::failure(
              Outcome::Invalid, "withdrawal references a finding the document does not contain");
        }
        break;
      }
      case RecordType::BootAdvance:
      case RecordType::Note: {
        if (delta.boot_ledger.empty()) {
          return Result<DurableStore>::failure(Outcome::Invalid, "boot record carries no payload");
        }
        const BootRecord& incoming = delta.boot_ledger.front();
        bool replaced = false;
        for (BootRecord& existing : store.state_.boot_ledger) {
          if (existing.boot == incoming.boot) {
            existing.closed_at = incoming.closed_at;
            existing.clean_shutdown = incoming.clean_shutdown;
            replaced = true;
            break;
          }
        }
        if (!replaced) {
          if (record.type == RecordType::Note) {
            return Result<DurableStore>::failure(
                Outcome::Invalid,
                "a shutdown marker must reference a boot the ledger already knows");
          }
          store.state_.boot_ledger.push_back(incoming);
        }
        break;
      }
      case RecordType::FenceAdvance:
        store.state_.committed_fence = delta.committed_fence;
        break;
    }
    ++store.recovery_.records_applied;
  }

  // Open the file for appending. A genuine torn tail is truncated to the last complete
  // record; nothing else is ever discarded.
  std::FILE* handle = std::fopen(path.c_str(), present ? "r+b" : "w+b");
  if (handle == nullptr) {
    return Result<DurableStore>::failure(Outcome::IoFailure, "cannot open the durable store");
  }
  if (present && store.recovery_.torn_tail_recovered) {
    const Status truncated = truncate_at(handle, good_offset);
    if (!truncated.is_ok()) {
      std::fclose(handle);
      return Result<DurableStore>::failure(truncated.outcome(), truncated.detail());
    }
  }
  if (std::fseek(handle, 0, SEEK_END) != 0) {
    std::fclose(handle);
    return Result<DurableStore>::failure(Outcome::IoFailure, "cannot seek in the durable store");
  }
  store.handle_ = handle;
  store.next_sequence_ = expected_sequence;
  store.journal_bytes_ = good_offset;
  store.journal_records_ = records.size();

  // A brand new document is written from scratch below, with its very first boot record
  // already inside it, so a fresh store starts at boot 1 and epoch 1 rather than at a
  // placeholder that a later mint has to step over.
  const bool fresh_document = records.empty();
  if (fresh_document) {
    store.reset();
    store.state_ = StoreState{};
  }

  // Mint a fresh process/incarnation authority boundary. Persistence is not liveness: the
  // previous incarnation's authority is never reused.
  std::uint64_t max_boot = 0;
  std::uint64_t max_incarnation = 0;
  std::uint64_t max_epoch =
      store.state_.committed_fence.epoch.valid() ? store.state_.committed_fence.epoch.value() : 0U;
  for (const BootRecord& record : store.state_.boot_ledger) {
    max_boot = std::max(max_boot, record.boot.value());
    max_incarnation = std::max(max_incarnation, record.incarnation.value());
    max_epoch = std::max(max_epoch, record.epoch.value());
  }
  constexpr std::uint64_t kIdMax = 0xFFFF'FFFF'FFFF'FFFFULL;
  if (max_boot == kIdMax || max_incarnation == kIdMax || max_epoch == kIdMax) {
    store.reset();
    return Result<DurableStore>::failure(Outcome::Exhausted,
                                         "boot/incarnation/epoch space is exhausted");
  }

  BootRecord boot_record;
  boot_record.boot = BootId::from_value(max_boot + 1U);
  boot_record.incarnation = IncarnationId::from_value(max_incarnation + 1U);
  boot_record.epoch = CoordinatorEpoch::from_value(max_epoch + 1U);
  boot_record.id = BootRecordId::from_value(boot_record.boot.value());
  boot_record.producer = producer;
  boot_record.started_at = monotonic_tick();
  boot_record.closed_at = 0;
  boot_record.clean_shutdown = false;

  if (fresh_document) {
    store.state_.committed_fence.topology = TopologyGeneration::from_value(1);
    store.state_.committed_fence.forwarding = ForwardingGeneration::from_value(1);
    store.state_.committed_fence.policy = PolicyGeneration::from_value(1);
    store.state_.committed_fence.fabric_epoch = FabricEpoch::from_value(1);
    store.state_.committed_fence.epoch = boot_record.epoch;
    store.state_.committed_fence.boot = boot_record.boot;
    store.state_.boot_ledger.push_back(boot_record);
    // The append handle is released before the snapshot is installed, because the
    // snapshot is written by an atomic replace and some platforms refuse to replace an
    // open file.
    const Status written = store.rewrite_snapshot(1U);
    if (!written.is_ok()) {
      store.reset();
      return Result<DurableStore>::failure(written.outcome(), written.detail());
    }
    store.next_sequence_ = 2U;
  } else {
    const std::vector<std::uint8_t> boot_payload = encode_boot_record(boot_record);
    const Status appended = store.append_payload(RecordType::BootAdvance, boot_payload);
    if (!appended.is_ok()) {
      store.reset();
      return Result<DurableStore>::failure(appended.outcome(), appended.detail());
    }
    store.state_.boot_ledger.push_back(boot_record);
    store.state_.committed_fence.boot = boot_record.boot;
    store.state_.committed_fence.epoch = boot_record.epoch;
  }
  store.identity_ =
      ProcessIdentity{boot_record.boot, boot_record.incarnation, boot_record.epoch, producer};

  if (store.state_.boot_ledger.size() > 1U) {
    const BootRecord& previous = store.state_.boot_ledger[store.state_.boot_ledger.size() - 2U];
    if (!previous.clean_shutdown) {
      store.recovery_.explanation.add(
          ReasonCode::FindingFencedByRestart, store.path_,
          "the previous boot " + previous.boot.to_string() +
              " has no clean shutdown record; every pre-restart dynamic fact is treated as stale");
    }
  }
  store.recovery_.outcome = Outcome::Ok;
  store.recovery_.explanation.add(
      ReasonCode::RestartFreshIncarnation, store.path_,
      "minted boot " + boot_record.boot.to_string() + ", incarnation " +
          boot_record.incarnation.to_string() + ", epoch " + boot_record.epoch.to_string());
  store.recovery_.explanation.add(
      ReasonCode::DynamicStateNotRestored, store.path_,
      "observations, leases, grants and in-flight intents are never restored from durable state");
  return Result<DurableStore>::ok(std::move(store));
}

Status DurableStore::append_payload(RecordType type, std::span<const std::uint8_t> payload) {
  if (handle_ == nullptr) {
    return Status::failure(Outcome::Invalid, "the durable store is not open");
  }
  if (payload.size() > Maxima::kRecordPayload) {
    return Status::failure(Outcome::Exhausted, "record payload exceeds the hard ceiling");
  }
  // Compact before appending, never after. The in-memory state always reflects every
  // record that is already in the document, so a rewrite at this point cannot drop the
  // record that is about to be written.
  if (journal_bytes_ > limits_.max_journal_bytes || journal_records_ > limits_.max_journal_records) {
    const Status compacted = compact();
    if (!compacted.is_ok()) {
      return compacted;
    }
  }

  const std::vector<std::uint8_t> frame =
      frame_record(type, next_sequence_, state_.store_generation, payload);
  std::FILE* file = static_cast<std::FILE*>(handle_);
  if (!write_all(file, frame.data(), frame.size())) {
    return Status::failure(Outcome::IoFailure, "journal append failed");
  }
  // Flush and sync *before* the mutation is published in memory: a caller that observes the
  // new state can rely on it being durable.
  const Status synced = flush_and_sync(file);
  if (!synced.is_ok()) {
    return synced;
  }
  ++next_sequence_;
  journal_bytes_ += frame.size();
  ++journal_records_;
  dirty_ = true;
  return Status::ok();
}

Status DurableStore::rewrite_snapshot(std::uint32_t generation) {
  state_.store_generation = generation;
  const std::vector<std::uint8_t> snapshot = encode_store_state(state_, limits_);
  if (snapshot.empty()) {
    return Status::failure(Outcome::Exhausted, "snapshot encoding exceeded its bounds");
  }
  if (snapshot.size() > Maxima::kSnapshotPayload) {
    return Status::failure(Outcome::Exhausted, "snapshot exceeds the hard ceiling");
  }
  const std::vector<std::uint8_t> frame =
      frame_record(RecordType::Snapshot, 1U, generation, snapshot);
  // The append handle is released before the replace: replacing a file that is still open
  // is not permitted on every platform, and the ordering also makes the failure path
  // unambiguous. If the replace fails, the previous document is still on disk and is
  // reopened for append so that the caller can continue from a known state.
  if (handle_ != nullptr) {
    std::fclose(static_cast<std::FILE*>(handle_));
    handle_ = nullptr;
  }
  const Status written = write_file_atomic(path_, frame);
  if (!written.is_ok()) {
    std::FILE* fallback = std::fopen(path_.c_str(), "r+b");
    if (fallback != nullptr) {
      (void)std::fseek(fallback, 0, SEEK_END);
      handle_ = fallback;
    }
    return written;
  }
  std::FILE* reopened = std::fopen(path_.c_str(), "r+b");
  if (reopened == nullptr) {
    return Status::failure(Outcome::IoFailure, "cannot reopen the compacted store");
  }
  if (std::fseek(reopened, 0, SEEK_END) != 0) {
    std::fclose(reopened);
    return Status::failure(Outcome::IoFailure, "cannot seek in the compacted store");
  }
  handle_ = reopened;
  journal_bytes_ = frame.size();
  journal_records_ = 1U;
  return Status::ok();
}

Status DurableStore::compact() {
  if (handle_ == nullptr) {
    return Status::failure(Outcome::Invalid, "the durable store is not open");
  }
  if (state_.store_generation == 0xFFFF'FFFFU) {
    return Status::failure(Outcome::Exhausted, "store generation space is exhausted");
  }
  const Status written = rewrite_snapshot(state_.store_generation + 1U);
  if (!written.is_ok()) {
    return written;
  }
  next_sequence_ = 2U;
  recovery_.snapshot_compacted = true;
  recovery_.explanation.add(ReasonCode::PersistenceSnapshotCommitted, path_,
                            "snapshot rewritten transactionally at store generation " +
                                std::to_string(state_.store_generation));
  return Status::ok();
}

Status DurableStore::set_topology(const TopologyDefinition& topology) {
  auto canonical = canonicalize_topology(topology, limits_);
  if (!canonical.has_value()) {
    return Status::failure(canonical.outcome(), canonical.detail());
  }
  TopologyDefinition definition = std::move(canonical).value();
  if (state_.topology_generation.valid() && definition.generation() <= state_.topology_generation) {
    return Status::failure(Outcome::Stale,
                           "topology generation did not advance past the committed generation");
  }
  StoreState delta;
  delta.topology = definition;
  delta.topology_generation = definition.generation();
  const std::vector<std::uint8_t> payload = encode_record_payload(
      RecordType::TopologyDefinition, delta, Finding{}, LineageRecord{}, BootRecord{}, limits_);
  if (payload.empty()) {
    return Status::failure(Outcome::Exhausted, "topology payload could not be encoded");
  }
  const Status status = append_payload(RecordType::TopologyDefinition, payload);
  if (!status.is_ok()) {
    return status;
  }
  state_.topology = std::move(definition);
  state_.topology_generation = state_.topology->generation();
  return Status::ok();
}

Status DurableStore::set_policy(const ContainmentPolicy& policy) {
  if (!policy.generation.valid()) {
    return Status::failure(Outcome::Invalid, "policy generation must be non-zero");
  }
  if (state_.policy.has_value() && policy.generation < state_.policy->generation) {
    return Status::failure(Outcome::Stale, "policy generation regressed");
  }
  StoreState delta;
  delta.policy = policy;
  const std::vector<std::uint8_t> payload = encode_record_payload(
      RecordType::ContainmentPolicyRecord, delta, Finding{}, LineageRecord{}, BootRecord{}, limits_);
  if (payload.empty()) {
    return Status::failure(Outcome::Exhausted, "policy payload could not be encoded");
  }
  const Status status = append_payload(RecordType::ContainmentPolicyRecord, payload);
  if (!status.is_ok()) {
    return status;
  }
  state_.policy = policy;
  return Status::ok();
}

Status DurableStore::advance_fence(const FenceVector& fence) {
  StoreState delta;
  delta.committed_fence = fence;
  const std::vector<std::uint8_t> payload = encode_record_payload(
      RecordType::FenceAdvance, delta, Finding{}, LineageRecord{}, BootRecord{}, limits_);
  if (payload.empty()) {
    return Status::failure(Outcome::Exhausted, "fence payload could not be encoded");
  }
  const Status status = append_payload(RecordType::FenceAdvance, payload);
  if (!status.is_ok()) {
    return status;
  }
  state_.committed_fence = fence;
  return Status::ok();
}

Status DurableStore::append_lineage(const LineageRecord& record) {
  if (!record.sequence.valid()) {
    return Status::failure(Outcome::Invalid, "lineage sequence must be non-zero");
  }
  if (state_.lineage_sequence.valid() && record.sequence <= state_.lineage_sequence) {
    return Status::failure(Outcome::Stale, "lineage sequence regressed");
  }
  const std::vector<std::uint8_t> payload = encode_record_payload(
      RecordType::LineageAppend, StoreState{}, Finding{}, record, BootRecord{}, limits_);
  if (payload.empty()) {
    return Status::failure(Outcome::Exhausted, "lineage payload could not be encoded");
  }
  const Status status = append_payload(RecordType::LineageAppend, payload);
  if (!status.is_ok()) {
    return status;
  }
  state_.lineage.push_back(record);
  state_.lineage_sequence = record.sequence;
  while (state_.lineage.size() > limits_.max_retained_lineage) {
    state_.lineage.erase(state_.lineage.begin());
  }
  return Status::ok();
}

Status DurableStore::upsert_finding(const Finding& finding) {
  if (!finding.id.valid() || !finding.generation.valid()) {
    return Status::failure(Outcome::Invalid, "finding identity and generation must be non-zero");
  }
  const std::vector<std::uint8_t> payload = encode_record_payload(
      RecordType::FindingUpsert, StoreState{}, finding, LineageRecord{}, BootRecord{}, limits_);
  if (payload.empty()) {
    return Status::failure(Outcome::Exhausted, "finding payload could not be encoded");
  }
  const Status status = append_payload(RecordType::FindingUpsert, payload);
  if (!status.is_ok()) {
    return status;
  }
  bool replaced = false;
  for (Finding& existing : state_.findings) {
    if (existing.id == finding.id) {
      existing = finding;
      replaced = true;
      break;
    }
  }
  if (!replaced) {
    state_.findings.push_back(finding);
  }
  while (state_.findings.size() > limits_.max_retained_findings) {
    state_.findings.erase(state_.findings.begin());
  }
  state_.finding_sequence = AttemptSequence::from_value(finding.generation.value());
  return Status::ok();
}

Status DurableStore::withdraw_finding(FindingId id, FenceCause cause, Tick now, ReasonCode reason) {
  Finding withdrawal;
  withdrawal.id = id;
  withdrawal.fence_cause = cause;
  withdrawal.updated_at = now;
  withdrawal.explanation = Explanation(limits_.max_explanation_reasons);
  withdrawal.explanation.add(reason, id.to_string(), "withdrawn by the owning runtime");
  const std::vector<std::uint8_t> payload = encode_record_payload(
      RecordType::FindingWithdraw, StoreState{}, withdrawal, LineageRecord{}, BootRecord{}, limits_);
  if (payload.empty()) {
    return Status::failure(Outcome::Exhausted, "withdrawal payload could not be encoded");
  }
  const Status status = append_payload(RecordType::FindingWithdraw, payload);
  if (!status.is_ok()) {
    return status;
  }
  for (Finding& existing : state_.findings) {
    if (existing.id == id) {
      existing.state = FindingState::Withdrawn;
      existing.fence_cause = cause;
      existing.updated_at = now;
      existing.explanation.add(reason, id.to_string(), "withdrawn by the owning runtime");
      return Status::ok();
    }
  }
  return Status::failure(Outcome::NotFound, "finding is not durable");
}

Status DurableStore::flush() {
  if (handle_ == nullptr) {
    return Status::ok();
  }
  return flush_and_sync(static_cast<std::FILE*>(handle_));
}

Status DurableStore::close(bool clean) {
  if (handle_ == nullptr) {
    return Status::ok();
  }
  Status status = Status::ok();
  if (clean && identity_.boot.valid()) {
    const Tick now = monotonic_tick();
    const std::vector<std::uint8_t> payload = encode_shutdown_marker(identity_.boot, true, now);
    status = append_payload(RecordType::Note, payload);
    if (status.is_ok()) {
      for (BootRecord& record : state_.boot_ledger) {
        if (record.boot == identity_.boot) {
          record.clean_shutdown = true;
          record.closed_at = now;
          break;
        }
      }
    }
  }
  if (status.is_ok()) {
    status = flush();
  }
  reset();
  return status;
}

}  // namespace loop_guard
