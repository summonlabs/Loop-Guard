// Loop Guard - durable state.
//
// What is durable here is exactly what is legitimately durable: topology definitions,
// containment policy, the boot/incarnation ledger, committed authority lineage and
// completed findings with their fences. Nothing dynamic is durable. Observations,
// leases, in-flight intents, live grants and verified effects never survive restart:
// their semantics do not survive a process boundary, so restoring them would convert
// old evidence into current authority.
//
// Durability rules enforced by this layer:
//   * every record carries magic, format version, record type, flags, sequence,
//     declared payload length, a payload digest and a header digest;
//   * a declared length above the hard ceiling is refused before allocation;
//   * corrupt headers, corrupt payloads, impossible lengths, unsupported versions,
//     invalid enums, sequence regression and trailing garbage all refuse the open -
//     they are never silently truncated, because they may represent tampering;
//   * only a genuine torn tail is recovered, and only when the trailing bytes are a
//     strict prefix of a well-formed record;
//   * snapshots and compactions are written to a temporary file, flushed, and moved
//     into place with an atomic replace; the journal record is flushed before the
//     mutation is published in memory.
#pragma once

#include <cstdint>
#include <cstddef>
#include <optional>
#include <string>
#include <vector>

#include "loop_guard/authority.hpp"
#include "loop_guard/containment.hpp"
#include "loop_guard/core.hpp"
#include "loop_guard/digest.hpp"
#include "loop_guard/enums.hpp"
#include "loop_guard/finding.hpp"
#include "loop_guard/id.hpp"
#include "loop_guard/limits.hpp"
#include "loop_guard/result.hpp"
#include "loop_guard/topology.hpp"

namespace loop_guard {

/// Durable format versions. A reader accepts exactly these values and refuses
/// anything else with Outcome::Unsupported.
inline constexpr std::uint16_t kDurableRecordVersion = 1;
inline constexpr std::uint16_t kDurableSnapshotSchema = 1;
inline constexpr std::uint32_t kDurableMagic = 0x3147524CU;  // "LGR1"

/// Size of the fixed record header that precedes every payload.
inline constexpr std::size_t kRecordHeaderBytes = 88;

enum class RecordType : std::uint16_t {
  Snapshot = 0,
  TopologyDefinition = 1,
  ContainmentPolicyRecord = 2,
  LineageAppend = 3,
  FindingUpsert = 4,
  FindingWithdraw = 5,
  BootAdvance = 6,
  FenceAdvance = 7,
  Note = 8,
};

[[nodiscard]] bool is_valid_record_type(std::uint16_t raw) noexcept;
[[nodiscard]] std::string_view to_string(RecordType type) noexcept;

/// One boot of the runtime. The ledger is durable and grows by exactly one entry per
/// successful open; it is the mechanism that makes restart authority explicit.
struct BootRecord {
  BootRecordId id;
  BootId boot;
  IncarnationId incarnation;
  CoordinatorEpoch epoch;
  ProducerId producer;
  Tick started_at = 0;
  /// Tick at which the *next* boot recorded this one as closed. Zero while unknown,
  /// which is exactly what an unclean shutdown leaves behind.
  Tick closed_at = 0;
  bool clean_shutdown = false;

  friend bool operator==(const BootRecord&, const BootRecord&) noexcept = default;
  [[nodiscard]] Digest content_digest() const;
};

/// What happened while reopening the durable state.
struct RecoveryReport {
  Outcome outcome = Outcome::Invalid;
  std::uint64_t records_read = 0;
  std::uint64_t records_applied = 0;
  std::uint64_t bytes_read = 0;
  bool torn_tail_recovered = false;
  std::uint64_t torn_tail_bytes = 0;
  bool trailing_garbage = false;
  bool snapshot_compacted = false;
  Explanation explanation;

  [[nodiscard]] std::string to_text() const;
};

/// Everything that legitimately survives restart.
struct StoreState {
  std::uint16_t record_version = kDurableRecordVersion;
  std::uint16_t snapshot_schema = kDurableSnapshotSchema;
  /// Incremented once per snapshot compaction. Every mutation record carries the
  /// generation it belongs to, so bytes salvaged from a superseded document are refused
  /// instead of being replayed into the current one.
  std::uint32_t store_generation = 1;
  TopologyGeneration topology_generation;
  std::optional<TopologyDefinition> topology;
  std::optional<ContainmentPolicy> policy;
  std::vector<BootRecord> boot_ledger;
  std::vector<LineageRecord> lineage;
  std::vector<Finding> findings;
  FenceVector committed_fence;
  AttemptSequence lineage_sequence;
  AttemptSequence finding_sequence;
  AttemptSequence assessment_sequence;

  [[nodiscard]] Digest digest() const;
};

/// Canonical encoders/decoders for the durable document. Decoding is total and
/// sticky: the first violation aborts and is reported as an Outcome.
[[nodiscard]] std::vector<std::uint8_t> encode_store_state(const StoreState& state,
                                                           const Limits& limits);
[[nodiscard]] Result<StoreState> decode_store_state(std::span<const std::uint8_t> bytes,
                                                    const Limits& limits);

/// Encodes and decodes one mutation payload.
[[nodiscard]] std::vector<std::uint8_t> encode_record_payload(RecordType type,
                                                              const StoreState& delta,
                                                              const Finding& finding,
                                                              const LineageRecord& lineage,
                                                              const BootRecord& boot,
                                                              const Limits& limits);
[[nodiscard]] Result<StoreState> decode_record_payload(RecordType type,
                                                       std::span<const std::uint8_t> payload,
                                                       const Limits& limits);

[[nodiscard]] std::vector<std::uint8_t> encode_finding(const Finding& finding, const Limits& limits);
[[nodiscard]] Result<Finding> decode_finding(std::span<const std::uint8_t> bytes, const Limits& limits);
[[nodiscard]] std::vector<std::uint8_t> encode_lineage(const LineageRecord& record);
[[nodiscard]] Result<LineageRecord> decode_lineage(std::span<const std::uint8_t> bytes,
                                                   const Limits& limits);
[[nodiscard]] std::vector<std::uint8_t> encode_boot_record(const BootRecord& record);
[[nodiscard]] Result<BootRecord> decode_boot_record(std::span<const std::uint8_t> bytes,
                                                    const Limits& limits);
/// Payload of a clean/unclean shutdown marker. It carries no authority; it only records
/// what the durable ledger knows about how a boot ended.
[[nodiscard]] std::vector<std::uint8_t> encode_shutdown_marker(BootId boot, bool clean, Tick at);
[[nodiscard]] Result<BootRecord> decode_shutdown_marker(std::span<const std::uint8_t> bytes,
                                                        const Limits& limits);
/// Payload of a finding withdrawal. Decoded as a Finding carrying only the withdrawal.
[[nodiscard]] std::vector<std::uint8_t> encode_finding_withdrawal(FindingId id, FenceCause cause,
                                                                  Tick now, ReasonCode reason,
                                                                  std::string_view detail);
[[nodiscard]] Result<Finding> decode_finding_withdrawal(std::span<const std::uint8_t> bytes,
                                                        const Limits& limits);

/// Builds a complete record frame (header + payload). The store generation is carried
/// in the header so that bytes salvaged from a superseded document are refused.
[[nodiscard]] std::vector<std::uint8_t> frame_record(RecordType type, std::uint64_t sequence,
                                                     std::uint32_t store_generation,
                                                     std::span<const std::uint8_t> payload);

struct DecodedRecord {
  RecordType type = RecordType::Snapshot;
  std::uint16_t version = 0;
  std::uint32_t flags = 0;
  std::uint64_t sequence = 0;
  std::vector<std::uint8_t> payload;
};

/// Result of decoding one record frame at \p offset in \p bytes.
enum class RecordDecodeStatus : std::uint8_t {
  Ok = 0,
  TornTail = 1,      ///< Trailing bytes are a strict prefix of a well-formed record.
  Corrupt = 2,       ///< Integrity, version, enum or length violation. Never recovered.
  End = 3,           ///< No bytes remain.
};

struct RecordDecodeResult {
  RecordDecodeStatus status = RecordDecodeStatus::End;
  DecodedRecord record;
  std::size_t next_offset = 0;
  ReasonCode reason = ReasonCode::PersistenceRecordRejected;
  std::string detail;
};

[[nodiscard]] RecordDecodeResult decode_record_at(std::span<const std::uint8_t> bytes,
                                                  std::size_t offset, const Limits& limits);

/// Transactional, journaled durable store.
///
/// Not copyable: it owns an open file handle and a durability ordering contract.
/// Movable so that it can be returned from open_or_create().
class DurableStore {
 public:
  DurableStore() = default;
  ~DurableStore();

  DurableStore(const DurableStore&) = delete;
  DurableStore& operator=(const DurableStore&) = delete;
  DurableStore(DurableStore&& other) noexcept;
  DurableStore& operator=(DurableStore&& other) noexcept;

  /// Opens or creates the store at \p path.
  ///
  /// The call always mints a fresh boot/incarnation/epoch: reopening never reuses a
  /// previous incarnation's authority. The previous boot record is closed as unclean
  /// unless \p previous_shutdown_was_clean is true.
  [[nodiscard]] static Result<DurableStore> open_or_create(const std::string& path,
                                                           const Limits& limits,
                                                           ProducerId producer);

  [[nodiscard]] bool is_open() const noexcept { return handle_ != nullptr; }
  [[nodiscard]] const std::string& path() const noexcept { return path_; }
  [[nodiscard]] const StoreState& state() const noexcept { return state_; }
  [[nodiscard]] const RecoveryReport& recovery() const noexcept { return recovery_; }
  [[nodiscard]] const ProcessIdentity& identity() const noexcept { return identity_; }

  /// Durable mutations. Each one appends a journal record, flushes it, and only then
  /// publishes the change in memory. A failure leaves the in-memory state untouched.
  [[nodiscard]] Status set_topology(const TopologyDefinition& topology);
  [[nodiscard]] Status set_policy(const ContainmentPolicy& policy);
  [[nodiscard]] Status advance_fence(const FenceVector& fence);
  [[nodiscard]] Status append_lineage(const LineageRecord& record);
  [[nodiscard]] Status upsert_finding(const Finding& finding);
  [[nodiscard]] Status withdraw_finding(FindingId id, FenceCause cause, Tick now, ReasonCode reason);

  /// Rewrites the store as a single snapshot record using a temporary file and an
  /// atomic replace. Used when the journal exceeds its configured bounds.
  [[nodiscard]] Status compact();
  /// Flushes any buffered journal bytes to durable storage.
  [[nodiscard]] Status flush();
  /// Marks the current boot as cleanly shut down and releases the handle.
  [[nodiscard]] Status close(bool clean);

  [[nodiscard]] std::uint64_t journal_bytes() const noexcept { return journal_bytes_; }
  [[nodiscard]] std::uint64_t journal_records() const noexcept { return journal_records_; }

 private:
  [[nodiscard]] Status append_payload(RecordType type, std::span<const std::uint8_t> payload);
  [[nodiscard]] Status rewrite_snapshot(std::uint32_t generation);

  void reset() noexcept;
  void move_from(DurableStore&& other) noexcept;

  void* handle_ = nullptr;  ///< std::FILE* on every supported platform.
  std::string path_;
  Limits limits_;
  StoreState state_;
  RecoveryReport recovery_;
  ProcessIdentity identity_;
  std::uint64_t journal_bytes_ = 0;
  std::uint64_t journal_records_ = 0;
  std::uint64_t next_sequence_ = 1;
  bool dirty_ = false;
};

/// Reads a whole file into memory with an explicit size ceiling. Refuses rather than
/// allocating an unbounded buffer.
[[nodiscard]] Result<std::vector<std::uint8_t>> read_file_bounded(const std::string& path,
                                                                  std::uint64_t max_bytes);

/// Writes \p bytes to \p path, flushes, and (on POSIX) fsyncs, then atomically
/// replaces \p path. The temporary file is removed on every failure path.
[[nodiscard]] Status write_file_atomic(const std::string& path, std::span<const std::uint8_t> bytes);

/// Removes a file, reporting whether it existed. Never throws.
[[nodiscard]] Status remove_file_if_present(const std::string& path);

/// Returns the process-local monotonic tick. Used by tools for leases and expiry; the
/// library itself always takes ticks as parameters.
[[nodiscard]] Tick monotonic_tick() noexcept;

}  // namespace loop_guard
