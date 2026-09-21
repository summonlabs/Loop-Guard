// Loop Guard - bounded resources.
//
// Every table, history, queue, document, explanation and retained attempt in this
// runtime is bounded before allocation. Limits are explicit, checked before use,
// and reported as outcomes rather than by process instability.
#pragma once

#include <cstddef>
#include <cstdint>

namespace loop_guard {

/// Absolute ceilings enforced by the wire codec and the persistence layer. These
/// are compile-time constants: they cannot be widened by a caller, and a peer
/// cannot negotiate them upward.
struct Maxima {
  /// Largest accepted frame payload. A declared payload above this is refused
  /// before any allocation proportional to the declared length happens.
  static constexpr std::uint32_t kFramePayload = 1U << 20U;  // 1 MiB
  /// Largest accepted hello/negotiation payload.
  static constexpr std::uint32_t kHandshakePayload = 4U * 1024U;
  /// Largest accepted durable record payload.
  static constexpr std::uint32_t kRecordPayload = 4U << 20U;  // 4 MiB
  /// Largest accepted durable snapshot payload.
  static constexpr std::uint32_t kSnapshotPayload = 32U << 20U;  // 32 MiB
  /// Largest accepted canonical document (whole store file).
  static constexpr std::uint64_t kDocumentBytes = 1ULL << 32U;  // 4 GiB
  /// Hard ceiling on any single in-memory collection decoded from untrusted bytes.
  static constexpr std::uint32_t kCollectionElements = 1U << 20U;
  /// Hard ceiling on canonical string length accepted from untrusted bytes.
  static constexpr std::uint32_t kStringBytes = 4096U;
};

/// Runtime-configurable bounds. Defaults are deliberately small enough that the
/// bounded-search behaviour is exercised by the ordinary suites.
struct Limits {
  /// Maximum length (hops) of a loop witness the detector will accept or emit.
  std::uint32_t max_witness_hops = 64;
  /// Maximum number of witnesses retained in one assessment.
  std::uint32_t max_witnesses_per_assessment = 256;
  /// Maximum number of simple cycles enumerated while searching for loops.
  std::uint64_t max_cycles_enumerated = 200000;
  /// Maximum number of DFS steps (edge examinations) during cycle enumeration.
  std::uint64_t max_search_steps = 4000000;
  /// Maximum resources accepted in one topology definition.
  std::uint32_t max_resources = 65536;
  /// Maximum edges accepted in one topology definition.
  std::uint32_t max_edges = 262144;
  /// Maximum traffic selectors accepted in one topology definition.
  std::uint32_t max_selectors = 8192;
  /// Maximum live observations retained per edge before the oldest is evicted.
  std::uint32_t max_observations_per_edge = 8;
  /// Maximum live observations retained in one ledger.
  std::uint32_t max_observations = 262144;
  /// Maximum retained assessments kept in the runtime history.
  std::uint32_t max_retained_assessments = 512;
  /// Maximum retained findings kept in the runtime registry.
  std::uint32_t max_retained_findings = 512;
  /// Maximum retained containment plans.
  std::uint32_t max_retained_plans = 512;
  /// Maximum lineage records retained in memory (journal is separately bounded).
  std::uint32_t max_retained_lineage = 4096;
  /// Maximum distinct traffic selectors the detector will consider when proving cycle
  /// absence. Exceeding this bound yields INDETERMINATE, never NO_LOOP.
  std::uint32_t max_candidate_selectors = 1024;
  /// Maximum containment targets a single plan may carry.
  std::uint32_t max_plan_targets = 64;
  /// Maximum length of one textual line inside a canonical document.
  std::uint32_t max_text_line = 1024;
  /// Maximum reason entries carried by one explanation document.
  std::uint32_t max_explanation_reasons = 64;
  /// Maximum detail string length carried by one explanation reason.
  std::uint32_t max_reason_detail_bytes = 256;
  /// Node budget for the containment search (branch-and-bound expansions).
  std::uint64_t max_containment_search_nodes = 2000000;
  /// Maximum candidate target subsets inspected by the containment search.
  std::uint64_t max_containment_candidates = 2000000;
  /// Durable journal: maximum records retained before snapshot compaction is required.
  /// This bound applies to the journal, never to the collections a snapshot may hold.
  std::uint32_t max_journal_records = 100000;
  /// Maximum boot-ledger entries a durable document may hold. Bounded separately from
  /// the journal so that a compacted document with many retained records still decodes.
  std::uint32_t max_boot_records = 4096;
  /// Durable journal: maximum bytes retained before snapshot compaction is required.
  std::uint64_t max_journal_bytes = 64ULL << 20U;
  /// Maximum concurrent sessions accepted by the coordinator.
  std::uint32_t max_sessions = 64;
  /// Maximum queued inbound frames per session.
  std::uint32_t max_session_queue = 256;
  /// Maximum peers accepted in one listener backlog.
  std::uint32_t max_backlog = 32;
};

/// The default limits used by every entry point unless a caller supplies others.
[[nodiscard]] const Limits& default_limits() noexcept;

/// Validates a caller-supplied limit set against Maxima. Returns false when any
/// field exceeds a hard ceiling or is zero where zero is meaningless.
[[nodiscard]] bool limits_are_sane(const Limits& limits) noexcept;

}  // namespace loop_guard
