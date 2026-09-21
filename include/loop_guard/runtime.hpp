// Loop Guard - the runtime facade.
//
// The runtime owns the durable definitions, the dynamic evidence ledger, the detector,
// the containment planner, the finding registry and the authority lineage. It is the
// only supported entry point for a service; every entry point below is thread safe.
//
// Locking contract (audited in docs/OWNERSHIP_AUDIT.md):
//   * the runtime holds exactly one mutex, and it is never held across a callback, a
//     filesystem write, a socket operation or a nested runtime call;
//   * no runtime method re-enters another runtime method while holding the lock: every
//     public method takes the lock once, copies what it needs, and releases before
//     invoking anything that could call back;
//   * observer callbacks are invoked after the lock is released, with a copy of the
//     finding, so a callback cannot observe torn state and cannot deadlock the runtime.
#pragma once

#include <functional>
#include <memory>
#include <optional>
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
#include "loop_guard/witness.hpp"

namespace loop_guard {

struct RuntimeConfig {
  Limits limits;
  ProducerId producer;
  /// Empty means "run without durable state". A non-empty path creates or reopens a
  /// journaled store and mints a fresh boot/incarnation/epoch.
  std::string store_path;
  /// True when the caller knows the previous process shut down cleanly.
  bool previous_shutdown_was_clean = false;
  /// Tick used to stamp the boot. Callers supply time; the library never reads a clock
  /// in a decision path.
  Tick boot_tick = 0;
  EvidenceOrigin origin = EvidenceOrigin::Synthetic;
};

struct RuntimeCounters {
  std::uint64_t observations_submitted = 0;
  std::uint64_t observations_rejected = 0;
  std::uint64_t assessments_run = 0;
  std::uint64_t findings_published = 0;
  std::uint64_t findings_refused = 0;
  std::uint64_t findings_fenced = 0;
  std::uint64_t plans_computed = 0;
  std::uint64_t intents_issued = 0;
  std::uint64_t intents_refused = 0;
  std::uint64_t effects_recorded = 0;
  std::uint64_t effects_unverified = 0;
  std::uint64_t lineage_records = 0;
  std::uint64_t retained_attempts = 0;
};

class Runtime {
 public:
  Runtime() noexcept;
  ~Runtime();
  Runtime(const Runtime&) = delete;
  Runtime& operator=(const Runtime&) = delete;
  Runtime(Runtime&& other) noexcept;
  Runtime& operator=(Runtime&& other) noexcept;

  [[nodiscard]] static Result<Runtime> open(const RuntimeConfig& config);

  [[nodiscard]] bool is_open() const noexcept;

  // --- Authority identity and fence -----------------------------------------
  [[nodiscard]] ProcessIdentity identity() const;
  [[nodiscard]] FenceVector fence() const;
  [[nodiscard]] const Limits& limits() const;
  [[nodiscard]] const RecoveryReport& recovery() const;
  [[nodiscard]] RuntimeCounters counters() const;

  /// Advances the forwarding generation. Every live finding is fenced.
  [[nodiscard]] Status advance_forwarding(ForwardingGeneration generation, Tick now);
  /// Advances the fabric epoch. Every live finding is fenced.
  [[nodiscard]] Status advance_fabric_epoch(FabricEpoch epoch, Tick now);
  /// Advances the coordinator epoch without restarting. Every live finding is fenced.
  [[nodiscard]] Status advance_epoch(Tick now);

  // --- Definitions -----------------------------------------------------------
  /// Installs a topology definition. The definition's generation must be strictly
  /// greater than the installed one; a regression is refused as Stale.
  [[nodiscard]] Status set_topology(TopologyDefinition topology, Tick now);
  [[nodiscard]] Status set_policy(ContainmentPolicy policy, Tick now);
  [[nodiscard]] std::optional<TopologyDefinition> topology() const;
  [[nodiscard]] std::optional<ContainmentPolicy> policy() const;

  // --- Evidence --------------------------------------------------------------
  [[nodiscard]] Status submit_observation(const ForwardingObservation& observation, Tick now);
  [[nodiscard]] Status clear_evidence();
  [[nodiscard]] std::size_t observation_count() const;

  // --- Detection and containment --------------------------------------------
  [[nodiscard]] Result<LoopAssessment> detect(Tick now,
                                              std::vector<TrafficSelectorId> selector_scope = {});
  /// Publishes a finding for an affirmative assessment. A non-affirmative assessment is
  /// refused with Outcome::Refused; UNKNOWN never becomes a finding.
  [[nodiscard]] Result<Finding> publish_finding(const LoopAssessment& assessment, Tick now);
  [[nodiscard]] Result<ContainmentPlan> plan_containment(const LoopAssessment& assessment,
                                                         Tick now);
  [[nodiscard]] Result<ContainmentIntent> authorize_containment(
      FindingId finding, const ContainmentGrant& grant, Tick now, Tick lease_ticks,
      std::vector<ResourceId> targets = {});
  [[nodiscard]] Status record_acknowledgement(const ContainmentAcknowledgement& ack, Tick now);
  [[nodiscard]] Status record_verified_effect(ContainmentIntentId intent,
                                              const VerifiedEffect& effect, Tick now);
  [[nodiscard]] Status withdraw_finding(FindingId finding, ReasonCode reason, Tick now,
                                        std::string detail = {});

  // --- Findings and lineage --------------------------------------------------
  [[nodiscard]] std::optional<Finding> find_finding(FindingId id) const;
  [[nodiscard]] std::vector<FindingSummary> findings() const;
  [[nodiscard]] std::vector<LineageRecord> lineage() const;
  [[nodiscard]] std::optional<ContainmentPlan> find_plan(ContainmentPlanId id) const;
  [[nodiscard]] std::optional<ContainmentApplication> application(ContainmentIntentId id) const;

  // --- Lifecycle -------------------------------------------------------------
  /// Observer invoked after the lock is released, with a copy of the finding.
  void set_finding_observer(std::function<void(const Finding&)> observer);
  /// Flushes and (when the store exists) closes durable state, marking the boot clean.
  [[nodiscard]] Status close(bool clean_shutdown);
  [[nodiscard]] Digest state_digest() const;
  [[nodiscard]] std::string describe() const;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace loop_guard
