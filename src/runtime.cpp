#include "loop_guard/runtime.hpp"

#include <algorithm>
#include <map>
#include <mutex>
#include <set>

namespace loop_guard {
namespace {

void hash_u64(Sha256& hasher, std::uint64_t value) {
  hasher.update(
      std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(&value), sizeof(value)));
}

}  // namespace

// ---------------------------------------------------------------------------
// Runtime::Impl
//
// Ownership and locking audit (see docs/OWNERSHIP_AUDIT.md):
//   * exactly one mutex guards all mutable runtime state;
//   * no public method calls another public method while holding the mutex, and no
//     callback, filesystem operation or allocation of user code runs under it;
//   * the durable store is written while the mutex is held only because the store is
//     owned exclusively by this runtime and its methods never call back into it; the
//     comment at each site records that invariant;
//   * observer callbacks are invoked after the lock is released, on a copy.
// ---------------------------------------------------------------------------
struct Runtime::Impl {
  /// Appends a lineage record and, when a durable store exists, commits it before the
  /// in-memory lineage is extended. The store is owned exclusively by this runtime, so
  /// calling it under the runtime mutex cannot re-enter the runtime.
  Status append_lineage(AuthorityKind kind, FindingId finding, ContainmentPlanId plan,
                        ContainmentIntentId intent, const FenceVector& bound_fence, Digest subject,
                        ReasonCode reason, Severity severity, Tick now);

  mutable std::mutex mutex;
  RuntimeConfig config;
  bool open = false;
  ProcessIdentity identity;
  FenceVector fence;
  TopologyDefinition topology;
  bool has_topology = false;
  ContainmentPolicy policy;
  bool has_policy = false;
  EvidenceLedger ledger;
  FindingRegistry findings;
  DurableStore store;
  bool has_store = false;
  RecoveryReport recovery;
  LoopDetector detector;
  ContainmentPlanner planner;
  std::vector<LineageRecord> lineage;
  std::map<std::uint64_t, ContainmentPlan> plans;
  std::map<std::uint64_t, ContainmentApplication> applications;
  RuntimeCounters counters;
  std::function<void(const Finding&)> observer;
};

Runtime::Runtime() noexcept = default;
Runtime::~Runtime() = default;
Runtime::Runtime(Runtime&& other) noexcept : impl_(std::move(other.impl_)) {}
Runtime& Runtime::operator=(Runtime&& other) noexcept {
  if (this != &other) {
    impl_ = std::move(other.impl_);
  }
  return *this;
}

Result<Runtime> Runtime::open(const RuntimeConfig& config) {
  if (!limits_are_sane(config.limits)) {
    return Result<Runtime>::failure(Outcome::Unsupported, "limit set is not sane");
  }
  auto impl = std::make_unique<Impl>();
  impl->config = config;
  impl->ledger = EvidenceLedger(config.limits);
  impl->findings = FindingRegistry(config.limits);
  impl->detector = LoopDetector(config.limits);
  impl->planner = ContainmentPlanner(config.limits);
  impl->recovery.explanation = Explanation(config.limits.max_explanation_reasons);

  if (!config.store_path.empty()) {
    auto store = DurableStore::open_or_create(config.store_path, config.limits, config.producer);
    if (!store.has_value()) {
      return Result<Runtime>::failure(store.outcome(), store.detail());
    }
    impl->store = std::move(store.value());
    impl->has_store = true;
    impl->identity = impl->store.identity();
    impl->recovery = impl->store.recovery();
    const StoreState& state = impl->store.state();
    if (state.topology.has_value()) {
      impl->topology = *state.topology;
      impl->has_topology = true;
    }
    if (state.policy.has_value()) {
      impl->policy = *state.policy;
      impl->has_policy = true;
    }
    impl->lineage = state.lineage;
    // Durable findings are restored only as fenced history: their state is forced to
    // Fenced, because the process that produced them no longer exists.
    for (const Finding& finding : state.findings) {
      Finding restored = finding;
      restored.state = FindingState::Fenced;
      restored.fence_cause = FenceCause::BootAdvanced;
      restored.explanation.add(ReasonCode::FindingFencedByRestart, restored.id.to_string(),
                               "restored from durable state; the producing incarnation is gone");
      (void)impl->findings.register_finding(std::move(restored));
    }
    impl->fence = state.committed_fence;
    impl->fence.boot = impl->identity.boot;
    impl->fence.epoch = impl->identity.epoch;
    if (!impl->fence.topology.valid() && impl->has_topology) {
      impl->fence.topology = impl->topology.generation();
    }
    if (!impl->fence.forwarding.valid()) {
      impl->fence.forwarding = ForwardingGeneration::from_value(1);
    }
    if (!impl->fence.policy.valid()) {
      impl->fence.policy = impl->has_policy ? impl->policy.generation : PolicyGeneration::from_value(1);
    }
    if (!impl->fence.fabric_epoch.valid()) {
      impl->fence.fabric_epoch = FabricEpoch::from_value(1);
    }
    impl->recovery.explanation.add(
        ReasonCode::DynamicStateNotRestored, config.store_path,
        "restart restored definitions, policy and lineage; observations, leases, grants and "
        "in-flight intents were dropped");
  } else {
    impl->identity = ProcessIdentity{BootId::from_value(1), IncarnationId::from_value(1),
                                     CoordinatorEpoch::from_value(1), config.producer};
    impl->fence.boot = impl->identity.boot;
    impl->fence.epoch = impl->identity.epoch;
    impl->fence.forwarding = ForwardingGeneration::from_value(1);
    impl->fence.policy = PolicyGeneration::from_value(1);
    impl->fence.fabric_epoch = FabricEpoch::from_value(1);
    impl->recovery.outcome = Outcome::Ok;
    impl->recovery.explanation.add(ReasonCode::RestartFreshIncarnation, "in-memory",
                                   "the runtime was opened without durable state");
  }

  // Every finding restored from an earlier incarnation is fenced before the runtime
  // answers any question.
  (void)impl->findings.fence_boot(impl->fence, config.boot_tick);
  impl->fence.topology = impl->has_topology ? impl->topology.generation()
                                            : TopologyGeneration::from_value(1);
  impl->open = true;
  auto runtime = Runtime();
  runtime.impl_ = std::move(impl);
  return Result<Runtime>::ok(std::move(runtime));
}

bool Runtime::is_open() const noexcept { return impl_ != nullptr && impl_->open; }

ProcessIdentity Runtime::identity() const {
  if (impl_ == nullptr) {
    return ProcessIdentity{};
  }
  const std::lock_guard<std::mutex> lock(impl_->mutex);
  return impl_->identity;
}

FenceVector Runtime::fence() const {
  if (impl_ == nullptr) {
    return FenceVector{};
  }
  const std::lock_guard<std::mutex> lock(impl_->mutex);
  return impl_->fence;
}

const Limits& Runtime::limits() const {
  static const Limits kFallback;
  if (impl_ == nullptr) {
    return kFallback;
  }
  const std::lock_guard<std::mutex> lock(impl_->mutex);
  return impl_->config.limits;
}

const RecoveryReport& Runtime::recovery() const {
  static const RecoveryReport kFallback;
  if (impl_ == nullptr) {
    return kFallback;
  }
  const std::lock_guard<std::mutex> lock(impl_->mutex);
  return impl_->recovery;
}

RuntimeCounters Runtime::counters() const {
  if (impl_ == nullptr) {
    return RuntimeCounters{};
  }
  const std::lock_guard<std::mutex> lock(impl_->mutex);
  return impl_->counters;
}

void Runtime::set_finding_observer(std::function<void(const Finding&)> observer) {
  if (impl_ == nullptr) {
    return;
  }
  const std::lock_guard<std::mutex> lock(impl_->mutex);
  impl_->observer = std::move(observer);
}

Status Runtime::Impl::append_lineage(AuthorityKind kind, FindingId finding, ContainmentPlanId plan,
                                     ContainmentIntentId intent, const FenceVector& bound_fence,
                                     Digest subject, ReasonCode reason, Severity severity,
                                     Tick now) {
  Impl& impl = *this;
  const auto next = impl.lineage.empty()
                        ? AttemptSequence::from_value(1)
                        : impl.lineage.back().sequence.try_next().value_or(AttemptSequence{});
  if (!next.valid()) {
    return Status::failure(Outcome::Exhausted, "lineage sequence space is exhausted");
  }
  LineageRecord record;
  record.sequence = next;
  record.id = LineageRecordId::from_value(next.value());
  record.recorded_at = now;
  record.kind = kind;
  record.finding = finding;
  record.plan = plan;
  record.intent = intent;
  record.fence = bound_fence;
  record.subject_digest = subject;
  record.reason = reason;
  record.severity = severity;

  if (impl.has_store) {
    const Status status = impl.store.append_lineage(record);
    if (!status.is_ok()) {
      return status;
    }
  }
  impl.lineage.push_back(record);
  while (impl.lineage.size() > impl.config.limits.max_retained_lineage) {
    impl.lineage.erase(impl.lineage.begin());
  }
  ++impl.counters.lineage_records;
  impl.counters.retained_attempts = impl.lineage.size();
  return Status::ok();
}

Status Runtime::advance_forwarding(ForwardingGeneration generation, Tick now) {
  if (impl_ == nullptr) {
    return Status::failure(Outcome::Invalid, "runtime is not open");
  }
  std::vector<FindingId> fenced;
  {
    const std::lock_guard<std::mutex> lock(impl_->mutex);
    if (!generation.valid() || generation <= impl_->fence.forwarding) {
      return Status::failure(Outcome::Stale,
                             "forwarding generation must advance past the current generation");
    }
    impl_->fence.forwarding = generation;
    if (impl_->has_store) {
      const Status status = impl_->store.advance_fence(impl_->fence);
      if (!status.is_ok()) {
        return status;
      }
    }
    fenced = impl_->findings.fence_stale(impl_->fence, now);
    impl_->counters.findings_fenced += fenced.size();
    const Status lineage = impl_->append_lineage(AuthorityKind::Withdrawal, FindingId{}, ContainmentPlanId{}, ContainmentIntentId{},
        impl_->fence, impl_->fence.digest(), ReasonCode::FindingFencedByGenerationChange,
        Severity::Critical, now);
    if (!lineage.is_ok()) {
      return lineage;
    }
  }
  return Status::ok();
}

Status Runtime::advance_fabric_epoch(FabricEpoch epoch, Tick now) {
  if (impl_ == nullptr) {
    return Status::failure(Outcome::Invalid, "runtime is not open");
  }
  {
    const std::lock_guard<std::mutex> lock(impl_->mutex);
    if (!epoch.valid() || epoch <= impl_->fence.fabric_epoch) {
      return Status::failure(Outcome::Stale,
                             "fabric epoch must advance past the current fabric epoch");
    }
    impl_->fence.fabric_epoch = epoch;
    if (impl_->has_store) {
      const Status status = impl_->store.advance_fence(impl_->fence);
      if (!status.is_ok()) {
        return status;
      }
    }
    const auto fenced = impl_->findings.fence_stale(impl_->fence, now);
    impl_->counters.findings_fenced += fenced.size();
    const Status lineage = impl_->append_lineage(AuthorityKind::Withdrawal, FindingId{}, ContainmentPlanId{}, ContainmentIntentId{},
        impl_->fence, impl_->fence.digest(), ReasonCode::FindingFencedByGenerationChange,
        Severity::Critical, now);
    if (!lineage.is_ok()) {
      return lineage;
    }
  }
  return Status::ok();
}

Status Runtime::advance_epoch(Tick now) {
  if (impl_ == nullptr) {
    return Status::failure(Outcome::Invalid, "runtime is not open");
  }
  {
    const std::lock_guard<std::mutex> lock(impl_->mutex);
    const auto next = impl_->fence.epoch.try_next();
    if (!next.has_value()) {
      return Status::failure(Outcome::Exhausted, "coordinator epoch space is exhausted");
    }
    impl_->fence.epoch = *next;
    impl_->identity.epoch = *next;
    if (impl_->has_store) {
      const Status status = impl_->store.advance_fence(impl_->fence);
      if (!status.is_ok()) {
        return status;
      }
    }
    const auto fenced = impl_->findings.fence_stale(impl_->fence, now);
    impl_->counters.findings_fenced += fenced.size();
    const Status lineage = impl_->append_lineage(AuthorityKind::Withdrawal, FindingId{}, ContainmentPlanId{}, ContainmentIntentId{},
        impl_->fence, impl_->fence.digest(), ReasonCode::FindingFencedByGenerationChange,
        Severity::Critical, now);
    if (!lineage.is_ok()) {
      return lineage;
    }
  }
  return Status::ok();
}

Status Runtime::set_topology(TopologyDefinition topology, Tick now) {
  if (impl_ == nullptr) {
    return Status::failure(Outcome::Invalid, "runtime is not open");
  }
  {
    const std::lock_guard<std::mutex> lock(impl_->mutex);
    auto canonical = canonicalize_topology(std::move(topology), impl_->config.limits);
    if (!canonical.has_value()) {
      return Status::failure(canonical.outcome(), canonical.detail());
    }
    TopologyDefinition definition = std::move(canonical).value();
    if (impl_->has_topology && definition.generation() <= impl_->topology.generation()) {
      return Status::failure(Outcome::Stale,
                             "topology generation must advance past the installed generation");
    }
    if (impl_->has_store) {
      const Status status = impl_->store.set_topology(definition);
      if (!status.is_ok()) {
        return status;
      }
    }
    impl_->topology = std::move(definition);
    impl_->has_topology = true;
    impl_->fence.topology = impl_->topology.generation();
    if (impl_->topology.generation() > impl_->fence.topology) {
      impl_->fence.topology = impl_->topology.generation();
    }
    if (impl_->has_store) {
      const Status status = impl_->store.advance_fence(impl_->fence);
      if (!status.is_ok()) {
        return status;
      }
    }
    const auto fenced = impl_->findings.fence_stale(impl_->fence, now);
    impl_->counters.findings_fenced += fenced.size();
    // Observations made against the previous topology generation are now stale. They are
    // retained for audit, but nothing dynamic is rewritten to look current.
    const Status lineage = impl_->append_lineage(AuthorityKind::Withdrawal, FindingId{}, ContainmentPlanId{}, ContainmentIntentId{},
        impl_->fence, impl_->topology.digest(), ReasonCode::FindingFencedByGenerationChange,
        Severity::Critical, now);
    if (!lineage.is_ok()) {
      return lineage;
    }
  }
  return Status::ok();
}

Status Runtime::set_policy(ContainmentPolicy policy, Tick now) {
  if (impl_ == nullptr) {
    return Status::failure(Outcome::Invalid, "runtime is not open");
  }
  {
    const std::lock_guard<std::mutex> lock(impl_->mutex);
    if (!policy.generation.valid()) {
      return Status::failure(Outcome::Invalid, "policy generation must be non-zero");
    }
    if (impl_->has_policy && policy.generation <= impl_->policy.generation) {
      return Status::failure(Outcome::Stale,
                             "policy generation must advance past the installed generation");
    }
    if (impl_->has_store) {
      const Status status = impl_->store.set_policy(policy);
      if (!status.is_ok()) {
        return status;
      }
    }
    impl_->policy = policy;
    impl_->has_policy = true;
    impl_->fence.policy = policy.generation;
    if (impl_->has_store) {
      const Status status = impl_->store.advance_fence(impl_->fence);
      if (!status.is_ok()) {
        return status;
      }
    }
    const auto fenced = impl_->findings.fence_stale(impl_->fence, now);
    impl_->counters.findings_fenced += fenced.size();
  }
  return Status::ok();
}

std::optional<TopologyDefinition> Runtime::topology() const {
  if (impl_ == nullptr) {
    return std::nullopt;
  }
  const std::lock_guard<std::mutex> lock(impl_->mutex);
  if (!impl_->has_topology) {
    return std::nullopt;
  }
  return impl_->topology;
}

std::optional<ContainmentPolicy> Runtime::policy() const {
  if (impl_ == nullptr) {
    return std::nullopt;
  }
  const std::lock_guard<std::mutex> lock(impl_->mutex);
  if (!impl_->has_policy) {
    return std::nullopt;
  }
  return impl_->policy;
}

Status Runtime::submit_observation(const ForwardingObservation& observation, Tick now) {
  (void)now;
  if (impl_ == nullptr) {
    return Status::failure(Outcome::Invalid, "runtime is not open");
  }
  const std::lock_guard<std::mutex> lock(impl_->mutex);
  const Status status = impl_->ledger.submit(observation);
  if (status.is_ok()) {
    ++impl_->counters.observations_submitted;
  } else {
    ++impl_->counters.observations_rejected;
  }
  return status;
}

Status Runtime::clear_evidence() {
  if (impl_ == nullptr) {
    return Status::failure(Outcome::Invalid, "runtime is not open");
  }
  const std::lock_guard<std::mutex> lock(impl_->mutex);
  impl_->ledger.clear_dynamic_state();
  return Status::ok();
}

std::size_t Runtime::observation_count() const {
  if (impl_ == nullptr) {
    return 0;
  }
  const std::lock_guard<std::mutex> lock(impl_->mutex);
  return impl_->ledger.size();
}

Result<LoopAssessment> Runtime::detect(Tick now, std::vector<TrafficSelectorId> selector_scope) {
  if (impl_ == nullptr) {
    return Result<LoopAssessment>::failure(Outcome::Invalid, "runtime is not open");
  }
  const std::lock_guard<std::mutex> lock(impl_->mutex);
  if (!impl_->has_topology) {
    return Result<LoopAssessment>::failure(Outcome::NotFound,
                                           "no topology definition is installed");
  }
  DetectionRequest request;
  request.topology = &impl_->topology;
  request.ledger = &impl_->ledger;
  request.fence = impl_->fence;
  request.now = now;
  request.selector_scope = std::move(selector_scope);
  ++impl_->counters.assessments_run;
  return impl_->detector.assess(request);
}

Result<Finding> Runtime::publish_finding(const LoopAssessment& assessment, Tick now) {
  if (impl_ == nullptr) {
    return Result<Finding>::failure(Outcome::Invalid, "runtime is not open");
  }
  std::optional<Finding> published;
  std::function<void(const Finding&)> observer;
  {
    const std::lock_guard<std::mutex> lock(impl_->mutex);
    if (assessment.outcome != LoopOutcome::LoopConfirmed) {
      ++impl_->counters.findings_refused;
      return Result<Finding>::failure(
          Outcome::Refused, std::string("only a confirmed loop becomes a finding; the assessment is ") +
                                std::string(to_string(assessment.outcome)));
    }
    if (!(assessment.fence == impl_->fence)) {
      ++impl_->counters.findings_refused;
      return Result<Finding>::failure(
          Outcome::Stale, "the assessment binds a fence that is no longer current");
    }
    if (assessment.witnesses.empty()) {
      ++impl_->counters.findings_refused;
      return Result<Finding>::failure(Outcome::Refused,
                                      "an affirmative assessment without a witness is not publishable");
    }
    if (!impl_->has_topology || !(impl_->topology.generation() == assessment.fence.topology)) {
      ++impl_->counters.findings_refused;
      return Result<Finding>::failure(Outcome::Stale,
                                      "the installed definition is not the generation the finding binds");
    }
    // Re-derive every witness before publishing: a finding never carries an unvalidated proof.
    for (const LoopWitness& witness : assessment.witnesses) {
      auto validation = impl_->detector.revalidate(witness, impl_->topology, impl_->ledger,
                                                   impl_->fence, now);
      if (!validation.has_value() || !validation.value().valid) {
        return Result<Finding>::failure(
            Outcome::Refused,
            "a witness in the assessment failed independent revalidation at publish time");
      }
    }

    const auto next = impl_->findings.findings().empty()
                          ? FindingGeneration::from_value(1)
                          : FindingGeneration::from_value(
                                impl_->findings.findings().back().generation.value() + 1U);
    Finding finding;
    finding.generation = next;
    finding.assessment = assessment.id;
    finding.assessment_digest = assessment.digest();
    finding.fence = assessment.fence;
    finding.state = FindingState::Confirmed;
    finding.assessment_outcome = assessment.outcome;
    finding.assessment_flags = assessment.flags;
    for (const LoopWitness& witness : assessment.witnesses) {
      finding.witnesses.push_back(witness.id);
    }
    finding.implicated_resources = assessment.implicated_resources();
    finding.implicated_selectors = assessment.implicated_selectors();
    finding.created_at = now;
    finding.updated_at = now;
    finding.origin = assessment.origin;
    finding.explanation = Explanation(impl_->config.limits.max_explanation_reasons);
    finding.explanation.add(ReasonCode::WitnessSuccessfullyValidated, "finding",
                            "every witness was independently revalidated at publish time");
    // Content-addressed identity: the identity is a function of the finding's facts, so a
    // replay of the same facts produces the same identity rather than a new finding.
    finding.id = content_addressed_id<FindingId>(finding.content_digest());

    if (impl_->has_store) {
      const Status status = impl_->store.upsert_finding(finding);
      if (!status.is_ok()) {
        return Result<Finding>::failure(status.outcome(), status.detail());
      }
    }
    auto registered = impl_->findings.register_finding(finding);
    if (!registered.has_value()) {
      return Result<Finding>::failure(registered.outcome(), registered.detail());
    }
    const Status lineage = impl_->append_lineage(AuthorityKind::Recommendation, finding.id, ContainmentPlanId{},
        ContainmentIntentId{}, finding.fence, finding.content_digest(),
        ReasonCode::WitnessSuccessfullyValidated, Severity::Critical, now);
    if (!lineage.is_ok()) {
      return Result<Finding>::failure(lineage.outcome(), lineage.detail());
    }
    ++impl_->counters.findings_published;
    published = finding;
    observer = impl_->observer;
  }
  if (observer != nullptr && published.has_value()) {
    observer(*published);
  }
  return Result<Finding>::ok(std::move(*published));
}

Result<ContainmentPlan> Runtime::plan_containment(const LoopAssessment& assessment, Tick now) {
  if (impl_ == nullptr) {
    return Result<ContainmentPlan>::failure(Outcome::Invalid, "runtime is not open");
  }
  std::optional<ContainmentPlan> result;
  std::function<void(const Finding&)> observer;
  {
    const std::lock_guard<std::mutex> lock(impl_->mutex);
    if (!impl_->has_topology || !impl_->has_policy) {
      return Result<ContainmentPlan>::failure(Outcome::NotFound,
                                              "a topology and a containment policy are required");
    }
    auto plan = impl_->planner.plan(assessment, impl_->topology, impl_->policy, now);
    if (!plan.has_value()) {
      return Result<ContainmentPlan>::failure(plan.outcome(), plan.detail());
    }
    ContainmentPlan computed = std::move(plan).value();
    if (impl_->plans.size() >= impl_->config.limits.max_retained_plans) {
      // Bounded retention: drop the lowest plan identity, which is the oldest by
      // construction because plan identities are monotone counters.
      impl_->plans.erase(impl_->plans.begin());
    }
    impl_->plans[computed.id.value()] = computed;
    ++impl_->counters.plans_computed;
    // Attach the plan to the finding it contains, if one was published for the assessment.
    for (const Finding& finding : impl_->findings.findings()) {
      if (finding.assessment == assessment.id && !finding.is_terminal()) {
        (void)impl_->findings.attach_plan(finding.id, computed.id, now);
        const Status lineage = impl_->append_lineage(AuthorityKind::Eligibility, finding.id, computed.id, ContainmentIntentId{},
            computed.fence, computed.content_digest(), computed.explanation.reasons().empty()
                                                           ? ReasonCode::ContainmentPlanValidated
                                                           : computed.explanation.reasons().front().code,
            Severity::Warning, now);
        if (!lineage.is_ok()) {
          return Result<ContainmentPlan>::failure(lineage.outcome(), lineage.detail());
        }
        break;
      }
    }
    result = computed;
    observer = impl_->observer;
  }
  return Result<ContainmentPlan>::ok(std::move(*result));
}

Result<ContainmentIntent> Runtime::authorize_containment(FindingId finding_id,
                                                         const ContainmentGrant& grant, Tick now,
                                                         Tick lease_ticks,
                                                         std::vector<ResourceId> targets) {
  if (impl_ == nullptr) {
    return Result<ContainmentIntent>::failure(Outcome::Invalid, "runtime is not open");
  }
  std::optional<ContainmentIntent> issued;
  std::function<void(const Finding&)> observer;
  {
    const std::lock_guard<std::mutex> lock(impl_->mutex);
    const Finding* finding = impl_->findings.find(finding_id);
    if (finding == nullptr) {
      return Result<ContainmentIntent>::failure(Outcome::NotFound, "finding is not registered");
    }
    if (finding->is_terminal() || !(finding->fence == impl_->fence)) {
      ++impl_->counters.intents_refused;
      return Result<ContainmentIntent>::failure(
          Outcome::Fenced, "the finding is fenced and can no longer authorize containment");
    }
    const auto plan_position = impl_->plans.find(finding->plan.value());
    if (plan_position == impl_->plans.end()) {
      ++impl_->counters.intents_refused;
      return Result<ContainmentIntent>::failure(Outcome::NotFound,
                                                "the finding has no retained containment plan");
    }
    const ContainmentPlan& plan = plan_position->second;
    if (!plan.authorizes_action()) {
      ++impl_->counters.intents_refused;
      return Result<ContainmentIntent>::failure(
          Outcome::Refused, std::string("the plan does not authorize action: ") +
                                std::string(to_string(plan.outcome)));
    }
    if (!(plan.fence == impl_->fence)) {
      ++impl_->counters.intents_refused;
      return Result<ContainmentIntent>::failure(Outcome::Fenced,
                                                "the plan is fenced and no longer authorizes action");
    }
    if (targets.empty()) {
      targets = plan.target_resources();
    }
    std::sort(targets.begin(), targets.end());
    if (std::adjacent_find(targets.begin(), targets.end()) != targets.end()) {
      return Result<ContainmentIntent>::failure(Outcome::Invalid, "target set contains duplicates");
    }
    std::uint64_t total_cost = 0;
    for (const ResourceId target : targets) {
      const ContainmentTarget* selected = nullptr;
      for (const ContainmentTarget& candidate : plan.targets) {
        if (candidate.resource == target) {
          selected = &candidate;
          break;
        }
      }
      if (selected == nullptr) {
        ++impl_->counters.intents_refused;
        return Result<ContainmentIntent>::failure(
            Outcome::Refused, "a requested target is not part of the authorized plan");
      }
      total_cost += selected->cost;
    }
    const Status authorized = grant.authorize(targets, total_cost, impl_->fence, now);
    if (!authorized.is_ok()) {
      ++impl_->counters.intents_refused;
      return Result<ContainmentIntent>::failure(authorized.outcome(), authorized.detail());
    }

    ContainmentIntent intent;
    intent.plan = plan.id;
    intent.finding = finding_id;
    intent.assessment = plan.assessment;
    intent.fence = impl_->fence;
    intent.issued_by = impl_->identity;
    intent.targets = targets;
    for (const ContainmentTarget& candidate : plan.targets) {
      if (std::binary_search(targets.begin(), targets.end(), candidate.resource)) {
        intent.selectors.insert(intent.selectors.end(), candidate.selectors.begin(),
                                candidate.selectors.end());
      }
    }
    std::sort(intent.selectors.begin(), intent.selectors.end());
    intent.selectors.erase(std::unique(intent.selectors.begin(), intent.selectors.end()),
                           intent.selectors.end());
    intent.issued_at = now;
    intent.expires_at = now + lease_ticks;
    intent.plan_digest = plan.content_digest();
    intent.id = content_addressed_id<ContainmentIntentId>(intent.content_digest());

    ContainmentApplication application;
    application.intent = intent.id;
    application.plan = plan.id;
    application.finding = finding_id;
    application.fence = impl_->fence;
    application.applier = impl_->identity;
    application.targets = targets;
    application.explanation = Explanation(impl_->config.limits.max_explanation_reasons);
    application.explanation.add(ReasonCode::RequestAccepted, intent.id.to_string(),
                                "a bounded containment intent was authorized");

    (void)impl_->findings.attach_intent(finding_id, intent.id, now);
    (void)impl_->findings.update_state(finding_id, FindingState::ContainmentRequested,
                                       FenceCause::None, now, ReasonCode::RequestAccepted,
                                       "a bounded containment intent was issued");
    impl_->applications[intent.id.value()] = std::move(application);
    const Status lineage = impl_->append_lineage(AuthorityKind::Authorization, finding_id, plan.id, intent.id, impl_->fence,
        intent.content_digest(), ReasonCode::RequestAccepted, Severity::Critical, now);
    if (!lineage.is_ok()) {
      return Result<ContainmentIntent>::failure(lineage.outcome(), lineage.detail());
    }
    ++impl_->counters.intents_issued;
    issued = intent;
    observer = impl_->observer;
  }
  if (observer != nullptr) {
    const std::optional<Finding> updated = find_finding(issued->finding);
    if (updated.has_value()) {
      observer(*updated);
    }
  }
  return Result<ContainmentIntent>::ok(std::move(*issued));
}

Status Runtime::record_acknowledgement(const ContainmentAcknowledgement& ack, Tick now) {
  if (impl_ == nullptr) {
    return Status::failure(Outcome::Invalid, "runtime is not open");
  }
  const std::lock_guard<std::mutex> lock(impl_->mutex);
  const auto position = impl_->applications.find(ack.intent.value());
  if (position == impl_->applications.end()) {
    return Status::failure(Outcome::NotFound, "intent is not registered");
  }
  ContainmentApplication& application = position->second;
  if (!(application.fence == impl_->fence)) {
    return Status::failure(Outcome::Fenced, "the intent was issued under a superseded fence");
  }
  if (now > 0 && application.acknowledgements.size() >= 4U) {
    return Status::failure(Outcome::Exhausted, "acknowledgement history is bounded");
  }
  application.acknowledgements.push_back(ack);
  // An acknowledgement is not an effect: it never moves the finding to a verified state.
  const Status updated = impl_->findings.update_state(
      application.finding, FindingState::ContainmentAppliedUnverified, FenceCause::None, now,
      ReasonCode::AcknowledgementIsNotEffect,
      "the applier acknowledged the intent; the effect is still unverified");
  const Status lineage = impl_->append_lineage(AuthorityKind::Acknowledgement, application.finding, application.plan, ack.intent,
      impl_->fence, ack.intent_digest, ReasonCode::AcknowledgementIsNotEffect, Severity::Warning,
      now);
  if (!lineage.is_ok()) {
    return lineage;
  }
  return updated;
}

Status Runtime::record_verified_effect(ContainmentIntentId intent, const VerifiedEffect& effect,
                                       Tick now) {
  if (impl_ == nullptr) {
    return Status::failure(Outcome::Invalid, "runtime is not open");
  }
  const std::lock_guard<std::mutex> lock(impl_->mutex);
  const auto position = impl_->applications.find(intent.value());
  if (position == impl_->applications.end()) {
    return Status::failure(Outcome::NotFound, "intent is not registered");
  }
  ContainmentApplication& application = position->second;
  if (!(application.fence == impl_->fence)) {
    return Status::failure(Outcome::Fenced, "the intent was issued under a superseded fence");
  }
  if (!std::binary_search(application.targets.begin(), application.targets.end(), effect.target)) {
    return Status::failure(Outcome::Refused, "the effect names a target the intent never contained");
  }
  if (!(effect.fence == impl_->fence)) {
    return Status::failure(Outcome::Stale,
                           "the effect was observed under a fence that is not current");
  }
  for (const VerifiedEffect& existing : application.effects) {
    if (existing.target == effect.target) {
      return Status::failure(Outcome::AlreadyExists,
                             "a verified effect for this target is already recorded");
    }
  }
  application.effects.push_back(effect);
  std::sort(application.effects.begin(), application.effects.end());
  application.explanation.add(ReasonCode::EffectVerifiedForTarget, effect.target.to_string(),
                              "an independent observation confirms the target is contained");
  ++impl_->counters.effects_recorded;

  const bool complete = application.fully_verified();
  if (!complete) {
    ++impl_->counters.effects_unverified;
    for (const ResourceId missing : application.unverified_targets()) {
      application.explanation.add(ReasonCode::EffectUnverifiedForTarget, missing.to_string(),
                                  "no verified effect has been recorded for this target");
    }
  }
  const Status updated = impl_->findings.update_state(
      application.finding,
      complete ? FindingState::ContainmentVerified : FindingState::ContainmentAppliedUnverified,
      FenceCause::None, now,
      complete ? ReasonCode::EffectVerifiedForTarget : ReasonCode::EffectUnverifiedForTarget,
      complete ? "every target carries an independently verified effect"
               : "at least one target has no verified effect");
  const Status lineage = impl_->append_lineage(AuthorityKind::VerifiedEffect, application.finding, application.plan, intent,
      impl_->fence, application.content_digest(),
      complete ? ReasonCode::EffectVerifiedForTarget : ReasonCode::EffectUnverifiedForTarget,
      complete ? Severity::Notice : Severity::Warning, now);
  if (!lineage.is_ok()) {
    return lineage;
  }
  return updated;
}

Status Runtime::withdraw_finding(FindingId finding_id, ReasonCode reason, Tick now,
                                 std::string detail) {
  if (impl_ == nullptr) {
    return Status::failure(Outcome::Invalid, "runtime is not open");
  }
  const std::lock_guard<std::mutex> lock(impl_->mutex);
  const Finding* existing = impl_->findings.find(finding_id);
  if (existing == nullptr) {
    return Status::failure(Outcome::NotFound, "finding is not registered");
  }
  if (impl_->has_store) {
    const Status status =
        impl_->store.withdraw_finding(finding_id, FenceCause::ExplicitWithdrawal, now, reason);
    if (!status.is_ok()) {
      return status;
    }
  }
  const Status updated = impl_->findings.update_state(
      finding_id, FindingState::Withdrawn, FenceCause::ExplicitWithdrawal, now, reason,
      std::move(detail));
  if (!updated.is_ok()) {
    return updated;
  }
  return impl_->append_lineage(AuthorityKind::Withdrawal, finding_id, ContainmentPlanId{},
                               ContainmentIntentId{}, impl_->fence, Digest{}, reason,
                               Severity::Critical, now);
}

std::optional<Finding> Runtime::find_finding(FindingId id) const {
  if (impl_ == nullptr) {
    return std::nullopt;
  }
  const std::lock_guard<std::mutex> lock(impl_->mutex);
  const Finding* finding = impl_->findings.find(id);
  if (finding == nullptr) {
    return std::nullopt;
  }
  return *finding;
}

std::vector<FindingSummary> Runtime::findings() const {
  if (impl_ == nullptr) {
    return {};
  }
  const std::lock_guard<std::mutex> lock(impl_->mutex);
  std::vector<FindingSummary> summaries;
  summaries.reserve(impl_->findings.findings().size());
  for (const Finding& finding : impl_->findings.findings()) {
    FindingSummary summary = summarize(finding);
    const auto plan = impl_->plans.find(finding.plan.value());
    if (plan != impl_->plans.end()) {
      summary.containment_outcome = plan->second.outcome;
      summary.target_count = plan->second.targets.size();
    }
    summaries.push_back(std::move(summary));
  }
  return summaries;
}

std::vector<LineageRecord> Runtime::lineage() const {
  if (impl_ == nullptr) {
    return {};
  }
  const std::lock_guard<std::mutex> lock(impl_->mutex);
  return impl_->lineage;
}

std::optional<ContainmentPlan> Runtime::find_plan(ContainmentPlanId id) const {
  if (impl_ == nullptr) {
    return std::nullopt;
  }
  const std::lock_guard<std::mutex> lock(impl_->mutex);
  const auto position = impl_->plans.find(id.value());
  if (position == impl_->plans.end()) {
    return std::nullopt;
  }
  return position->second;
}

std::optional<ContainmentApplication> Runtime::application(ContainmentIntentId id) const {
  if (impl_ == nullptr) {
    return std::nullopt;
  }
  const std::lock_guard<std::mutex> lock(impl_->mutex);
  const auto position = impl_->applications.find(id.value());
  if (position == impl_->applications.end()) {
    return std::nullopt;
  }
  return position->second;
}

Digest Runtime::state_digest() const {
  if (impl_ == nullptr) {
    return Digest{};
  }
  const std::lock_guard<std::mutex> lock(impl_->mutex);
  Sha256 hasher;
  hash_u64(hasher, impl_->fence.topology.value());
  hash_u64(hasher, impl_->fence.forwarding.value());
  hash_u64(hasher, impl_->fence.policy.value());
  hash_u64(hasher, impl_->fence.fabric_epoch.value());
  hash_u64(hasher, impl_->fence.epoch.value());
  hash_u64(hasher, impl_->fence.boot.value());
  const Digest topology = impl_->has_topology ? impl_->topology.digest() : Digest{};
  hasher.update(topology.bytes.data(), kDigestBytes);
  const Digest policy = impl_->has_policy ? impl_->policy.digest() : Digest{};
  hasher.update(policy.bytes.data(), kDigestBytes);
  const Digest evidence = impl_->ledger.digest();
  hasher.update(evidence.bytes.data(), kDigestBytes);
  const Digest findings = impl_->findings.digest();
  hasher.update(findings.bytes.data(), kDigestBytes);
  hash_u64(hasher, impl_->lineage.size());
  for (const LineageRecord& record : impl_->lineage) {
    const Digest content = record.content_digest();
    hasher.update(content.bytes.data(), kDigestBytes);
  }
  return hasher.finish();
}

std::string Runtime::describe() const {
  if (impl_ == nullptr) {
    return "runtime: closed\n";
  }
  const std::lock_guard<std::mutex> lock(impl_->mutex);
  std::string out = "runtime identity=" + impl_->identity.to_string() + "\n";
  out += "fence=" + impl_->fence.to_string() + "\n";
  out += "topology=" + (impl_->has_topology ? impl_->topology.generation().to_string() : "none") +
         " edges=" + std::to_string(impl_->has_topology ? impl_->topology.edges().size() : 0U) + "\n";
  out += "policy=" + (impl_->has_policy ? impl_->policy.generation.to_string() : "none") + "\n";
  out += "observations=" + std::to_string(impl_->ledger.size()) + "\n";
  out += "findings=" + std::to_string(impl_->findings.findings().size()) +
         " live=" + std::to_string(impl_->findings.live_count()) + "\n";
  out += "lineage=" + std::to_string(impl_->lineage.size()) + "\n";
  out += "state_digest=" + state_digest().to_hex() + "\n";
  return out;
}

Status Runtime::close(bool clean_shutdown) {
  if (impl_ == nullptr) {
    return Status::failure(Outcome::Invalid, "runtime is not open");
  }
  {
    const std::lock_guard<std::mutex> lock(impl_->mutex);
    if (!impl_->open) {
      return Status::ok();
    }
    impl_->open = false;
    if (impl_->has_store) {
      const Status status = impl_->store.close(clean_shutdown);
      if (!status.is_ok()) {
        return status;
      }
    }
  }
  return Status::ok();
}

}  // namespace loop_guard