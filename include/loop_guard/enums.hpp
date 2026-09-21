// Loop Guard - the closed enumeration vocabulary of the runtime.
//
// Every externally visible decision is expressed with these values. There is no
// "other", no free-form status string and no implicit success mapping: UNKNOWN,
// STALE, CONFLICT, INVALID and UNSUPPORTED are first-class outcomes that a
// decision must name explicitly instead of collapsing into ordinary absence.
//
// All enums are contiguous and total: every value in [min, max] is a real value,
// every value has a canonical name, and enum_from_u32 rejects anything outside the
// declared range. The unit suite proves totality, uniqueness and round-tripping.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace loop_guard {

// ---------------------------------------------------------------------------
// Generic operation outcome.
// ---------------------------------------------------------------------------
enum class Outcome : std::uint8_t {
  Ok = 0,
  Invalid = 1,         ///< Input violates a structural or domain rule.
  Unknown = 2,         ///< Required fact is not established either way.
  Stale = 3,           ///< Bound generation/epoch is no longer current.
  Conflict = 4,        ///< Authoritative inputs contradict each other.
  Unsupported = 5,     ///< Well-formed but outside the supported problem class.
  NotFound = 6,
  AlreadyExists = 7,
  Exhausted = 8,       ///< A bounded resource or budget was reached.
  IntegrityFailure = 9,///< Durable or framed bytes failed integrity validation.
  IoFailure = 10,
  Refused = 11,        ///< Policy or authority refused the operation.
  Indeterminate = 12,  ///< Search bound reached; no proof either way.
  Interrupted = 13,    ///< Owning process/incarnation ended before completion.
  Fenced = 14,         ///< Superseded by a newer authority boundary.
};

// ---------------------------------------------------------------------------
// Loop assessment.
// ---------------------------------------------------------------------------
enum class LoopOutcome : std::uint8_t {
  NoLoop = 0,        ///< Proved: no forwarding loop exists under the bound evidence.
  LoopConfirmed = 1, ///< Proved: at least one canonical witness with exact-generation evidence.
  Unknown = 2,       ///< Some hop on a candidate cycle is not established either way.
  Stale = 3,         ///< Evidence or topology generations moved; the question must be re-asked.
  Conflict = 4,      ///< Authoritative evidence contradicts itself on a relevant hop.
  Invalid = 5,       ///< Request was structurally rejected.
  Unsupported = 6,   ///< Request is outside the supported problem class.
  Indeterminate = 7, ///< Proof budget reached before the search space was exhausted.
};

/// Bitset of secondary facts about an assessment. These never replace the primary
/// outcome; they record what else is true so that a caller cannot mistake a bounded
/// search for an exhaustive one.
using AssessmentFlags = std::uint32_t;
inline constexpr AssessmentFlags kAssessmentNone = 0U;
inline constexpr AssessmentFlags kAssessmentSearchLimitReached = 1U << 0U;
inline constexpr AssessmentFlags kAssessmentUnprovenHopsPresent = 1U << 1U;
inline constexpr AssessmentFlags kAssessmentConflictsPresent = 1U << 2U;
inline constexpr AssessmentFlags kAssessmentStaleEvidencePresent = 1U << 3U;
inline constexpr AssessmentFlags kAssessmentAdditionalCyclesPossible = 1U << 4U;
inline constexpr AssessmentFlags kAssessmentContainedByActiveIntent = 1U << 5U;
inline constexpr AssessmentFlags kAssessmentNoEvidenceAtAll = 1U << 6U;
inline constexpr AssessmentFlags kAssessmentAllFlags =
    kAssessmentSearchLimitReached | kAssessmentUnprovenHopsPresent | kAssessmentConflictsPresent |
    kAssessmentStaleEvidencePresent | kAssessmentAdditionalCyclesPossible |
    kAssessmentContainedByActiveIntent | kAssessmentNoEvidenceAtAll;

// ---------------------------------------------------------------------------
// Evidence.
// ---------------------------------------------------------------------------
/// The class a producer asserted for one forwarding hop.
enum class EvidenceClass : std::uint8_t {
  Present = 0,  ///< Producer asserts traffic can traverse this hop now.
  Absent = 1,   ///< Producer asserts traffic cannot traverse this hop now.
  Unknown = 2,  ///< Producer explicitly does not know.
};

/// How an observation bound to the current question.
enum class EvidenceBinding : std::uint8_t {
  Exact = 0,             ///< Observation generations equal the current generations and the lease is live.
  GenerationMismatch = 1,///< Observation was made against different topology/forwarding generations.
  EpochFenced = 2,       ///< Observation was produced under a superseded coordinator epoch or boot.
  LeaseExpired = 3,      ///< Observation's liveness window closed at the current tick.
  Superseded = 4,        ///< A newer observation from the same producer replaced it.
  NoEvidence = 5,        ///< Nothing was ever observed for this hop.
};

/// The effective class of a hop after all observations for it are resolved.
enum class HopResolution : std::uint8_t {
  ProvenOpen = 0,    ///< Exactly-bound live evidence asserts Present; usable as loop proof.
  ProvenClosed = 1,  ///< Exactly-bound live evidence asserts Absent; breaks the cycle.
  UnprovenOpen = 2,  ///< No exact evidence, but a non-current observation said Present: possible, unproved.
  Unproven = 3,      ///< No evidence at all, or only Unknown observations.
  Conflicted = 4,    ///< Exact-bound evidence asserts both Present and Absent.
  Unsupported = 5,   ///< Hop is outside the supported problem class (e.g. unknown domain).
};

// ---------------------------------------------------------------------------
// Topology vocabulary.
// ---------------------------------------------------------------------------
enum class ResourceKind : std::uint8_t {
  Switch = 0,
  PortGroup = 1,
  NextHopGroup = 2,
  TunnelEndpoint = 3,
  ServiceStage = 4,
  HostInterface = 5,
  VirtualSwitch = 6,
  Unsupported = 7,
};

enum class AdministrativeState : std::uint8_t {
  Enabled = 0,
  Disabled = 1,
  Unknown = 2,
};

enum class LinkState : std::uint8_t {
  Up = 0,
  Down = 1,
  Unknown = 2,
};

enum class TrafficSelectorKind : std::uint8_t {
  FlowClass = 0,
  PrefixPair = 1,
  TenantScope = 2,
  ServiceChain = 3,
};

// ---------------------------------------------------------------------------
// Containment.
// ---------------------------------------------------------------------------
enum class ContainmentOutcome : std::uint8_t {
  NotRequired = 0,      ///< No confirmed loop; nothing is authorized or recommended.
  PlanOptimal = 1,      ///< Exhaustive search proved the returned target set is minimum cost.
  PlanFeasible = 2,     ///< A valid plan found, but not proved minimum cost.
  ProvenInfeasible = 3, ///< Exhaustive search proved no admissible target set exists; certificate attached.
  SearchLimitReached = 4,///< Budget reached before optimality or infeasibility could be decided.
  Unsupported = 5,      ///< Policy or topology is outside the supported class.
  Invalid = 6,          ///< Request structurally rejected.
};

using PlanFlags = std::uint32_t;
inline constexpr PlanFlags kPlanNone = 0U;
inline constexpr PlanFlags kPlanGreedyRecommendationPresent = 1U << 0U;
inline constexpr PlanFlags kPlanTouchesNonContainableResources = 1U << 1U;
inline constexpr PlanFlags kPlanCostBudgetExceeded = 1U << 2U;
inline constexpr PlanFlags kPlanUnrelatedForwardingUntouched = 1U << 3U;
inline constexpr PlanFlags kPlanWitnessSetIncomplete = 1U << 4U;
inline constexpr PlanFlags kPlanSearchLimitReached = 1U << 5U;
inline constexpr PlanFlags kPlanProvedMinimum = 1U << 6U;
inline constexpr PlanFlags kPlanCertificateAttached = 1U << 7U;
inline constexpr PlanFlags kPlanContainsWholeWitness = 1U << 8U;
inline constexpr PlanFlags kPlanAllFlags =
    kPlanGreedyRecommendationPresent | kPlanTouchesNonContainableResources | kPlanCostBudgetExceeded |
    kPlanUnrelatedForwardingUntouched | kPlanWitnessSetIncomplete | kPlanSearchLimitReached |
    kPlanProvedMinimum | kPlanCertificateAttached | kPlanContainsWholeWitness;

/// Why a resource was selected as a containment target.
enum class TargetReason : std::uint8_t {
  SoleBreakOfWitness = 0,     ///< Removing it alone breaks at least one witness.
  MinimumCostHittingSet = 1,  ///< Member of the proved minimum-cost hitting set.
  FeasibleHittingSet = 2,     ///< Member of a feasible (not proved minimum) hitting set.
  GreedyRecommendation = 3,   ///< Advisory only; carries no authority.
};

// ---------------------------------------------------------------------------
// Authority.
// ---------------------------------------------------------------------------
/// The distinct authority stages. Loop Guard never lets one stand in for another.
enum class AuthorityKind : std::uint8_t {
  Observation = 0,       ///< A producer says something is true. Not authority by itself.
  Eligibility = 1,       ///< A resource is allowed by policy to be a containment target.
  Recommendation = 2,    ///< A planner suggests targets. No permission to act.
  Authorization = 3,     ///< A grant permits a bounded containment intent.
  Request = 4,           ///< The intent was handed to an applier.
  Acknowledgement = 5,   ///< The applier says it received the intent. Not an effect.
  VerifiedEffect = 6,    ///< An independent observation confirms the target is contained.
  Withdrawal = 7,        ///< The finding was retracted; containment intent loses force.
};

enum class GrantState : std::uint8_t {
  Active = 0,
  Consumed = 1,
  Expired = 2,
  Revoked = 3,
  Fenced = 4,
};

// ---------------------------------------------------------------------------
// Finding lifecycle.
// ---------------------------------------------------------------------------
enum class FindingState : std::uint8_t {
  Proposed = 0,
  Confirmed = 1,
  ContainmentAuthorized = 2,
  ContainmentRequested = 3,
  ContainmentAppliedUnverified = 4,
  ContainmentVerified = 5,
  Withdrawn = 6,
  Stale = 7,
  Fenced = 8,     ///< Superseded by a newer boot/epoch boundary.
  Rejected = 9,
};

enum class FenceCause : std::uint8_t {
  None = 0,
  TopologyGenerationAdvanced = 1,
  ForwardingGenerationAdvanced = 2,
  PolicyGenerationAdvanced = 3,
  FabricEpochAdvanced = 4,
  CoordinatorEpochAdvanced = 5,
  BootAdvanced = 6,
  ExplicitWithdrawal = 7,
  GrantExpired = 8,
  GrantRevoked = 9,
};

// ---------------------------------------------------------------------------
// Provenance labelling. Every externally visible artifact carries one of these.
// ---------------------------------------------------------------------------
enum class EvidenceOrigin : std::uint8_t {
  Real = 0,        ///< Derived from real processes, real sockets or real durable files on this host.
  Synthetic = 1,   ///< Derived from deterministic in-process fixtures labelled SYNTHETIC.
  Unsupported = 2, ///< Would require hardware or a toolchain that was not exercised here.
};

enum class ProducerKind : std::uint8_t {
  SyntheticFixture = 0,
  InProcessRuntime = 1,
  RemoteCoordinator = 2,
  RemoteWorker = 3,
  Operator = 4,
};

// ---------------------------------------------------------------------------
// Deterministic reason codes. Explanations are (code, subject, detail) triples.
// ---------------------------------------------------------------------------
enum class ReasonCode : std::uint8_t {
  RequestAccepted = 0,
  RequestRejectedStructural = 1,
  LimitsExceeded = 2,
  DuplicateObservationRejected = 3,
  ObservationSequenceRegressed = 4,
  ObservationGenerationMismatch = 5,
  ObservationEpochFenced = 6,
  ObservationLeaseExpired = 7,
  ObservationSuperseded = 8,
  NoObservationForHop = 9,
  HopConflictsWithItself = 10,
  CycleInTopologyButNoForwardingEvidence = 11,
  CycleRequiresUnprovenHop = 12,
  CycleBrokenByAbsentEvidence = 13,
  WitnessRequiresExactGenerations = 14,
  WitnessHopGenerationsDisagree = 15,
  WitnessSelectorNotAdmitted = 16,
  WitnessResourceAdministrativelyDown = 17,
  WitnessResourceUnknown = 18,
  WitnessSuccessfullyValidated = 19,
  WitnessRejectedByValidator = 20,
  SearchBudgetExhausted = 21,
  SearchCompletedExhaustively = 22,
  SelectorScopeEmpty = 23,
  ContainmentNotRequired = 24,
  ContainmentPlanEmptyButLoopsRemain = 25,
  ContainmentTargetsProvedMinimum = 26,
  ContainmentTargetsFeasibleOnly = 27,
  ContainmentProvedInfeasible = 28,
  ContainmentCertificateNonContainableCycle = 29,
  ContainmentPolicyRefusedTargets = 30,
  ContainmentUnrelatedForwardingUntouched = 31,
  ContainmentGreedyRecommendationOnly = 32,
  ContainmentCostBudgetExceeded = 33,
  ContainmentPlanValidated = 34,
  ContainmentPlanInvalid = 35,
  AuthorityGrantAbsent = 36,
  AuthorityGrantExpired = 37,
  AuthorityGrantRevoked = 38,
  AuthorityGrantFenced = 39,
  AuthorityTargetOutOfScope = 40,
  AuthorityBudgetExceeded = 41,
  AcknowledgementIsNotEffect = 42,
  EffectUnverifiedForTarget = 43,
  EffectVerifiedForTarget = 44,
  FindingWithdrawn = 45,
  FindingFencedByGenerationChange = 46,
  FindingFencedByRestart = 47,
  FindingSupersededByNewerAssessment = 48,
  PersistenceFormatUnsupported = 49,
  PersistenceIntegrityFailure = 50,
  PersistenceTornTailRecovered = 51,
  PersistenceTrailingGarbage = 52,
  PersistenceSequenceRegression = 53,
  PersistenceRecordRejected = 54,
  PersistenceSnapshotCommitted = 55,
  RestartFreshIncarnation = 56,
  DynamicStateNotRestored = 57,
  WireFrameAccepted = 58,
  WireFrameTruncated = 59,
  WireFrameOversized = 60,
  WireFrameBadMagic = 61,
  WireFrameBadVersion = 62,
  WireFrameBadIntegrity = 63,
  WireFrameBadEnum = 64,
  WireFrameTrailingBytes = 65,
  WireSessionMismatch = 66,
  WireSequenceRegressed = 67,
  WireHandshakeRejected = 68,
  WireSessionClosed = 69,
  WireFrameTypeUnsupported = 70,
  UnsupportedHardwarePath = 71,
  ResourceBudgetExhausted = 72,
  InternalInvariantViolated = 73,
};

enum class Severity : std::uint8_t {
  Info = 0,
  Notice = 1,
  Warning = 2,
  Critical = 3,
};

// ---------------------------------------------------------------------------
// Total enumeration support. EnumRange<E> is specialised for every enum above so
// that enum_from_u32 can reject out-of-domain values without a table lookup.
// ---------------------------------------------------------------------------
template <class E>
struct EnumRange;  // primary template intentionally undefined

template <class E>
[[nodiscard]] inline std::optional<E> enum_from_u32(std::uint32_t raw) noexcept {
  if (raw < static_cast<std::uint32_t>(EnumRange<E>::min) ||
      raw > static_cast<std::uint32_t>(EnumRange<E>::max)) {
    return std::nullopt;
  }
  return static_cast<E>(raw);
}

#define LG_ENUM_RANGE(type, first, last)          \
  template <>                                     \
  struct EnumRange<type> {                        \
    static constexpr type min = type::first;      \
    static constexpr type max = type::last;       \
  }

LG_ENUM_RANGE(Outcome, Ok, Fenced);
LG_ENUM_RANGE(LoopOutcome, NoLoop, Indeterminate);
LG_ENUM_RANGE(EvidenceClass, Present, Unknown);
LG_ENUM_RANGE(EvidenceBinding, Exact, NoEvidence);
LG_ENUM_RANGE(HopResolution, ProvenOpen, Unsupported);
LG_ENUM_RANGE(ResourceKind, Switch, Unsupported);
LG_ENUM_RANGE(AdministrativeState, Enabled, Unknown);
LG_ENUM_RANGE(LinkState, Up, Unknown);
LG_ENUM_RANGE(TrafficSelectorKind, FlowClass, ServiceChain);
LG_ENUM_RANGE(ContainmentOutcome, NotRequired, Invalid);
LG_ENUM_RANGE(TargetReason, SoleBreakOfWitness, GreedyRecommendation);
LG_ENUM_RANGE(AuthorityKind, Observation, Withdrawal);
LG_ENUM_RANGE(GrantState, Active, Fenced);
LG_ENUM_RANGE(FindingState, Proposed, Rejected);
LG_ENUM_RANGE(FenceCause, None, GrantRevoked);
LG_ENUM_RANGE(EvidenceOrigin, Real, Unsupported);
LG_ENUM_RANGE(ProducerKind, SyntheticFixture, Operator);
LG_ENUM_RANGE(ReasonCode, RequestAccepted, InternalInvariantViolated);
LG_ENUM_RANGE(Severity, Info, Critical);

#undef LG_ENUM_RANGE

// ---------------------------------------------------------------------------
// Canonical names. to_string() is total: every valid value has a stable,
// upper-snake-case token used by the explanation documents, the wire codec and
// the command line tools.
// ---------------------------------------------------------------------------
[[nodiscard]] std::string_view to_string(Outcome value) noexcept;
[[nodiscard]] std::string_view to_string(LoopOutcome value) noexcept;
[[nodiscard]] std::string_view to_string(EvidenceClass value) noexcept;
[[nodiscard]] std::string_view to_string(EvidenceBinding value) noexcept;
[[nodiscard]] std::string_view to_string(HopResolution value) noexcept;
[[nodiscard]] std::string_view to_string(ResourceKind value) noexcept;
[[nodiscard]] std::string_view to_string(AdministrativeState value) noexcept;
[[nodiscard]] std::string_view to_string(LinkState value) noexcept;
[[nodiscard]] std::string_view to_string(TrafficSelectorKind value) noexcept;
[[nodiscard]] std::string_view to_string(ContainmentOutcome value) noexcept;
[[nodiscard]] std::string_view to_string(TargetReason value) noexcept;
[[nodiscard]] std::string_view to_string(AuthorityKind value) noexcept;
[[nodiscard]] std::string_view to_string(GrantState value) noexcept;
[[nodiscard]] std::string_view to_string(FindingState value) noexcept;
[[nodiscard]] std::string_view to_string(FenceCause value) noexcept;
[[nodiscard]] std::string_view to_string(EvidenceOrigin value) noexcept;
[[nodiscard]] std::string_view to_string(ProducerKind value) noexcept;
[[nodiscard]] std::string_view to_string(ReasonCode value) noexcept;
[[nodiscard]] std::string_view to_string(Severity value) noexcept;

/// Renders an assessment flag bitset as a canonical, comma separated, sorted list.
[[nodiscard]] std::string assessment_flags_to_string(AssessmentFlags flags);
/// Renders a plan flag bitset as a canonical, comma separated, sorted list.
[[nodiscard]] std::string plan_flags_to_string(PlanFlags flags);

}  // namespace loop_guard
