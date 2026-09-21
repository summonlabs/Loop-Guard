#include "loop_guard/core.hpp"

#include "loop_guard/limits.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <limits>

namespace loop_guard {
namespace {

void append_u64(std::vector<std::uint8_t>& out, std::uint64_t value) {
  for (std::size_t index = 0; index < 8; ++index) {
    out.push_back(static_cast<std::uint8_t>((value >> (index * 8U)) & 0xFFU));
  }
}

bool is_utf8_continuation(char character) {
  return (static_cast<unsigned char>(character) & 0xC0U) == 0x80U;
}

}  // namespace

// ---------------------------------------------------------------------------
// Checked arithmetic.
// ---------------------------------------------------------------------------
bool checked_add_u64(std::uint64_t lhs, std::uint64_t rhs, std::uint64_t& out) noexcept {
  if (lhs > std::numeric_limits<std::uint64_t>::max() - rhs) {
    return false;
  }
  out = lhs + rhs;
  return true;
}

bool checked_mul_u64(std::uint64_t lhs, std::uint64_t rhs, std::uint64_t& out) noexcept {
  if (lhs != 0U && rhs > std::numeric_limits<std::uint64_t>::max() / lhs) {
    return false;
  }
  out = lhs * rhs;
  return true;
}

bool narrow_u32(std::uint64_t value, std::uint32_t& out) noexcept {
  if (value > std::numeric_limits<std::uint32_t>::max()) {
    return false;
  }
  out = static_cast<std::uint32_t>(value);
  return true;
}

bool checked_add_u32(std::uint32_t lhs, std::uint32_t rhs, std::uint32_t& out) noexcept {
  if (lhs > std::numeric_limits<std::uint32_t>::max() - rhs) {
    return false;
  }
  out = lhs + rhs;
  return true;
}

const Limits& default_limits() noexcept {
  static const Limits kLimits;
  return kLimits;
}

bool limits_are_sane(const Limits& limits) noexcept {
  if (limits.max_witness_hops == 0U || limits.max_witness_hops > 256U) {
    return false;
  }
  if (limits.max_witnesses_per_assessment == 0U ||
      limits.max_witnesses_per_assessment > Maxima::kCollectionElements) {
    return false;
  }
  if (limits.max_cycles_enumerated == 0U || limits.max_search_steps == 0U) {
    return false;
  }
  if (limits.max_resources == 0U || limits.max_resources > Maxima::kCollectionElements) {
    return false;
  }
  if (limits.max_edges == 0U || limits.max_edges > Maxima::kCollectionElements) {
    return false;
  }
  if (limits.max_selectors == 0U || limits.max_selectors > Maxima::kCollectionElements) {
    return false;
  }
  if (limits.max_candidate_selectors == 0U ||
      limits.max_candidate_selectors > Maxima::kCollectionElements) {
    return false;
  }
  if (limits.max_plan_targets == 0U || limits.max_plan_targets > Maxima::kCollectionElements) {
    return false;
  }
  if (limits.max_observations_per_edge == 0U ||
      limits.max_observations_per_edge > Maxima::kCollectionElements) {
    return false;
  }
  if (limits.max_observations == 0U || limits.max_observations > Maxima::kCollectionElements) {
    return false;
  }
  if (limits.max_explanation_reasons == 0U) {
    return false;
  }
  if (limits.max_reason_detail_bytes == 0U || limits.max_text_line == 0U) {
    return false;
  }
  if (limits.max_containment_search_nodes == 0U || limits.max_containment_candidates == 0U) {
    return false;
  }
  if (limits.max_session_queue == 0U || limits.max_sessions == 0U || limits.max_backlog == 0U) {
    return false;
  }
  if (limits.max_journal_records == 0U || limits.max_journal_bytes == 0U) {
    return false;
  }
  if (limits.max_boot_records == 0U || limits.max_boot_records > Maxima::kCollectionElements) {
    return false;
  }
  if (limits.max_retained_lineage == 0U || limits.max_retained_lineage > Maxima::kCollectionElements) {
    return false;
  }
  if (limits.max_retained_findings == 0U ||
      limits.max_retained_findings > Maxima::kCollectionElements) {
    return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// Fence vector.
// ---------------------------------------------------------------------------
bool operator<(const FenceVector& lhs, const FenceVector& rhs) noexcept {
  if (lhs.boot != rhs.boot) {
    return lhs.boot < rhs.boot;
  }
  if (lhs.epoch != rhs.epoch) {
    return lhs.epoch < rhs.epoch;
  }
  if (lhs.fabric_epoch != rhs.fabric_epoch) {
    return lhs.fabric_epoch < rhs.fabric_epoch;
  }
  if (lhs.topology != rhs.topology) {
    return lhs.topology < rhs.topology;
  }
  if (lhs.forwarding != rhs.forwarding) {
    return lhs.forwarding < rhs.forwarding;
  }
  return lhs.policy < rhs.policy;
}

bool FenceVector::is_zero() const noexcept {
  return !topology.valid() && !forwarding.valid() && !policy.valid() && !fabric_epoch.valid() &&
         !epoch.valid() && !boot.valid();
}

Digest FenceVector::digest() const {
  std::vector<std::uint8_t> bytes;
  bytes.reserve(48);
  append_u64(bytes, topology.value());
  append_u64(bytes, forwarding.value());
  append_u64(bytes, policy.value());
  append_u64(bytes, fabric_epoch.value());
  append_u64(bytes, epoch.value());
  append_u64(bytes, boot.value());
  return sha256(bytes);
}

std::string FenceVector::to_string() const {
  return "t" + topology.to_string() + "/f" + forwarding.to_string() + "/p" + policy.to_string() +
         "/e" + fabric_epoch.to_string() + "/c" + epoch.to_string() + "/b" + boot.to_string();
}

FenceCause fence_cause(const FenceVector& candidate, const FenceVector& current) noexcept {
  if (candidate.boot != current.boot) {
    return FenceCause::BootAdvanced;
  }
  if (candidate.epoch != current.epoch) {
    return FenceCause::CoordinatorEpochAdvanced;
  }
  if (candidate.fabric_epoch != current.fabric_epoch) {
    return FenceCause::FabricEpochAdvanced;
  }
  if (candidate.topology != current.topology) {
    return FenceCause::TopologyGenerationAdvanced;
  }
  if (candidate.forwarding != current.forwarding) {
    return FenceCause::ForwardingGenerationAdvanced;
  }
  if (candidate.policy != current.policy) {
    return FenceCause::PolicyGenerationAdvanced;
  }
  return FenceCause::None;
}

std::string ProcessIdentity::to_string() const {
  return "producer" + producer.to_string() + "/boot" + boot.to_string() + "/inc" +
         incarnation.to_string() + "/epoch" + epoch.to_string();
}

// ---------------------------------------------------------------------------
// Explanation.
// ---------------------------------------------------------------------------
bool operator<(const ExplanationReason& lhs, const ExplanationReason& rhs) noexcept {
  if (lhs.code != rhs.code) {
    return lhs.code < rhs.code;
  }
  if (lhs.subject != rhs.subject) {
    return lhs.subject < rhs.subject;
  }
  return lhs.detail < rhs.detail;
}

std::string ExplanationReason::to_string() const {
  std::string out(loop_guard::to_string(code));
  if (!subject.empty()) {
    out += " [";
    out += subject;
    out += "]";
  }
  if (!detail.empty()) {
    out += " ";
    out += detail;
  }
  return out;
}

bool Explanation::add(ReasonCode code, std::string subject, std::string detail) {
  if (reasons_.size() >= static_cast<std::size_t>(max_reasons_)) {
    ++dropped_;
    return false;
  }
  ExplanationReason reason;
  reason.code = code;
  reason.subject = bounded_text(subject, 128);
  reason.detail = bounded_text(detail, 192);
  const auto position =
      std::lower_bound(reasons_.begin(), reasons_.end(), reason,
                       [](const ExplanationReason& lhs, const ExplanationReason& rhs) {
                         return lhs < rhs;
                       });
  reasons_.insert(position, std::move(reason));
  return true;
}

void Explanation::add_unique(ReasonCode code, std::string subject, std::string detail) {
  const std::string bounded_subject = bounded_text(subject, 128);
  for (const ExplanationReason& existing : reasons_) {
    if (existing.code == code && existing.subject == bounded_subject) {
      return;
    }
  }
  (void)add(code, std::move(subject), std::move(detail));
}

bool Explanation::contains(ReasonCode code) const noexcept {
  for (const ExplanationReason& reason : reasons_) {
    if (reason.code == code) {
      return true;
    }
  }
  return false;
}

Severity Explanation::severity() const noexcept {
  Severity worst = Severity::Info;
  for (const ExplanationReason& reason : reasons_) {
    const Severity candidate = severity_of(reason.code);
    if (candidate > worst) {
      worst = candidate;
    }
  }
  return worst;
}

std::string Explanation::to_text() const {
  std::string out;
  for (const ExplanationReason& reason : reasons_) {
    out += reason.to_string();
    out.push_back('\n');
  }
  if (dropped_ != 0U) {
    out += "(dropped ";
    out += std::to_string(dropped_);
    out += " reason(s) at capacity)\n";
  }
  return out;
}

Digest Explanation::digest() const {
  Sha256 hasher;
  for (const ExplanationReason& reason : reasons_) {
    hasher.update(static_cast<std::uint8_t>(reason.code));
    hasher.update(reason.subject);
    hasher.update(static_cast<std::uint8_t>(0));
    hasher.update(reason.detail);
    hasher.update(static_cast<std::uint8_t>(0));
  }
  return hasher.finish();
}

void Explanation::sort_and_truncate() {
  // Reasons are inserted in canonical order, so this is a defensive no-op.
  sorted_ = true;
}

Outcome outcome_of(ReasonCode code) noexcept {
  switch (code) {
    case ReasonCode::PersistenceFormatUnsupported:
    case ReasonCode::WireFrameTypeUnsupported:
    case ReasonCode::UnsupportedHardwarePath:
      return Outcome::Unsupported;
    case ReasonCode::PersistenceIntegrityFailure:
    case ReasonCode::PersistenceTrailingGarbage:
    case ReasonCode::WireFrameBadIntegrity:
    case ReasonCode::WireFrameBadMagic:
    case ReasonCode::WireFrameBadVersion:
      return Outcome::IntegrityFailure;
    case ReasonCode::LimitsExceeded:
    case ReasonCode::ResourceBudgetExhausted:
    case ReasonCode::WireFrameOversized:
      return Outcome::Exhausted;
    case ReasonCode::PersistenceSequenceRegression:
    case ReasonCode::ObservationSequenceRegressed:
    case ReasonCode::WireSequenceRegressed:
    case ReasonCode::ObservationGenerationMismatch:
    case ReasonCode::ObservationLeaseExpired:
      return Outcome::Stale;
    case ReasonCode::WireSessionMismatch:
    case ReasonCode::WireHandshakeRejected:
    case ReasonCode::AuthorityGrantAbsent:
    case ReasonCode::AuthorityGrantExpired:
    case ReasonCode::AuthorityGrantRevoked:
    case ReasonCode::AuthorityGrantFenced:
    case ReasonCode::AuthorityTargetOutOfScope:
    case ReasonCode::AuthorityBudgetExceeded:
      return Outcome::Refused;
    case ReasonCode::DuplicateObservationRejected:
      return Outcome::AlreadyExists;
    case ReasonCode::HopConflictsWithItself:
      return Outcome::Conflict;
    case ReasonCode::WireFrameBadEnum:
    case ReasonCode::WireFrameTruncated:
    case ReasonCode::WireFrameTrailingBytes:
    case ReasonCode::PersistenceRecordRejected:
    case ReasonCode::RequestRejectedStructural:
      return Outcome::Invalid;
    case ReasonCode::SearchBudgetExhausted:
      return Outcome::Indeterminate;
    default:
      return Outcome::Invalid;
  }
}

Severity severity_of(ReasonCode code) noexcept {
  switch (code) {
    case ReasonCode::InternalInvariantViolated:
    case ReasonCode::PersistenceIntegrityFailure:
    case ReasonCode::PersistenceTrailingGarbage:
    case ReasonCode::PersistenceSequenceRegression:
    case ReasonCode::HopConflictsWithItself:
    case ReasonCode::FindingFencedByGenerationChange:
    case ReasonCode::FindingFencedByRestart:
    case ReasonCode::AuthorityGrantFenced:
    case ReasonCode::ContainmentProvedInfeasible:
      return Severity::Critical;
    case ReasonCode::ObservationGenerationMismatch:
    case ReasonCode::ObservationEpochFenced:
    case ReasonCode::ObservationLeaseExpired:
    case ReasonCode::ObservationSuperseded:
    case ReasonCode::ObservationSequenceRegressed:
    case ReasonCode::NoObservationForHop:
    case ReasonCode::CycleRequiresUnprovenHop:
    case ReasonCode::SearchBudgetExhausted:
    case ReasonCode::LimitsExceeded:
    case ReasonCode::ResourceBudgetExhausted:
    case ReasonCode::ContainmentPlanEmptyButLoopsRemain:
    case ReasonCode::ContainmentPolicyRefusedTargets:
    case ReasonCode::ContainmentCostBudgetExceeded:
    case ReasonCode::ContainmentPlanInvalid:
    case ReasonCode::AuthorityGrantAbsent:
    case ReasonCode::AuthorityGrantExpired:
    case ReasonCode::AuthorityGrantRevoked:
    case ReasonCode::AuthorityTargetOutOfScope:
    case ReasonCode::AuthorityBudgetExceeded:
    case ReasonCode::EffectUnverifiedForTarget:
    case ReasonCode::AcknowledgementIsNotEffect:
    case ReasonCode::WitnessRejectedByValidator:
    case ReasonCode::RequestRejectedStructural:
    case ReasonCode::DuplicateObservationRejected:
    case ReasonCode::PersistenceFormatUnsupported:
    case ReasonCode::PersistenceRecordRejected:
    case ReasonCode::WireFrameTruncated:
    case ReasonCode::WireFrameOversized:
    case ReasonCode::WireFrameBadMagic:
    case ReasonCode::WireFrameBadVersion:
    case ReasonCode::WireFrameBadIntegrity:
    case ReasonCode::WireFrameBadEnum:
    case ReasonCode::WireFrameTrailingBytes:
    case ReasonCode::WireSessionMismatch:
    case ReasonCode::WireSequenceRegressed:
    case ReasonCode::WireHandshakeRejected:
    case ReasonCode::WireFrameTypeUnsupported:
    case ReasonCode::UnsupportedHardwarePath:
      return Severity::Warning;
    case ReasonCode::RequestAccepted:
    case ReasonCode::CycleInTopologyButNoForwardingEvidence:
    case ReasonCode::CycleBrokenByAbsentEvidence:
    case ReasonCode::WitnessRequiresExactGenerations:
    case ReasonCode::WitnessHopGenerationsDisagree:
    case ReasonCode::WitnessSelectorNotAdmitted:
    case ReasonCode::WitnessResourceAdministrativelyDown:
    case ReasonCode::WitnessResourceUnknown:
    case ReasonCode::WitnessSuccessfullyValidated:
    case ReasonCode::SearchCompletedExhaustively:
    case ReasonCode::SelectorScopeEmpty:
    case ReasonCode::ContainmentNotRequired:
    case ReasonCode::ContainmentTargetsProvedMinimum:
    case ReasonCode::ContainmentTargetsFeasibleOnly:
    case ReasonCode::ContainmentCertificateNonContainableCycle:
    case ReasonCode::ContainmentUnrelatedForwardingUntouched:
    case ReasonCode::ContainmentGreedyRecommendationOnly:
    case ReasonCode::ContainmentPlanValidated:
    case ReasonCode::EffectVerifiedForTarget:
    case ReasonCode::FindingWithdrawn:
    case ReasonCode::FindingSupersededByNewerAssessment:
    case ReasonCode::PersistenceTornTailRecovered:
    case ReasonCode::PersistenceSnapshotCommitted:
    case ReasonCode::RestartFreshIncarnation:
    case ReasonCode::DynamicStateNotRestored:
    case ReasonCode::WireFrameAccepted:
    case ReasonCode::WireSessionClosed:
      return Severity::Info;
  }
  return Severity::Notice;
}

std::string bounded_text(std::string_view text, std::size_t max_bytes) {
  if (text.size() <= max_bytes) {
    return std::string(text);
  }
  std::size_t cut = max_bytes;
  while (cut > 0 && is_utf8_continuation(text[cut])) {
    --cut;
  }
  std::string out(text.substr(0, cut));
  out += "...";
  return out;
}

// ---------------------------------------------------------------------------
// Deterministic pseudo-randomness (splitmix64).
// ---------------------------------------------------------------------------
std::uint64_t Rng::next_u64() noexcept {
  state_ += 0x9E3779B97F4A7C15ULL;
  std::uint64_t value = state_;
  value = (value ^ (value >> 30U)) * 0xBF58476D1CE4E5B9ULL;
  value = (value ^ (value >> 27U)) * 0x94D049BB133111EBULL;
  return value ^ (value >> 31U);
}

std::uint64_t Rng::next_below(std::uint64_t bound) noexcept {
  if (bound == 0U) {
    return 0U;
  }
  return next_u64() % bound;
}

}  // namespace loop_guard
