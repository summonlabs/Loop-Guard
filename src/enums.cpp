#include "loop_guard/enums.hpp"

#include <string>
#include <vector>

namespace loop_guard {
namespace {

/// Strips the enum qualification from a stringified enumerator so that the canonical
/// token is "LoopConfirmed" rather than "LoopOutcome::LoopConfirmed". The computation is
/// constexpr over a literal, so it costs nothing at run time and is fully deterministic.
constexpr std::string_view strip_scope(std::string_view text) noexcept {
  const std::size_t position = text.rfind("::");
  return position == std::string_view::npos ? text : text.substr(position + 2U);
}

}  // namespace

#define LG_NAME(value) \
  case value:          \
    return strip_scope(#value)

std::string_view to_string(Outcome value) noexcept {
  switch (value) {
    LG_NAME(Outcome::Ok);
    LG_NAME(Outcome::Invalid);
    LG_NAME(Outcome::Unknown);
    LG_NAME(Outcome::Stale);
    LG_NAME(Outcome::Conflict);
    LG_NAME(Outcome::Unsupported);
    LG_NAME(Outcome::NotFound);
    LG_NAME(Outcome::AlreadyExists);
    LG_NAME(Outcome::Exhausted);
    LG_NAME(Outcome::IntegrityFailure);
    LG_NAME(Outcome::IoFailure);
    LG_NAME(Outcome::Refused);
    LG_NAME(Outcome::Indeterminate);
    LG_NAME(Outcome::Interrupted);
    LG_NAME(Outcome::Fenced);
  }
  return "Invalid";
}

std::string_view to_string(LoopOutcome value) noexcept {
  switch (value) {
    LG_NAME(LoopOutcome::NoLoop);
    LG_NAME(LoopOutcome::LoopConfirmed);
    LG_NAME(LoopOutcome::Unknown);
    LG_NAME(LoopOutcome::Stale);
    LG_NAME(LoopOutcome::Conflict);
    LG_NAME(LoopOutcome::Invalid);
    LG_NAME(LoopOutcome::Unsupported);
    LG_NAME(LoopOutcome::Indeterminate);
  }
  return "Invalid";
}

std::string_view to_string(EvidenceClass value) noexcept {
  switch (value) {
    LG_NAME(EvidenceClass::Present);
    LG_NAME(EvidenceClass::Absent);
    LG_NAME(EvidenceClass::Unknown);
  }
  return "Invalid";
}

std::string_view to_string(EvidenceBinding value) noexcept {
  switch (value) {
    LG_NAME(EvidenceBinding::Exact);
    LG_NAME(EvidenceBinding::GenerationMismatch);
    LG_NAME(EvidenceBinding::EpochFenced);
    LG_NAME(EvidenceBinding::LeaseExpired);
    LG_NAME(EvidenceBinding::Superseded);
    LG_NAME(EvidenceBinding::NoEvidence);
  }
  return "Invalid";
}

std::string_view to_string(HopResolution value) noexcept {
  switch (value) {
    LG_NAME(HopResolution::ProvenOpen);
    LG_NAME(HopResolution::ProvenClosed);
    LG_NAME(HopResolution::UnprovenOpen);
    LG_NAME(HopResolution::Unproven);
    LG_NAME(HopResolution::Conflicted);
    LG_NAME(HopResolution::Unsupported);
  }
  return "Invalid";
}

std::string_view to_string(ResourceKind value) noexcept {
  switch (value) {
    LG_NAME(ResourceKind::Switch);
    LG_NAME(ResourceKind::PortGroup);
    LG_NAME(ResourceKind::NextHopGroup);
    LG_NAME(ResourceKind::TunnelEndpoint);
    LG_NAME(ResourceKind::ServiceStage);
    LG_NAME(ResourceKind::HostInterface);
    LG_NAME(ResourceKind::VirtualSwitch);
    LG_NAME(ResourceKind::Unsupported);
  }
  return "Invalid";
}

std::string_view to_string(AdministrativeState value) noexcept {
  switch (value) {
    LG_NAME(AdministrativeState::Enabled);
    LG_NAME(AdministrativeState::Disabled);
    LG_NAME(AdministrativeState::Unknown);
  }
  return "Invalid";
}

std::string_view to_string(LinkState value) noexcept {
  switch (value) {
    LG_NAME(LinkState::Up);
    LG_NAME(LinkState::Down);
    LG_NAME(LinkState::Unknown);
  }
  return "Invalid";
}

std::string_view to_string(TrafficSelectorKind value) noexcept {
  switch (value) {
    LG_NAME(TrafficSelectorKind::FlowClass);
    LG_NAME(TrafficSelectorKind::PrefixPair);
    LG_NAME(TrafficSelectorKind::TenantScope);
    LG_NAME(TrafficSelectorKind::ServiceChain);
  }
  return "Invalid";
}

std::string_view to_string(ContainmentOutcome value) noexcept {
  switch (value) {
    LG_NAME(ContainmentOutcome::NotRequired);
    LG_NAME(ContainmentOutcome::PlanOptimal);
    LG_NAME(ContainmentOutcome::PlanFeasible);
    LG_NAME(ContainmentOutcome::ProvenInfeasible);
    LG_NAME(ContainmentOutcome::SearchLimitReached);
    LG_NAME(ContainmentOutcome::Unsupported);
    LG_NAME(ContainmentOutcome::Invalid);
  }
  return "Invalid";
}

std::string_view to_string(TargetReason value) noexcept {
  switch (value) {
    LG_NAME(TargetReason::SoleBreakOfWitness);
    LG_NAME(TargetReason::MinimumCostHittingSet);
    LG_NAME(TargetReason::FeasibleHittingSet);
    LG_NAME(TargetReason::GreedyRecommendation);
  }
  return "Invalid";
}

std::string_view to_string(AuthorityKind value) noexcept {
  switch (value) {
    LG_NAME(AuthorityKind::Observation);
    LG_NAME(AuthorityKind::Eligibility);
    LG_NAME(AuthorityKind::Recommendation);
    LG_NAME(AuthorityKind::Authorization);
    LG_NAME(AuthorityKind::Request);
    LG_NAME(AuthorityKind::Acknowledgement);
    LG_NAME(AuthorityKind::VerifiedEffect);
    LG_NAME(AuthorityKind::Withdrawal);
  }
  return "Invalid";
}

std::string_view to_string(GrantState value) noexcept {
  switch (value) {
    LG_NAME(GrantState::Active);
    LG_NAME(GrantState::Consumed);
    LG_NAME(GrantState::Expired);
    LG_NAME(GrantState::Revoked);
    LG_NAME(GrantState::Fenced);
  }
  return "Invalid";
}

std::string_view to_string(FindingState value) noexcept {
  switch (value) {
    LG_NAME(FindingState::Proposed);
    LG_NAME(FindingState::Confirmed);
    LG_NAME(FindingState::ContainmentAuthorized);
    LG_NAME(FindingState::ContainmentRequested);
    LG_NAME(FindingState::ContainmentAppliedUnverified);
    LG_NAME(FindingState::ContainmentVerified);
    LG_NAME(FindingState::Withdrawn);
    LG_NAME(FindingState::Stale);
    LG_NAME(FindingState::Fenced);
    LG_NAME(FindingState::Rejected);
  }
  return "Invalid";
}

std::string_view to_string(FenceCause value) noexcept {
  switch (value) {
    LG_NAME(FenceCause::None);
    LG_NAME(FenceCause::TopologyGenerationAdvanced);
    LG_NAME(FenceCause::ForwardingGenerationAdvanced);
    LG_NAME(FenceCause::PolicyGenerationAdvanced);
    LG_NAME(FenceCause::FabricEpochAdvanced);
    LG_NAME(FenceCause::CoordinatorEpochAdvanced);
    LG_NAME(FenceCause::BootAdvanced);
    LG_NAME(FenceCause::ExplicitWithdrawal);
    LG_NAME(FenceCause::GrantExpired);
    LG_NAME(FenceCause::GrantRevoked);
  }
  return "Invalid";
}

std::string_view to_string(EvidenceOrigin value) noexcept {
  switch (value) {
    LG_NAME(EvidenceOrigin::Real);
    LG_NAME(EvidenceOrigin::Synthetic);
    LG_NAME(EvidenceOrigin::Unsupported);
  }
  return "Invalid";
}

std::string_view to_string(ProducerKind value) noexcept {
  switch (value) {
    LG_NAME(ProducerKind::SyntheticFixture);
    LG_NAME(ProducerKind::InProcessRuntime);
    LG_NAME(ProducerKind::RemoteCoordinator);
    LG_NAME(ProducerKind::RemoteWorker);
    LG_NAME(ProducerKind::Operator);
  }
  return "Invalid";
}

std::string_view to_string(Severity value) noexcept {
  switch (value) {
    LG_NAME(Severity::Info);
    LG_NAME(Severity::Notice);
    LG_NAME(Severity::Warning);
    LG_NAME(Severity::Critical);
  }
  return "Invalid";
}

std::string_view to_string(ReasonCode value) noexcept {
  switch (value) {
    LG_NAME(ReasonCode::RequestAccepted);
    LG_NAME(ReasonCode::RequestRejectedStructural);
    LG_NAME(ReasonCode::LimitsExceeded);
    LG_NAME(ReasonCode::DuplicateObservationRejected);
    LG_NAME(ReasonCode::ObservationSequenceRegressed);
    LG_NAME(ReasonCode::ObservationGenerationMismatch);
    LG_NAME(ReasonCode::ObservationEpochFenced);
    LG_NAME(ReasonCode::ObservationLeaseExpired);
    LG_NAME(ReasonCode::ObservationSuperseded);
    LG_NAME(ReasonCode::NoObservationForHop);
    LG_NAME(ReasonCode::HopConflictsWithItself);
    LG_NAME(ReasonCode::CycleInTopologyButNoForwardingEvidence);
    LG_NAME(ReasonCode::CycleRequiresUnprovenHop);
    LG_NAME(ReasonCode::CycleBrokenByAbsentEvidence);
    LG_NAME(ReasonCode::WitnessRequiresExactGenerations);
    LG_NAME(ReasonCode::WitnessHopGenerationsDisagree);
    LG_NAME(ReasonCode::WitnessSelectorNotAdmitted);
    LG_NAME(ReasonCode::WitnessResourceAdministrativelyDown);
    LG_NAME(ReasonCode::WitnessResourceUnknown);
    LG_NAME(ReasonCode::WitnessSuccessfullyValidated);
    LG_NAME(ReasonCode::WitnessRejectedByValidator);
    LG_NAME(ReasonCode::SearchBudgetExhausted);
    LG_NAME(ReasonCode::SearchCompletedExhaustively);
    LG_NAME(ReasonCode::SelectorScopeEmpty);
    LG_NAME(ReasonCode::ContainmentNotRequired);
    LG_NAME(ReasonCode::ContainmentPlanEmptyButLoopsRemain);
    LG_NAME(ReasonCode::ContainmentTargetsProvedMinimum);
    LG_NAME(ReasonCode::ContainmentTargetsFeasibleOnly);
    LG_NAME(ReasonCode::ContainmentProvedInfeasible);
    LG_NAME(ReasonCode::ContainmentCertificateNonContainableCycle);
    LG_NAME(ReasonCode::ContainmentPolicyRefusedTargets);
    LG_NAME(ReasonCode::ContainmentUnrelatedForwardingUntouched);
    LG_NAME(ReasonCode::ContainmentGreedyRecommendationOnly);
    LG_NAME(ReasonCode::ContainmentCostBudgetExceeded);
    LG_NAME(ReasonCode::ContainmentPlanValidated);
    LG_NAME(ReasonCode::ContainmentPlanInvalid);
    LG_NAME(ReasonCode::AuthorityGrantAbsent);
    LG_NAME(ReasonCode::AuthorityGrantExpired);
    LG_NAME(ReasonCode::AuthorityGrantRevoked);
    LG_NAME(ReasonCode::AuthorityGrantFenced);
    LG_NAME(ReasonCode::AuthorityTargetOutOfScope);
    LG_NAME(ReasonCode::AuthorityBudgetExceeded);
    LG_NAME(ReasonCode::AcknowledgementIsNotEffect);
    LG_NAME(ReasonCode::EffectUnverifiedForTarget);
    LG_NAME(ReasonCode::EffectVerifiedForTarget);
    LG_NAME(ReasonCode::FindingWithdrawn);
    LG_NAME(ReasonCode::FindingFencedByGenerationChange);
    LG_NAME(ReasonCode::FindingFencedByRestart);
    LG_NAME(ReasonCode::FindingSupersededByNewerAssessment);
    LG_NAME(ReasonCode::PersistenceFormatUnsupported);
    LG_NAME(ReasonCode::PersistenceIntegrityFailure);
    LG_NAME(ReasonCode::PersistenceTornTailRecovered);
    LG_NAME(ReasonCode::PersistenceTrailingGarbage);
    LG_NAME(ReasonCode::PersistenceSequenceRegression);
    LG_NAME(ReasonCode::PersistenceRecordRejected);
    LG_NAME(ReasonCode::PersistenceSnapshotCommitted);
    LG_NAME(ReasonCode::RestartFreshIncarnation);
    LG_NAME(ReasonCode::DynamicStateNotRestored);
    LG_NAME(ReasonCode::WireFrameAccepted);
    LG_NAME(ReasonCode::WireFrameTruncated);
    LG_NAME(ReasonCode::WireFrameOversized);
    LG_NAME(ReasonCode::WireFrameBadMagic);
    LG_NAME(ReasonCode::WireFrameBadVersion);
    LG_NAME(ReasonCode::WireFrameBadIntegrity);
    LG_NAME(ReasonCode::WireFrameBadEnum);
    LG_NAME(ReasonCode::WireFrameTrailingBytes);
    LG_NAME(ReasonCode::WireSessionMismatch);
    LG_NAME(ReasonCode::WireSequenceRegressed);
    LG_NAME(ReasonCode::WireHandshakeRejected);
    LG_NAME(ReasonCode::WireSessionClosed);
    LG_NAME(ReasonCode::WireFrameTypeUnsupported);
    LG_NAME(ReasonCode::UnsupportedHardwarePath);
    LG_NAME(ReasonCode::ResourceBudgetExhausted);
    LG_NAME(ReasonCode::InternalInvariantViolated);
  }
  return "Invalid";
}

#undef LG_NAME

namespace {
void append_flag(std::vector<std::string_view>& parts, AssessmentFlags flags, AssessmentFlags bit,
                 std::string_view name) {
  if ((flags & bit) != 0U) {
    parts.push_back(name);
  }
}

void append_plan_flag(std::vector<std::string_view>& parts, PlanFlags flags, PlanFlags bit,
                      std::string_view name) {
  if ((flags & bit) != 0U) {
    parts.push_back(name);
  }
}

std::string join(const std::vector<std::string_view>& parts) {
  std::string out;
  for (std::size_t index = 0; index < parts.size(); ++index) {
    if (index != 0U) {
      out.push_back(',');
    }
    out.append(parts[index]);
  }
  if (out.empty()) {
    out = "None";
  }
  return out;
}
}  // namespace

std::string assessment_flags_to_string(AssessmentFlags flags) {
  std::vector<std::string_view> parts;
  append_flag(parts, flags, kAssessmentSearchLimitReached, "SearchLimitReached");
  append_flag(parts, flags, kAssessmentUnprovenHopsPresent, "UnprovenHopsPresent");
  append_flag(parts, flags, kAssessmentConflictsPresent, "ConflictsPresent");
  append_flag(parts, flags, kAssessmentStaleEvidencePresent, "StaleEvidencePresent");
  append_flag(parts, flags, kAssessmentAdditionalCyclesPossible, "AdditionalCyclesPossible");
  append_flag(parts, flags, kAssessmentContainedByActiveIntent, "ContainedByActiveIntent");
  append_flag(parts, flags, kAssessmentNoEvidenceAtAll, "NoEvidenceAtAll");
  return join(parts);
}

std::string plan_flags_to_string(PlanFlags flags) {
  std::vector<std::string_view> parts;
  append_plan_flag(parts, flags, kPlanGreedyRecommendationPresent, "GreedyRecommendationPresent");
  append_plan_flag(parts, flags, kPlanTouchesNonContainableResources, "TouchesNonContainableResources");
  append_plan_flag(parts, flags, kPlanCostBudgetExceeded, "CostBudgetExceeded");
  append_plan_flag(parts, flags, kPlanUnrelatedForwardingUntouched, "UnrelatedForwardingUntouched");
  append_plan_flag(parts, flags, kPlanWitnessSetIncomplete, "WitnessSetIncomplete");
  append_plan_flag(parts, flags, kPlanSearchLimitReached, "SearchLimitReached");
  append_plan_flag(parts, flags, kPlanProvedMinimum, "ProvedMinimum");
  append_plan_flag(parts, flags, kPlanCertificateAttached, "CertificateAttached");
  append_plan_flag(parts, flags, kPlanContainsWholeWitness, "ContainsWholeWitness");
  return join(parts);
}

}  // namespace loop_guard
