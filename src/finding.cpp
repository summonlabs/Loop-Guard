#include "loop_guard/finding.hpp"

#include <algorithm>
#include <set>

namespace loop_guard {
namespace {

void hash_u64(Sha256& hasher, std::uint64_t value) {
  hasher.update(
      std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(&value), sizeof(value)));
}

}  // namespace

bool Finding::is_terminal() const noexcept {
  switch (state) {
    case FindingState::Withdrawn:
    case FindingState::Stale:
    case FindingState::Fenced:
    case FindingState::Rejected:
      return true;
    case FindingState::Proposed:
    case FindingState::Confirmed:
    case FindingState::ContainmentAuthorized:
    case FindingState::ContainmentRequested:
    case FindingState::ContainmentAppliedUnverified:
    case FindingState::ContainmentVerified:
      return false;
  }
  return true;
}

Digest Finding::content_digest() const {
  Sha256 hasher;
  hash_u64(hasher, id.value());
  hash_u64(hasher, generation.value());
  hash_u64(hasher, assessment.value());
  hasher.update(assessment_digest.bytes.data(), kDigestBytes);
  hash_u64(hasher, fence.topology.value());
  hash_u64(hasher, fence.forwarding.value());
  hash_u64(hasher, fence.policy.value());
  hash_u64(hasher, fence.fabric_epoch.value());
  hash_u64(hasher, fence.epoch.value());
  hash_u64(hasher, fence.boot.value());
  hasher.update(static_cast<std::uint8_t>(state));
  hasher.update(static_cast<std::uint8_t>(fence_cause));
  hasher.update(static_cast<std::uint8_t>(assessment_outcome));
  hash_u64(hasher, assessment_flags);
  for (const WitnessId witness : witnesses) {
    hash_u64(hasher, witness.value());
  }
  hasher.update(static_cast<std::uint8_t>(0xF5));
  for (const ResourceId resource : implicated_resources) {
    hash_u64(hasher, resource.value());
  }
  hasher.update(static_cast<std::uint8_t>(0xF5));
  for (const TrafficSelectorId selector : implicated_selectors) {
    hash_u64(hasher, selector.value());
  }
  hasher.update(static_cast<std::uint8_t>(0xF5));
  hash_u64(hasher, plan.value());
  hash_u64(hasher, intent.value());
  hash_u64(hasher, created_at);
  hash_u64(hasher, updated_at);
  hasher.update(static_cast<std::uint8_t>(origin));
  return hasher.finish();
}

std::string Finding::to_text() const {
  return "finding " + id.to_string() + " state=" + std::string(to_string(state)) +
         " cause=" + std::string(to_string(fence_cause)) +
         " outcome=" + std::string(to_string(assessment_outcome)) +
         " flags=" + assessment_flags_to_string(assessment_flags) +
         " witnesses=" + std::to_string(witnesses.size()) +
         " resources=" + std::to_string(implicated_resources.size()) +
         " selectors=" + std::to_string(implicated_selectors.size()) +
         " fence=" + fence.to_string();
}

// ---------------------------------------------------------------------------
// FindingRegistry.
// ---------------------------------------------------------------------------
FindingRegistry::FindingRegistry(const Limits& limits) : limits_(limits) {}

Result<FindingId> FindingRegistry::register_finding(Finding finding) {
  if (!finding.id.valid()) {
    return Result<FindingId>::failure(Outcome::Invalid, "finding identity must be non-zero");
  }
  if (!finding.fence.is_zero() && finding.fence.boot.valid()) {
    // The fence is required: a finding that cannot be fenced cannot be withdrawn.
  } else {
    return Result<FindingId>::failure(Outcome::Invalid, "finding must bind a complete fence vector");
  }
  for (const Finding& existing : findings_) {
    if (existing.id == finding.id) {
      return Result<FindingId>::failure(Outcome::AlreadyExists, "finding identity is already present");
    }
  }
  if (findings_.size() >= limits_.max_retained_findings) {
    // Deterministic retention: evict exactly one oldest terminal finding. If every
    // retained finding is still live, refuse rather than evicting live authority.
    std::size_t victim = findings_.size();
    for (std::size_t index = 0; index < findings_.size(); ++index) {
      if (!findings_[index].is_terminal()) {
        continue;
      }
      if (victim == findings_.size() || findings_[index].updated_at < findings_[victim].updated_at ||
          (findings_[index].updated_at == findings_[victim].updated_at &&
           findings_[index].id < findings_[victim].id)) {
        victim = index;
      }
    }
    if (victim == findings_.size()) {
      return Result<FindingId>::failure(
          Outcome::Exhausted, "finding registry is full of live findings; refusing to evict authority");
    }
    findings_.erase(findings_.begin() + static_cast<std::ptrdiff_t>(victim));
  }
  const FindingId id = finding.id;
  const auto position =
      std::lower_bound(findings_.begin(), findings_.end(), id,
                       [](const Finding& lhs, FindingId key) { return lhs.id < key; });
  findings_.insert(position, std::move(finding));
  return Result<FindingId>::ok(id);
}

Status FindingRegistry::update_state(FindingId id, FindingState state, FenceCause cause, Tick now,
                                     ReasonCode reason, std::string detail) {
  for (Finding& finding : findings_) {
    if (finding.id != id) {
      continue;
    }
    if (finding.is_terminal() && state != FindingState::Withdrawn) {
      return Status::failure(Outcome::Refused,
                             "a terminal finding cannot be moved to " +
                                 std::string(to_string(state)));
    }
    finding.state = state;
    if (cause != FenceCause::None) {
      finding.fence_cause = cause;
    }
    finding.updated_at = now;
    finding.explanation.add(reason, id.to_string(), std::move(detail));
    return Status::ok();
  }
  return Status::failure(Outcome::NotFound, "finding is not registered");
}

Status FindingRegistry::attach_plan(FindingId id, ContainmentPlanId plan, Tick now) {
  for (Finding& finding : findings_) {
    if (finding.id == id) {
      finding.plan = plan;
      finding.updated_at = now;
      return Status::ok();
    }
  }
  return Status::failure(Outcome::NotFound, "finding is not registered");
}

Status FindingRegistry::attach_intent(FindingId id, ContainmentIntentId intent, Tick now) {
  for (Finding& finding : findings_) {
    if (finding.id == id) {
      finding.intent = intent;
      finding.updated_at = now;
      return Status::ok();
    }
  }
  return Status::failure(Outcome::NotFound, "finding is not registered");
}

const Finding* FindingRegistry::find(FindingId id) const noexcept {
  for (const Finding& finding : findings_) {
    if (finding.id == id) {
      return &finding;
    }
  }
  return nullptr;
}

std::size_t FindingRegistry::count(FindingState state) const noexcept {
  std::size_t total = 0;
  for (const Finding& finding : findings_) {
    if (finding.state == state) {
      ++total;
    }
  }
  return total;
}

std::size_t FindingRegistry::live_count() const noexcept {
  std::size_t total = 0;
  for (const Finding& finding : findings_) {
    if (!finding.is_terminal()) {
      ++total;
    }
  }
  return total;
}

std::vector<FindingId> FindingRegistry::fence_stale(const FenceVector& current, Tick now) {
  std::vector<FindingId> fenced;
  for (Finding& finding : findings_) {
    if (finding.is_terminal()) {
      continue;
    }
    const FenceCause cause = fence_cause(finding.fence, current);
    if (cause == FenceCause::None) {
      continue;
    }
    finding.state = FindingState::Stale;
    finding.fence_cause = cause;
    finding.updated_at = now;
    finding.explanation.add(ReasonCode::FindingFencedByGenerationChange, finding.id.to_string(),
                            std::string("fenced by ") + std::string(to_string(cause)));
    fenced.push_back(finding.id);
  }
  std::sort(fenced.begin(), fenced.end());
  return fenced;
}

std::vector<FindingId> FindingRegistry::fence_restart(const FenceVector& current, Tick now) {
  (void)current;
  std::vector<FindingId> fenced;
  for (Finding& finding : findings_) {
    if (finding.is_terminal()) {
      continue;
    }
    finding.state = FindingState::Fenced;
    finding.fence_cause = FenceCause::BootAdvanced;
    finding.updated_at = now;
    finding.explanation.add(ReasonCode::FindingFencedByRestart, finding.id.to_string(),
                            "the process that produced this finding no longer exists");
    fenced.push_back(finding.id);
  }
  std::sort(fenced.begin(), fenced.end());
  return fenced;
}

std::vector<FindingId> FindingRegistry::fence_boot(const FenceVector& current, Tick now) {
  std::vector<FindingId> fenced;
  for (Finding& finding : findings_) {
    if (finding.fence.boot == current.boot && finding.fence.epoch == current.epoch) {
      continue;
    }
    finding.state = FindingState::Fenced;
    finding.fence_cause = FenceCause::BootAdvanced;
    finding.updated_at = now;
    finding.explanation.add(ReasonCode::FindingFencedByRestart, finding.id.to_string(),
                            "finding was produced under a different boot or coordinator epoch");
    fenced.push_back(finding.id);
  }
  std::sort(fenced.begin(), fenced.end());
  return fenced;
}

void FindingRegistry::clear() noexcept { findings_.clear(); }

Digest FindingRegistry::digest() const {
  Sha256 hasher;
  for (const Finding& finding : findings_) {
    const Digest content = finding.content_digest();
    hasher.update(content.bytes.data(), kDigestBytes);
  }
  return hasher.finish();
}

FindingSummary summarize(const Finding& finding) {
  FindingSummary summary;
  summary.id = finding.id;
  summary.generation = finding.generation;
  summary.state = finding.state;
  summary.fence_cause = finding.fence_cause;
  summary.assessment_outcome = finding.assessment_outcome;
  summary.assessment_flags = finding.assessment_flags;
  summary.witness_count = finding.witnesses.size();
  summary.implicated_resource_count = finding.implicated_resources.size();
  summary.content_digest = finding.content_digest();
  return summary;
}

std::string to_string(const FindingSummary& summary) {
  return "finding " + summary.id.to_string() + " state=" + std::string(to_string(summary.state)) +
         " outcome=" + std::string(to_string(summary.assessment_outcome)) +
         " witnesses=" + std::to_string(summary.witness_count) +
         " resources=" + std::to_string(summary.implicated_resource_count) +
         " containment=" + std::string(to_string(summary.containment_outcome)) +
         " targets=" + std::to_string(summary.target_count);
}

}  // namespace loop_guard
