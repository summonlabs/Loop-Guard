#include "loop_guard/authority.hpp"

#include <algorithm>
#include <set>

namespace loop_guard {
namespace {

void hash_u64(Sha256& hasher, std::uint64_t value) {
  hasher.update(
      std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(&value), sizeof(value)));
}

void hash_fence(Sha256& hasher, const FenceVector& fence) {
  hash_u64(hasher, fence.topology.value());
  hash_u64(hasher, fence.forwarding.value());
  hash_u64(hasher, fence.policy.value());
  hash_u64(hasher, fence.fabric_epoch.value());
  hash_u64(hasher, fence.epoch.value());
  hash_u64(hasher, fence.boot.value());
}

void hash_identity(Sha256& hasher, const ProcessIdentity& identity) {
  hash_u64(hasher, identity.producer.value());
  hash_u64(hasher, identity.boot.value());
  hash_u64(hasher, identity.incarnation.value());
  hash_u64(hasher, identity.epoch.value());
}

}  // namespace

Digest ContainmentGrant::content_digest() const {
  Sha256 hasher;
  hash_u64(hasher, id.value());
  hash_u64(hasher, policy_generation.value());
  hash_fence(hasher, fence);
  for (const ResourceId resource : scope) {
    hash_u64(hasher, resource.value());
  }
  hasher.update(static_cast<std::uint8_t>(0xF7));
  hash_u64(hasher, max_targets);
  hash_u64(hasher, max_total_cost);
  hash_u64(hasher, issued_at);
  hash_u64(hasher, expires_at);
  hash_u64(hasher, issued_by.value());
  hasher.update(static_cast<std::uint8_t>(state));
  return hasher.finish();
}

FenceCause ContainmentGrant::fence_cause_if_not_current(const FenceVector& current) const noexcept {
  return fence_cause(fence, current);
}

bool ContainmentGrant::is_active(const FenceVector& current, Tick now) const noexcept {
  if (state != GrantState::Active) {
    return false;
  }
  if (!(fence == current)) {
    return false;
  }
  return now <= expires_at;
}

Status ContainmentGrant::authorize(const std::vector<ResourceId>& targets, std::uint64_t total_cost,
                                   const FenceVector& current, Tick now) const {
  if (state != GrantState::Active) {
    return Status::failure(Outcome::Refused,
                           std::string("grant is not active: ") + std::string(to_string(state)));
  }
  const FenceCause cause = fence_cause(fence, current);
  if (cause != FenceCause::None) {
    return Status::failure(Outcome::Fenced,
                           std::string("grant is fenced by ") + std::string(to_string(cause)));
  }
  if (now > expires_at) {
    return Status::failure(Outcome::Stale, "grant has expired");
  }
  if (targets.empty()) {
    return Status::failure(Outcome::Refused, "a grant cannot authorize an empty target set");
  }
  if (targets.size() > max_targets) {
    return Status::failure(Outcome::Refused, "target count exceeds the grant's budget");
  }
  if (total_cost > max_total_cost) {
    return Status::failure(Outcome::Refused, "target cost exceeds the grant's budget");
  }
  for (const ResourceId target : targets) {
    if (!std::binary_search(scope.begin(), scope.end(), target)) {
      return Status::failure(Outcome::Refused,
                             "target " + target.to_string() + " is outside the grant's scope");
    }
  }
  return Status::ok();
}

std::vector<ResourceId> ContainmentApplication::verified_targets() const {
  std::vector<ResourceId> verified;
  for (const VerifiedEffect& effect : effects) {
    if (!targets.empty() && !std::binary_search(targets.begin(), targets.end(), effect.target)) {
      continue;
    }
    verified.push_back(effect.target);
  }
  std::sort(verified.begin(), verified.end());
  verified.erase(std::unique(verified.begin(), verified.end()), verified.end());
  return verified;
}

std::vector<ResourceId> ContainmentApplication::unverified_targets() const {
  const std::vector<ResourceId> verified = verified_targets();
  std::vector<ResourceId> missing;
  for (const ResourceId target : targets) {
    if (!std::binary_search(verified.begin(), verified.end(), target)) {
      missing.push_back(target);
    }
  }
  return missing;
}

bool ContainmentApplication::fully_verified() const {
  if (targets.empty()) {
    return false;
  }
  return unverified_targets().empty();
}

Digest ContainmentApplication::content_digest() const {
  Sha256 hasher;
  hash_u64(hasher, intent.value());
  hash_u64(hasher, plan.value());
  hash_u64(hasher, finding.value());
  hash_fence(hasher, fence);
  hash_identity(hasher, applier);
  for (const ContainmentAcknowledgement& ack : acknowledgements) {
    hash_u64(hasher, ack.intent.value());
    hash_u64(hasher, ack.session.value());
    hash_identity(hasher, ack.applier);
    hash_u64(hasher, ack.sequence.value());
    hash_u64(hasher, ack.acknowledged_at);
    hasher.update(ack.intent_digest.bytes.data(), kDigestBytes);
  }
  hasher.update(static_cast<std::uint8_t>(0xF6));
  for (const VerifiedEffect& effect : effects) {
    hash_u64(hasher, effect.target.value());
    hash_u64(hasher, effect.observation.value());
    hash_fence(hasher, effect.fence);
    hash_u64(hasher, effect.verified_at);
    hasher.update(static_cast<std::uint8_t>(effect.origin));
  }
  hasher.update(static_cast<std::uint8_t>(0xF6));
  return hasher.finish();
}

Digest LineageRecord::content_digest() const {
  Sha256 hasher;
  hash_u64(hasher, id.value());
  hash_u64(hasher, sequence.value());
  hash_u64(hasher, recorded_at);
  hasher.update(static_cast<std::uint8_t>(kind));
  hash_u64(hasher, finding.value());
  hash_u64(hasher, plan.value());
  hash_u64(hasher, intent.value());
  hash_fence(hasher, fence);
  hasher.update(subject_digest.bytes.data(), kDigestBytes);
  hasher.update(static_cast<std::uint8_t>(reason));
  hasher.update(static_cast<std::uint8_t>(severity));
  return hasher.finish();
}

std::string LineageRecord::to_text() const {
  return "lineage #" + sequence.to_string() + " " + std::string(to_string(kind)) +
         " finding=" + finding.to_string() + " plan=" + plan.to_string() +
         " intent=" + intent.to_string() + " fence=" + fence.to_string() +
         " reason=" + std::string(to_string(reason)) +
         " severity=" + std::string(to_string(severity));
}

}  // namespace loop_guard
