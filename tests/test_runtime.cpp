#include <algorithm>

#include "fixtures.hpp"
#include "harness.hpp"
#include "loop_guard/runtime.hpp"
#include "procs.hpp"
#include "tool_common.hpp"

namespace {

using namespace lg_test;
using namespace loop_guard;

RuntimeConfig make_config(const std::string& store) {
  RuntimeConfig config;
  config.producer = ProducerId::from_value(9);
  config.store_path = store;
  config.origin = EvidenceOrigin::Real;
  return config;
}

void feed_ring(Runtime& runtime) {
  const TopologyDefinition installed = runtime.topology().value();
  const FenceVector fence = runtime.fence();
  for (const ForwardingEdge& edge : installed.edges()) {
    LG_CHECK(runtime
                 .submit_observation(lg_tool::synthetic_observation(
                                         installed, edge.id, EvidenceClass::Present, edge.id.value(),
                                         200, edge.id.value(), fence,
                                         ProducerKind::InProcessRuntime, EvidenceOrigin::Real),
                                     0)
                 .is_ok());
  }
}

}  // namespace

LG_TEST(runtime, lifecycle_from_definitions_to_verified_effect) {
  const std::string store = lg_test::scratch_path("runtime-lifecycle.lgstore");
  lg_test::remove_file(store);
  auto runtime = Runtime::open(make_config(store));
  LG_REQUIRE(runtime.has_value());

  LG_CHECK(runtime.value().set_topology(lg_tool::synthetic_ring(3, 1), 0).is_ok());
  LG_CHECK(runtime.value().set_policy(lg_tool::synthetic_policy(1), 0).is_ok());
  feed_ring(runtime.value());

  auto assessment = runtime.value().detect(100);
  LG_REQUIRE(assessment.has_value());
  LG_CHECK_EQ(assessment.value().outcome, LoopOutcome::LoopConfirmed);
  LG_CHECK(assessment.value().origin == EvidenceOrigin::Real);

  auto finding = runtime.value().publish_finding(assessment.value(), 100);
  LG_REQUIRE(finding.has_value());
  LG_CHECK(finding.value().state == FindingState::Confirmed);

  auto plan = runtime.value().plan_containment(assessment.value(), 100);
  LG_REQUIRE(plan.has_value());
  LG_CHECK_EQ(plan.value().outcome, ContainmentOutcome::PlanOptimal);

  ContainmentGrant grant;
  grant.policy_generation = runtime.value().fence().policy;
  grant.fence = runtime.value().fence();
  grant.scope = plan.value().target_resources();
  grant.max_targets = 2;
  grant.max_total_cost = 16;
  grant.expires_at = 1000;
  grant.issued_by = runtime.value().identity().producer;
  auto intent = runtime.value().authorize_containment(finding.value().id, grant, 100, 500);
  LG_REQUIRE(intent.has_value());
  LG_CHECK(!intent.value().targets.empty());

  ContainmentAcknowledgement ack;
  ack.intent = intent.value().id;
  ack.session = SessionId::from_value(1);
  ack.applier = runtime.value().identity();
  ack.sequence = ProducerSequence::from_value(1);
  ack.acknowledged_at = 200;
  ack.intent_digest = intent.value().content_digest();
  LG_CHECK(runtime.value().record_acknowledgement(ack, 200).is_ok());
  const auto after_ack = runtime.value().find_finding(finding.value().id);
  LG_REQUIRE(after_ack.has_value());
  LG_CHECK(after_ack.value().state == FindingState::ContainmentAppliedUnverified);

  for (const ResourceId target : intent.value().targets) {
    VerifiedEffect effect;
    effect.target = target;
    effect.observation = ObservationId::from_value(5000 + target.value());
    effect.fence = runtime.value().fence();
    effect.verified_at = 300;
    effect.origin = EvidenceOrigin::Real;
    LG_CHECK(runtime.value().record_verified_effect(intent.value().id, effect, 300).is_ok());
  }
  const auto verified = runtime.value().find_finding(finding.value().id);
  LG_REQUIRE(verified.has_value());
  LG_CHECK(verified.value().state == FindingState::ContainmentVerified);

  VerifiedEffect duplicate;
  duplicate.target = intent.value().targets.front();
  duplicate.observation = ObservationId::from_value(9999);
  duplicate.fence = runtime.value().fence();
  LG_CHECK_EQ(runtime.value().record_verified_effect(intent.value().id, duplicate, 400).outcome(),
              Outcome::AlreadyExists);

  LG_CHECK(runtime.value()
               .withdraw_finding(finding.value().id, ReasonCode::FindingWithdrawn, 500)
               .is_ok());
  const auto withdrawn = runtime.value().find_finding(finding.value().id);
  LG_REQUIRE(withdrawn.has_value());
  LG_CHECK(withdrawn.value().state == FindingState::Withdrawn);
  LG_CHECK(!runtime.value().lineage().empty());
  LG_CHECK(runtime.value().close(true).is_ok());
  lg_test::remove_file(store);
}

LG_TEST(runtime, non_affirmative_assessments_never_become_findings) {
  const std::string store = lg_test::scratch_path("runtime-refuse.lgstore");
  lg_test::remove_file(store);
  auto runtime = Runtime::open(make_config(store));
  LG_REQUIRE(runtime.has_value());
  LG_CHECK(runtime.value().set_topology(lg_tool::synthetic_ring(3, 1), 0).is_ok());
  LG_CHECK(runtime.value().set_policy(lg_tool::synthetic_policy(1), 0).is_ok());
  auto assessment = runtime.value().detect(100);
  LG_REQUIRE(assessment.has_value());
  LG_REQUIRE(assessment.value().outcome == LoopOutcome::Unknown);
  const auto finding = runtime.value().publish_finding(assessment.value(), 100);
  LG_CHECK(!finding.has_value());
  LG_CHECK_EQ(finding.outcome(), Outcome::Refused);
  LG_CHECK_EQ(runtime.value().findings().size(), std::size_t{0});
  LG_CHECK_EQ(runtime.value().counters().findings_refused, std::uint64_t{1});
  LG_CHECK(runtime.value().close(true).is_ok());
  lg_test::remove_file(store);
}

LG_TEST(runtime, generation_change_fences_findings_immediately) {
  const std::string store = lg_test::scratch_path("runtime-fence.lgstore");
  lg_test::remove_file(store);
  auto runtime = Runtime::open(make_config(store));
  LG_REQUIRE(runtime.has_value());
  LG_CHECK(runtime.value().set_topology(lg_tool::synthetic_ring(3, 1), 0).is_ok());
  LG_CHECK(runtime.value().set_policy(lg_tool::synthetic_policy(1), 0).is_ok());
  feed_ring(runtime.value());
  auto assessment = runtime.value().detect(100);
  LG_REQUIRE(assessment.has_value());
  auto finding = runtime.value().publish_finding(assessment.value(), 100);
  LG_REQUIRE(finding.has_value());
  LG_CHECK(runtime.value().advance_forwarding(ForwardingGeneration::from_value(2), 200).is_ok());
  const auto fenced = runtime.value().find_finding(finding.value().id);
  LG_REQUIRE(fenced.has_value());
  LG_CHECK(fenced.value().state == FindingState::Stale);
  LG_CHECK(fenced.value().fence_cause == FenceCause::ForwardingGenerationAdvanced);
  ContainmentGrant grant;
  grant.policy_generation = runtime.value().fence().policy;
  grant.fence = runtime.value().fence();
  grant.scope = {ResourceId::from_value(1)};
  grant.max_targets = 1;
  grant.max_total_cost = 4;
  grant.expires_at = 1000;
  const auto refused = runtime.value().authorize_containment(finding.value().id, grant, 300, 100);
  LG_CHECK(!refused.has_value());
  LG_CHECK(refused.outcome() == Outcome::Fenced || refused.outcome() == Outcome::Refused);
  LG_CHECK(runtime.value().close(true).is_ok());
  lg_test::remove_file(store);
}

LG_TEST(runtime, restart_does_not_restore_dynamic_state) {
  const std::string store = lg_test::scratch_path("runtime-restart.lgstore");
  lg_test::remove_file(store);
  FindingId published;
  BootId first_boot;
  {
    auto runtime = Runtime::open(make_config(store));
    LG_REQUIRE(runtime.has_value());
    first_boot = runtime.value().identity().boot;
    LG_CHECK(runtime.value().set_topology(lg_tool::synthetic_ring(3, 1), 0).is_ok());
    LG_CHECK(runtime.value().set_policy(lg_tool::synthetic_policy(1), 0).is_ok());
    feed_ring(runtime.value());
    auto assessment = runtime.value().detect(100);
    LG_REQUIRE(assessment.has_value());
    auto finding = runtime.value().publish_finding(assessment.value(), 100);
    LG_REQUIRE(finding.has_value());
    published = finding.value().id;
    LG_CHECK(runtime.value().close(false).is_ok());
  }
  {
    auto runtime = Runtime::open(make_config(store));
    LG_REQUIRE(runtime.has_value());
    LG_CHECK(runtime.value().identity().boot > first_boot);
    LG_CHECK_EQ(runtime.value().observation_count(), std::size_t{0});
    auto restored = runtime.value().find_finding(published);
    LG_REQUIRE(restored.has_value());
    LG_CHECK(restored.value().state == FindingState::Fenced);
    LG_CHECK(runtime.value().topology().has_value());
    auto assessment = runtime.value().detect(200);
    LG_REQUIRE(assessment.has_value());
    LG_CHECK(assessment.value().outcome != LoopOutcome::LoopConfirmed);
    LG_CHECK(runtime.value().close(true).is_ok());
  }
  lg_test::remove_file(store);
}

LG_TEST(runtime, observer_callbacks_run_outside_the_lock) {
  const std::string store = lg_test::scratch_path("runtime-observer.lgstore");
  lg_test::remove_file(store);
  auto runtime = Runtime::open(make_config(store));
  LG_REQUIRE(runtime.has_value());
  LG_CHECK(runtime.value().set_topology(lg_tool::synthetic_ring(3, 1), 0).is_ok());
  LG_CHECK(runtime.value().set_policy(lg_tool::synthetic_policy(1), 0).is_ok());
  feed_ring(runtime.value());
  // The observer re-enters the runtime. This deadlocks if the callback runs under the
  // runtime mutex, which is exactly what the ownership audit forbids.
  std::uint64_t observed = 0;
  runtime.value().set_finding_observer([&runtime, &observed](const Finding& finding) {
    ++observed;
    (void)runtime.value().find_finding(finding.id);
    (void)runtime.value().findings();
    (void)runtime.value().state_digest();
  });
  auto assessment = runtime.value().detect(100);
  LG_REQUIRE(assessment.has_value());
  const auto finding = runtime.value().publish_finding(assessment.value(), 100);
  LG_REQUIRE(finding.has_value());
  LG_CHECK_EQ(observed, std::uint64_t{1});
  LG_CHECK(runtime.value().close(true).is_ok());
  lg_test::remove_file(store);
}
