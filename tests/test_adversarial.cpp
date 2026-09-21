#include <algorithm>
#include <set>

#include "fixtures.hpp"
#include "harness.hpp"
#include "loop_guard/persistence.hpp"
#include "loop_guard/runtime.hpp"
#include "loop_guard/wire.hpp"
#include "procs.hpp"
#include "tool_common.hpp"

namespace {

using namespace lg_test;
using namespace loop_guard;

}  // namespace

LG_TEST(adversarial, contradictory_evidence_from_two_authorities_is_conflict) {
  RingScenario ring = make_ring(3);
  Scenario& scenario = ring.scenario;
  const TrafficSelectorId selector = scenario.selector_id(0);
  for (const ForwardingEdgeId edge : ring.edges) {
    (void)scenario.observe_present(edge, {selector});
  }
  // A second authority contradicts one hop at the same generations.
  (void)scenario.observe(ring.edges[1], EvidenceClass::Absent, {}, TopologyGeneration{},
                         ForwardingGeneration{}, 0, 1000000, BootId{}, CoordinatorEpoch{},
                         FabricEpoch{}, ProducerId::from_value(9999));
  const auto assessment = scenario.assess();
  LG_REQUIRE(assessment.has_value());
  LG_CHECK_EQ(assessment.value().outcome, LoopOutcome::Conflict);
  LG_CHECK(assessment.value().witnesses.empty());
}

LG_TEST(adversarial, huge_counts_in_a_payload_are_refused_before_allocation) {
  const Limits limits = default_limits();
  // A topology payload that claims a huge resource count.
  std::vector<std::uint8_t> payload;
  ByteWriter writer;
  writer.u16(1U);
  writer.u64(1U);
  writer.u32(0U);            // selectors
  writer.u32(0xFFFF'FFF0U);  // resources
  payload = std::move(writer).take();
  const auto decoded = decode_topology(payload, limits);
  LG_CHECK(!decoded.has_value());
  LG_CHECK(decoded.outcome() == Outcome::Exhausted || decoded.outcome() == Outcome::Invalid);

  // A hello payload whose producer kind is out of domain must be refused.
  std::vector<std::uint8_t> hello;
  ByteWriter hello_writer;
  hello_writer.u16(1U);
  hello_writer.u64(1U);
  hello_writer.u64(1U);
  hello_writer.u64(1U);
  hello_writer.u64(1U);
  hello_writer.u64(1U);
  hello_writer.u8(0xF0U);
  hello_writer.u8(0U);
  hello_writer.u64(0U);
  hello_writer.u64(0U);
  hello = std::move(hello_writer).take();
  const auto hello_decoded = decode_hello(hello, limits);
  LG_CHECK(!hello_decoded.has_value());

  // A hello payload truncated inside its identity must be refused, not partially read.
  std::vector<std::uint8_t> truncated(hello.begin(), hello.end() - 5);
  LG_CHECK(!decode_hello(truncated, limits).has_value());
}

LG_TEST(adversarial, duplicate_and_late_completions_are_refused) {
  const std::string store = lg_test::scratch_path("adversarial-late.lgstore");
  lg_test::remove_file(store);
  RuntimeConfig config;
  config.producer = ProducerId::from_value(41);
  config.store_path = store;
  config.origin = EvidenceOrigin::Real;
  auto runtime = Runtime::open(config);
  LG_REQUIRE(runtime.has_value());
  LG_CHECK(runtime.value().set_topology(lg_tool::synthetic_ring(3, 1), 0).is_ok());
  LG_CHECK(runtime.value().set_policy(lg_tool::synthetic_policy(1), 0).is_ok());
  const TopologyDefinition installed = runtime.value().topology().value();
  const FenceVector fence = runtime.value().fence();
  for (const ForwardingEdge& edge : installed.edges()) {
    const ForwardingObservation observation = lg_tool::synthetic_observation(
        installed, edge.id, EvidenceClass::Present, edge.id.value(), 300, edge.id.value(), fence,
        ProducerKind::InProcessRuntime, EvidenceOrigin::Real);
    LG_CHECK(runtime.value().submit_observation(observation, 0).is_ok());
    // A duplicate of the same completion is refused, never counted twice.
    LG_CHECK_EQ(runtime.value().submit_observation(observation, 0).outcome(),
                Outcome::AlreadyExists);
  }
  auto assessment = runtime.value().detect(100);
  LG_REQUIRE(assessment.has_value());
  auto finding = runtime.value().publish_finding(assessment.value(), 100);
  LG_REQUIRE(finding.has_value());
  auto plan = runtime.value().plan_containment(assessment.value(), 100);
  LG_REQUIRE(plan.has_value());

  ContainmentGrant grant;
  grant.policy_generation = runtime.value().fence().policy;
  grant.fence = runtime.value().fence();
  grant.scope = plan.value().target_resources();
  grant.max_targets = 4;
  grant.max_total_cost = 64;
  grant.expires_at = 1000;
  auto intent = runtime.value().authorize_containment(finding.value().id, grant, 100, 500);
  LG_REQUIRE(intent.has_value());

  // A late completion arriving after the fence moved must be refused, not applied.
  LG_CHECK(runtime.value().advance_forwarding(ForwardingGeneration::from_value(2), 200).is_ok());
  VerifiedEffect late;
  late.target = intent.value().targets.front();
  late.observation = ObservationId::from_value(77);
  late.fence = intent.value().fence;
  const Status late_status = runtime.value().record_verified_effect(intent.value().id, late, 250);
  LG_CHECK(!late_status.is_ok());
  LG_CHECK(late_status.outcome() == Outcome::Fenced || late_status.outcome() == Outcome::Stale);
  const auto finding_after = runtime.value().find_finding(finding.value().id);
  LG_REQUIRE(finding_after.has_value());
  LG_CHECK(finding_after.value().state != FindingState::ContainmentVerified);
  LG_CHECK(runtime.value().close(true).is_ok());
  lg_test::remove_file(store);
}

LG_TEST(adversarial, restart_at_every_durable_boundary_is_conservative) {
  const std::string path = lg_test::scratch_path("adversarial-boundary.lgstore");
  const Limits limits = default_limits();
  for (int boundary = 0; boundary < 6; ++boundary) {
    lg_test::remove_file(path);
    {
      auto store = DurableStore::open_or_create(path, limits, ProducerId::from_value(1));
      LG_REQUIRE(store.has_value());
      if (boundary >= 1) {
        LG_CHECK(store.value().set_topology(lg_tool::synthetic_ring(3, 1)).is_ok());
      }
      if (boundary >= 2) {
        LG_CHECK(store.value().set_policy(lg_tool::synthetic_policy(1)).is_ok());
      }
      if (boundary >= 3) {
        LineageRecord record;
        record.sequence = AttemptSequence::from_value(1);
        record.id = LineageRecordId::from_value(1);
        record.kind = AuthorityKind::Observation;
        record.fence = store.value().state().committed_fence;
        LG_CHECK(store.value().append_lineage(record).is_ok());
      }
      if (boundary >= 4) {
        Finding finding;
        finding.id = FindingId::from_value(1);
        finding.generation = FindingGeneration::from_value(1);
        finding.fence = store.value().state().committed_fence;
        finding.state = FindingState::Confirmed;
        finding.assessment_outcome = LoopOutcome::LoopConfirmed;
        LG_CHECK(store.value().upsert_finding(finding).is_ok());
      }
      if (boundary >= 5) {
        // An unclean stop right after the last commit: no close() call.
      } else {
        LG_CHECK(store.value().close(true).is_ok());
      }
    }
    auto reopened = DurableStore::open_or_create(path, limits, ProducerId::from_value(1));
    LG_REQUIRE(reopened.has_value());
    const StoreState& state = reopened.value().state();
    LG_CHECK_EQ(state.topology.has_value(), boundary >= 1);
    LG_CHECK_EQ(state.policy.has_value(), boundary >= 2);
    LG_CHECK_EQ(state.lineage.size(), boundary >= 3 ? std::size_t{1} : std::size_t{0});
    LG_CHECK_EQ(state.findings.size(), boundary >= 4 ? std::size_t{1} : std::size_t{0});
    LG_CHECK_EQ(reopened.value().identity().boot, BootId::from_value(2));
    LG_CHECK(reopened.value().close(true).is_ok());
  }
  lg_test::remove_file(path);
}

LG_TEST(adversarial, canonical_documents_survive_byte_level_fuzzing) {
  const Limits limits = default_limits();
  RingScenario ring = make_ring(3, 1);
  const std::vector<std::uint8_t> document =
      encode_topology(ring.scenario.topology(), limits);
  Rng rng(20260101U);
  std::size_t decoded_count = 0;
  for (std::size_t round = 0; round < 2000; ++round) {
    std::vector<std::uint8_t> mutated = document;
    const std::size_t flips = 1U + static_cast<std::size_t>(rng.next_below(3));
    for (std::size_t flip = 0; flip < flips; ++flip) {
      const std::size_t offset = static_cast<std::size_t>(rng.next_below(mutated.size()));
      mutated[offset] ^= static_cast<std::uint8_t>(1U + rng.next_below(255));
    }
    const auto decoded = decode_topology(mutated, limits);
    if (decoded.has_value()) {
      ++decoded_count;
      // A mutation that still decodes must produce a self-consistent definition, and
      // re-canonicalising it must be idempotent.
      const auto recanonicalized = canonicalize_topology(decoded.value(), limits);
      if (recanonicalized.has_value()) {
        LG_CHECK_EQ(recanonicalized.value().digest(), decoded.value().digest());
      } else {
        LG_CHECK(!recanonicalized.detail().empty());
      }
      // Whatever survives mutation must still be a structurally complete definition.
      LG_CHECK_EQ(decoded.value().edges().size(), ring.scenario.topology().edges().size());
    }
  }
  // Some mutations land on label bytes and are legitimately still decodable; the
  // invariant is that nothing crashes, nothing hangs, and every accepted document is
  // structurally valid.
  LG_CHECK(decoded_count <= 2000U);
}

LG_TEST(adversarial, bounded_explanation_documents_never_grow_without_limit) {
  Explanation explanation(4);
  for (std::uint32_t index = 0; index < 1000; ++index) {
    (void)explanation.add(ReasonCode::LimitsExceeded, "subject" + std::to_string(index),
                          std::string(4096, 'x'));
  }
  LG_CHECK_EQ(explanation.reasons().size(), std::size_t{4});
  LG_CHECK_EQ(explanation.dropped(), std::uint32_t{996});
  for (const ExplanationReason& reason : explanation.reasons()) {
    LG_CHECK(reason.detail.size() <= 192U + 3U);
  }
  LG_CHECK(explanation.to_text().size() < 4096U);
}

LG_TEST(adversarial, hostile_selector_scope_and_fence_are_refused) {
  RingScenario ring = make_ring(3);
  Scenario& scenario = ring.scenario;
  DetectionRequest request;
  request.topology = &scenario.topology();
  request.ledger = &scenario.ledger();
  request.fence = scenario.fence();
  request.now = 10;
  request.selector_scope = {TrafficSelectorId::from_value(5), TrafficSelectorId::from_value(5)};
  const LoopDetector detector;
  const auto assessment = detector.assess(request);
  LG_REQUIRE(assessment.has_value());
  LG_CHECK_EQ(assessment.value().outcome, LoopOutcome::Invalid);

  DetectionRequest unsigned_request;
  unsigned_request.topology = &scenario.topology();
  unsigned_request.ledger = &scenario.ledger();
  unsigned_request.now = 10;
  const auto unsigned_assessment = detector.assess(unsigned_request);
  LG_REQUIRE(unsigned_assessment.has_value());
  LG_CHECK_EQ(unsigned_assessment.value().outcome, LoopOutcome::Invalid);

  const auto missing = detector.assess(DetectionRequest{});
  LG_CHECK(!missing.has_value());
  LG_CHECK_EQ(missing.outcome(), Outcome::Invalid);
}
