#include <algorithm>
#include <set>

#include "fixtures.hpp"
#include "harness.hpp"
#include "loop_guard/persistence.hpp"

namespace {

using namespace lg_test;
using namespace loop_guard;

Limits small_limits() {
  Limits limits = default_limits();
  limits.max_journal_records = 64;
  limits.max_journal_bytes = 1U << 20U;
  limits.max_retained_lineage = 32;
  limits.max_retained_findings = 16;
  return limits;
}

TopologyDefinition sample_topology(TopologyGeneration generation) {
  TopologyBuilder builder;
  builder.set_generation(generation);
  TrafficSelector selector;
  selector.id = TrafficSelectorId::from_value(1);
  (void)builder.add_selector(selector);
  for (std::uint64_t id = 1; id <= 3; ++id) {
    ResourceRecord record;
    record.id = ResourceId::from_value(id);
    record.domain = DomainId::from_value(1);
    record.kind = ResourceKind::Switch;
    record.admin = AdministrativeState::Enabled;
    record.containable = true;
    record.containment_cost = 1;
    (void)builder.add_resource(record);
  }
  for (std::uint64_t id = 1; id <= 3; ++id) {
    ForwardingEdge edge;
    edge.id = ForwardingEdgeId::from_value(id);
    edge.from = ResourceId::from_value(id);
    edge.to = ResourceId::from_value((id % 3U) + 1U);
    edge.domain = DomainId::from_value(1);
    edge.link = LinkState::Up;
    edge.admitted_selectors = {TrafficSelectorId::from_value(1)};
    (void)builder.add_edge(edge);
  }
  return builder.build().value();
}

Finding sample_finding(FindingGeneration generation, const FenceVector& fence) {
  Finding finding;
  finding.generation = generation;
  finding.assessment = AssessmentId::from_value(generation.value());
  finding.assessment_digest = sha256(std::string("assessment-") + generation.to_string());
  finding.fence = fence;
  finding.state = FindingState::Confirmed;
  finding.assessment_outcome = LoopOutcome::LoopConfirmed;
  finding.witnesses = {WitnessId::from_value(generation.value())};
  finding.implicated_resources = {ResourceId::from_value(1), ResourceId::from_value(2),
                                  ResourceId::from_value(3)};
  finding.implicated_selectors = {TrafficSelectorId::from_value(1)};
  finding.created_at = generation.value() * 10U;
  finding.updated_at = finding.created_at;
  finding.origin = EvidenceOrigin::Real;
  finding.explanation = Explanation(8);
  finding.explanation.add(ReasonCode::WitnessSuccessfullyValidated, "test", "synthetic");
  finding.id = content_addressed_id<FindingId>(finding.content_digest());
  return finding;
}

LineageRecord sample_lineage(AttemptSequence sequence, const FenceVector& fence) {
  LineageRecord record;
  record.sequence = sequence;
  record.id = LineageRecordId::from_value(sequence.value());
  record.recorded_at = sequence.value();
  record.kind = AuthorityKind::Authorization;
  record.fence = fence;
  record.subject_digest = sha256(std::string("subjects") + sequence.to_string());
  record.reason = ReasonCode::RequestAccepted;
  record.severity = Severity::Notice;
  return record;
}

}  // namespace

LG_TEST(persistence, create_append_reopen_preserves_definitions_not_dynamics) {
  const std::string path = scratch_path("persistence-basic.lgstore");
  remove_scratch(path);
  const Limits limits = small_limits();
  const ProducerId producer = ProducerId::from_value(77);

  BootId first_boot;
  IncarnationId first_incarnation;
  {
    auto store = DurableStore::open_or_create(path, limits, producer);
    LG_REQUIRE(store.has_value());
    LG_CHECK_EQ(store.value().recovery().outcome, Outcome::Ok);
    first_boot = store.value().identity().boot;
    first_incarnation = store.value().identity().incarnation;
    LG_CHECK_EQ(first_boot, BootId::from_value(1));
    LG_CHECK(store.value().set_topology(sample_topology(TopologyGeneration::from_value(1))).is_ok());
    ContainmentPolicy policy;
    policy.generation = PolicyGeneration::from_value(1);
    policy.eligible_kinds = {ResourceKind::Switch};
    LG_CHECK(store.value().set_policy(policy).is_ok());
    LG_CHECK(store.value().append_lineage(sample_lineage(AttemptSequence::from_value(1),
                                                         store.value().state().committed_fence))
                  .is_ok());
    LG_CHECK(store.value().upsert_finding(
                  sample_finding(FindingGeneration::from_value(1),
                                 store.value().state().committed_fence))
                  .is_ok());
    LG_CHECK(store.value().close(true).is_ok());
  }

  {
    auto store = DurableStore::open_or_create(path, limits, producer);
    if (!store.has_value()) {
      LG_CHECK_EQ(std::string(to_string(store.outcome())) + " " + store.detail(), std::string(""));
    }
    LG_REQUIRE(store.has_value());
    const StoreState& state = store.value().state();
    LG_REQUIRE(state.topology.has_value());
    LG_CHECK_EQ(state.topology->generation(), TopologyGeneration::from_value(1));
    LG_REQUIRE(state.policy.has_value());
    LG_CHECK_EQ(state.policy->generation, PolicyGeneration::from_value(1));
    LG_CHECK_EQ(state.lineage.size(), std::size_t{1});
    LG_CHECK_EQ(state.findings.size(), std::size_t{1});
    LG_CHECK(store.value().identity().boot > first_boot);
    LG_CHECK(store.value().identity().incarnation > first_incarnation);
    // The previous boot is recorded as cleanly shut down.
    bool clean = false;
    for (const BootRecord& record : state.boot_ledger) {
      if (record.boot == first_boot) {
        clean = record.clean_shutdown;
      }
    }
    LG_CHECK(clean);
    LG_CHECK(store.value().close(true).is_ok());
  }
  remove_scratch(path);
}

LG_TEST(persistence, unclean_shutdown_is_detectable) {
  const std::string path = scratch_path("persistence-unclean.lgstore");
  remove_scratch(path);
  const Limits limits = small_limits();
  const ProducerId producer = ProducerId::from_value(8);
  {
    auto store = DurableStore::open_or_create(path, limits, producer);
    LG_REQUIRE(store.has_value());
    // No close(): the process is gone.
  }
  auto reopened = DurableStore::open_or_create(path, limits, producer);
  LG_REQUIRE(reopened.has_value());
  LG_CHECK(reopened.value().identity().boot == BootId::from_value(2));
  bool found = false;
  for (const ExplanationReason& reason : reopened.value().recovery().explanation.reasons()) {
    if (reason.code == ReasonCode::FindingFencedByRestart) {
      found = true;
    }
  }
  LG_CHECK(found);
  LG_CHECK(reopened.value().close(true).is_ok());
  remove_scratch(path);
}

LG_TEST(persistence, generation_regression_is_refused) {
  const std::string path = scratch_path("persistence-regression.lgstore");
  remove_scratch(path);
  const Limits limits = small_limits();
  auto store = DurableStore::open_or_create(path, limits, ProducerId::from_value(5));
  LG_REQUIRE(store.has_value());
  LG_CHECK(store.value().set_topology(sample_topology(TopologyGeneration::from_value(2))).is_ok());
  LG_CHECK_EQ(store.value()
                  .set_topology(sample_topology(TopologyGeneration::from_value(2)))
                  .outcome(),
              Outcome::Stale);
  LG_CHECK_EQ(store.value()
                  .set_topology(sample_topology(TopologyGeneration::from_value(1)))
                  .outcome(),
              Outcome::Stale);
  LG_CHECK(store.value().set_topology(sample_topology(TopologyGeneration::from_value(3))).is_ok());
  LG_CHECK(store.value().close(true).is_ok());
  remove_scratch(path);
}

LG_TEST(persistence, lineage_sequence_regression_is_refused) {
  const std::string path = scratch_path("persistence-lineage.lgstore");
  remove_scratch(path);
  const Limits limits = small_limits();
  auto store = DurableStore::open_or_create(path, limits, ProducerId::from_value(5));
  LG_REQUIRE(store.has_value());
  const FenceVector fence = store.value().state().committed_fence;
  LG_CHECK(store.value().append_lineage(sample_lineage(AttemptSequence::from_value(2), fence)).is_ok());
  LG_CHECK_EQ(store.value()
                  .append_lineage(sample_lineage(AttemptSequence::from_value(2), fence))
                  .outcome(),
              Outcome::Stale);
  LG_CHECK_EQ(store.value()
                  .append_lineage(sample_lineage(AttemptSequence::from_value(1), fence))
                  .outcome(),
              Outcome::Stale);
  LG_CHECK(store.value().append_lineage(sample_lineage(AttemptSequence::from_value(3), fence)).is_ok());
  LG_CHECK(store.value().close(true).is_ok());
  remove_scratch(path);
}

LG_TEST(persistence, compaction_preserves_state_and_advances_generation) {
  const std::string path = scratch_path("persistence-compact.lgstore");
  remove_scratch(path);
  Limits limits = small_limits();
  limits.max_journal_records = 4;
  auto store = DurableStore::open_or_create(path, limits, ProducerId::from_value(5));
  LG_REQUIRE(store.has_value());
  const std::uint32_t initial_generation = store.value().state().store_generation;
  for (std::uint64_t index = 1; index <= 12; ++index) {
    const Status status = store.value().append_lineage(
        sample_lineage(AttemptSequence::from_value(index), store.value().state().committed_fence));
    LG_REQUIRE(status.is_ok());
  }
  LG_CHECK(store.value().state().store_generation > initial_generation);
  LG_CHECK_EQ(store.value().state().lineage.size(), std::size_t{12});
  LG_CHECK(store.value().close(true).is_ok());

  auto reopened = DurableStore::open_or_create(path, limits, ProducerId::from_value(5));
  LG_REQUIRE(reopened.has_value());
  LG_CHECK_EQ(reopened.value().state().lineage.size(), std::size_t{12});
  LG_CHECK(reopened.value().close(true).is_ok());
  remove_scratch(path);
}

LG_TEST(persistence, corrupt_payload_is_refused) {
  const std::string path = scratch_path("persistence-corrupt.lgstore");
  remove_scratch(path);
  const Limits limits = small_limits();
  auto store = DurableStore::open_or_create(path, limits, ProducerId::from_value(5));
  LG_REQUIRE(store.has_value());
  LG_CHECK(store.value().append_lineage(sample_lineage(
                AttemptSequence::from_value(1), store.value().state().committed_fence))
                .is_ok());
  LG_CHECK(store.value().close(true).is_ok());

  std::vector<std::uint8_t> bytes = read_bytes(path);
  LG_REQUIRE(bytes.size() > 200U);
  // Flip one byte in the middle of the document.
  bytes[bytes.size() / 2U] ^= 0x40U;
  write_bytes(path, bytes);
  const auto reopened = DurableStore::open_or_create(path, limits, ProducerId::from_value(5));
  LG_CHECK(!reopened.has_value());
  LG_CHECK_EQ(reopened.outcome(), Outcome::IntegrityFailure);
  remove_scratch(path);
}

LG_TEST(persistence, torn_tail_is_recovered_but_only_a_genuine_prefix) {
  const std::string path = scratch_path("persistence-torn.lgstore");
  remove_scratch(path);
  const Limits limits = small_limits();
  auto store = DurableStore::open_or_create(path, limits, ProducerId::from_value(5));
  LG_REQUIRE(store.has_value());
  LG_CHECK(store.value().append_lineage(sample_lineage(
                AttemptSequence::from_value(1), store.value().state().committed_fence))
                .is_ok());
  LG_CHECK(store.value().close(true).is_ok());

  std::vector<std::uint8_t> bytes = read_bytes(path);
  LG_REQUIRE(bytes.size() > 100U);
  // Truncate inside the final record: a genuine torn tail.
  std::vector<std::uint8_t> torn(bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(bytes.size() - 40U));
  write_bytes(path, torn);
  auto recovered = DurableStore::open_or_create(path, limits, ProducerId::from_value(5));
  LG_REQUIRE(recovered.has_value());
  LG_CHECK(recovered.value().recovery().torn_tail_recovered);
  LG_CHECK(recovered.value().recovery().torn_tail_bytes > 0U);
  LG_CHECK(recovered.value().close(true).is_ok());
  remove_scratch(path);
}

LG_TEST(persistence, trailing_garbage_is_refused_not_truncated) {
  const std::string path = scratch_path("persistence-garbage.lgstore");
  remove_scratch(path);
  const Limits limits = small_limits();
  auto store = DurableStore::open_or_create(path, limits, ProducerId::from_value(5));
  LG_REQUIRE(store.has_value());
  LG_CHECK(store.value().close(true).is_ok());

  std::vector<std::uint8_t> bytes = read_bytes(path);
  bytes.push_back(0xDEU);
  bytes.push_back(0xADU);
  bytes.push_back(0xBEU);
  bytes.push_back(0xEFU);
  write_bytes(path, bytes);
  const auto reopened = DurableStore::open_or_create(path, limits, ProducerId::from_value(5));
  LG_CHECK(!reopened.has_value());
  LG_CHECK_EQ(reopened.outcome(), Outcome::IntegrityFailure);
  remove_scratch(path);
}

LG_TEST(persistence, unsupported_version_is_refused) {
  const std::string path = scratch_path("persistence-version.lgstore");
  remove_scratch(path);
  const Limits limits = small_limits();
  auto store = DurableStore::open_or_create(path, limits, ProducerId::from_value(5));
  LG_REQUIRE(store.has_value());
  LG_CHECK(store.value().close(true).is_ok());
  std::vector<std::uint8_t> bytes = read_bytes(path);
  LG_REQUIRE(bytes.size() > 8U);
  bytes[4] = 9U;
  write_bytes(path, bytes);
  const auto reopened = DurableStore::open_or_create(path, limits, ProducerId::from_value(5));
  LG_CHECK(!reopened.has_value());
  remove_scratch(path);
}

LG_TEST(persistence, store_state_codec_round_trips) {
  StoreState state;
  state.topology_generation = TopologyGeneration::from_value(3);
  state.topology = sample_topology(TopologyGeneration::from_value(3));
  ContainmentPolicy policy;
  policy.generation = PolicyGeneration::from_value(4);
  policy.eligible_kinds = {ResourceKind::Switch, ResourceKind::PortGroup};
  policy.eligible_domains = {DomainId::from_value(1)};
  state.policy = policy;
  state.committed_fence.topology = TopologyGeneration::from_value(3);
  state.committed_fence.forwarding = ForwardingGeneration::from_value(1);
  state.committed_fence.policy = PolicyGeneration::from_value(4);
  state.committed_fence.fabric_epoch = FabricEpoch::from_value(1);
  state.committed_fence.epoch = CoordinatorEpoch::from_value(1);
  state.committed_fence.boot = BootId::from_value(1);
  state.lineage_sequence = AttemptSequence::from_value(9);
  state.lineage.push_back(sample_lineage(AttemptSequence::from_value(9), state.committed_fence));
  state.findings.push_back(sample_finding(FindingGeneration::from_value(4), state.committed_fence));

  const Limits limits = small_limits();
  const std::vector<std::uint8_t> encoded = encode_store_state(state, limits);
  LG_REQUIRE(!encoded.empty());
  const auto decoded = decode_store_state(encoded, limits);
  LG_REQUIRE(decoded.has_value());
  LG_CHECK_EQ(decoded.value().digest(), state.digest());
  LG_CHECK_EQ(encode_store_state(decoded.value(), limits), encoded);

  // Truncation at every length must fail rather than silently decode a prefix.
  for (std::size_t length = 0; length < encoded.size(); ++length) {
    const std::vector<std::uint8_t> prefix(encoded.begin(),
                                           encoded.begin() + static_cast<std::ptrdiff_t>(length));
    const auto result = decode_store_state(prefix, limits);
    LG_CHECK(!result.has_value());
  }
  // Trailing bytes must fail.
  std::vector<std::uint8_t> trailing = encoded;
  trailing.push_back(0U);
  LG_CHECK(!decode_store_state(trailing, limits).has_value());
}
