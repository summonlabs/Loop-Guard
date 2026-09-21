#include <algorithm>
#include <set>

#include "fixtures.hpp"
#include "harness.hpp"
#include "loop_guard/net.hpp"
#include "loop_guard/wire.hpp"

namespace {

using namespace lg_test;
using namespace loop_guard;

FenceVector sample_fence() {
  FenceVector fence;
  fence.topology = TopologyGeneration::from_value(1);
  fence.forwarding = ForwardingGeneration::from_value(2);
  fence.policy = PolicyGeneration::from_value(3);
  fence.fabric_epoch = FabricEpoch::from_value(4);
  fence.epoch = CoordinatorEpoch::from_value(5);
  fence.boot = BootId::from_value(6);
  return fence;
}

}  // namespace

LG_TEST(wire, frame_round_trip_and_layout) {
  const std::vector<std::uint8_t> payload = {1U, 2U, 3U, 4U, 5U};
  const auto frame = encode_frame(MessageType::DetectRequest, SessionId::from_value(9), 42U, payload);
  LG_REQUIRE(frame.has_value());
  LG_CHECK_EQ(frame.value().size(), kWireHeaderBytes + payload.size() + kDigestBytes);
  const auto decoded = decode_frame(frame.value());
  LG_REQUIRE(decoded.has_value());
  LG_CHECK_EQ(decoded.value().header.type, MessageType::DetectRequest);
  LG_CHECK_EQ(decoded.value().header.session, SessionId::from_value(9));
  LG_CHECK_EQ(decoded.value().header.sequence, std::uint64_t{42});
  LG_CHECK_EQ(decoded.value().payload, payload);
}

LG_TEST(wire, oversized_payload_is_refused_before_encoding) {
  const std::vector<std::uint8_t> huge(Maxima::kFramePayload + 1U, 0U);
  const auto frame = encode_frame(MessageType::Bye, SessionId::from_value(1), 1U, huge);
  LG_CHECK(!frame.has_value());
  LG_CHECK_EQ(frame.outcome(), Outcome::Exhausted);
}

LG_TEST(wire, every_truncated_prefix_is_rejected) {
  const std::vector<std::uint8_t> payload(300U, 7U);
  const auto frame = encode_frame(MessageType::FindingQuery, SessionId::from_value(1), 1U, payload);
  LG_REQUIRE(frame.has_value());
  for (std::size_t length = 0; length < frame.value().size(); ++length) {
    const std::vector<std::uint8_t> prefix(
        frame.value().begin(), frame.value().begin() + static_cast<std::ptrdiff_t>(length));
    LG_CHECK(!decode_frame(prefix).has_value());
  }
}

LG_TEST(wire, corrupted_field_is_rejected) {
  const std::vector<std::uint8_t> payload = {1U, 2U, 3U};
  const auto frame = encode_frame(MessageType::Bye, SessionId::from_value(1), 1U, payload);
  LG_REQUIRE(frame.has_value());
  for (std::size_t offset = 0; offset < kWireHeaderBytes; offset += 3U) {
    std::vector<std::uint8_t> corrupted = frame.value();
    corrupted[offset] ^= 0x5AU;
    LG_CHECK(!decode_frame(corrupted).has_value());
  }
  std::vector<std::uint8_t> corrupted = frame.value();
  corrupted.back() ^= 0x01U;
  LG_CHECK(!decode_frame(corrupted).has_value());
}

LG_TEST(wire, trailing_bytes_are_rejected) {
  const std::vector<std::uint8_t> payload = {1U};
  auto frame = encode_frame(MessageType::Bye, SessionId::from_value(1), 1U, payload);
  LG_REQUIRE(frame.has_value());
  frame.value().push_back(0U);
  LG_CHECK(!decode_frame(frame.value()).has_value());
}

LG_TEST(wire, decoder_is_sticky_and_streaming) {
  Limits limits = default_limits();
  FrameDecoder decoder(limits);
  std::vector<DecodedFrame> frames;
  const auto first = encode_frame(MessageType::Bye, SessionId::from_value(1), 1U, {});
  const auto second = encode_frame(MessageType::Hello, SessionId::from_value(1), 2U, {});
  LG_REQUIRE(first.has_value() && second.has_value());

  std::vector<std::uint8_t> stream;
  stream.insert(stream.end(), first.value().begin(), first.value().end());
  stream.insert(stream.end(), second.value().begin(), second.value().end());

  // Feed one byte at a time: the decoder must assemble both frames.
  for (const std::uint8_t byte : stream) {
    LG_CHECK(decoder.feed(std::span<const std::uint8_t>(&byte, 1), frames).is_ok());
  }
  LG_CHECK_EQ(frames.size(), std::size_t{2});
  LG_CHECK(decoder.finish().is_ok());

  FrameDecoder broken(limits);
  std::vector<std::uint8_t> bad = first.value();
  bad[0] = 0U;
  LG_CHECK(!broken.feed(bad, frames).is_ok());
  LG_CHECK(broken.failed());
  LG_CHECK_EQ(broken.failure_reason(), ReasonCode::WireFrameBadMagic);
  // Sticky: a later well-formed frame cannot revive the decoder.
  LG_CHECK(!broken.feed(first.value(), frames).is_ok());
}

LG_TEST(wire, truncation_at_stream_end_is_a_failure) {
  FrameDecoder decoder;
  std::vector<DecodedFrame> frames;
  const auto frame = encode_frame(MessageType::Bye, SessionId::from_value(1), 1U, {});
  LG_REQUIRE(frame.has_value());
  const std::vector<std::uint8_t> prefix(frame.value().begin(), frame.value().end() - 3);
  LG_CHECK(decoder.feed(prefix, frames).is_ok());
  LG_CHECK(!decoder.finish().is_ok());
  LG_CHECK_EQ(decoder.failure_reason(), ReasonCode::WireFrameTruncated);
}

LG_TEST(wire, declared_length_above_ceiling_is_refused_without_allocation) {
  FrameDecoder decoder;
  std::vector<DecodedFrame> frames;
  std::vector<std::uint8_t> header(kWireHeaderBytes, 0U);
  header[0] = static_cast<std::uint8_t>(kWireMagic & 0xFFU);
  header[1] = static_cast<std::uint8_t>((kWireMagic >> 8U) & 0xFFU);
  header[2] = static_cast<std::uint8_t>((kWireMagic >> 16U) & 0xFFU);
  header[3] = static_cast<std::uint8_t>((kWireMagic >> 24U) & 0xFFU);
  header[4] = 1U;
  header[6] = static_cast<std::uint8_t>(MessageType::Bye);
  const std::uint32_t huge = Maxima::kFramePayload + 1U;
  for (std::size_t index = 0; index < 4; ++index) {
    header[28U + index] = static_cast<std::uint8_t>((huge >> (index * 8U)) & 0xFFU);
  }
  LG_CHECK(!decoder.feed(header, frames).is_ok());
  LG_CHECK_EQ(decoder.failure_reason(), ReasonCode::WireFrameOversized);
}

LG_TEST(wire, message_codecs_round_trip) {
  const Limits limits = default_limits();

  HelloMessage hello;
  hello.session = SessionId::from_value(11);
  hello.identity = ProcessIdentity{BootId::from_value(2), IncarnationId::from_value(3),
                                   CoordinatorEpoch::from_value(4), ProducerId::from_value(5)};
  hello.kind = ProducerKind::RemoteWorker;
  hello.origin = EvidenceOrigin::Real;
  hello.nonce = 99U;
  hello.requested_lease_ticks = 500U;
  const auto hello_bytes = encode_hello(hello);
  const auto hello_back = decode_hello(hello_bytes, limits);
  LG_REQUIRE(hello_back.has_value());
  LG_CHECK_EQ(hello_back.value().session, hello.session);
  LG_CHECK_EQ(hello_back.value().identity, hello.identity);
  LG_CHECK_EQ(hello_back.value().nonce, hello.nonce);

  HelloAckMessage ack;
  ack.session = SessionId::from_value(11);
  ack.coordinator = hello.identity;
  ack.fence = sample_fence();
  ack.lease_expires_at = 1000U;
  ack.outcome = Outcome::Ok;
  ack.reason = ReasonCode::WireFrameAccepted;
  ack.detail = "accepted";
  const auto ack_back = decode_hello_ack(encode_hello_ack(ack), limits);
  LG_REQUIRE(ack_back.has_value());
  LG_CHECK_EQ(ack_back.value().fence, ack.fence);
  LG_CHECK_EQ(ack_back.value().detail, ack.detail);

  DetectRequestMessage request;
  request.fence = sample_fence();
  request.now = 77U;
  request.selector_scope = {TrafficSelectorId::from_value(1), TrafficSelectorId::from_value(2)};
  const auto request_back = decode_detect_request(encode_detect_request(request), limits);
  LG_REQUIRE(request_back.has_value());
  LG_CHECK_EQ(request_back.value().selector_scope, request.selector_scope);

  ContainIntentMessage intent;
  intent.intent = ContainmentIntentId::from_value(3);
  intent.plan = ContainmentPlanId::from_value(4);
  intent.finding = FindingId::from_value(5);
  intent.fence = sample_fence();
  intent.issued_by = hello.identity;
  intent.targets = {ResourceId::from_value(1), ResourceId::from_value(2)};
  intent.selectors = {TrafficSelectorId::from_value(1)};
  intent.issued_at = 10U;
  intent.expires_at = 20U;
  const auto intent_back = decode_contain_intent(encode_contain_intent(intent, limits), limits);
  LG_REQUIRE(intent_back.has_value());
  LG_CHECK_EQ(intent_back.value().targets, intent.targets);
  LG_CHECK_EQ(intent_back.value().expires_at, intent.expires_at);

  ContainAckMessage contain_ack;
  contain_ack.intent = intent.intent;
  contain_ack.session = SessionId::from_value(11);
  contain_ack.applier = hello.identity;
  contain_ack.sequence = ProducerSequence::from_value(4);
  contain_ack.acknowledged_at = 12U;
  contain_ack.detail = "received";
  const auto contain_back = decode_contain_ack(encode_contain_ack(contain_ack, limits), limits);
  LG_REQUIRE(contain_back.has_value());
  LG_CHECK_EQ(contain_back.value().sequence, contain_ack.sequence);

  StateDigestReplyMessage digest;
  digest.store_digest = sha256(std::string("store"));
  digest.fence_digest = sample_fence().digest();
  digest.fence = sample_fence();
  digest.finding_count = 3U;
  digest.lineage_count = 4U;
  digest.observation_count = 5U;
  digest.retained_attempts = 6U;
  const auto digest_back = decode_state_digest_reply(encode_state_digest_reply(digest), limits);
  LG_REQUIRE(digest_back.has_value());
  LG_CHECK_EQ(digest_back.value().store_digest, digest.store_digest);

  AssessmentReplyMessage assessment;
  assessment.assessment = AssessmentId::from_value(9);
  assessment.fence = sample_fence();
  assessment.outcome = LoopOutcome::LoopConfirmed;
  assessment.flags = kAssessmentConflictsPresent;
  assessment.witness_count = 2;
  assessment.hop_count = 7;
  assessment.counters.scc_runs = 3;
  assessment.counters.steps_used = 11;
  assessment.counters.witnesses_validated = 2;
  assessment.counters.length_bound_reached = true;
  assessment.assessment_digest = sha256(std::string("assessment"));
  assessment.origin = EvidenceOrigin::Real;
  assessment.witnesses = {"witness 1", "witness 2"};
  assessment.explanation = "because";
  const auto assessment_back =
      decode_assessment_reply(encode_assessment_reply(assessment, limits), limits);
  LG_REQUIRE(assessment_back.has_value());
  LG_CHECK_EQ(assessment_back.value().witness_count, std::size_t{2});
  LG_CHECK_EQ(assessment_back.value().hop_count, std::size_t{7});
  LG_CHECK_EQ(assessment_back.value().counters.steps_used, std::uint64_t{11});
  LG_CHECK(assessment_back.value().counters.length_bound_reached);
  LG_CHECK_EQ(assessment_back.value().witnesses, assessment.witnesses);
  LG_CHECK_EQ(assessment_back.value().assessment_digest, assessment.assessment_digest);

  PlanReplyMessage plan;
  plan.plan = ContainmentPlanId::from_value(4);
  plan.assessment = AssessmentId::from_value(9);
  plan.fence = sample_fence();
  plan.outcome = ContainmentOutcome::PlanOptimal;
  plan.flags = kPlanProvedMinimum;
  plan.targets = {ResourceId::from_value(2)};
  plan.total_cost = 5;
  plan.witness_count = 2;
  plan.witnesses_covered = 2;
  plan.plan_digest = sha256(std::string("plan"));
  plan.explanation = "optimal";
  const auto plan_back = decode_plan_reply(encode_plan_reply(plan, limits), limits);
  LG_REQUIRE(plan_back.has_value());
  LG_CHECK_EQ(plan_back.value().targets, plan.targets);
  LG_CHECK_EQ(plan_back.value().total_cost, plan.total_cost);
  LG_CHECK_EQ(plan_back.value().witnesses_covered, plan.witnesses_covered);

  FindingSummary summary;
  summary.id = FindingId::from_value(3);
  summary.generation = FindingGeneration::from_value(4);
  summary.state = FindingState::ContainmentVerified;
  summary.fence_cause = FenceCause::None;
  summary.assessment_outcome = LoopOutcome::LoopConfirmed;
  summary.assessment_flags = kAssessmentUnprovenHopsPresent;
  summary.witness_count = 2;
  summary.implicated_resource_count = 6;
  summary.containment_outcome = ContainmentOutcome::PlanOptimal;
  summary.target_count = 1;
  summary.content_digest = sha256(std::string("finding"));
  FindingReplyMessage findings;
  findings.findings = {summary};
  findings.runtime_state_digest = sha256(std::string("state"));
  const auto findings_back = decode_finding_reply(encode_finding_reply(findings, limits), limits);
  LG_REQUIRE(findings_back.has_value());
  LG_CHECK_EQ(findings_back.value().findings.size(), std::size_t{1});
  LG_CHECK(findings_back.value().findings.front() == summary);

  RestartReportMessage restart;
  restart.boot = BootId::from_value(2);
  restart.incarnation = IncarnationId::from_value(2);
  restart.epoch = CoordinatorEpoch::from_value(2);
  restart.torn_tail_recovered = true;
  restart.fenced_findings = 1U;
  restart.store_digest = digest.store_digest;
  const auto restart_back = decode_restart_report(encode_restart_report(restart), limits);
  LG_REQUIRE(restart_back.has_value());
  LG_CHECK(restart_back.value().torn_tail_recovered);
}

LG_TEST(wire, message_decoders_reject_tampering) {
  const Limits limits = default_limits();
  DetectRequestMessage request;
  request.fence = sample_fence();
  request.selector_scope = {TrafficSelectorId::from_value(2), TrafficSelectorId::from_value(1)};
  // Unsorted selector scope must be refused, not silently sorted.
  LG_CHECK(!decode_detect_request(encode_detect_request(request), limits).has_value());

  DetectRequestMessage valid;
  valid.fence = sample_fence();
  const std::vector<std::uint8_t> bytes = encode_detect_request(valid);
  for (std::size_t length = 0; length < bytes.size(); ++length) {
    const std::vector<std::uint8_t> prefix(
        bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(length));
    LG_CHECK(!decode_detect_request(prefix, limits).has_value());
  }
  std::vector<std::uint8_t> trailing = bytes;
  trailing.push_back(0U);
  LG_CHECK(!decode_detect_request(trailing, limits).has_value());

  // An out-of-domain enum must be refused rather than clamped.
  HelloMessage hello;
  hello.session = SessionId::from_value(1);
  hello.identity = ProcessIdentity{BootId::from_value(1), IncarnationId::from_value(1),
                                   CoordinatorEpoch::from_value(1), ProducerId::from_value(1)};
  std::vector<std::uint8_t> hello_bytes = encode_hello(hello);
  hello_bytes[2U + 8U + 8U * 4U] = 0xF0U;  // kind field
  LG_CHECK(!decode_hello(hello_bytes, limits).has_value());
}

LG_TEST(wire, fence_codec_rejects_all_zero) {
  const std::span<const std::uint8_t> empty;
  ByteReader reader(empty);
  LG_CHECK(!decode_fence(reader).has_value());
  const std::vector<std::uint8_t> encoded = encode_fence(sample_fence());
  ByteReader good(encoded);
  const auto decoded = decode_fence(good);
  LG_REQUIRE(decoded.has_value());
  LG_CHECK_EQ(decoded.value(), sample_fence());
  LG_CHECK(good.at_end());
}

LG_TEST(wire, handshake_gate_allows_only_hello) {
  LG_CHECK(allowed_before_handshake(MessageType::Hello));
  LG_CHECK(!allowed_before_handshake(MessageType::DetectRequest));
  LG_CHECK(!allowed_before_handshake(MessageType::SubmitObservation));
  LG_CHECK(!allowed_before_handshake(MessageType::ContainIntent));
  LG_CHECK(!allowed_before_handshake(MessageType::FindingQuery));
}

LG_TEST(wire, topology_and_policy_codecs_round_trip) {
  const Limits limits = default_limits();
  RingScenario ring = make_ring(4, 2);
  const std::vector<std::uint8_t> bytes = encode_topology(ring.scenario.topology(), limits);
  const auto decoded = decode_topology(bytes, limits);
  LG_REQUIRE(decoded.has_value());
  LG_CHECK_EQ(decoded.value().digest(), ring.scenario.topology().digest());
  for (std::size_t length = 0; length < bytes.size(); ++length) {
    const std::vector<std::uint8_t> prefix(
        bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(length));
    LG_CHECK(!decode_topology(prefix, limits).has_value());
  }

  ContainmentPolicy policy;
  policy.generation = PolicyGeneration::from_value(3);
  policy.max_targets = 4;
  policy.max_total_cost = 12;
  policy.eligible_kinds = {ResourceKind::Switch, ResourceKind::PortGroup};
  policy.eligible_domains = {DomainId::from_value(1), DomainId::from_value(2)};
  const auto policy_bytes = encode_policy(policy, limits);
  const auto policy_back = decode_policy(policy_bytes, limits);
  LG_REQUIRE(policy_back.has_value());
  LG_CHECK(policy_back.value() == policy);
  LG_CHECK_EQ(policy_back.value().digest(), policy.digest());
}

LG_TEST(wire, observation_codec_round_trip_and_bounds) {
  const Limits limits = default_limits();
  ForwardingObservation observation;
  observation.id = ObservationId::from_value(1);
  observation.edge = ForwardingEdgeId::from_value(2);
  observation.from = ResourceId::from_value(3);
  observation.to = ResourceId::from_value(4);
  observation.domain = DomainId::from_value(5);
  observation.klass = EvidenceClass::Present;
  observation.selectors = {TrafficSelectorId::from_value(1)};
  observation.topology_generation = TopologyGeneration::from_value(1);
  observation.forwarding_generation = ForwardingGeneration::from_value(1);
  observation.producer = ProducerId::from_value(7);
  observation.sequence = ProducerSequence::from_value(9);
  observation.lease.boot = BootId::from_value(1);
  observation.lease.epoch = CoordinatorEpoch::from_value(1);
  observation.lease.fabric_epoch = FabricEpoch::from_value(1);
  observation.lease.valid_until = 1000U;
  const std::vector<std::uint8_t> bytes = encode_observation(observation, limits);
  const auto decoded = decode_observation(bytes, limits);
  LG_REQUIRE(decoded.has_value());
  LG_CHECK(decoded.value() == observation);
  std::vector<std::uint8_t> trailing = bytes;
  trailing.push_back(0U);
  LG_CHECK(!decode_observation(trailing, limits).has_value());
}
