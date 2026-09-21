// lg_coordinator - the Loop Guard service process.
//
// It owns one Runtime instance, serves the bounded framed protocol on loopback, and
// enforces the session authority model: a session is bound to its socket at handshake
// time, every frame must carry that session identity and a strictly increasing sequence,
// and no session can ever act under another session's identity, boot or epoch.
//
// Crash-proof flags used by the restart suites:
//   --exit-after-commit=N   exit(9) after the Nth durable commit, before the reply
//   --exit-before-commit=N  exit(9) after receiving the Nth mutation, before committing
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "tool_common.hpp"

namespace {

using namespace loop_guard;
using lg_tool::Args;

struct Session {
  SessionId id;
  ProducerKind kind = ProducerKind::RemoteWorker;
  ProcessIdentity identity;
  FramedConnection connection;
  /// Inbound and outbound sequences are independent spaces. Sharing one counter made the
  /// coordinator's own replies advance the sequence it demanded from its peer.
  std::uint64_t inbound_sequence = 0;
  std::uint64_t outbound_sequence = 0;
  Tick lease_expires_at = 0;
  bool worker = false;
  std::optional<LoopAssessment> last_assessment;
  std::vector<ContainmentIntent> issued;
};

struct Coordinator {
  explicit Coordinator(const Args& args)
      : args(args),
        runtime(),
        limits(default_limits()) {}

  const Args& args;
  Runtime runtime;
  Limits limits;
  Listener listener;
  std::map<std::uint64_t, Session> sessions;
  std::uint64_t durable_commits = 0;
  std::uint64_t mutations_seen = 0;
  bool shutting_down = false;

  [[nodiscard]] Status reply(Session& session, MessageType type,
                             const std::vector<std::uint8_t>& payload) {
    return session.connection.send_frame(type, session.id, ++session.outbound_sequence, payload,
                                         2000U);
  }

  [[nodiscard]] Status reply_error(Session& session, Outcome outcome, ReasonCode reason,
                                   MessageType offending, const std::string& detail) {
    ErrorMessage message;
    message.outcome = outcome;
    message.reason = reason;
    message.offending_type = offending;
    message.detail = detail;
    return reply(session, MessageType::Error, encode_error(message));
  }

  void note_commit() {
    ++durable_commits;
    const std::uint64_t threshold = args.get_u64("exit-after-commit", 0);
    if (threshold != 0U && durable_commits >= threshold) {
      std::cout << "crash=after-commit\n";
      std::cout.flush();
      std::_Exit(9);
    }
  }

  [[nodiscard]] bool should_exit_before_commit() {
    ++mutations_seen;
    const std::uint64_t threshold = args.get_u64("exit-before-commit", 0);
    if (threshold != 0U && mutations_seen >= threshold) {
      std::cout << "crash=before-commit\n";
      std::cout.flush();
      std::_Exit(9);
    }
    return false;
  }
};

[[nodiscard]] bool handle_frame(Coordinator& coordinator, Session& session, const DecodedFrame& frame) {
  using namespace loop_guard;
  if (frame.header.session != session.id) {
    (void)coordinator.reply_error(session, Outcome::Refused, ReasonCode::WireSessionMismatch,
                                  frame.header.type,
                                  "the frame carries a session identity that is not this socket's");
    lg_tool::report("close_reason", "session-mismatch");
    return false;
  }
  if (frame.header.sequence <= session.inbound_sequence) {
    (void)coordinator.reply_error(session, Outcome::Stale, ReasonCode::WireSequenceRegressed,
                                  frame.header.type, "frame sequence did not advance");
    lg_tool::report("close_reason",
                    "sequence-regressed " + std::to_string(frame.header.sequence) + "<=" +
                        std::to_string(session.inbound_sequence) + " type=" +
                        std::string(to_string(frame.header.type)));
    return false;
  }
  session.inbound_sequence = frame.header.sequence;

  switch (frame.header.type) {
    case MessageType::SetTopology: {
      auto topology = decode_topology(frame.payload, coordinator.limits);
      if (!topology.has_value()) {
        (void)coordinator.reply_error(session, topology.outcome(), ReasonCode::RequestRejectedStructural,
                                      frame.header.type, topology.detail());
        return true;
      }
      (void)coordinator.should_exit_before_commit();
      const Status status = coordinator.runtime.set_topology(std::move(topology).value(), 0);
      if (!status.is_ok()) {
        (void)coordinator.reply_error(session, status.outcome(), ReasonCode::RequestRejectedStructural,
                                      frame.header.type, status.detail());
        return true;
      }
      coordinator.note_commit();
      (void)coordinator.reply(session, MessageType::ConfigurationAccepted, {});
      return true;
    }
    case MessageType::SetPolicy: {
      auto policy = decode_policy(frame.payload, coordinator.limits);
      if (!policy.has_value()) {
        (void)coordinator.reply_error(session, policy.outcome(), ReasonCode::RequestRejectedStructural,
                                      frame.header.type, policy.detail());
        return true;
      }
      (void)coordinator.should_exit_before_commit();
      const Status status = coordinator.runtime.set_policy(std::move(policy).value(), 0);
      if (!status.is_ok()) {
        (void)coordinator.reply_error(session, status.outcome(), ReasonCode::RequestRejectedStructural,
                                      frame.header.type, status.detail());
        return true;
      }
      coordinator.note_commit();
      (void)coordinator.reply(session, MessageType::ConfigurationAccepted, {});
      return true;
    }
    case MessageType::SubmitObservation: {
      auto observation = decode_observation(frame.payload, coordinator.limits);
      if (!observation.has_value()) {
        (void)coordinator.reply_error(session, observation.outcome(),
                                      ReasonCode::RequestRejectedStructural, frame.header.type,
                                      observation.detail());
        return true;
      }
      const Status status = coordinator.runtime.submit_observation(observation.value(), 0);
      std::vector<std::uint8_t> payload;
      ByteWriter writer;
      writer.u8(static_cast<std::uint8_t>(status.outcome()));
      writer.u8(static_cast<std::uint8_t>(status.is_ok() ? ReasonCode::RequestAccepted
                                                         : ReasonCode::RequestRejectedStructural));
      writer.text(status.detail(), 256);
      payload = std::move(writer).take();
      (void)coordinator.reply(session, MessageType::ObservationAccepted, payload);
      return true;
    }
    case MessageType::DetectRequest: {
      auto request = decode_detect_request(frame.payload, coordinator.limits);
      if (!request.has_value()) {
        (void)coordinator.reply_error(session, request.outcome(), ReasonCode::RequestRejectedStructural,
                                      frame.header.type, request.detail());
        return true;
      }
      const FenceVector current = coordinator.runtime.fence();
      if (!(request.value().fence == current)) {
        (void)coordinator.reply_error(
            session, Outcome::Stale, ReasonCode::ObservationGenerationMismatch, frame.header.type,
            "the request binds fence " + request.value().fence.to_string() + " but the coordinator is at " +
                current.to_string());
        return true;
      }
      auto assessment = coordinator.runtime.detect(request.value().now, request.value().selector_scope);
      if (!assessment.has_value()) {
        (void)coordinator.reply_error(session, assessment.outcome(),
                                      ReasonCode::RequestRejectedStructural, frame.header.type,
                                      assessment.detail());
        return true;
      }
      AssessmentReplyMessage reply;
      reply.assessment = assessment.value().id;
      reply.fence = assessment.value().fence;
      reply.outcome = assessment.value().outcome;
      reply.flags = assessment.value().flags;
      reply.witness_count = assessment.value().witnesses.size();
      reply.hop_count = assessment.value().hops.size();
      reply.counters = assessment.value().counters;
      reply.assessment_digest = assessment.value().digest();
      reply.origin = assessment.value().origin;
      for (const LoopWitness& witness : assessment.value().witnesses) {
        reply.witnesses.push_back(witness.to_text());
      }
      reply.explanation = assessment.value().explanation.to_text();
      session.last_assessment = assessment.value();
      (void)coordinator.reply(session, MessageType::AssessmentReply,
                              encode_assessment_reply(reply, coordinator.limits));
      return true;
    }
    case MessageType::PlanRequest: {
      if (!session.last_assessment.has_value()) {
        (void)coordinator.reply_error(session, Outcome::NotFound,
                                      ReasonCode::RequestRejectedStructural, frame.header.type,
                                      "no assessment has been produced on this session");
        return true;
      }
      auto policy = coordinator.runtime.policy();
      auto topology = coordinator.runtime.topology();
      if (!policy.has_value() || !topology.has_value()) {
        (void)coordinator.reply_error(session, Outcome::NotFound,
                                      ReasonCode::RequestRejectedStructural, frame.header.type,
                                      "a topology and a policy must be configured first");
        return true;
      }
      auto plan = coordinator.runtime.plan_containment(session.last_assessment.value(), 0);
      if (!plan.has_value()) {
        (void)coordinator.reply_error(session, plan.outcome(), ReasonCode::RequestRejectedStructural,
                                      frame.header.type, plan.detail());
        return true;
      }
      PlanReplyMessage reply;
      reply.plan = plan.value().id;
      reply.assessment = plan.value().assessment;
      reply.fence = plan.value().fence;
      reply.outcome = plan.value().outcome;
      reply.flags = plan.value().flags;
      reply.targets = plan.value().target_resources();
      reply.total_cost = plan.value().total_cost;
      reply.witness_count = plan.value().witness_count;
      reply.witnesses_covered = plan.value().witnesses_covered;
      reply.plan_digest = plan.value().content_digest();
      reply.explanation = plan.value().explanation.to_text();
      (void)coordinator.reply(session, MessageType::PlanReply,
                              encode_plan_reply(reply, coordinator.limits));
      return true;
    }
    case MessageType::FindingPublish: {
      if (!session.last_assessment.has_value()) {
        (void)coordinator.reply_error(session, Outcome::NotFound,
                                      ReasonCode::RequestRejectedStructural, frame.header.type,
                                      "no assessment has been produced on this session");
        return true;
      }
      (void)coordinator.should_exit_before_commit();
      auto published = coordinator.runtime.publish_finding(session.last_assessment.value(), 0);
      if (!published.has_value()) {
        (void)coordinator.reply_error(session, published.outcome(), ReasonCode::FindingWithdrawn,
                                      frame.header.type, published.detail());
        return true;
      }
      coordinator.note_commit();
      FindingReplyMessage reply;
      reply.findings = coordinator.runtime.findings();
      reply.runtime_state_digest = coordinator.runtime.state_digest();
      (void)coordinator.reply(session, MessageType::FindingReply,
                              encode_finding_reply(reply, coordinator.limits));
      return true;
    }
    case MessageType::ContainAuthorize: {
      ByteReader reader(frame.payload);
      FindingId finding;
      auto fence = decode_fence(reader);
      std::uint64_t now = 0;
      std::uint64_t lease = 0;
      if (!reader.read_id(finding) || !fence.has_value() || !reader.read_u64(now) ||
          !reader.read_u64(lease)) {
        (void)coordinator.reply_error(session, Outcome::Invalid,
                                      ReasonCode::RequestRejectedStructural, frame.header.type,
                                      "containment authorization payload is malformed");
        return true;
      }
      if (!(fence.value() == coordinator.runtime.fence())) {
        (void)coordinator.reply_error(session, Outcome::Stale,
                                      ReasonCode::ObservationGenerationMismatch, frame.header.type,
                                      "the authorization request binds a superseded fence");
        return true;
      }
      auto plan = coordinator.runtime.find_plan(
          coordinator.runtime.find_finding(finding).has_value()
              ? coordinator.runtime.find_finding(finding)->plan
              : ContainmentPlanId{});
      if (!plan.has_value()) {
        (void)coordinator.reply_error(session, Outcome::NotFound,
                                      ReasonCode::RequestRejectedStructural, frame.header.type,
                                      "the finding has no retained containment plan");
        return true;
      }
      ContainmentGrant grant;
      grant.id = ContainmentGrantId::from_value(session.id.value());
      grant.policy_generation = coordinator.runtime.fence().policy;
      grant.fence = coordinator.runtime.fence();
      grant.scope = plan->target_resources();
      grant.max_targets = static_cast<std::uint32_t>(plan->targets.size());
      grant.max_total_cost = plan->total_cost;
      grant.issued_at = now;
      grant.expires_at = now + lease;
      grant.issued_by = coordinator.runtime.identity().producer;
      auto issued = coordinator.runtime.authorize_containment(finding, grant, now, lease);
      if (!issued.has_value()) {
        (void)coordinator.reply_error(session, issued.outcome(), ReasonCode::AuthorityGrantAbsent,
                                      frame.header.type, issued.detail());
        return true;
      }
      // Dispatch the intent to every worker session. It is an intent, not an effect.
      ContainIntentMessage message;
      message.intent = issued.value().id;
      message.plan = issued.value().plan;
      message.finding = issued.value().finding;
      message.fence = issued.value().fence;
      message.issued_by = issued.value().issued_by;
      message.targets = issued.value().targets;
      message.selectors = issued.value().selectors;
      message.issued_at = issued.value().issued_at;
      message.expires_at = issued.value().expires_at;
      message.plan_digest = issued.value().plan_digest;
      const std::vector<std::uint8_t> payload =
          encode_contain_intent(message, coordinator.limits);
      for (auto& entry : coordinator.sessions) {
        if (entry.second.worker && entry.first != session.id.value()) {
          (void)entry.second.connection.send_frame(MessageType::ContainIntent, entry.second.id,
                                                   ++entry.second.outbound_sequence, payload, 2000U);
        }
      }
      session.issued.push_back(issued.value());
      lg_tool::report("intent", issued.value().id.to_string());
      PlanReplyMessage reply;
      reply.plan = plan->id;
      reply.assessment = plan->assessment;
      reply.fence = plan->fence;
      reply.outcome = plan->outcome;
      reply.flags = plan->flags;
      reply.targets = plan->target_resources();
      reply.total_cost = plan->total_cost;
      reply.witness_count = plan->witness_count;
      reply.witnesses_covered = plan->witnesses_covered;
      reply.plan_digest = plan->content_digest();
      reply.explanation = plan->explanation.to_text();
      (void)coordinator.reply(session, MessageType::PlanReply,
                              encode_plan_reply(reply, coordinator.limits));
      return true;
    }
    case MessageType::ContainAck: {
      auto ack = decode_contain_ack(frame.payload, coordinator.limits);
      if (!ack.has_value()) {
        (void)coordinator.reply_error(session, ack.outcome(), ReasonCode::RequestRejectedStructural,
                                      frame.header.type, ack.detail());
        return true;
      }
      ContainmentAcknowledgement record;
      record.intent = ack.value().intent;
      record.session = session.id;
      record.applier = ack.value().applier;
      record.sequence = ack.value().sequence;
      record.acknowledged_at = ack.value().acknowledged_at;
      record.intent_digest = ack.value().intent_digest;
      const Status status = coordinator.runtime.record_acknowledgement(record, ack.value().acknowledged_at);
      ByteWriter writer;
      writer.u8(static_cast<std::uint8_t>(status.outcome()));
      writer.text(status.detail(), 256);
      (void)coordinator.reply(session, MessageType::ObservationAccepted,
                              std::move(writer).take());
      return true;
    }
    case MessageType::EffectReport: {
      auto effect = decode_effect_report(frame.payload, coordinator.limits);
      if (!effect.has_value()) {
        (void)coordinator.reply_error(session, effect.outcome(),
                                      ReasonCode::RequestRejectedStructural, frame.header.type,
                                      effect.detail());
        return true;
      }
      if (effect.value().has_observation) {
        (void)coordinator.runtime.submit_observation(effect.value().observation_payload,
                                                     effect.value().verified_at);
      }
      VerifiedEffect record;
      record.target = effect.value().target;
      record.observation = effect.value().observation;
      record.fence = effect.value().fence;
      record.verified_at = effect.value().verified_at;
      record.origin = effect.value().origin;
      const Status status =
          coordinator.runtime.record_verified_effect(effect.value().intent, record,
                                                     effect.value().verified_at);
      ByteWriter writer;
      writer.u8(static_cast<std::uint8_t>(status.outcome()));
      writer.text(status.detail(), 256);
      (void)coordinator.reply(session, MessageType::ObservationAccepted,
                              std::move(writer).take());
      return true;
    }
    case MessageType::FindingQuery: {
      FindingReplyMessage reply;
      reply.findings = coordinator.runtime.findings();
      reply.runtime_state_digest = coordinator.runtime.state_digest();
      (void)coordinator.reply(session, MessageType::FindingReply,
                              encode_finding_reply(reply, coordinator.limits));
      return true;
    }
    case MessageType::FindingWithdraw: {
      ByteReader reader(frame.payload);
      FindingId id;
      std::uint8_t raw = 0;
      if (!reader.read_id(id)) {
        (void)coordinator.reply_error(session, Outcome::Invalid,
                                      ReasonCode::RequestRejectedStructural, frame.header.type,
                                      "withdrawal payload is malformed");
        return true;
      }
      const Status status = coordinator.runtime.withdraw_finding(
          id, ReasonCode::FindingWithdrawn, 0, "withdrawn over the wire");
      (void)coordinator.reply(session, MessageType::ConfigurationAccepted,
                              std::vector<std::uint8_t>{static_cast<std::uint8_t>(status.outcome()),
                                                        raw});
      return true;
    }
    case MessageType::StateDigestRequest: {
      StateDigestReplyMessage reply;
      reply.store_digest = coordinator.runtime.state_digest();
      reply.fence_digest = coordinator.runtime.fence().digest();
      reply.fence = coordinator.runtime.fence();
      reply.finding_count = coordinator.runtime.findings().size();
      reply.lineage_count = coordinator.runtime.lineage().size();
      reply.observation_count = coordinator.runtime.observation_count();
      reply.retained_attempts = coordinator.runtime.counters().retained_attempts;
      (void)coordinator.reply(session, MessageType::StateDigestReply,
                              encode_state_digest_reply(reply));
      return true;
    }
    case MessageType::FenceAdvance: {
      ByteReader reader(frame.payload);
      auto fence = decode_fence(reader);
      std::uint8_t raw = 0;
      std::uint64_t now = 0;
      if (!fence.has_value() || !reader.read_u8(raw) || !reader.read_u64(now)) {
        (void)coordinator.reply_error(session, Outcome::Invalid,
                                      ReasonCode::RequestRejectedStructural, frame.header.type,
                                      "fence advance payload is malformed");
        return true;
      }
      Status status = Status::ok();
      if (fence.value().topology > coordinator.runtime.fence().topology) {
        auto topology = coordinator.runtime.topology();
        if (topology.has_value()) {
          TopologyDefinition advanced = topology.value();
          advanced.set_generation(fence.value().topology);
          status = coordinator.runtime.set_topology(std::move(advanced), now);
          if (status.is_ok()) {
            coordinator.note_commit();
          }
        }
      } else if (fence.value().forwarding > coordinator.runtime.fence().forwarding) {
        status = coordinator.runtime.advance_forwarding(fence.value().forwarding, now);
      } else if (fence.value().fabric_epoch > coordinator.runtime.fence().fabric_epoch) {
        status = coordinator.runtime.advance_fabric_epoch(fence.value().fabric_epoch, now);
      } else if (fence.value().epoch > coordinator.runtime.fence().epoch) {
        status = coordinator.runtime.advance_epoch(now);
      }
      ByteWriter writer;
      writer.u8(static_cast<std::uint8_t>(status.outcome()));
      writer.text(status.detail(), 256);
      (void)coordinator.reply(session, MessageType::ConfigurationAccepted,
                              std::move(writer).take());
      return true;
    }
    case MessageType::RestartReportRequest: {
      RestartReportMessage reply;
      reply.boot = coordinator.runtime.identity().boot;
      reply.incarnation = coordinator.runtime.identity().incarnation;
      reply.epoch = coordinator.runtime.identity().epoch;
      reply.torn_tail_recovered = coordinator.runtime.recovery().torn_tail_recovered;
      reply.fenced_findings = static_cast<std::uint32_t>(
          coordinator.runtime.counters().findings_fenced);
      reply.dropped_findings = 0U;
      reply.retained_findings = static_cast<std::uint32_t>(coordinator.runtime.findings().size());
      reply.lineage_records = static_cast<std::uint32_t>(coordinator.runtime.lineage().size());
      reply.store_digest = coordinator.runtime.state_digest();
      (void)coordinator.reply(session, MessageType::RestartReportReply,
                              encode_restart_report(reply));
      return true;
    }
    case MessageType::Bye:
      lg_tool::report("close_reason", "bye");
      return false;
    case MessageType::Hello:
    case MessageType::HelloAck:
    case MessageType::Error:
    case MessageType::ConfigurationAccepted:
    case MessageType::ObservationAccepted:
    case MessageType::AssessmentReply:
    case MessageType::PlanReply:
    case MessageType::FindingReply:
    case MessageType::StateDigestReply:
    case MessageType::RestartReportReply:
    case MessageType::ContainIntent:
      (void)coordinator.reply_error(session, Outcome::Unsupported,
                                    ReasonCode::WireFrameTypeUnsupported, frame.header.type,
                                    "this frame type is not accepted by the coordinator");
      return true;
  }
  return true;
}

[[nodiscard]] bool handle_hello(Coordinator& coordinator, FramedConnection& connection,
                                const DecodedFrame& frame) {
  using namespace loop_guard;
  auto hello = decode_hello(frame.payload, coordinator.limits);
  if (!hello.has_value()) {
    return false;
  }
  if (hello.value().protocol_version != kWireVersion) {
    HelloAckMessage ack;
    ack.protocol_version = kWireVersion;
    ack.session = hello.value().session;
    ack.coordinator = coordinator.runtime.identity();
    ack.fence = coordinator.runtime.fence();
    ack.outcome = Outcome::Unsupported;
    ack.reason = ReasonCode::WireHandshakeRejected;
    ack.detail = "protocol version mismatch";
    (void)connection.send_frame(MessageType::HelloAck, hello.value().session, 1U,
                                encode_hello_ack(ack), 2000U);
    return false;
  }
  if (!hello.value().session.valid()) {
    return false;
  }
  if (coordinator.sessions.find(hello.value().session.value()) != coordinator.sessions.end()) {
    HelloAckMessage ack;
    ack.protocol_version = kWireVersion;
    ack.session = hello.value().session;
    ack.coordinator = coordinator.runtime.identity();
    ack.fence = coordinator.runtime.fence();
    ack.outcome = Outcome::AlreadyExists;
    ack.reason = ReasonCode::WireHandshakeRejected;
    ack.detail = "session identity is already claimed by another connection";
    (void)connection.send_frame(MessageType::HelloAck, hello.value().session, 1U,
                                encode_hello_ack(ack), 2000U);
    return false;
  }

  Session session;
  session.id = hello.value().session;
  session.kind = hello.value().kind;
  session.identity = hello.value().identity;
  session.worker = hello.value().kind == ProducerKind::RemoteWorker;
  session.inbound_sequence = 1U;
  session.outbound_sequence = 0U;
  session.connection = std::move(connection);

  HelloAckMessage ack;
  ack.protocol_version = kWireVersion;
  ack.session = session.id;
  ack.coordinator = coordinator.runtime.identity();
  ack.fence = coordinator.runtime.fence();
  ack.accepted_at = 0;
  ack.lease_expires_at = hello.value().requested_lease_ticks;
  ack.outcome = Outcome::Ok;
  ack.reason = ReasonCode::WireFrameAccepted;
  ack.detail = "session bound to this socket";
  const Status sent = session.connection.send_frame(MessageType::HelloAck, session.id, 1U,
                                                    encode_hello_ack(ack), 2000U);
  if (!sent.is_ok()) {
    return false;
  }
  lg_tool::report("session", session.id.to_string());
  lg_tool::report("kind", std::string(to_string(session.kind)));
  lg_tool::report("boot", coordinator.runtime.identity().boot.to_string());
  lg_tool::report("epoch", coordinator.runtime.identity().epoch.to_string());
  coordinator.sessions[session.id.value()] = std::move(session);
  return true;
}

}  // namespace

int main(int argc, char** argv) {
  using namespace loop_guard;
  const Args args = lg_tool::parse_args(argc, argv, 1);
  if (args.has("help")) {
    std::cout << "lg_coordinator --port=N [--store=PATH] [--ring=N] [--policy-generation=N]\n";
    return 0;
  }

  SocketSubsystem sockets;
  if (!sockets.ok()) {
    std::cerr << "socket subsystem unavailable\n";
    return 2;
  }

  RuntimeConfig config;
  config.producer = ProducerId::from_value(args.get_u64("producer", 1));
  config.store_path = args.get("store");
  config.origin = EvidenceOrigin::Real;
  if (args.has("limits-journal-records")) {
    config.limits.max_journal_records = static_cast<std::uint32_t>(args.get_u64("limits-journal-records"));
  }
  if (args.has("limits-witness-hops")) {
    config.limits.max_witness_hops = static_cast<std::uint32_t>(args.get_u64("limits-witness-hops"));
  }
  auto runtime = Runtime::open(config);
  if (!runtime.has_value()) {
    std::cerr << "runtime open failed: " << runtime.detail() << "\n";
    return 3;
  }

  Coordinator coordinator(args);
  coordinator.runtime = std::move(runtime.value());
  coordinator.limits = config.limits;

  // The listener is established and reported before any default configuration is
  // installed, so a client can always reach a coordinator that is about to be tested for
  // a crash at a durable boundary.
  const std::uint16_t requested_port = static_cast<std::uint16_t>(args.get_u64("port", 0));
  auto listener = Listener::listen_loopback(requested_port, coordinator.limits);
  if (!listener.has_value()) {
    std::cerr << "listen failed: " << listener.detail() << "\n";
    return 3;
  }
  coordinator.listener = std::move(listener.value());
  lg_tool::report("port", coordinator.listener.port());
  lg_tool::report("boot", coordinator.runtime.identity().boot.to_string());
  lg_tool::report("incarnation", coordinator.runtime.identity().incarnation.to_string());
  lg_tool::report("epoch", coordinator.runtime.identity().epoch.to_string());
  lg_tool::report("fence", coordinator.runtime.fence().to_string());
  lg_tool::report("torn_tail", coordinator.runtime.recovery().torn_tail_recovered ? "1" : "0");

  // Installing the default fixture advances past whatever the durable store already
  // holds, so restarting a coordinator against its own store is not a generation
  // regression.
  const std::size_t ring = static_cast<std::size_t>(args.get_u64("ring", 0));
  if (ring > 0U) {
    std::uint64_t generation = 1U;
    const auto existing = coordinator.runtime.topology();
    if (existing.has_value()) {
      generation = existing->generation().value() + 1U;
    }
    TopologyDefinition topology = lg_tool::synthetic_ring(ring, generation);
    const Status status = coordinator.runtime.set_topology(std::move(topology), 0);
    if (!status.is_ok()) {
      std::cerr << "default topology rejected: " << status.detail() << "\n";
      return 3;
    }
    coordinator.note_commit();
  }
  if (args.has("policy-generation") || ring > 0U) {
    std::uint64_t generation = args.get_u64("policy-generation", 0);
    if (generation == 0U) {
      const auto existing = coordinator.runtime.policy();
      generation = existing.has_value() ? existing->generation.value() + 1U : 1U;
    }
    ContainmentPolicy policy = lg_tool::synthetic_policy(generation);
    const Status status = coordinator.runtime.set_policy(std::move(policy), 0);
    if (!status.is_ok()) {
      std::cerr << "default policy rejected: " << status.detail() << "\n";
      return 3;
    }
    coordinator.note_commit();
  }

  const bool oneshot = args.has("oneshot");
  bool running = true;
  while (running) {
    bool progressed = false;
    for (auto entry = coordinator.sessions.begin(); entry != coordinator.sessions.end();) {
      Session& session = entry->second;
      auto frame = session.connection.receive_frame(2U);
      if (frame.has_value()) {
        progressed = true;
        if (!handle_frame(coordinator, session, frame.value())) {
          // The identity is copied before the node is erased: reading it afterwards would
          // be a use-after-free.
          const SessionId closed_session = session.id;
          (void)session.connection.close();
          entry = coordinator.sessions.erase(entry);
          lg_tool::report("session_closed", closed_session.to_string());
          if (oneshot && coordinator.sessions.empty()) {
            running = false;
          }
          continue;
        }
        ++entry;
        continue;
      }
      if (frame.outcome() != Outcome::Indeterminate) {
        lg_tool::report("close_reason",
                        std::string(to_string(frame.outcome())) + " " + frame.detail());
        (void)session.connection.close();
        entry = coordinator.sessions.erase(entry);
        continue;
      }
      ++entry;
    }
    auto accepted = coordinator.listener.accept(progressed ? 0U : 5U);
    if (accepted.has_value()) {
      FramedConnection connection(std::move(accepted.value()), coordinator.limits);
      auto frame = connection.receive_frame(1000U);
      if (!frame.has_value() || frame.value().header.type != MessageType::Hello ||
          !allowed_before_handshake(frame.value().header.type)) {
        (void)connection.close();
        continue;
      }
      (void)handle_hello(coordinator, connection, frame.value());
      continue;
    }
    if (coordinator.sessions.empty() && args.has("exit-when-idle")) {
      running = false;
    }
  }

  (void)coordinator.runtime.close(true);
  lg_tool::report("stopped", "1");
  return 0;
}
