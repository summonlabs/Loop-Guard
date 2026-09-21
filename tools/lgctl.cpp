// lgctl - the operator command line client.
//
// It performs exactly the operations an operator is allowed to perform, in the order the
// authority model requires, and prints one machine-readable line per step.
#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "tool_common.hpp"

namespace {

using namespace loop_guard;

std::vector<std::string> split(const std::string& text, char separator) {
  std::vector<std::string> parts;
  std::string current;
  for (const char character : text) {
    if (character == separator) {
      parts.push_back(current);
      current.clear();
      continue;
    }
    current.push_back(character);
  }
  if (!current.empty()) {
    parts.push_back(current);
  }
  return parts;
}

struct Ctl {
  FramedConnection connection;
  SessionId session = SessionId::from_value(1);
  ProcessIdentity identity;
  FenceVector fence;
  std::uint64_t sequence = 1;
  std::optional<LoopAssessment> assessment;
  std::optional<ContainmentPlan> plan;
  std::optional<ContainmentIntent> intent;
  FindingId finding;
  bool ok = true;

  [[nodiscard]] bool send(MessageType type, const std::vector<std::uint8_t>& payload) {
    const Status status =
        connection.send_frame(type, session, sequence++, payload, 5000U);
    if (!status.is_ok()) {
      lg_tool::report("error", "send:" + status.detail());
      ok = false;
      return false;
    }
    return true;
  }

  [[nodiscard]] std::optional<DecodedFrame> expect(MessageType type) {
    auto frame = connection.receive_frame(5000U);
    if (!frame.has_value()) {
      lg_tool::report("error", "receive:" + frame.detail());
      ok = false;
      return std::nullopt;
    }
    if (frame.value().header.type != type) {
      if (frame.value().header.type == MessageType::Error) {
        auto error = decode_error(frame.value().payload, default_limits());
        if (error.has_value()) {
          lg_tool::report("error_outcome", std::string(to_string(error.value().outcome)));
          lg_tool::report("error_reason", std::string(to_string(error.value().reason)));
          lg_tool::report("error_detail", error.value().detail);
        }
      }
      ok = false;
      return std::nullopt;
    }
    return std::optional<DecodedFrame>(std::move(frame.value()));
  }
};

}  // namespace

int main(int argc, char** argv) {
  using namespace loop_guard;
  const lg_tool::Args args = lg_tool::parse_args(argc, argv, 1);
  if (args.has("help")) {
    std::cout << "lgctl --port=N --script=detect,publish,plan,authorize,effects,findings,digest,"
                 "withdraw,fence-advance,restart-report,shutdown\n";
    return 0;
  }
  SocketSubsystem sockets;
  if (!sockets.ok()) {
    std::cerr << "socket subsystem unavailable\n";
    return 2;
  }
  const std::uint16_t port = static_cast<std::uint16_t>(args.get_u64("port", 0));
  auto socket = Socket::connect_loopback(port, 5000U);
  if (!socket.has_value()) {
    std::cerr << "connect failed: " << socket.detail() << "\n";
    return 3;
  }
  Ctl ctl;
  ctl.connection = FramedConnection(std::move(socket.value()));
  ctl.session = SessionId::from_value(args.get_u64("session", 1));
  ctl.identity.producer = ProducerId::from_value(args.get_u64("producer", 1));
  ctl.identity.boot = BootId::from_value(1);
  ctl.identity.incarnation = IncarnationId::from_value(1);
  ctl.identity.epoch = CoordinatorEpoch::from_value(1);

  HelloMessage hello;
  hello.session = ctl.session;
  hello.identity = ctl.identity;
  hello.kind = args.has("as-worker") ? ProducerKind::RemoteWorker : ProducerKind::Operator;
  hello.origin = EvidenceOrigin::Real;
  hello.requested_lease_ticks = 100000U;
  if (!ctl.send(MessageType::Hello, encode_hello(hello))) {
    return 3;
  }
  auto ack_frame = ctl.expect(MessageType::HelloAck);
  if (!ack_frame.has_value()) {
    return 3;
  }
  auto ack = decode_hello_ack(ack_frame.value().payload, default_limits());
  if (!ack.has_value()) {
    return 3;
  }
  lg_tool::report("handshake_outcome", std::string(to_string(ack.value().outcome)));
  if (ack.value().outcome != Outcome::Ok) {
    return 4;
  }
  ctl.fence = ack.value().fence;
  lg_tool::report("fence", ctl.fence.to_string());
  lg_tool::report("coordinator_boot", ack.value().coordinator.boot.to_string());
  lg_tool::report("coordinator_epoch", ack.value().coordinator.epoch.to_string());

  const std::size_t ring = static_cast<std::size_t>(args.get_u64("ring", 0));
  const std::vector<std::string> script = split(args.get("script", "findings,shutdown"), ',');
  for (const std::string& step : script) {
    if (step.empty()) {
      continue;
    }
    if (step == "topology") {
      if (ring == 0U) {
        lg_tool::report("topology_skipped", "no ring was requested");
        continue;
      }
      TopologyDefinition topology =
          lg_tool::synthetic_ring(ring, ctl.fence.topology.value() + 1U);
      if (!ctl.send(MessageType::SetTopology, encode_topology(topology, default_limits()))) {
        break;
      }
      auto frame = ctl.expect(MessageType::ConfigurationAccepted);
      if (!frame.has_value()) {
        break;
      }
      ctl.fence.topology = topology.generation();
      lg_tool::report("topology_installed", topology.generation().to_string());
      continue;
    }
    if (step == "observe") {
      // Submits the synthetic ring's evidence over the wire, exactly as the worker does.
      // This is a SYNTHETIC fixture; it is not a device read.
      if (ring == 0U) {
        lg_tool::report("observe_skipped", "no ring was requested");
        continue;
      }
      const TopologyDefinition topology = lg_tool::synthetic_ring(ring, ctl.fence.topology.value());
      std::uint64_t observation_id = 1;
      std::uint64_t sequence = 0;
      for (const ForwardingEdge& edge : topology.edges()) {
        const ForwardingObservation observation = lg_tool::synthetic_observation(
            topology, edge.id, EvidenceClass::Present, observation_id++, ctl.identity.producer.value(),
            ++sequence, ctl.fence, ProducerKind::Operator, EvidenceOrigin::Synthetic);
        if (!ctl.send(MessageType::SubmitObservation,
                      encode_observation(observation, default_limits()))) {
          break;
        }
        auto frame = ctl.expect(MessageType::ObservationAccepted);
        if (!frame.has_value()) {
          break;
        }
      }
      lg_tool::report("observed_edges", topology.edges().size());
      continue;
    }
    if (step == "detect") {
      DetectRequestMessage request;
      request.fence = ctl.fence;
      request.now = args.get_u64("now", 100);
      if (!ctl.send(MessageType::DetectRequest, encode_detect_request(request))) {
        break;
      }
      auto frame = ctl.expect(MessageType::AssessmentReply);
      if (!frame.has_value()) {
        break;
      }
      auto reply = decode_assessment_reply(frame.value().payload, default_limits());
      if (!reply.has_value()) {
        break;
      }
      lg_tool::report("assessment", reply.value().assessment.to_string());
      lg_tool::report("outcome", std::string(to_string(reply.value().outcome)));
      lg_tool::report("flags", assessment_flags_to_string(reply.value().flags));
      lg_tool::report("witnesses", reply.value().witnesses.size());
      lg_tool::report("hops", reply.value().hop_count);
      lg_tool::report("validated", reply.value().counters.witnesses_validated);
      lg_tool::report("rejected", reply.value().counters.witnesses_rejected);
      lg_tool::report("selectors_considered", reply.value().counters.selectors_considered);
      lg_tool::report("steps", reply.value().counters.steps_used);
      lg_tool::report("assessment_digest", reply.value().assessment_digest.to_hex());
      for (const std::string& witness : reply.value().witnesses) {
        lg_tool::report("witness", witness);
      }
      continue;
    }
    if (step == "detect-stale") {
      DetectRequestMessage request;
      request.fence = ctl.fence;
      request.fence.topology = TopologyGeneration::from_value(ctl.fence.topology.value() + 100U);
      request.now = 100;
      if (!ctl.send(MessageType::DetectRequest, encode_detect_request(request))) {
        break;
      }
      auto frame = ctl.connection.receive_frame(5000U);
      if (!frame.has_value()) {
        break;
      }
      lg_tool::report("stale_reply_type", std::string(to_string(frame.value().header.type)));
      if (frame.value().header.type == MessageType::Error) {
        auto error = decode_error(frame.value().payload, default_limits());
        if (error.has_value()) {
          lg_tool::report("stale_outcome", std::string(to_string(error.value().outcome)));
        }
      }
      continue;
    }
    if (step == "publish") {
      ByteWriter writer;
      writer.raw(encode_fence(ctl.fence));
      writer.u64(args.get_u64("now", 100));
      if (!ctl.send(MessageType::FindingPublish, std::move(writer).take())) {
        break;
      }
      auto frame = ctl.expect(MessageType::FindingReply);
      if (!frame.has_value()) {
        break;
      }
      auto reply = decode_finding_reply(frame.value().payload, default_limits());
      if (!reply.has_value()) {
        break;
      }
      lg_tool::report("published_findings", reply.value().findings.size());
      for (const FindingSummary& summary : reply.value().findings) {
        lg_tool::report("finding", to_string(summary));
      }
      continue;
    }
    if (step == "authorize") {
      ByteWriter writer;
      writer.raw(encode_fence(ctl.fence));
      writer.u64(args.get_u64("finding", 0));
      writer.u64(args.get_u64("now", 100));
      writer.u64(args.get_u64("lease", 1000));
      if (!ctl.send(MessageType::ContainAuthorize, std::move(writer).take())) {
        break;
      }
      auto frame = ctl.expect(MessageType::PlanReply);
      if (!frame.has_value()) {
        break;
      }
      auto reply = decode_plan_reply(frame.value().payload, default_limits());
      if (!reply.has_value()) {
        break;
      }
      lg_tool::report("authorized_plan", reply.value().plan.to_string());
      lg_tool::report("authorized_targets", reply.value().targets.size());
      continue;
    }
    if (step == "plan") {
      if (!ctl.send(MessageType::PlanRequest, {})) {
        break;
      }
      auto frame = ctl.expect(MessageType::PlanReply);
      if (!frame.has_value()) {
        break;
      }
      auto reply = decode_plan_reply(frame.value().payload, default_limits());
      if (!reply.has_value()) {
        break;
      }
      lg_tool::report("plan", reply.value().plan.to_string());
      lg_tool::report("plan_outcome", std::string(to_string(reply.value().outcome)));
      lg_tool::report("plan_flags", plan_flags_to_string(reply.value().flags));
      lg_tool::report("plan_targets", reply.value().targets.size());
      lg_tool::report("plan_cost", reply.value().total_cost);
      lg_tool::report("plan_covered", reply.value().witnesses_covered);
      std::string targets;
      for (const ResourceId target : reply.value().targets) {
        if (!targets.empty()) {
          targets.push_back(',');
        }
        targets += target.to_string();
      }
      lg_tool::report("plan_target_ids", targets);
      continue;
    }
    if (step == "findings") {
      if (!ctl.send(MessageType::FindingQuery, {})) {
        break;
      }
      auto frame = ctl.expect(MessageType::FindingReply);
      if (!frame.has_value()) {
        break;
      }
      auto reply = decode_finding_reply(frame.value().payload, default_limits());
      if (!reply.has_value()) {
        break;
      }
      lg_tool::report("finding_count", reply.value().findings.size());
      for (const FindingSummary& summary : reply.value().findings) {
        lg_tool::report("finding", to_string(summary));
      }
      continue;
    }
    if (step == "digest") {
      if (!ctl.send(MessageType::StateDigestRequest, {})) {
        break;
      }
      auto frame = ctl.expect(MessageType::StateDigestReply);
      if (!frame.has_value()) {
        break;
      }
      auto reply = decode_state_digest_reply(frame.value().payload, default_limits());
      if (!reply.has_value()) {
        break;
      }
      lg_tool::report("observations", reply.value().observation_count);
      lg_tool::report("lineage", reply.value().lineage_count);
      lg_tool::report("retained_findings", reply.value().finding_count);
      lg_tool::report("state_digest", reply.value().store_digest.to_hex());
      continue;
    }
    if (step == "restart-report") {
      if (!ctl.send(MessageType::RestartReportRequest, {})) {
        break;
      }
      auto frame = ctl.expect(MessageType::RestartReportReply);
      if (!frame.has_value()) {
        break;
      }
      auto reply = decode_restart_report(frame.value().payload, default_limits());
      if (!reply.has_value()) {
        break;
      }
      lg_tool::report("report_boot", reply.value().boot.to_string());
      lg_tool::report("report_incarnation", reply.value().incarnation.to_string());
      lg_tool::report("report_epoch", reply.value().epoch.to_string());
      lg_tool::report("torn_tail", reply.value().torn_tail_recovered ? "1" : "0");
      lg_tool::report("fenced_findings", reply.value().fenced_findings);
      lg_tool::report("retained_findings", reply.value().retained_findings);
      continue;
    }
    if (step == "withdraw") {
      ByteWriter writer;
      const std::uint64_t raw = args.get_u64("finding", 0);
      writer.u64(raw);
      if (!ctl.send(MessageType::FindingWithdraw, std::move(writer).take())) {
        break;
      }
      auto frame = ctl.expect(MessageType::ConfigurationAccepted);
      if (!frame.has_value()) {
        break;
      }
      lg_tool::report("withdrawn", "1");
      continue;
    }
    if (step == "fence-advance") {
      ByteWriter writer;
      FenceVector advanced = ctl.fence;
      advanced.forwarding = ForwardingGeneration::from_value(ctl.fence.forwarding.value() + 1U);
      writer.raw(encode_fence(advanced));
      writer.u8(static_cast<std::uint8_t>(ReasonCode::FindingFencedByGenerationChange));
      writer.u64(args.get_u64("now", 100));
      if (!ctl.send(MessageType::FenceAdvance, std::move(writer).take())) {
        break;
      }
      auto frame = ctl.expect(MessageType::ConfigurationAccepted);
      if (!frame.has_value()) {
        break;
      }
      ctl.fence.forwarding = advanced.forwarding;
      lg_tool::report("fence_advanced", ctl.fence.to_string());
      continue;
    }
    if (step == "shutdown") {
      (void)ctl.connection.send_frame(MessageType::Bye, ctl.session, ctl.sequence++, {}, 2000U);
      lg_tool::report("bye", "1");
      continue;
    }
    lg_tool::report("unknown_step", step);
    ctl.ok = false;
    break;
  }

  (void)ctl.connection.close();
  return ctl.ok ? 0 : 5;
}
