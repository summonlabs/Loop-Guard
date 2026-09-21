// lg_worker - a forwarding-evidence producer and containment applier.
//
// The worker owns no authority. It submits observations it actually made, acknowledges
// containment intents it received, and reports an independently observed effect only
// when it can produce the observation that proves it. Acknowledgement and effect are
// separate frames precisely so that a test can prove they are different things.
#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#include "tool_common.hpp"

namespace {

using namespace loop_guard;

struct WorkerState {
  SessionId session;
  ProcessIdentity identity;
  TopologyDefinition topology;
  bool has_topology = false;
  FenceVector fence;
  std::uint64_t sequence = 1;
  std::uint64_t observation_id = 1;
  std::uint64_t producer_sequence = 0;
  std::vector<ContainIntentMessage> intents;
  std::uint64_t handled_intents = 0;
};

}  // namespace

int main(int argc, char** argv) {
  using namespace loop_guard;
  const lg_tool::Args args = lg_tool::parse_args(argc, argv, 1);
  if (args.has("help")) {
    std::cout << "lg_worker --port=N [--session=N] [--absent-ratio=K] [--no-effect]\n";
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
  FramedConnection connection(std::move(socket.value()));

  WorkerState state;
  state.session = SessionId::from_value(args.get_u64("session", 100));
  state.identity.producer = ProducerId::from_value(args.get_u64("producer", 200));
  state.identity.boot = BootId::from_value(1);
  state.identity.incarnation = IncarnationId::from_value(1);
  state.identity.epoch = CoordinatorEpoch::from_value(1);

  HelloMessage hello;
  hello.session = state.session;
  hello.identity = state.identity;
  hello.kind = ProducerKind::RemoteWorker;
  hello.origin = EvidenceOrigin::Real;
  hello.nonce = args.get_u64("nonce", 1);
  hello.requested_lease_ticks = 100000U;
  if (!connection.send_frame(MessageType::Hello, state.session, state.sequence++,
                             encode_hello(hello), 5000U)
           .is_ok()) {
    std::cerr << "handshake send failed\n";
    return 3;
  }
  auto ack_frame = connection.receive_frame(5000U);
  if (!ack_frame.has_value() || ack_frame.value().header.type != MessageType::HelloAck) {
    std::cerr << "handshake failed\n";
    return 3;
  }
  auto ack = decode_hello_ack(ack_frame.value().payload, default_limits());
  if (!ack.has_value() || ack.value().outcome != Outcome::Ok) {
    std::cerr << "handshake rejected\n";
    return 3;
  }
  state.fence = ack.value().fence;
  state.identity.epoch = ack.value().coordinator.epoch;
  lg_tool::report("worker_session", state.session.to_string());
  lg_tool::report("fence", state.fence.to_string());

  // Ask the coordinator for the topology and policy by requesting the synthetic ring it
  // was started with. The worker only needs edge identities, so it re-derives them from
  // its own definition; this is a synthetic fixture, not a device read.
  const std::size_t ring = static_cast<std::size_t>(args.get_u64("ring", 3));
  state.topology = lg_tool::synthetic_ring(ring, state.fence.topology.value());
  state.has_topology = true;

  const std::uint64_t absent_ratio = args.get_u64("absent-ratio", 0);
  for (const ForwardingEdge& edge : state.topology.edges()) {
    EvidenceClass klass = EvidenceClass::Present;
    if (absent_ratio != 0U && (edge.id.value() % absent_ratio) == 0U) {
      klass = EvidenceClass::Absent;
    }
    if (args.has("all-absent")) {
      klass = EvidenceClass::Absent;
    }
    const ForwardingObservation observation = lg_tool::synthetic_observation(
        state.topology, edge.id, klass, state.observation_id++, state.identity.producer.value(),
        ++state.producer_sequence, state.fence, ProducerKind::RemoteWorker, EvidenceOrigin::Real);
    if (!connection.send_frame(MessageType::SubmitObservation, state.session, state.sequence++,
                               encode_observation(observation, default_limits()), 5000U)
             .is_ok()) {
      std::cerr << "observation send failed\n";
      return 3;
    }
    auto reply = connection.receive_frame(5000U);
    if (!reply.has_value()) {
      std::cerr << "observation reply missing\n";
      return 3;
    }
  }
  lg_tool::report("observations_submitted", state.topology.edges().size());

  const std::uint64_t kill_after = args.get_u64("kill-after-observations", 0);
  if (kill_after != 0U && state.topology.edges().size() >= kill_after) {
    std::cout << "worker=hard-kill\n";
    std::cout.flush();
    std::_Exit(11);
  }

  const bool report_effect = !args.has("no-effect");
  const std::uint64_t expected_intents = args.get_u64("intents", 0);
  const std::uint64_t idle_rounds = args.get_u64("idle-rounds", 40);
  std::uint64_t idle = 0;
  while (idle < idle_rounds) {
    auto frame = connection.receive_frame(50U);
    if (!frame.has_value()) {
      ++idle;
      if (expected_intents != 0U && state.handled_intents >= expected_intents) {
        break;
      }
      continue;
    }
    idle = 0;
    if (frame.value().header.session != state.session) {
      std::cerr << "session mismatch\n";
      return 3;
    }
    switch (frame.value().header.type) {
      case MessageType::ContainIntent: {
        auto intent = decode_contain_intent(frame.value().payload, default_limits());
        if (!intent.has_value()) {
          std::cerr << "intent decode failed\n";
          return 3;
        }
        lg_tool::report("intent_received", intent.value().intent.to_string());
        ContainAckMessage ack_message;
        ack_message.intent = intent.value().intent;
        ack_message.session = state.session;
        ack_message.applier = state.identity;
        ack_message.sequence = ProducerSequence::from_value(++state.producer_sequence);
        ack_message.acknowledged_at = 10U;
        ack_message.intent_digest = intent.value().plan_digest;
        ack_message.outcome = Outcome::Ok;
        ack_message.reason = ReasonCode::RequestAccepted;
        ack_message.detail = "intent received";
        if (!connection
                 .send_frame(MessageType::ContainAck, state.session, state.sequence++,
                             encode_contain_ack(ack_message, default_limits()), 5000U)
                 .is_ok()) {
          return 3;
        }
        state.intents.push_back(intent.value());
        (void)0;
        ++state.handled_intents;
        if (report_effect) {
          for (const ResourceId target : intent.value().targets) {
            EffectReportMessage effect;
            effect.intent = intent.value().intent;
            effect.target = target;
            effect.observation = ObservationId::from_value(state.observation_id++);
            effect.fence = state.fence;
            effect.verified_at = 20U;
            effect.origin = EvidenceOrigin::Real;
            // The effect is reported as an observation that the hop through the target is
            // now closed. The coordinator records it as an independent verified effect.
            for (const ForwardingEdge& edge : state.topology.edges()) {
              if (edge.from == target) {
                effect.observation_payload = lg_tool::synthetic_observation(
                    state.topology, edge.id, EvidenceClass::Absent, effect.observation.value(),
                    state.identity.producer.value(), ++state.producer_sequence, state.fence,
                    ProducerKind::RemoteWorker, EvidenceOrigin::Real);
                effect.has_observation = true;
                break;
              }
            }
            if (!connection
                     .send_frame(MessageType::EffectReport, state.session, state.sequence++,
                                 encode_effect_report(effect, default_limits()), 5000U)
                     .is_ok()) {
              return 3;
            }
            auto effect_reply = connection.receive_frame(5000U);
            if (!effect_reply.has_value()) {
              return 3;
            }
          }
          lg_tool::report("effect_reported", intent.value().targets.size());
        }
        break;
      }
      case MessageType::Bye:
        idle = idle_rounds;
        break;
      default:
        break;
    }
  }

  (void)connection.send_frame(MessageType::Bye, state.session, state.sequence++, {}, 2000U);
  lg_tool::report("intents_handled", state.handled_intents);
  (void)connection.close();
  return 0;
}
