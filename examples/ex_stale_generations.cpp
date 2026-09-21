// Loop Guard example: generation advance stales prior witnesses. SYNTHETIC fixtures only; no hardware is involved.
#include <cstdio>
#include <iostream>
#include <string>
#include <utility>

#include "fixtures.hpp"
#include "loop_guard/containment.hpp"
#include "loop_guard/detect.hpp"
#include "loop_guard/persistence.hpp"
#include "loop_guard/runtime.hpp"
#include "loop_guard/witness.hpp"
#include "tool_common.hpp"

using namespace loop_guard;
using lg_test::make_ring;
using lg_test::RingScenario;
using lg_test::Scenario;

int main() {

  RuntimeConfig config;
  config.producer = ProducerId::from_value(1);
  config.origin = EvidenceOrigin::Synthetic;
  auto runtime = std::move(Runtime::open(config).value());
  (void)runtime.set_topology(lg_tool::synthetic_ring(3, 1), 0);
  TopologyDefinition topology = runtime.topology().value();
  const FenceVector fence = runtime.fence();
  std::uint64_t sequence = 0;
  for (const ForwardingEdge& edge : topology.edges()) {
    (void)runtime.submit_observation(lg_tool::synthetic_observation(
        topology, edge.id, EvidenceClass::Present, edge.id.value(), 2, ++sequence, fence,
        ProducerKind::SyntheticFixture, EvidenceOrigin::Synthetic), 0);
  }
  const auto before = runtime.detect(100).value();
  auto finding = runtime.publish_finding(before, 100);
  std::cout << "before=" << to_string(before.outcome) << "\n";
  // A new topology generation arrives; the observation set is not re-bound.
  topology.set_generation(TopologyGeneration::from_value(2));
  (void)runtime.set_topology(std::move(topology), 200);
  const auto after = runtime.detect(300).value();
  std::cout << "after=" << to_string(after.outcome) << "\n";
  const auto stored = runtime.find_finding(finding.value().id);
  std::cout << "finding_state=" << to_string(stored.value().state) << "\n";
  return after.outcome != LoopOutcome::LoopConfirmed && stored.value().state == FindingState::Stale
             ? 0
             : 1;

}
