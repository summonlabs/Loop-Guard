// Loop Guard example: a confirmed forwarding loop. SYNTHETIC fixtures only; no hardware is involved.
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
  (void)runtime.set_topology(lg_tool::synthetic_ring(4, 1), 0);
  const TopologyDefinition topology = runtime.topology().value();
  const FenceVector fence = runtime.fence();
  std::uint64_t sequence = 0;
  for (const ForwardingEdge& edge : topology.edges()) {
    (void)runtime.submit_observation(lg_tool::synthetic_observation(
        topology, edge.id, EvidenceClass::Present, edge.id.value(), 2, ++sequence, fence,
        ProducerKind::SyntheticFixture, EvidenceOrigin::Synthetic), 0);
  }
  const auto assessment = runtime.detect(100).value();
  std::cout << assessment.to_text();
  return assessment.outcome == LoopOutcome::LoopConfirmed && !assessment.witnesses.empty() ? 0 : 1;

}
