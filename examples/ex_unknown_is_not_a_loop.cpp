// Loop Guard example: UNKNOWN is never a confirmed loop. SYNTHETIC fixtures only; no hardware is involved.
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
  const TopologyDefinition topology = runtime.topology().value();
  const FenceVector fence = runtime.fence();
  (void)runtime.submit_observation(lg_tool::synthetic_observation(
      topology, topology.edges()[0].id, EvidenceClass::Unknown, 1, 2, 1, fence,
      ProducerKind::SyntheticFixture, EvidenceOrigin::Synthetic), 0);
  const auto assessment = runtime.detect(100).value();
  std::cout << "outcome=" << to_string(assessment.outcome) << "\n";
  std::cout << assessment.to_text();
  const auto finding = runtime.publish_finding(assessment, 100);
  std::cout << "publish_refused=" << (finding.has_value() ? 0 : 1) << "\n";
  return assessment.outcome == LoopOutcome::Unknown && !finding.has_value() ? 0 : 1;

}
