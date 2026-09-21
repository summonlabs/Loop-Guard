// Loop Guard example: a reached proof budget yields INDETERMINATE. SYNTHETIC fixtures only; no hardware is involved.
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

  Limits limits = default_limits();
  limits.max_search_steps = 8;
  RingScenario ring = make_ring(64);
  Scenario& scenario = ring.scenario;
  const TrafficSelectorId selector = scenario.selector_id(0);
  for (const ForwardingEdgeId edge : ring.edges) {
    (void)scenario.observe_present(edge, {selector});
  }
  DetectionRequest request;
  request.topology = &scenario.topology();
  request.ledger = &scenario.ledger();
  request.fence = scenario.fence();
  request.now = scenario.now();
  const LoopDetector detector(limits);
  const auto assessment = detector.assess(request).value();
  std::cout << assessment.to_text();
  std::cout << "steps_exhausted=" << (assessment.counters.steps_exhausted ? 1 : 0) << "\n";
  return assessment.outcome == LoopOutcome::Indeterminate ? 0 : 1;

}
