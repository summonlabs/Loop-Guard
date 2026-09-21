// Loop Guard example: bounded containment never disables unrelated forwarding. SYNTHETIC fixtures only; no hardware is involved.
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

  Scenario scenario;
  const DomainId domain = DomainId::from_value(1);
  const ResourceId a = scenario.add_resource(domain, true, 3);
  const ResourceId b = scenario.add_resource(domain, true, 1);
  const ResourceId c = scenario.add_resource(domain, true, 1);
  const ResourceId spare = scenario.add_resource(domain, true, 1);
  const TrafficSelectorId flow = scenario.add_selector();
  const TrafficSelectorId other = scenario.add_selector();
  (void)scenario.add_edge(a, b, LinkState::Up, {flow, other});
  (void)scenario.add_edge(b, c, LinkState::Up, {flow, other});
  (void)scenario.add_edge(c, a, LinkState::Up, {flow, other});
  (void)scenario.add_edge(c, spare, LinkState::Up, {flow, other});
  (void)scenario.install();
  scenario.observe_all_present();
  const auto assessment = scenario.assess().value();
  ContainmentPolicy policy;
  policy.generation = scenario.fence().policy;
  policy.max_targets = 4;
  policy.max_total_cost = 64;
  policy.eligible_kinds = {ResourceKind::Switch};
  const ContainmentPlanner planner;
  const auto plan = planner.plan(assessment, scenario.topology(), policy, scenario.now()).value();
  std::cout << plan.to_text();
  const auto shadow = apply_containment_shadow(scenario.topology(), plan).value();
  std::size_t untouched = 0;
  for (const ForwardingEdge& edge : scenario.topology().edges()) {
    const ForwardingEdge* after = shadow.find_edge(edge.id);
    if (after != nullptr && after->admitted_selectors == edge.admitted_selectors) {
      ++untouched;
    }
  }
  std::cout << "edges_untouched=" << untouched << "\n";
  return plan.authorizes_action() && untouched >= 1U ? 0 : 1;

}
