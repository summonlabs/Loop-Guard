// Loop Guard example: overlapping loops and one shared target. SYNTHETIC fixtures only; no hardware is involved.
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
  const ResourceId shared = scenario.add_resource(domain, true, 1);
  const ResourceId left = scenario.add_resource(domain, true, 4);
  const ResourceId right = scenario.add_resource(domain, true, 9);
  const TrafficSelectorId selector = scenario.add_selector();
  (void)scenario.add_edge(shared, left, LinkState::Up, {selector});
  (void)scenario.add_edge(left, shared, LinkState::Up, {selector});
  (void)scenario.add_edge(shared, right, LinkState::Up, {selector});
  (void)scenario.add_edge(right, shared, LinkState::Up, {selector});
  (void)scenario.install();
  scenario.observe_all_present();
  const auto assessment = scenario.assess().value();
  std::cout << "witnesses=" << assessment.witnesses.size() << "\n";
  ContainmentPolicy policy;
  policy.generation = scenario.fence().policy;
  policy.max_targets = 4;
  policy.max_total_cost = 64;
  policy.eligible_kinds = {ResourceKind::Switch};
  const ContainmentPlanner planner;
  const auto plan = planner.plan(assessment, scenario.topology(), policy, scenario.now()).value();
  std::cout << plan.to_text();
  return plan.outcome == ContainmentOutcome::PlanOptimal && plan.targets.size() == 1U ? 0 : 1;

}
