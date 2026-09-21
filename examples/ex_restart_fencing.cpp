// Loop Guard example: restart fences every pre-restart authority. SYNTHETIC fixtures only; no hardware is involved.
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

  const std::string store = "ex_restart_fencing.lgstore";
  (void)std::remove(store.c_str());
  FindingId published;
  {
    RuntimeConfig config;
    config.producer = ProducerId::from_value(1);
    config.store_path = store;
    config.origin = EvidenceOrigin::Synthetic;
    auto runtime = std::move(Runtime::open(config).value());
    (void)runtime.set_topology(lg_tool::synthetic_ring(3, 1), 0);
    const TopologyDefinition topology = runtime.topology().value();
    const FenceVector fence = runtime.fence();
    std::uint64_t sequence = 0;
    for (const ForwardingEdge& edge : topology.edges()) {
      (void)runtime.submit_observation(lg_tool::synthetic_observation(
          topology, edge.id, EvidenceClass::Present, edge.id.value(), 2, ++sequence, fence,
          ProducerKind::SyntheticFixture, EvidenceOrigin::Synthetic), 0);
    }
    published = runtime.publish_finding(runtime.detect(100).value(), 100).value().id;
    (void)runtime.close(false);
  }
  RuntimeConfig config;
  config.producer = ProducerId::from_value(1);
  config.store_path = store;
  config.origin = EvidenceOrigin::Synthetic;
  auto runtime = std::move(Runtime::open(config).value());
  const auto restored = runtime.find_finding(published).value();
  std::cout << "boot=" << runtime.identity().boot.to_string() << "\n";
  std::cout << "restored_state=" << to_string(restored.state) << "\n";
  std::cout << "observations=" << runtime.observation_count() << "\n";
  std::cout << "topology_present=" << (runtime.topology().has_value() ? 1 : 0) << "\n";
  (void)runtime.close(true);
  (void)std::remove(store.c_str());
  return restored.state == FindingState::Fenced && runtime.observation_count() == 0 ? 0 : 1;

}
