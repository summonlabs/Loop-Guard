#include <algorithm>
#include <chrono>

#include "fixtures.hpp"
#include "harness.hpp"
#include "loop_guard/detect.hpp"

namespace {

using namespace lg_test;
using namespace loop_guard;

struct Measurement {
  std::size_t nodes = 0;
  std::size_t edges = 0;
  std::uint64_t steps = 0;
  std::uint64_t cycles = 0;
  std::uint64_t microseconds = 0;
  LoopOutcome outcome = LoopOutcome::Invalid;
  std::size_t witnesses = 0;
};

Measurement measure_ring(std::size_t nodes, Limits limits) {
  RingScenario ring = make_ring(nodes);
  Scenario& scenario = ring.scenario;
  const TrafficSelectorId selector = scenario.selector_id(0);
  for (const ForwardingEdgeId edge : ring.edges) {
    (void)scenario.observe_present(edge, {selector});
  }
  const auto started = std::chrono::steady_clock::now();
  DetectionRequest request;
  request.topology = &scenario.topology();
  request.ledger = &scenario.ledger();
  request.fence = scenario.fence();
  request.now = scenario.now();
  const LoopDetector detector(limits);
  const auto assessment = detector.assess(request);
  const auto finished = std::chrono::steady_clock::now();
  Measurement measurement;
  measurement.nodes = nodes;
  measurement.edges = scenario.topology().edges().size();
  measurement.microseconds = static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::microseconds>(finished - started).count());
  if (assessment.has_value()) {
    measurement.steps = assessment.value().counters.steps_used;
    measurement.cycles = assessment.value().counters.cycles_enumerated;
    measurement.outcome = assessment.value().outcome;
    measurement.witnesses = assessment.value().witnesses.size();
  }
  return measurement;
}

}  // namespace

LG_TEST(scale, large_cyclic_graphs_stay_bounded_and_correct) {
  // The witness-length bound is raised to cover the ring, because a cycle longer than the
  // bound cannot produce a witness and would be reported as INDETERMINATE by design.
  const std::vector<std::size_t> sizes = {64, 128, 256};
  std::vector<Measurement> measurements;
  for (const std::size_t size : sizes) {
    Limits limits = default_limits();
    limits.max_witness_hops = static_cast<std::uint32_t>(size);
    const Measurement measurement = measure_ring(size, limits);
    measurements.push_back(measurement);
    LG_CHECK_EQ(measurement.outcome, LoopOutcome::LoopConfirmed);
    LG_CHECK_EQ(measurement.witnesses, std::size_t{1});
    LG_CHECK_EQ(measurement.cycles, std::uint64_t{1});
    LG_CHECK(measurement.steps > 0U);
    // Work is bounded by the graph size times the witness-length bound, never by an
    // unbounded search.
    LG_CHECK(measurement.steps <=
             static_cast<std::uint64_t>(measurement.edges) * static_cast<std::uint64_t>(size) +
                 4096U);
  }
  // Report ratios so an accidental superlinear term is visible.
  for (std::size_t index = 1; index < measurements.size(); ++index) {
    const double step_ratio = static_cast<double>(measurements[index].steps) /
                              static_cast<double>(measurements[index - 1].steps);
    const double size_ratio = static_cast<double>(measurements[index].nodes) /
                              static_cast<double>(measurements[index - 1].nodes);
    // Steps grow at most quadratically in the ring size (the enumeration is bounded by
    // nodes x witness bound), which is what the ratio bound below encodes.
    LG_CHECK(step_ratio <= size_ratio * size_ratio * 4.0);
  }
}

LG_TEST(scale, tight_budget_reports_indeterminate_rather_than_no_loop) {
  Limits limits = default_limits();
  limits.max_search_steps = 64;
  const Measurement measurement = measure_ring(4096, limits);
  LG_CHECK_EQ(measurement.outcome, LoopOutcome::Indeterminate);
  LG_CHECK(measurement.witnesses == 0U);
}

LG_TEST(scale, dense_acyclic_graph_with_evidence_proves_no_loop) {
  // A layered DAG with a large fan-out, fully observed: no cycle can exist, and the
  // exact existence proof must say so without enumerating anything.
  Scenario scenario;
  const DomainId domain = DomainId::from_value(1);
  const std::size_t layers = 24;
  const std::size_t width = 24;
  std::vector<std::vector<ResourceId>> nodes(layers);
  for (std::size_t layer = 0; layer < layers; ++layer) {
    for (std::size_t index = 0; index < width; ++index) {
      nodes[layer].push_back(scenario.add_resource(domain));
    }
  }
  const TrafficSelectorId selector = scenario.add_selector();
  for (std::size_t layer = 0; layer + 1U < layers; ++layer) {
    for (std::size_t from = 0; from < width; ++from) {
      for (std::size_t to = 0; to < width; ++to) {
        if ((from + to) % 2U == layer % 2U) {
          (void)scenario.add_edge(nodes[layer][from], nodes[layer + 1U][to], LinkState::Up,
                                  {selector});
        }
      }
    }
  }
  LG_CHECK(scenario.install().is_ok());
  scenario.observe_all_present();
  const auto assessment = scenario.assess();
  LG_REQUIRE(assessment.has_value());
  LG_CHECK_EQ(assessment.value().outcome, LoopOutcome::NoLoop);
  LG_CHECK_EQ(assessment.value().counters.cycles_enumerated, std::uint64_t{0});
  LG_CHECK(scenario.topology().edges().size() > 6000U);
}

LG_TEST(scale, many_selectors_scale_linearly) {
  const std::vector<std::size_t> selector_counts = {1, 8, 64};
  std::vector<std::uint64_t> steps;
  for (const std::size_t count : selector_counts) {
    RingScenario ring = make_ring(64, count);
    Scenario& scenario = ring.scenario;
    std::vector<TrafficSelectorId> selectors;
    for (std::size_t index = 0; index < count; ++index) {
      selectors.push_back(scenario.selector_id(index));
    }
    for (const ForwardingEdgeId edge : ring.edges) {
      (void)scenario.observe_present(edge, selectors);
    }
    const auto assessment = scenario.assess();
    LG_REQUIRE(assessment.has_value());
    LG_CHECK_EQ(assessment.value().outcome, LoopOutcome::LoopConfirmed);
    steps.push_back(assessment.value().counters.steps_used);
  }
  for (std::size_t index = 1; index < steps.size(); ++index) {
    const double ratio = static_cast<double>(steps[index]) / static_cast<double>(steps[index - 1]);
    const double selector_ratio = static_cast<double>(selector_counts[index]) /
                                  static_cast<double>(selector_counts[index - 1]);
    LG_CHECK(ratio <= selector_ratio * 4.0);
  }
}
