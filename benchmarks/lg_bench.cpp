// lg_bench - completed-work benchmark for Loop Guard.
//
// The benchmark measures completed detections and completed containment plans, never
// submission latency. Retained state is asserted to stay bounded.
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "loop_guard/containment.hpp"
#include "loop_guard/detect.hpp"
#include "loop_guard/persistence.hpp"
#include "loop_guard/runtime.hpp"

namespace {

using namespace loop_guard;

struct TopologyFixture {
  TopologyDefinition topology;
  EvidenceLedger ledger;
  FenceVector fence;
};

TopologyFixture make_fixture(std::size_t nodes, std::size_t selectors, bool all_open) {
  TopologyBuilder builder;
  builder.set_generation(TopologyGeneration::from_value(1));
  std::vector<TrafficSelectorId> admitted;
  for (std::size_t index = 0; index < selectors; ++index) {
    TrafficSelector selector;
    selector.id = TrafficSelectorId::from_value(index + 1U);
    (void)builder.add_selector(selector);
    admitted.push_back(selector.id);
  }
  for (std::size_t index = 0; index < nodes; ++index) {
    ResourceRecord record;
    record.id = ResourceId::from_value(index + 1U);
    record.domain = DomainId::from_value(1);
    record.kind = ResourceKind::Switch;
    record.admin = AdministrativeState::Enabled;
    record.containable = true;
    record.containment_cost = 1;
    (void)builder.add_resource(record);
  }
  for (std::size_t index = 0; index < nodes; ++index) {
    ForwardingEdge edge;
    edge.id = ForwardingEdgeId::from_value(index + 1U);
    edge.from = ResourceId::from_value(index + 1U);
    edge.to = ResourceId::from_value(((index + 1U) % nodes) + 1U);
    edge.domain = DomainId::from_value(1);
    edge.link = LinkState::Up;
    edge.admitted_selectors = admitted;
    (void)builder.add_edge(edge);
  }
  TopologyFixture fixture;
  fixture.topology = builder.build().value();
  fixture.fence.topology = TopologyGeneration::from_value(1);
  fixture.fence.forwarding = ForwardingGeneration::from_value(1);
  fixture.fence.policy = PolicyGeneration::from_value(1);
  fixture.fence.fabric_epoch = FabricEpoch::from_value(1);
  fixture.fence.epoch = CoordinatorEpoch::from_value(1);
  fixture.fence.boot = BootId::from_value(1);
  std::uint64_t sequence = 0;
  for (const ForwardingEdge& edge : fixture.topology.edges()) {
    ForwardingObservation observation;
    observation.id = ObservationId::from_value(edge.id.value());
    observation.edge = edge.id;
    observation.from = edge.from;
    observation.to = edge.to;
    observation.domain = edge.domain;
    observation.klass = all_open ? EvidenceClass::Present : EvidenceClass::Absent;
    if (all_open) {
      observation.selectors = edge.admitted_selectors;
    }
    observation.topology_generation = fixture.fence.topology;
    observation.forwarding_generation = fixture.fence.forwarding;
    observation.producer = ProducerId::from_value(1);
    observation.sequence = ProducerSequence::from_value(++sequence);
    observation.lease.boot = fixture.fence.boot;
    observation.lease.epoch = fixture.fence.epoch;
    observation.lease.fabric_epoch = fixture.fence.fabric_epoch;
    observation.lease.valid_until = 0xFFFF'FFFF'FFFF'FFFFULL;
    (void)fixture.ledger.submit(observation);
  }
  return fixture;
}

std::uint64_t now_micros() {
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::microseconds>(
          std::chrono::steady_clock::now().time_since_epoch())
          .count());
}

void report(const std::string& name, std::size_t nodes, std::size_t selectors, std::uint64_t micros,
            const LoopAssessment& assessment) {
  std::printf(
      "%-28s nodes=%-6zu selectors=%-4zu outcome=%-14s witness_hops=%-4zu cycles=%-6llu "
      "steps=%-9llu us=%-8llu\n",
      name.c_str(), nodes, selectors, std::string(to_string(assessment.outcome)).c_str(),
      assessment.witnesses.empty() ? 0U : assessment.witnesses.front().hop_count(),
      static_cast<unsigned long long>(assessment.counters.cycles_enumerated),
      static_cast<unsigned long long>(assessment.counters.steps_used),
      static_cast<unsigned long long>(micros));
}

}  // namespace

int main(int argc, char** argv) {
  const bool quick = argc > 1 && std::string(argv[1]) == "--quick";
  const std::vector<std::size_t> sizes = quick ? std::vector<std::size_t>{64, 256}
                                               : std::vector<std::size_t>{64, 256, 1024, 4096};
  const std::vector<std::size_t> selector_counts = quick ? std::vector<std::size_t>{1, 16}
                                                         : std::vector<std::size_t>{1, 16, 128};
  Limits detector_limits = default_limits();
  for (const std::size_t nodes : sizes) {
    for (const std::size_t selectors : selector_counts) {
      TopologyFixture fixture = make_fixture(nodes, selectors, true);
      DetectionRequest request;
      request.topology = &fixture.topology;
      request.ledger = &fixture.ledger;
      request.fence = fixture.fence;
      request.now = 100;
      // The witness-length bound is stated explicitly. A ring longer than the bound
      // cannot produce a witness, and the benchmark reports INDETERMINATE rather than
      // claiming a confirmation it did not earn.
      Limits limits = default_limits();
      limits.max_witness_hops =
          static_cast<std::uint32_t>(std::min<std::size_t>(nodes, 256U));
      const LoopDetector bounded_detector(limits);
      const std::uint64_t started = now_micros();
      const auto assessment = bounded_detector.assess(request);
      const std::uint64_t micros = now_micros() - started;
      if (!assessment.has_value()) {
        std::printf("detection failed\n");
        return 1;
      }
      report("detect-open-cycle", nodes, selectors, micros, assessment.value());

      TopologyFixture closed = make_fixture(nodes, selectors, false);
      DetectionRequest closed_request;
      closed_request.topology = &closed.topology;
      closed_request.ledger = &closed.ledger;
      closed_request.fence = closed.fence;
      closed_request.now = 100;
      const std::uint64_t closed_started = now_micros();
      const auto closed_assessment = bounded_detector.assess(closed_request);
      const std::uint64_t closed_micros = now_micros() - closed_started;
      if (!closed_assessment.has_value()) {
        std::printf("closed detection failed\n");
        return 1;
      }
      report("detect-proven-closed", nodes, selectors, closed_micros, closed_assessment.value());

      if (assessment.value().outcome == LoopOutcome::LoopConfirmed) {
        ContainmentPolicy policy;
        policy.generation = fixture.fence.policy;
        policy.max_targets = 8;
        policy.max_total_cost = 64;
        policy.eligible_kinds = {ResourceKind::Switch};
        const ContainmentPlanner planner;
        const std::uint64_t plan_started = now_micros();
        const auto plan =
            planner.plan(assessment.value(), fixture.topology, policy, 100);
        const std::uint64_t plan_micros = now_micros() - plan_started;
        if (!plan.has_value()) {
          std::printf("plan failed\n");
          return 1;
        }
        std::printf("%-28s nodes=%-6zu selectors=%-4zu outcome=%-14s targets=%-3zu cost=%-4llu "
                    "nodes_expanded=%-8llu us=%-8llu\n",
                    "contain-plan", nodes, selectors,
                    std::string(to_string(plan.value().outcome)).c_str(),
                    plan.value().targets.size(),
                    static_cast<unsigned long long>(plan.value().total_cost),
                    static_cast<unsigned long long>(plan.value().counters.nodes_expanded),
                    static_cast<unsigned long long>(plan_micros));
      }
    }
  }

  // Retained state must stay bounded while many durable mutations happen.
  const std::string path = "bench-loopguard.store";
  std::remove(path.c_str());
  Limits limits = default_limits();
  limits.max_journal_records = 1024;
  auto store = DurableStore::open_or_create(path, limits, ProducerId::from_value(1));
  if (!store.has_value()) {
    std::printf("store open failed: %s %s\n", std::string(to_string(store.outcome())).c_str(),
                store.detail().c_str());
    return 1;
  }
  const std::uint64_t durable_started = now_micros();
  std::uint64_t committed = 0;
  for (std::uint64_t index = 1; index <= 2000; ++index) {
    LineageRecord record;
    record.sequence = AttemptSequence::from_value(index);
    record.id = LineageRecordId::from_value(index);
    record.kind = AuthorityKind::Observation;
    record.fence = store.value().state().committed_fence;
    if (!store.value().append_lineage(record).is_ok()) {
      break;
    }
    ++committed;
  }
  const std::uint64_t durable_micros = now_micros() - durable_started;
  const std::uint64_t retained = store.value().state().lineage.size();
  const std::uint64_t generation = store.value().state().store_generation;
  (void)store.value().close(true);
  std::remove(path.c_str());
  std::printf("%-28s committed=%-6llu retained=%-6llu generations=%-4llu us=%-8llu\n",
              "durable-lineage", static_cast<unsigned long long>(committed),
              static_cast<unsigned long long>(retained),
              static_cast<unsigned long long>(generation),
              static_cast<unsigned long long>(durable_micros));
  std::printf("bounded=%d\n", retained <= limits.max_retained_lineage ? 1 : 0);
  return 0;
}
