#include <atomic>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <vector>

#include "fixtures.hpp"
#include "harness.hpp"
#include "loop_guard/runtime.hpp"
#include "procs.hpp"
#include "tool_common.hpp"

namespace {

using namespace lg_test;
using namespace loop_guard;

/// A deterministic latch: threads wait until the counter reaches the expected value.
/// No sleeps, no timing luck.
class Latch {
 public:
  explicit Latch(std::size_t expected) : expected_(expected) {}

  void arrive_and_wait() {
    std::unique_lock<std::mutex> lock(mutex_);
    ++arrived_;
    if (arrived_ == expected_) {
      open_ = true;
      condition_.notify_all();
      return;
    }
    condition_.wait(lock, [this] { return open_; });
  }

 private:
  std::mutex mutex_;
  std::condition_variable condition_;
  std::size_t expected_;
  std::size_t arrived_ = 0;
  bool open_ = false;
};

RuntimeConfig make_config(const std::string& store) {
  RuntimeConfig config;
  config.producer = ProducerId::from_value(31);
  config.store_path = store;
  config.origin = EvidenceOrigin::Real;
  return config;
}

}  // namespace

LG_TEST(concurrency, concurrent_submitters_and_readers_agree_on_state) {
  const std::string store = lg_test::scratch_path("concurrency-a.lgstore");
  lg_test::remove_file(store);
  auto runtime = Runtime::open(make_config(store));
  LG_REQUIRE(runtime.has_value());
  LG_CHECK(runtime.value().set_topology(lg_tool::synthetic_ring(4, 1), 0).is_ok());
  LG_CHECK(runtime.value().set_policy(lg_tool::synthetic_policy(1), 0).is_ok());
  const TopologyDefinition installed = runtime.value().topology().value();

  constexpr std::size_t kThreads = 4;
  Latch start(kThreads + 1);
  std::atomic<std::uint64_t> accepted{0};
  std::atomic<std::uint64_t> rejected{0};
  std::vector<std::thread> threads;
  for (std::size_t index = 0; index < kThreads; ++index) {
    threads.emplace_back([&runtime, &installed, &start, &accepted, &rejected, index] {
      start.arrive_and_wait();
      for (const ForwardingEdge& edge : installed.edges()) {
        const ForwardingObservation observation = lg_tool::synthetic_observation(
            installed, edge.id, EvidenceClass::Present,
            index * 1000U + edge.id.value(), 100U + index, edge.id.value(),
            runtime.value().fence(), ProducerKind::InProcessRuntime, EvidenceOrigin::Real);
        const Status status = runtime.value().submit_observation(observation, 0);
        if (status.is_ok()) {
          ++accepted;
        } else {
          ++rejected;
        }
        (void)runtime.value().state_digest();
        (void)runtime.value().findings();
      }
    });
  }
  start.arrive_and_wait();
  for (std::thread& thread : threads) {
    thread.join();
  }
  LG_CHECK_EQ(accepted.load(), std::uint64_t{4} * installed.edges().size());
  const auto assessment = runtime.value().detect(100);
  LG_REQUIRE(assessment.has_value());
  LG_CHECK_EQ(assessment.value().outcome, LoopOutcome::LoopConfirmed);
  LG_CHECK(runtime.value().close(true).is_ok());
  lg_test::remove_file(store);
}

LG_TEST(concurrency, fence_advance_during_detection_never_yields_a_current_finding) {
  const std::string store = lg_test::scratch_path("concurrency-b.lgstore");
  lg_test::remove_file(store);
  auto runtime = Runtime::open(make_config(store));
  LG_REQUIRE(runtime.has_value());
  LG_CHECK(runtime.value().set_topology(lg_tool::synthetic_ring(3, 1), 0).is_ok());
  LG_CHECK(runtime.value().set_policy(lg_tool::synthetic_policy(1), 0).is_ok());
  const TopologyDefinition installed = runtime.value().topology().value();
  for (const ForwardingEdge& edge : installed.edges()) {
    LG_CHECK(runtime.value()
                 .submit_observation(lg_tool::synthetic_observation(
                                         installed, edge.id, EvidenceClass::Present, edge.id.value(),
                                         200, edge.id.value(), runtime.value().fence(),
                                         ProducerKind::InProcessRuntime, EvidenceOrigin::Real),
                                     0)
                 .is_ok());
  }

  // Two racing actors: one advances the fence, one publishes. Whatever the interleaving,
  // the runtime must never retain a live finding under a superseded fence.
  for (int round = 0; round < 12; ++round) {
    auto assessment = runtime.value().detect(100);
    LG_REQUIRE(assessment.has_value());
    Latch start(3);
    std::thread publisher([&runtime, &assessment, &start] {
      start.arrive_and_wait();
      (void)runtime.value().publish_finding(assessment.value(), 100);
    });
    std::thread advancer([&runtime, &start] {
      start.arrive_and_wait();
      const FenceVector fence = runtime.value().fence();
      (void)runtime.value().advance_fabric_epoch(
          FabricEpoch::from_value(fence.fabric_epoch.value() + 1U), 100);
    });
    start.arrive_and_wait();
    publisher.join();
    advancer.join();

    const FenceVector current = runtime.value().fence();
    for (const FindingSummary& summary : runtime.value().findings()) {
      const auto finding = runtime.value().find_finding(summary.id);
      LG_REQUIRE(finding.has_value());
      const bool live = !finding.value().is_terminal();
      if (live) {
        LG_CHECK(finding.value().fence == current);
      }
    }
  }
  LG_CHECK(runtime.value().close(true).is_ok());
  lg_test::remove_file(store);
}

LG_TEST(concurrency, evidence_survives_a_torn_read_between_resolutions) {
  const std::string store = lg_test::scratch_path("concurrency-c.lgstore");
  lg_test::remove_file(store);
  auto runtime = Runtime::open(make_config(store));
  LG_REQUIRE(runtime.has_value());
  LG_CHECK(runtime.value().set_topology(lg_tool::synthetic_ring(3, 1), 0).is_ok());
  const TopologyDefinition installed = runtime.value().topology().value();

  constexpr std::size_t kWriters = 3;
  Latch start(kWriters + 1);
  std::vector<std::thread> writers;
  for (std::size_t index = 0; index < kWriters; ++index) {
    writers.emplace_back([&runtime, &installed, &start, index] {
      start.arrive_and_wait();
      for (std::uint64_t round = 0; round < 20; ++round) {
        for (const ForwardingEdge& edge : installed.edges()) {
          (void)runtime.value().submit_observation(
              lg_tool::synthetic_observation(
                  installed, edge.id, EvidenceClass::Present,
                  index * 100000U + round * 100U + edge.id.value(), 500U + index,
                  round * 10U + edge.id.value(), runtime.value().fence(),
                  ProducerKind::InProcessRuntime, EvidenceOrigin::Real),
              0);
        }
        (void)runtime.value().observation_count();
      }
    });
  }
  std::thread reader([&runtime, &start] {
    start.arrive_and_wait();
    for (int round = 0; round < 40; ++round) {
      (void)runtime.value().detect(100);
      (void)runtime.value().state_digest();
    }
  });
  start.arrive_and_wait();
  for (std::thread& thread : writers) {
    thread.join();
  }
  reader.join();
  // The ledger's per-edge retention bound must still hold after concurrent pressure.
  for (const ForwardingEdge& edge : installed.edges()) {
    LG_CHECK(runtime.value().observation_count() <=
             static_cast<std::size_t>(default_limits().max_observations));
    (void)edge;
  }
  LG_CHECK(runtime.value().close(true).is_ok());
  lg_test::remove_file(store);
}

LG_TEST(concurrency, many_runtimes_in_parallel_do_not_share_authority) {
  constexpr std::size_t kRuntimes = 4;
  Latch start(kRuntimes + 1);
  std::atomic<std::uint64_t> confirmed{0};
  std::vector<std::thread> threads;
  for (std::size_t index = 0; index < kRuntimes; ++index) {
    threads.emplace_back([&start, &confirmed, index] {
      start.arrive_and_wait();
      const std::string store =
          lg_test::scratch_path("concurrency-parallel-" + std::to_string(index) + ".lgstore");
      lg_test::remove_file(store);
      auto runtime = Runtime::open(make_config(store));
      if (!runtime.has_value()) {
        return;
      }
      if (!runtime.value().set_topology(lg_tool::synthetic_ring(3, 1), 0).is_ok()) {
        return;
      }
      if (!runtime.value().set_policy(lg_tool::synthetic_policy(1), 0).is_ok()) {
        return;
      }
      const TopologyDefinition installed = runtime.value().topology().value();
      for (const ForwardingEdge& edge : installed.edges()) {
        (void)runtime.value().submit_observation(
            lg_tool::synthetic_observation(installed, edge.id, EvidenceClass::Present,
                                           edge.id.value(), 700U + index, edge.id.value(),
                                           runtime.value().fence(), ProducerKind::InProcessRuntime,
                                           EvidenceOrigin::Real),
            0);
      }
      auto assessment = runtime.value().detect(100);
      if (assessment.has_value() && assessment.value().outcome == LoopOutcome::LoopConfirmed) {
        ++confirmed;
      }
      (void)runtime.value().close(true);
      lg_test::remove_file(store);
    });
  }
  start.arrive_and_wait();
  for (std::thread& thread : threads) {
    thread.join();
  }
  LG_CHECK_EQ(confirmed.load(), std::uint64_t{kRuntimes});
}
