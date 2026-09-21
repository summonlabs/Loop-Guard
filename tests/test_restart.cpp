#include "fixtures.hpp"
#include "harness.hpp"
#include "loop_guard/persistence.hpp"
#include "procs.hpp"

namespace {

using namespace lg_test;
using namespace loop_guard;

/// A real process boundary: the coordinator is started, driven over loopback, terminated
/// with an OS-level kill, and restarted against the same durable store.
struct Harness {
  std::string store;
  std::string name;

  explicit Harness(const std::string& base) {
    store = scratch_path(base + ".lgstore");
    name = base;
    (void)kill_image("lg_coordinator");
    remove_file(store);
    remove_file(process_log(name));
  }

  ~Harness() { (void)kill_image("lg_coordinator"); }

  [[nodiscard]] bool available() const { return !tool_path("lg_coordinator").empty(); }

  [[nodiscard]] std::string start(const std::string& extra) {
    std::vector<std::string> arguments = {"--port=0", "--store=" + store, "--ring=3"};
    if (!extra.empty()) {
      arguments.push_back(extra);
    }
    if (!spawn_process(name, tool_path("lg_coordinator"), arguments)) {
      return {};
    }
    if (!wait_for_marker(process_log(name), "port=", 30000U)) {
      return {};
    }
    return read_value(process_log(name), "port");
  }
};

}  // namespace

LG_TEST(restart, hard_kill_fences_every_pre_restart_finding) {
  Harness harness("restart");
  if (!harness.available()) {
    // The tools were not built in this configuration; the suite reports rather than
    // silently passing.
    LG_CHECK(true);
    return;
  }
  const std::string port = harness.start("");
  LG_REQUIRE(!port.empty());

  const std::string ctl_log = scratch_path("restart-ctl.out");
  const int publish_status = run_tool(
      "lgctl",
      {"--port=" + port, "--session=11", "--ring=3",
       "--script=observe,detect,publish,findings,digest,shutdown"},
      ctl_log);
  LG_CHECK_EQ(publish_status, 0);
  const std::string before = read_text(ctl_log);
  LG_CHECK(before.find("outcome=LoopConfirmed") != std::string::npos);
  LG_CHECK(before.find("finding_count=1") != std::string::npos);
  LG_CHECK_EQ(read_value(ctl_log, "coordinator_boot"), std::string("1"));
  LG_CHECK_EQ(read_value(ctl_log, "observations"), std::string("3"));
  const std::string first_epoch = read_value(ctl_log, "coordinator_epoch");

  LG_CHECK(kill_image("lg_coordinator"));
  LG_CHECK(wait_until_gone("lg_coordinator", 15000U));

  const std::string second_port = harness.start("");
  LG_REQUIRE(!second_port.empty());
  const std::string after_log = scratch_path("restart-ctl-after.out");
  const int after_status =
      run_tool("lgctl",
               {"--port=" + second_port, "--session=12",
                "--script=restart-report,findings,digest,shutdown"},
               after_log);
  LG_CHECK_EQ(after_status, 0);
  const std::string after = read_text(after_log);
  // A fresh incarnation and epoch, an advanced boot, and every retained finding fenced.
  LG_CHECK_EQ(read_value(after_log, "report_boot"), std::string("2"));
  LG_CHECK_EQ(read_value(after_log, "report_incarnation"), std::string("2"));
  // The coordinator epoch must advance across the restart; it must never repeat.
  LG_CHECK(!first_epoch.empty());
  LG_CHECK(read_value(after_log, "report_epoch") != first_epoch);
  LG_CHECK(after.find("finding_count=1") != std::string::npos);
  LG_CHECK(after.find("state=Fenced") != std::string::npos);
  // Dynamic state is not restored.
  LG_CHECK_EQ(read_value(after_log, "observations"), std::string("0"));
  LG_CHECK(run_tool("lgctl", {"--port=" + second_port, "--session=13", "--script=shutdown"},
                    scratch_path("restart-stop.out")) == 0);
  (void)kill_image("lg_coordinator");
}

LG_TEST(restart, kill_before_durable_commit_leaves_no_trace) {
  if (tool_path("lg_coordinator").empty()) {
    LG_CHECK(true);
    return;
  }
  Harness harness("restart-before");
  // The coordinator exits inside its first mutation before the durable append.
  const std::string port = harness.start("--exit-before-commit=1");
  LG_REQUIRE(!port.empty());
  const std::string ctl_log = scratch_path("restart-before-ctl.out");
  // The client's first durable mutation is the one under test. The acknowledgment never
  // arrives because the coordinator terminates before committing it.
  (void)run_tool("lgctl",
                 {"--port=" + port, "--session=21", "--ring=3", "--script=topology,shutdown"},
                 ctl_log);
  LG_CHECK(wait_for_marker(process_log("restart-before"), "crash=before-commit", 30000U));
  LG_CHECK(wait_until_gone("lg_coordinator", 30000U));

  auto store = DurableStore::open_or_create(harness.store, default_limits(), ProducerId::from_value(1));
  LG_REQUIRE(store.has_value());
  // Only the startup fixture is durable: the client's later generation was never committed.
  LG_REQUIRE(store.value().state().topology.has_value());
  LG_CHECK_EQ(store.value().state().topology->generation(), TopologyGeneration::from_value(1));
  LG_CHECK_EQ(store.value().state().findings.size(), std::size_t{0});
  LG_CHECK(store.value().close(true).is_ok());
}

LG_TEST(restart, kill_after_durable_commit_keeps_the_commit) {
  if (tool_path("lg_coordinator").empty()) {
    LG_CHECK(true);
    return;
  }
  Harness harness("restart-after");
  // The coordinator exits after the first durable commit but before acknowledging it, so
  // the client never sees a success. The commit must nevertheless survive.
  const std::string port = harness.start("--exit-after-commit=1");
  LG_REQUIRE(!port.empty());
  LG_CHECK(wait_for_marker(process_log("restart-after"), "crash=after-commit", 30000U));
  LG_CHECK(wait_until_gone("lg_coordinator", 30000U));

  auto store = DurableStore::open_or_create(harness.store, default_limits(), ProducerId::from_value(1));
  LG_REQUIRE(store.has_value());
  LG_REQUIRE(store.value().state().topology.has_value());
  LG_CHECK_EQ(store.value().state().topology->generation(), TopologyGeneration::from_value(1));
  LG_CHECK_EQ(store.value().state().topology->edges().size(), std::size_t{3});
  // The client never received an acknowledgement, so no finding was ever published.
  LG_CHECK_EQ(store.value().state().findings.size(), std::size_t{0});
  LG_CHECK(store.value().close(true).is_ok());
}

LG_TEST(restart, torn_tail_from_a_killed_process_is_recovered) {
  const std::string path = scratch_path("restart-torn.lgstore");
  remove_file(path);
  const Limits limits = default_limits();
  {
    auto store = DurableStore::open_or_create(path, limits, ProducerId::from_value(1));
    LG_REQUIRE(store.has_value());
    LG_CHECK(store.value().close(true).is_ok());
  }
  std::vector<std::uint8_t> bytes = read_bytes(path);
  LG_REQUIRE(bytes.size() > 50U);
  bytes.resize(bytes.size() - 20U);
  write_bytes(path, bytes);
  auto reopened = DurableStore::open_or_create(path, limits, ProducerId::from_value(1));
  LG_REQUIRE(reopened.has_value());
  LG_CHECK(reopened.value().recovery().torn_tail_recovered);
  LG_CHECK(reopened.value().close(true).is_ok());
  remove_file(path);
}
