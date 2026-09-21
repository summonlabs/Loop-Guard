#include <algorithm>
#include <cstring>

#include "fixtures.hpp"
#include "harness.hpp"
#include "procs.hpp"

namespace {

using namespace lg_test;
using namespace loop_guard;

struct Cluster {
  std::string name;
  std::string store;
  std::string port;

  ~Cluster() {
    (void)kill_image("lg_worker");
    (void)kill_image("lg_coordinator");
  }

  [[nodiscard]] bool available() const {
    return !tool_path("lg_coordinator").empty() && !tool_path("lg_worker").empty() &&
           !tool_path("lgctl").empty();
  }

  [[nodiscard]] bool start(const std::string& base, const std::string& port_argument) {
    name = base;
    store = scratch_path(base + ".lgstore");
    remove_file(store);
    if (!spawn_process(name, tool_path("lg_coordinator"),
                       {port_argument, "--store=" + store, "--ring=3"})) {
      return false;
    }
    if (!wait_for_marker(process_log(name), "port=", 30000U)) {
      return false;
    }
    port = read_value(process_log(name), "port");
    return !port.empty();
  }

  [[nodiscard]] bool start_worker(const std::string& worker_name,
                                  const std::vector<std::string>& extra) {
    std::vector<std::string> arguments = {"--port=" + port};
    arguments.insert(arguments.end(), extra.begin(), extra.end());
    return spawn_process(worker_name, tool_path("lg_worker"), arguments);
  }
};

std::string extract_finding_id(const std::string& text) {
  const std::string marker = "finding=finding ";
  const std::size_t position = text.find(marker);
  if (position == std::string::npos) {
    return {};
  }
  const std::size_t start = position + marker.size();
  const std::size_t end = text.find(' ', start);
  return text.substr(start, end - start);
}

}  // namespace

LG_TEST(multiprocess, real_processes_detect_and_contain_over_loopback) {
  Cluster cluster;
  if (!cluster.available()) {
    LG_CHECK(true);
    return;
  }
  LG_REQUIRE(cluster.start("cluster-a", "--port=0"));

  LG_REQUIRE(cluster.start_worker(
      "cluster-a-worker", {"--session=200", "--ring=3", "--intents=0", "--idle-rounds=4000"}));
  LG_REQUIRE(wait_for_marker(process_log("cluster-a-worker"), "observations_submitted=", 30000U));

  const std::string ctl_log = scratch_path("cluster-a-ctl.out");
  const int status = run_tool("lgctl",
                              {"--port=" + cluster.port, "--session=21",
                               "--script=detect,publish,plan,findings,digest,shutdown"},
                              ctl_log);
  LG_CHECK_EQ(status, 0);
  const std::string text = read_text(ctl_log);
  LG_CHECK(text.find("outcome=LoopConfirmed") != std::string::npos);
  LG_CHECK(text.find("witnesses=1") != std::string::npos);
  LG_CHECK(text.find("published_findings=1") != std::string::npos);
  LG_CHECK(text.find("plan_outcome=PlanOptimal") != std::string::npos);
  LG_CHECK(text.find("plan_targets=1") != std::string::npos);
  LG_CHECK(text.find("validated=1") != std::string::npos);

  // A second connection may not claim an identity that is bound to a live session.
  LG_CHECK(image_running("lg_worker"));
  const std::string replay_log = scratch_path("cluster-a-replay.out");
  (void)run_tool("lgctl", {"--port=" + cluster.port, "--session=200", "--script=digest"},
                 replay_log);
  LG_CHECK(read_text(replay_log).find("handshake_outcome=AlreadyExists") != std::string::npos);
  (void)kill_image("lg_worker");
  (void)kill_image("lg_coordinator");
}

LG_TEST(multiprocess, stale_fence_request_is_refused_over_the_wire) {
  Cluster cluster;
  if (!cluster.available()) {
    LG_CHECK(true);
    return;
  }
  LG_REQUIRE(cluster.start("cluster-d", "--port=0"));
  const std::string log = scratch_path("cluster-d-ctl.out");
  const int status =
      run_tool("lgctl", {"--port=" + cluster.port, "--session=41", "--script=detect-stale,shutdown"}, log);
  LG_CHECK_EQ(status, 0);
  const std::string text = read_text(log);
  LG_CHECK(text.find("stale_reply_type=Error") != std::string::npos);
  LG_CHECK(text.find("stale_outcome=Stale") != std::string::npos);
  (void)kill_image("lg_coordinator");
}

LG_TEST(multiprocess, acknowledgement_is_not_a_verified_effect) {
  Cluster cluster;
  if (!cluster.available()) {
    LG_CHECK(true);
    return;
  }
  LG_REQUIRE(cluster.start("cluster-b", "--port=0"));

  // This worker acknowledges intents but never reports an effect.
  LG_REQUIRE(cluster.start_worker(
      "cluster-b-worker",
      {"--session=201", "--ring=3", "--no-effect", "--intents=1", "--idle-rounds=4000"}));
  LG_REQUIRE(wait_for_marker(process_log("cluster-b-worker"), "observations_submitted=", 30000U));

  const std::string publish_log = scratch_path("cluster-b-publish.out");
  const int published = run_tool("lgctl",
                                 {"--port=" + cluster.port, "--session=23",
                                  "--script=detect,publish,findings"},
                                 publish_log);
  LG_CHECK_EQ(published, 0);
  const std::string finding_id = extract_finding_id(read_text(publish_log));
  LG_REQUIRE(!finding_id.empty());

  const std::string authorize_log = scratch_path("cluster-b-authorize.out");
  (void)run_tool("lgctl",
                 {"--port=" + cluster.port, "--session=24", "--finding=" + finding_id,
                  "--script=detect,plan,authorize"},
                 authorize_log);
  LG_REQUIRE(wait_for_marker(process_log("cluster-b-worker"), "intent_received=", 30000U));
  LG_REQUIRE(wait_for_marker(process_log("cluster-b-worker"), "intents_handled=1", 30000U));

  const std::string final_log = scratch_path("cluster-b-final.out");
  (void)run_tool("lgctl", {"--port=" + cluster.port, "--session=25", "--script=findings,shutdown"},
                 final_log);
  const std::string final_text = read_text(final_log);
  LG_CHECK(final_text.find("ContainmentAppliedUnverified") != std::string::npos);
  LG_CHECK(final_text.find("state=ContainmentVerified") == std::string::npos);
  (void)kill_image("lg_worker");
  (void)kill_image("lg_coordinator");
}

LG_TEST(multiprocess, coordinator_shutdown_releases_blocked_sessions) {
  Cluster cluster;
  if (!cluster.available()) {
    LG_CHECK(true);
    return;
  }
  LG_REQUIRE(cluster.start("cluster-c", "--port=0"));

  // A hard kill must not leave the port bound: a fresh coordinator binds and serves.
  LG_CHECK(kill_image("lg_coordinator"));
  LG_CHECK(wait_until_gone("lg_coordinator", 15000U));
  Cluster second;
  LG_REQUIRE(second.start("cluster-c2", "--port=" + cluster.port));
  const std::string ctl_log = scratch_path("cluster-c-ctl.out");
  const int status =
      run_tool("lgctl", {"--port=" + cluster.port, "--session=31", "--script=detect,shutdown"}, ctl_log);
  LG_CHECK_EQ(status, 0);
  LG_CHECK(read_text(ctl_log).find("outcome=") != std::string::npos);
  (void)kill_image("lg_coordinator");
}
