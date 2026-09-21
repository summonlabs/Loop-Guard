#include "harness.hpp"

#include <algorithm>
#include <cstdio>
#include <iostream>
#include <map>
#include <set>

#include "loop_guard/enums.hpp"

namespace lg_test {
namespace {
std::uint64_t g_failures = 0;
std::uint64_t g_assertions = 0;
std::string g_current;
}  // namespace

Registry& Registry::instance() {
  static Registry registry;
  return registry;
}

bool Registry::add(std::string suite, std::string name, std::function<void()> body) {
  cases_.push_back(TestCase{std::move(suite), std::move(name), std::move(body)});
  return true;
}

void record_failure(const char* file, int line, const std::string& message) {
  ++g_failures;
  std::cout << "  FAIL " << g_current << " (" << file << ":" << line << ") " << message << "\n";
  std::cout.flush();
}

void count_assertion() { ++g_assertions; }

std::uint64_t failure_count() { return g_failures; }
std::uint64_t assertion_count() { return g_assertions; }

std::string render(const std::string& value) { return "\"" + value + "\""; }
std::string render(const char* value) { return std::string("\"") + (value == nullptr ? "" : value) + "\""; }
std::string render(bool value) { return value ? "true" : "false"; }
std::string render(std::uint64_t value) { return std::to_string(value); }
std::string render(std::int64_t value) { return std::to_string(value); }
std::string render(std::uint32_t value) { return std::to_string(value); }
std::string render(std::int32_t value) { return std::to_string(value); }

std::vector<std::string> suites() {
  std::set<std::string> unique;
  for (const TestCase& test : Registry::instance().cases()) {
    unique.insert(test.suite);
  }
  return std::vector<std::string>(unique.begin(), unique.end());
}

std::uint64_t run_suite(const std::string& suite) {
  std::uint64_t failed = 0;
  std::uint64_t cases = 0;
  for (const TestCase& test : Registry::instance().cases()) {
    if (test.suite != suite) {
      continue;
    }
    ++cases;
    const std::uint64_t before = g_failures;
    g_current = test.suite + "." + test.name;
    try {
      test.body();
    } catch (const Abort&) {
      // The failure was already recorded by LG_REQUIRE.
    } catch (const std::exception& error) {
      record_failure(__FILE__, __LINE__,
                     std::string("unexpected exception: ") + error.what());
    } catch (...) {
      record_failure(__FILE__, __LINE__, "unexpected non-standard exception");
    }
    if (g_failures != before) {
      ++failed;
    }
  }
  std::cout << "suite " << suite << ": " << cases << " cases, " << failed << " failed\n";
  std::cout.flush();
  return failed;
}

std::uint64_t run_all() {
  std::uint64_t failed = 0;
  for (const std::string& suite : suites()) {
    failed += run_suite(suite);
  }
  return failed;
}

}  // namespace lg_test
