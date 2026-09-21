// Loop Guard - minimal, dependency-free test harness.
//
// The harness deliberately has no timeout machinery: a hang is a defect and must be
// diagnosed, not masked. Every wait in the suites is a bounded wait with an explicit
// failure, and every suite runs to completion.
#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <type_traits>
#include <vector>

#include "loop_guard/enums.hpp"

namespace lg_test {

struct TestCase {
  std::string suite;
  std::string name;
  std::function<void()> body;
};

class Registry {
 public:
  static Registry& instance();
  bool add(std::string suite, std::string name, std::function<void()> body);
  [[nodiscard]] const std::vector<TestCase>& cases() const { return cases_; }

 private:
  std::vector<TestCase> cases_;
};

/// Thrown to abort the current test case after a fatal assertion.
struct Abort {};

void record_failure(const char* file, int line, const std::string& message);
/// Counts one assertion. A function rather than a returned counter so that the macros
/// can call it without producing a discarded-value expression.
void count_assertion();
[[nodiscard]] std::uint64_t failure_count();
[[nodiscard]] std::uint64_t assertion_count();

/// Runs one suite. Returns the number of failed cases.
std::uint64_t run_suite(const std::string& suite);
/// Runs every registered case. Returns the number of failed cases.
std::uint64_t run_all();
/// Lists the registered suites.
[[nodiscard]] std::vector<std::string> suites();

struct SuiteResult {
  std::uint64_t cases = 0;
  std::uint64_t failed = 0;
  std::uint64_t assertions = 0;
};

}  // namespace lg_test

#define LG_TEST(suite_name, case_name)                                                      \
  static void suite_name##_##case_name##_body();                                            \
  namespace {                                                                               \
  const bool suite_name##_##case_name##_registered =                                        \
      ::lg_test::Registry::instance().add(#suite_name, #case_name,                          \
                                          &suite_name##_##case_name##_body);                \
  }                                                                                         \
  static void suite_name##_##case_name##_body()

#define LG_CHECK(condition)                                                              \
  do {                                                                                   \
    ::lg_test::count_assertion();                                                        \
    if (!(condition)) {                                                                  \
      ::lg_test::record_failure(__FILE__, __LINE__, "check failed: " #condition);        \
    }                                                                                    \
  } while (false)

#define LG_REQUIRE(condition)                                                            \
  do {                                                                                   \
    ::lg_test::count_assertion();                                                        \
    if (!(condition)) {                                                                  \
      ::lg_test::record_failure(__FILE__, __LINE__, "requirement failed: " #condition);  \
      throw ::lg_test::Abort{};                                                          \
    }                                                                                    \
  } while (false)

#define LG_CHECK_EQ(lhs, rhs)                                                                     \
  do {                                                                                            \
    ::lg_test::count_assertion();                                                                 \
    const auto& lg_lhs = (lhs);                                                                   \
    const auto& lg_rhs = (rhs);                                                                   \
    if (!(lg_lhs == lg_rhs)) {                                                                    \
      ::lg_test::record_failure(__FILE__, __LINE__,                                               \
                                std::string("expected equality: " #lhs " == " #rhs " (") +        \
                                    ::lg_test::render(lg_lhs) + " vs " + ::lg_test::render(lg_rhs) + \
                                    ")");                                                         \
    }                                                                                             \
  } while (false)

#define LG_CHECK_NE(lhs, rhs)                                                          \
  do {                                                                                 \
    ::lg_test::count_assertion();                                                       \
    if ((lhs) == (rhs)) {                                                               \
      ::lg_test::record_failure(__FILE__, __LINE__, "expected inequality: " #lhs " != " #rhs); \
    }                                                                                  \
  } while (false)

namespace lg_test {

/// Renders common values for failure messages. Falls back to "?" for anything else.
std::string render(const std::string& value);
std::string render(const char* value);
std::string render(bool value);
std::string render(std::uint64_t value);
std::string render(std::int64_t value);
std::string render(std::uint32_t value);
std::string render(std::int32_t value);

template <class T>
std::string render(const T& value) {
  if constexpr (requires { value.to_string(); }) {
    return value.to_string();
  } else if constexpr (std::is_enum_v<T>) {
    if constexpr (requires { loop_guard::to_string(value); }) {
      return std::string(loop_guard::to_string(value));
    } else {
      return "?";
    }
  } else if constexpr (std::is_convertible_v<T, std::uint64_t>) {
    return std::to_string(static_cast<std::uint64_t>(value));
  } else {
    return "?";
  }
}

}  // namespace lg_test
