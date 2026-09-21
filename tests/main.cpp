#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include "harness.hpp"

int main(int argc, char** argv) {
  std::vector<std::string> requested;
  for (int index = 1; index < argc; ++index) {
    const std::string argument = argv[index];
    if (argument == "--suite" && index + 1 < argc) {
      requested.emplace_back(argv[++index]);
      continue;
    }
    if (argument.rfind("--suite=", 0) == 0) {
      requested.push_back(argument.substr(8));
      continue;
    }
    if (argument == "--list") {
      for (const std::string& suite : lg_test::suites()) {
        std::cout << suite << "\n";
      }
      return 0;
    }
    std::cerr << "unknown argument: " << argument << "\n";
    return 2;
  }

  std::uint64_t failed = 0;
  if (requested.empty()) {
    failed = lg_test::run_all();
  } else {
    for (const std::string& suite : requested) {
      failed += lg_test::run_suite(suite);
    }
  }
  std::cout << "assertions: " << lg_test::assertion_count()
            << ", failures: " << lg_test::failure_count() << "\n";
  std::cout.flush();
  return failed == 0 ? 0 : 1;
}
