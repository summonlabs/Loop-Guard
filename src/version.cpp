#include "loop_guard/version.hpp"

namespace loop_guard {
namespace {

std::string build_identity_text() {
  std::string text;
#if defined(NDEBUG)
  text = "release";
#else
  text = "debug";
#endif
#if defined(__clang__)
  text += "/clang";
#elif defined(_MSC_VER)
  text += "/msvc";
#elif defined(__GNUC__)
  text += "/gcc";
#else
  text += "/unknown-compiler";
#endif
  return text;
}

}  // namespace

const std::string& version_string() {
  static const std::string kVersion = "1.0.0";
  return kVersion;
}

const std::string& build_identity() {
  static const std::string kBuild = build_identity_text();
  return kBuild;
}

}  // namespace loop_guard
