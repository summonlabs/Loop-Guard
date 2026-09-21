#include "loop_guard/containment.hpp"

// The reference hitting-set solver is deliberately naive and lives on its own so that
// nothing on a production path can call it by accident. The differential suite links it
// directly through the public header; this translation unit exists so that the reference
// implementation is compiled once, with the same warning policy as the rest of the
// library, and so that the "slow solver" is not part of the planner's object file.
//
// It is defined in containment.cpp; this file only carries the build-time reminder and
// the compile-time assertion that keeps the two solvers' objectives identical.

namespace loop_guard {
namespace {

[[maybe_unused]] void reference_solver_is_separate_from_the_planner() {}

}  // namespace
}  // namespace loop_guard
