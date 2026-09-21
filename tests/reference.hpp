// Loop Guard - independent reference implementations used only by the test suites.
//
// These are deliberately naive: they exist so that the production algorithms can be
// differential-tested against something whose correctness is obvious by inspection.
// Nothing here is on a production path.
#pragma once

#include <cstddef>
#include <utility>
#include <vector>

#include "loop_guard/containment.hpp"
#include "loop_guard/id.hpp"

namespace lg_test {

/// Every simple cycle of an adjacency matrix, up to max_length hops, each returned in
/// canonical rotation (smallest node index first). Brute force over permutations.
[[nodiscard]] std::vector<std::vector<std::size_t>> reference_simple_cycles(
    const std::vector<std::vector<bool>>& adjacency, std::size_t max_length);

/// Minimal-cost hitting set by enumerating every subset of the candidate options.
/// Ties are broken by fewest targets then lexicographically smallest sorted sequence.
/// Returns an empty vector with \p feasible set to false when no hitting set exists.
[[nodiscard]] std::vector<loop_guard::ResourceId> reference_min_hitting_set(
    const std::vector<std::vector<loop_guard::ResourceId>>& sets,
    const std::vector<std::pair<loop_guard::ResourceId, std::uint32_t>>& options, bool& feasible);

}  // namespace lg_test
