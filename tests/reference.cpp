#include "reference.hpp"

#include <algorithm>
#include <numeric>

namespace lg_test {

std::vector<std::vector<std::size_t>> reference_simple_cycles(
    const std::vector<std::vector<bool>>& adjacency, std::size_t max_length) {
  const std::size_t count = adjacency.size();
  std::vector<std::vector<std::size_t>> cycles;
  if (count == 0U) {
    return cycles;
  }
  // Walk every length from 1 to max_length and every ordered node sequence. This is
  // intentionally exponential and obviously correct.
  for (std::size_t length = 1; length <= max_length && length <= count; ++length) {
    std::vector<std::size_t> sequence(length, 0U);
    const std::size_t combinations = [&]() {
      std::size_t total = 1U;
      for (std::size_t index = 0; index < length; ++index) {
        total *= count;
      }
      return total;
    }();
    for (std::size_t ordinal = 0; ordinal < combinations; ++ordinal) {
      std::size_t value = ordinal;
      for (std::size_t index = 0; index < length; ++index) {
        sequence[index] = value % count;
        value /= count;
      }
      bool distinct = true;
      for (std::size_t index = 0; index < length && distinct; ++index) {
        for (std::size_t other = index + 1; other < length; ++other) {
          if (sequence[index] == sequence[other]) {
            distinct = false;
            break;
          }
        }
      }
      if (!distinct) {
        continue;
      }
      bool closed = true;
      for (std::size_t index = 0; index < length; ++index) {
        const std::size_t from = sequence[index];
        const std::size_t to = sequence[(index + 1U) % length];
        if (!adjacency[from][to]) {
          closed = false;
          break;
        }
      }
      if (!closed) {
        continue;
      }
      // Rotate so the smallest node index is first.
      const auto smallest = std::min_element(sequence.begin(), sequence.end());
      std::rotate(sequence.begin(), smallest, sequence.end());
      if (std::find(cycles.begin(), cycles.end(), sequence) == cycles.end()) {
        cycles.push_back(sequence);
      }
    }
  }
  std::sort(cycles.begin(), cycles.end());
  return cycles;
}

std::vector<loop_guard::ResourceId> reference_min_hitting_set(
    const std::vector<std::vector<loop_guard::ResourceId>>& sets,
    const std::vector<std::pair<loop_guard::ResourceId, std::uint32_t>>& options, bool& feasible) {
  using loop_guard::ResourceId;
  feasible = false;
  std::vector<ResourceId> best;
  std::uint64_t best_cost = 0;
  const std::size_t option_count = options.size();
  if (option_count > 22U) {
    return best;
  }
  const std::uint64_t total = 1ULL << option_count;
  for (std::uint64_t mask = 0; mask < total; ++mask) {
    std::vector<ResourceId> chosen;
    std::uint64_t cost = 0;
    for (std::size_t index = 0; index < option_count; ++index) {
      if ((mask & (1ULL << index)) != 0U) {
        chosen.push_back(options[index].first);
        cost += options[index].second;
      }
    }
    std::sort(chosen.begin(), chosen.end());
    bool hits_all = true;
    for (const auto& set : sets) {
      bool hit = false;
      for (const ResourceId resource : set) {
        if (std::binary_search(chosen.begin(), chosen.end(), resource)) {
          hit = true;
          break;
        }
      }
      if (!hit) {
        hits_all = false;
        break;
      }
    }
    if (!hits_all) {
      continue;
    }
    const bool better =
        !feasible || cost < best_cost ||
        (cost == best_cost &&
         (chosen.size() < best.size() ||
          (chosen.size() == best.size() &&
           std::lexicographical_compare(chosen.begin(), chosen.end(), best.begin(), best.end()))));
    if (better) {
      best = std::move(chosen);
      best_cost = cost;
      feasible = true;
    }
  }
  return best;
}

}  // namespace lg_test
