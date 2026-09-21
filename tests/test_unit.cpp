#include <array>
#include <set>
#include <string>

#include "harness.hpp"
#include "loop_guard/core.hpp"
#include "loop_guard/digest.hpp"
#include "loop_guard/enums.hpp"
#include "loop_guard/limits.hpp"
#include "loop_guard/result.hpp"
#include "loop_guard/version.hpp"

namespace {

using namespace lg_test;
using namespace loop_guard;

template <class Enum>
void check_total_enum() {
  // Deliberately non-const so that the range checks below are runtime conditions rather
  // than constant expressions the compiler would flag.
  std::uint32_t first = static_cast<std::uint32_t>(EnumRange<Enum>::min);
  std::uint32_t last = static_cast<std::uint32_t>(EnumRange<Enum>::max);
  std::set<std::string> names;
  for (std::uint32_t raw = first; raw <= last; ++raw) {
    const auto value = enum_from_u32<Enum>(raw);
    LG_REQUIRE(value.has_value());
    const std::string name(to_string(*value));
    LG_CHECK(!name.empty());
    // Every value in the declared range has a distinct canonical token. "Invalid" is a
    // legitimate token for outcome enums; uniqueness is the invariant that matters.
    LG_CHECK(names.insert(name).second);
  }
  LG_CHECK(!enum_from_u32<Enum>(last + 1U).has_value());
  (void)first;
  (void)last;
}

}  // namespace

LG_TEST(unit, sha256_known_vectors) {
  LG_CHECK_EQ(sha256(std::string_view("")).to_hex(),
              std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
  LG_CHECK_EQ(sha256(std::string_view("abc")).to_hex(),
              std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
  LG_CHECK_EQ(sha256(std::string_view("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))
                  .to_hex(),
              std::string("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));
  std::string long_input(1000000, 'a');
  LG_CHECK_EQ(sha256(long_input).to_hex(),
              std::string("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));
}

LG_TEST(unit, digest_hex_round_trip) {
  const Digest digest = sha256(std::string_view("loop-guard"));
  const std::string hex = digest.to_hex();
  LG_CHECK_EQ(hex.size(), std::size_t{64});
  const auto parsed = Digest::from_hex(hex);
  LG_REQUIRE(parsed.has_value());
  LG_CHECK(*parsed == digest);
  LG_CHECK(!Digest::from_hex("").has_value());
  LG_CHECK(!Digest::from_hex(std::string(63, 'a')).has_value());
  LG_CHECK(!Digest::from_hex(std::string(63, 'a') + "z").has_value());
  LG_CHECK(!Digest::from_hex("0x" + hex.substr(2)).has_value());
  LG_CHECK(Digest{}.is_zero());
}

LG_TEST(unit, digest_segments_match_concatenation) {
  const std::string a = "loop";
  const std::string b = "-guard";
  const std::array<std::span<const std::uint8_t>, 2> segments = {
      std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(a.data()), a.size()),
      std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(b.data()), b.size())};
  LG_CHECK(sha256_segments(segments) == sha256(std::string_view("loop-guard")));
}

LG_TEST(unit, enum_totality_and_uniqueness) {
  check_total_enum<Outcome>();
  check_total_enum<LoopOutcome>();
  check_total_enum<EvidenceClass>();
  check_total_enum<EvidenceBinding>();
  check_total_enum<HopResolution>();
  check_total_enum<ResourceKind>();
  check_total_enum<AdministrativeState>();
  check_total_enum<LinkState>();
  check_total_enum<TrafficSelectorKind>();
  check_total_enum<ContainmentOutcome>();
  check_total_enum<TargetReason>();
  check_total_enum<AuthorityKind>();
  check_total_enum<GrantState>();
  check_total_enum<FindingState>();
  check_total_enum<FenceCause>();
  check_total_enum<EvidenceOrigin>();
  check_total_enum<ProducerKind>();
  check_total_enum<ReasonCode>();
  check_total_enum<Severity>();
}

LG_TEST(unit, flag_rendering_is_canonical) {
  LG_CHECK_EQ(assessment_flags_to_string(kAssessmentNone), std::string("None"));
  const AssessmentFlags flags = kAssessmentConflictsPresent | kAssessmentSearchLimitReached;
  LG_CHECK_EQ(assessment_flags_to_string(flags), std::string("SearchLimitReached,ConflictsPresent"));
  const AssessmentFlags complement = ~kAssessmentAllFlags;
  LG_CHECK_EQ(kAssessmentAllFlags & complement, AssessmentFlags{0});
  const PlanFlags plan_flags = kPlanProvedMinimum | kPlanUnrelatedForwardingUntouched;
  LG_CHECK_EQ(plan_flags_to_string(plan_flags), std::string("UnrelatedForwardingUntouched,ProvedMinimum"));
  LG_CHECK_EQ(plan_flags_to_string(kPlanNone), std::string("None"));
}

LG_TEST(unit, checked_arithmetic_never_wraps) {
  std::uint64_t out = 0;
  LG_CHECK(checked_add_u64(1, 2, out));
  LG_CHECK_EQ(out, std::uint64_t{3});
  LG_CHECK(!checked_add_u64(0xFFFF'FFFF'FFFF'FFFFULL, 1, out));
  LG_CHECK(checked_mul_u64(3, 4, out));
  LG_CHECK_EQ(out, std::uint64_t{12});
  LG_CHECK(!checked_mul_u64(0xFFFF'FFFF'FFFF'FFFFULL, 2, out));
  LG_CHECK(checked_mul_u64(0, 0xFFFF'FFFF'FFFF'FFFFULL, out));
  std::uint32_t narrow = 0;
  LG_CHECK(narrow_u32(0xFFFF'FFFFULL, narrow));
  LG_CHECK(!narrow_u32(0x1'0000'0000ULL, narrow));
  std::uint32_t sum = 0;
  LG_CHECK(!checked_add_u32(0xFFFF'FFFFU, 1U, sum));
}

LG_TEST(unit, strongly_typed_identifiers_are_not_interchangeable) {
  const ResourceId resource = ResourceId::from_value(5);
  const DomainId domain = DomainId::from_value(5);
  LG_CHECK(resource.value() == domain.value());
  static_assert(!std::is_convertible_v<ResourceId, DomainId>);
  static_assert(!std::is_constructible_v<DomainId, ResourceId>);
  LG_CHECK(!ResourceId{}.valid());
  LG_CHECK(ResourceId::from_value(1).valid());
  const auto parsed = ResourceId::parse("42");
  LG_REQUIRE(parsed.has_value());
  LG_CHECK_EQ(parsed->value(), std::uint64_t{42});
  LG_CHECK(!ResourceId::parse("0").has_value());
  LG_CHECK(!ResourceId::parse("").has_value());
  LG_CHECK(!ResourceId::parse("-1").has_value());
  LG_CHECK(!ResourceId::parse(" 1").has_value());
  LG_CHECK(!ResourceId::parse("18446744073709551616").has_value());
  const auto next = ResourceId::from_value(0xFFFF'FFFF'FFFF'FFFFULL).try_next();
  LG_CHECK(!next.has_value());
}

LG_TEST(unit, fence_vector_ordering_and_cause) {
  FenceVector base;
  base.topology = TopologyGeneration::from_value(1);
  base.forwarding = ForwardingGeneration::from_value(1);
  base.policy = PolicyGeneration::from_value(1);
  base.fabric_epoch = FabricEpoch::from_value(1);
  base.epoch = CoordinatorEpoch::from_value(1);
  base.boot = BootId::from_value(1);
  LG_CHECK(!base.is_zero());
  LG_CHECK_EQ(fence_cause(base, base), FenceCause::None);

  FenceVector moved = base;
  moved.topology = TopologyGeneration::from_value(2);
  LG_CHECK_EQ(fence_cause(base, moved), FenceCause::TopologyGenerationAdvanced);
  moved = base;
  moved.forwarding = ForwardingGeneration::from_value(2);
  LG_CHECK_EQ(fence_cause(base, moved), FenceCause::ForwardingGenerationAdvanced);
  moved = base;
  moved.policy = PolicyGeneration::from_value(2);
  LG_CHECK_EQ(fence_cause(base, moved), FenceCause::PolicyGenerationAdvanced);
  moved = base;
  moved.fabric_epoch = FabricEpoch::from_value(2);
  LG_CHECK_EQ(fence_cause(base, moved), FenceCause::FabricEpochAdvanced);
  moved = base;
  moved.epoch = CoordinatorEpoch::from_value(2);
  LG_CHECK_EQ(fence_cause(base, moved), FenceCause::CoordinatorEpochAdvanced);
  moved = base;
  moved.boot = BootId::from_value(2);
  LG_CHECK_EQ(fence_cause(base, moved), FenceCause::BootAdvanced);

  FenceVector older = base;
  older.boot = BootId::from_value(0);
  LG_CHECK(older < base);
  LG_CHECK(base.digest() != moved.digest());
  LG_CHECK_EQ(base.to_string(), std::string("t1/f1/p1/e1/c1/b1"));
}

LG_TEST(unit, explanation_is_bounded_and_canonical) {
  Explanation explanation(4);
  LG_CHECK(explanation.add(ReasonCode::WitnessSuccessfullyValidated, "b", "second"));
  LG_CHECK(explanation.add(ReasonCode::RequestAccepted, "a", "first"));
  LG_CHECK(explanation.add(ReasonCode::RequestAccepted, "a", "zeroth"));
  LG_CHECK(explanation.add(ReasonCode::LimitsExceeded, "c"));
  LG_CHECK(!explanation.add(ReasonCode::SearchBudgetExhausted, "d"));
  LG_CHECK_EQ(explanation.reasons().size(), std::size_t{4});
  LG_CHECK_EQ(explanation.dropped(), std::uint32_t{1});
  LG_CHECK(explanation.at_capacity());
  LG_CHECK(explanation.contains(ReasonCode::RequestAccepted));
  LG_CHECK_EQ(explanation.severity(), Severity::Warning);

  Explanation same(4);
  (void)same.add(ReasonCode::LimitsExceeded, "c");
  (void)same.add(ReasonCode::RequestAccepted, "a", "zeroth");
  (void)same.add(ReasonCode::RequestAccepted, "a", "first");
  (void)same.add(ReasonCode::WitnessSuccessfullyValidated, "b", "second");
  LG_CHECK_EQ(explanation.digest(), same.digest());
  // The rendered document also reports how many reasons were dropped at capacity, which
  // is part of the document and therefore legitimately differs here.
  LG_CHECK(explanation.to_text().find("RequestAccepted [a] first") != std::string::npos);
  LG_CHECK(same.to_text().find("RequestAccepted [a] first") != std::string::npos);
  LG_CHECK(explanation.to_text().find("dropped 1 reason") != std::string::npos);
  LG_CHECK(same.to_text().find("dropped") == std::string::npos);
}

LG_TEST(unit, bounded_text_preserves_utf8_boundaries) {
  const std::string ascii = "abcdefghij";
  LG_CHECK_EQ(bounded_text(ascii, 5), std::string("abcde..."));
  LG_CHECK_EQ(bounded_text(ascii, 100), ascii);
  LG_CHECK_EQ(bounded_text(ascii, 10), ascii);
  const std::string utf8 = "\xC3\xA9\xC3\xA9\xC3\xA9";
  const std::string truncated = bounded_text(utf8, 4);
  LG_CHECK_EQ(truncated, std::string("\xC3\xA9\xC3\xA9..."));
  for (std::size_t limit = 0; limit < 12U; ++limit) {
    LG_CHECK(bounded_text(utf8, limit).size() <= limit + 3U);
  }
}

LG_TEST(unit, deterministic_rng_reproduces) {
  Rng first(12345);
  Rng second(12345);
  for (int index = 0; index < 32; ++index) {
    LG_CHECK_EQ(first.next_u64(), second.next_u64());
  }
  Rng third(1);
  for (int index = 0; index < 64; ++index) {
    LG_CHECK(third.next_below(7) < 7);
  }
  LG_CHECK_EQ(third.seed(), std::uint64_t{1});
}

LG_TEST(unit, result_semantics) {
  const auto value = Result<int>::ok(7);
  LG_REQUIRE(value.has_value());
  LG_CHECK_EQ(value.value(), 7);
  const auto failure = Result<int>::failure(Outcome::Conflict, "two authorities disagree");
  LG_CHECK(!failure.has_value());
  LG_CHECK_EQ(failure.outcome(), Outcome::Conflict);
  bool threw = false;
  try {
    (void)failure.value();
  } catch (const std::logic_error&) {
    threw = true;
  }
  LG_CHECK(threw);
  const auto from_reason = Result<int>::failure(ReasonCode::LimitsExceeded, "too big");
  LG_CHECK_EQ(from_reason.outcome(), Outcome::Exhausted);
  const Status status = Status::ok();
  LG_CHECK(status.is_ok());
}

LG_TEST(unit, limits_sanity) {
  LG_CHECK(limits_are_sane(default_limits()));
  Limits broken = default_limits();
  broken.max_witness_hops = 0;
  LG_CHECK(!limits_are_sane(broken));
  broken = default_limits();
  broken.max_witness_hops = 4096;
  LG_CHECK(!limits_are_sane(broken));
  broken = default_limits();
  broken.max_observations = 0;
  LG_CHECK(!limits_are_sane(broken));
  broken = default_limits();
  broken.max_sessions = 0;
  LG_CHECK(!limits_are_sane(broken));
}

LG_TEST(unit, version_is_reported) {
  LG_CHECK_EQ(version_string(), std::string("1.0.0"));
  LG_CHECK_EQ(version_packed(), std::uint32_t{0x00010000U});
  LG_CHECK(!build_identity().empty());
}
