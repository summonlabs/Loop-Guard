#include <algorithm>
#include <filesystem>
#include <set>

#include "fixtures.hpp"
#include "harness.hpp"
#include "loop_guard/wire.hpp"

namespace {

using namespace lg_test;
using namespace loop_guard;

Limits small_limits() {
  Limits limits = default_limits();
  limits.max_journal_records = 64;
  limits.max_journal_bytes = 1U << 20U;
  return limits;
}

std::vector<std::uint8_t> build_document() {
  std::vector<std::uint8_t> document;
  for (std::uint64_t sequence = 1; sequence <= 4; ++sequence) {
    std::vector<std::uint8_t> payload;
    for (std::uint64_t index = 0; index < sequence * 8U; ++index) {
      payload.push_back(static_cast<std::uint8_t>((sequence * 31U + index) & 0xFFU));
    }
    const auto frame = frame_record(sequence == 1U ? RecordType::Snapshot : RecordType::Note,
                                    sequence, 1U, payload);
    document.insert(document.end(), frame.begin(), frame.end());
  }
  return document;
}

}  // namespace

LG_TEST(journal_adversarial, every_truncated_prefix_is_torn_or_corrupt_never_accepted) {
  const std::vector<std::uint8_t> document = build_document();
  const Limits limits = small_limits();
  for (std::size_t length = 0; length < document.size(); ++length) {
    const std::vector<std::uint8_t> prefix(document.begin(),
                                           document.begin() + static_cast<std::ptrdiff_t>(length));
    std::size_t offset = 0;
    bool terminated = false;
    while (offset < prefix.size()) {
      const RecordDecodeResult decoded = decode_record_at(prefix, offset, limits);
      if (decoded.status == RecordDecodeStatus::Ok) {
        LG_CHECK(decoded.record.sequence >= 1U);
        offset = decoded.next_offset;
        continue;
      }
      if (decoded.status == RecordDecodeStatus::End) {
        terminated = true;
        break;
      }
      // Torn tail or corruption: never a decoded record.
      LG_CHECK(decoded.status == RecordDecodeStatus::TornTail ||
               decoded.status == RecordDecodeStatus::Corrupt);
      terminated = true;
      break;
    }
    if (offset >= prefix.size()) {
      terminated = true;
    }
    LG_CHECK(terminated);
  }
}

LG_TEST(journal_adversarial, declared_length_above_the_ceiling_is_refused_before_allocation) {
  std::vector<std::uint8_t> document = build_document();
  const Limits limits = small_limits();
  // Rewrite the declared payload length of record two to the maximum 32-bit value and
  // repair the header digest so that only the length ceiling can reject it.
  const RecordDecodeResult first = decode_record_at(document, 0, limits);
  LG_REQUIRE(first.status == RecordDecodeStatus::Ok);
  const std::size_t second = first.next_offset;
  const std::uint32_t huge = 0xFFFF'FFFFU;
  for (std::size_t index = 0; index < 4; ++index) {
    document[second + 20U + index] = static_cast<std::uint8_t>((huge >> (index * 8U)) & 0xFFU);
  }
  const Digest header_digest =
      sha256(std::span<const std::uint8_t>(document.data() + second, 80));
  std::copy(header_digest.bytes.begin(), header_digest.bytes.begin() + 8,
            document.begin() + static_cast<std::ptrdiff_t>(second + 80U));
  const RecordDecodeResult decoded = decode_record_at(document, second, limits);
  LG_CHECK(decoded.status == RecordDecodeStatus::Corrupt);
  LG_CHECK(decoded.reason == ReasonCode::PersistenceIntegrityFailure);
}

LG_TEST(journal_adversarial, reserved_bytes_must_be_zero) {
  std::vector<std::uint8_t> document = build_document();
  const Limits limits = small_limits();
  document[60] = 1U;
  const Digest header_digest = sha256(std::span<const std::uint8_t>(document.data(), 80));
  std::copy(header_digest.bytes.begin(), header_digest.bytes.begin() + 8, document.begin() + 80);
  const RecordDecodeResult decoded = decode_record_at(document, 0, limits);
  LG_CHECK(decoded.status == RecordDecodeStatus::Corrupt);
}

LG_TEST(journal_adversarial, payload_digest_mismatch_is_refused) {
  std::vector<std::uint8_t> document = build_document();
  const Limits limits = small_limits();
  document[kRecordHeaderBytes + 3U] ^= 0xFFU;
  const RecordDecodeResult decoded = decode_record_at(document, 0, limits);
  LG_CHECK(decoded.status == RecordDecodeStatus::Corrupt);
  LG_CHECK(decoded.reason == ReasonCode::PersistenceIntegrityFailure);
}

LG_TEST(journal_adversarial, invalid_record_type_and_sequence_zero_are_refused) {
  const Limits limits = small_limits();
  std::vector<std::uint8_t> document = build_document();
  document[6] = 0xF0U;
  document[7] = 0xFFU;
  Digest header_digest = sha256(std::span<const std::uint8_t>(document.data(), 80));
  std::copy(header_digest.bytes.begin(), header_digest.bytes.begin() + 8, document.begin() + 80);
  LG_CHECK_EQ(decode_record_at(document, 0, limits).status, RecordDecodeStatus::Corrupt);

  document = build_document();
  for (std::size_t index = 0; index < 8; ++index) {
    document[12U + index] = 0U;
  }
  header_digest = sha256(std::span<const std::uint8_t>(document.data(), 80));
  std::copy(header_digest.bytes.begin(), header_digest.bytes.begin() + 8, document.begin() + 80);
  const RecordDecodeResult decoded = decode_record_at(document, 0, limits);
  LG_CHECK_EQ(decoded.status, RecordDecodeStatus::Corrupt);
  LG_CHECK_EQ(decoded.reason, ReasonCode::PersistenceSequenceRegression);
}

LG_TEST(journal_adversarial, superseded_generation_is_refused_rather_than_replayed) {
  const std::string path = scratch_path("journal-generation.lgstore");
  remove_scratch(path);
  const Limits limits = small_limits();
  auto store = DurableStore::open_or_create(path, limits, ProducerId::from_value(3));
  LG_REQUIRE(store.has_value());
  LG_CHECK(store.value().close(true).is_ok());

  std::vector<std::uint8_t> bytes = read_bytes(path);
  // Force a compaction so the document's store generation advances, then splice an old
  // record back in. The spliced record must be refused.
  auto reopened = DurableStore::open_or_create(path, limits, ProducerId::from_value(3));
  LG_REQUIRE(reopened.has_value());
  const std::vector<std::uint8_t> before = read_bytes(path);
  LG_CHECK(reopened.value().compact().is_ok());
  const std::vector<std::uint8_t> after = read_bytes(path);
  LG_CHECK(after.size() != before.size() || after != before);
  LG_CHECK(reopened.value().close(true).is_ok());

  // Append a well-formed record that claims the previous generation.
  std::vector<std::uint8_t> document = read_bytes(path);
  const std::vector<std::uint8_t> payload = {1U, 2U, 3U};
  const std::vector<std::uint8_t> stale =
      frame_record(RecordType::Note, 2U, 1U, payload);  // generation 1, not the current one
  document.insert(document.end(), stale.begin(), stale.end());
  write_bytes(path, document);
  const auto rejected = DurableStore::open_or_create(path, limits, ProducerId::from_value(3));
  LG_CHECK(!rejected.has_value());
  remove_scratch(path);
}

LG_TEST(journal_adversarial, out_of_order_sequence_is_refused) {
  const std::string path = scratch_path("journal-sequence.lgstore");
  remove_scratch(path);
  const Limits limits = small_limits();
  auto store = DurableStore::open_or_create(path, limits, ProducerId::from_value(3));
  LG_REQUIRE(store.has_value());
  LG_CHECK(store.value().close(true).is_ok());

  std::vector<std::uint8_t> document = read_bytes(path);
  const std::vector<std::uint8_t> payload = {9U};
  const std::vector<std::uint8_t> duplicate = frame_record(RecordType::Note, 1U, 1U, payload);
  document.insert(document.end(), duplicate.begin(), duplicate.end());
  write_bytes(path, document);
  const auto rejected = DurableStore::open_or_create(path, limits, ProducerId::from_value(3));
  LG_CHECK(!rejected.has_value());
  remove_scratch(path);
}

LG_TEST(journal_adversarial, a_second_snapshot_is_refused) {
  const std::string path = scratch_path("journal-second-snapshot.lgstore");
  remove_scratch(path);
  const Limits limits = small_limits();
  auto store = DurableStore::open_or_create(path, limits, ProducerId::from_value(3));
  LG_REQUIRE(store.has_value());
  LG_CHECK(store.value().close(true).is_ok());
  std::vector<std::uint8_t> document = read_bytes(path);
  const auto first = decode_record_at(document, 0, limits);
  LG_REQUIRE(first.status == RecordDecodeStatus::Ok);
  document.insert(document.begin() + static_cast<std::ptrdiff_t>(first.next_offset),
                  document.begin(), document.begin() + static_cast<std::ptrdiff_t>(first.next_offset));
  // Repair the sequence of the spliced snapshot so only the duplicate-snapshot rule can
  // reject it.
  const std::size_t second = first.next_offset;
  for (std::size_t index = 0; index < 8; ++index) {
    document[second + 12U + index] = static_cast<std::uint8_t>(((2ULL) >> (index * 8U)) & 0xFFU);
  }
  const Digest header_digest =
      sha256(std::span<const std::uint8_t>(document.data() + second, 80));
  std::copy(header_digest.bytes.begin(), header_digest.bytes.begin() + 8,
            document.begin() + static_cast<std::ptrdiff_t>(second + 80U));
  write_bytes(path, document);
  const auto rejected = DurableStore::open_or_create(path, limits, ProducerId::from_value(3));
  LG_CHECK(!rejected.has_value());
  remove_scratch(path);
}

LG_TEST(journal_adversarial, document_must_begin_with_a_snapshot) {
  const std::string path = scratch_path("journal-first-record.lgstore");
  remove_scratch(path);
  const Limits limits = small_limits();
  const std::vector<std::uint8_t> payload = {1U};
  const std::vector<std::uint8_t> frame = frame_record(RecordType::Note, 1U, 1U, payload);
  write_bytes(path, frame);
  const auto rejected = DurableStore::open_or_create(path, limits, ProducerId::from_value(3));
  LG_CHECK(!rejected.has_value());
  LG_CHECK_EQ(rejected.outcome(), Outcome::IntegrityFailure);
  remove_scratch(path);
}

LG_TEST(journal_adversarial, temporary_files_are_never_left_behind) {
  const std::string path = scratch_path("journal-temp.lgstore");
  remove_scratch(path);
  const Limits limits = small_limits();
  auto store = DurableStore::open_or_create(path, limits, ProducerId::from_value(3));
  LG_REQUIRE(store.has_value());
  for (std::uint64_t index = 1; index <= 3; ++index) {
    LG_CHECK(store.value().compact().is_ok());
  }
  LG_CHECK(store.value().close(true).is_ok());
  const std::string directory = scratch_path("");
  std::size_t strays = 0;
  for (const auto& entry : std::filesystem::directory_iterator(directory)) {
    const std::string name = entry.path().filename().string();
    if (name.rfind("journal-temp.lgstore.tmp-", 0) == 0) {
      ++strays;
    }
  }
  LG_CHECK_EQ(strays, std::size_t{0});
  remove_scratch(path);
}
