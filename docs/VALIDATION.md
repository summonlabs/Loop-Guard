# Loop Guard 1.0.0 - validation record

This document records the evidence that was actually produced for this release, on this
host, with these commands. Nothing here is projected or intended behaviour: it is what
ran.

Host: Windows, MSVC 19.44 (Visual Studio 2022), CMake 4.3.2, Ninja, x64.

---

## 1. Build matrix

| Configuration | Command | Result |
| --- | --- | --- |
| Release | `cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release` then `cmake --build build --parallel` | Clean. `/W4 /WX /permissive- /Zc:__cplusplus /utf-8` on every first-party target. |
| Debug | `cmake -S . -B build-debug -G Ninja -DCMAKE_BUILD_TYPE=Debug` | Clean under the same warning policy. |
| AddressSanitizer | `cmake -S . -B build-asan -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DLG_ENABLE_ASAN=ON` | Clean; the whole matrix passes with ASan enabled. |
| MSVC static analyzer | `-DLG_ENABLE_ANALYZE=ON` (`/analyze`) on the library target | Clean after the findings in section 6 were fixed. |

The warning policy is applied by one function, `lg_configure_target`, to every target in
the project. No target opts out, and `LG_WARNINGS_AS_ERRORS` defaults to `ON`.

---

## 2. Test matrix

All suites are registered with CTest. **No test configures a timeout**, and no suite is
given a watchdog: a hang is a defect to diagnose, and every wait inside the suites is a
bounded wait that fails explicitly with a reason.

```
ctest --test-dir build --output-on-failure
```

| Configuration | Tests | Result |
| --- | --- | --- |
| Release | 26 | 26 passed |
| Debug | 26 | 26 passed |
| AddressSanitizer | 26 | 26 passed |

Registered tests: the 17 library suites, the benchmark in quick mode, and the 8 public
API examples.

| Suite | Cases | Focus |
| --- | --- | --- |
| `unit` | 14 | Enum totality and uniqueness, SHA-256 known-answer vectors, checked arithmetic, fence ordering, bounded explanations, deterministic RNG, limits sanity, version reporting. |
| `topology` | 10 | Definition validation, insertion-order-independent canonical form, adjacency index versus linear scan, strict text parsing, limit enforcement. |
| `evidence` | 10 | The full binding classification matrix, conflicts, supersession, lease expiry, definition-closed hops, selector intersection, bounded per-edge retention, refusal under exhaustion. |
| `witness` | 8 | Canonical rotation, hop alignment, ordering, and the validator's rejection matrix. |
| `detect` | 18 | Harmless cycles, confirmed loops, UNKNOWN, CONFLICT, STALE, budget exhaustion, selector scope, self-loops, a dense graph with many harmless cycles, canonical shortest witness, overlapping loops, insertion-order independence. |
| `containment` | 12 | Minimum-cost selection, deterministic tie-breaks, budget refusals, infeasibility certificates, plan tampering, shadow application, overlapping loops sharing one target. |
| `oracle` | 4 | 1,600 seeded differential cases against an independent naive solver, an adversarial instance where greedy is suboptimal, agreement with a brute-force cycle enumerator, and exhaustive agreement over every three-node digraph. |
| `property` | 5 | Seeded random scenarios with invariants asserted after every detection, canonical-witness stability, UNKNOWN-never-confirms perturbation, hitting-set validity, monotone evidence resolution. |
| `persistence` | 10 | Create/append/reopen, clean and unclean shutdown, generation regression, lineage regression, compaction, corruption refusal, torn-tail recovery, codec round trips with every truncated prefix rejected. |
| `journal_adversarial` | 10 | Every truncated prefix, oversized declared lengths, reserved bytes, payload-digest corruption, invalid record types, zero sequences, superseded-generation replay, out-of-order sequences, duplicate snapshots, stray temporary files. |
| `wire` | 14 | Frame round trip, every truncated prefix, corrupted field sweep, trailing bytes, sticky decoding, stream truncation, length ceilings before allocation, message codec round trips for every reply type, handshake gating. |
| `runtime` | 5 | The full lifecycle from definitions to verified effect, refusal to publish a non-affirmative assessment, immediate fencing, restart behaviour, observer re-entrancy. |
| `concurrency` | 4 | Deterministic latches, concurrent submitters, fence advances racing publication, torn reads, independent runtimes in parallel. |
| `restart` | 4 | Real process kill and restart, kill before and after a durable commit, torn-tail recovery from a killed process. |
| `multiprocess` | 4 | Real coordinator and worker processes over real loopback TCP, session identity binding, stale-fence refusal, acknowledgement versus verified effect, port release after a hard kill. |
| `scale` | 4 | Ring graphs at three sizes, a dense DAG with more than 6,000 edges, selector scaling, and explicit INDETERMINATE under a tight budget. |
| `adversarial` | 7 | Contradictory authorities, huge declared counts, duplicate and late completions, restart at six durable boundaries, byte-level fuzzing of a canonical document, bounded explanation documents, hostile scopes and fences. |

Assertion totals for the Release run: **13,186 assertions across 143 cases, 0 failures**.

---

## 3. Real multiprocess, crash and restart proof

These are real operating-system processes and real loopback sockets. Threads are never
used as a substitute.

* `multiprocess.real_processes_detect_and_contain_over_loopback` starts
  `lg_coordinator.exe` and `lg_worker.exe` as separate processes, exchanges framing
  over a real TCP loopback connection, detects a confirmed loop, publishes a finding,
  computes an optimal containment plan, and proves that a second connection cannot claim
  a session identity that is already bound.
* `multiprocess.stale_fence_request_is_refused_over_the_wire` binds a topology
  generation that is not current and requires the coordinator to answer with
  `Outcome::Stale` rather than reinterpreting the request.
* `multiprocess.acknowledgement_is_not_a_verified_effect` runs a worker that
  acknowledges an intent and never reports an effect, and requires the finding to remain
  `ContainmentAppliedUnverified` and never to read as `ContainmentVerified`.
* `multiprocess.coordinator_shutdown_releases_blocked_sessions` hard-kills the
  coordinator with an OS-level terminate, then binds the same port with a fresh process
  and serves a session, proving no handle or listener survived.
* `restart.hard_kill_fences_every_pre_restart_finding` publishes a finding, kills
  the coordinator, restarts it against the same durable store, and requires a new boot, a
  new incarnation, a new coordinator epoch, the restored finding fenced, and zero
  observations.
* `restart.kill_after_durable_commit_keeps_the_commit` terminates the coordinator
  immediately after a durable commit and before the acknowledgement, and requires the
  commit to be present on reopen.
* `restart.kill_before_durable_commit_leaves_no_trace` terminates the coordinator
  inside a durable mutation before the append, and requires the mutation to be absent.
* `restart.torn_tail_from_a_killed_process_is_recovered` truncates a real durable
  file mid-record and requires recovery plus an explicit recovery report.

---

## 4. Persistence proof

* Every durable record carries magic, record version, type, store generation, sequence,
  declared payload length, a payload digest and a header digest.
* Corrupt headers, corrupt payloads, impossible lengths, unsupported versions, invalid
  record types, non-zero reserved bytes, sequence regression and trailing garbage all
  refuse the open. None of them is silently truncated.
* Only a genuine torn tail - trailing bytes that are a strict prefix of a well-formed
  record - is recovered, and the file is truncated to the last complete record.
* Snapshots and compactions are written to a temporary file, flushed, synchronised and
  moved into place with an atomic replace. Compaction happens *before* an append, never
  after, so a rewrite cannot drop the record that triggered it.
* The boot ledger, the retained lineage and the retained findings each have their own
  bound, so a document compacted under a small journal record bound still decodes.
* Restart mints a new boot, incarnation and coordinator epoch. Restored findings are
  forced to `Fenced`; observations, leases, grants, in-flight intents and verified
  effects are never restored.

---

## 5. Property, adversarial and concurrency proof

* Property suites run seeded random graphs and assert invariants after every detection:
  every witness is re-derived by the independent validator, the canonical rotation holds,
  an affirmative outcome always carries at least one witness, and a reached search budget
  never produces `NO_LOOP`.
* The oracle suite differential-tests the branch-and-bound hitting-set solver against an
  independent naive solver over 1,600 seeded instances, and the cycle enumeration against
  a brute-force enumerator over every three-node digraph.
* Concurrency suites use explicit latches and barriers, never sleeps. The observer
  callback re-enters the runtime, which deadlocks if a callback ever runs under the
  runtime mutex - the concurrency suite would hang rather than pass.
* Adversarial suites mutate a canonical document at the byte level, submit contradictory
  authorities, replay duplicate and late completions, and restart at six distinct durable
  boundaries.

---

## 6. Static analysis findings and fixes

`/analyze` reported three findings. All three were fixed rather than suppressed,
except one third-party header finding, which is suppressed only around its include.

1. **C6262, `src/persistence.cpp`:** the bounded file reader used a 64 KiB stack
   frame. Fixed by heap allocating the staging buffer, which matters for a runtime
   embedded in services with small thread stacks.
2. **C28020, `src/digest.cpp`:** the analyzer could not prove that the SHA-256 block
   buffer was written inside its bounds. Fixed by making the block extent part of the
   type (`std::span<const std::uint8_t, 64>`) and by computing the padding length in
   closed form instead of appending padding byte by byte. The result is both provable and
   simpler: the padding is now a single bounded write of at most 128 bytes.
3. **C6101, Windows SDK header:** an inline helper in `ws2tcpip.h` that this runtime
   never calls. Suppressed with a scoped `#pragma warning(disable : 6101)` around the
   include, with the reason recorded next to it.

After those fixes the analyzer completes with no findings on the library target.

---

## 7. Install, downstream consumer and closure

`scripts/validate_install.ps1` performs, in order:

1. configure, build and `cmake --install` into a prefix;
2. generate a consumer project **outside the source tree** that uses
   `find_package(LoopGuard 1.0 CONFIG REQUIRED)` and links
   `SummonSoftwareLabs::LoopGuard`;
3. configure, build and run that consumer against the installed prefix;
4. run each installed tool and require a zero exit status.

The recorded consumer output is:

```
version=1.0.0 outcome=LoopConfirmed witnesses=1
plan_outcome=PlanOptimal targets=1
```

---

## 8. REAL / SYNTHETIC / UNSUPPORTED

| Capability | Label | Basis |
| --- | --- | --- |
| Detection, containment, persistence and protocol logic | SYNTHETIC | Deterministic in-process fixtures, labelled `EvidenceOrigin::Synthetic`. |
| Process restart, kill, fencing, boot/incarnation/epoch advance | REAL | Real OS processes, OS-level termination, real files reopened across the boundary. |
| Framed protocol, session authority, stale-fence refusal | REAL | Real coordinator and worker processes over real loopback TCP sockets. |
| Durable format integrity and adversarial rejection | REAL | Real files on the host filesystem, mutated at byte level. |
| Switch, NIC, RDMA, DPU, switch ASIC, NVLink, InfiniBand, RoCE, multi-node fabrics | UNSUPPORTED | No such hardware was exercised. |
| Peer authentication, encryption, secure transport | UNSUPPORTED | Deliberately outside the boundary. |
| GCC/Clang builds and UBSan | UNSUPPORTED on this host | Only the MSVC toolchain is installed here. The CMake options exist and the code paths are written, but they were not built or run. |
