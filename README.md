# Loop Guard

Loop Guard is a forwarding-loop detection and containment-intent runtime for Summon
Software Labs infrastructure. It answers one question, deterministically and truthfully,
under stale, partial, contradictory, restarted, concurrent and adversarial conditions:

> Given authoritative forwarding/path observations and current topology generations, does
> a forwarding loop exist **now**, which resources and traffic are implicated, what
> **bounded** containment is authorized, and when must that finding be withdrawn or
> revalidated?

Loop Guard 1.0.0 is a portable C++20 library with zero third-party runtime dependencies,
an installable CMake package, a bounded framed service protocol, a coordinator, a worker
and an operator client.

---

## 1. Exact systems boundary

**Loop Guard owns** forwarding-loop detection and containment *intent*:

* the governed topology definition (resources, directed adjacencies, traffic selectors);
* forwarding evidence resolution against exact generations;
* loop witnesses — the proof object that traffic can revisit a governed resource;
* the containment objective, its bounded search and its certificate;
* findings, their fences, their authority lineage, and their durability.

**Loop Guard does not** compute normal routes, program forwarding tables or device state,
collect raw telemetry, own congestion or queue recovery, authenticate peers, or encrypt
anything. It integrates with neighbouring authorities only through explicit typed inputs,
outputs, evidence references and grants.

The practical consequence: Loop Guard tells an operator or an adjacent runtime *what is
proved and what is permitted*. It never tells anyone that a device was changed.

---

## 2. Authority model

Six authority stages are kept strictly separate. No stage can stand in for the next.

| Stage | Meaning | Where it lives |
| --- | --- | --- |
| **Observation** | A producer says a hop is open, closed or unknown, bound to exact generations and a lease. | `ForwardingObservation`, `EvidenceLedger` |
| **Eligibility** | Policy says a resource may be a containment target. | `ContainmentPolicy`, `ResourceRecord::containable` |
| **Recommendation** | A planner suggests targets. No permission to act. | `ContainmentPlan::greedy_recommendation` |
| **Authorization** | A bounded, time-limited grant permits a specific target set. | `ContainmentGrant`, `ContainmentIntent` |
| **Acknowledgement** | An applier says it received the intent. Not an effect. | `ContainmentAcknowledgement` |
| **Verified effect** | An independent observation confirms the target is contained. | `VerifiedEffect` |

Rules that follow from the model, all enforced in code:

* Observation is not authority. Evidence alone never authorizes containment.
* Eligibility is not authorization. A containable resource is only a candidate.
* Authorization is not application. `authorize_containment` returns an intent.
* Acknowledgement is not verified effect. `record_acknowledgement` moves a finding to
  `ContainmentAppliedUnverified`; only a `VerifiedEffect` exactly bound to the current
  fence moves it to `ContainmentVerified`.
* A finding that has no verified effect for **every** target never reads as verified.

### Generations and the fence vector

Every externally visible decision binds a `FenceVector`:

```
topology generation / forwarding generation / policy generation / fabric epoch /
coordinator epoch / boot
```

A decision is current only while all six components still compare equal. Matching
identity is not matching generation: a `ResourceId` that survives a topology reload does
not make an old finding current. When any component moves, every live finding is fenced
with an explicit `FenceCause` and becomes `Stale` or `Fenced` before the runtime answers
anything else.

---

## 3. Product-defining invariants

1. **A graph cycle is not a loop.** A topology adjacency never proves forwarding. A
   witness requires exactly-generation-bound evidence that every hop of the cycle is
   forwarding *now*, that every resource is administratively enabled, that every link is
   up, and that at least one traffic selector is admitted and proven open on every hop.
2. **UNKNOWN never becomes LOOP_CONFIRMED.** A hop that is not established either way
   cannot appear in a witness. If a cycle exists only through unproven hops the answer is
   `UNKNOWN`; if it exists only through a hop whose authoritative evidence contradicts
   itself the answer is `CONFLICT`.
3. **NO_LOOP is proved, never guessed.** `NO_LOOP` is emitted only when cycle absence is
   proved exactly — for every candidate selector — in both the proven-open graph and the
   possibly-open graph. A bounded search that stops early yields `INDETERMINATE`.
4. **Budgets are surfaced, never hidden.** A reached proof, enumeration, selector, witness
   or memory budget sets `SEARCH_LIMIT_REACHED` and yields `INDETERMINATE` when the
   question is unanswered. It never yields a false `NO_LOOP`.
5. **Witnesses are canonical and content addressed.** The cycle is rotated to its smallest
   resource identity, hops follow the cycle, selectors are sorted, and the witness
   identity is derived from its own content. Insertion, discovery and container order
   cannot change the answer.
6. **Every produced witness is independently re-derived.** `WitnessValidator` re-derives
   each hop from the raw evidence ledger rather than trusting the detector's tables. A
   detector that fabricates a cycle is caught before it becomes a finding.
7. **Every produced plan is independently re-derived.** `PlanValidator` re-derives
   coverage from the assessment, the policy and the definition. It never trusts the
   plan's own accounting.
8. **Containment is bounded and never silently disables unrelated forwarding.** The plan
   names exact targets, exact selectors and exact affected hops. `apply_containment_shadow`
   removes only those selectors from those hops, and the scale and containment suites
   prove that no other hop loses anything.
9. **Optimality and infeasibility are claims that need proof.** `PlanOptimal` requires an
   exhaustively completed search. `ProvenInfeasible` requires a certificate: a confirmed
   witness none of whose resources is eligible. A reached budget yields `PlanFeasible` or
   `SearchLimitReached`, never a claim of optimality.
10. **Persistence is not liveness.** Definitions, policy, the boot ledger, committed
    lineage and completed findings survive restart. Observations, leases, grants,
    in-flight intents and verified effects never do.

---

## 4. The detection problem, stated precisely

**Supported problem class.** A finite directed graph of governed resources (≤ 65536) with
directed adjacencies (≤ 262144), each carrying a canonical set of traffic selectors
(≤ 8192 distinct). Each hop has zero or more observations, each bound to a
(topology generation, forwarding generation) pair, a fabric epoch, a boot, a coordinator
epoch and a lease window. The detector answers, for each candidate selector, whether a
simple cycle exists in the graph of hops that are **proven open** for that selector.

**Correctness.** Every emitted witness is a simple cycle whose every hop is proved open by
exactly bound evidence at the request's fence, for every selector the witness names, and
the witness passes independent re-derivation.

**Completeness.** When the outcome is `NO_LOOP`, no simple cycle exists in the proven or
possibly-open graph for any candidate selector. Cycle *existence* is decided exactly by an
iterative topological-order test per selector — it is not a bounded search — so a negative
answer is a proof. Cycle *enumeration* (which produces the witness list and feeds
containment) is bounded, and reaching its bound sets `SEARCH_LIMIT_REACHED` and
`ADDITIONAL_CYCLES_POSSIBLE`.

**Determinism.** The candidate selectors, the hop table, the witness list and the
containment result are all totally ordered by content. Tie-breaks are: shortest cycle,
then lexicographically smallest resource sequence, then hop sequence, then selector set.
The containment objective is: minimum total cost, then fewest targets, then
lexicographically smallest sorted target sequence.

**Failure is not absence.** "I could not find a cycle" and "there is no cycle" are
different outcomes and are reported as different outcomes.

---

## 5. Lifecycle and restart semantics

```
Proposed ──▶ Confirmed ──▶ ContainmentRequested ──▶ ContainmentAppliedUnverified
                  │                     │                        │
                  │                     │                        ▼
                  │                     │              ContainmentVerified
                  ▼                     ▼
              Stale / Fenced / Withdrawn / Rejected
```

* A finding is published only for an affirmative assessment, whose every witness is
  re-validated at publish time.
* Any change to topology, forwarding, policy, fabric epoch, coordinator epoch or boot
  fences every live finding immediately, with the component that moved recorded as the
  cause.
* Restart mints a new boot, incarnation and coordinator epoch. Restored findings are
  forced to `Fenced`; the durable ledger records the boot advance before the runtime
  answers anything. No pre-restart dynamic fact is promoted to current authority.
* A grant is active only while its fence is current and its lease has not expired. A
  fenced or expired grant authorizes nothing, and an out-of-scope target is refused
  rather than clamped.

---

## 6. Build, install and use

### Requirements

* CMake 3.24 or newer
* A C++20 compiler: MSVC 19.3x (Visual Studio 2022), GCC 11+, or Clang 14+
* No third-party runtime dependencies. On Windows the library links `ws2_32`.

### Build and test

```powershell
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

On Windows, `scripts/with-msvc.ps1` locates the Visual Studio toolchain with `vswhere`
and runs a command inside a developer environment:

```powershell
pwsh -File scripts/with-msvc.ps1 -Command "cmake --build build --parallel"
```

### Install

```powershell
cmake --install build --prefix C:/prefix/loop-guard
```

This installs the library, the public headers, the three tools and the CMake package
files (`LoopGuardConfig.cmake`, `LoopGuardConfigVersion.cmake`,
`LoopGuardTargets.cmake`) under the `SummonSoftwareLabs::` namespace.

### Consume from an independent project

```cmake
cmake_minimum_required(VERSION 3.24)
project(MyNeighbour LANGUAGES CXX)
find_package(LoopGuard 1.0 CONFIG REQUIRED)
add_executable(neighbour main.cpp)
target_compile_features(neighbour PRIVATE cxx_std_20)
target_link_libraries(neighbour PRIVATE SummonSoftwareLabs::LoopGuard)
```

```
cmake -S . -B build -DCMAKE_PREFIX_PATH=C:/prefix/loop-guard
cmake --build build
```

`scripts/validate_install.ps1` performs exactly this end to end, with the consumer
generated **outside** the source tree, and then runs the installed tools.

### Minimal use

```cpp
#include "loop_guard/runtime.hpp"

using namespace loop_guard;

RuntimeConfig config;
config.producer = ProducerId::from_value(1);
config.store_path = "fabric.lgstore";   // empty for a purely in-memory runtime
auto runtime = std::move(Runtime::open(config).value());

runtime.set_topology(definition, tick);          // durable definition generation
runtime.set_policy(policy, tick);                // durable containment policy generation
runtime.submit_observation(observation, tick);   // dynamic evidence, never durable

auto assessment = runtime.detect(tick).value();  // LoopOutcome + canonical witnesses
if (assessment.outcome == LoopOutcome::LoopConfirmed) {
  auto finding = runtime.publish_finding(assessment, tick).value();
  auto plan = runtime.plan_containment(assessment, tick).value();
  // plan.authorizes_action() is true only for an exhaustively proved minimum that fits
  // the policy budgets. Authorizing still only produces an intent.
}
```

Every entry point returns a structured `Result`/`Status` carrying an `Outcome` and a
detail string. Nothing reports success as a bare `bool`, and no operation returns a
default-constructed success.

---

## 7. Tools and examples

| Tool | Role |
| --- | --- |
| `lg_coordinator` | Runs the runtime, owns durable state, serves the framed protocol. |
| `lg_worker` | Submits real observations, acknowledges intents, reports verified effects. |
| `lgctl` | Operator client: detect, publish, plan, authorize, withdraw, query, shut down. |

```powershell
# Start a coordinator with a synthetic three-switch ring and a durable store
build/lg_coordinator.exe --port=0 --store=fabric.lgstore --ring=3

# Feed it evidence from a separate process, over a real loopback socket
build/lg_worker.exe --port=<port> --session=200 --ring=3

# Ask the detection question and act on the answer
build/lgctl.exe --port=<port> --session=1 --script=detect,publish,plan,findings,shutdown
```

`lgctl --script` accepts: `detect`, `detect-stale`, `publish`, `plan`, `authorize`,
`findings`, `digest`, `restart-report`, `fence-advance`, `withdraw`, `shutdown`. Each
step prints machine-readable `key=value` lines.

The wire format, the trust boundary and every session rule are specified in
[docs/PROTOCOL.md](docs/PROTOCOL.md).

### Examples

| Example | Demonstrates |
| --- | --- |
| `ex_harmless_cycle` | A topology cycle that is not a forwarding loop. |
| `ex_confirmed_loop` | A confirmed loop and its canonical witness. |
| `ex_unknown_is_not_a_loop` | UNKNOWN is never published as a finding. |
| `ex_stale_generations` | A generation advance stales the prior witness. |
| `ex_overlapping_loops` | Two overlapping loops and one shared target. |
| `ex_bounded_containment` | Containment that spares unrelated forwarding. |
| `ex_restart_fencing` | Restart fences every pre-restart authority. |
| `ex_indeterminate_budget` | A reached proof budget yields INDETERMINATE. |

---

## 8. Testing and evidence

The suite is built as one binary with named suites, registered with CTest. No test
configures a timeout: a hang is a defect to diagnose, and every wait inside the suites is
a bounded wait that fails explicitly.

| Suite | What it proves |
| --- | --- |
| `unit` | Enum totality and uniqueness, SHA-256 vectors, checked arithmetic, fence ordering, bounded explanations, deterministic RNG, limits sanity. |
| `topology` | Definition validation, canonical form independent of insertion order, adjacency index correctness, strict text parsing. |
| `evidence` | The complete binding classification matrix, supersession, conflicts, definition-closed hops, bounded retention, refusal under exhaustion. |
| `witness` | Canonical rotation, ordering, and the validator's rejection matrix for tampering. |
| `detect` | Harmless cycles, confirmed loops, UNKNOWN, CONFLICT, STALE, budget exhaustion, selector scope, self-loops, overlapping loops, dense graphs with many harmless cycles. |
| `containment` | Minimum-cost selection, tie-breaks, budget refusals, infeasibility certificates, plan tampering, shadow application, overlapping loops sharing a target. |
| `oracle` | Differential testing against an independent naive hitting-set solver and an independent brute-force cycle enumerator, plus exhaustive small-graph cycle agreement. |
| `property` | Seeded random scenarios with invariants asserted after every operation. |
| `persistence` | Create, append, reopen, unclean shutdown detection, generation regression, compaction, corruption refusal, torn-tail recovery, codec round trips and prefix rejection. |
| `journal_adversarial` | Every truncated prefix, oversized declared lengths, reserved bytes, digest corruption, generation replay, sequence regression, duplicate snapshots, stray temporary files. |
| `wire` | Frame round trip, every truncated prefix, corrupted fields, trailing bytes, sticky decoding, length ceilings, message codec round trips, handshake gating. |
| `runtime` | The full lifecycle from definitions to verified effect, publication refusal, immediate fencing, restart behaviour, observer re-entrancy. |
| `concurrency` | Deterministic latches, concurrent submitters, fence advances racing publication, torn reads, independent runtimes in parallel. |
| `restart` | Real process kill and restart, kill before and after durable commit, torn tail from a killed process. |
| `multiprocess` | Real coordinator and worker processes over real loopback sockets, session identity, stale fence refusal, acknowledgement versus effect, port release after a kill. |
| `scale` | Large cyclic and dense synthetic graphs, bounded work counters, explicit INDETERMINATE under a tight budget. |
| `adversarial` | Contradictory authorities, huge declared counts, duplicate and late completions, restart at every durable boundary, byte-level fuzzing, bounded documents, hostile scopes and fences. |

### REAL / SYNTHETIC / UNSUPPORTED

| Capability | Label | Basis |
| --- | --- | --- |
| Detection, containment, persistence, protocol logic | **SYNTHETIC** | Deterministic in-process fixtures. Every artifact is labelled `EvidenceOrigin::Synthetic` unless a real producer supplies it. |
| Restart, kill, fencing, boot/incarnation/epoch advance | **REAL** | Real operating-system processes, OS-level termination, real files reopened across the boundary. |
| Framed protocol, session authority, stale-fence refusal | **REAL** | Real coordinator and worker processes over real loopback TCP sockets. |
| Durable format integrity and adversarial rejection | **REAL** | Real files on the host filesystem, mutated at byte level. |
| Switch, NIC, RDMA, DPU, switch ASIC, NVLink, InfiniBand, RoCE, multi-node fabrics | **UNSUPPORTED** | No such hardware was exercised. No claim is made about it, and none is implied by the synthetic fixtures. |
| Peer authentication, encryption, secure transport | **UNSUPPORTED** | Deliberately outside the boundary. See the trust boundary in docs/PROTOCOL.md. |

---

## 9. Performance

`lg_bench` measures **completed work**, not submission latency. It reports, per scale and
selector count, the outcome, the canonical witness length, the enumeration counters, the
number of DFS steps and the elapsed microseconds, then exercises the durable path and
asserts that retained state stays bounded.

```powershell
build/lg_bench.exe            # full run
build/lg_bench.exe --quick    # reduced scale, used by CTest
```

Cycle *existence* is decided in `O(V + E)` per candidate selector by an iterative
topological-order test. Cycle *enumeration* is bounded by the witness-length bound, the
cycle ceiling and the step budget. A ring longer than the configured witness bound cannot
produce a witness and is reported as `INDETERMINATE` with `SEARCH_LIMIT_REACHED` rather
than as a confirmation.

---

## 10. Genuine limitations

* **No hardware validation.** Nothing in this release was exercised against a real
  switch, NIC, RDMA fabric or multi-node deployment. Detection correctness is proved
  against the runtime's own semantic model, not against a physical device.
* **The wire format is not authenticated.** A peer that can reach the loopback listener
  can attempt a handshake. Session identity, boot and epoch are bound to the socket, but
  the peer is not authenticated.
* **Containment intent is expressed as a bounded selector removal.** The runtime computes
  and validates the intent; it does not program a device, and it reports a verified effect
  only when an independent observation proves one.
* **Cycle enumeration is exponential in the worst case.** It is bounded, and reaching a
  bound is reported, but a topology with an enormous number of overlapping cycles will
  report `ADDITIONAL_CYCLES_POSSIBLE` rather than an exhaustive witness list.
* **Containment is NP-hard in general.** The exact search is branch and bound with an
  explicit node budget; past the budget the runtime reports a feasible plan, or
  `SearchLimitReached`, and never claims optimality.
* **Windows is the only platform exercised in this release.** The POSIX code paths exist
  and are written to the same discipline, but they were not built or run here, so the
  sanitizer matrix is marked UNSUPPORTED on this host for the GCC/Clang configurations.
* **`Limits::max_witness_hops` is capped at 256.** Longer simple cycles cannot be
  witnessed; they are reported as `INDETERMINATE` with `SEARCH_LIMIT_REACHED`.

---

## 11. Documentation

* [docs/PROTOCOL.md](docs/PROTOCOL.md) — the framed protocol, session rules and trust boundary.
* [docs/OWNERSHIP_AUDIT.md](docs/OWNERSHIP_AUDIT.md) — the concurrency, ownership and
  lifetime audit, including every defect it found and the fix applied.
* [docs/VALIDATION.md](docs/VALIDATION.md) — the recorded evidence for this release.

---

## License
Apache License 2.0. Copyright 2026 Summon Software Labs.
