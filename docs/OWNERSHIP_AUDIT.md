# Ownership, locking and lifetime audit

This document records the deliberate inspection of Loop Guard's concurrency and
ownership behaviour. It is not a summary of tests: it is the audit itself, the defects
it found, and the fixes that were applied.

## Inventory of owned resources

| Resource | Owner | Lifetime | Notes |
| --- | --- | --- | --- |
| `Runtime` | the process that created it | until `close()` | Move-only; holds one `std::unique_ptr<Impl>`. |
| `Runtime::Impl::mutex` | `Impl` | `Impl` lifetime | Exactly one mutex guards all mutable runtime state. |
| `DurableStore` | `Runtime::Impl` (or a tool) | until `close()`/`reset()` | Move-only; owns one `std::FILE*`. |
| `EvidenceLedger` | `Runtime::Impl` | `Impl` lifetime | Value member; no separate lock; only touched under the runtime mutex. |
| `FindingRegistry` | `Runtime::Impl` | `Impl` lifetime | Same discipline. |
| `Socket` / `Listener` | the connection object | until `close()` | Move-only RAII; `close()` is idempotent. |
| `FramedConnection` | the session loop | until `close()` | Move-only; owns a `Socket` and a sticky `FrameDecoder`. |
| Observer callback | the caller | until replaced or the runtime closes | Invoked without the runtime mutex. |

## Checklist

### Read-lock then write-lock re-entry on the same lock

Not possible: the runtime uses a single non-recursive `std::mutex` and every public
method takes it exactly once, at the top, with `std::lock_guard`. A helper that needed
the lock would have to be a public method, and every public method would then deadlock
immediately — which the concurrency suite would surface as a hang. No helper takes the
lock.

### Write lock held across a helper or callback that re-enters state

The runtime never invokes caller code under the mutex. `publish_finding` and
`plan_containment` copy the observer into a local, release the lock, and only then call
it. The concurrency suite proves this by having an observer re-enter
`find_finding`, `findings` and `state_digest`; a callback under the lock would
deadlock, and the suite would hang rather than pass.

### Event/log/callback invocation beneath internal locks

Only the explanation documents and the bounded lineage log are touched under the lock.
Neither invokes user code. The lineage append calls into `DurableStore`, which is
exclusively owned by the runtime and never calls back into the runtime; the invariant is
recorded in a comment at each call site.

### Joining workers while holding state they need

Loop Guard starts no threads. The suites start threads, and every one of them is joined
outside any runtime call. The tools are single-threaded event loops; the only
concurrency in the service is one connection per session, driven sequentially.

### Cancellation/shutdown with reversed lock ordering

There is one lock in the runtime, so no order can be reversed. The transport has no lock
at all: a socket is owned by exactly one `FramedConnection`, and `close()` calls
`shutdown` before `closesocket`/`close` so that a blocked `select` is released and
returns an error rather than waiting for the deadline.

### Blocked socket/thread teardown

Every wait in the transport is a bounded `select` with a caller-supplied deadline, and
the deadline expiring is reported as `Outcome::Indeterminate` with the connection left
usable. `Listener::close()` and `Socket::close()` release a blocked `accept` or
`recv` in another thread. The multiprocess suite kills the coordinator with an OS-level
terminate and then binds the same port with a fresh process, which fails if any handle
survived.

### Cross-object mutex order inversion

Only one mutex exists in the library. `DurableStore`, `EvidenceLedger`,
`FindingRegistry`, `LoopDetector`, `ContainmentPlanner` and the codecs are all
lock-free. No two locks are ever held at once.

### Moved-from handle ownership

`Runtime`, `DurableStore`, `Socket`, `Listener` and `FramedConnection` are
move-only with explicit move constructors and move assignment operators. `Socket` and
`Listener` set the moved-from handle to the `kNoSocketHandle` sentinel, so a
moved-from object's destructor and `close()` are no-ops rather than a double close.
`DurableStore::move_from` transfers the `std::FILE*` and nulls the source.

### Close/shutdown races and double close

`Socket::close()`, `Listener::close()` and `DurableStore::reset()` all begin with a
sentinel check, so they are idempotent. `Runtime::close()` clears `open` under the
mutex before closing the store, so a concurrent `close()` observes `open == false`
and returns `Ok` without touching the store twice.

### Callbacks retaining references to mutable state beyond lock lifetime

The observer receives `const Finding&` bound to a local copy that lives for the
duration of the call. It cannot observe torn state and cannot keep a reference alive:
the copy is destroyed when the observer returns, and nothing in the runtime stores the
reference.

## Defects found and fixed during this audit

1. **Moved-from `Socket`/`Listener` sentinel.** The sentinel was a private static
   member declared after the inline `valid()` that used it, and the move operations
   used it before it existed as a namespace-level name. Fixed by introducing one
   namespace constant, `kNoSocketHandle`, used by both classes.
2. **`FramedConnection` dropped surplus frames.** A single read could complete several
   frames; only the first was returned and the rest were discarded, silently losing
   protocol progress. Fixed with a bounded pending queue.
3. **`Rng` never initialised its recorded seed.** `seed()` returned indeterminate
   memory, which made any diagnostic that printed the seed non-reproducible. Fixed by
   initialising `seed_` in the constructor.
4. **Durable snapshot written while the append handle was open.** On a platform that
   refuses to replace an open file, every fresh store and every compaction failed with
   `IoFailure`. Fixed by releasing the handle before the atomic replace and reopening
   the previous document if the replace fails.
5. **Compact / journal bounds leaked into the snapshot decoder.** A document that had
   been compacted under a small journal record bound could no longer be decoded, because
   the snapshot's collection bounds reused the journal ceiling. Fixed with dedicated
   bounds for the boot ledger, the retained lineage and the retained findings.
6. **Superseded observations resurrected possible openness.** A producer's retracted
   statement still contributed to the "possibly open" graph, which could keep a topology
   cycle alive after its author withdrew it. Fixed by excluding superseded observations
   from both the exact and the possible evidence paths.
7. **Validated witnesses were counted but not attached to the assessment.** The detector
   produced and independently validated witnesses, then reported `LoopConfirmed` with an
   empty witness list. Fixed by attaching the accepted set before the outcome is decided.
8. **Finding and lineage records stored a fence digest instead of the fence.** A decoded
   record could not be re-encoded byte-identically, so `StoreState::digest()` was not
   stable across a durable round trip. Fixed by storing the full fence.

## Standing rules

* No library type holds a lock while calling into another library type.
* No public entry point calls another public entry point.
* Every wait has a caller-supplied deadline, and every deadline expiry is an explicit
  outcome rather than a silent retry.
* Every handle is sentinel-checked before use, and every close is idempotent.
