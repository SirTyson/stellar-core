# H011: Make `shortHash::gKey` Lock-Free to Eliminate `gKeyMutex` from `XDRShortHasher` Constructor and `computeHash`

**Date**: 2026-04-29
**Subsystem**: crypto
**Severity**: Low (proposed) → rejected
**Impact**: remove per-`xdrComputeHash<LedgerKey>` mutex acquisition during
parallel apply (bucket scans, host-state ordered-map probes)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`shortHash::gKey` is set exactly once by `shortHash::initialize()` at process
startup and is read on every subsequent hash call. Because `gKey` never
mutates after initialization (the `BUILD_TESTS`-only `seed()` aside), reads
should not require taking a `std::mutex`. Each `XDRShortHasher` constructor
and each `shortHash::computeHash` call should be lock-free, exposing zero
inter-thread contention to the parallel-apply workers that drive the
`InMemoryBucketState::scan` and host-state map-probe paths.

## Mechanism

Today (`src/crypto/ShortHash.cpp:62-79`), every call into
`shortHash::computeHash` and the `XDRShortHasher::XDRShortHasher()`
constructor takes `gKeyMutex` for the duration of one `gKey` read plus a
small write to the `gHaveHashed` flag. The hash is invoked from the
parallel-apply hot path through `std::hash<LedgerKey>` →
`shortHash::xdrComputeHash<LedgerKey>` (via `BucketEntryHash`,
`unordered_set<InternalInMemoryBucketEntry>`, and the host-state ordered
map). With `NUM_CLUSTERS` worker threads all probing the in-memory bucket
indexes and host-state maps concurrently, the same global mutex is the
single contention point.

The proposed fix would store `gKey` as an immutable post-init value (e.g.,
copied into a `static const std::array` after `initialize()` returns, or
synchronized once via `std::call_once`/`std::atomic_thread_fence`),
making `XDRShortHasher::XDRShortHasher()` and `shortHash::computeHash`
fully lock-free.

## Trigger

Run the soroswap apply-load benchmark with `NUM_CLUSTERS=8`. Each cluster
thread issues hundreds of thousands of `xdrComputeHash<LedgerKey>` calls
through bucket-scan and host-state map-probe paths during apply, all
serializing on a single process-wide mutex.

## Target Code

- `src/crypto/ShortHash.cpp:14-26` — `gKey`, `gKeyMutex`, `initialize()`
- `src/crypto/ShortHash.cpp:62-79` — `computeHash` and
  `XDRShortHasher::XDRShortHasher()` both take `gKeyMutex`
- `src/crypto/ShortHash.h` — `xdrComputeHash<T>` template entry point
- `src/bucket/InMemoryIndex.cpp:251-262` — `InMemoryBucketState::scan`
  hash callsite (drives the bulk of the apply-window contention)

## Evidence

- Tracy trace
  `1695facd04c8-20260429-013014-02-soroswap-tx-2000-t-8.tracy`:
  `scan,bucket/InMemoryIndex.cpp:253` is 1.73 s self over 857 848 calls;
  `getBucketEntry,bucket/BucketListSnapshot.cpp:174` is 707 847 calls.
  Each call enters `std::hash<LedgerKey>{}(searchKey)` →
  `shortHash::xdrComputeHash<LedgerKey>` → constructs an `XDRShortHasher`
  (one mutex acquisition) and computes a SipHash, then the host-state
  ordered map adds further `shortHash::computeHash` mutex acquisitions on
  top.
- The mutex protects only a single read of a 16-byte `gKey` and an
  unconditional `gHaveHashed = true` write — both trivially replaceable
  with lock-free reads if `gKey` is treated as immutable post-init.
- Parallel apply runs with `NUM_CLUSTERS` worker threads, all of which
  hash through this single `std::mutex`.

## Anti-Evidence

- The critical section is microscopically short (one 16-byte read, one
  bool write, ~30–50 ns uncontended). Even with 8-thread contention,
  the aggregate wall-clock cost is bounded above by ~50 ns × 857 k
  calls / 8 threads ≈ 5 ms of in-apply wall time across the run, far
  below the 1 % Low floor (apply window is ~595 ms median × 65 ledgers
  ≈ 39 s of apply wall-time across the trace).
- Failure record `007-cache-ledgerkey-siphash-on-prefetch.md` already
  established that the dominant `scan` self-time is `unordered_set`
  bucket walking and XDR equality compare, not hashing or its
  associated lock. Removing the mutex returns a strict subset of the
  H007 SipHash budget.
- The crypto fail-summary's "SHA256 / Hashing Budget Ceiling" meta-pattern
  generalises to short-hash work in apply: total in-apply hashing
  (SipHash, SHA256, BLAKE2 combined) is bounded by a few percent of
  apply time, and lock removal recovers only a sliver of the SipHash
  fraction of that ceiling.
- `BUILD_TESTS` exposes a `seed()` mutator that violates the "immutable
  post-init" invariant, so a lock-free implementation must guard the
  test-only mutator, adding code complexity for a sub-1 % win.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Failed At**: hypothesis
**Novelty**: PASS — `gKeyMutex` lock-removal (as distinct from the
SipHash-recomputation focus of H007 and the verify-cache shard mutex
focus of H008) was not previously investigated in crypto fail/
hypothesis/reviewed/poc records.

### Why It Failed

The targeted critical section is on the order of tens of nanoseconds per
call and the in-apply call volume — even with contention amplification —
cannot reach the 1 % Low floor, let alone the 3 % Medium floor required
by this objective. The hashing-budget ceiling in apply is a few percent;
lock removal recovers only a small fraction of the SipHash sub-share of
that ceiling.

### Lesson Learned

`gKeyMutex` contention is a real but quantitatively negligible cost on
the apply path; combined with H007's finding that SipHash recomputation
itself is dominated by the surrounding `unordered_set` walk, future
hypotheses targeting `shortHash` synchronization or recomputation should
not be filed against this objective unless paired with a structural
change to the consuming index data structure.
