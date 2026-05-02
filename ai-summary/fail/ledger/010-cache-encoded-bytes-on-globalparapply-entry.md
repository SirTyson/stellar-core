# H010: Carry cached XDR-encoded bytes for read-only Soroban entries through GlobalParallelApplyEntry to skip C++ re-encoding in addReads

**Date**: 2026-05-02
**Subsystem**: ledger / parallel apply / Soroban host bridge
**Severity**: Medium
**Impact**: 3-5% soroswap apply-time reduction by eliminating the per-tx
`xdr_to_opaque(LedgerEntry)` work in `addReads` for the dominant read-only
Soroban footprint entries (contract instances, contract code, frequently-read
ContractData), and reducing Rust-side `read xdr with budget` repetition
for those entries.
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

For every successful Soroban transaction the C++ apply path should ship
each footprint ledger entry to the Rust host **at most once per ledger** when
that entry is read-only and immutable for the ledger duration (because
`InMemorySorobanState` is the canonical immutable source within a ledger).
Pre-loading the entry into `GlobalParallelApplyEntry` is already done; the
encoded byte buffer required by the Rust bridge should be produced once at
pre-load time and reused (via `std::shared_ptr<std::vector<uint8_t> const>`)
across every `addReads` call that touches the same key, instead of being
re-serialized in `toCxxBuf(*entryOpt)` per transaction.

## Mechanism

`InvokeHostFunctionOpFrame::HostFunctionMetricsHelper::addReads`
(`src/transactions/InvokeHostFunctionOpFrame.cpp:484, 493`) calls
`toCxxBuf(*entryOpt)` for every footprint key on every transaction.
`toCxxBuf` (`src/transactions/TransactionUtils.h:370-376`) executes
`xdr::xdr_to_opaque(t)` and allocates a fresh
`std::vector<uint8_t>`. For soroswap, the same read-only contract instance
and contract-code entries are touched by **every** swap transaction, so the
host bridge re-encodes the same bytes thousands of times per ledger. The
GlobalParallelApplyLedgerState already pre-loads these RO entries from
`InMemorySorobanState` (`ParallelApplyUtils.cpp:646-718`) into
`mGlobalEntryMap` precisely because per-tx `InMemorySorobanState::get()`
costs a SHA256 + LedgerEntry copy; the symmetric per-tx XDR encode is the
remaining redundancy that has not been cached.

This deviates from the expected behaviour in two ways: (1) C++ pays
`O(n_tx × n_RO_keys)` `xdr_to_opaque` work where `O(n_RO_keys)` would
suffice, and (2) the Rust bridge then decodes those identical bytes
repeatedly via `read_xdr_with_budget` (1.17% self-time across 97k calls).
A `std::shared_ptr<std::vector<uint8_t> const>` carried alongside the
LedgerEntry in `GlobalParallelApplyEntry` (and propagated through
`ThreadParallelApplyEntry` → `TxParApplyLedgerEntryOpt`) lets `addReads`
construct a `CxxBuf` whose `data` field is shared (or, more conservatively,
copy the vector once instead of re-encoding from XDR — copying is still
cheaper than encoding for typical sizes).

## Trigger

Run `scripts/run_apply_load_matrix.py` soroswap scenario (TX=2000, T=8).
The soroswap workload re-uses the same router contract instance, two SAC
contract instances, and two SAC contract code entries across all 2000 swaps
per ledger — each marked read-only in tx footprints. `addReads` is invoked
twice per tx, encoding ~5-7 RO entries each call, producing ~15k-20k
redundant `xdr_to_opaque` calls per ledger that all serialize a small set of
identical entries.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:386-535` — `addReads`
  loop calling `toCxxBuf(*entryOpt)` and `toCxxBuf(*ttlEntry)` per key.
- `src/transactions/TransactionUtils.h:370-376` — `toCxxBuf` template
  performing `xdr_to_opaque` allocation per call.
- `src/transactions/ParallelApplyUtils.cpp:646-718` —
  `GlobalParallelApplyLedgerState` RO pre-load site; the natural place to
  encode-once into a shared buffer.
- `src/transactions/ParallelApplyUtils.h:81-100, 162` —
  `GlobalParallelApplyEntry` definition and `getLiveEntryOpt` flow that
  needs to carry the shared encoded buffer through the scoped wrappers.
- `src/ledger/InMemorySorobanState.h:46-66` — `ContractDataMapEntryT`
  already caches `sizeBytes`; the same construction site can produce and
  store the encoded buffer (or it can be produced lazily on first global
  pre-load to avoid memory cost for cold entries).
- `src/rust/src/bridge.rs:193-208` and
  `src/rust/src/soroban_invoke.rs:7-38` — bridge signature accepts
  `&CxxBuf` references; a shared-ownership variant or const reference is
  compatible with the existing borrowing pattern (per stored bridge fact).

## Evidence

1. Tracy soroswap trace (`1e0b14a6b879-20260430-160627`):
   `addReads` self-time 149,142,123 ns / 1.45% applyLedger; this number
   is the **C++ side** encoding cost only (it does not include the Rust
   `read xdr with budget` 1.17% counterpart).
2. The same trace shows `read xdr with budget` self 120,657,693 ns / 1.17%
   across 97,415 calls — these are the symmetric Rust-side decodes of the
   buffers produced in `addReads` plus auth / hostFunction inputs.
3. `GlobalParallelApplyLedgerState` already pays the cost to pre-load
   read-only Soroban entries precisely because it observed redundant
   per-thread `InMemorySorobanState::get()` work (see comments at
   `ParallelApplyUtils.cpp:646-653`); the same argument applies to the
   per-tx encode redundancy that follows.
4. Reviewer feedback on the previously rejected
   `003-cache-xdr-encoded-soroban-readonly-entries.md` explicitly noted:
   "encoded bytes must be carried at the
   GlobalParallelApplyEntry/ThreadParallelApplyEntry level with a zero-copy
   bridge path to eliminate both C++ encoding and Rust per-invocation
   decoding". This hypothesis follows that prescription rather than the
   rejected InMemorySorobanState-level approach.
5. Determinism is preserved: the encoded buffer is a deterministic function
   of the (immutable, per-ledger) `LedgerEntry`; sharing it across
   transactions does not alter ledger output, ordering, or hashing.

## Anti-Evidence

- Memory cost: an encoded buffer per cached entry inflates GlobalParallelApply
  state. Bounded by the live RO footprint per ledger (typically dozens of
  entries for soroswap, even at 2000 TPS), so total overhead is on the order
  of tens to a few hundred KB; tractable.
- The Rust bridge currently takes `&CxxBuf` (per stored memory
  `src/transactions/InvokeHostFunctionOpFrame.cpp:575-584`); reusing a
  shared buffer requires either (a) wrapping the shared buffer in a
  per-call `CxxBuf` whose vector is moved-out cheaply, or (b) copying the
  vector once. Both are cheaper than re-encoding, but the wins depend on
  which is chosen.
- For RW footprint keys the entry mutates per-tx; only RO entries can be
  cached. Soroswap RO/RW ratio is favorable (router + 2 instances + 2 code
  entries are RO; 1-2 ContractData entries per swap are RW), so most
  encodes are cacheable.
- TTL entries: RO Soroban entries also have an associated TTL entry that
  is encoded in `addReads` (`InvokeHostFunctionOpFrame.cpp:493`). TTLs
  *can* mutate when a tx calls `extend_ttl`, but the per-call mutation is
  rare relative to footprint reads and can fall back to the un-cached
  path when a dirty bit fires.
- Below-threshold risk: the C++ encode portion alone is only ~1.45%; the
  hypothesis depends on additionally eliminating most of the Rust decode
  side (1.17%) to land in Medium territory. A PoC must measure both
  sides, not just the C++ encode.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-02
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — the earlier failed `003-cache-xdr-encoded-soroban-readonly-entries.md` covered the misplaced `InMemorySorobanState` cache design; this version moves the proposed cache to the global/thread scoped parallel-apply layer, and no ledger success record covers this exact design.
**Failed At**: reviewer

### Trace Summary

The C++ inefficiency exists: during parallel Soroban apply, `InvokeHostFunctionOpFrame::addReads` obtains each footprint entry through the tx/thread scoped ledger state, then serializes it into a fresh owned `CxxBuf` for every invocation. Global preloading already avoids repeated `InMemorySorobanState::get()` calls for read-only Soroban keys, but the scoped entry maps carry only `LedgerEntry` values, not encoded buffers. However, cached encoded bytes at this layer would only remove the C++ `xdr_to_opaque` work (or replace it with a vector copy under the current bridge type); the Rust host still receives per-invocation buffers and decodes them into a fresh storage map with `metered_from_xdr_with_budget`. Therefore the only clearly removable in-scope cost is the `addReads` encode fraction, which is below the optimize-soroswap Medium severity floor.

### Code Paths Examined

- `src/transactions/InvokeHostFunctionOpFrame.cpp:386-497` — `addReads` loops over read-only and read-write footprints, calls `getLedgerEntryOpt`, serializes `*entryOpt` via `toCxxBuf`, serializes TTLs via `toCxxBuf(*ttlEntry)`, and stores owned buffers in `mLedgerEntryCxxBufs` / `mTtlEntryCxxBufs`.
- `src/transactions/TransactionUtils.h:370-376` — `toCxxBuf` constructs a new `std::vector<uint8_t>` from `xdr::xdr_to_opaque(t)` on each call.
- `src/transactions/ParallelApplyUtils.cpp:646-718` — `GlobalParallelApplyLedgerState` preloads read-only Soroban entries and their TTL entries from `InMemorySorobanState` / LCL into `mGlobalEntryMap`, but stores only scoped `LedgerEntry` optionals.
- `src/transactions/ParallelApplyUtils.cpp:925-1000` — thread state copies global scoped entries into `mThreadEntryMap` before cluster execution.
- `src/transactions/ParallelApplyUtils.cpp:1285-1313` and `src/transactions/ParallelApplyUtils.cpp:337-342` — each transaction creates a `TxParallelApplyLedgerState`; `getLedgerEntryOpt` adopts from thread scope into tx scope and returns a copied `std::optional<LedgerEntry>` to `addReads`.
- `src/transactions/TransactionFrameBase.h:107-153` — `ParallelApplyEntry` contains only `ScopedLedgerEntryOpt<S>`, dirty state, and new-entry state; no existing side channel carries encoded bytes.
- `src/rust/src/bridge.rs:13-15` and `src/rust/src/bridge.rs:193-208` — `CxxBuf` owns a `UniquePtr<CxxVector<u8>>`, and `invoke_host_function` receives `Vec<CxxBuf>` for ledger and TTL entries, so the existing bridge ABI is not a shared-buffer zero-copy API.
- `src/rust/src/soroban_proto_any.rs:433-443` — the bridge adapter passes `ledger_entries.iter()` and `ttl_entries.iter()` into the protocol-specific host function on every invocation.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:439-447` and `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:959-1043` — enforcing-mode invocation builds a new storage map per call and decodes every supplied ledger and TTL buffer with `metered_from_xdr_with_budget`.
- `ai-summary/success/ledger/002-cache-old-entry-xdr-sizes.md:9-16` — the existing successful XDR-size cache addresses post-decode rent-size reserialization, not ingress `addReads` buffer construction or host input decoding.

### Why It Failed

The proposed mechanism depends on counting both C++ `addReads` serialization and Rust `read xdr with budget` as removable. The C++ side is real, but the Rust side is not removed by caching encoded bytes in `GlobalParallelApplyEntry`: the host API still consumes encoded ledger-entry buffers and rebuilds a fresh enforcing storage map per invocation, so each invocation must deserialize its inputs unless a much larger decoded-storage or host-state reuse design is introduced. The hypothesis's own trace numbers put `addReads` self-time at 1.45% of `applyLedger`; even if all C++ serialization inside that zone disappeared, the result would be Low/sub-Medium for the optimize-soroswap objective, and the objective rejects Low-severity hypotheses.

### Lesson Learned

For Soroban host-input optimizations, separate "avoid C++ re-encoding the bytes" from "avoid Rust decoding the bytes." Carrying encoded buffers through scoped parallel-apply state can address the former, but the current `CxxBuf`/host API intentionally presents encoded XDR to each fresh invocation, so Medium-tier savings require a design that removes or amortizes the Rust per-invocation storage-map decode as well, not just a global cached byte vector.
