# H005: Cache TTL keyhash to avoid per-lookup SHA-256 in InMemorySorobanState::get(CONTRACT_DATA)

**Date**: 2026-05-02
**Subsystem**: transactions
**Severity**: Low
**Impact**: Eliminate redundant per-lookup XDR-encode + SHA-256 + heap allocation when resolving CONTRACT_DATA / CONTRACT_CODE LedgerKeys against `InMemorySorobanState` from soroban worker threads.
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

Resolving a CONTRACT_DATA (or CONTRACT_CODE) `LedgerKey` against
`InMemorySorobanState` from a soroban parallel-apply worker should be a
constant-time hash-table probe whose key-side cost is bounded by one
already-computed hash plus an equality check. The TTL keyhash for a given
footprint key has already been computed earlier in the apply path
(`InvokeHostFunctionOpFrame::addReads` line 406 calls `getTTLKey(lk)` for
every soroban footprint entry), so subsequent `InMemorySorobanState::get(lk)`
calls for the same key should not recompute that hash.

## Mechanism

`InMemorySorobanState::get(LedgerKey const&)` for a CONTRACT_DATA key
constructs a temporary `InternalContractDataMapEntry(ledgerKey)` (see
`src/ledger/InMemorySorobanState.h:249-255`). That constructor:

1. Calls `getTTLKey(ledgerKey)` →
   `sha256(xdr::xdr_to_opaque(ledgerKey))` (`src/ledger/LedgerTypeUtils.cpp:36`),
   doing a fresh XDR encode plus SHA-256 of the entire LedgerKey on every
   probe.
2. Allocates a `QueryKey` via `std::make_unique<QueryKey>(...)` for
   each lookup — a dynamic dispatch wrapper that exists solely so the
   stored `ValueEntry` and lookup `QueryKey` can share a virtual interface
   in `mContractDataEntries`.
3. Then `mContractDataEntries.find(...)` calls
   `std::hash<uint256>{}(ledgerKeyHash)` on the result.

`ThreadParallelApplyLedgerState::getLiveEntryOpt`
(`src/transactions/ParallelApplyUtils.cpp:1085-1121`) is the soroban worker
path and calls `mInMemorySorobanState.get(key)` whenever the key is not in
the per-thread map. `addReads` (`src/transactions/InvokeHostFunctionOpFrame.cpp:411,476`)
goes through that path twice per soroban footprint entry (TTL lookup, then
data-entry lookup), and `getReadWriteKeysForStage`
(`src/transactions/ParallelApplyUtils.cpp:104-132`) plus
`recordStorageChanges` re-derive the same TTL key independently. The
deviation from the expected behavior is the redundant SHA-256 + heap
allocation per CONTRACT_DATA lookup — the caller already has, or can
cheaply carry, the TTL keyhash.

## Trigger

Run the soroswap apply-load scenario (`soroswap, TX=2000, T=8`). Every
soroban tx footprint hit on `addReads` triggers two `getLiveEntryOpt` calls
per CONTRACT_DATA / CONTRACT_CODE key (TTL key + entry key); the entry-key
lookup recomputes the TTL hash that `addReads` already produced.

## Target Code

- `src/ledger/InMemorySorobanState.h:249-265,151-156` —
  `InternalContractDataMapEntry(LedgerKey const&)` and
  `ValueEntry::copyKey()` both call `getTTLKey(...)` per lookup.
- `src/ledger/InMemorySorobanState.cpp:206-238` —
  `InMemorySorobanState::get`, with the CONTRACT_CODE branch also calling
  `getTTLKey(ledgerKey)` directly.
- `src/ledger/LedgerTypeUtils.cpp:30-38` — `getTTLKey(LedgerKey)` does
  `sha256(xdr_to_opaque(e))`.
- `src/transactions/ParallelApplyUtils.cpp:1085-1121` —
  `ThreadParallelApplyLedgerState::getLiveEntryOpt` calling site.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:395-498` — `addReads`
  computing the TTL key and then re-doing it implicitly through the data
  lookup.

## Evidence

In the current accepted soroswap trace
(`/mnt/nvme2/apply-load/1e0b14a6b879-20260430-160627/logs/...02-soroswap-tx-2000-t-8.tracy`):

- `sha256, crypto/SHA.cpp:33` — 605,759,766 ns total / 396,740 calls /
  mean 1,526 ns. (Captures all SHA-256 in the trace, including TX-set
  construction, fee processing, etc.)
- `InvokeHostFunctionOpFrame doApply` mean per tx is 2,159,684 ns; only
  a small fraction is C++-side. `addReads` self is 149,142,123 ns / 1.45%,
  matching the structural picture that per-key XDR/hash work is non-zero
  but not dominant.

Source confirms: every CONTRACT_DATA lookup pays an XDR encode + SHA-256 +
`make_unique` heap allocation, and `addReads` invariably runs the same
`getTTLKey(lk)` immediately before the data lookup, so the second hash is
a literal duplicate.

## Anti-Evidence (why it is NOT viable for this objective)

Estimating addressable wall-clock impact:

- For T=8 soroswap, addReads runs ~10,294 times per trace (5,093 tx ×
  ~2 RO+RW passes), with ~4 contract_data keys per soroban footprint on
  average → ~40,000 redundant `InternalContractDataMapEntry(LedgerKey)`
  constructions per trace.
- Each redundant call costs an XDR encode (small) plus a SHA-256 over a
  ~50-byte LedgerKey. SHA-256 trace mean is ~1.5us; the XDR + alloc adds
  perhaps another 0.5–1us. Generous bound: ~3us per call.
- Aggregate: 40,000 × 3us = 120ms across all worker threads in the
  trace. Critical-path (T=8): ~15ms across 70 ledgers = ~0.21ms per
  ledger.
- Versus the 280ms soroswap close-time median: ~0.075% improvement
  upper bound.

This is far below the 1% benchmark-noise floor and well below the 3%
Medium threshold.

A combined refactor that also (a) removes the `make_unique<QueryKey>`
heap allocation from every CONTRACT_DATA lookup and (b) carries the
already-computed TTL keyhash through `getLiveEntryOpt` would still be
sub-1%. The InMemorySorobanState path is already a hash-table probe
post-lookup; the per-call constant factor is small relative to the rest
of `addReads` (the dominant cost is `toCxxBuf` and entry-validation
work).

## Why filed as fail rather than hypothesis

Per the optimize-soroswap rules: "Minimum severity: Medium ... If your
projected impact is Low (1–3% apply time reduction), do not write the
hypothesis to ai-summary/hypothesis/ — write it to
ai-summary/fail/transactions/ instead". The maximum addressable wall-clock
impact here is ~0.1%, which falls below even the Low band.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-02
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated. Distinct from
fail/001-mutable-enforcing-storage-map-writes (host map insert),
fail/002-single-pass-ledger-change-map-diff (post-invocation diff),
and fail/003-precompute-modified-classic-keys-hashset
(`requiresSequentialPreParallelApply` snapshot loads).

### Why It Failed

Below objective severity threshold. The per-lookup SHA-256 +
`make_unique<QueryKey>` cost is real and structurally avoidable, but the
total addressable wall-time across the soroswap trace bounds at ~0.1% of
close time (15ms of critical-path savings against ~19s of close time).
Even an aggressive implementation that threaded the precomputed TTL
keyhash through `getLiveEntryOpt` and the ContractData map's
`InternalContractDataMapEntry` interface — including replacing the
virtual `AbstractEntry`/`make_unique<QueryKey>` indirection with a plain
PoD lookup key — could not lift this to Medium.

### Lesson Learned

`InMemorySorobanState::get` for CONTRACT_DATA / CONTRACT_CODE keys
performs a per-lookup XDR-encode + SHA-256 + heap allocation via the
`InternalContractDataMapEntry(LedgerKey)` ↔ `QueryKey` virtual interface.
This is a small constant per probe but is not a soroswap apply-time
bottleneck on its own. Any future hypothesis that refactors this lookup
should first justify Medium-tier impact independent of the per-probe
hash cost — e.g. by also removing `toCxxBuf` re-serialization or by
batching multiple lookups across a stage.
