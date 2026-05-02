# H006: Pre-serialize InMemorySorobanState LedgerEntries to avoid per-tx toCxxBuf XDR encoding in addReads

**Date**: 2026-05-02
**Subsystem**: transactions
**Severity**: Low
**Impact**: Eliminate redundant XDR re-encoding when handing soroban footprint entries from `InMemorySorobanState` to the Rust bridge, by storing entries in their already-XDR-encoded form alongside the unwrapped `LedgerEntry`.
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

For a soroban parallel-apply worker, the path that hands a CONTRACT_DATA
or CONTRACT_CODE entry from the in-memory soroban cache to the Rust
bridge should ideally not re-serialize the entry every time. The entry
arrives at `InMemorySorobanState` in XDR form (from BucketList load /
network state machine), is decoded once into a `LedgerEntry`, then in
the soroban apply hot path is re-encoded back to XDR by `toCxxBuf` for
every read. The expected behavior is that the cache stores both the
already-decoded `LedgerEntry` (for stellar-core-side use such as TTL /
metadata) and the canonical XDR bytes (for hand-off to the Rust bridge),
so that `addReads` can attach a shared, immutable byte buffer to the
`CxxBuf` instead of re-encoding.

## Mechanism

`InMemorySorobanState` stores soroban entries as
`std::shared_ptr<LedgerEntry const>` (unwrapped XDR struct), see
`src/ledger/InMemorySorobanState.h:46-65,326-330`. Each soroban worker
read in `addReads` does:

```cpp
auto entryOpt = getLedgerEntryOpt(lk);     // copies LedgerEntry out
auto leBuf = toCxxBuf(*entryOpt);          // xdr::xdr_to_opaque + heap alloc
entrySize = static_cast<uint32_t>(leBuf.data->size());
```

(`src/transactions/InvokeHostFunctionOpFrame.cpp:476-498`)

`toCxxBuf<T>` is defined in `src/transactions/TransactionUtils.h:370-376`
as `std::make_unique<std::vector<uint8_t>>(xdr::xdr_to_opaque(t))`. So
every read of a soroban footprint entry from the in-memory cache
performs:

1. A `std::optional<LedgerEntry>` materialization in
   `ParallelLedgerAccessHelper::getLedgerEntryOpt` (copies the
   `shared_ptr` content into an optional).
2. An XDR encode of the LedgerEntry into a fresh `std::vector<uint8_t>`.
3. A heap allocation for that vector and the surrounding `unique_ptr`.

For an entry served from `InMemorySorobanState`, the same XDR bytes
were available at insertion time (the entry was decoded from a
BucketList byte stream / network state). Storing those bytes alongside
the `LedgerEntry` and handing them out as a `shared_ptr<vector<uint8_t>
const>` would let `toCxxBuf`-style callers attach a shared buffer
without re-encoding.

The entries are immutable in `InMemorySorobanState` for the duration of
a ledger close (they are replaced atomically by
`updateInMemorySorobanState (async)` in `src/ledger/LedgerManagerImpl.cpp`
after apply), so a shared-buffer model is safe.

## Trigger

Run the soroswap apply-load scenario (`soroswap, TX=2000, T=8`). Every
soroban tx that reads CONTRACT_CODE or CONTRACT_DATA footprint entries
exercises `addReads` → `toCxxBuf` per key.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:476-498` — `addReads`
  body where each entry is loaded, copied, and re-encoded.
- `src/transactions/TransactionUtils.h:370-376` — `toCxxBuf` template.
- `src/ledger/InMemorySorobanState.h:46-79,326-330` — entry storage
  layout (currently `shared_ptr<LedgerEntry const>` only).
- `src/ledger/InMemorySorobanState.cpp:206-238` — `get(LedgerKey)`
  return surface that would need a parallel "get xdr buffer" sibling.
- `src/transactions/ParallelApplyUtils.cpp:1085-1121` —
  `ThreadParallelApplyLedgerState::getLiveEntryOpt` lookup boundary.

## Evidence

In the accepted soroswap trace
(`/mnt/nvme2/apply-load/1e0b14a6b879-20260430-160627/logs/...02-soroswap-tx-2000-t-8.tracy`):

- `addReads, transactions/InvokeHostFunctionOpFrame.cpp:388` — total
  206,489,901 ns (2.0%) / self 149,142,123 ns (1.45%) over 10,294
  invocations. Most of `addReads` self-time is the per-key
  validate + `toCxxBuf` + ledger entry copy combination.
- `InvokeHostFunctionOpFrame doApply` mean per tx 2,159,684 ns; the
  soroban host (`invokeHostFunction`) totals 10,655,698,784 ns / 5,093
  calls = 2,092,224 ns mean. So addReads is ~3% of per-tx cost.

Per-soroswap tx footprint: ~5 RO + ~5 RW soroban entries. For each, the
worker performs one `getLedgerEntryOpt(lk)` returning an
`std::optional<LedgerEntry>` (one copy of the LedgerEntry out of the
cache) plus one `toCxxBuf` (one XDR encode + heap allocation). Together
that is ~10 redundant XDR encodes per tx, each over a contract-data
entry that was decoded from XDR before insertion into
`InMemorySorobanState`.

## Anti-Evidence (why it is NOT viable for this objective)

Quantifying the addressable surface:

- `addReads` self-time of 149ms across the trace, divided by 8 worker
  threads = ~18.6ms wall on critical path.
- Of that 18.6ms, the share attributable to `toCxxBuf` (XDR encode +
  heap alloc) is realistically half — the rest is
  `validateContractLedgerEntry`, the `getLedgerEntryOpt` map lookup
  itself, the optional copy out of the InMemorySorobanState, etc. So
  the upper bound on this specific optimization is ~9ms of critical
  path across the trace = ~0.13ms per ledger = ~0.05% of the ~280ms
  soroswap close median.
- Even an aggressive design that also removes the per-lookup
  `optional<LedgerEntry>` copy and threads a shared `CxxBuf` directly
  through the bridge would cap at ~0.2% — well below the 3% Medium
  floor.

Additional risks that would shrink the addressable surface further:

- The `LedgerEntry::lastModifiedLedgerSeq` field is mutated when the
  entry is dirtied by apply; pre-serialized buffers must not include
  stale `lastModifiedLedgerSeq` values for entries that have been
  modified during the same close. (Read-only soroban footprint entries
  in `addReads` are unmodified, so this is solvable, but it adds
  versioning complexity to `InMemorySorobanState`.)
- The pre-serialized buffer roughly doubles the in-memory footprint of
  `InMemorySorobanState`, which is not free for the network configs
  this benchmark uses.
- Existing successes (`bulk-build-host-storage-maps`,
  `cache-old-entry-xdr-sizes`) already removed the largest XDR
  re-encoding opportunities on the soroban write side; the read side
  is what remains, and it is structurally smaller.

## Why filed as fail rather than hypothesis

Per the optimize-soroswap rules: "Minimum severity: Medium ... If your
projected impact is Low (1–3% apply time reduction), do not write the
hypothesis to ai-summary/hypothesis/". The projected wall-clock impact
is ~0.05–0.2%, an order of magnitude below the Medium threshold and
below the 1% benchmark-noise floor.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-02
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated. Distinct from
fail/001-cluster-shared-readonly-footprint-prebuild (sharing CxxBufs
across txs in a cluster), fail/002-metered-xdr-size-for-rent (rent
sizing buffers), and fail/CURRENT_STATE entries (write-side
optimizations like `cache-old-entry-xdr-sizes`).

### Why It Failed

Below objective severity threshold. The total `addReads` self-time
across the trace is 149ms; even the most optimistic `toCxxBuf`-only
share, divided by T=8 worker parallelism, is ~9ms wall over 70
ledgers. That maps to ~0.05% of soroswap close-time and is well
inside benchmark noise. Pre-serialization also imposes memory and
versioning costs that further erode the marginal benefit.

### Lesson Learned

The soroban read-side `addReads` → `toCxxBuf` re-encoding is real but
not on the soroswap critical path at any meaningful scale, especially
after the `cache-old-entry-xdr-sizes` and bulk-build storage
optimizations that already addressed the write side. Future hypotheses
that target soroban footprint serialization must combine multiple
removable per-key costs (XDR re-encode + redundant SHA-256 +
`make_unique` heap allocations + optional-copy-out) AND demonstrate the
sum reaches Medium against the authoritative non-Tracy close-time
baseline before promotion.
