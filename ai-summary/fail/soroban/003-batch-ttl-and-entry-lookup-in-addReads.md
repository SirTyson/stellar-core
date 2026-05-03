# H003: Batch TTL+entry lookups in `InvokeHostFunctionOpFrame::addReads` to halve `InMemorySorobanState::get` probes

**Date**: 2026-05-03
**Subsystem**: transactions / ledger
**Severity**: Low
**Impact**: Reduce per-tx footprint walk cost in `addReads` (Tracy: 197 ms self / 13 648 calls / ~1.91% of `applyLedger`).
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`InvokeHostFunctionOpFrame::addReads` (`src/transactions/InvokeHostFunctionOpFrame.cpp:380-450`)
walks a Soroban transaction's read-only and read-write footprint keys. For each Soroban
contract-data / contract-code key it must establish two facts:

1. Whether the entry currently exists in the live snapshot, and if so its size for read-byte
   accounting.
2. Whether the corresponding TTL entry indicates the entry is live or archived.

The most efficient implementation looks each pair up with a *single* hash and a *single* probe
into `InMemorySorobanState`'s underlying map, since CONTRACT_DATA / CONTRACT_CODE entries and
their TTL siblings live in the same map shard and share the same key prefix (the contract-data
ledger key hash is the seed for the TTL key).

## Mechanism

The current implementation calls `getLedgerEntryOpt(key)` for the data entry and a separate
`getLedgerEntryOpt(getTTLKey(key))` for the TTL. Each call hashes the LedgerKey (32-byte SHA256
or equivalent) and probes the map. For ~6.7 k Soroban txs each carrying an average ~6 footprint
entries, this is ~80 k key-hash + map-probe pairs per ledger, of which exactly half are
redundant since (a) the TTL key is derivable from the data key with a single SHA256 step that
is already done inside `getTTLKey`, and (b) `InMemorySorobanState`'s storage is keyed in a way
that allows a coalesced lookup that returns both entries in one probe.

The deviation from expected behaviour is the doubled probe count: actual cost is 2× the
necessary lookups, plus the extra `getTTLKey` recompute on every footprint walk.

## Trigger

Soroswap apply-load benchmark; observe `addReads` zone in Tracy.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:380-450` — `addReads` loop body.
- `src/bucket/InMemorySorobanState.cpp` — `get` / `getTTL` API surface that would need a new
  combined `getEntryAndTtl(key)` method.
- `src/ledger/LedgerTxnImpl.cpp` (`getTTLKey`) — TTL key derivation, currently re-run per call.

## Evidence

- Tracy: `addReads` 197 ms self / 13 648 calls / 14.4 µs per call. The combined-probe path
  would, by structural argument, eliminate one of the two hash+probe operations per key.
- `InMemorySorobanState` currently exposes separate `get` / `getTTL` methods on the same
  underlying storage; the underlying map *can* return both with one probe.

## Anti-Evidence

- See Review.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-03
**Failed At**: hypothesis
**Novelty**: PASS — the specific batched-API angle is not in fail/summary.md, but the
projected savings ceiling is below the objective severity floor.

### Why It Failed

`addReads` accounts for **1.91%** of `applyLedger` Tracy time. Even an optimistic 50% reduction
(eliminating one of the two probes for every footprint key) yields only ~0.96% of `applyLedger`
Tracy time, which translates to **~0.26% of real benchmark apply time** by the Tracy/real
proportion in the current accepted trace. That is an order of magnitude below the
**Medium = 3%** severity floor declared in the optimize-soroswap objective, and well within
benchmark noise.

In addition, `InMemorySorobanState::get` and `getTtl` are already covered by the cluster of
fails #024 / #014 / #017 (TTL-and-footprint caching) as well as fail #027 (per-call alloc and
virtual dispatch in the same `get` path). Those fails noted that further per-call work
reductions in this exact API hover around the 0.3–1% level, consistent with the bound derived
here.

The clean-diff size is small (a single new combined-API method plus one call-site change), but
the change still carries non-trivial ABI risk to `InMemorySorobanState` consumers, requires
adding a new public method on a hot interface, and must be justified by a measurable benchmark
move. Below-1% savings cannot be reliably distinguished from noise by
`scripts/run_apply_load_matrix.py`, which is the explicit termination criterion in the
objective context.

### Lesson Learned

For any per-tx footprint-loop micro-optimisation, divide the parent zone's `applyLedger` share
by **2** (the realistic reduction ceiling for this pattern) and check against the 3% Medium
floor *before* writing a hypothesis. `addReads`-class zones at <2% of `applyLedger` cannot
clear the floor on per-element work alone; they require a structural change (e.g., hoisting
out of the per-tx loop entirely into a once-per-ledger pre-built table) to be viable.
