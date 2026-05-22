# H022: Specialize `InMemorySorobanState::getTTL` for callers that know the underlying entry type

**Date**: 2026-05-22
**Subsystem**: soroban-env (C++ bridge: `InMemorySorobanState` / `addReads`)
**Severity**: Low
**Impact**: Apply-time reduction (CPU on apply hot path)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

When `addReads` walks an op's footprint and needs the TTL for a soroban
entry, it should perform exactly one hash-table lookup against the
appropriate `InMemorySorobanState` map — `mContractDataEntries` for a
`CONTRACT_DATA` source key, or `mContractCodeEntries` for a
`CONTRACT_CODE` source key — since the caller already knows the
underlying type (it just called `getTTLKey(lk)`).

## Mechanism

`InMemorySorobanState::getTTL` (`src/ledger/InMemorySorobanState.cpp:413`)
is invoked with a `TTL` key whose `keyHash` is opaque to it. The comment at
line 430 acknowledges: "Since the TTL key is the hash of the associated
LedgerKey, we don't know which map it could belong in, so check both." It
therefore always probes `mContractDataEntries.find(...)` first and then
`mContractCodeEntries.find(...)` on miss. In `addReads`
(`src/transactions/InvokeHostFunctionOpFrame.cpp:411`), every soroban
footprint entry triggers a `getLedgerEntryOpt(ttlKey)` that falls through
(via `ThreadParallelApplyLedgerState::getLiveEntryOpt`,
`src/transactions/ParallelApplyUtils.cpp:1085`) to
`InMemorySorobanState::get` → `getTTL`. The caller in `addReads` already
knows whether the source key `lk` is `CONTRACT_DATA` or `CONTRACT_CODE`, so
the second `find` is provably wasted work on every soroban-entry TTL
lookup.

## Trigger

Run `scripts/run_apply_load_matrix.py` against a soroswap workload. Every
soroban footprint entry processed by `addReads` triggers one wasted
hash-table probe inside `InMemorySorobanState::getTTL`.

## Target Code

- `src/ledger/InMemorySorobanState.cpp:413-446` — `getTTL` double-probe.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:386-535` — `addReads`
  footprint walk that calls `getLedgerEntryOpt(ttlKey)` per entry.
- `src/transactions/ParallelApplyUtils.cpp:1085-1121` — thread-state
  fallthrough into `InMemorySorobanState::get`.

## Evidence

- Tracy zone `addReads` (`InvokeHostFunctionOpFrame.cpp:388`): 205.8 ms
  aggregate self, 14,092 calls, ~14.6 µs/call on the 2026-05-22 soroswap
  baseline trace
  (`/mnt/nvme2/apply-load/2ff900fcd176-20260522-031343/logs/...-02-soroswap-tx-2000-t-8.tracy`).
- `getTTL`'s comment explicitly acknowledges the double-probe.
- A specialized overload that takes the source-entry type as a hint would
  pick the correct map on the first probe, eliminating one `unordered_set`
  lookup per soroban-entry TTL access on the apply path.

## Anti-Evidence

- Per-call cost of a single `unordered_set::find` against the in-memory
  maps is on the order of 100–200 ns.
- Even a generous estimate of ~5–7 soroban footprint entries per op × 14,092
  ops × ~150 ns per skipped probe ≈ 12–15 ms aggregate trace time.
- Normalising by 8-cluster apply parallelism and 72 measured ledgers gives
  roughly 0.025 ms per ledger, ≈ 0.01% of the 250 ms soroswap apply
  baseline.
- The `getTTL` zone is not separately broken out in the trace, and even the
  parent `addReads` zone (205 ms) is only ~4% of the apply envelope; the
  removable double-probe is a tiny sub-fraction of that.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Failed At**: hypothesis
**Novelty**: PASS — not present in fail/hypothesis/reviewed/poc.

### Why It Failed

The optimization is correct and clean, but its projected apply-time impact
is ≈ 0.01% — three orders of magnitude below this objective's 3% Medium
floor and well under the 1% benchmark noise floor. Per the objective rules
("Minimum severity: Medium"), Low projections must be written to fail/
rather than promoted to hypothesis/.

### Lesson Learned

`InMemorySorobanState::getTTL`'s "probe both maps" comment looks like a
clear inefficiency, but the cost of an `unordered_set` lookup at the
relevant table sizes is small enough that even eliminating it for every
soroban footprint entry on every op falls far short of the Medium floor.
Future C++-side InMemorySorobanState micro-optimisations should pre-quantify
`ns × call_count / parallelism / ledger_count` before promotion; the
benchmark window's apply-path budget is dominated by host-side metering and
Wasm execution, not by hot-path hash probes.
