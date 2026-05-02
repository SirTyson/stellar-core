# H006: Empty-set fast path for `flushRoTTLBumps` per-tx and per-cluster walks

**Date**: 2026-05-02
**Subsystem**: transaction-ledger / parallel apply
**Severity**: Low
**Impact**: Per-tx avoidable RW footprint walk in worker hot loop
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`ThreadParallelApplyLedgerState::flushRoTTLBumpsInTxWriteFootprint` (called
once per tx in `LedgerManagerImpl::applyThread` at line 2502 before the host
invocation) and `flushRemainingRoTTLBumps` (called once per cluster at line
2518) should perform zero work in the common case where `mRoTTLBumps` is
empty for the relevant keys. For soroswap, RO TTL bumps are produced only by
SAC code/instance auto-extension on the very first SAC call to a contract;
later txs in the same cluster typically find the bump already drained.
Walking the tx RW footprint, calling `getTTLKey` (which builds a
`TTLKey(LedgerKey)` and computes its hash) and probing `mRoTTLBumps.find`
for each RW key when the bump map is empty is wasted CPU on the cluster's
critical path.

## Mechanism

`flushRoTTLBumpsInTxWriteFootprint` (`ParallelApplyUtils.cpp:1004`)
unconditionally iterates `txBundle.getTx()->sorobanResources().footprint.readWrite`
and, for each Soroban RW key, builds the TTL key and probes
`mRoTTLBumps.find(ttlParallelKey)`. When `mRoTTLBumps` is empty the entire
loop is dead work. A trivial guard `if (mRoTTLBumps.empty()) return;` at the
top of both `flushRoTTLBumpsInTxWriteFootprint` and `flushRemainingRoTTLBumps`
would skip the per-key walk in that case.

## Trigger

Any soroswap parallel-apply cluster after the first SAC code/instance TTL
extension has been drained back to the writable footprint by an earlier tx.
For most clusters `mRoTTLBumps` is empty for most txs.

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:1004-1039` — `flushRoTTLBumpsInTxWriteFootprint`
- `src/transactions/ParallelApplyUtils.cpp:1041-1064` — `flushRemainingRoTTLBumps`
- `src/ledger/LedgerManagerImpl.cpp:2502,2518` — call sites in `applyThread`

## Evidence

- Per-tx call inside the worker hot loop (one of the few non-host operations
  that runs unconditionally per tx in `applyThread`).
- The map is populated only via `addRoTTLBump`, which is itself called only
  on the SAC code/instance auto-extend path, and is drained both by
  `flushRoTTLBumpsInTxWriteFootprint` (when the bumped key reappears in a
  later tx's RW footprint) and by `flushRemainingRoTTLBumps` at end of
  cluster.
- For soroswap clusters dominated by repeated swap calls on the same pair,
  the SAC instance/code TTL bumps land in `mRoTTLBumps` once and are then
  pulled out by the first subsequent tx whose RW footprint references them;
  remaining txs in the cluster see an empty map.

## Anti-Evidence

- The walk is very cheap per key: 2 RW soroban keys per tx × ~5093 txs ×
  (`isSorobanEntry` + `getTTLKey` + hashed lookup ≈ 100–200 ns total) =
  roughly 1–2 ms aggregate worker time across the entire benchmark.
- After dividing by `NUM_CLUSTERS=8`, the critical-path saving is on the
  order of 100–250 µs per benchmark run. As a per-ledger figure that is
  ~3 µs / ledger, four orders of magnitude below the Medium 3 % floor (≈
  8.4 ms / ledger).
- No Tracy zone exists for these calls (they don't appear in
  `soroswap_self.csv`), confirming the absolute time is sub-instrumentation
  overhead.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-02
**Failed At**: hypothesis
**Novelty**: PASS — the `flushRoTTL...` empty-fast-path has not been
investigated in any prior fail/hypothesis/reviewed/poc record.

### Why It Failed

The targeted work is real but absolutely tiny. Aggregate worker time for the
empty-map fast path saves at most low-millisecond CPU time across the entire
70-ledger benchmark, divided by 8 clusters, giving sub-millisecond
critical-path savings per benchmark run. The optimize-soroswap objective
explicitly excludes Low (1–3 %) hypotheses at the hypothesis stage; this
falls four orders of magnitude below even the Low floor.

### Lesson Learned

Per-tx worker bookkeeping calls that lack a Tracy zone in the soroswap
self-time CSV are below the instrumentation noise floor. Adding a fast path
to such code is a free correctness/clarity win but cannot be justified as a
performance optimization at the Medium severity bar.
