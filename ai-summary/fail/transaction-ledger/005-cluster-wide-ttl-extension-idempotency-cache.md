# H005: Cluster-wide TTL extension idempotency cache across transactions

**Date**: 2026-05-22
**Subsystem**: transaction-ledger
**Severity**: Low
**Impact**: Apply-time reduction from eliding redundant
`extend_current_contract_instance_and_code_ttl` calls across transactions in
the same Soroban apply cluster
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

For a Soroban apply cluster that executes ~10–15 transactions sequentially on
one worker, each calling SAC `transfer` / `transfer_from` and therefore
`extend_current_contract_instance_and_code_ttl` for the same SAC `(instance,
code)` pair, the host should only do real TTL-extension work on the first call
in the cluster. Subsequent calls in the same cluster that target a
`(contract_id, code_hash, target_live_until_ledger)` triple already serviced
should be no-ops: no storage lookup, no `MeteredOrdMap` insert, no TTL bump in
`mRoTTLBumps`. The cache may still need to charge the protocol-visible per-call
budget to preserve `cpu_insns` / `mem_bytes` semantics.

## Mechanism

The accepted SAC code path calls `extend_current_contract_instance_and_code_ttl`
at the end of every `transfer`, `transfer_from`, `mint`, `burn`,
`burn_from`, `clawback`, `set_admin`, `set_authorized`, `approve`,
`deauthorize` — every state-changing SAC operation. For soroswap, each swap
performs 2 SAC transfers (one for each token leg), so each tx generates ≥ 2
extensions of the same SAC instance/code. The current per-tx coalescing
addressed in `fail/transaction-ledger/summary.md` H006 only deduplicates
within a single tx; across txs in the same cluster the same SAC instance is
re-extended every time, with each call doing a storage-map lookup and a TTL
update / `mRoTTLBumps` accumulation. A per-worker `(contract_id, code_hash) →
already_extended_to_ledger` cache, reset at cluster boundaries, would skip the
storage and TTL work on cache hits while still charging budget.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=2000, T=8`). Each
cluster contains 10–15 swap transactions targeting the same small set of
SAC tokens; nearly every transaction calls
`extend_current_contract_instance_and_code_ttl` for the same `(token_sac_id,
code_hash)` pair multiple times.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs` —
  `Host::extend_current_contract_instance_and_code_ttl` implementation; reads
  current frame's contract, loads instance entry, extends instance TTL, looks
  up code key, extends code TTL.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:150-326`
  — 10 SAC entry points that all call
  `extend_current_contract_instance_and_code_ttl`.
- `src/transactions/ParallelApplyUtils.cpp:1033,1059` —
  `ThreadParallelApplyLedgerState::upsertEntry` writes RW TTL bumps;
  `mRoTTLBumps` accumulates RO bumps. Cluster-wide cache would be attached to
  `ThreadParallelApplyLedgerState`.

## Evidence

The current Tracy soroswap trace reports:
- `extend_current_contract_instance_and_code_ttl` (vmcaller_env.rs:270):
  390.3 ms self, 27 942 events.
- `extend_current_contract_instance_and_code_ttl` (dispatch.rs:304):
  114.3 ms self, 14 039 events.
- Combined aggregate worker self-time: ≈ 504 ms across the 70-ledger trace.

70 ledgers × 8 clusters → 27 942 / 70 / 8 ≈ 50 extensions per cluster.
If the cluster touches ~5 distinct SAC contract instances, the cache hit
rate is ≈ 80–90 %.

## Anti-Evidence

The per-call cost includes a protocol-visible Soroban budget charge that
cannot be skipped without breaking `cpu_insns`/`mem_bytes` accounting
(meta-pattern #11 and #12: "Soroban Host Internal Micro-Optimizations Are
Individually Sub-Threshold" and "`ValSer` Const-Term Prevents Naive
Old-Entry Serialization Elimination"). Only the storage lookup and TTL
update portion is removable; the budget charge itself must remain.

The TTL extension target depends on the current ledger sequence and the
threshold/extend-to arguments. A cache key must include
`(contract_id, code_hash, threshold, extend_to)` and may have low hit
rates if SAC entry points pass different `extend_to` values.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Failed At**: hypothesis
**Novelty**: PASS — previous TTL-extend hypotheses targeted per-tx
coalescing (`fail/transaction-ledger/summary.md` H006) or frame-cached
current contract instance (`fail/transaction-ledger/summary.md` H001
frame-cached-contract-instance-ttl); no prior cluster-scoped TTL
idempotency cache spanning multiple transactions is recorded.

### Why It Failed

Critical-path savings ceiling is sub-threshold:
- Aggregate worker self-time: 504 ms across 70 ledgers / 8 clusters
  = ≈ 0.9 ms/cluster/ledger critical-path.
- With an optimistic 85 % cache hit rate after correctness preservation
  (cache key includes `(contract_id, code_hash, threshold, extend_to)`),
  removable cost ≈ 0.76 ms/cluster/ledger.
- Against the 250 ms soroswap apply-time median this is 0.30 % — well
  below the 1 % Low floor and orders of magnitude below the 3 % Medium
  floor.

Additionally, the protocol-visible Soroban budget charge inside
`extend_current_contract_instance_and_code_ttl` must remain even on
cache hits to preserve identical `cpu_insns`/`mem_bytes` accounting,
shrinking the removable subset further. Adding cache structures to
`ThreadParallelApplyLedgerState` increases per-cluster memory pressure
and risks cache-locality regression similar to fail
`summary.md` `001-cache-serialized-soroban-entries-in-memory-state`.

### Lesson Learned

Cluster-scoped Soroban host caches for repeated host calls hit the same
critical-path ceiling as per-tx caches once aggregate worker time is
divided by cluster count. The 8-way cluster division turns even
500 ms-aggregate host categories into < 1 ms/cluster/ledger
critical-path budgets. Future cross-tx-within-cluster cache hypotheses
need an aggregate worker-time category > ≈ 2.5 s across the 70-ledger
trace to have any chance of clearing the Medium floor after cluster
normalization and after subtracting the mandatory protocol-visible
metering portion. Cluster-scoped host caches also share the L1/L2
pressure risk documented in meta-pattern #7.
