# H205: Fuse processFeesSeqNums source-account load with preParallelApplyWrite processSeqNum load

**Date**: 2026-05-25
**Subsystem**: soroban, transaction-ledger
**Severity**: Low
**Impact**: redundant per-tx source-account `LedgerTxn::load`
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

For each Soroban transaction in a soroswap-style ledger, the apply path
should load the source `AccountEntry` at most once before parallel
clusters dispatch. The expected fast-path: `processFeesSeqNums` loads the
fee-source account, charges the fee, bumps `seqNum`, and stashes a handle
on the `TxBundle` (or equivalent context) that `preParallelApplyWrite`
reuses to bump the sequence number without a second load. This matches the
optimization pattern already applied by success #4 (parallel-apply
`LedgerKey` hash caching) of avoiding repeated key hashing/lookups across
phases.

## Mechanism

In the current code, `processFeesSeqNums` (LedgerManagerImpl.cpp) calls
`loadAccount` to charge fees and bump seq on the fee source. Then for each
Soroban tx, `preParallelApplyWrite` opens a child ltx and
`processSeqNum(ltxTx)` calls `loadAccount` *again* on the same source
account (the per-tx ltx wraps the parent, so it walks the parent's
`mActive` map, constructs a fresh `LedgerTxnEntry`, and decodes the cached
entry). Both loads target the identical key; the second is redundant work
on the apply critical path.

## Trigger

Any Soroban-only ledger where every tx has a single source account that is
the fee source (the default soroswap benchmark configuration). The
duplicate load fires once per Soroban tx × N tx/ledger × N ledgers.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2303-2400` — `processFeesSeqNums`
  performs the first `loadAccount` for fee+seq updates.
- `src/transactions/TransactionFrame.cpp:2314-2349` — `preParallelApplyWrite`
  calls `processSeqNum(ltxTx)` which performs the second `loadAccount`.
- `src/transactions/TransactionFrame.cpp:605-652` — `loadAccount` helper
  used by both call sites.

## Evidence

- `processSeqNum` appears at 26.4ms / 34,110 calls in the Tracy trace.
- The fee-source account is loaded into the parent ltx's `mActive` map by
  `processFeesSeqNums`, so the second load is structurally cache-hot but
  still goes through `LedgerTxn::loadAccount` → `getNewestVersion` →
  `LedgerTxnEntry` construction.

## Anti-Evidence

- `mActive` is hash-keyed and a cache-hot lookup is ~100–200 ns; the
  decode is essentially free for a small `AccountEntry`.
- 98 Soroban tx/ledger × ~200ns = ~20 µs/ledger.
- 20 µs / 207 ms = ~0.01% — three orders of magnitude below the 3% Medium
  threshold and below the 1% noise floor.
- API surface to thread an `AccountEntry` handle from `processFeesSeqNums`
  through tx-result/bundle plumbing into `preParallelApplyWrite` is
  non-trivial; the engineering cost vastly exceeds the projected win.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated (existing fails address
either `processFeesSeqNums` short-circuits in the meta-disabled path
(fail #001/#203) or `preParallelApplyWrite` itself (new fail #204);
no prior entry targets fusion of the fee-source `loadAccount` across
the two phases).

### Why It Failed

The fee-source account is already cache-hot in the parent `LedgerTxn`'s
`mActive` map by the time `processSeqNum` runs in `preParallelApplyWrite`,
so the "second load" is a hash-lookup-and-entry-construction, not a real
disk/decoding hit. Per-ledger savings are ~20 µs, or ~0.01% of soroswap
apply time — well below the 1% noise floor and far below the 3% Medium
threshold mandated by the optimize-soroswap stage. Combined with the
non-trivial plumbing cost to thread a cached `AccountEntry` handle
across the per-tx interface boundary, this falls cleanly into the
"below objective severity threshold" reject bucket called out in the
hypothesis skill.

### Lesson Learned

Within a single parent `LedgerTxn`, repeat loads of the same key are
near-free because of the existing `mActive` cache; eliminating them
yields only the cost of the lookup itself (≪1 µs). Meta-Pattern #14's
threshold equation (`agg-self-time ≥ 3.5 s` for Medium on soroswap)
applies just as strongly to "structural redundancies" as to raw
self-time wins. Future per-Soroban-tx fusion proposals should
multiply the projected per-tx-µs by ≤100 tx/ledger before drafting.
