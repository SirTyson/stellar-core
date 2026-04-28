# H002: Skip prefetchTransactionData Iteration for Soroban Transactions

**Date**: 2026-04-28
**Subsystem**: ledger
**Severity**: Medium
**Impact**: ~6% reduction in soroswap apply time by eliminating an empty-prefetch tx-set iteration
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`prefetchTransactionData` should only do work proportional to the number of
classic-ledger keys that the tx set actually needs to load. For an
all-Soroban tx set (such as soroswap, where every transaction is an
`InvokeHostFunctionOp`), the function should be a near-no-op: every Soroban
operation type (`InvokeHostFunction`, `ExtendFootprintTTL`,
`RestoreFootprint`) implements `insertLedgerKeysToPrefetch` as an empty
function, and `LedgerTxnRoot::Impl::prefetch` actively forbids Soroban or
TTL keys (it throws). Therefore the only classic keys a Soroban tx could
contribute are op-source overrides (when `op.sourceID != tx.sourceID`).
For soroswap, source-account Soroban credentials guarantee
`op.sourceID == tx.sourceID` (`src/simulation/ApplyLoad.cpp:3395-3407`), so
the resulting key set is empty — the function should cost essentially
nothing.

## Mechanism

`LedgerManagerImpl::prefetchTransactionData`
(`ledger/LedgerManagerImpl.cpp:2463-2481`) iterates every phase, every tx,
and inside `TransactionFrame::insertKeysForTxApply`
(`transactions/TransactionFrame.cpp:2033-2043`) walks every operation,
making a virtual call to `op->insertLedgerKeysToPrefetch(keys)`. For the
soroswap benchmark (4000 InvokeHostFunctionOps × 65 ledgers = 260000 op
visits), every iteration body is wasted: the source-ID equality check
short-circuits the only key insertion, and the virtual no-op fires for
every op. Tracy reports `prefetchTransactionData,...,2468` at **283 ms
self-time over 66 calls** (mean 4.30 ms/ledger) — 6.2% of `applyLedger`'s
4591 ms. The downstream `prefetch,LedgerTxn.cpp,3103` self-time
attribution is separate (`ZoneScoped` at line 3103), confirming the
283 ms is iteration overhead, not the underlying prefetch work. Adding a
single check `if (tx->isSoroban()) continue;` in the loop (or better,
refactoring `insertKeysForTxApply` to early-return for Soroban TXs) would
eliminate this overhead while preserving correctness: the only classic
keys a Soroban tx can ask the prefetcher to load are op-source-override
account keys, which are conservatively prefetched by `prefetchTxSourceIds`
already (it inserts `accountKey(getSourceID())` for the tx; op-source
overrides for Soroban ops are rare in real workloads and miss the
prefetch cache only on the source-account first touch — a single bucket
load).

## Trigger

Run the soroswap apply-load benchmark
(`scripts/run_apply_load_matrix.py`, default `apply-load-benchmark-sac.cfg`,
TX=4000, T=8). Tracy zone
`prefetchTransactionData,ledger/LedgerManagerImpl.cpp,2468` reports
283.7 M ns self-time over 66 calls (mean 4298 µs, max 37.6 ms). After
short-circuiting Soroban txs, the same zone should drop to <10 ms total,
moving the soroswap apply median by ~3-6%.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2463-2481` — `prefetchTransactionData`
  outer loop; the place to add the `tx->isSoroban()` short-circuit.
- `src/transactions/TransactionFrame.cpp:2033-2043` —
  `insertKeysForTxApply`; alternative early-return location.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1420-1424` — empty
  `insertLedgerKeysToPrefetch` confirms Soroban ops contribute nothing.
- `src/transactions/RestoreFootprintOpFrame.cpp:454-458` — same.
- `src/transactions/ExtendFootprintTTLOpFrame.cpp:365-369` — same.
- `src/ledger/LedgerTxn.cpp:3118-3125` — `LedgerTxnRoot::Impl::prefetch`
  rejects Soroban and TTL keys; reinforces that no Soroban-typed key
  could ever be added by `insertKeysForTxApply` anyway.
- `src/simulation/ApplyLoad.cpp:3395-3407` — soroswap source-account
  Soroban credentials (op.sourceID == tx.sourceID by construction).

## Evidence

- Tracy: `prefetchTransactionData,...,2468` self-time 283.7 ms = 6.18% of
  `applyLedger,...,1484` (4591 ms total, 65 calls).
- All three Soroban op types implement `insertLedgerKeysToPrefetch` as
  empty bodies (verified at the line numbers above).
- `LedgerTxnRoot::Impl::prefetch` throws on Soroban/TTL keys, proving
  the prefetch cache is exclusively for classic entries.
- `prefetchTxSourceIds` (94 ms self-time) already prefetches the tx
  source-account; the only thing `prefetchTransactionData` could add for a
  Soroban tx is an op-source-override account key, which for soroswap is
  empty by construction (source-account credentials).
- The downstream `prefetch,LedgerTxn.cpp,3103` zone has its own
  `ZoneScoped`, so Tracy's self-time on `prefetchTransactionData` is pure
  iteration overhead — not work that would just shift to the callee if we
  early-return.

## Anti-Evidence

- For mixed phases (classic + Soroban together), the loop must still run
  for classic txs, so the optimization is only effective when many txs
  are Soroban. Soroswap and max-sac both fit this shape, so the win
  applies to both target benchmarks.
- For non-soroswap Soroban workloads where ops use op-source overrides
  (`SOROBAN_CREDENTIALS_ADDRESS` with a different signing account), an
  account key the apply path will need is no longer in the prefetch
  cache. The miss falls through to the per-tx LTX load on first apply
  touch — a single SearchableBucketListSnapshot::load() per missing key.
  This adds latency for that one path but does not break correctness;
  the hypothesis must measure that this regression (if any) is dominated
  by the 283 ms saving on the common soroswap path.
- If we naively `continue` on Soroban txs but later workloads add an
  op-source override to a Soroban op, the lost prefetch becomes a real
  per-tx miss. A safer implementation walks each Soroban tx's
  operations only when `numOperations() > 1` or when `tx->getSourceID()
  != op->getSourceID()` for any op — both are O(1) checks per tx but
  preserve the current correctness guarantees in heterogeneous tx
  shapes.
- The 283 ms attribution assumes the empty-key downstream `prefetch` call
  truly costs nothing; if `LedgerTxnRoot::Impl::prefetch` itself does
  measurable work on an empty set (e.g., snapshot acquisition), removing
  the second call also avoids that cost — a net positive but the
  measured impact may shift slightly. PoC must verify with side-by-side
  benchmark runs (≥3 each) to confirm the win exceeds 3% (Medium
  threshold).

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-28
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/ledger/summary.md` entry `003-skip-empty-soroban-prefetch-transaction-data.md`
**Failed At**: reviewer

### Trace Summary

`LedgerManagerImpl::applyTransactions` calls `prefetchTransactionData` before applying phases, so the target is on the ledger apply path. `prefetchTransactionData` iterates all phases and transactions and delegates to `TransactionFrame::insertKeysForTxApply`, which checks each operation source and calls the operation-specific prefetch hook. For Soroban operations (`InvokeHostFunction`, `ExtendFootprintTTL`, and `RestoreFootprint`), the hook bodies are empty, and `LedgerTxnRoot::Impl::prefetch` rejects Soroban and TTL keys anyway. The soroswap generator creates one source-account-authorized `InvokeHostFunction` op per transaction from the transaction source account, matching the duplicate prior hypothesis.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2790-2827` — `applyTransactions` records setup timing and calls `prefetchTransactionData` before phase application.
- `src/ledger/LedgerManagerImpl.cpp:2463-2481` — `prefetchTransactionData` builds a key set by visiting each transaction and then calls `ltx.prefetch(keysToPreFetch)`.
- `src/transactions/TransactionFrame.cpp:2033-2043` — `insertKeysForTxApply` checks op-source overrides and invokes each operation's `insertLedgerKeysToPrefetch`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1420-1424`, `src/transactions/ExtendFootprintTTLOpFrame.cpp:365-369`, `src/transactions/RestoreFootprintOpFrame.cpp:454-458` — Soroban operation prefetch hooks are empty.
- `src/ledger/LedgerTxn.cpp:3101-3125` — `LedgerTxnRoot::Impl::prefetch` has a separate `ZoneScoped` and throws if any Soroban or TTL key reaches it.
- `src/simulation/ApplyLoad.cpp:3395-3407,3477-3505` — soroswap uses a unique transaction source account and `SOROBAN_CREDENTIALS_SOURCE_ACCOUNT` for the generated invoke-host-function operation.

### Why It Failed

This is not novel. `ai-summary/fail/ledger/summary.md` already records `003-skip-empty-soroban-prefetch-transaction-data.md` / "Skip empty Soroban transaction-data prefetch" with the conclusion that the optimization is plausible but below the objective's Medium severity threshold, and the objective rejects Low-severity optimizations even when technically correct. The current hypothesis is substantially the same mechanism: skip or short-circuit empty Soroban transaction-data prefetch iteration for soroswap-style all-Soroban ledgers.

### Lesson Learned

For this objective, technically correct prefetch-path micro-optimizations are insufficient unless the projected top-line soroswap apply-time reduction clears the 3% Medium threshold. The ledger failure summary's "Prefetch Path Triviality" meta-pattern should be checked before re-proposing skipped or combined Soroban prefetch work.
