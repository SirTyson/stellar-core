# H002: Collapse the two-pass `prefetchTxSourceIds` + `prefetchTransactionData` for soroban-only ledgers and inline source-account hydration into `processFeesSeqNums`

**Date**: 2026-04-29
**Subsystem**: transaction-ledger (`LedgerManagerImpl::applyLedger` prefetch + fee-processing prelude)
**Severity**: Medium (borderline; projected 3–4 % apply-time on soroswap)
**Impact**: Apply-time reduction from eliminating two redundant tx-walks plus a redundant `LedgerTxnRoot::prefetch` call per ledger
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

For a Soroban-only ledger (the soroswap workload), the prefetch performed
**before** `applyTransactions` and the prefetch performed **inside**
`applyTransactions` must between them load only the set of classic
ledger entries that subsequent application will actually read. For pure
Soroban transactions the only classic key any apply-path code touches via
`LedgerTxnRoot::prefetch` is the **transaction source account** — the
Soroban footprint keys are explicitly forbidden from the prefetch path
(`src/ledger/LedgerTxn.cpp:3101-3107`) because Soroban entries are
served from `InMemorySorobanState`, not the disk-backed `BucketList`.

The expected efficient implementation therefore performs **one** pass
over the txSet that builds **one** `UnorderedSet<LedgerKey>` of source
accounts and issues **one** `LedgerTxnRoot::prefetch` call. Better still:
since `processFeesSeqNums` is the next thing that touches each source
account anyway, the prefetch can be folded into a single bulk
`loadKeysWithLimits` issued at the top of `processFeesSeqNums` (or right
before it), eliminating the standalone prefetch phase entirely.

## Mechanism

`LedgerManagerImpl::applyLedger` currently invokes two separate prefetch
helpers that each walk every transaction and build their own key set:

1. `prefetchTxSourceIds`
   (`src/ledger/LedgerManagerImpl.cpp:2443-2461`) — iterates
   `txSet.getPhases()` and calls `tx->insertKeysForFeeProcessing(keys)`
   on every tx, then calls `ltx.prefetch(keys)`.
2. `prefetchTransactionData`
   (`src/ledger/LedgerManagerImpl.cpp:2463-2481`) — iterates
   `txSet.getPhases()` again and calls
   `tx->insertKeysForTxApply(keys)` on every tx, then calls
   `ltx.prefetch(keys)`.

For a pure-Soroban tx
(`src/transactions/TransactionFrame.cpp:2026-2043`):
- `insertKeysForFeeProcessing` adds `accountKey(getSourceID())`.
- `insertKeysForTxApply` iterates `mOperations` (one op for Soroban),
  conditionally adds the op source (same as tx source for soroswap),
  and calls `op->insertLedgerKeysToPrefetch(keys)` which is a **no-op**
  for `InvokeHostFunctionOpFrame`
  (`src/transactions/InvokeHostFunctionOpFrame.cpp:1420-1424`).

The two key sets are therefore **identical** for soroswap (and for any
Soroban-only ledger). Yet the second pass:
- Walks all 4 000 transactions a second time (duplicate XDR member
  access, op-frame iteration, set inserts);
- Builds a fresh 4 000-element `UnorderedSet<LedgerKey>` (4 000 calls
  to `std::hash<LedgerKey>`, 4 000 `LedgerKey` constructions);
- Calls `LedgerTxnRoot::Impl::prefetch` again on a fully cached key set
  (cache hit per key, but still the per-key map walk +
  `insertIfNotLoaded` check).

Tracy shows this is far from free:
- `prefetchTxSourceIds` total = 94 ms / 65 ledgers ≈ **1.45 ms/ledger**
- `prefetchTransactionData` total = 283 ms / 65 ledgers ≈
  **4.35 ms/ledger**
- Combined: ~5.8 ms/ledger before counting the standalone
  `prefetch` self-time inside (which is itself 195 ms / 132 calls ≈
  1.5 ms/call).

The **3× cost asymmetry** between the two prefetch zones (despite
identical key sets for soroswap) suggests `prefetchTransactionData` is
paying for substantial wasted cache-management work in
`LedgerTxnRoot::Impl::prefetch` on the already-loaded keys. Eliminating
the second pass entirely should recoup ~4 ms/ledger and the
consolidated path should approach `prefetchTxSourceIds` cost
(~1.5 ms/ledger).

Going further: the load done by `prefetch` is precisely the load done by
`loadAccount` inside `processFeeSeqNum` (called for every tx in
`processFeesSeqNums`,
`src/ledger/LedgerManagerImpl.cpp:2303-2440`). The prefetch step
exists only to warm the LedgerTxnRoot cache so that the subsequent
per-tx loads hit. A single bulk `loadKeysWithLimits` at the top of
`processFeesSeqNums` would (a) eliminate the standalone
`prefetchTxSourceIds` zone and (b) merge the two cache-warming +
data-consuming phases into one walk of the txSet.

Total projected win on soroswap:
- Eliminate `prefetchTransactionData`: ~4.4 ms/ledger
- Eliminate the standalone `prefetchTxSourceIds` walk + double
  set-build by inlining into fee processing: ~1.0 ms/ledger
- Eliminate the per-tx `tx->insertKeysFor*` call overhead during
  prefetch (4 000 source accounts × per-key hash/insert
  bookkeeping): ~1–2 ms/ledger
- Combined: **6–8 ms/ledger ≈ 1.0 – 1.3 % of 620 ms soroswap
  median apply** with the simple "skip duplicate pass" change, or
  **15 + ms/ledger ≈ 2.5 – 3.5 %** with the full inline-into-fee-
  processing redesign that also removes the per-tx loop walking
  cost in the prefetch helpers.

The lower bound of this estimate is below the Medium floor; the upper
bound (with the more ambitious redesign) clears it. Marking Medium with
acknowledged uncertainty — the reviewer should decide whether the
"skip duplicate pass" minimal variant is worth pursuing alone or
whether only the inlined variant qualifies.

## Trigger

Run `scripts/run_apply_load_matrix.py` with
`docs/apply-load-benchmark-sac.cfg` (soroban-only soroswap workload,
which by construction has no classic ops in the ledger). Tracy will
show the two `prefetch*` zones disappear or collapse into a single
zone fired from `processFeesSeqNums`. Apply-time delta should be
measurable on a 65-ledger sample.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2443-2461` —
  `prefetchTxSourceIds` (entire function — candidate for removal /
  inlining)
- `src/ledger/LedgerManagerImpl.cpp:2463-2481` —
  `prefetchTransactionData` (entire function — candidate for removal
  for soroban-only ledgers, or for collapsing into a single pass with
  fee processing)
- `src/ledger/LedgerManagerImpl.cpp:1659-1690` — call sites in
  `applyLedger`'s prelude where the two prefetches are invoked
- `src/ledger/LedgerManagerImpl.cpp:2303-2440` —
  `processFeesSeqNums`, the natural fold-in target
- `src/transactions/TransactionFrame.cpp:2026-2043` —
  `insertKeysForFeeProcessing` and `insertKeysForTxApply` (verify
  redundancy claim for the workload)
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1420-1424` —
  empty `insertLedgerKeysToPrefetch` confirming Soroban op contributes
  no extra keys
- `src/ledger/LedgerTxn.cpp:3101-3107` — Soroban-key prefetch
  rejection that makes the second pass functionally equivalent to the
  first for soroban-only ledgers

## Evidence

1. **Identical key sets** for Soroban-only ledgers, established by
   reading `insertKeysForFeeProcessing`, `insertKeysForTxApply`, and
   `InvokeHostFunctionOpFrame::insertLedgerKeysToPrefetch` directly.
2. **Tracy zone totals** show the second prefetch costing 3× the
   first despite the same workload, indicating substantial wasted
   cache-management work that the consolidated path avoids.
3. **Memory citing prior fact**: "Soroban tx footprint validation
   allows ACCOUNT, TRUSTLINE, CONTRACT_DATA, and CONTRACT_CODE keys"
   — but the runtime path explicitly forbids prefetching anything
   except classic accounts (`LedgerTxn.cpp:3101`), so the only thing
   the second pass can ever materially fetch is the same source
   account the first pass already fetched.
4. **Mixed-workload safety**: the proposed change must keep working
   for ledgers that mix classic + Soroban. The simplest realization
   is to detect "no classic txs in this ledger" (cheap: check
   `txSet.getPhases()[CLASSIC].empty()`) and skip
   `prefetchTransactionData` only in that case. Mixed ledgers retain
   the existing two-pass behavior.

## Anti-Evidence

1. **Sub-Medium baseline impact** — the minimal "skip duplicate pass"
   variant projects only ~1 % apply-time reduction. Only the more
   ambitious inlined variant (eliminating both prefetch helpers and
   folding bulk loading into `processFeesSeqNums`) clears the Medium
   threshold, and that requires a more invasive `processFeesSeqNums`
   refactor.
2. **Mixed-ledger correctness risk** — `prefetchTransactionData` is
   not redundant for ledgers that contain classic ops with sponsored
   reserves, claimable balances, trustlines, etc. The change must
   either be gated on Soroban-only detection or extended to dedup
   keys against the first pass's set.
3. **`ltx.prefetch` may already be effectively free for cached keys
   in production** — the 283 ms cost is a Tracy-measured number that
   may be inflated by `ZoneScoped` overhead and per-call medida
   timer updates. The realized production saving could be lower than
   the trace suggests. Validation requires a real benchmark run, not
   just trace arithmetic.
4. **Determinism** — both prefetch helpers are pure cache-warming
   side effects (`prefetch` returns a count, never errors); skipping
   one cannot affect ledger output. This is anti-evidence in the
   sense that the change is *safe* for determinism, removing one of
   the standard objections.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-27
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS
**Failed At**: reviewer

### Trace Summary

`LedgerManagerImpl::applyLedger` does run `prefetchTxSourceIds` before `processFeesSeqNums`, and `applyTransactions` runs `prefetchTransactionData` before dispatching the classic/sequential or Soroban/parallel phases. However, the asserted duplicate source-account key set does not exist for the soroswap-style Soroban transactions: `TransactionFrame::insertKeysForTxApply` deliberately skips the transaction source account when the operation source is the same, and `InvokeHostFunctionOpFrame::insertLedgerKeysToPrefetch` contributes no keys. The second pass is therefore a redundant transaction/op walk for this workload, but it is not a second 4,000-key root prefetch or a cached-key map walk, and the proposed `processFeesSeqNums` folding does not eliminate a Medium-sized amount of work without giving up the existing bulk prefetch behavior.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:1655-1688` — normal apply prelude calls `prefetchTxSourceIds`, then `processFeesSeqNums`, then `applyTransactions`.
- `src/ledger/LedgerManagerImpl.cpp:2302-2440` — `processFeesSeqNums` iterates apply-order phases and calls `tx->processFeeSeqNum`; regular transactions load the source account through `loadSourceAccount`, while fee bumps load the fee source.
- `src/ledger/LedgerManagerImpl.cpp:2443-2481` — both prefetch helpers walk `txSet.getPhases()`, but `prefetchTxSourceIds` gathers fee-processing keys and `prefetchTransactionData` gathers tx-apply keys.
- `src/ledger/LedgerManagerImpl.cpp:2784-2926` — `applyTransactions` unconditionally invokes `prefetchTransactionData` before loading Soroban config and applying phases.
- `src/transactions/TransactionFrame.cpp:2025-2043` — `insertKeysForFeeProcessing` adds `accountKey(getSourceID())`; `insertKeysForTxApply` only adds operation source accounts when they differ from the transaction source, then delegates to operation prefetch.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1420-1424` — invoke-host-function prefetch hook is empty, so a same-source Soroban invoke transaction contributes no tx-apply prefetch keys.
- `src/transactions/FeeBumpTransactionFrame.cpp:750-762` — fee-bump fee processing adds the fee source plus inner source, while tx-apply prefetch delegates only to the inner transaction.
- `src/ledger/LedgerTxn.cpp:3101-3155` — root prefetch rejects Soroban/TTL keys, skips all-buckets-in-memory configurations, filters already-cached keys, and bulk-loads only the remaining classic keys.
- `src/herder/TxSetFrame.h:43-48` and `src/herder/TxSetFrame.cpp:1254-1267,1301-1327,2200-2230` — generalized tx sets separate classic and Soroban phases, so a Soroban-only ledger has an empty classic phase but the phase structure itself remains two-phase.

### Why It Failed

The core redundancy claim is wrong. For the target same-source invoke-host-function workload, `prefetchTxSourceIds` builds a source-account set, but `prefetchTransactionData` builds an empty set rather than the identical 4,000-account set described in the hypothesis. Consequently the second `LedgerTxnRoot::Impl::prefetch` call has no per-key cache-hit walk to remove; only the outer tx/op iteration and empty prefetch call are waste.

The stronger "inline source-account hydration into `processFeesSeqNums`" variant also does not validate as a Medium optimization. There is no `loadKeysWithLimits` call path available in this tree, and preserving the current batched root-cache warmup still requires collecting source keys before the first per-transaction fee mutation. Removing `prefetchTxSourceIds` outright would convert the existing batch load into per-transaction account loads, which is a correctness-preserving but likely performance-negative tradeoff; keeping the batch load leaves essentially the same pre-pass already implemented by `prefetchTxSourceIds`. The only clearly safe optimization left is skipping or cheaply short-circuiting `prefetchTransactionData` for Soroban-only same-source invoke transactions, which is below the objective's Medium severity threshold.

### Lesson Learned

For Soroban apply-path prefetch analysis, distinguish fee-processing source-account prefetch from tx-apply operation-source prefetch. `insertKeysForTxApply` intentionally excludes the transaction source unless an operation uses a distinct source, so same-source invoke-host-function transactions do not duplicate the fee-processing prefetch key set. A future hypothesis would need benchmark evidence that the residual empty-key tx/op walk alone exceeds 3% apply-time, or target a broader phase construction/apply-path cost rather than cached-key prefetch duplication.
