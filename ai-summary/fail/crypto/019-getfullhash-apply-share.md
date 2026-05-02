# H019: Eliminate `getFullHash` recomputation on the apply path

**Date**: 2026-05-02
**Subsystem**: crypto
**Severity**: Low
**Impact**: apply-time SHA256 reduction
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`TransactionFrame::getFullHash()` should only be computed once per transaction,
on first access; subsequent calls inside `applyLedger` should hit the cached
`mFullHash` field. If `getFullHash()` is invoked from hot apply-path code
without contributing to ledger state, it should be elided. The aggregate
in-apply share of full-envelope hashing should be a small fraction of
`applyLedger` time.

## Mechanism

Tracy reports `TransactionFrame::getFullHash` (TransactionFrame.cpp:124) at
173 ms self-time across 3.33 M calls in the soroswap diagnostic trace. If a
meaningful share of those calls were inside `applyLedger`, eliminating the
accessor / cache-probe overhead (or hoisting the call out of an inner loop)
might shorten apply time. The hypothesis would be that the ZoneScoped
overhead plus `isZero(mFullHash)` check in 50 K+ calls per ledger could be
hoisted or removed.

## Trigger

Run the soroswap apply-load benchmark and inspect `getFullHash` self-time
attribution within `applyLedger` descendants vs. tx-set construction
descendants.

## Target Code

- `src/transactions/TransactionFrame.cpp:122-130` — `getFullHash()` accessor with
  ZoneScoped and `isZero` cache-probe.
- `src/herder/TxSetUtils.cpp:49,55,188,286,385,399,425` — bulk `getFullHash()`
  use during tx-set construction / validation.
- `src/herder/TxSetFrame.cpp:232,488,600,1850,1934` — tx-set sort and
  precomputation calls.
- `src/herder/TransactionQueue.cpp:286,304,327,555,557` — herder-side queue
  use.

## Evidence

`getFullHash` shows 3.33 M calls and 173 ms self-time in the diagnostic
soroswap trace, well above many other small zones.

## Anti-Evidence

A `grep -nE 'getFullHash\(\)' src/` reveals that **all** non-test, non-error-log
callers live in:

- `src/herder/TxSetUtils.cpp` (tx-set construction, validity tracking)
- `src/herder/TxSetFrame.cpp` (tx-set sort, hash, precomputation)
- `src/herder/TransactionQueue.cpp` (herder transaction queue)

Inside `applyLedger`'s subtree the only callers are:

- `src/transactions/TransactionFrame.cpp:2465,2474,2647,2656,2667,2675` —
  exception logging in `try { … } catch` blocks. Zero cost on the
  success path.
- `src/transactions/TransactionFrame.cpp:2841-2844` — `binToHex(getContentsHash())`
  in the `BUILD_TESTS`-only "skipped failed" replay branch (not part of
  production apply).

So the 3.33 M calls / 173 ms attributed to `getFullHash` originate almost
entirely in tx-set construction, validation, and herder-queue work — all
**outside** the `applyLedger` window per the OUT_OF_SCOPE rules and
Meta-Pattern 2 in `ai-summary/fail/crypto/summary.md`. The apply-path share
of `getFullHash` is structurally zero for the soroswap success path.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-02
**Failed At**: hypothesis
**Novelty**: PASS — distinct from H001 (contents-hash streaming), H005
(contents-hash apply accessors), and Meta-Pattern 5 (verifySig apply share);
this entry investigates `getFullHash` (envelope hash) specifically.

### Why It Failed

Every non-test caller of `getFullHash()` reachable from `applyLedger` is
inside an exception `catch` block that executes only on internal-error or
outdated-protocol-version paths. On the soroswap success path the call count
is zero, so even removing the accessor entirely would save zero apply time.
The 173 ms / 3.33 M Tracy attribution is owned by `TxSetUtils`, `TxSetFrame`,
and `TransactionQueue`, all of which run during tx-set construction /
validation / herder gossip — explicitly out of scope for this objective.

### Lesson Learned

For envelope/contents-hash optimizations on the apply path, distinguish
between (a) success-path uses that drive ledger state (e.g. `SignatureChecker`
construction in `commonPreApply`/`preParallelApply`, already covered as cache
hits in H005) and (b) error-logging uses inside `catch` blocks that never
fire on benign workloads. Tracy attribution that aggregates both production
and non-production call sites can mislead — verify by enumerating callers
with `grep` before sizing savings. Add `getFullHash` to the same
"already-bounded apply-path crypto" cluster as `getContentsHash` in
Meta-Pattern 2.
