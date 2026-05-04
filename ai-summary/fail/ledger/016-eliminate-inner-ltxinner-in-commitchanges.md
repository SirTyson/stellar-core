# H016: Eliminate inner `ltxInner` in `commitChangesToLedgerTxn`

**Date**: 2026-05-04
**Subsystem**: ledger / parallel apply commit
**Severity**: Low
**Impact**: <1% apply-time reduction (sub-Medium)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`commitChangesToLedgerTxn` (`src/transactions/ParallelApplyUtils.cpp:722-801`)
applies the buffered restored-entries and per-thread changes from a
finished cluster back into the outer `LedgerTxn`. The expected design is
that these writes flow directly into the outer `ltx`, since the cluster
result is fully validated by the time we reach commit and there is no
intermediate state that needs atomic rollback semantics — the outer
`LedgerTxn`'s commit-or-discard contract already provides the necessary
atomicity at the ledger boundary.

Concretely: skip constructing the inner `LedgerTxn ltxInner(ltx)` at line
736, write all entries (`createWithoutLoading`/`erase`/`upsert`) and
restore markers directly into `ltx`, and remove the
`ltxInner.commit()` round-trip at line 800.

## Mechanism

The current implementation creates an inner `LedgerTxn ltxInner(ltx)` and
applies all per-cluster commit work against it, only to immediately
`commit()` the inner txn back into the outer `ltx` at function exit. The
inner LedgerTxn provides no observable benefit here because:

1. The function never throws a recoverable error mid-commit — every
   failure path is an `releaseAssertOrThrow` (which terminates the
   process), so the rollback semantics are unused in practice.
2. All entries written to `ltxInner` get copied into `ltx` via
   `commit()`, which walks the inner entry map and `createOrUpdate`s each
   into the parent — this is pure overhead (one extra hashmap insert per
   entry, plus one inner-LedgerTxn allocation per cluster commit).

Removing the inner LedgerTxn would save: (a) one `LedgerTxn` allocation
per cluster commit (24 per ledger = 24 mallocs + 24 destruction sweeps),
and (b) the second hashmap insert per committed entry.

## Trigger

Standard soroswap apply-load run — every cluster commit hits this path.

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:722-801` —
  `commitChangesToLedgerTxn`. Replace the inner `ltxInner` with direct
  writes to `ltx` and drop the trailing `ltxInner.commit()`.

## Evidence

- Trace data: `commitChangesToLedgerTxn` self time = 27 ms (0.26% of
  trace) over 213 calls. Adding the indirect `commitChild` cost
  attributable to this site adds at most another 0.3–0.5%.
- Code structure shows zero use of `ltxInner` rollback — every failure
  path within the function is `releaseAssertOrThrow`.

## Anti-Evidence

- Even with both direct + indirect costs combined, the absolute ceiling
  is ~0.6–0.8% of trace, well below the 3% Medium threshold for this
  objective.
- `LedgerTxn::commit()` includes an extra normalization step
  (`maybeUpdateLastModifiedThenInvokeEntryProcessor`) that interacts with
  the parent's `mActive` set; eliminating the inner txn requires
  carefully replicating the same normalization for direct writes,
  enlarging the diff.
- The restore-marker write loop at line 781,794 deliberately wants
  read-then-write semantics on `mGlobalRestoredEntries`; while this works
  the same on the outer ltx, it removes the per-cluster scoping that
  could become important if future protocols reintroduce inner-cluster
  rollback.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-04
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated

### Why It Failed

The combined (self + commit-into-parent) cost of the inner `ltxInner`
is at most ~0.6–0.8% of trace, below the Medium tier (3–10%) and below
the objective's hypothesis-stage acceptance threshold. Even a fully
successful PoC would land in the noise band.

### Lesson Learned

Inner-LedgerTxn elimination is structurally tempting but pays only
single-digit-millisecond per-ledger savings unless the inner txn is on a
genuinely hot path (many entries, many commits). For cluster-commit
sites with ~24 commits per ledger and small per-cluster entry counts,
the win is below the objective floor. Future hypotheses targeting
LedgerTxn nesting overhead should focus on sites with **per-tx** or
**per-op** inner LedgerTxn churn (e.g., the per-tx `LedgerTxn`
construction in `applyTransaction` paths) rather than per-cluster sites.
