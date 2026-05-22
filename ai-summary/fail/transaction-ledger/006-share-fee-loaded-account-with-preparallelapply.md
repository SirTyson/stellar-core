# H006: Share fee-loaded source account with preParallelApply commonValid

**Date**: 2026-05-22
**Subsystem**: transaction-ledger
**Severity**: Low
**Impact**: Apply-time reduction from eliding redundant per-tx source-account
loads between `processFeesSeqNums` and `preParallelApplyReadOnly` /
`preParallelApplyWrite`
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

For each Soroban transaction in the apply phase, the source `AccountEntry`
should be loaded from the outer `LedgerTxn` exactly once and then handed to
subsequent phases (sequence-number processing, `commonValid` during
`preParallelApply`, signature processing) instead of being re-loaded through
`stellar::loadAccount(ltx, accountID)` in each phase. Each load involves a
hash-and-probe in the `LedgerTxn` entry map, a wrap into a `LedgerTxnEntry`
handle, an `activate` in the `mActive` map, and a `deactivate` on
destruction; for a 2000-tx soroswap ledger this is multiplied across phases.

## Mechanism

`processFeesSeqNums` (LedgerManagerImpl.cpp:2308 zone, 16.2 ms self / 71
ledgers ≈ 228 µs/ledger) calls `processFeeSeqNum` per tx, which calls
`loadSourceAccount` / `loadAccount` (TransactionFrame.cpp:601, 624) to load
and mutate the fee/source account. Then, during parallel-apply setup,
`preParallelApplyReadOnly` runs `commonValid` (TransactionFrame.cpp:1675)
which also calls `loadSourceAccount` to validate balance and sequence
preconditions, and `processSignatures` (line 1583) which can call
`stellar::loadAccount` again for one-time-signer removal. Each call walks
the `LedgerTxn::Impl::mEntry` `UnorderedMap<InternalLedgerKey, LedgerEntryPtr>`,
constructs a fresh `LedgerTxnEntry` handle, and tracks it in `mActive`. A
per-tx cached `LedgerEntry` snapshot, passed between phases via a
short-lived context object, could elide the repeated map probes.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=2000, T=8`).
For every tx, the same source-account `LedgerKey` is loaded at least twice
on the serial pre-parallel-apply path (`processFeesSeqNums` →
`preParallelApplyReadOnly::commonValid` →
`preParallelApplyWrite::processSeqNum`).

## Target Code

- `src/transactions/TransactionFrame.cpp:601-660` — `loadSourceAccount` /
  `loadAccount` per-tx serial loads.
- `src/transactions/TransactionFrame.cpp:1565-1581` — `processSeqNum` reloads
  source account via `loadSourceAccount`.
- `src/transactions/TransactionFrame.cpp:1675-1745` — `commonValid` calls
  `loadAccount(ltx, header, getSourceID())` for precondition checks.
- `src/transactions/TransactionFrame.cpp:1780-1830` — `processFeeSeqNum`
  loads and mutates source account.
- `src/transactions/TransactionFrame.cpp:2200-2280` —
  `preParallelApplyReadOnly` / `preParallelApplyWrite` orchestrate the
  serial phases that all share a source-account dependency.

## Evidence

From the current soroswap Tracy trace, serial pre-parallel-apply phase
self-times:
- `processFeesSeqNums` (LedgerManagerImpl.cpp:2308): 16.2 ms self / 71
  ledgers = 228 µs/ledger.
- `processFeeSeqNum` (TransactionFrame.cpp:1780): 21.9 ms self / 32 945
  events = 665 ns/event (also fee-bump inner txs).
- `processSeqNum` (TransactionFrame.cpp:1567): 12.0 ms self / 32 945 = 363 ns/event.
- `preParallelApplyReadOnly` (TransactionFrame.cpp:2277): 6.6 ms self /
  14 036 events = 471 ns/event.
- `preParallelApplyWrite` (TransactionFrame.cpp:2320): 9.2 ms self /
  14 036 = 657 ns/event.
- `commonValid` (TransactionFrame.cpp:1675) apply-only self: 92.4 ms /
  ~70 ledgers = ≈ 1.3 ms/ledger (after subtracting TX-set-construction
  validation per meta-pattern #9).

Per-tx these phases each repeat the source-account load. With ≈ 98
Soroban tx/ledger on the soroswap shape, eliding one redundant load per
tx (at ≈ 1–3 µs per `LedgerTxn::load` probe + handle construction)
saves a fraction of a millisecond per ledger.

## Anti-Evidence

`LedgerTxnRoot`'s `mEntryCache` already serves repeated loads from a
per-LedgerTxn `EntryMap` after the first miss; the subsequent loads do
not touch SQL or the BucketList. The cost being targeted is purely the
`UnorderedMap` probe, handle construction, and `mActive`
register/deregister. Each of these is a sub-microsecond operation.
The pre-parallel-apply phase zones (`preParallelApplyReadOnly`
6.6 ms, `preParallelApplyWrite` 9.2 ms) together total < 16 ms self
across the 70-ledger trace = 229 µs/ledger, bounding the entire
removable subset before considering caching overhead.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Failed At**: hypothesis
**Novelty**: PASS — previous hypotheses targeted batch source-account loads
(`summary.md` H008 batch-source-account-loads-in-processfeesseqnums), child
LTX elimination (`summary.md` H005 eliminate-per-tx-child-ltx-in-fees-seqnums),
and source-account carry forward into pre-apply (`summary.md` H008
carry-fee-source-account-into-preapply). The carry-forward hypothesis (H008)
is closest but is recorded as targeting only the fee→pre-apply seam without
considering signature processing and seq-num reload as additional reload
sites. The conclusion below confirms the broader scope still falls into the
same sub-threshold envelope.

### Why It Failed

The entire serial pre-parallel-apply phase envelope bounds the
opportunity:
- `processFeesSeqNums` + `preParallelApplyReadOnly` + `preParallelApplyWrite`
  combined self-time = 16.2 + 6.6 + 9.2 ≈ 32 ms across 70 ledgers
  = 457 µs/ledger serial.
- `commonValid` apply-only self ≈ 1.3 ms/ledger serial.
- Combined envelope: ≈ 1.76 ms/ledger serial = 0.70 % of the 250 ms
  baseline.

Even eliminating every redundant source-account map probe in the
combined envelope (which is the realistic upper bound) saves a small
fraction of 1.76 ms — well below the 1 % Low floor and orders of
magnitude below the 3 % Medium floor. This matches `summary.md` meta-pattern
#5 "Sub-Threshold Narrow Fixes" and `fail/transaction-ledger/summary.md`
H008 `carry-fee-source-account-into-preapply` conclusion that the
"serial fee+pre-apply envelope is under 3 ms/ledger total".

Additionally, threading a cached `AccountEntry` between phases requires
new lifetime/ownership plumbing (the account is mutated by
`processFeeSeqNum` so the cache must be the up-to-date in-memory
view, not a stale snapshot) and risks introducing subtle bugs where a
later phase consumes a stale value. The correctness review burden
exceeds the sub-threshold performance gain.

### Lesson Learned

The serial pre-parallel-apply phase on the soroswap shape is bounded
under ≈ 2 ms/ledger total self-time. Any hypothesis that targets per-tx
source-account load deduplication, ledger-header re-reads, or other
fine-grained reductions in this region is structurally capped below the
1 % Low floor regardless of how many call sites are unified. Future
serial-phase hypotheses must either eliminate an entire phase
(e.g. fold all of `processSeqNum`/`processSignatures`/`commonValid`
into a single combined pass that also removes a measurable allocation
or hash dominated cost) or move the entire serial seam off the apply
critical path. Per-call-site coalescing in this region is exhausted.
