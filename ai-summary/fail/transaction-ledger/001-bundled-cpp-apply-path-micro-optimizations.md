# H001: Bundled C++ apply-path micro-optimizations stacked into a single PoC

**Date**: 2026-05-05
**Subsystem**: transaction-ledger (C++ apply path; non-Soroban-host)
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by stacking four previously sub-threshold C++ wins into one combined PoC, projected at 4-6% combined
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

For each Soroban transaction the apply path should perform the minimum amount
of C++-side per-tx work that is logically required: fee/seqnum bookkeeping,
signature processing, footprint construction, host invocation marshalling, and
result/meta recording. Work that is provably idempotent across the apply window
(e.g., per-footprint `xdr_size` over fixed `LedgerKey` shapes, TTL-key
derivation in `recordStorageChanges`, `toCxxBuf` over const `Resources` /
`HostFunction` / `SourceID` / `auth` XDR) should be performed at most once per
transaction frame, not once per parallel-apply invocation. Per-tx
instrumentation (medida `mTransactionApply.TimeScope()`) and lazy
`TransactionMetaBuilder` construction should be elided when meta is disabled
or the metric is not consumed downstream.

## Mechanism

Meta-pattern #5 in `ai-summary/fail/transaction-ledger/summary.md` records that
several apply-path C++ optimizations were each independently rejected at
0.5-2.5% (below the 3% Medium floor) but explicitly notes that
"a combined approach touching multiple of these paths might reach Medium".
None of the bundles has been built or measured yet. The four largest
non-overlapping sub-threshold wins identified across the existing fail log are:

1. **CxxBuf precompute on `TransactionFrame` construction** (fail 005,
   ~2.5%): hoist `toCxxBuf` for `hostFunction`, `resources`, `sourceID`,
   and auth entries into `TransactionFrame` construction so that
   `InvokeHostFunctionOpFrame::doParallelApply` reads cached buffers
   instead of rebuilding them on every invoke.
2. **xdr_size skip / cross-call cache** (fail 002 / 007, ~1.0-1.5%):
   gate `xdr::xdr_size(lk)` in `addReads` on Soroban-typed footprints,
   and reuse the size on the matching `recordStorageChanges` call site.
3. **TransactionMetaBuilder lazy construction when meta disabled** (fail
   001 in reviewed/, ~0.5-1.7%): skip per-op `OperationMetaBuilder`
   construction and per-tx allocations when `LedgerCloseMeta` emission is
   disabled (the soroswap apply-load benchmark runs with meta off).
4. **`recordStorageChanges` TTL-key precompute** (fail 004, covered by
   broader hypothesis but never landed standalone): precompute
   `LedgerEntryKey -> TTLKey` once per RW footprint key on
   `TransactionFrame` rather than recomputing inside the inner loop.

Each operation runs on the apply critical path through
`InvokeHostFunctionOpFrame::doParallelApply` and surrounding bookkeeping.
The four touch disjoint sub-paths (frame construction, footprint encoding,
meta building, RW-key TTL precompute), so their savings stack rather than
overlap. Summed lower bound is ~4.0%, with a plausible 5-6% if all four land
cleanly; either falls in the Medium band (3-10%).

## Trigger

Build a single PoC branch on the current accepted baseline
(`a0e763089aff250a6cb1395535253ba740ad6b39`, p26 SHA `fa1226b3`) that lands
all four changes behind no protocol gate (each is metering-neutral) and run
`scripts/run_apply_load_matrix.py` for three independent non-Tracy soroswap
runs. Compare the median apply time against the baseline averages
(`soroswap median average: 272.895607 ms` per `ai-summary/CURRENT_STATE.md`).

## Target Code

- `src/transactions/TransactionFrame.cpp:107-150` — `TransactionFrame`
  constructor; site to precompute and cache `CxxBuf` for hostFunction /
  resources / sourceID / auth and TTL-key map for RW footprint keys.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:380-450` — `addReads`
  computes `xdr::xdr_size(lk)` per footprint key on every parallel apply;
  swap to cached size from frame.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:570-610` — host invocation
  passes resources/sourceID/auth as freshly built `CxxBuf`s; consume cached
  buffers instead.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:625-670` —
  `recordStorageChanges` inner loop currently calls `getTTLKey()` per RW
  footprint entry; consume precomputed TTL-key map.
- `src/transactions/MutableTransactionResult.cpp` and
  `src/transactions/TransactionMeta.cpp` — `TransactionMetaBuilder` /
  `OperationMetaBuilder` construction in `apply()`; gate non-essential
  allocations on `mApp.getConfig().METADATA_OUTPUT_STREAM`-equivalent
  enabled check.
- `src/ledger/LedgerManagerImpl.cpp:2733-2790` — apply-loop call site that
  constructs the `TransactionMetaBuilder` per tx; verify the gate path
  flows through here.

## Evidence

- Per-zone Tracy self-time inside `applyLedger` confirms each individual
  sub-target lives on the apply critical path (e.g., `addReads`
  196.7 ms aggregate, `recordStorageChanges` 55.1 ms aggregate,
  `loadAccount` 73.3 ms / `loadAccountWithoutRecord` 44.9 ms in the
  worker phase; per-tx meta and CxxBuf construction in
  `InvokeHostFunctionOpFrame::doParallelApply` zone 35.3 ms aggregate
  with 6776 calls — these add up to a meaningful fraction even after
  cluster normalization).
- The four targets are independent code paths with no shared cache or
  shared invariant, so their wall-clock contributions are additive.
- Each individual sub-fix was rejected for being below the 3% floor, not
  for correctness reasons — the underlying mechanisms are all
  metering-neutral and protocol-invisible.
- All four are pure C++ apply-path edits (no submodule changes), keeping
  the diff small and the review burden bounded.

## Anti-Evidence

- Some of the cited 2.5% / 1.5% individual estimates were upper bounds at
  the time of rejection, before recent successes (typed SAC balance fast
  path, bulk-build host storage maps, host metering coalescing) were
  accepted; the current baseline's apply-time floor is lower (272 ms vs.
  the historical ~620 ms used in many of the original projections), which
  could compress the absolute saving and require the bundle to land all
  four wins to clear the Medium floor.
- Meta-builder gating risks subtly altering downstream meta consumers if
  any test path implicitly assumes a constructed builder; the soroswap
  benchmark itself does not consume meta but unit tests do.
- `TransactionFrame` is `const`; precomputing CxxBuf requires `mutable`
  cache members or computing during construction (which adds latency
  outside `applyLedger` but inside other Tracy windows).
- Three-run benchmark consistency (meta-pattern #17) is the final-review
  gate; even a 4-5% projected median win must beat baseline on every run,
  not just on average.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-05
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — the exact four-part bundle was not present in `fail/transaction-ledger` or `success/transaction-ledger`
**Failed At**: reviewer

### Trace Summary

The cited C++ paths are on the parallel Soroban apply path: `LedgerManagerImpl::applyParallelPhase` builds `TxBundle`/`TxEffects`, `applyThread` times and invokes each transaction, and `InvokeHostFunctionOpFrame::doParallelApply` constructs an apply helper that loads footprint entries, invokes the Rust host bridge, records modified ledger entries, and later finalizes result/meta. The individual wastes exist in source, but the proposed bundle does not establish a correct additive Medium-severity improvement on the current objective baseline. Two components are already bounded by the fail summary below Medium, the TTL-key component is a strict subset of a previously logged broader hypothesis, and the CxxBuf component is less removable than claimed because the bridge uses owned `UniquePtr`-backed buffers and `resources` is passed by value.

### Code Paths Examined

- `ai-summary/fail/transaction-ledger/summary.md:15-18,23,37` — previous failures cap `xdr_size` gating/cross-call caching at ~1.5%, CxxBuf precompute at ~2.5%, disabled-meta builder construction at ~0.5-1.7%, and pure C++ residual apply-path work as individually sub-threshold.
- `src/ledger/LedgerManagerImpl.cpp:2483-2507` — each Soroban worker creates a `mTransactionApply.TimeScope()` unless testing disables Soroban metrics, flushes pending TTL bumps, and calls `parallelApply`.
- `src/ledger/LedgerManagerImpl.cpp:2835-2847,2966-3031` — `enableTxMeta` is already false when `ledgerCloseMeta` is absent outside tests, but parallel apply still constructs `TxBundle`/`TxEffects` and `TransactionMetaBuilder` for API plumbing and fee event no-ops.
- `src/transactions/ParallelApplyStage.h:22-84` — `TxEffects` always owns a `TransactionMetaBuilder`; eliminating it when disabled would require changing the `TxEffects`/`TxBundle` interface, not just skipping a local allocation.
- `src/transactions/TransactionMeta.cpp:924-974,1035-1108,1111-1119` — disabled meta builders still allocate/resize per-op builder scaffolding, but heavy ledger changes, event finalization, fee meta, and finalization paths are already gated by `mEnabled`.
- `src/transactions/EventManager.cpp:138-146,236-246,351-359` — diagnostic, transaction, and operation event managers are disabled when meta is disabled; downstream event calls quickly no-op.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:386-535` — `addReads` computes `xdr::xdr_size(lk)` before discovering whether p23+ Soroban entries will skip disk-read metering, so the inefficiency is real but confined to small footprint-key XDR sizing.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-585` — every host invocation builds auth `CxxBuf`s and temporary `CxxBuf`s for host function, resources, and source account before crossing the Rust bridge.
- `src/rust/src/bridge.rs:13-15,193-208` and `src/rust/src/soroban_invoke.rs:7-39` — `CxxBuf` owns a `UniquePtr<CxxVector<u8>>`; host function/source are borrowed, auth is borrowed as a vector, but `resources` is passed as an owned `CxxBuf` by value, so a cached buffer cannot simply be reused without a bridge ownership/API change or a replacement copy.
- `src/transactions/TransactionUtils.h:370-376` — `toCxxBuf` always allocates a new `std::vector<uint8_t>` containing `xdr::xdr_to_opaque(t)`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:640-766` — `recordStorageChanges` linearly scans RW footprint keys for each modified output and calls `getTTLKey(rwKeys[j])` on TTL-related comparisons, then computes TTL keys again for uncovered erased Soroban entries.

### Why It Failed

The bundle's Medium projection is an arithmetic sum of historical upper bounds, not a demonstrated additive removable cost on the current baseline. `xdr_size` and disabled-meta construction are already logged below threshold; the `recordStorageChanges` TTL-key precompute is a narrow subset of a previously logged broader TTL precompute idea; and CxxBuf caching is not the simple "read cached buffers" change described because `CxxBuf` ownership and the current Rust bridge require fresh owned buffers for at least `resources` unless the bridge API is redesigned to borrow all precomputed bytes. Computing buffers in `TransactionFrame` construction would also move work out of the measured apply window rather than remove it from the system, which is not a sound optimize-soroswap apply-path win.

Even taking the fail summary's optimistic ceilings at face value, the current accepted baseline is ~272.9 ms, so Medium requires roughly 8.2 ms of reproducible top-line reduction. After excluding non-removable bridge copies/API work, already-gated meta/event work, and subcomponents that are strict subsets of prior failures, the real bundle ceiling is below the objective threshold and likely within benchmark noise. This should not proceed to PoC as a four-part "stacked" patch; a viable C++ apply-path hypothesis needs a fresh measurement showing a single coherent removable operation above the Medium floor, not a collection of previously rejected micro-optimizations.

### Lesson Learned

Combining sub-threshold failures is only viable when the removable costs are still present on the current baseline, independent, and actually removable by the proposed patches. For this objective, pure C++ apply-path micro-optimizations must be remeasured against the current accepted baseline and audited for ownership/metering/API constraints before their old percentage estimates can be stacked.
