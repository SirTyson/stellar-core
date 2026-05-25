# H002: Eager Transaction Contents Hash Before Apply

**Date**: 2026-05-25
**Subsystem**: transactions
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by removing serial first-touch transaction content hashing from `applyLedger`
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

During Soroban `applyLedger`, transaction content hashes should already be available on each `TransactionFrame` before fee processing and pre-parallel apply validation need them. `processFeesSeqNums`, `preParallelApply`, signature checking, expected-result matching, logging, and PRNG seed derivation should all observe the same deterministic hash value they do today, but close-time apply should not be the phase that first serializes and SHA-256 hashes each transaction envelope.

## Mechanism

`TransactionFrame::getContentsHash` is lazy: the first call serializes `mNetworkID`, envelope type, and the transaction body to opaque XDR and hashes it. The current parallel Soroban apply path calls `getContentsHash()` from serial apply-thread code before worker execution (`preParallelApply` at `TransactionFrame.cpp:2250-2268`, expected replay result matching in `processFeesSeqNums` under tests, and related validation/signature paths). On the current trace, apply-contained `getContentsHash` time at `transactions/TransactionFrame.cpp:135` totals 151.7ms across 164,725 calls, or 3.42% of the `applyLedger` window total; this is a serial close-time cost, unlike worker aggregate zones that must be divided by T=8.

The proposed change is to eagerly compute and store `mContentsHash` when a `TransactionFrame` is built or first admitted/validated before close, so `applyLedger` only reads the cached hash. This preserves determinism because the transaction envelope and network ID are immutable members of `TransactionFrame`; it changes when the hash is paid for, not the hash value or observable ledger output.

## Trigger

Run the accepted soroswap apply-load baseline and inspect `getContentsHash` events fully contained in `applyLedger`. The issue triggers when Soroban transactions reach `LedgerManagerImpl::processFeesSeqNums` and `TransactionFrame::preParallelApply` with `mContentsHash` still zero, causing serial close-time XDR serialization and SHA-256 hashing. A successful PoC should reduce or eliminate first-touch `getContentsHash` work inside `applyLedger` and produce a reproducible 3-10% soroswap median apply-time reduction across three non-Tracy runs.

## Target Code

- `src/transactions/TransactionFrame.cpp:107-119` — constructor currently builds operation frames but leaves `mContentsHash` lazy.
- `src/transactions/TransactionFrame.cpp:132-154` — `getContentsHash` performs the lazy XDR-to-opaque serialization and SHA-256 hash when `mContentsHash` is zero.
- `src/transactions/TransactionFrame.cpp:2250-2268` — `preParallelApply` / `preParallelApplyReadOnly` call `getContentsHash()` on the serial apply thread before worker execution.
- `src/ledger/LedgerManagerImpl.cpp:2303-2440` — `processFeesSeqNums` iterates all transactions before apply; in BUILD_TESTS/benchmark builds with expected results it also compares `transactionHash == tx->getContentsHash()`.
- `src/ledger/LedgerManagerImpl.cpp:2784-3030` — `applyTransactions` builds Soroban bundles and then executes the parallel phase after serial hash-dependent setup.

## Evidence

The current Tracy trace from `ai-summary/CURRENT_STATE.md` was exported with `csvexport-release -u` and filtered to events fully contained in `applyLedger`. The contained-zone sum reports:

- `applyLedger`, `ledger/LedgerManagerImpl.cpp:1484`: 4.437s total over 71 windows.
- `getContentsHash`, `transactions/TransactionFrame.cpp:135`: 151.741ms contained total over 164,725 calls, 3.420% of apply-contained time.
- `preParallelApply`, `transactions/TransactionFrame.cpp:2359`: 150.300ms contained total, showing this is the same serial pre-worker region rather than parallel worker aggregate.
- `processFeesSeqNums`, `ledger/LedgerManagerImpl.cpp:2308`: 149.404ms contained total, another serial region that may first-touch hashes in benchmark/replay builds.

The source confirms `mEnvelope` and `mNetworkID` are immutable after construction, while `mContentsHash` is mutable cache state. Eager construction-time or admission-time hashing would therefore preserve the exact hash and avoid a serial first-touch inside close.

## Anti-Evidence

Some `getContentsHash` calls are cached getter calls, and Tracy instrumentation inflates tiny cached calls; the PoC must separate true first-touch hashing from `ZoneScoped` overhead and prove the non-Tracy benchmark moves. Eager hashing shifts cost earlier in the transaction lifecycle rather than deleting it, so it should only be accepted if the transaction is already expected to need its contents hash during validation/admission and the change does not create a new transaction-ingestion DoS surface for envelopes that would otherwise be discarded without hashing.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated
**Failed At**: reviewer

### Trace Summary

The claimed serial first-touch in fee processing or pre-parallel apply is not present on the current applicable-txset construction path. `LedgerManagerImpl::applyLedger` calls `TxSetXDRFrame::prepareForApply`, which creates the `TransactionFrame`s from wire XDR; both legacy/generalized sequential components and parallel Soroban components explicitly call `tx->getContentsHash()` and `tx->getFullHash()` while constructing those frames. By the time `processFeesSeqNums`, `preParallelApply`, signature checking, result hashing, logging, and Soroban PRNG seeding call `getContentsHash()`, they are reading an already-populated cache rather than serializing and SHA-256 hashing the transaction body.

### Code Paths Examined

- `src/transactions/TransactionFrame.cpp:107-119` — constructor stores the immutable envelope/network ID and builds operation frames, leaving hash caches lazy at the class level.
- `src/transactions/TransactionFrame.cpp:132-158` — `getContentsHash()` only serializes and hashes when `mContentsHash` is zero; otherwise it returns the cached hash, with `ZoneScoped` still present on every cached getter call.
- `src/herder/TxSetFrame.cpp:474-489` — generalized/legacy list frame creation constructs each transaction frame and immediately precomputes contents and full hashes.
- `src/herder/TxSetFrame.cpp:590-600` — the single-transaction sequential path also precomputes contents and full hashes for consistency.
- `src/herder/TxSetFrame.cpp:1824-1851` — parallel Soroban stage frame creation constructs transaction frames in parallel and precomputes contents and full hashes before sorting or apply.
- `src/herder/TxSetFrame.cpp:1923-1935` — the single parallel-component transaction path also precomputes both hashes.
- `src/ledger/LedgerManagerImpl.cpp:1581` and `src/herder/TxSetFrame.cpp:1383-1434` — `applyLedger` prepares the XDR txset into an `ApplicableTxSetFrame` through the precomputing paths above before fee/seq processing starts.
- `src/ledger/LedgerManagerImpl.cpp:2303-2440` — `processFeesSeqNums` only calls `getContentsHash()` under `BUILD_TESTS` when replay expected results are present; normal apply-load fee processing does not first-touch transaction contents hashes here.
- `src/transactions/TransactionFrame.cpp:2250-2268` — `preParallelApply` and `preParallelApplyReadOnly` pass `getContentsHash()` into validation, but on applicable txsets built by `prepareForApply` this is a cached read.
- `src/ledger/LedgerManagerImpl.cpp:2727-2736` and `src/ledger/LedgerManagerImpl.cpp:2833` — result-pair hashing and Soroban base PRNG seed derivation read cached transaction/txset hashes during apply.

### Why It Failed

The optimization claim depends on `mContentsHash` still being zero when Soroban transactions enter `processFeesSeqNums` or `preParallelApply`, but the txset-to-applicable-txset conversion already precomputes the contents hash for every transaction before those phases. The remaining `getContentsHash` samples in Tracy are therefore cached getter calls (plus Tracy `ZoneScoped` overhead), not avoidable XDR serialization and SHA-256 work. A constructor-level eager hash would only move the same precomputation within `prepareForApply` and would not remove a Medium-tier soroswap apply cost; moving arbitrary externalized txset hashing out of `applyLedger` would require a different txset/application-data reuse design, not the proposed transaction-frame cache change.

### Lesson Learned

For transaction hash optimizations, trace how the `ApplicableTxSetFrame` is produced before attributing `getContentsHash()` zones in apply to first-touch hashing. Current txset preparation intentionally precomputes transaction hashes to make sorting and later apply-phase consumers cached; cached getter instrumentation can look significant in Tracy but is not a reliable Medium-tier non-Tracy apply-time target.
