# H002: Specialize Soroban PRNG Sub-Seed Hashing to Avoid Per-Tx XDR Allocation

**Date**: 2026-04-27
**Subsystem**: crypto, ledger apply, transactions
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by removing high-frequency allocation and extra SHA update calls in per-Soroban-transaction sub-seed derivation
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Every Soroban transaction and Soroban operation should receive the same deterministic PRNG sub-seed it receives today: `SHA256(seed || XDR(counter))`, where `counter` is encoded exactly as an XDR `uint64`. The optimization should only change how the bytes are staged for hashing; it must not change seed hierarchy, counter type, byte order, ledger output, host behavior, or cross-node determinism.

## Mechanism

`subSha256` is called on the apply path for every Soroban transaction bundle and again for each Soroban operation. Its current implementation performs incremental SHA setup, calls `SHA256::add(seed)`, allocates/serializes `xdr::xdr_to_opaque(counter)`, calls `SHA256::add(...)` again, and finalizes. In the current soroswap trace, timestamp overlap with `applyLedger` shows 973,195 in-scope `SHA256::add` calls totaling 99,595,515 ns from `crypto/SHA.cpp:65`, which closely matches the expected two `add` calls per Soroban tx/op sub-seed; specializing `subSha256` to hash a 40-byte stack buffer (`32-byte seed || big-endian uint64`) with one OpenSSL call should remove both the tiny XDR allocation and one million incremental-update calls.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=4000, T=8`) and apply many single-operation Soroban invoke-host-function transactions. The hot path is reached once in `LedgerManagerImpl::applyThread` per transaction bundle and once in `TransactionFrame::apply` per Soroban operation.

## Target Code

- `src/crypto/SHA.cpp:41-47` - `subSha256` currently uses `SHA256` incremental mode plus `xdr::xdr_to_opaque(counter)`.
- `src/ledger/LedgerManagerImpl.cpp:2490-2506` - parallel Soroban apply computes `txSubSeed = subSha256(sorobanBasePrngSeed, txBundle.getTxNum())` for every bundle.
- `src/transactions/TransactionFrame.cpp:2535-2553` - operation apply computes another `subSha256(sorobanBasePrngSeed, opNum)` for every Soroban operation.
- `src/crypto/SHA.cpp:29-38` - the one-shot OpenSSL `::SHA256` path is already used for stack-contiguous bytes and auto-selects SHA-NI.

## Evidence

The current accepted soroswap trace is `/mnt/nvme2/apply-load/14571316dcdf-20260427-185013/logs/14571316dcdf-20260427-185013-02-soroswap-tx-4000-t-8.tracy`. `csvexport-release -e` reports `add,crypto/SHA.cpp,65` at 289,667,309 ns self-time overall; timestamp overlap with `applyLedger` shows 973,195 in-scope `SHA256::add` events and 108,166,626 ns total in-scope `add` time, with 99,595,515 ns from `crypto/SHA.cpp:65`. The only source-level callers of `subSha256` are the Soroban apply loops and the helper itself, and the in-scope `SHA256::add` count is consistent with the two-update implementation being exercised at soroswap scale.

## Anti-Evidence

This is a narrow crypto helper optimization, so the raw traced `SHA256::add` self-time alone is slightly below the Medium threshold. The hypothesis depends on the untraced cost of repeated `xdr::xdr_to_opaque(counter)` allocation/serialization and SHA init/final overhead pushing the total reduction above 3%; if a PoC shows only a Low-tier improvement, it should be rejected under this objective's minimum-severity rule. The implementation must also preserve exact XDR uint64 byte order, not host-endian order.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-27
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated; existing crypto fail records cover signature verification timing and transaction contents hashing, not Soroban PRNG sub-seed derivation
**Failed At**: reviewer

### Trace Summary

The local inefficiency exists: `subSha256` hashes `seed || XDR(counter)` via two incremental `SHA256::add` calls and `xdr::xdr_to_opaque(counter)` allocates a fresh `opaque_vec` before the second update. However, the soroswap v23+ parallel apply path derives only one C++ sub-seed per transaction bundle in `LedgerManagerImpl::applyThread`; it does not also execute the operation-level `TransactionFrame::apply` sub-seed loop. The operation-level sub-seed path belongs to the sequential Soroban/classic apply path, while current parallel invoke-host-function application passes the transaction sub-seed directly to `InvokeHostFunctionOpFrame::doParallelApply`. The evidence also over-attributes aggregate `SHA256::add` samples to `subSha256`: the same line is reached by streaming XDR hashing and invoke-host-function success hashing inside apply.

### Code Paths Examined

- `src/crypto/SHA.cpp:41-47` — `subSha256` constructs an incremental `SHA256`, adds the seed, allocates and serializes the uint64 counter with `xdr::xdr_to_opaque`, adds those bytes, and finalizes.
- `lib/xdrpp/xdrpp/marshal.h:262-271` and `lib/xdrpp/xdrpp/types.h:497-498` — `xdr_to_opaque` returns a newly sized `xdr::opaque_vec<>`, which is an `xvector<uint8_t>`/vector-backed allocation; the allocation claim is real.
- `src/ledger/LedgerManagerImpl.cpp:2483-2506` — parallel Soroban apply calls `subSha256(sorobanBasePrngSeed, txBundle.getTxNum())` once per successful bundle before `TransactionFrame::parallelApply`.
- `src/transactions/TransactionFrame.cpp:2385-2430` — parallel Soroban transactions assert a single operation and pass `txPrngSeed` directly to `OperationFrame::parallelApply`; no per-operation `subSha256` occurs on this path.
- `src/transactions/OperationFrame.cpp:175-188` and `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1377` — `OperationFrame::parallelApply` delegates to `InvokeHostFunctionOpFrame::doParallelApply`, which constructs its helper with the already-derived transaction PRNG seed.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:570-584` and `src/rust/src/soroban_proto_any.rs:391-448` — the derived seed is copied into a `CxxBuf` and forwarded to the Rust host invocation as `base_prng_seed`.
- `src/ledger/LedgerManagerImpl.cpp:3035-3078` and `src/transactions/TransactionFrame.cpp:2535-2553` — the second `subSha256` call exists only in the sequential apply path, where `applySequentialPhase` derives a transaction seed and `TransactionFrame::apply` derives an operation seed for Soroban operations.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:902-920` and `src/crypto/SHA.h:39-64` — other in-apply `SHA256::add` callers include invoke-host-function success hashing and `XDRSHA256`, so Tracy samples at `crypto/SHA.cpp:65` are not uniquely attributable to `subSha256`.
- `/mnt/nvme2/apply-load/14571316dcdf-20260427-185013/results.csv:1-3` — the referenced run reports `soroswap,TX=4000,T=8` median apply time of about 621 ms per ledger, making the observed ~108 ms aggregate in-scope `SHA256::add` time across the whole trace far below the 3% Medium threshold even before subtracting non-`subSha256` callers and unavoidable SHA work.

### Why It Failed

The proposed specialization would be correctness-preserving if implemented carefully for a 32-byte seed and XDR big-endian uint64 counter, and it would remove a real tiny allocation in `subSha256`. It is not viable for this objective because the claimed hot-path frequency is overstated: the current soroswap parallel path pays one `subSha256` per transaction bundle, not both transaction and operation sub-seeds, and `SHA256::add` line samples include other hashing work. With the referenced median apply time, even eliminating all reported in-scope `SHA256::add` self-time would be below 1% of total apply time across the run; the actual removable portion is smaller because one-shot SHA still hashes the 40-byte preimage and because non-`subSha256` `add` callers remain. This falls below the objective severity threshold, so a PoC would be very unlikely to produce the required 3-10% reproducible apply-time reduction.

### Lesson Learned

For crypto helper optimizations in Soroban apply, distinguish parallel and sequential transaction paths before multiplying per-transaction costs. Tracy line-level attribution for generic helpers such as `SHA256::add` must be separated by caller; otherwise unrelated streaming hashes can make a narrow helper look much hotter than it is.
