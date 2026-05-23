# H002: Cluster-Local Rust Soroban Executor

**Date**: 2026-05-23
**Subsystem**: soroban-env / rust bridge / transaction-ledger boundary
**Severity**: High
**Impact**: Dominant-phase redesign of the Soroban `closeLedger` apply path; expected 3-10%+ soroswap apply-time reduction if per-transaction C++↔Rust XDR setup and teardown are collapsed inside each deterministic cluster worker
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Within one Soroban apply cluster, transactions must still execute in the cluster's deterministic transaction order, produce the same per-transaction results, events, rent fees, modified ledger entries, TTL updates, refunds, and rollback behavior, and must not use more workers than the configured cluster parallelism. The implementation should not rebuild a full Rust host from freshly serialized C++ buffers for every transaction when a cluster worker already owns the sequential state transition for that cluster.

## Mechanism

`InvokeHostFunctionOpFrame` currently serializes each transaction's footprint entries into `CxxBuf`s, calls the Rust bridge once per transaction, Rust decodes those buffers into a fresh host/storage/budget, then Rust re-serializes modified entries for C++ to parse and commit back into the same cluster-local ledger state. A next-protocol cluster-local Rust executor can move the sequential cluster loop across the FFI boundary: C++ passes the ordered cluster bundle and a deterministic storage adapter once, Rust creates a fresh per-transaction `Budget`/auth/events context while retaining an unmetered cluster-local decoded storage cache and returning per-transaction effects in order. This avoids the repeated C++ `addReads` serialization, Rust metered-XDR setup, Rust-to-C++ effect serialization/parsing, and bridge call overhead without adding nondeterminism or exceeding `NUM_CLUSTERS`.

## Trigger

Run the current soroswap apply-load benchmark with the accepted next-protocol baseline. Every successful Soroban transaction in a cluster currently goes through `InvokeHostFunctionOpFrame::addFootprint`, `invokeHostFunction`, and `recordStorageChanges` independently even though `LedgerManagerImpl::applyThread` then applies those effects sequentially to the same `ThreadParallelApplyLedgerState`.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — `applyThread` already owns the deterministic per-cluster transaction loop; this is the boundary to replace with a Rust cluster executor call while preserving cluster order.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:386-535` — `addReads` serializes footprint ledger entries and TTL entries into per-transaction `CxxBuf`s.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-592` — `invokeHostFunction` performs one FFI call per transaction with separately serialized host function, resources, source account, auth entries, ledger entries, TTL entries, and PRNG seed.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:641-720` — `recordStorageChanges` parses Rust-emitted entries and matches them back to the read-write footprint before applying them to the same cluster state.
- `src/rust/src/soroban_proto_any.rs:310-500` — Rust bridge entry point decodes C++ buffers, creates per-transaction host execution, extracts rent/storage effects, and serializes outputs.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:183-292,408-580` — fresh per-transaction storage-map construction and ledger-change extraction to replace with a cluster-local executor/storage adapter.

## Evidence

The current soroswap trace verifies these zones are inside `applyLedger`, not TX-set construction. Apply-contained unwrap totals include `addReads` at 314,372,335 ns across 15,794 events, `read xdr with budget` at 204,336,327 ns across 149,459 events, `write xdr` at 180,059,763 ns across 227,325 events, `recordStorageChanges` at 112,473,485 ns across 7,851 events, and the Rust `invoke_host_function` / `invoke_host_function_or_maybe_panic` parent envelope at 21,578,080,129 ns across 15,702 nested events. Source inspection shows the same cluster worker immediately consumes each transaction's Rust output and mutates `ThreadParallelApplyLedgerState`, so the per-transaction bridge roundtrip is an architectural boundary rather than an externally observable ordering requirement.

## Anti-Evidence

This must be a protocol-gated redesign, not a p26-compatible decoded-value cache. Reusing decoded ledger entries while pretending the old per-transaction `ValDeser`, map-construction, and `ValSer` charges still occurred would violate exact budget accounting and repeat prior metering failures. A viable design needs an explicit next-protocol resource model for cluster execution, fresh per-transaction budget/error boundaries, deterministic per-transaction output ordering, and a conservative fallback to the existing per-transaction bridge for unsupported transactions, hot-archive restores, diagnostics modes, or any cluster shape the new executor cannot prove equivalent.
