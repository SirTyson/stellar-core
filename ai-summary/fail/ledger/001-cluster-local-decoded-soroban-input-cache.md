# H001: Cluster-local decoded Soroban input cache for repeated swap footprints

**Date**: 2026-05-05
**Subsystem**: ledger / Soroban parallel apply bridge
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by amortizing repeated input decoding and storage-map construction across same-cluster swaps
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Parallel Soroban apply should still execute every transaction in a fresh host with an isolated budget, auth stack, events, storage overlay, and deterministic per-transaction result ordering. However, when many transactions in the same cluster repeatedly provide the same read-only contract instance/code entries and TTL entries, the apply path should be able to reuse immutable decoded input objects instead of re-decoding the same XDR buffers and rebuilding equivalent metered storage/footprint maps from scratch for every invocation.

## Mechanism

`LedgerManagerImpl::applyThread` currently invokes each transaction independently, and `InvokeHostFunctionOpFrame` serializes footprint entries into `CxxBuf`s before `e2e_invoke::invoke_host_function` decodes `SorobanResources`, builds the footprint, decodes every ledger/TTL entry, validates footprint membership, inserts each entry into `MeteredOrdMap`, clones the initial storage map, then builds a fresh enforcing `Storage`. Soroswap intentionally repeats hot router/SAC/pair read-only entries within each dependent cluster, so this per-transaction bridge path pays repeated XDR decode, `ScVal` conversion, and map lookup/build work for immutable inputs that could be cached at the cluster worker boundary.

The proposed optimization is to introduce a cluster-local decoded input cache owned by `ThreadParallelApplyLedgerState` or a new Rust batch-invocation context keyed by `(LedgerKey, encoded LedgerEntry bytes or hash, TTL bytes, protocol)`. Each transaction would still receive a fresh host and fresh mutable storage overlay, but read-only decoded entries, TTL metadata, and possibly prebuilt footprint-key objects would be cloned or referenced from the cluster cache in deterministic transaction order. The cache must be per-worker/per-cluster, not global mutable state, and must invalidate or bypass entries that are read-write, restored, expired, or modified by earlier transactions in the cluster.

## Trigger

Run the current soroswap apply-load workload (`soroswap, TX=2000, T=8`). `ApplyLoad::generateSoroswapSwaps` creates exactly one pair per dependent cluster, round-robins swaps across pairs, and puts the router instance, two SAC instances, router code, and pair code in the read-only footprint for every swap. This causes many transactions in a cluster to repeatedly pass the same immutable read-only entries through `addReads` and `invoke_host_function`.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2483-2520` - `applyThread` loops over every transaction in a cluster and invokes the full per-transaction Soroban bridge path.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:386-497` - `addReads` serializes live footprint entries and TTLs into per-transaction `CxxBuf` vectors.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` - `invokeHostFunction` passes per-transaction owned buffers to Rust.
- `src/rust/src/bridge.rs:193-208` - the CXX bridge exposes only per-invocation `CxxBuf`/`Vec<CxxBuf>` inputs.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-451` - `invoke_host_function` decodes resources, builds the footprint/storage map, and clones the initial storage map before creating the host.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:959-1052` - `build_storage_map_from_xdr_ledger_entries` decodes every input ledger/TTL entry and inserts it into `MeteredOrdMap` for every invocation.
- `src/simulation/ApplyLoad.cpp:2672-2678` and `src/simulation/ApplyLoad.cpp:3381-3475` - soroswap creates one pair per cluster and repeats the same hot read-only router/SAC/pair entries across swaps.

## Evidence

The current soroswap trace reports `applyLedger` total time of 5,230,315,999 ns. Timeline overlap analysis shows 100% of the following candidate zones are descendants of `applyLedger`: `invoke_host_function` total 12,055,276,481 ns / self 741,215,306 ns over 6,776 calls at `soroban-env-host/src/e2e_invoke.rs:488`; `read xdr with budget` self 164,491,109 ns over 129,270 calls at `soroban-env-host/src/host/metered_xdr.rs:109`; `ScVal to Val` self 429,988,065 ns over 691,521 calls at `soroban-env-host/src/host/conversion.rs:436`; and `map lookup indexed` self 408,451,716 ns over 779,242 calls at `soroban-env-host/src/host/metered_map.rs:330`.

Prior rejection of a narrower `GlobalParallelApplyEntry` encoded-byte cache concluded that C++ `addReads` alone was too small and that a viable design would need to amortize Rust-side per-invocation decode too. This hypothesis targets that broader boundary: avoid both repeated input XDR decoding and repeated storage-map construction for immutable read-only entries while preserving per-transaction host isolation.

## Anti-Evidence

The current branch already includes several Soroban input optimizations, including bulk host footprint/storage-map construction and cached old-entry XDR size metadata, so a PoC must prove that enough repeated read-only decode/map-build work remains after those changes. The design must not reuse mutable `Storage`, `Host`, budget state, events, auth state, or read-write entries across transactions; doing so would risk nondeterministic or incorrect ledger effects. It also must avoid increasing memory/cache pressure enough to repeat the measured regression seen in prior cluster-state parallelism experiments.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-05
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not an exact duplicate, though adjacent prior failures cover encoded-buffer caching and typed host storage ingress
**Failed At**: reviewer

### Trace Summary

The claimed per-transaction path is real: each cluster worker calls `parallelApply`, constructs a fresh apply helper, serializes all footprint entries into owned C++ buffers, and passes those buffers to a Rust invocation that decodes resources, builds footprint/storage maps, clones the initial map, and creates a fresh host. Soroswap does repeat the same five read-only router/SAC/code entries within each pair/cluster, but those are only a subset of each transaction's input buffers, and the read-write pair/user entries still need per-transaction values. After normalizing the cited Rust zones by the 8 parallel clusters and restricting the removable work to immutable read-only ingress, the realistic ceiling falls below the objective's 3% Medium threshold.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — `applyThread` applies each transaction in a cluster independently and commits successful changes back into the thread state.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:386-497` — `addReads` loads each read-only and read-write footprint key, serializes live entries and TTLs into fresh `CxxBuf`s, and appends them to per-helper vectors.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — `invokeHostFunction` sends owned per-transaction buffers through the current bridge API.
- `src/rust/src/bridge.rs:193-208` — the bridge exposes only per-invocation encoded buffers and has no cluster/session object for decoded inputs.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-451` — `invoke_host_function` decodes resources, builds a footprint, decodes ledger/TTL entries into a storage map, clones that map, and creates a fresh host.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:959-1052` — `build_storage_map_from_xdr_ledger_entries` decodes every supplied entry and TTL, checks footprint membership, inserts entries into metered maps, and fills absent footprint keys each invocation.
- `src/simulation/ApplyLoad.cpp:2672-2678,3381-3475` — soroswap creates one pair per cluster and repeats the router instance, two SAC instances, router code, and pair code in read-only footprints, while trustlines, pair balances, and the pair instance remain read-write per transaction.
- `ai-summary/fail/ledger/summary.md:29,34` — prior investigations already found C++ encoded-buffer caching alone below threshold and recorded a failed typed-ingress attempt; this hypothesis is broader but must still clear the same Medium floor.

### Why It Failed

The hypothesis overestimates the removable work. The cited `invoke_host_function` total is mostly actual host execution, not cacheable ingress construction. The cited `ScVal to Val` and `map lookup indexed` zones are broad aggregate worker-thread costs and include contract execution, auth, storage use, footprint checks, and result processing that a decoded read-only-entry cache would not remove. The directly relevant XDR-read self-time is 164 ms aggregate, which is only about 20 ms of serial critical-path time at 8-way cluster parallelism; soroswap's cacheable read-only entries are only part of that. Prior measurement also put the C++ `addReads` encoding side around the Low range, and combining the cacheable subset of C++ encoding with the cacheable subset of Rust decode/map construction is still unlikely to reach the 3% objective threshold without a larger storage-ingress redesign.

The proposed cache is therefore a plausible Low-tier cleanup, but this objective accepts only Medium and High findings. It should not proceed to PoC under optimize-soroswap unless supported by narrower non-Tracy measurements showing that read-only ingress construction alone exceeds the current estimate.

### Lesson Learned

For parallel Soroban worker zones, normalize aggregate Tracy time by cluster parallelism and then isolate the subset a proposed cache can actually remove. Repeated read-only footprint entries are real, but most per-invocation Soroban host cost remains fresh by design: read-write state, host/budget/auth/events, footprint decoding, and contract execution all still occur per transaction.
