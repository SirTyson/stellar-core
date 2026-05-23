# H002: Pre-bridge native Soroswap storage fast path

**Date**: 2026-05-23
**Subsystem**: ledger / Soroban apply
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by bypassing generic host storage-map construction and ledger-change extraction for recognized native Soroswap pool swaps
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For a recognized native Soroswap pair `swap`, the host should read the same footprint entries, apply the same SAC transfer and balance semantics, update the same pair reserve instance-storage keys, emit the same swap event, charge protocol-gated budget consistently, and return the same `InvokeHostFunctionOutput` ledger changes as the current generic `invoke_host_function` path. The fast path must preserve deterministic transaction order within each parallel-apply cluster and must fall back to the existing generic host path unless the contract hash, function symbol, arguments, footprint, and instance layout match the accepted native pool-swap shape exactly.

## Mechanism

The current native pool `swap` still starts after `rust_bridge::invoke_host_function` decodes the full footprint into a generic enforcing `StorageMap`, clones the initial storage map, constructs a `Host`, decodes auth entries/source/host function XDR, runs `Host::invoke_function`, finishes the host, and then scans storage again in `get_ledger_changes`. The current soroswap trace confirms these zones are inside `applyLedger`: unwrap overlap reports `invoke_host_function`-filtered events totaling 21,578,080,129 ns of in-apply worker time, with apply-contained `new map` at 461,915,256 ns, `storage get` at 672,084,842 ns, `map lookup indexed` at 585,969,208 ns, `read xdr with budget` at 204,336,327 ns, and `write xdr` at 180,059,763 ns. A pre-bridge native fast path can parse just the required ledger-entry buffers and return already-formed ledger changes/events for the exact native pool swap, avoiding generic storage-map build/clone/finish/extraction work without changing observable ledger output.

## Trigger

Run the current soroswap apply-load trace and filter descendants of `applyLedger` for `invoke_host_function`, `new map`, `storage get`, `map lookup indexed`, `read xdr with budget`, and `write xdr`. Successful native Soroswap pair swaps still enter the generic Rust host bridge at `InvokeHostFunctionOpFrame::invokeHostFunction`; the native pair logic is only reached later from `Host::call_contract_fn` after generic host input construction has already happened.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-585` — C++ builds `CxxBuf` inputs and calls `rust_bridge::invoke_host_function`; this is where an exact native result could be requested without altering parallel apply ordering.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:472-523` at p26 `fbbea0d9` — generic bridge decodes resources/footprint/ledger entries, builds `StorageMap`, clones `init_storage_map`, and constructs the `Host` before any native pair detection can occur.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:549-580` at p26 `fbbea0d9` — generic path invokes the host, finishes storage, and scans storage with `get_ledger_changes` to produce output.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1013-1392` at p26 `fbbea0d9` — accepted native pool `swap` and direct SAC balance code provide the exact semantics the pre-bridge recognizer must preserve.
- `src/transactions/ParallelApplyUtils.cpp:1084-1162` — thread-local ledger-entry reads/writes remain deterministic through `ThreadParallelApplyLedgerState`; a fast path should still commit via existing `upsertEntry`/`eraseEntry` and stage merge order.

## Evidence

The bridge and host-storage setup are on the measured close path: the unwrap overlap script found the selected zones almost entirely within `applyLedger` windows, while TX-set construction traps such as `tryAdd` and surge pricing are excluded. The current accepted p26 native code already proves that exact Soroswap pool swap semantics can be represented outside Wasm for the benchmark shape; moving recognition earlier attacks the remaining generic bridge work that the accepted native hook cannot remove. The structural win is larger than a loop micro-optimization because it can skip whole phases: generic footprint `StorageMap` construction, initial map clone, host setup, generic storage finish, and storage-diff extraction for native swaps.

## Anti-Evidence

This is a specialized protocol-gated redesign, not a small local edit. It must either reproduce budget-visible costs intentionally under the next protocol or update budget expectations for the cheaper native path, and it must return byte-equivalent ledger-change/event XDR after Core stamps `lastModifiedLedgerSeq`. Some XDR encode/decode and map work is mandatory for non-native invocations and for unsupported pool calls, so the hypothesis depends on the soroswap workload having enough recognized native pool swaps to amortize the extra recognizer and fallback checks.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate/follow-on of `ai-summary/fail/ledger/summary.md` entries `002-raw-native-pair-instance-storage.md`, `001-skip-output-side-sac-balance-read.md`, and the "Native Soroswap Path Must Be Present Before Optimization" meta-pattern
**Failed At**: reviewer

### Trace Summary

The C++ apply path still serializes footprint ledger entries into `CxxBuf`s, calls `rust_bridge::invoke_host_function`, records returned storage changes, and applies them through the existing parallel-apply ledger state. The Rust bridge still decodes the resources, footprint, ledger entries, auth entries, host function, and source account, builds a generic enforcing `StorageMap`, clones it as the initial snapshot, constructs a `Host`, invokes `Host::invoke_function`, finishes storage, and derives ledger changes through `get_ledger_changes`. However, the current p26 `Host::call_contract_fn` has no native Soroswap pool/pair/router dispatch at all: production contract execution matches only `ContractExecutable::Wasm` or `ContractExecutable::StellarAsset`, and a repository-wide search found no `soroswap`, `try_call_native_soroswap_pool_swap`, `call_native_soroswap_pool_swap`, or equivalent native pool helper in the p26 host source.

### Code Paths Examined

- `ai-summary/fail/ledger/summary.md:71,74-75,97` — prior retained failures already rejected follow-on native Soroswap optimizations because the source tree under review has no native Soroswap pair/router/SAC implementation.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:386-535` — `addReads` walks the footprint, loads ledger entries/TTLs, serializes them into owned `CxxBuf`s, validates resources, and meters reads before Rust invocation.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-585` — `invokeHostFunction` always calls `rust_bridge::invoke_host_function` with encoded host function, resources, auth entries, source account, ledger-entry buffers, TTL buffers, PRNG seed, rent config, and module cache.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:982-1010` — `doApply` calls `addFootprint`, then the Rust host bridge, then `recordStorageChanges`; a pre-bridge shortcut would have to reproduce the same output shape consumed by this writeback path.
- `src/rust/src/soroban_invoke.rs:7-60` and `src/rust/src/soroban_proto_any.rs:391-500` — the CXX bridge selects the protocol host module, invokes `e2e_invoke`, then extracts rent changes and modified ledger entries from the returned host ledger changes.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-521` — generic enforcing invocation decodes resources/footprint/input XDR, builds storage, clones `init_storage_map`, constructs the host, decodes auth/source/host function, invokes the host, finishes storage/events, and calls `get_ledger_changes`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:959-1083` — input ledger entries are decoded into a `StorageMap`; `StorageMapSnapshotSource` reads old values from the cloned map during change extraction.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-785` — production `call_contract_fn` dispatches only Wasm contracts through `instantiate_vm`/`vm.invoke_function_raw` and Stellar Asset contracts through `StellarAssetContract.call`; there is no Soroswap native pair branch to move earlier.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:923-1121` — `call_n_internal` enforces reserved-name/reentry rules, diagnostics, test-only native contracts behind `testutils`, and then calls `call_contract_fn`; the only compiled-in native Rust contract path is test-only, not production Soroswap apply.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1125-1194` — top-level `HostFunction::InvokeContract` decodes the contract id/function/arguments, enters a host-function frame, and calls `call_n_internal`.
- `src/transactions/ParallelApplyUtils.cpp:1084-1162` — thread-local reads first use `mThreadEntryMap`, then `InMemorySorobanState` for Soroban key types, otherwise LCL snapshot; writes still flow through `upsertEntry`/`eraseEntry` with deterministic dirty state.

### Why It Failed

The mechanism depends on an "accepted native pool swap" and "direct SAC balance" implementation that is not present in the checked-out p26 source. Without an existing native Soroswap semantic implementation, a pre-bridge recognizer is not a local fast path over known native logic; it would be a new native Soroswap contract reimplementation plus a new host-output synthesis pipeline. That is the same blocked optimization class already captured in the ledger failure history: before optimizing native Soroswap storage access, the native Soroswap path must actually exist in the source under review. The generic storage-map work is real, but it remains mandatory for the actual Wasm Soroswap router/pool path, and the proposed shortcut cannot preserve correctness by "moving recognition earlier" when there is no later production recognition to move.

### Lesson Learned

Do not propose follow-on native Soroswap storage or SAC fast paths from trace totals alone. First verify that production p26 contains a native Soroswap pair/router dispatch path; otherwise the benchmark is still executing official Soroswap Wasm through the generic host bridge, and any "native fast path" hypothesis is a new contract-reimplementation design rather than an optimization of existing ledger apply code.
