# H081: `contract_code_memory_size_for_rent` Rust-FFI Has No Soroswap Apply-Path Reachability

**Date**: 2026-05-25
**Subsystem**: crypto / rust
**Severity**: Low
**Impact**: per-CONTRACT_CODE rent-size FFI hop with zero soroswap coverage

**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

When `closeLedger` writes Soroban entries, `ledgerEntrySizeForRent` (`src/ledger/LedgerTypeUtils.cpp:52-74`) must compute the rent-charged size for each entry. For `CONTRACT_CODE` entries on protocol ≥ V23, the function adds the in-memory module size (computed via Rust by parsing the WASM and querying `wasmi`'s engine-side memory accounting) to the XDR byte size. This requires a Rust-FFI hop with three `CxxBuf` arguments (contract-code XDR, CPU cost params, mem cost params). A viable optimization would either cache the per-WASM result on `LedgerKey(hash)`, batch the FFI for multiple code entries per ledger, or inline a C++ estimator — but only if the apply path actually exercises this branch for soroswap.

## Mechanism

`ledgerEntrySizeForRent` branches on `isContractCodeEntry(entry.data)` (line 56). For non-code entries (CONTRACT_DATA, TTL, account, trustline), the function returns `entryXdrSize` directly with no FFI. The candidate Rust-bridge optimization (`rust_bridge::contract_code_memory_size_for_rent`) only matters if soroswap apply repeatedly writes new `CONTRACT_CODE` entries, since the FFI requires three `toCxxBuf` allocations and dispatches into the soroban-env-host module-cache parser to materialize a `ParsedModule` (`src/rust/src/soroban_module_cache.rs:124-132`).

For soroswap, the deployed pool/router/SAC contracts are uploaded once during benchmark setup, not during the measured apply window. Each apply-window transaction is an `INVOKE_HOST_FUNCTION` against pre-existing contracts; the per-tx footprint touches contract instance, persistent data, and TTL entries — never new contract code. The deviation from expected impact is that the `isCodeEntry` branch is never taken from `applyLedger` descendants in the soroswap workload.

## Trigger

Run the protocol-27 soroswap apply-load benchmark and grep the trace for `contract_code_memory_size_for_rent` (or `rentEntrySize` zones) inside `applyLedger` windows. The candidate optimization would require apply-window events; source review of the soroswap workload finds zero `LEDGER_ENTRY_TYPE::CONTRACT_CODE` writes per applied tx (uploads happen during setup tx-set generation, outside the measured benchmark window).

## Target Code

- `src/ledger/LedgerTypeUtils.cpp:51-74` — `ledgerEntrySizeForRent`; only enters the FFI branch when `isContractCodeEntry(entry.data)` is true.
- `src/transactions/TransactionUtils.cpp:2349` — apply-path caller (rent fee computation via tracker).
- `src/ledger/InMemorySorobanState.cpp:33` — in-memory load-time caller (init path, not apply hot loop).
- `src/invariant/BucketListStateConsistency.cpp:135` — invariant-only caller (opt-in, not enabled in benchmark; see H077 for the analogous pattern).
- `src/rust/src/soroban_module_cache.rs:124-132` — `contract_code_memory_size_for_rent` FFI dispatch through `HOST_MODULES`.
- `src/rust/src/soroban_proto_any.rs:623+` — protocol-specific implementation calling into soroban-env-host module parsing.

## Evidence

The FFI surface is real: parsing a WASM module to determine its in-memory footprint is genuinely expensive (allocates a `ParsedModule`, walks sections, queries cost-params arithmetic). If this were called per-tx on the soroswap apply path, the per-call cost (likely 10s–100s of µs) would compound with the 130k tx FFI count and be a Medium-tier candidate.

## Anti-Evidence

The branch is unreachable for soroswap apply. Soroswap's transactions are `InvokeHostFunctionOp` calls against already-uploaded contracts; the per-tx footprint touches `CONTRACT_DATA` (pool reserves, balances), `CONTRACT_DATA` instance entries, and `TTL` entries — never `CONTRACT_CODE`. `isContractCodeEntry` returns false for all apply-path entries in the benchmark, so the FFI hop is never taken.

The other reachable callers are off-scope: `InMemorySorobanState.cpp:33` runs at startup load (before the measured benchmark window), and `BucketListStateConsistency.cpp:135` is an opt-in invariant not registered in apply-load configuration (analogous to H077 — invariant-only callers are dead code under the benchmark config).

Realistic apply-window FFI count: **zero**. Optimization impact on soroswap apply: **0%**.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Failed At**: hypothesis
**Novelty**: PASS — `contract_code_memory_size_for_rent` was not previously recorded in `ai-summary/fail/crypto/summary.md`. Adjacent priors cover other Rust-bridge per-call surfaces (H070 HostModule dispatch, H071 CxxFeeConfiguration, H037 cost-param decode), none of which target this specific code-entry rent-size FFI.

### Why It Failed

The `isContractCodeEntry` guard in `ledgerEntrySizeForRent` is never true on the soroswap apply path: the benchmark workload contains no per-tx `CONTRACT_CODE` writes. The FFI is therefore dead code under the benchmark and any optimization (caching, batching, C++ inlining) has zero apply-time impact. The two adjacent callers (`InMemorySorobanState` init path and `BucketListStateConsistency` invariant) are both off-scope per Meta-Pattern 11 (out-of-apply or opt-in invariant; see H077).

### Lesson Learned

Before sizing a Rust-bridge optimization for a per-entry FFI hop, enumerate which ledger-entry types actually trigger the hop on the target workload. For `contract_code_memory_size_for_rent`, the only triggering type is `CONTRACT_CODE`, which soroswap never writes after setup. Apply Meta-Pattern 11 (verify `closeLedger` reachability with the actual workload's entry-type mix) before any rent-related FFI optimization.
