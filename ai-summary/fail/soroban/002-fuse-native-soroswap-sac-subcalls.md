# H002: Fuse Native Soroswap SAC Transfer and Balance Subcalls

**Date**: 2026-05-22
**Subsystem**: soroban
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by removing fixed SAC subcall frames from the native swap path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For the exact next-protocol Soroswap swap shape, token movement should preserve the same SAC transfer events, source-account/invoker authorization semantics, trustline and contract-balance writes, pair reserve reads, and failure behavior as the existing sequence of SAC `transfer` and `balance` subcalls. The efficient path should perform the fixed input transfer, output transfer, and pair balance reads through an internal typed helper while recording the same observable SAC events and falling back to the current subcall path whenever the asset, address shape, auth mode, or footprint does not match the benchmark pattern.

## Mechanism

The accepted native pair `swap` still calls back into the Stellar Asset Contract through `call_n_internal` for the output transfer and for two balance reads; the top-level router Wasm also performs the input SAC transfer. In the current trace these fixed subcalls remain hot inside `applyLedger`: `SAC transfer` total is 2.217731408s over 14,847 in-apply events, `SAC balance` total is 415.920127ms over 14,830 in-apply events, and the frame/auth overhead that surrounds these subcalls is also visible (`push context` 545.214325ms, `push auth frame` 407.080556ms, `snapshot auth` 238.564753ms in-apply totals). A protocol-gated typed helper for the exact Soroswap path can keep ledger/event/auth effects identical while avoiding repeated generic SAC frame setup, symbol dispatch, and balance subcall round-trips.

## Trigger

Run the current soroswap apply-load benchmark. Each swap performs a source-account-authorized input SAC transfer to the pair, a pair-authorized output SAC transfer to the recipient, and pair balance reads used to compute the fee-adjusted constant-product invariant.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1151-1173` at submodule commit `03d78248` — native pair `swap` invokes SAC `transfer` and two SAC `balance` calls via `call_n_internal`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1327-1360` at submodule commit `03d78248` — helper boundary for the current SAC transfer/balance subcalls.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — SAC `transfer` body whose fixed soroswap source/pair cases can be represented by a typed internal helper.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:44-63,376-617` — balance read/write paths for contract balances and classic trustlines that the helper must preserve.

## Evidence

The current native pair swap already has the exact pair code hash, token addresses, reserves, output amounts, recipient address, and pair contract address available before it dispatches the SAC subcalls. The apply-load generator fixes the surrounding source-account transfer shape in `src/simulation/ApplyLoad.cpp:3477-3496`, including the authorized root router invocation and token-in transfer sub-invocation. This makes the subcall sequence deterministic enough to express as a next-protocol typed transfer plan: debit the source/user trustline for token-in, credit the pair contract balance for token-in, debit the pair contract balance for token-out, credit the user trustline for token-out, emit the two SAC transfer events under the token contract IDs, then compute pair reserves without two separate SAC `balance` frames.

## Anti-Evidence

This is not viable as a mere SAC dispatcher shortcut: prior direct-dispatch ideas only removed symbol scanning and cheap wrapper conversions. The helper must cover the whole fixed subcall sequence and must explicitly preserve SAC event contract IDs, muxed-address handling, authorization trees, issuer/trustline/account edge cases, TTL extension, and rollback. It probably depends on the exact-router native plan so the input transfer can be fused with the pair swap; if only the output transfer and two balance reads are fused, the recoverable slice may be below Medium.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/soroban/001-fused-applyload-soroswap-swap-precompile.md` and `ai-summary/fail/soroban/summary.md` entries `001-protocol-gated-soroswap-native-router-pair.md + 001-protocol-gated-two-hop-soroswap-native-swap`, `001-pool-only-soroswap-native-precompile.md + 001-native-soroswap-pool-swap.md`, and `001-router-only-native-soroswap-trampoline.md + 002-native-two-token-router-swap-plan.md`
**Failed At**: reviewer

### Trace Summary

The apply-load benchmark does fix the relevant swap shape: it uploads vendored pool/router Wasm, invokes router `swap_exact_tokens_for_tokens` with a two-token path, and supplies an auth tree containing the token-in SAC `transfer` sub-invocation. In the traced p26 source, production contract dispatch has only `ContractExecutable::Wasm` and `ContractExecutable::StellarAsset` paths; Wasm calls instantiate a `Vm` and SAC calls use `Frame::StellarAssetContract`, with no in-tree native Soroswap router/pair frame or helper at the claimed line range. SAC `transfer` and `balance` effects are real and correctness-sensitive, but fusing the fixed router/pair/SAC sequence is substantially the same native Soroswap bypass family already reviewed and retained as failed/refinement records.

### Code Paths Examined

- `ai-summary/fail/soroban/001-fused-applyload-soroswap-swap-precompile.md:42-78` — prior review rejected the broader fixed router -> pool -> SAC transfer precompile as a duplicate of the same native Soroswap bypass family.
- `ai-summary/fail/soroban/summary.md:109-117` — records prior full router/pair and pool-only native Soroswap precompile attempts as under-specified on hashes, ABI, storage schema, events, errors, auth, rollback, and protocol metering.
- `ai-summary/fail/soroban/summary.md:131,167` — records the router-only native trampoline and pool-only native-precompile meta-patterns, including the requirement for code-hash-specific attribution and a complete native frame/auth/event/metering design.
- `src/simulation/ApplyLoad.cpp:2855-2913` — uploads vendored Soroswap factory, pair, and router Wasms and records their contract-code hashes.
- `src/simulation/ApplyLoad.cpp:3382-3496` — builds every measured swap as router `swap_exact_tokens_for_tokens` with fixed amount/path/deadline, declared router/SAC/pair footprint, and source-account auth with a token-in SAC `transfer` sub-invocation.
- `src/ledger/LedgerManagerImpl.cpp:1461-1510` and `src/transactions/InvokeHostFunctionOpFrame.cpp:575-584,1358-1378` — `closeLedger` apply reaches Soroban host invocation through the Rust bridge during parallel Soroban apply.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:137-147` — production frames are `ContractVM`, `HostFunction`, and `StellarAssetContract`; no native Soroswap frame exists in this checkout.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:401-598` — `with_frame` pushes auth/storage context, persists instance storage on success, and rolls back context state on error; a fused helper would need equivalent rollback semantics.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-784` — `call_contract_fn` dispatches Wasm through `instantiate_vm` + `Frame::ContractVM` and SAC through `Frame::StellarAssetContract`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:923-1121` — `call_n_internal` performs reserved-function/reentry handling and then delegates to `call_contract_fn`; the current file has 1279 lines, so the claimed `1327-1360` helper boundary is not present.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-218,393-412` — Wasm calls instantiate wasmi components and enter `Vm::invoke_function_raw`.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1340-1369` and `src/rust/soroban/p26/soroban-env-host/src/host.rs:3592-3631` — authorization frames are derived from the current `ContractVM` or `StellarAssetContract` frame and current frame args.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:186-225` — SAC `balance` extends instance/code TTL before reading balances; SAC `transfer` checks amount, requires auth, extends TTL, spends/receives balance, and emits the transfer/mint/burn event.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:44-63,90-225,376-617` — SAC balance reads and writes cover contract balances, account/trustline balances, authorization, checked arithmetic, TTL extension, and ledger storage updates.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:47-113` — SAC transfer events are contract-context events with issuer/muxed-address-sensitive data shape.

### Why It Failed

This is not novel. The current hypothesis narrows the previously rejected fused Soroswap precompile to SAC `transfer`/`balance` subcalls, but its own mechanism still depends on fusing the fixed router/pair/SAC sequence and preserving the same unresolved semantics: root and sub-invocation auth frames, SAC event contract IDs and order, muxed-address data, issuer/trustline/account edge cases, TTL behavior, rollback, error mapping, and a next-protocol metering schedule. Those blockers are exactly the retained failure requirements in the prior full router/pair, router-only, pool-only, and fused apply-load Soroswap records.

The traced source also does not match the hypothesis's premise that an accepted native pair `swap` helper exists in this checkout and still calls SAC through `call_n_internal`; `host/frame.rs` has no native Soroswap production frame or helper boundary at the cited lines. Without a new semantic design plus isolated measurements showing the additional SAC-subcall fusion clears the objective's Medium threshold after prior router/pool-native blockers are addressed, this is a duplicate native-bypass variant rather than a viable review-stage finding.

### Lesson Learned

Do not resubmit Soroswap native-bypass variants by moving the fusion boundary between router, pair, and SAC unless the proposal completes the retained requirements: a concrete next-protocol native frame/helper design, binary-proven storage/event/error/auth equivalence, deterministic metering and rollback behavior, forced-Wasm byte-equivalence criteria, and code-hash-specific measurements isolating the newly removable work above the Medium threshold.
