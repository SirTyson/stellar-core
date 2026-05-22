# H001: Specialize SAC transfer internal-call boundary for Soroswap swaps

**Date**: 2026-05-22
**Subsystem**: ledger / Soroban apply
**Severity**: Medium
**Impact**: 3-6% soroswap apply-time reduction by bypassing generic host-call frame and argument dispatch overhead for the SAC transfer calls that remain on the native Soroswap swap path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When a Soroswap swap performs the same deterministic SAC `transfer` calls as today, the apply path should debit and credit the same balances, require the same source authorization, extend the same instance/code and balance TTLs, emit the same transfer events, charge a protocol-gated equivalent budget, and preserve the same per-transaction ordering inside each Soroban cluster. It should not need to route each transfer through the full generic `call` host function, `call_n_internal`, contract frame construction, generated builtin dispatch, and generic argument-vector path when the callee is known to be a Stellar Asset Contract and the function is exactly `transfer`.

## Mechanism

The current optimized Soroswap path still leaves SAC transfers as internal host calls. Each transfer crosses the generic VM host-call boundary, copies the `VecObject` into a fresh `Vec<Val>`, runs `call_n_internal` frame/reentry/panic/diagnostic scaffolding, pushes a `StellarAssetContract` frame, dispatches through the generated builtin contract wrapper, and only then reaches `StellarAssetContract::transfer`. The accepted soroswap trace confirms this work is inside `applyLedger`: `call` overlaps apply windows for 5.379s across 22,353 events, `SAC transfer` for 2.218s across 14,847 events, `push context` for 545ms, `snapshot auth` for 239ms, and `ScVal to Val` for 1.027s; normalized by the configured eight clusters, the SAC-transfer/call-boundary family is large enough to support a Medium win if the exact transfer path skips most generic wrapper work.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) from `ai-summary/CURRENT_STATE.md`. The trigger is every successful swap that invokes SAC `transfer` twice through Soroswap's token calls: the apply worker executes the swap in cluster order, then the host repeatedly enters the same Stellar Asset Contract transfer path for the two pool/user balance movements.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2568-2592` — `Host::call` converts a contract-call `VecObject` into a fresh argument vector before calling `call_n_internal`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:923-1121` — `call_n_internal` performs generic internal-call checks, frame handling, panic recovery, and diagnostics before/after the actual call.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-784` — `call_contract_fn` retrieves the contract instance and pushes a `Frame::StellarAssetContract` before dispatching to the builtin contract wrapper.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — `StellarAssetContract::transfer` is the semantic body that must remain unchanged: amount check, `require_auth`, TTL extension, spend/receive balance, and transfer event.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:192-194` — `call_args_from_obj` copies the VM argument vector even for fixed-arity SAC calls.

## Evidence

`csvexport-release -u` overlap against the current soroswap trace's 71 `applyLedger` windows shows this is not a TX-set construction artifact. In-apply overlap totals were: `applyLedger` 4.566s, `call` 5.379s aggregate worker time, `SAC transfer` 2.218s, `ScVal to Val` 1.027s, `push context` 545ms, `snapshot auth` 239ms, and `add host object` 352ms. Dividing worker aggregate time by `NUM_CLUSTERS=8`, `SAC transfer` alone is about 6.1% of the apply window and the enclosing generic `call` zone is about 14.7%, so a specialized path that removes the generic dispatch/frame/argument-copy layer for the exact builtin transfer calls plausibly clears the 3% Medium threshold.

A concrete implementation direction is a protocol-next fast path before or inside `Host::call`: if the target contract executable is `StellarAsset`, the symbol is `transfer`, arity is three, reentry mode is the normal internal Soroswap call mode, diagnostics do not require generic frame details, and the arguments decode to `Address`, `MuxedAddress`, and `i128`, call a typed helper that wraps the existing `StellarAssetContract::transfer` semantics while charging an explicit next-protocol fast-path budget. This does not add parallelism and does not reorder transactions, so cluster determinism is unchanged.

## Anti-Evidence

The trace zones are aggregate worker time and must be normalized by eight-way parallelism; a narrow dispatch-only shortcut would be insufficient if most time remains in balance storage, auth, event emission, and TTL extension. The fast path must be protocol-gated because it changes metered work, and it must fall back to the generic path whenever diagnostics, arity, symbol, executable type, or argument decoding do not exactly match the supported SAC transfer case.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — no ledger fail/success record covers this exact SAC `transfer` call-boundary specialization
**Failed At**: reviewer

### Trace Summary

The SAC transfer path does cross the generic host call boundary: a Wasm `call` import copies the `VecObject` to `Vec<Val>`, enters `call_n_internal`, retrieves the callee instance in `call_contract_fn`, pushes a `Frame::StellarAssetContract`, then dispatches through the builtin contract wrapper to `StellarAssetContract::transfer`. However, the dominant frame/auth/rollback parts are correctness boundaries, not removable wrapper overhead. `require_auth` builds the authorized invocation from the current frame's contract id, function symbol, and args, and SAC storage helpers depend on the current contract id and per-frame instance-storage/rollback behavior; skipping the frame would change auth, current-contract, diagnostics/lifecycle, and error rollback semantics.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2568-2600` — `Host::call` is the VM-import entry point, copies the argument object with `call_args_from_obj`, calls `call_n_internal` with external-call parameters, and records failure diagnostics.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:192-194` — `call_args_from_obj` materializes a fresh `Vec<Val>` from the host vector.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:100-122,923-1121` — `CallParams::default_external_call` prohibits reentry; `call_n_internal` performs reserved-function checks, reentry checks, diagnostics, and delegates to `call_contract_fn`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-784` — `call_contract_fn` retrieves the contract instance, copies the args for frame storage, and for `ContractExecutable::StellarAsset` runs `StellarAssetContract.call` inside `with_frame(Frame::StellarAssetContract(...))`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:186-205,401-562` — `with_frame`/`push_context` pushes auth context, snapshots storage/events/auth for rollback, runs lifecycle hooks, persists instance storage on success, and rolls back on error.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1340-1370,829-850` — every frame push records an auth stack frame; `require_auth` converts the current call-stack frame and current frame args into the authorized function that must match the transaction's auth entries.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:3605-3631` — `require_auth` obtains args from the current `Frame::StellarAssetContract`; without that frame, SAC `transfer` cannot produce the same auth requirement.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — the semantic transfer body performs amount validation, source auth, instance/code TTL extension, balance debit/credit, and event emission.
- `ai-summary/fail/ledger/summary.md:33,45,47,69` — adjacent SAC/frame hypotheses were previously rejected as sub-threshold or final-review failures, but none is the same call-boundary specialization.

### Why It Failed

The optimization claim overestimates the removable work. A correctness-preserving SAC-transfer fast path still needs a contract frame or an exactly equivalent lightweight context so `require_auth`, current-contract lookup, instance storage persistence, lifecycle hooks, event/storage rollback, and auth snapshots remain identical. That means the cited `push context` and `snapshot auth` costs cannot be counted as generic dispatch waste, and the `SAC transfer` body itself is deliberately unchanged. What remains is a narrow shortcut around one `Vec<Val>` copy, symbol/reentry/diagnostic checks, executable match, and generated builtin dispatch/typed-argument conversion. With roughly 14,847 transfer events over 71 ledgers and eight clusters, that residual per-call scaffolding is too small to plausibly clear the optimize-soroswap Medium threshold of a reproducible 3% apply-time reduction, especially after prior ledger summaries already found adjacent SAC instance, SAC storage-fusion, and host-frame snapshot subsets below threshold or not benchmark-successful.

### Lesson Learned

For Soroban host-call optimizations, separate semantic frame work from dispatch scaffolding before projecting impact. SAC calls look expensive inside the broad `call` zone, but the auth/current-contract/rollback frame is part of the contract semantics; a viable Medium SAC optimization must remove or fuse substantive balance/storage work, not just bypass the generic function-dispatch wrapper.
