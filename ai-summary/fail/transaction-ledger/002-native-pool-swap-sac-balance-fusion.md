# H002: Fuse native pool swap SAC transfer and balance accounting

**Date**: 2026-05-23
**Subsystem**: transaction-ledger, soroban-env
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by eliminating residual SAC subcall and balance-read work inside the native pool swap path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

The native Soroswap pool `swap` path should update the output SAC balance, compute `amount_0_in` / `amount_1_in`, enforce the same constant-product check, update reserves, emit the same transfer and swap events, and preserve authorization/error semantics exactly as the current native pool swap plus SAC subcalls. For the canonical apply-load shape with one input token and one output token, the optimized path should avoid re-entering generic external SAC calls and should not re-read a balance whose post-swap value is already known from the reserve and output amount.

## Mechanism

The accepted native pool swap still calls `soroswap_pool_invoke_sac_transfer` for the output token via `call_n_internal`, then calls `soroswap_pool_invoke_sac_balance` for both pool-token balances before computing `amount_0_in` and `amount_1_in`. The direct SAC balance fast path removed full `balance` subframes, but this code still pays generic SAC transfer call-frame/auth/event plumbing and at least one redundant post-transfer balance lookup: for the output side of a standard swap, the pair balance after the transfer is `reserve_out - amount_out`, while the input side is the only side that needs a balance read to detect the transferred input amount.

A pool-swap-local typed helper can combine the output transfer and balance accounting: validate that the token executable is SAC, perform the same SAC transfer semantics from the pair contract to `to`, return the updated pair balance for the output token, and read only the input-side pair balance (or return both balances when the helper also handles the input transfer in a router-fused variant). This is not a general SAC fast lane; it is restricted to the already hash-gated native Soroswap pool swap and can preserve deterministic ledger output by executing the same storage mutations and event emission in the same observable order.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) on the accepted baseline. Each native pool `swap` call with exactly one positive output amount enters `call_native_soroswap_pool_swap`, transfers the output SAC from the pair to the recipient, then reads both SAC pair balances before computing the input amount and updating reserves.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1076-1176` — native pool `swap` validates reserves/tokens, performs output SAC transfer(s), then reads both pair balances.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1178-1266` — computes input amounts from the post-transfer balances and updates reserves.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1330-1347` — `soroswap_pool_invoke_sac_transfer` re-enters generic `call_n_internal` for SAC `transfer`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1349-1392` — `soroswap_pool_invoke_sac_balance` uses the direct SAC balance read for contract owners but still reads both token balances.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:180-199` — accepted direct contract-owner SAC balance reader that can be reused or extended for a transfer-and-return-balance helper.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — SAC `transfer` semantics that must be preserved for events, auth, TTL, and balance mutation.

## Evidence

The current Tracy trace from `ai-summary/CURRENT_STATE.md` shows this path is still material inside `applyLedger`: timestamp-filtered `SAC transfer` events total 2,477.085 ms aggregate worker time (about 4.36 ms per ledger after T=8 normalization), `storage get` totals 672.085 ms, `extend_current_contract_instance_and_code_ttl` totals 455.825 ms, and `call` totals 5,134.323 ms. The native pool swap is one of the few remaining places where the accepted Soroswap native path deliberately re-enters a generic contract call (`call_n_internal`) and then performs balance reads immediately afterward.

Source structure supports a narrower optimization than prior rejected generic SAC fast lanes. `call_native_soroswap_pool_swap` already knows the pool contract id, token addresses, reserves, output amounts, and recipient before calling the SAC. For the normal one-output swap, the output token's post-transfer pair balance is determined by the same transfer just executed, so reading it again is redundant for the K-check. A helper scoped to this native pool code path can preserve transfer events and storage writes while returning the updated pair balance to the caller, avoiding at least the output-side balance lookup and potentially the generic external-call dispatch overhead.

## Anti-Evidence

Several SAC micro-optimizations have failed because remaining SAC transfer work is semantically load-bearing: source authorization, diagnostic/event emission, TTL extension, and storage error behavior cannot simply be skipped. The PoC must prove it preserves the exact external SAC transfer event and authorization tree, or restrict itself to replacing only the balance read immediately after an unchanged transfer call. The impact also depends on the exact share of `SAC transfer` and direct balance-read work attributable to native pool swaps; if narrow Tracy spans show that the removable output-side read plus call-dispatch subset is below roughly 6-7 ms on the current 218 ms soroswap baseline, this should be downgraded to a fail record rather than pursued.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/transaction-ledger/summary.md` meta-pattern #22 and the condensed native-Soroswap-hook failures targeting absent `soroswap_pool_invoke_sac_transfer` / `soroswap_pool_invoke_sac_balance` paths
**Failed At**: reviewer

### Trace Summary

The actual soroswap apply-load path is still a normal Soroban `InvokeContract` transaction applied through `LedgerManagerImpl::applyThread`, `TransactionFrame::parallelApply`, `InvokeHostFunctionOpFrame::doParallelApply`, and the Rust p26 host. `ApplyLoad.cpp` deploys the router and pair as Wasm contracts and invokes `swap_exact_tokens_for_tokens` on the router; in the host, `call_contract_fn` dispatches `ContractExecutable::Wasm` by instantiating the VM and only dispatches `ContractExecutable::StellarAsset` through the native SAC built-in. There is no native Soroswap pool swap branch and no `soroswap_pool_invoke_sac_transfer` / `soroswap_pool_invoke_sac_balance` helper in the reviewed source, so the proposed fusion has no target call site to optimize.

### Code Paths Examined

- `ai-summary/fail/transaction-ledger/summary.md:161-164,221` — prior condensed failures already record that native Soroswap pool getter/swap helpers, native router trampolines, raw pair-instance helpers, and `soroswap_pool_invoke_sac_*` helpers are absent from the current p26 host source.
- `src/ledger/LedgerManagerImpl.cpp:2483-2510` — each Soroban cluster worker applies transactions by calling `txBundle.getTx()->parallelApply`.
- `src/transactions/TransactionFrame.cpp:2385-2430` — Soroban parallel apply asserts a single operation and delegates to `OperationFrame::parallelApply`.
- `src/transactions/OperationFrame.cpp:175-188` — operation parallel apply delegates directly to the operation's `doParallelApply`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584,1358-1377` — invoke-host-function parallel apply builds the helper and calls `rust_bridge::invoke_host_function`; this is the only host-entry path for the benchmark swap operation.
- `src/rust/src/soroban_invoke.rs:7-38` and `src/rust/src/soroban_proto_any.rs:310-340` — Rust dispatches to the protocol-specific host module and catches panics around the normal host invocation path.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-481` — p26 constructs enforcing storage, installs auth/module state, decodes the `HostFunction`, and calls `Host::invoke_function`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-785` — `call_contract_fn` has only `ContractExecutable::Wasm` and `ContractExecutable::StellarAsset` branches; the Wasm branch instantiates and invokes the VM, with no native Soroswap hook.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:923-1114` — `call_n_internal` eventually falls through to `call_contract_fn`; the referenced native swap lines instead contain generic call/error handling, not pool-swap balance accounting.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — SAC `transfer` remains the native built-in transfer path with auth, TTL extension, balance mutation, and transfer event emission.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:44-97,156-199` — the checked p26 source uses the generic SAC balance storage helpers; the claimed accepted direct contract-owner balance helper is not present in this worktree.
- `src/simulation/ApplyLoad.cpp:2896-3028,3427-3475` — the benchmark uploads/deploys router Wasm and constructs steady-state `swap_exact_tokens_for_tokens` calls with router/pair Wasm code and SAC balance footprint entries.

### Why It Failed

The mechanism depends on an already-existing native Soroswap pool swap implementation and native pool-local SAC transfer/balance helpers, but those symbols and dispatch paths are absent. In the reviewed code, pair and router contracts execute as ordinary Wasm, and the only native contract dispatch available from `call_contract_fn` is for `ContractExecutable::StellarAsset`. This is therefore a duplicate of the already-condensed native-Soroswap-hook failure family and cannot produce a Medium soroswap apply-time optimization without first adding a new native Soroswap precompile/trampoline, which is outside this hypothesis and previously rejected.

### Lesson Learned

Do not stack follow-on optimizations on "accepted" native Soroswap pool paths unless the current source tree contains the hook being optimized. Tracy time in SAC transfer, storage, or generic call zones must be attributed to actual reachable code; without a native pool swap call site, there is no deterministic output balance to reuse and no pool-local fusion point to modify.
