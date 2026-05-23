# H001: Direct typed SAC `transfer` fast path inside native pair swap

**Date**: 2026-05-23
**Subsystem**: transaction-ledger / soroban-env (Stellar Asset Contract host bridge)
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by removing the two `call_n_internal` SAC `transfer` subframes that the accepted native pair `swap` path still issues per swap, mirroring the just-accepted direct SAC `balance` fast path
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

When the accepted native Soroswap pair `swap` path moves the two output token amounts, it should mutate the persistent `Balance(owner_contract)` contract-data entries directly for confirmed Stellar Asset Contract tokens whose `from` and `to` addresses are both contract addresses (the pair contract for `from`, the destination contract for `to`). The efficient path should preserve every protocol-visible effect of the existing `Token::transfer` SAC entry point: enforce non-negative amount, charge equivalent metered work, extend the SAC instance and code TTL with the same thresholds, decrement the pair's `Balance` entry, credit (or create) the recipient's `Balance` entry, write the same `Token::transfer` event (with the SAC's `(from, to, amount)` payload), and produce identical authorization-tree observable behavior. For any non-SAC executable, non-contract-address arguments, mixed-token shape, or released protocols, it should fall back to the existing `soroswap_pool_invoke_sac_transfer` path unchanged.

## Mechanism

`soroswap_pool_invoke_sac_transfer` (p26 `soroban-env-host/src/host/frame.rs:1330-1347`) still routes every native-pair output transfer through generic `Host::call_n_internal`. Inside `Host::call_contract_fn` (`frame.rs:783-839`), each call does (i) `retrieve_contract_instance_from_storage` which performs a metered clone of the entire `ScContractInstance` (including its `instance-storage` `ScMap`) just to dispatch on the executable, (ii) `Vec::charge_bulk_init_cpy` plus a `to_vec()` over the argument slice, (iii) `with_frame(Frame::Token, ...)` pushing a SAC contract frame, (iv) `push auth frame` + `snapshot auth` so `require_auth_for_args` can later succeed, and (v) generic `Val`-shaped argument plumbing for amounts that are already typed `i128` and addresses that are already known `AddressObject`s.

For a confirmed-SAC, contract-to-contract token transfer with the pair as the `from` address, a direct typed entry point can mirror SAC `transfer` (`stellar_asset_contract/contract.rs:212`) by calling its internal `spend_balance` / `receive_balance` helpers and `events::transfer` with the typed arguments already in hand, using the same peek-only executable check the accepted SAC balance fast path uses (`data_helper.rs` `contract_instance_executable_is_stellar_asset`). That removes the per-call `ScContractInstance` clone and `ScMap` materialization, the `Frame::Token`+auth-frame push/pop, the argument vector copy, two `ScVal↔Val` conversions, and the generic call dispatch — exactly the layers the accepted SAC `balance` fast path removed for read-only balance subframes (success `001-direct-sac-balance-for-native-pair`, soroswap median improved 5.18%).

The Tracy trace at `/mnt/nvme2/apply-load/62ee1ffb5d05-20260523-010230/logs/62ee1ffb5d05-20260523-010230-02-soroswap-tx-2000-t-8.tracy` records the relevant aggregate worker self-time inside `applyLedger` windows: `SAC transfer` 638.6 ms self / 2,486.0 ms inclusive over 15,747 calls (≈ 2 calls per native pair `swap`), `push context` 459.5 ms self over 47,427 calls, `push auth frame` 341.3 ms self over 47,428 calls, `call` 1,216.4 ms self / 5,153.0 ms inclusive over 23,696 calls, plus `ScVal to Val` 493.9 ms and `Val to ScVal` 249.3 ms self that include the per-transfer argument-conversion work. The removable subset attributable to the two per-swap SAC transfer subframes — `retrieve_contract_instance_from_storage` clone, frame/auth push+pop, `to_vec()` + arg conversion, dispatch — is structurally the same removable subset the accepted SAC balance fast path eliminated for two balance subframes per swap, and that change delivered 11.9 ms/ledger ≈ 5.18% on the soroswap median. Applying the same fast-path pattern to the two output transfers per swap therefore plausibly clears the 3% Medium floor on top of the current 218 ms baseline.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) from the baseline recorded in `ai-summary/CURRENT_STATE.md` (outer commit `04c9035453c68519e19c52006255f4ca0f40ca42`, p26 SHA `fbbea0d9cb33e94fbab331d3d4bf8e69f088f9d4`). Every accepted swap executes the native pair `swap` path at `frame.rs:1013` and calls `soroswap_pool_invoke_sac_transfer` twice (lines 1159 and 1167) with `from = pair_address` (a `ScAddress::Contract`), `to = recipient` (`ScAddress::Contract` for the benchmark's contract-to-contract token movement), and amounts already typed as `i128`, exercising the proposed fast path on every successful swap. Non-SAC executables, non-contract `to` addresses, released-protocol ledgers, or any input that fails the same shape gates as the accepted balance fast path fall back to the existing `call_n_internal` path unchanged.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1159-1173` — native pair `swap` issues the two SAC `transfer` subframes via `soroswap_pool_invoke_sac_transfer`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1330-1347` — `soroswap_pool_invoke_sac_transfer` constructs a generic `call_n_internal` call that pays full `retrieve_contract_instance_from_storage`, frame push, auth push, and dispatch overhead.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:783-820` — `call_contract_fn` clones the full `ScContractInstance` and pushes a SAC frame even for confirmed StellarAsset executables; the peek-only executable check already used by the balance fast path can also gate the transfer fast path.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs` — existing `contract_instance_executable_is_stellar_asset` helper added by `001-direct-sac-balance-for-native-pair`; reuse for the transfer fast path's executable peek.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:212` — SAC `transfer` body; the direct typed helper mirrors its `spend_balance` + `receive_balance` + `events::transfer` sequence with identical TTL and event behavior.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs` — already exposes typed direct contract-owner SAC helpers for the balance side; extend with `transfer_contract_balance_to_contract` mirroring the same TTL and missing-balance semantics.

## Evidence

The accepted SUCCESS `ai-summary/success/soroban-env/001-direct-sac-balance-for-native-pair.md` records a **5.18% soroswap median improvement (230.225 ms → 218.310 ms)** for eliminating the *read-only* SAC balance subframes on this exact native pair `swap` path. The proposed transfer fast path is the direct structural parallel: it removes the same `retrieve_contract_instance_from_storage` metered clone, the same `with_frame(Frame::Token, ...)` push/pop, the same auth-frame push/snapshot, the same argument vector materialization, and the same `ScVal↔Val` conversions, but for the *output* SAC transfer subframes that immediately precede the now-fast balance reads in `try_call_native_soroswap_pool_swap`. The Tracy aggregate `SAC transfer` self-time (638 ms across 15,747 calls in 71 dense applyLedger windows) is comparable in magnitude to the pre-fix balance subframe aggregate that the previous accepted change addressed, and the per-call inclusive overhead of 157 µs versus 40 µs self-time leaves a structurally similar removable subset.

The reusable helpers required for the typed transfer path already exist in the active baseline: `contract_instance_executable_is_stellar_asset` (added by the balance fast path) gives the same peek-only executable check; `spend_balance` and `receive_balance` are SAC-internal typed helpers; `events::transfer` is the existing typed event emitter. No new metering model, no new protocol-visible state, and no consensus-affecting change is required beyond the same next-protocol gating used by the accepted native pair swap and balance fast path.

## Anti-Evidence

The accepted balance fast path delivered 5.18% on top of removing only two read-only subframes; transfers are heavier (mutate state, allocate authorization, emit events) so a larger fraction of each transfer's 157 µs inclusive time is mandatory body work rather than removable dispatch overhead. The realistic critical-path saving may be smaller than the balance fast path's 11.9 ms/ledger, and could land below the 3% Medium floor if frame/auth/clone overhead is a smaller share of `SAC transfer` time than it was for `SAC balance` (which had a much higher overhead-to-body ratio because the body was a single map read).

Authorization correctness is also a stricter constraint than for balance reads: the pair contract's authorization context must be preserved exactly (the pair is the `from` address and must transitively authorize the transfer the same way it does today when SAC `transfer` calls `from.require_auth_for_args(...)`). A direct typed path must reproduce the exact authorization-tree consumption order, including any sub-invocation matching against authorized contract function invocations. Reviewers should verify the existing native pair swap's authorization context (the pair's source-account authorization chain established by the router) is the same context the typed helper would consume from, before promoting beyond reviewer.

Finally, fee/budget metering must remain protocol-equivalent under the gating protocol version: the typed path must charge the same total `cpu_insns`, `mem_bytes`, and refundable bytes as the `call_n_internal` path so that fee accounting and budget-exceeded behavior are unchanged. The accepted SAC balance fast path solved the analogous problem by mirroring SAC `balance`'s storage side effects directly under the same protocol gate; the transfer fast path needs to do the same for SAC `transfer`'s state and event side effects.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/transaction-ledger/002-native-pool-swap-sac-balance-fusion.md` and the native-Soroswap-hook absence recorded in `ai-summary/fail/transaction-ledger/summary.md`
**Failed At**: reviewer

### Trace Summary

The actual soroswap apply-load path is a normal Soroban `InvokeContract` transaction: C++ parallel apply reaches `InvokeHostFunctionOpFrame::doParallelApply`, the Rust p26 host builds enforcing storage, and `HostFunction::InvokeContract` enters `Host::call_n_internal`. From there `call_contract_fn` has only two production branches: instantiate/run `ContractExecutable::Wasm`, or dispatch `ContractExecutable::StellarAsset` through the SAC built-in. The referenced native pair `swap`, `soroswap_pool_invoke_sac_transfer`, and `contract_instance_executable_is_stellar_asset` helper do not exist in the reviewed p26 source, so there is no native swap-local transfer call site to optimize.

### Code Paths Examined

- `ai-summary/fail/transaction-ledger/002-native-pool-swap-sac-balance-fusion.md:44-77` — prior review already rejected a substantially equivalent native pool SAC transfer/balance optimization because `soroswap_pool_invoke_sac_transfer` and native Soroswap pool swap helpers are absent.
- `ai-summary/fail/transaction-ledger/summary.md:161-164` — condensed failures record absent native Soroswap pool getter/swap helpers and related raw instance/cache follow-ons.
- `src/ledger/LedgerManagerImpl.cpp:2483-2510` — Soroban worker apply invokes `txBundle.getTx()->parallelApply` for each transaction in a cluster.
- `src/transactions/TransactionFrame.cpp:2385-2430` — `TransactionFrame::parallelApply` asserts a single Soroban operation and delegates to `op->parallelApply`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584,1358-1377` — the invoke-host-function parallel helper calls `rust_bridge::invoke_host_function`; this is the benchmark's host-entry path.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-481` — p26 constructs enforcing storage, installs auth/module/ledger state, decodes the host function, and calls `Host::invoke_function`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:923-929,1113-1148` — `call_n_internal` falls through to `call_contract_fn`; `HostFunction::InvokeContract` converts arguments and invokes this generic path.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:749-785` — `call_contract_fn` retrieves and clones the contract instance, copies args, then dispatches only to Wasm VM execution or the built-in Stellar Asset Contract; no Soroswap-native branch exists.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-226` — SAC `transfer` still performs the real built-in semantics: nonnegative check, `from.require_auth`, instance/code TTL extension, `spend_balance`, `receive_balance`, and transfer event emission.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:73-97,100-145,156-230` — SAC balance mutation helpers exist, but they are reached from normal SAC dispatch, not from a native Soroswap pair swap.
- `src/simulation/ApplyLoad.cpp:3427-3475` — the generated benchmark operation invokes router Wasm function `swap_exact_tokens_for_tokens` and includes router/pair Wasm footprints plus SAC balance entries; it does not invoke a native pair-swap entry point.

### Why It Failed

The proposed optimization is built on a nonexistent prerequisite. In the reviewed source tree there is no accepted native Soroswap pair `swap`, no `soroswap_pool_invoke_sac_transfer`, no native pair output-transfer lines at the cited ranges, and no `contract_instance_executable_is_stellar_asset` fast-path gate. The only viable SAC transfer path is the normal built-in SAC call reached through generic contract invocation, so replacing a native swap-local transfer subframe would require first adding a new native Soroswap precompile/trampoline rather than optimizing an existing hot path. This is the same failure mode as the prior native pool SAC transfer/balance fusion review.

### Lesson Learned

Do not stack SAC transfer fast paths on "accepted" native Soroswap pair hooks unless the hook is present in the source tree being reviewed. Broad Tracy totals for SAC transfer, call frames, auth frames, and conversion work are not enough to establish a native swap-local optimization target; the actual reachable path must contain the specific call site being replaced.
