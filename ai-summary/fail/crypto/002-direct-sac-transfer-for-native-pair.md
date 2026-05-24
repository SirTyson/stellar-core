# H002: Direct SAC transfer fast path inside native Soroswap pair swap

**Date**: 2026-05-24
**Subsystem**: crypto-adjacent rust/Soroban apply path
**Severity**: Medium
**Impact**: remove generic SAC transfer subcall overhead from native pair swap
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When the next-protocol native Soroswap pair `swap` fast path transfers the output token from the pair contract to the benchmark user account, the host should update the same SAC balance/trustline entries and emit the same SAC transfer event as `StellarAssetContract::transfer`. For any non-StellarAsset token instance, non-benchmark address shape, missing footprint entry, authorization mismatch, issuer/mint/burn edge case, or storage layout mismatch, the code should fall back to the existing `call_n_internal(... "transfer" ...)` path.

## Mechanism

`call_native_soroswap_pool_swap` already avoids the two read-only SAC `balance` subframes by reading pair contract SAC balances directly, but it still performs each output transfer by building a `transfer` symbol and calling `call_n_internal` into the SAC contract. That generic path re-enters contract dispatch, creates a StellarAsset frame, checks generic auth, extends the SAC instance TTL, performs generic balance read/write helpers, reads asset metadata for event classification/name, and emits the event. A narrow helper modeled after the accepted direct balance reader can check that the token instance executable is `StellarAsset`, require auth for the pair contract sender, directly debit the pair's persistent SAC `Balance[pair]`, credit the user's trustline for the known credit asset, and emit the ordinary transfer event, avoiding the generic subcall/frame path for the hot soroswap case.

## Trigger

Run the current soroswap apply-load scenario. `ApplyLoad::generateSoroswapSwaps` builds each swap with a two-token path and `to` equal to the source account (`src/simulation/ApplyLoad.cpp:3405-3439`), and includes `Balance[pair]` for both SAC tokens plus user trustlines in the footprint (`src/simulation/ApplyLoad.cpp:3447-3475`). The native pair swap then calls `soroswap_pool_invoke_sac_transfer` for the nonzero output token at `host/frame.rs:1158-1173`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1076-1176` — native pair swap performs output SAC transfers, then reads balances directly.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1330-1347` — `soroswap_pool_invoke_sac_transfer` currently constructs `transfer` and calls `call_n_internal`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1368-1393` — accepted direct SAC balance reader showing the strict StellarAsset-instance guard and direct typed-balance access pattern.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — generic SAC `transfer` path still executed by the native pair swap.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:150-199,235-346,357-428,431-440,773-817` — storage helpers that the direct transfer path can either reuse after making an internal helper public, or mirror under stricter benchmark-only guards.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:47-113` — event semantics that must be preserved.

## Evidence

Current trace: `/mnt/nvme2/apply-load/62ee1ffb5d05-20260523-010230/logs/62ee1ffb5d05-20260523-010230-02-soroswap-tx-2000-t-8.tracy`.

- `SAC transfer` at `soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:212` total: 2,485,970,004 ns, self: 638,599,625 ns, 15,747 calls.
- Timestamp filtering against `applyLedger` found 15,665 of 15,747 `SAC transfer` events inside apply, totaling 2,477,084,982 ns.
- With `NUM_CLUSTERS=8`, this is roughly 310 ms wall-clock equivalent, about 6.9% of the 4,475,605,676 ns traced `applyLedger` envelope. A direct fast path only needs to remove about half of the generic SAC transfer envelope to clear the 3% Medium floor.
- The benchmark footprint and auth shape are simple and stable: one source-account root auth entry with a single `token_in.transfer(user, pair, amount)` sub-invocation for the input side, and the pair contract performs the output transfer from itself to the user. The existing direct balance success already proves that pair-contract SAC balance storage can be read safely under a strict StellarAsset executable guard.

## Anti-Evidence

The generic SAC transfer path handles many cases that the fast path must not silently approximate: account creation for native XLM, issuer mint/burn event classification, authorization-required assets, clawback flags, muxed-address event data, and arbitrary contract recipients. The PoC should therefore start with the benchmark's credit-asset, pair-contract-to-account shape and return `None`/fallback for every other shape; otherwise correctness risk outweighs the performance win. Event construction may still require some host-object allocation, so the benchmark must verify that the removable subcall/frame/storage overhead is at least half of the measured SAC transfer envelope.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — no prior fail/success record for a native-pair output SAC transfer fast path; H001 discusses a native router and only notes that SAC transfers remain necessary.
**Failed At**: reviewer

### Trace Summary

The native Soroswap pair swap does call `soroswap_pool_invoke_sac_transfer` for the nonzero output amount, and that helper dispatches through `call_n_internal` into the built-in Stellar Asset Contract `transfer` implementation. The existing direct balance reader proves the SAC executable guard and explicit-token balance-key pattern are feasible, and a narrow output-transfer helper could remove the subcall frame plus several generic redundant reads. However, the cited `SAC transfer` envelope covers both router input transfers and pair output transfers, while this hypothesis only targets the pair output side, and most of each output transfer's storage mutation and event work must still remain.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1076-1176` — native pair swap validates reserves, loads token addresses, calls `soroswap_pool_invoke_sac_transfer` once for the nonzero output token, then reads both pair balances directly.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1330-1347` — output transfer builds the `transfer` symbol and calls `call_n_internal` with `[from, to, amount]`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1531-1645` and `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:434-550` — `call_n_internal` performs reentry checks, diagnostics, and `with_frame`; the SAC frame push/pop snapshots auth, storage, and events for rollback.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:782-837` — `ContractExecutable::StellarAsset` dispatch creates `Frame::StellarAssetContract` and invokes `StellarAssetContract.call`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — generic `transfer` checks amount, requires auth, extends the SAC instance TTL, spends the sender balance, receives the destination balance, and emits the transfer/mint/burn event.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:303-428` and `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:773-817` — output transfer must still debit `Balance[pair]` and credit the user's trustline with limit/authorization checks.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:47-113` — event emission must still classify issuer/mint/burn vs ordinary transfer and include the SAC metadata name in topics.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:829-849`, `src/rust/soroban/p26/soroban-env-host/src/auth.rs:875-930`, and `src/rust/soroban/p26/soroban-env-host/src/host.rs:3629-3657` — generic SAC auth succeeds for the output side because the SAC frame's direct invoker is the pair contract; a frame-less fast path would need an explicit proof/emulation of that direct-invoker relationship rather than a normal `require_auth` in the pair frame.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1368-1393` and `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:136-145` — the accepted direct balance reader peeks at the SAC instance executable and extends TTL without cloning the full instance.
- `src/simulation/ApplyLoad.cpp:3382-3505` — each benchmark swap has a router root call, a `token_in.transfer(user, pair, amount)` authorized sub-invocation, and then the native pair performs the output transfer from pair to user; therefore the total `SAC transfer` trace contains both input and output transfers.

### Why It Failed

The optimization target is smaller than the severity claim. The cited 2.477 s in-apply `SAC transfer` total normalizes to about 310 ms wall-clock, but the native-pair helper can only affect the output transfer from pair to user; the router's input `token_in.transfer(user, pair, amount)` remains a generic SAC transfer. With one input and one output transfer per benchmark swap, even eliminating the entire output transfer envelope would cap the savings around half of 6.9%, roughly 3.45% of `applyLedger`. A correct direct path cannot eliminate the whole output envelope: it must still update `Balance[pair]`, update the user's trustline with authorization/limit checks, extend relevant TTLs, preserve event semantics including SAC metadata, and account for the pair-as-direct-invoker authorization behavior. The realistic removable portion is the subcall/frame dispatch plus redundant generic reads, which is below the objective's 3% Medium threshold.

### Lesson Learned

For Soroswap SAC-transfer optimizations, separate router input transfers from native-pair output transfers before projecting impact. A direct pair-output helper may be technically feasible, but its severity must be sized against only the output half of `SAC transfer` and only the work that can be removed while preserving ledger mutations, TTL extensions, auth semantics, and events.
