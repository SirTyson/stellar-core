# H001: Native Pool SAC Transfer Should Return Post-Transfer Pair Balance

**Date**: 2026-05-24
**Subsystem**: soroban
**Severity**: Medium
**Impact**: soroswap apply-time reduction by removing one generic SAC subframe and one redundant post-transfer balance read from the native pool swap path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For a protocol-27 allowlisted Soroswap pool `swap`, the native path should preserve the exact ordered effects of the Wasm pair contract while avoiding generic host work that is only needed for arbitrary contracts. After transferring the output token from the pair contract to the recipient, the native path should know the pair contract's new SAC balance for that output token and should use it directly in the K-invariant calculation, while still reading the non-output token balance from storage to observe the router's earlier input transfer.

## Mechanism

`call_native_soroswap_pool_swap` currently invokes `soroswap_pool_invoke_sac_transfer` for the output token and then calls `soroswap_pool_invoke_sac_balance` for both token balances. For the output side, this repeats the same pair-balance ledger read that the SAC transfer already performed while decrementing the pair's balance, and it pays the generic `Frame::StellarAssetContract` dispatch/argument path before returning to native code. A protocol-gated helper that performs the SAC transfer with typed balance helpers and returns the pair's post-transfer `i128` balance would remove the output-side balance subcall and a slice of the `SAC transfer` zone without changing observable ledger state, event order, or auth semantics.

## Trigger

Run the current protocol-27 soroswap apply-load benchmark. Each successful router-driven native pool swap reaches `Host::call_native_soroswap_pool_swap`, performs one output-token SAC `transfer` for the typical one-sided swap, then reads both SAC balances before updating reserves. The optimized path would trigger only when the pool Wasm hash, `swap` symbol, argument shape, token addresses, and instance-storage schema all match the existing native pool guards.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1178-1253` — native pool `swap` performs SAC output transfer(s), then re-reads both token balances.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1465-1501` — `soroswap_pool_invoke_sac_transfer` uses generic `call_n_internal`, while `soroswap_pool_invoke_sac_balance` already has a direct contract-owner balance fast path.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:303-428` — typed SAC balance mutation helpers that can be reused under the same SAC frame/auth/event constraints.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — reference SAC `transfer` ordering: amount check, muxed-address extraction, auth, instance/code TTL extension, spend, receive, transfer event.

## Evidence

The current state already accepted native pool swap and raw instance-storage handling, so the pool side has a real native frame and exact fixed-schema guards in source. The current diagnostic exports show the residual SAC boundary remains material: `/mnt/nvme2/tmp/tracy-overlap.43Iol6/SAC_transfer.csv` intersects the apply windows with about 1.48s aggregate `SAC transfer` duration, and `/mnt/nvme2/tmp/tracy-extra-storage_get.csv` shows about 439ms of `storage get` inside the same apply-window export. Source reading confirms the output token's pair balance is read during SAC `spend_balance` and then read again by `soroswap_pool_invoke_sac_balance`; a transfer helper that returns the updated source/pair balance would remove the second read for one side of every one-sided swap.

This is narrower than a full native SAC pipeline: it does not bypass router execution, does not attempt to fuse both token contracts, and does not remove SAC transfer events or authorization. It only plumbs the post-transfer balance that the transfer already computes back to the native pool K-invariant code.

## Anti-Evidence

Several broader SAC-transfer optimizations have failed after normalization, especially generic direct SAC transfer and single-read SAC transfer variants. This hypothesis must therefore prove that the combined "transfer plus returned output balance" slice clears the 3% floor on the current post-raw-instance baseline, not just that a duplicate read exists. The implementation must preserve the SAC frame context for `require_auth`, diagnostic/error behavior, TTL extension, `transfer_maybe_with_issuer` event ordering, and next-protocol metering; dropping any of those would make the speedup invalid.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/soroban/summary.md` entry `001-single-read-sac-transfer-balances.md + 001-sac-transfer-balance-read-dedup.md`; also overlaps `001-native-pair-direct-sac-transfer.md`
**Failed At**: reviewer

### Trace Summary

The native Soroswap pool path is real: `call_contract_fn` recognizes the allowlisted pool Wasm and pushes `Frame::NativeContract`, then `call_native_soroswap_pool_swap` performs SAC transfer subcalls followed by two balance reads for the K-invariant. The claimed redundant output-side read is also real: SAC `transfer` spends the pair contract balance via `spend_balance`, while `soroswap_pool_invoke_sac_balance` later reads the same pair balance again through the direct SAC contract-owner fast path. However, the fail summary already records the substantially equivalent single-read SAC transfer/balance dedup investigation, whose PoC passed tests but regressed soroswap by 2.43% across all three non-Tracy benchmark runs; the direct native SAC transfer/frame-dispatch component was also previously rejected below the Medium threshold after normalization and semantic constraints.

### Code Paths Examined

- `ai-summary/fail/soroban/summary.md:110` — Records `001-single-read-sac-transfer-balances.md + 001-sac-transfer-balance-read-dedup.md`, rejected at final review because the optimization removed a real duplicate read but regressed soroswap 2.43% across all three authoritative non-Tracy runs.
- `ai-summary/fail/soroban/summary.md:165` — Records `001-native-pair-direct-sac-transfer.md`, rejecting direct native SAC transfer/frame-dispatch cleanup as ~2.0% normalized and below the 3% objective threshold after preserving auth-frame, TTL, event, and mandatory SAC semantics.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:782-833` — `call_contract_fn` loads the contract instance, matches native Soroswap pool calls only for the allowlisted Wasm, and otherwise dispatches SAC calls through `Frame::StellarAssetContract`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1178-1252` — Native `swap` validates amounts/reserves/tokens, performs `soroswap_pool_invoke_sac_transfer` for nonzero outputs, then reads both token balances before computing inputs and the K-invariant.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1465-1501` — The transfer helper calls `call_n_internal("transfer")`; the balance helper first tries `soroswap_pool_read_sac_contract_balance` and falls back to generic SAC `balance`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1503-1528` and `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:136-160` — The direct balance fast path verifies the token instance is `StellarAsset`, extends instance TTL, and reads the contract-owner balance.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — Reference SAC `transfer` ordering is amount check, destination extraction, `from.require_auth`, instance/code TTL extension, `spend_balance`, `receive_balance`, and transfer event emission.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:150-199,213-224,303-428` — Contract-owner balance reads, public `balance`, `receive_balance`, and `spend_balance` confirm the duplicate read surface and the typed mutation helpers the hypothesis would reuse.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:436-630` — `with_frame` shows why SAC-frame semantics are not free to remove: frame push snapshots storage/events/auth, frame exit persists instance storage, and errors roll back the frame state.

### Why It Failed

This is not novel. The core optimization surface — making SAC transfer/balance handling single-read by reusing the balance already observed during transfer — has already been investigated and rejected at final review after a passing PoC regressed the objective benchmark. The current hypothesis narrows the scope to native pool output-side balance plumbing and combines it with a slice of direct SAC transfer/frame cleanup, but both components are already represented in the retained fail summary: the balance-dedup component regressed when implemented, and the direct-transfer/frame-dispatch component was below the objective's Medium threshold once mandatory SAC semantics and 8-way parallel apply normalization were accounted for.

### Lesson Learned

For the post-raw-instance native pool baseline, a real duplicate SAC balance read is not sufficient evidence for a new Medium finding. New SAC-transfer hypotheses must either point to a genuinely untried measured surface beyond the retained single-read transfer/balance PoC or provide new benchmark evidence overcoming the prior 2.43% regression; rephrasing the same returned-balance mechanism as native pool plumbing is a duplicate.
