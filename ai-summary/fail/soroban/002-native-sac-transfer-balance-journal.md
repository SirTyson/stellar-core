# H002: Native SAC Transfer Balance Journal for Soroswap Pool Swap

**Date**: 2026-05-26
**Subsystem**: soroban
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by fusing SAC transfer side effects with the pair balance reads they immediately feed
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

The native Soroswap pool swap path should produce the same SAC transfer events, authorization checks, balance mutations, pair balance observations, pair reserve update, and pair/router events as the existing SAC-contract calls. After a native pool output transfer mutates a token balance for the pair, the pool should be able to observe the resulting pair balance without re-entering the generic SAC `transfer` frame and then performing a separate SAC `balance` read for the same `(token, pair)` owner.

## Mechanism

`call_native_soroswap_pool_swap` currently invokes SAC transfer through `soroswap_pool_invoke_sac_transfer`, then calls `soroswap_pool_invoke_sac_balance` for both token balances before checking the constant-product invariant. The balance fast path reads SAC balance storage directly, but the transfer itself still crosses `call_n_internal`, builds SAC frames, and emits events through the generic SAC contract path. A post-p26 typed native SAC transfer helper can perform the same trustline/contract-balance mutation and event emission, return the post-transfer pair balance for the affected token, and let the pool read only the unaffected side, removing one or two generic SAC frames plus redundant balance storage probes per swap.

## Trigger

Run the current soroswap apply-load Tracy trace from `ai-summary/CURRENT_STATE.md`:

`/mnt/nvme2/apply-load/9e61f0301cf2-20260525-143357/logs/9e61f0301cf2-20260525-143357-02-soroswap-tx-2000-t-8.tracy`

The apply-window intersection shows the SAC/pool residual is still hot:

- `SAC transfer` (`soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:212`) — 2.644782958 s inside `applyLedger` across 16,005 calls.
- `call` (`soroban-env-host/src/vm/dispatch.rs:304`) — 4.937728356 s inside `applyLedger` across 24,078 calls.
- `storage get` (`soroban-env-host/src/storage.rs:329`) — 718.936767 ms inside `applyLedger` across 328,819 calls.
- `map lookup` + `map lookup indexed` (`soroban-env-host/src/host/metered_map.rs:173,330`) — 1.273251865 s inside `applyLedger`.

Prototype the helper only for post-p26 native Soroswap pool frames and the existing direct-balance-readable SAC shape. Compare three non-Tracy soroswap runs against the current baseline and confirm diagnostic counts for SAC transfer frames and balance reads drop.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1274-1292` — native pool swap calls SAC transfer for output and then reads both pair balances.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1505-1521` — `soroswap_pool_invoke_sac_transfer` converts values and enters generic `call_n_internal`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1524-1540` — `soroswap_pool_invoke_sac_balance` already has a direct SAC balance read fast path but runs after transfer as a separate probe.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1543-1568` — direct SAC contract-balance reader proves the native path can recognize SAC storage and owner ids without instantiating the SAC VM.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:212-240` — SAC `transfer` semantics and event/auth ordering to preserve in the typed helper.

## Evidence

The current source already added direct SAC balance reads for the native Soroswap pair, so the remaining mismatch is that transfer mutation still goes through the generic SAC contract frame and the pool then re-reads balances as independent operations. On the headline path each swap emits one output transfer from pair to user, and the pair balance for the output token after that transfer is exactly the value needed for the invariant check. Returning that balance from a typed transfer journal removes repeated storage lookup/conversion work and a generic host-call frame on a path whose aggregate Tracy time is large enough, when combined with avoided balance probes, to plausibly clear the 3% Medium floor.

## Anti-Evidence

This must not become a broad native-SAC replacement without a complete metering and semantic specification. SAC transfer handles account-vs-contract balances, authorization, trustline/account storage, event construction, and failure codes; the helper is only viable if it reuses existing SAC helpers or mirrors them exactly under a post-p26 protocol gate. If preserving SAC event/auth/metering requires calling most of the existing SAC frame anyway, or if only one small balance probe is eliminated after normalization by 8 clusters, the gain will be below Medium.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/soroban/summary.md` row `001-single-read-sac-transfer-balances.md + 001-sac-transfer-balance-read-dedup.md + 001-native-pool-sac-transfer-return-balance.md`
**Failed At**: reviewer

### Trace Summary

The current p26 native pool swap path still performs output SAC transfers through `soroswap_pool_invoke_sac_transfer`, then separately reads both pool token balances before computing input amounts and the K invariant. The balance side has an existing direct SAC contract-balance fast path for contract owners, while the transfer side goes through `call_n_internal` and the generic SAC `transfer` semantics: nonnegative check, auth, instance/code TTL extension, spend/receive balance mutation, and event emission. This is the same optimization surface as the prior returned-balance variant: eliminate a redundant post-transfer balance probe by returning or journaling the post-transfer balance from the SAC transfer path. That prior variant already reached final review and was rejected because the passing PoC regressed soroswap by 2.43% in all three non-Tracy benchmark runs.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1234-1252` — native pool swap invokes SAC output transfers and then reads `balance_0` and `balance_1`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1465-1482` — `soroswap_pool_invoke_sac_transfer` converts the amount/token and enters generic `call_n_internal("transfer")`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1484-1528` — `soroswap_pool_invoke_sac_balance` first tries the direct SAC contract-balance fast path and only falls back to `call_n_internal("balance")`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — SAC `transfer` requires auth, TTL extension, balance spend/receive, and transfer/mint/burn event logic.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:565-817` — transfer balance mutation covers native account and credit trustline cases, with storage reads/writes and balance-range checks.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:47-64` — transfer event selection may become transfer, mint, or burn depending on issuer endpoints.

### Why It Failed

This is not novel. The Soroban fail summary already records `001-native-pool-sac-transfer-return-balance.md` as the returned-balance variant of the single-read SAC transfer balance optimization and states that it shares the final-review blocker from the earlier PoC: removing the structurally redundant storage probe regressed soroswap by 2.43% across all three authoritative non-Tracy runs. The same summary also records `001-native-pair-direct-sac-transfer.md` as below the objective's Medium threshold after correct 8-way parallel-apply normalization and mandatory auth/frame/TTL/event work.

### Lesson Learned

Do not resubmit SAC transfer/balance-dedup variants unless there is new non-Tracy benchmark evidence that overcomes the prior returned-balance regression; aggregate `SAC transfer`, `call`, and `storage get` Tracy totals are insufficient once mandatory SAC semantics and NUM_CLUSTERS normalization are applied.
