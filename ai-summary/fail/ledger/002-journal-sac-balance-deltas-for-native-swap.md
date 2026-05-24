# H002: Journal SAC balance deltas to avoid post-swap balance storage reads

**Date**: 2026-05-24
**Subsystem**: ledger / Soroban native Soroswap apply path
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by eliminating residual SAC balance reads after native pair swap transfers
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For the native Soroswap pair `swap` fast path, the pair should compute the same `balance_0`, `balance_1`, `amount_0_in`, `amount_1_in`, K-invariant result, reserve writes, and event output as the Wasm contract. When all balance changes to the pair address during the current host invocation are known SAC transfers, the native path should be able to derive final pair balances from prior reserves plus a deterministic per-host SAC balance delta journal, falling back to direct storage reads when the journal is incomplete.

## Mechanism

The accepted direct SAC balance optimization still calls `soroswap_pool_invoke_sac_balance` twice after output transfers in `call_native_soroswap_pool_swap`. Those calls avoid read-only SAC subframes, but they still perform token-id conversion, SAC instance executable checks, TTL extension, balance key construction, and storage reads for both tokens. A transaction-local journal maintained by SAC transfer writes can record `(token_id, owner_contract_id) -> delta` for the pair address; native swap can then compute the output-side balance as `reserve_out - amount_out` and the input-side balance as `reserve_in + journaled_input_delta` (including any earlier router transfer into the pair), while falling back to `soroswap_pool_invoke_sac_balance` if the journal lacks either token.

## Trigger

Run a successful Soroswap router swap on the current native pair fast path. The router transfers input SAC balance into the pair, then calls pair `swap`; the native pair may transfer one output token to `to`, then lines 1175-1176 read both token balances from storage solely to infer input amounts and verify the K invariant.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1158-1176` — native pair swap performs output SAC transfer(s) and then reads both token balances.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1178-1255` — input amounts and K invariant are derived from the post-transfer balance reads.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1330-1347` — output transfer re-enters SAC through `call_n_internal`, where a balance-delta journal could be updated by SAC write helpers.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1349-1392` — direct SAC balance read fallback checks the SAC executable and loads the typed balance entry.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/` — SAC transfer/balance helpers that update and read contract balance storage.

## Evidence

The current diagnostic trace's `SAC transfer` zone is an in-apply hotspot: timeline filtering found 15,665 in-apply events totaling 2,477.085 ms in `soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:212`. The residual direct-balance path is not separately zoned, but it is structurally visible in `frame.rs:1175-1176` and contributes to the in-apply `storage get` total of 672.085 ms and `extend_current_contract_instance_and_code_ttl` total of 455.825 ms. The previous accepted direct-balance change improved soroswap median by 5.18% by removing the heavier read-only SAC balance subframes; this hypothesis targets the remaining reason those two balance queries exist at all.

This is not the prior rejected `skip-output-side-sac-balance-read` hypothesis as written: that review failed because the native pair swap/direct balance code did not exist in the reviewed checkout. The current source now has `try_call_native_soroswap_pool_swap`, `soroswap_pool_invoke_sac_balance`, and `soroswap_pool_read_sac_contract_balance`. This version also covers both token balances through a conservative SAC balance-delta journal rather than deriving only the output side and blindly reading the input side.

## Anti-Evidence

The journal must be exactly scoped to a single host invocation and must respect rollback through host frames; otherwise failed internal calls could leak deltas into later checks. It also cannot assume every asset contract is SAC or that every balance-changing path is a simple transfer into/out of the pair. The optimization is only viable if it falls back to the existing direct balance reads whenever the pair balance may have changed through an unjournaled path, and if the journal maintenance in SAC transfer is cheaper than the two balance reads it removes.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS
**Failed At**: reviewer

### Trace Summary

The native Soroswap swap path is real in this checkout: `closeLedger` reaches parallel Soroban apply, Rust constructs a per-transaction `Host`, router/pair/SAC calls enter `call_contract_fn`, and the native pair `swap` reads both SAC pair balances after any output transfer. The two residual direct reads avoid full SAC `balance` frames but still do a SAC-executable storage lookup, instance TTL extension, balance key construction, balance `storage get`, balance-value decode, and balance TTL extension. SAC transfer writes already read and write the same contract-owner balance entries and extend balance TTLs, so a correctly rollback-scoped journal would be mechanically possible if attached to the SAC balance write path rather than only to `transfer`. However, the removable work is only two small indexed storage lookups/TTL checks per native swap and falls well below this objective's Medium threshold after normalizing aggregate worker time by benchmark samples and 8-way parallel apply.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2785-3030` — `applyTransactions` dispatches parallel Soroban phases from `closeLedger` through `applyParallelPhase` and `applySorobanStages`.
- `src/ledger/LedgerManagerImpl.cpp:2483-2511` — each cluster worker applies transactions sequentially in `applyThread`, so Rust host spans are aggregate worker time and must be normalized by parallel cluster count for top-line apply-time estimates.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1378` — parallel Soroban operation apply bridges each transaction into the Rust host via `InvokeHostFunctionParallelApplyHelper`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:520-593` — one enforcing-storage `Host` is built per invoke-host-function transaction, executes `host.invoke_function`, then extracts storage changes.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:783-838` — `call_contract_fn` loads the contract instance and dispatches to native Soroswap getter/swap fast paths or SAC/VM frames.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1013-1073` — `try_call_native_soroswap_pool_swap` protocol-gates the native pair fast path, validates the pair instance shape, clones the instance into a native frame, and runs the native swap body.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1076-1266` — native swap extends pair instance/code TTL, reads reserves and token addresses, performs output SAC transfers, reads both pair token balances, derives inputs/K-invariant, and writes reserve instance storage.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1330-1392` — output transfer re-enters SAC via `call_n_internal`; direct balance fallback checks the token contract is SAC, extends SAC instance TTL, and reads the pair balance.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:180-200` — direct contract-owner balance read builds the SAC balance key, performs `read_contract_balance`, extends balance TTL, and returns the amount or zero.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:234-299` — contract balance writes read the current entry, update or create the `ContractData` balance entry, put it into storage, and extend its TTL; this is the only safe place to compute a complete delta for all SAC balance-changing functions.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` and `252-352` — `transfer`, `transfer_from`, `burn`, `burn_from`, `clawback`, and `mint` all mutate balances through the common spend/receive/write helpers, so a transfer-only journal would be incomplete.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:434-595` — `with_frame` rolls back storage/context state on errors; any host-level balance journal would need matching rollback semantics or delayed commit to avoid leaking failed subcall deltas.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:324-389` and `531-688` — the residual read/TTL path is an indexed storage-map lookup and TTL-extension lookup/update, not a full SAC subframe.
- `ai-summary/fail/ledger/summary.md:71-73` — the previous output-side balance-read hypothesis is related but not a duplicate; it failed because the native path did not exist in that checkout.
- `ai-summary/fail/ledger/summary.md:45,48,69,72` — adjacent SAC instance/TTL/key and SAC call-boundary optimizations have already been found below Medium once aggregate worker time is normalized by parallelism.

### Why It Failed

The inefficiency exists, and a complete journal could be made correct only if it records deltas at the common `write_contract_balance` path and participates in host-frame rollback. But the performance claim is over the objective threshold: the hypothesis's own broad upper-bound zones total 672.085 ms of `storage get` and 455.825 ms of TTL-extension work over the diagnostic run, and those totals include far more than the two residual post-swap balance reads. Normalized across the 236 measured soroswap samples and 8 configured clusters, even eliminating the entire broad `storage get` plus TTL-extension totals would be about 0.6 ms of wall-clock apply time per sample, well under 1% of the ~213-218 ms soroswap apply baseline; the actual removable subset is much smaller and would be offset by journal maintenance on every SAC contract-balance write.

Because the optimize-soroswap objective accepts only Medium-or-High findings, this is rejected as below objective severity threshold rather than promoted as a technically real Low/sub-1% optimization.

### Lesson Learned

After the direct SAC balance fast path removed full read-only SAC `balance` frames, the remaining pair-balance reads are small indexed storage/TTL operations. Future SAC-balance hypotheses need dedicated timing for the exact residual read path and must normalize worker-thread totals by both benchmark samples and `NUM_CLUSTERS`; broad SAC transfer, storage, or TTL totals are not enough to project a 3% apply-time win.
