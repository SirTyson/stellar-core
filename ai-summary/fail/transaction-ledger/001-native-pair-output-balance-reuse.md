# H001: Reuse native pair output balance after successful child SAC transfer

**Date**: 2026-05-24
**Subsystem**: transaction-ledger / soroban host native Soroswap path
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by removing one post-transfer SAC pair-balance read on the native pair swap output side
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For the protocol-gated native Soroswap pair `swap` path, a successful output SAC `transfer(pair, to, amount_out)` should leave the pair's output-token balance equal to the child SAC frame's committed balance mutation. The native pair executor should be able to use that post-transfer balance for the K-invariant calculation without re-entering the generic SAC `balance` path, while preserving the child SAC transfer frame, `from.require_auth()` semantics, rollback behavior, and event emission exactly.

## Mechanism

`call_native_soroswap_pool_swap` currently calls `soroswap_pool_invoke_sac_transfer` for the positive output leg, then immediately calls `soroswap_pool_invoke_sac_balance` for both token balances. This keeps auth correct because the transfer remains a normal child SAC call, but the output-side balance has just been modified by that child call and is read back through `contract_instance_executable_is_stellar_asset`, instance TTL extension, `read_contract_balance_for_contract_owner`, and balance TTL extension. A protocol-gated helper can have the child-transfer bridge return the updated pair balance for the exact `(token, pair_address)` slot it just debited, then use that value for the corresponding `balance_0` or `balance_1`; the opposite/input side is still read normally to detect transferred-in input.

## Trigger

Run the current soroswap apply-load benchmark from `ai-summary/CURRENT_STATE.md` (`soroswap, TX=2000, T=8`). Each accepted native pair swap with exactly one positive output amount enters `call_native_soroswap_pool_swap`, performs one child SAC transfer at `frame.rs:1158-1173`, then reads both pair balances at `frame.rs:1175-1176`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1076-1305` - native pair swap body; output SAC transfer followed by two balance reads and reserve update.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1330-1347` - child SAC transfer bridge; should remain a child SAC call but can return the updated `(token, pair)` balance when available.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1349-1393` - direct SAC pair balance read that can be skipped for the output side after a successful transfer.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:180-199,235-299,356-428` - typed SAC balance read/write helpers that expose the post-transfer balance semantics.

## Evidence

The current soroswap trace is dominated by apply-window SAC work: timestamp filtering against `applyLedger` shows `SAC transfer` at **2,477.085 ms** over **15,665** in-window events, `storage get` at **224.247 ms self** / **674.603 ms total**, `ScVal to Val` at **1,144.488 ms**, and `map lookup indexed` at **585.969 ms**. The direct pair balance reads are descendants of the measured `applyLedger -> applyTransactions -> applyParallelPhase -> applySorobanStages` path, not TX-set construction.

This hypothesis is narrower than the rejected same-frame SAC transfer fast lane: it does not bypass the child SAC frame, does not change `require_auth`, and does not skip the transfer's required storage/TTL/event work. It only avoids an immediate read-back of the output balance already produced by that child call in the native pair executor.

## Anti-Evidence

Soroswap permits both `amount_0_in` and `amount_1_in` to be positive if tokens were pre-sent to the pair, so the optimization must only reuse the output-side value when it is semantically the child transfer's post-debit balance; it must still read the input side normally. A PoC must prove the returned balance is taken after child-frame commit and is discarded on any transfer failure/rollback. The removable work is one of two post-swap pair balance reads, so narrow Tracy counters around `soroswap_pool_invoke_sac_balance` are needed to confirm the Medium estimate survives cluster normalization.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/transaction-ledger/summary.md` entry `002-sac-transfer-balance-slot-context.md`
**Failed At**: reviewer

### Trace Summary

The native Soroswap pair path is real: `call_contract_fn` recognizes the hash-gated pool Wasm, pushes a `Frame::NativeContract`, executes `call_native_soroswap_pool_swap`, calls `soroswap_pool_invoke_sac_transfer` for the positive output leg, and then reads both pair balances through `soroswap_pool_invoke_sac_balance`. The child transfer still enters `call_n_internal`, dispatches to a `Frame::StellarAssetContract`, runs SAC `transfer`, and commits or rolls back through normal frame context semantics. The proposed optimization is substantially the already-investigated transfer-local balance-slot context idea: carry the just-mutated SAC balance out of the transfer path to avoid a duplicate balance-key/read operation.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:782-837` — `call_contract_fn` dispatches hash-gated native Soroswap pool calls before VM fallback and pushes a `Frame::StellarAssetContract` for SAC calls.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1076-1305` — native pair `swap` validates output amounts/reserves, performs output SAC transfers, reads both pair balances, computes inputs/K-invariant, updates reserves, and emits the swap event.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1330-1393` — `soroswap_pool_invoke_sac_transfer` returns only `()` after `call_n_internal`, while `soroswap_pool_invoke_sac_balance` already uses the accepted direct typed SAC balance read fast path for contract owners.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1531-1729` — `call_n_internal` enforces reserved-function and reentry checks, emits diagnostics, dispatches the child call, and returns the child function result.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:219-260` — pushed frames snapshot storage, events, and auth so errors roll back child-frame effects.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — SAC `transfer` checks amount, performs `from.require_auth()`, extends instance/code TTL, debits/credits balances, emits the SAC event, and returns void.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:180-199,235-299,356-428` — contract-owner balances are read/written through the typed SAC helpers; the debit path computes the post-spend amount internally but does not expose it through the public transfer result.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:3629-3656` and `src/rust/soroban/p26/soroban-env-host/src/auth.rs:829-910` — `require_auth` authorizes the current child SAC frame and direct-invoker relationship, which this hypothesis correctly preserves by keeping the child call.

### Why It Failed

This is not novel. The fail summary already records `002-sac-transfer-balance-slot-context.md`, "Carry SAC transfer-local balance slot context to avoid duplicate balance-key operations per transfer", which was accepted at reviewer but rejected at final review after benchmarking: soroswap regressed by 1.99% and max-sac improved only 0.67%. The present hypothesis narrows that same mechanism to the native pair output leg after the child SAC transfer, but it still relies on carrying transfer-local balance-slot state out of SAC transfer to skip a duplicate balance read.

The actual source confirms the removable work is only one already-optimized direct typed pair-balance read per swap output leg. The child transfer's auth frame, storage snapshot/rollback, debit/credit writes, TTL work, issuer/event logic, and diagnostics remain mandatory. Given the prior final-review regression for the same balance-context reuse strategy and the objective's Medium floor, this should not be re-promoted without a materially different measured mechanism.

### Lesson Learned

After the typed SAC balance storage fast path is in the baseline, "reuse the balance just touched by SAC transfer" needs fresh narrow measurements and a demonstrably lower-overhead carrier design; the previously tested transfer-local context added more overhead than it saved on soroswap.
