# H001: Direct native SAC transfer for native Soroswap pair swap

**Date**: 2026-05-24
**Subsystem**: transaction-ledger / soroban host native Soroswap path
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by removing one full nested SAC contract call from each native pair swap output leg
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When the protocol-gated native Soroswap pair `swap` path transfers the output token from the pair contract to the recipient, it should preserve the observable SAC `transfer` semantics: pair-address authorization, amount validation, balance debit/credit, balance TTL extension, SAC transfer/mint/burn event selection, diagnostic/error behavior, and deterministic ledger writes. For the benchmark's standard pair swap shape, the transfer should not need to re-enter the generic `call_n_internal` contract-call pipeline only to dispatch immediately to `Frame::StellarAssetContract`.

## Mechanism

`call_native_soroswap_pool_swap` currently performs the output transfer through `soroswap_pool_invoke_sac_transfer`, which constructs `transfer` arguments and calls `call_n_internal` on the token contract (`src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1158-1173,1330-1347`). That nested call pushes another frame, snapshots auth/storage, dispatches through generic SAC argument conversion, executes `SAC transfer`, and then the pair swap reads the pair balances separately via the direct SAC balance fast path. A protocol-gated helper specialized for the already-validated native pair context can verify the token executable is `StellarAsset`, perform the same typed SAC transfer body directly using the existing typed balance helpers, and return the updated pair balance for the output token; this removes the nested external-call scaffolding and one immediate read-after-write while keeping deterministic ledger effects in the same pair-swap frame.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) from `ai-summary/CURRENT_STATE.md`. Each successful native pair swap with a positive `amount_0_out` or `amount_1_out` takes `call_native_soroswap_pool_swap`, calls `soroswap_pool_invoke_sac_transfer` for the output token, then calls `soroswap_pool_invoke_sac_balance` for both token balances.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1013-1074` — native pair `swap` dispatch and frame setup.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1076-1305` — native pair swap body; output transfer followed by pair-balance reads.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1330-1347` — `soroswap_pool_invoke_sac_transfer`, the nested generic SAC transfer call to replace.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — SAC `transfer` semantics that the direct helper must preserve.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:150-199,235-345,417-440` — typed contract-balance read/write/authorization helpers already used by accepted SAC balance fast paths.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:47-64,94-113` — event selection and transfer event construction that must remain equivalent.

## Evidence

Timestamp filtering against `applyTransactions` in the current soroswap trace confirms this is apply-path work, not TX-set construction: `SAC transfer` contributes **2,477.085 ms total** across **15,665 events** inside `applyTransactions`; `call` contributes **5,134.323 ms** across **23,569 events**; `push context` contributes **287.422 ms**; `snapshot auth` contributes **126.906 ms**. With `NUM_CLUSTERS=8`, even removing roughly half of the SAC transfer envelope (the pair-output transfer side, leaving router input transfers untouched) is about `2,477 ms / 2 / 8 = 155 ms` over the traced `applyLedger` total of **4,475.606 ms**, a plausible **3-4%** top-line apply improvement before counting the read-after-write balance reuse.

The source shape is concrete: accepted direct SAC balance reads already prove that the host can safely recognize `ContractExecutable::StellarAsset` by peeking at the token instance and directly read typed SAC balances (`frame.rs:1368-1393`, `data_helper.rs:122-160`). The native pair swap has stronger context than a generic external SAC call: the token address was read from validated pair instance storage, the caller frame is the pair contract, and the transfer amount/output side is already checked before the call.

## Anti-Evidence

The nested SAC transfer is not just dispatch overhead: it performs authorization, balance mutation, TTL extension, and event emission. A viable PoC must preserve those semantics exactly, including `from.require_auth()` behavior for the pair address, issuer mint/burn event selection, muxed destination handling, and budget/error accounting. The aggregate `SAC transfer` Tracy total includes both router input transfers and pair output transfers; this hypothesis targets only the output leg unless expanded into a broader router-level fast path.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — substantially covered by `ai-summary/fail/transaction-ledger/summary.md` entries `001-fused-sac-transfer-fast-lane.md` and `002-sac-transfer-balance-slot-context.md`
**Failed At**: reviewer

### Trace Summary

The current native pair path is real: hash-gated `try_call_native_soroswap_pool_swap` pushes a `Frame::NativeContract`, executes the pair `swap`, and calls `soroswap_pool_invoke_sac_transfer` for the output token. That helper enters the normal contract-call path, which loads the token instance, pushes a `Frame::StellarAssetContract`, and then runs SAC `transfer`. The proposed same-frame direct transfer is not behavior-preserving as stated because `from.require_auth()` derives the authorized function from the current auth frame; in the existing path the pair authorizes a direct sub-invocation of the token's `transfer`, while in the pair frame the current invocation is the pair's own `swap`.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1013-1074` — native pair swap is protocol-gated, validates the Soroswap pair hash/shape, then pushes a `Frame::NativeContract`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1076-1305` — native pair `swap` performs output transfers, reads both pair balances, checks inputs/K-invariant, updates reserves, and emits the pair event.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1330-1347` — output SAC transfer still calls `call_n_internal(token, "transfer", [from, to, amount])`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:780-837,1531-1729` — generic calls enforce reserved-function and reentry checks, run diagnostics, load the contract instance, and push `Frame::StellarAssetContract` for SAC execution.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:223-237,437-595` — every pushed frame records auth/storage/event rollback state and rolls it back on error.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:3629-3656` — `require_auth` clones the current frame's arguments and asks the authorization manager to authorize the current frame.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:829-850,875-910,1340-1370` — auth frames are built from `Frame::{NativeContract,StellarAssetContract}`; the direct-invoker rule authorizes the pair only when the pair is the caller of a child SAC frame.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — SAC `transfer` performs amount validation, `from.require_auth()`, instance/code TTL extension, debit/credit, and event emission.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:150-199,303-345,417-440` — contract-owner balances still require typed reads, writes, authorization checks, overflow checks, and TTL extension.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:47-64,94-113` — transfer/mint/burn event selection still requires issuer checks, name lookup, topics/data construction, and muxed-address handling.

### Why It Failed

This is a duplicate/subsumed SAC-transfer fast-lane proposal, and the traced mechanism overstates the removable work. A correct implementation cannot simply execute SAC transfer logic "in the same pair-swap frame": that changes the authorization function observed by `require_auth` from token `transfer(pair, to, amount)` to pair `swap(amount_0_out, amount_1_out, to)`, so pair-address invoker authorization and recorded auth payloads diverge. Preserving auth requires at least a synthetic SAC/auth frame equivalent to the existing child invocation, keeping a meaningful part of the claimed frame/auth overhead.

The remaining transfer body is also not an avoidable envelope. Amount validation, SAC instance/code TTL extension, balance authorization reads, spend/receive storage updates, balance TTL extension, issuer classification, event emission, diagnostics, and rollback-compatible auth/event behavior all remain. The hypothesis sizes its Medium claim from inclusive `SAC transfer` and broad `call`/`push context` totals, but prior transaction-ledger reviews already rejected the same residual SAC fast-lane and transfer-local balance-context ideas: the former because the residual work is mandatory, and the latter because the attempted context reuse regressed soroswap in final review.

### Lesson Learned

After native pair swap and direct SAC balance reads are already in the baseline, further SAC transfer shortcuts must first isolate a narrow, non-mandatory residual cost that survives auth-frame equivalence and cluster normalization. Inclusive SAC transfer time is mostly the required transfer itself, not removable dispatch overhead.
