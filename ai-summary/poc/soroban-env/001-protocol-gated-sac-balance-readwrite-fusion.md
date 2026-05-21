# H001: Protocol-Gated SAC Balance Read/Write Fusion

**Date**: 2026-05-21
**Subsystem**: soroban-env
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by removing repeated SAC balance lookups and conversions in the token-transfer hot path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For a SAC `transfer` between contract addresses, the host should read each side's balance entry once, validate authorization from the decoded balance state, compute the new amount, and write the final balance entry while preserving deterministic ledger output and emitting the same SAC event. On protocol versions that retain p26 metering, this path should remain unchanged; on a new protocol, budget constants can be recalibrated for the fused typed helper rather than replaying the old duplicate lookup sequence.

## Mechanism

`receive_balance` and `spend_balance` both call `is_authorized` before reading the same contract balance again to update it. For contract addresses this produces two `try_get_contract_data` / `BalanceValue::try_into_val` passes per side (`balance.rs:100-145`, `balance.rs:220-242`), so a normal contract-to-contract SAC transfer can read and decode the sender balance twice and the receiver balance twice. A next-protocol fused helper such as `read_contract_balance_for_update` could return `(amount, authorized, clawback, existed)` once per side, eliminating redundant storage-map searches and `ScVal` conversion work without trying to preserve p26's exact per-call metering.

## Trigger

Run the current soroswap apply-load benchmark with many pool swaps that invoke SAC `transfer` on contract addresses. In each successful transfer, instrument `try_get_contract_data` calls for `DataKey::Balance` inside `spend_balance`, `receive_balance`, and `is_authorized`; the expected trigger is repeated reads of the same balance key within a single SAC transfer leg.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:100-145` — `receive_balance` first checks `is_authorized`, then re-reads the same contract balance for mutation.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:220-242` — `spend_balance` checks `is_authorized`, while `spend_balance_no_authorization_check` re-reads the same contract balance.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — `transfer` calls `spend_balance` and `receive_balance` on the hot SAC path.
- Tracy zone `SAC transfer` at `soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:212` — 2,153,411,257 ns total across 13,527 calls in the current soroswap trace, fully inside `applyLedger`.
- Tracy zones `storage get` and `ScVal to Val` — 641,710,601 ns and 995,921,819 ns respectively inside `applyLedger`, covering the storage/conversion families this helper would reduce.

## Evidence

The current trace confirms that SAC transfer is a dominant apply-path descendant: unwrap containment found all 13,527 `SAC transfer` events inside `applyLedger`, totaling 2.15s aggregate in the diagnostic trace whose `applyLedger` envelope totals 5.23s. Source inspection shows repeated balance access in the exact transfer path: `receive_balance` invokes `is_authorized` and then `try_get_contract_data` again, while `spend_balance` invokes `is_authorized` and then delegates to `spend_balance_no_authorization_check`, which performs another `try_get_contract_data`. Because soroswap is token-transfer heavy, even removing one balance lookup/decode per transfer side has a plausible Medium impact if gated behind a new protocol cost model.

## Anti-Evidence

Prior exact-budget attempts to collapse optional SAC storage reads were rejected because p26 exposes the precise metering sequence. This hypothesis is only viable as a protocol-gated optimization with recalibrated SAC helper costs; a p26-compatible "skip the lookup but replay charges" variant would likely fail for the same reason. The broad `storage get` and `ScVal to Val` zones include many non-balance call sites, so a reviewer should first add focused instrumentation for `DataKey::Balance` duplicate reads before accepting the Medium estimate.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-05-21
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — prior `001-single-lookup-sac-try-get.md` covered an exact p26 budget-preserving collapse; this hypothesis is specifically the protocol-gated/cost-model-recalibrated variant and is not substantially the same viability claim.

### Trace Summary

The hot path enters the SAC built-in through `Host::call_contract_fn`, pushes a `Frame::StellarAssetContract`, dispatches `StellarAssetContract::transfer`, and then executes `spend_balance` followed by `receive_balance`. For contract addresses, both helpers first call `is_authorized`, which reads and decodes `DataKey::Balance`, and then each mutation path reads and decodes the same key again. `try_get_contract_data` itself is implemented as `has_contract_data` followed by `get_contract_data` on hits, so the existing path compounds the duplicate side-level authorization/update reads with repeated storage-key conversion, footprint/storage lookup, and `ScVal` to `Val` conversion work. A new-protocol-only typed helper can avoid relying on p26's exact per-component metering and can preserve semantic behavior while removing the redundant physical work.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-783` — `call_contract_fn` retrieves the contract instance, detects `ContractExecutable::StellarAsset`, pushes a `Frame::StellarAssetContract`, and invokes `StellarAssetContract.call`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — `transfer` is the traced hot SAC entry point; after auth and instance/code TTL extension, it calls `spend_balance` and `receive_balance`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:100-145` — `receive_balance` checks `is_authorized` and then, for `ScAddress::Contract`, constructs the same `DataKey::Balance`, calls `try_get_contract_data`, decodes `BalanceValue`, mutates the amount, and writes the balance.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:156-230` — `spend_balance` checks `is_authorized` and delegates to `spend_balance_no_authorization_check`, whose contract-address branch constructs the same `DataKey::Balance`, calls `try_get_contract_data`, decodes `BalanceValue`, validates funds, mutates the amount, and writes the balance.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:233-245` — `is_authorized` reads `DataKey::Balance` and decodes `BalanceValue.authorized`; on a missing balance it falls back to `!is_asset_auth_required(e)`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/storage_utils.rs:4-14` — `try_get_contract_data` is not a single lookup on existing entries; it calls `has_contract_data` and then `get_contract_data`.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2211-2249` — `has_contract_data` converts the storage key and calls `Storage::has`; `get_contract_data` converts the storage key again, calls `Storage::get`, and converts the stored `ScVal` to a host `Val`.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:159-166,422-460` — storage key construction round-trips through `from_host_val_for_storage`; ledger value retrieval charges/traces `ScVal to Val` through `to_valid_host_val`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:252-303,421-429,693-720` — storage reads enforce footprint access and search the storage map; `Storage::has` funnels into the same `try_get_full` path as `get`.

### Findings

The inefficiency exists on the claimed path. On a successful contract-address SAC transfer, the sender balance is read for authorization and then read again for mutation, and the receiver balance follows the same pattern. For existing balances, each `try_get_contract_data` hit performs `has` plus `get`, so the current path performs more storage-map searches and host/XDR value conversions than the logical operation requires.

The path is hot for the objective. The traced `SAC transfer` zone accounts for 2.15s aggregate across 13,527 calls inside a 5.23s aggregate `applyLedger` envelope, and the removed operations sit inside `closeLedger` rather than TX-set construction or background bucket work. The proposed new-protocol gate is essential: preserving p26's exact budget sequence would reintroduce much of the work or require fragile charge replay, matching the already-failed exact-metering variant.

The proposed fix is correctness-preserving if it is implemented as a typed read-for-update helper for contract balances only, with the p26 path unchanged. For existing balances, the helper can return the decoded `BalanceValue` once and use `authorized`, `amount`, and `clawback` for validation and mutation. For missing balances, it must preserve today's branch-specific behavior: `is_authorized` returns `!is_asset_auth_required(e)`, `receive_balance` creates an authorized balance with `clawback: is_asset_clawback_enabled(e)?` only after passing that check, and `spend_balance_no_authorization_check` still permits missing balance only when `amount == 0`.

The projected impact clears the review-stage Medium floor. The direct whole-zone upper bound is large (`SAC transfer` is ~41% of the aggregate apply envelope), and the specific removed duplicate read/decode work only needs to save about 0.16s aggregate, roughly 12us per transfer or about 6us per eliminated side-level duplicate, to reach 3% of the cited trace. Given that each eliminated duplicate currently includes balance-key conversion, footprint/storage lookup, `ScVal to Val`, and `BalanceValue` extraction, this is plausible enough for PoC measurement; exact acceptance should still depend on non-Tracy apply-load runs.

### PoC Guidance

- **Target code**: `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs`, plus any narrowly necessary host/storage helper in `host/data_helper.rs` or `host.rs` to read persistent contract data as a typed SAC balance without going through `try_get_contract_data` twice.
- **Change description**: Add a new-protocol-gated contract-address balance helper that constructs the `DataKey::Balance` storage key once, performs one optional storage read, decodes one `BalanceValue`, and returns enough state for authorization plus mutation. Route `spend_balance` and `receive_balance` contract-address branches through it only when `ledger.protocol_version` is above the p26-compatible range; leave account-address paths and p26 behavior unchanged.
- **Correctness check**: Preserve all existing SAC authorization, missing-balance, insufficient-funds, overflow, clawback, TTL-extension, and event behavior. Existing SAC tests under `stellar_asset_contract` should remain semantically unchanged; only protocol-gated budget constants/expectations may need mechanical updates for the new protocol.
- **Benchmark focus**: Instrument duplicate `DataKey::Balance` reads inside `is_authorized`, `spend_balance_no_authorization_check`, and `receive_balance` to confirm the count reduction, then run `scripts/run_apply_load_matrix.py` repeatedly without Tracy. The target metric is soroswap median apply time; expected improvement must be at least 3% to satisfy this objective.

---

## PoC Attempt

**Result**: POC_PASS
**Date**: 2026-05-21
**PoC by**: gpt-5.5, high

### Changes Made

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:169-268` adds a protocol-gated typed `ContractBalanceForUpdate` helper that constructs the SAC balance key once, performs one optional storage read, decodes `BalanceValue` once, and carries the original entry/live-until state for mutation.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:381-475` routes next-protocol contract-address `receive_balance` through the fused helper while preserving the legacy p26/account-address path.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:534-603` routes next-protocol contract-address `spend_balance` through the fused helper while preserving deauthorization, missing-balance, insufficient-funds, overflow, and zero-spend behavior.

### Demonstration

The optimization is gated by `Budget::coalesced_host_metering`, which is enabled only when the active ledger protocol is above p26, so p26 metering behavior remains on the legacy path. For next-protocol contract-address SAC transfers, sender and receiver balances are each read and decoded once for authorization plus mutation, avoiding the duplicate `is_authorized` read and the later mutation read while preserving the same final ledger entry and SAC event behavior.

### Test Results

`make -j $(nproc)` completed successfully. `env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS="--ll fatal -r simple --abort --disable-dots" make check` completed successfully; the final reported suites included `751 passed; 0 failed; 2 ignored` for `soroban_env_host`, followed by all listed Rust integration/doc tests and `test/selftest-nopg` / `test/check-nondet` passing.

---

## Final Review — Needs Revision

**Date**: 2026-05-21
**Final review by**: gpt-5.5, high

### What Needs Fixing

The PoC source change exists on the p26 submodule branch
`poc/001-protocol-gated-sac-balance-readwrite-fusion` at
`65f7c838cd667d66fbf9d579d96bdf9901522636`, but the outer PoC branch does not
record that submodule commit in its gitlink. The outer `HEAD` gitlink for
`src/rust/soroban/p26` is still the prior accepted baseline
`fa1226b3068605c5376efe56c6cf809ca225a036`.

Following the required final-review validation step,
`git submodule update --init --recursive src/rust/soroban/p26` checks out the
baseline SHA and discards the PoC code from the working tree. This makes the
handoff unreproducible from the committed outer branch and prevents an
authoritative build/test/benchmark verdict or promotion to `soroswap-perf`.

### Revision Instructions

Commit the outer-repo gitlink bump so that
`src/rust/soroban/p26` points at
`65f7c838cd667d66fbf9d579d96bdf9901522636`, then re-run the PoC handoff. The
next final review must be able to check out the outer PoC branch, run
`git submodule update --init --recursive src/rust/soroban/p26`, and land on the
same p26 submodule commit containing the SAC balance read/write fusion diff.

### Checks Passed So Far

- The p26 submodule branch contains a focused SAC balance-path diff in
  `soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs`.
- Source inspection found the intended protocol-gated fusion path in the PoC
  submodule commit.
- Build, full test, and benchmark validation were intentionally stopped before
  measurement because the committed outer branch resolves the submodule to the
  baseline SHA rather than the PoC SHA.

---

## PoC Attempt (Revision)

**Result**: POC_PASS
**Date**: 2026-05-21
**PoC by**: claude-opus-4.7, high

### Changes Made

No new source edits were required — the prior PoC's source diff was preserved
on the p26 submodule branch `poc/001-protocol-gated-sac-balance-readwrite-fusion`
at SHA `65f7c838cd667d66fbf9d579d96bdf9901522636`. The revision addresses the
final review's complaint that the outer worktree's gitlink for
`src/rust/soroban/p26` did not record that SHA. The submodule in this worktree
is now checked out at `65f7c838`, so the outer worktree shows
`modified: src/rust/soroban/p26 (new commits)`. On POC_PASS the orchestrator
will commit this gitlink bump onto the outer PoC branch, making the handoff
fully reproducible: `git submodule update --init --recursive src/rust/soroban/p26`
will land on the PoC SHA containing the SAC balance read/write fusion diff.

### Demonstration

The protocol-gated typed `ContractBalanceForUpdate` helper in
`builtin_contracts/stellar_asset_contract/balance.rs` constructs the SAC
balance storage key once, performs one storage read, decodes `BalanceValue`
once, and is reused for both authorization and mutation. It is gated by
`Budget::coalesced_host_metering` so the p26 path (and all account-address
paths) remain on the legacy duplicate-read sequence. For next-protocol
contract-address SAC transfers this eliminates one balance-key conversion,
one footprint/storage lookup, one `ScVal → Val` conversion, and one
`BalanceValue` decode per side, while preserving the exact final ledger
entry, missing-balance branch, insufficient-funds branch, clawback handling,
deauthorization handling, and SAC event behavior.

### Test Results

- `make -j $(nproc)` (with `--enable-tracy --enable-tracy-capture
  --enable-next-protocol-version-unsafe-for-production`) completed
  successfully.
- `env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple
  --abort --disable-dots' make check` completed with exit code 0.
  `soroban_env_host` reported `751 passed; 0 failed; 2 ignored`, all
  Rust integration/doc tests passed, and `test/selftest-nopg` plus
  `test/check-nondet` both passed.
