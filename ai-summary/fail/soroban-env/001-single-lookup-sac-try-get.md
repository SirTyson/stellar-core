# H001: Collapse SAC optional contract-data reads to one physical lookup

**Date**: 2026-04-29
**Subsystem**: soroban-env
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by removing duplicate physical storage-key conversion, footprint enforcement, map lookup, and value conversion in Stellar Asset Contract balance paths while preserving the existing budget charges
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

SAC helper code that needs "maybe present" contract data should determine presence and, when present, return the value with one physical storage lookup. It should still preserve the protocol-visible cost of the current `has_contract_data` + `get_contract_data` sequence, so transaction resource accounting and budget-limit behavior remain unchanged.

## Mechanism

`Host::try_get_contract_data` in `builtin_contracts/storage_utils.rs:4-13` currently implements optional reads as `has_contract_data(k, t)?` followed by `get_contract_data(k, t)?` when the key exists. In soroswap SAC balance paths, most balance entries are expected to exist, so every successful optional read performs two storage-key conversions and two enforcing-storage reads before decoding the same value once. A budget-preserving internal helper could perform the actual `Storage::try_get` / instance-map `get` once, then explicitly replay the same budget charges that the skipped `has`/`get` components would have incurred, eliminating duplicate physical map traversal without changing reported `cpu_insns`/`mem_bytes`.

## Trigger

Run the current soroswap apply-load scenario (`TX=2000, T=8`) and inspect the soroswap Tracy trace from `ai-summary/CURRENT_STATE.md`. The apply path contains 6,656 `SAC transfer` calls and 6,636 `SAC balance` calls; `balance.rs` calls `try_get_contract_data` for persistent balance records in `read_balance`, `receive_balance`, `spend_balance_no_authorization_check`, and `is_authorized`. On present balances, each call executes both `has_contract_data` and `get_contract_data` for the same key.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/storage_utils.rs:4-13` — optional contract-data helper that currently performs `has` then `get`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:44-63` — `read_balance` successful contract-balance path.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:100-145` — `receive_balance` successful contract-balance path.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:156-209` — `spend_balance_no_authorization_check` successful contract-balance path.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:233-245` — `is_authorized` successful contract-balance path.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2211-2264` — existing `has_contract_data` and `get_contract_data` implementations whose physical work is duplicated by the helper.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:252-303` — enforcing-storage `try_get_full_helper` / `try_get` path that can return `Option` directly.

## Evidence

- Tracy scope check: the cited zones are under `applyLedger` through `InvokeHostFunctionOpFrame::doApply` -> Rust `invoke_host_function` -> `Host::invoke_function` -> SAC built-in calls. This is not TX-set construction.
- The current soroswap trace reports `SAC transfer` at `stellar_asset_contract/contract.rs:212` with 196.112 ms self-time over 6,656 calls, `SAC balance` at `contract.rs:187` with 18.639 ms self-time over 6,636 calls, `has_contract_data` direct-env calls at `soroban-env-common/src/vmcaller_env.rs:270` with 28.209 ms self-time over 19,970 calls, and `get_contract_data` direct-env calls at the same source location with 85.412 ms self-time over 53,250 calls.
- The lower storage layers are also hot in the same trace: `storage get` at `storage.rs:258` has 161.252 ms self-time over 176,910 calls and `map lookup` at `metered_map.rs:95` has 732.363 ms self-time over 641,355 calls. Successful `try_get_contract_data` calls contribute one avoidable physical read to those totals.
- The source-level duplication is exact: `try_get_contract_data` receives one already-built key `Val`, calls `has_contract_data(k, t)`, and if true immediately calls `get_contract_data(k, t)` with the identical `(k, t)`.
- This is distinct from the prior accepted storage-map lookup fast path: that optimized each map search; this removes an avoidable second physical search at a SAC optional-read boundary while preserving metering.

## Anti-Evidence

- A naive change that simply replaces `has` + `get` with one `try_get` would change protocol-visible budget/resource totals and likely fail exact-budget tests. The PoC must either replay the skipped charges exactly or restrict itself to an internal helper whose budget behavior is proven identical to the current two-call sequence.
- Missing-key behavior still needs care: the current path only pays `has_contract_data` work when the key is absent, while present keys pay both `has` and `get`. The optimized helper must preserve that branch-specific charging.
- Some `has_contract_data` / `get_contract_data` trace time comes from Wasm dispatch (`vm/dispatch.rs:304`) and unrelated contract code. The relevant removable subset is the direct-env SAC helper path, so the trace totals are an upper bound.
- Physical savings will be reduced by the need to keep budget charges. The expected win comes from skipping duplicate key conversion, footprint checks, map traversal, borrow churn, and value decoding, not from reducing `Budget::charge` counts.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS
**Failed At**: reviewer

### Trace Summary

The duplicated optional-read path is real: SAC `transfer` and `balance` call the balance helpers, contract-address balance helpers call `Host::try_get_contract_data`, and that helper calls `has_contract_data` followed by `get_contract_data` for present entries. For persistent data, both host functions rebuild the same `LedgerKey` from the key `Val`, enforce the footprint, and search the storage map; `Storage::has` is just `try_get_full(...).is_some()`. However, the proposed budget-preserving single lookup cannot remove the metered conversion/search/comparison work without changing protocol-visible resource totals; replaying those charges exactly requires either running the same conversion/search path or duplicating its path-sensitive metering logic. The remaining safely removable work is a narrow subset of SAC optional reads and does not clear this objective's Medium threshold.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/storage_utils.rs:4-13` — `try_get_contract_data` performs `has_contract_data(k, t)?` and then `get_contract_data(k, t)?` for the same `(k, t)` when present.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:185-224` — SAC `balance` and `transfer` enter the traced balance paths under built-in contract execution.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:44-63,100-145,156-209,233-245,270-289,300-365` — contract-address balance, transfer, authorization, set-authorization, and clawback checks all use `try_get_contract_data` for persistent SAC balance records.
- `src/rust/soroban/p26/soroban-env-common/src/vmcaller_env.rs:180-210,244-255` — native SAC calls invoke host functions through the blanket `Env for VmCallerEnv` wrapper with `VmCaller::none()`, including tracing/error augmentation but no Wasm dispatch.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2211-2264` — persistent `has_contract_data` and `get_contract_data` each call `storage_key_from_val` and then `Storage::has`/`Storage::get`; instance storage uses a separate `MeteredOrdMap<Val, Val, Host>` path.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:159-166,422-430,463-539` — storage-key conversion walks the key `Val` into `ScVal`, toggles the storage-key conversion guard, visits host objects, and charges `VisitObject`, allocation, and copy costs as needed.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:252-303,421-429` — `Storage::has` funnels through `try_get_full`, which validates key type, enforces read access, and searches the storage map before returning presence.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:130-154` — each read enforces the footprint through another metered map lookup.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:168-240,294-300` — each map lookup charges binary-search access and runs path-dependent comparisons before optionally charging found-entry access.
- `src/rust/soroban/p26/soroban-env-host/src/host/comparison.rs:293-431` — `ScVal`/`LedgerKeyContractData`/`LedgerKey` comparisons charge `MemCmp` based on the compared values and the actual binary-search path.
- `ai-summary/fail/soroban-env/summary.md:9-18` and `ai-summary/fail/soroban-env/011-eliminate-is-clean-fuel-check.md:91-125` — no duplicate in target fail records; existing failures emphasize that broad Tracy zones and sub-threshold micro-optimizations are insufficient.
- `ai-summary/success/soroban-env/002-specialize-storage-map-lookup-fast-path.md:9-26,44-53,88-97` — the accepted storage-map fast path is related but distinct, and its much broader all-storage-map optimization measured only Low severity.

### Why It Failed

The hypothesis relies on removing duplicate physical key conversion, footprint enforcement, map traversal, and value conversion while preserving the exact `cpu_insns`/`mem_bytes` of the current two-call sequence. That is not available as a clean internal transformation. If the new helper skips the second `storage_key_from_val`, footprint lookup, storage-map lookup, and comparator sequence, it also skips `VisitObject`, `MemAlloc`, `MemCpy`, and `MemCmp` budget charges whose counts and inputs are protocol-visible. If it replays those charges by actually running the skipped conversion/search path, the expensive physical work remains and only small unmetered wrapper/borrow/error-handling overhead is saved.

Even with the most optimistic upper bound, the target is below this objective's accepted severity floor. The cited trace has 19,970 `has_contract_data` calls versus 176,910 `storage get` calls and 641,355 `map lookup` calls; the present-SAC optional-read subset is only a fraction of the storage subsystem. The broader prior storage-map fast path affected all Soroban storage/footprint/TTL/restored-key map searches and measured a 2.17% soroswap median improvement, which is Low. This narrower, budget-constrained helper cannot credibly project a reproducible 3-10% apply-time reduction, so it is rejected as below the objective severity threshold.

### Lesson Learned

For Soroban storage optimizations, "skip the duplicate lookup" is not sufficient: exact budget compatibility includes the metered key conversion, footprint lookup, storage lookup, and path-dependent comparison charges. If preserving those charges requires rerunning the same conversion/search path, the safely removable physical work is usually much smaller than the aggregate Tracy zones suggest and must be projected against the Medium floor before promotion.
