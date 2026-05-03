# H002: Carry a SAC transfer-local balance slot context through authorization, mutation, and writeback

**Date**: 2026-05-03
**Subsystem**: transaction-ledger / Soroban SAC apply
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by collapsing repeated contract-balance key construction, storage lookups, and writeback preparation in each SAC transfer
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

During a Stellar Asset Contract transfer, each contract-address balance slot should be decoded, authorized, mutated, written, and TTL-extended once per transfer side while preserving the same authorization result, missing-balance behavior, TTL threshold behavior, and emitted events. In the soroswap account-to-pair and pair-to-account shape, the contract side of each transfer should not reconstruct the same balance `LedgerKey` and re-read the same `ContractData` entry separately for authorization, balance mutation, and writeback.

## Mechanism

The current accepted typed SAC balance path removed the generic `Val` storage API round-trip, but the transfer helpers still do the same slot work multiple times. For a contract receiver, `receive_balance` calls `is_authorized`, which builds the balance key and reads the balance; then `receive_balance` builds the key again and reads the balance again; then `write_contract_balance` reconstructs the key `ScVal`, derives the `LedgerKey`, calls `try_get_full` for the same entry, clones/updates it, writes it back, and extends TTL. The contract spender path has the same repeated-read/writeback shape through `spend_balance` and `spend_balance_no_authorization_check`.

A transfer-local `ContractBalanceSlot` context could hold the `Rc<LedgerKey>`, optional current `EntryWithLiveUntil`, decoded `BalanceValue`, and key `ScVal` for the single contract side of each soroswap SAC transfer. Authorization, amount mutation, writeback, and TTL extension would operate on that context, preserving deterministic order and exact ledger effects while collapsing repeated map lookups, `ScVal` construction, metered clones, and storage reads.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) and instrument contract-address SAC transfers to count how many times a single transfer side calls `contract_balance_ledger_key`, `read_contract_balance`, and `Storage::try_get_full` for the same balance key. The reproducible trigger is any soroswap swap leg where the user account transfers into a pair contract or the pair contract transfers back to a user account; each leg exercises one contract-balance side.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-224` — SAC `transfer` dispatches to `spend_balance`, `receive_balance`, and event construction.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:44-56` — constructs the typed contract-balance key `ScVal` and derives the corresponding `LedgerKey`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:150-178` — `read_contract_balance` and `extend_contract_balance_ttl` read and extend the same storage slot independently.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:213-278` — `write_contract_balance` reconstructs the key, re-reads the current entry with `try_get_full`, clones and updates it, writes it back, then extends TTL.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:281-324,334-405,409-419` — receiver, spender, and authorization helpers repeat same-key balance reads in the transfer path.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:319-357,380-389,431-515` — storage get/put/TTL paths whose repeated map lookups and inserts would be collapsed by operating on one carried slot context.

## Evidence

- Current Tracy validation from the recorded soroswap trace shows these SAC/storage zones inside `applyLedger`: `SAC transfer` totals **2,153,411,257 ns** over 13,527 calls, `storage get` totals **641,710,601 ns** over 305,065 calls, `storage put` totals **119,301,798 ns** over 33,882 calls, `ScVal to Val` totals **995,921,819 ns**, `Val to ScVal` totals **431,617,333 ns**, and generic `map lookup` totals **1,123,770,554 ns**. The path is a descendant of parallel `InvokeHostFunctionOpFrame doParallelApply`.
- Source-level repetition remains after the accepted typed SAC balance fast path. On the receiver side, `is_authorized` reads the contract balance (`balance.rs:409-419`), `receive_balance` reads it again (`281-324`), and `write_contract_balance` re-fetches the same entry (`232-235`) before writing. The spender side has the analogous sequence through `spend_balance` and `spend_balance_no_authorization_check`.
- Soroswap is a mixed account/contract SAC workload: even though it is not a symmetric account/account transfer, every swap leg still exercises exactly one contract balance side for the pair address. That makes same-key contract-balance slot reuse per transfer much more targeted than broad instance-metadata or event-construction caching.
- Determinism is preserved if the context is local to one SAC transfer call and writes through `Storage::put` / `extend_ttl` in the same order currently observed. No cross-transaction cache or non-deterministic scheduling is involved.

## Anti-Evidence

- A previous authorization/balance-read fusion attempt was not confirmed because its PoC handoff was not reproducible; this hypothesis must be treated as a refined, narrower context design and must include clean committed source before benchmarking.
- Storage and conversion Tracy categories are broad. A PoC needs narrow counters around contract-balance keys to prove the removable same-key subset is large enough for the 3% Medium floor after dividing aggregate worker time by the eight soroswap clusters.
- Budget accounting is protocol-visible. Reusing a decoded `BalanceValue` or carried `LedgerEntry` must either preserve equivalent metered clone/conversion charges or be protocol-gated with updated budget expectations.
- TTL extension semantics must remain identical: missing entries, expired entries, threshold checks, clamping, and write-footprint enforcement still need to flow through the existing storage helpers.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-05-03
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — a related `002-fuse-sac-authorization-balance-reads.md` entry failed final review for non-reproducible dirty handoff, not because the optimization was technically disproven; this hypothesis extends the mechanism to the transfer-local key/value/writeback/TTL slot context and still requires a clean PoC.

### Trace Summary

`contract.rs::transfer` runs on the Soroban apply path and calls `spend_balance` followed by `receive_balance` for every SAC transfer. In the soroswap shape, exactly one side of each transfer is the pair contract, and that contract side currently constructs the same balance key and reads the same `ContractData` slot through authorization, mutation, writeback, and TTL extension. The repeated work remains even with the current enforcing-storage side-index fast path: indexing reduces each map search, but it does not remove the duplicate key construction, `Storage::try_get(_full)` calls, entry clone/writeback setup, or decoded `BalanceValue` reuse opportunity. A transfer-local slot object can preserve deterministic ordering because it is scoped to one SAC call and writes through the same storage map before event emission.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-224` — `transfer` checks amount/auth, extends instance/code TTL, then calls `spend_balance`, `receive_balance`, and transfer-event emission in deterministic order.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:44-56` — `contract_balance_key_scval` allocates/builds the typed `["Balance", address]` key and `contract_balance_ledger_key` derives the persistent `LedgerKey`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:150-178` — `read_contract_balance` calls `Storage::try_get` and decodes `BalanceValue`; `extend_contract_balance_ttl` separately calls `Storage::extend_ttl` for the same key.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:213-278` — `write_contract_balance` rebuilds the key `ScVal`, derives the `LedgerKey`, calls `try_get_full`, clones or creates the `ContractDataEntry`, calls `put`, then calls `extend_contract_balance_ttl`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:281-324` — contract receiver path first calls `is_authorized`, then rebuilds and rereads the same contract balance before adding the amount and writing.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:334-405` — contract spender path calls `is_authorized`, then `spend_balance_no_authorization_check` rebuilds and rereads the same balance before subtracting and writing.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:409-419` — `is_authorized` constructs and reads the contract balance key solely to obtain `BalanceValue.authorized`, duplicating the later mutation read for transfer sides.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:323-389,419-490,531-688` — `try_get_full`/`try_get`, `put`, and `extend_ttl` each enforce footprint access and hit the storage map; the existing side index skips binary-search comparisons but repeated same-key calls and value cloning still occur.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:317-380` — the current indexed helper preserves budget charges while skipping binary-search comparisons, confirming that the remaining opportunity is duplicate calls and key/value preparation, not merely map-search complexity.
- `ai-summary/fail/transaction-ledger/summary.md:47-57` — prior SAC-adjacent failures were checked; the closest entry failed due to reproducibility of a dirty PoC handoff, while account-side/event/metadata variants failed because their removable subset was narrower or below threshold.

### Findings

The inefficiency exists. For an existing contract balance side, the current path can perform an authorization read, a mutation read, a writeback `try_get_full`, and a TTL-extension read for the same `LedgerKey`, with repeated balance-key construction and decoded `BalanceValue` work around those calls. Missing balances have the same duplicate authorization/mutation key path before creating the entry, and then immediately run TTL extension through storage after `put`.

The path is hot for the objective. `SAC transfer` is invoked per swap leg in the parallel Soroban apply path, and the recorded trace shows 13,527 transfer calls inside `applyLedger`; soroswap's mixed account/contract shape gives one contract-balance endpoint per transfer rather than making this a rare edge case. The full `storage get` and conversion categories are broad, but the per-transfer repeated contract-balance subset is frequent enough that eliminating two to three same-key storage reads plus key reconstruction on the contract side is plausibly above the 3% Medium floor when combined with the writeback/TTL fusion.

Existing optimizations do not eliminate this opportunity. The current storage side index changes the cost of each lookup but still charges and executes each `try_get_full`/`put`/TTL path independently, and it cannot reuse a previously decoded `BalanceValue` or the already-derived `Rc<LedgerKey>`. This means the slot-context design is additive to the accepted storage-map fast path, though the PoC must measure the post-index baseline rather than reusing older broad Tracy totals.

Correctness is the main constraint. The PoC must either explicitly preserve the old metered charges for skipped `ScVal` construction, storage access, clones, and decoding, or intentionally protocol-gate the cheaper p26 behavior and update budget expectations. TTL handling must also reuse the same liveness, threshold, max-live-until clamping, and footprint enforcement logic as `Storage::extend_ttl`; skipping the extra read is viable only if those checks are factored so the carried `EntryWithLiveUntil` drives the same result.

### PoC Guidance

- **Target code**: `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs`, with any small storage helper factored in `src/rust/soroban/p26/soroban-env-host/src/storage.rs` only if needed to apply TTL from carried entry metadata.
- **Change description**: Introduce a transfer-local contract balance slot that builds the balance key once, loads `EntryWithLiveUntil` once with `try_get_full`, decodes `BalanceValue` once, and exposes methods for authorization, amount mutation, writeback, and TTL extension. Route only the `ScAddress::Contract` branches of `receive_balance` and `spend_balance_no_authorization_check` through this slot; keep account/trustline behavior unchanged.
- **Correctness check**: Preserve missing-balance authorization semantics (`!is_asset_auth_required`), deauthorized-balance rejection, insufficient-balance errors, overflow checks, clawback flag initialization, existing-entry live-until preservation, new-entry min live-until initialization, TTL threshold/clamping behavior, footprint enforcement, and event order.
- **Benchmark focus**: Add narrow temporary counters around contract-balance `contract_balance_ledger_key`, `read_contract_balance`, `try_get_full`, and TTL-extension reads for the soroswap `TX=2000, T=8` apply-load benchmark. The expected metric is fewer same-key storage reads/key builds per contract transfer side and a reproducible 3-10% reduction in top-line apply time relative to the current post-storage-index baseline.
