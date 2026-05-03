# H002: Carry a SAC transfer-local balance slot context through authorization, mutation, and writeback

**Date**: 2026-05-03
**Subsystem**: transaction-ledger / Soroban SAC apply
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by collapsing repeated contract-balance key construction, storage lookups, and writeback preparation in each SAC transfer
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

During a Stellar Asset Contract transfer, each contract-address balance slot should be decoded, authorized, mutated, written, and TTL-extended once per transfer side while preserving the same authorization result, missing-balance behavior, TTL threshold behavior, and emitted events. In the soroswap account-to-pair and pair-to-account shape, the contract side of each transfer should not reconstruct the same balance `LedgerKey` and re-read the same `ContractData` entry separately for authorization, balance mutation, and writeback.

## Mechanism

The current accepted typed SAC balance path removed the generic `Val` storage API round-trip, but the transfer helpers still do the same slot work multiple times. For a contract receiver, `receive_balance` calls `is_authorized`, which builds the balance key and reads the balance; then `receive_balance` builds the key again and reads the balance again; then `write_contract_balance` reconstructs the key `ScVal`, derives the `LedgerKey`, calls `try_get_full` for the same entry, clones/updates it, writes it, and extends TTL. The contract spender path has the same repeated-read/writeback shape through `spend_balance` and `spend_balance_no_authorization_check`.

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
