# H001: Fuse SAC balance storage reads/writes with TTL extension

**Date**: 2026-05-02
**Subsystem**: transaction-ledger / Soroban host storage
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by eliminating repeated enforcing-storage lookups on the typed SAC balance path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When a Stellar Asset Contract balance helper reads or writes a persistent balance entry and immediately extends that same entry's TTL, the host should touch the enforcing storage map once for the logical operation. A successful balance read should return the decoded `BalanceValue` and the live-until metadata needed for the TTL threshold check; a successful balance write should update the entry value and live-until value in one storage-map update when the extension threshold is met. The final ledger entry value, `lastModifiedLedgerSeq`, TTL bump behavior, storage errors, and deterministic transaction output should be identical to the current separate read/write plus `extend_ttl` sequence.

## Mechanism

The accepted typed SAC balance fast path still performs a second storage lookup for the same `Rc<LedgerKey>` when TTL extension follows a balance read or write. `read_balance` calls `read_contract_balance` and then `extend_contract_balance_ttl`; `write_contract_balance` performs `try_get_full`, writes through `Storage::put`, and then calls `extend_contract_balance_ttl`, whose `Storage::extend_ttl` path calls `prepare_extend_ttl` and `get_with_live_until_ledger`, redoing supported-key checks, footprint enforcement, indexed storage-map lookup, and entry cloning for a key the caller just resolved.

A fused typed helper can carry the `EntryWithLiveUntil` from `read_contract_balance`, or the post-write live-until value from `write_contract_balance`, into a specialized `Storage` method that applies the same TTL threshold/maximum-live-until logic without re-reading the entry. This preserves deterministic ordering and uses no additional parallelism, while removing hot per-SAC-transfer storage-map work that remains after the prior typed-balance and storage-index optimizations.

## Trigger

Run the current soroswap apply-load benchmark from `ai-summary/CURRENT_STATE.md` (`soroswap, TX=2000, T=8`) and inspect the accepted Tracy trace `/mnt/nvme2/apply-load/1e0b14a6b879-20260430-160627/logs/1e0b14a6b879-20260430-160627-02-soroswap-tx-2000-t-8.tracy`. Each router swap invokes SAC transfers; contract-side balance reads/writes in `SAC transfer` repeatedly read or write a persistent balance entry and then extend the same key's TTL.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:150-178` — `read_contract_balance` returns only the decoded value, so `extend_contract_balance_ttl` must re-enter storage for live-until metadata.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:191-277` — `read_balance` and `write_contract_balance` call `extend_contract_balance_ttl` immediately after reading or writing the same balance key.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:324-389` — `try_get_full_helper` performs supported-key checks, read-only footprint enforcement, indexed map lookup, and clones the stored `EntryWithLiveUntil`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:521-528` — `has` funnels through the same full storage read path.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:646-665` — `extend_ttl` calls `prepare_extend_ttl`, which re-fetches the same entry before computing the TTL bump.

## Evidence

- Tracy timestamp filtering against the 70 `applyLedger` windows confirms these zones are in scope: `SAC transfer` totals **2245.135 ms** over 10,140 events inside `applyLedger`; `storage get` totals **453.519 ms** over 228,838 events; `storage put` totals **84.640 ms** over 25,410 events; and `extend key` totals **178.892 ms** over 71,201 events.
- The self-time export for the same trace shows `storage get,soroban-env-host/src/storage.rs:329` at **151.678 ms self-time** over 229,684 calls, with `extend_current_contract_instance_and_code_ttl` and generic storage-access zones still visible after the accepted typed-SAC balance optimization.
- The source has a concrete same-key sequence rather than a theoretical broad storage complaint: the typed `Rc<LedgerKey>` is already available in `read_balance`, `receive_balance`, `spend_balance_no_authorization_check`, and `write_contract_balance`, but TTL extension re-enters `Storage` as if the key and entry had not just been accessed.
- The proposal is not the previously failed SAC authorization/balance-read fusion. It targets the storage/TTL boundary for a single logical key after the accepted typed balance helper exists, and it does not rely on changing the mixed account-to-contract soroswap transfer shape.

## Anti-Evidence

- The full `extend key` aggregate is worker time and must be divided by the configured eight clusters before projecting critical-path savings; a PoC needs narrow counters for SAC balance TTL extension specifically, not the broad zone total.
- `Storage::extend_ttl` contains protocol-visible checks for temporary-vs-persistent TTL limits, max-live-until clamping, expired-entry errors, and threshold behavior. A fused helper must preserve these exactly or deliberately protocol-gate any metering/behavior change.
- Some `storage get` time comes from user Wasm storage, contract instances, auth, and non-balance SAC metadata. The expected Medium win depends on combining read+TTL and write+TTL on the repeated balance keys, not on removing the entire storage zone.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-02
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS
**Failed At**: reviewer

### Trace Summary

The claimed redundant lookup exists: p26 SAC contract-balance writes call `Storage::try_get_full`, `Storage::put`, and then `extend_contract_balance_ttl`, whose `Storage::extend_ttl` path calls `prepare_extend_ttl` and `get_with_live_until_ledger` on the same key. `SAC transfer` reaches this path through `spend_balance`/`receive_balance` for contract endpoints, and the public `balance` endpoint has a read-then-extend sequence as well. However, the broad `extend key` total cited by the hypothesis is only 178.892 ms of aggregate worker time across eight clusters, or roughly 22.4 ms of critical-worker opportunity before filtering to SAC balance entries and before preserving mandatory TTL checks. Prior objective records use the same cluster-division sizing rule and show this scale is below the Medium threshold for soroswap apply-time improvements.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — `SAC transfer` extends the SAC instance TTL, then calls `spend_balance` and `receive_balance`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:150-178` — `read_contract_balance` returns only a decoded `BalanceValue`; `extend_contract_balance_ttl` calls generic `Storage::extend_ttl`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:191-277` — public `read_balance` extends after a successful contract-balance read; `write_contract_balance` gets the full entry, writes it, then extends the same key.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:281-385` — transfer-side `receive_balance` and `spend_balance_no_authorization_check` read contract balances and then call `write_contract_balance` for contract-address endpoints.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:323-389` — `try_get_full_helper` performs supported-key checks, footprint enforcement, indexed storage-map lookup, and clones the `EntryWithLiveUntil`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:531-688` — `extend_ttl` validates the request, re-fetches the entry via `prepare_extend_ttl`, checks live-until and durability constraints, clamps persistent TTLs, and only updates the map if the threshold condition is met.
- `ai-summary/fail/transaction-ledger/summary.md:29-30` — prior rejected TTL/storage-map hypotheses establish that aggregate worker timings in this soroswap trace must be divided by `T=8` clusters before projecting critical-path impact, and similar broader totals landed well below the objective's Medium floor.

### Why It Failed

The optimization target is real, but it is too small for the optimize-soroswap review objective. Even deleting the entire broad `extend key` aggregate would start at about 178.892 ms / 8 = 22.4 ms critical-worker time, and the proposed fused SAC-balance path can only remove a subset of that because it must exclude instance/code/user-storage TTL extensions and still preserve TTL threshold, max-live-until, expired-entry, durability, footprint, and deterministic metering behavior. That filtered opportunity is below the required 3-10% apply-time reduction for a Medium finding.

### Lesson Learned

For soroswap SAC storage hypotheses, a concrete duplicate same-key lookup is not sufficient by itself. The projected saving must be computed from the narrow removable subset after dividing aggregate worker Tracy totals by the configured cluster count; broad storage/TTL zones that are already sub-Medium cannot support a Medium claim when filtered down to one SAC balance subpath.
