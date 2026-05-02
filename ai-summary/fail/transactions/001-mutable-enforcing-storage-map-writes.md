# H001: Mutable Enforcing StorageMap Writes for SAC Balance Updates

**Date**: 2026-05-02
**Subsystem**: transactions
**Severity**: Medium
**Impact**: soroswap apply-time reduction by removing StorageMap write amplification in parallel Soroban workers
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Applying a soroswap ledger should execute each SAC transfer with the same authorization checks, balance updates, TTL bumps, budget charges, rollback behavior, and deterministic final `LedgerEntryChange` output. Updating a persistent SAC balance should replace the corresponding `StorageMap` entry while preserving sorted key order and existing metering semantics, but it should not physically rebuild the whole ordered map for every individual balance write when the host already owns the enforcing storage map for a single invocation.

## Mechanism

The current path routes every persistent storage write through `Storage::put_opt_helper`, which calls `self.map.insert(...)`. `MeteredOrdMap::insert` performs a binary search and then constructs a fresh map by cloning the prefix and suffix through `from_exact_iter`, so every SAC balance write physically copies the entire map even though only one key changes. Soroswap invokes SAC `transfer`, which calls `spend_balance` and `receive_balance`; each side eventually calls `write_contract_balance`, so the hot worker path repeatedly rebuilds small-but-nontrivial enforcing storage maps. A storage-specific mutable/COW write path that preserves sorted order, charges the same logical budget, and snapshots only when host rollback requires it should reduce the `new map`/lookup component without changing consensus-visible output.

## Trigger

Run the current soroswap apply-load scenario (`soroswap, TX=2000, T=8`) with the current diagnostic trace. The issue is triggered by many contract-to-contract SAC transfers in which both sender and receiver balances are updated in persistent contract data.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:333-357` — `put_opt_helper` enforces footprint access and replaces the storage map with `self.map.insert(...)`.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:196-222` — `MeteredOrdMap::insert` clones prefix/suffix and rebuilds a full map through `from_exact_iter`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:74-95` — `write_contract_balance` performs the persistent SAC balance write and TTL extension.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — SAC `transfer` calls `spend_balance` and `receive_balance` on the soroswap path.

## Evidence

The latest soroswap trace from `ai-summary/CURRENT_STATE.md` is `/mnt/nvme2/apply-load/1e0b14a6b879-20260430-160627/logs/1e0b14a6b879-20260430-160627-02-soroswap-tx-2000-t-8.tracy`. Timestamp-filtering zone events against `applyLedger` found 70 `applyLedger` windows totaling 5,092,107,609 ns. Inside those windows, `SAC transfer` accounted for 10,140 events / 2,245,135,102 ns total, `new map` accounted for 127,552 events / 378,707,696 ns total at `host/metered_map.rs:148`, and map lookup zones accounted for 961,422 events / 1,023,076,910 ns total. The structural source pattern explains the `new map` count: every `insert` rebuilds a vector-backed ordered map rather than mutating the owned storage map in place.

## Anti-Evidence

`MeteredOrdMap` immutability is useful for rollback/snapshot behavior, so a naive in-place mutation would be unsafe if nested host frames rely on old map values. The optimization must either be restricted to enforcing storage maps when no rollback snapshot aliases the map, or introduce an explicit COW/snapshot layer that keeps old maps alive for rollback while avoiding rebuilds in the common no-rollback SAC transfer path. It must also preserve the existing budget charges even when physical copying is removed, because metering is consensus-visible.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-02
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS
**Failed At**: reviewer

### Trace Summary

The local inefficiency exists: SAC `transfer` updates contract balances through `write_contract_balance`, `Host::put_contract_data`, `put_contract_data_into_ledger`, `Storage::put`, and finally `Storage::put_opt_helper`, where `MeteredOrdMap::insert` rebuilds a new vector-backed ordered map. However, the soroswap scenario sets `T=8`, and the apply path runs one async worker per cluster, so worker-zone totals inside one `applyLedger` window are aggregate parallel work rather than directly removable wall time. Even a perfect implementation that removed the entire cited `new map` total would recover at most about `378,707,696 ns / 8 = 47,338,462 ns` across the traced windows, which is only about 0.93% of the 5.09s `applyLedger` wall-window total and much less against the authoritative top-line close/apply medians. This is below the optimize-soroswap Medium threshold.

### Code Paths Examined

- `scripts/run_apply_load_matrix.py:120-124,417-424` — the active soroswap benchmark is `TX=2000, T=8`, and `T` is written to `APPLY_LOAD_LEDGER_MAX_DEPENDENT_TX_CLUSTERS`.
- `src/simulation/ApplyLoad.cpp:2672-2682,3389-3393` — soroswap setup creates one token pair per configured cluster and round-robins swaps across pairs to achieve maximum parallelism.
- `src/ledger/LedgerManagerImpl.cpp:2483-2520,2530-2574,2622-2640` — each stage launches one `std::async` worker per cluster and waits for all futures, so per-worker Tracy child-zone sums must be converted to critical-path time before severity assessment.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584,1358-1378` — parallel invoke-host-function application calls the Rust bridge for each Soroban transaction from the worker path.
- `src/rust/src/soroban_invoke.rs:7-38` and `src/rust/src/soroban_proto_any.rs:405-488` — the C++ bridge dispatches to the protocol host, invokes `e2e_invoke::invoke_function`, then extracts metered resource usage and ledger effects.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:426-452,485-507,1068-1082` — enforcing storage is built for the host invocation, an initial storage snapshot is retained for ledger-change extraction, and final changes are emitted after `Host::try_finish`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — SAC `transfer` performs `spend_balance` and `receive_balance`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:74-95,100-145,170-230` — contract-address balance receive/spend paths read the balance, mutate the amount, call `write_contract_balance`, and extend the balance TTL.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2190-2208,2293-2317` — persistent contract data writes and TTL extensions dispatch to ledger storage.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:509-564` — persistent `put_contract_data` checks existence, reads the current entry, mutates `ContractDataEntry.val`, and calls `Storage::put`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:333-389,500-515` — `put_opt_helper` enforces read-write footprint access and replaces `self.map` with `self.map.insert`; TTL extension uses the same immutable insert when it actually bumps live-until.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:144-160,196-222` — `insert` performs a lookup, clones prefix/suffix entries, and reconstructs a new map through the `new map` Tracy zone.

### Why It Failed

The optimization target is real, but it is below the objective severity threshold. The hypothesis treats the 378.7ms `new map` total as if it were serial apply time, but in this benchmark it is worker aggregate time distributed across 8 independent soroswap clusters. Dividing by the configured cluster count gives a sub-1% upper bound versus the cited `applyLedger` windows, and the bound is smaller against the authoritative non-Tracy top-line close/apply medians. The proposed mutable/COW path would also need to preserve existing budget charges and the initial-storage snapshot used by ledger-change extraction, but even assuming a perfect correctness-preserving implementation, the projected impact does not reach the required 3-10% Medium band.

### Lesson Learned

For soroswap parallel-apply hypotheses, aggregate Tracy totals for zones executed in worker threads must be converted to critical-path time using the configured cluster count before promotion. A local hot-looking storage operation can be real and still be invalid for this objective if its fully removable wall-time contribution is below the Medium floor.
