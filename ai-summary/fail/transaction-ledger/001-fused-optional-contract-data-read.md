# H001: Protocol-gated fused optional contract-data read for SAC hot paths

**Date**: 2026-05-05
**Subsystem**: transaction-ledger / Soroban host storage
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by replacing successful `has_contract_data` + `get_contract_data` pairs with one storage lookup and one host dispatch
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When built-in SAC code needs an optional contract-data value, the host should validate the storage key, enforce the footprint, and return `None` or the value with a single storage-map access. A successful optional read should not first call `has_contract_data` and then immediately repeat key conversion, footprint enforcement, storage lookup, VM-dispatch overhead, and result handling through `get_contract_data` for the same key.

## Mechanism

`Host::try_get_contract_data` in `builtin_contracts/storage_utils.rs` is implemented as `has_contract_data(k, t)` followed by `get_contract_data(k, t)` on success. In soroswap SAC transfers, existing balance entries dominate the hot path, so this doubles the persistent-storage read path for `Balance[pair]` keys before balance mutation. A protocol-gated fused optional-read primitive, used by SAC balance/allowance helpers, could call `Storage::try_get` / `try_get_full` once and return an optional host value, preserving missing-key behavior while removing redundant host dispatch, storage-key conversion, footprint/map lookup, and duplicate budget bookkeeping.

## Trigger

Run the current soroswap apply-load benchmark from `ai-summary/CURRENT_STATE.md` (`soroswap, TX=2000, T=8`) with the current diagnostic trace `/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`. Each successful SAC `transfer` calls `spend_balance` and `receive_balance`; contract-address sides use `is_authorized` and then the balance mutation helper, each of which reaches `try_get_contract_data` on the same SAC balance key shape.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/storage_utils.rs:3-14` — `Host::try_get_contract_data` currently implements optional reads as `has_contract_data` then `get_contract_data`.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2211-2249` — `has_contract_data` and `get_contract_data` each reconstruct the storage key and borrow/enforce storage independently.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:253-303` — `Storage::try_get_full` / `try_get` already provide the single-access optional-read primitive needed below the host API.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:44-63,100-145,156-245,260-290,300-365` — SAC balance authorization, receive, spend, authorization-write, and clawback checks amplify optional reads.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:982-999,1358-1377` — invoke-host-function apply and parallel apply place the Rust host storage work under `applyLedger`.

## Evidence

- `csvexport-release -e` on the current soroswap trace reports `has_contract_data,soroban-env-host/src/vm/dispatch.rs:304` at **170,471,757 ns** self-time over **81,375** calls, `get_contract_data,soroban-env-host/src/vm/dispatch.rs:304` at **86,400,163 ns** over **67,724** calls, and `get_contract_data,soroban-env-common/src/vmcaller_env.rs:270` at **80,528,795 ns** over **67,692** calls.
- The underlying storage-read categories are also material in the same trace: `storage get,soroban-env-host/src/storage.rs:329` is **215,980,007 ns** self-time over **305,065** calls, while `map lookup indexed` and `map lookup` together exceed **753 ms** aggregate self-time.
- Timestamp filtering against the 16 long `applyLedger` windows confirms the target zones occur in the measured apply path, not in TX-set construction: in those windows `has_contract_data` occurs **81,149** times, `get_contract_data` occurs **67,612** host-dispatch calls plus **67,571** vmcaller events, and `storage get` occurs **304,187** times.
- This is not the rejected `LastContractDataHas` cache (`002-cache-immediate-contract-data-has-get.md`): that PoC added a speculative one-entry cache after the redundant API split. This hypothesis removes the split itself with an explicit optional-read API, avoiding cache lookup/update overhead and miss-path complexity.

## Anti-Evidence

- The rejected `LastContractDataHas` PoC shows that a cache-shaped workaround can regress despite passing tests. A PoC for this hypothesis should add narrow counters proving the fused API removes actual has/get pairs without adding comparable abstraction overhead.
- Budget totals are protocol-visible. If the fused optional read charges less than the legacy has+get sequence, it must be gated behind a future protocol version; p26 must retain exact current metering.
- Not every `has_contract_data` call is followed by `get_contract_data`, and not every `get_contract_data` comes from SAC optional reads. The reviewer should filter to `builtin_contracts::storage_utils::try_get_contract_data` before claiming the full trace category.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-05
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/success/transaction-ledger/001-typed-sac-balance-storage-fast-path.md`
**Failed At**: reviewer

### Trace Summary

The claimed inefficiency is real in the current source: `Host::try_get_contract_data` calls `has_contract_data` and then `get_contract_data`, and both persistent-storage paths reconstruct the storage key before reaching `Storage`. The SAC `transfer` path calls `spend_balance` and `receive_balance`; for contract addresses these call `is_authorized` and the balance mutation helpers, which route through `try_get_contract_data` on `DataKey::Balance`. However, the already-confirmed `001-typed-sac-balance-storage-fast-path` success record investigated this same found-balance optional-read waste, traced it through the same SAC hot path, and PoC'd a single typed storage lookup for SAC balance reads.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/storage_utils.rs:3-14` — optional contract-data reads are implemented as `has_contract_data(k, t)` followed by `get_contract_data(k, t)` on the found path.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2211-2249` — both generic persistent-storage host functions call `storage_key_from_val` and then borrow storage independently.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:253-303,421-429` — `has` delegates to `try_get_full`, while `try_get` / `try_get_full` already provide the single-access optional-read primitive.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — SAC `transfer` extends instance/code TTL, then calls `spend_balance` and `receive_balance`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:44-63,100-145,156-245,270-365` — contract-address balance reads, authorization checks, receive/spend mutations, authorization writes, and clawback checks all call `try_get_contract_data` for `DataKey::Balance`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-585,1358-1377` and `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-481` — parallel Soroban apply invokes the Rust host inside `closeLedger`, so SAC storage work is on the objective's apply path.
- `ai-summary/success/transaction-ledger/001-typed-sac-balance-storage-fast-path.md:80-95,108-115,123-140` — prior confirmed finding explicitly identifies found-balance `try_get_contract_data` as `has_contract_data` + `get_contract_data`, replaces SAC balance reads with a single typed storage lookup, and reports a reproducible 3.82% soroswap median apply-time improvement.

### Why It Failed

This is a substantial duplicate of an already-confirmed success. The previous finding did not merely overlap the broader SAC storage area; it specifically called out the same `try_get_contract_data` found-balance `has`/`get` split and removed it for the same SAC `Balance[pair]` hot path with a typed single-lookup helper. Re-reviewing it as a new protocol-gated optional-read primitive would rediscover work that has already passed PoC and final review.

### Lesson Learned

When a later hypothesis isolates one component of SAC balance storage overhead, compare it against the confirmed typed SAC balance fast path before treating it as novel. That success record already covers both the generic Val/ScVal conversion round-trips and the redundant found-balance optional-read storage lookup for SAC balance entries.
