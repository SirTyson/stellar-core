# H002: Stack-only SAC balance-slot mutator to fuse read, write, and TTL update

**Date**: 2026-05-26
**Subsystem**: transaction-ledger / Stellar Asset Contract balance storage
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by eliminating repeated contract-balance storage lookups without the failed transfer-local context overhead
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For a contract-address SAC balance update in the soroswap path, the host should construct the balance `LedgerKey` once, read the existing balance slot once, perform authorization and arithmetic on a stack-local `BalanceValue`, then write the updated `ContractDataEntry` and apply the TTL extension using the same `EntryWithLiveUntil` information. It should preserve the same auth decisions, error codes, ledger entry values, TTL threshold/clamping behavior, event output, and budget semantics, while avoiding a second or third lookup of the same balance key inside one SAC transfer endpoint.

## Mechanism

After the typed SAC balance fast path, `balance.rs` still has a repeated same-key pattern: `receive_balance` calls `is_authorized`, then reads the contract balance again, and `write_contract_balance` calls `Storage::try_get_full` again before writing; `spend_balance` has the same authorization read, mutation read, and write-time read sequence. A stack-only mutator can avoid the failed `002-sac-transfer-balance-slot-context` overhead by not allocating or storing a transfer context at all: make one monomorphic helper that takes an `Address`, builds the key once, reads `EntryWithLiveUntil` once, calls a closure to validate and mutate `BalanceValue`, and then writes plus extends TTL from that same slot metadata. This changes only the local SAC helper call graph, not cluster-level journals or cross-frame state.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) with the current p26 host. Each swap executes SAC token transfers where the pool/pair side is a contract address; those contract endpoints enter `read_balance`, `receive_balance`, `spend_balance`, `is_authorized`, and `write_contract_balance` in `balance.rs`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:150-178` — `read_contract_balance` and `extend_contract_balance_ttl` are separate operations over the same key.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:213-224` — contract `read_balance` reads and then extends the same balance key.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:235-299` — `write_contract_balance` re-fetches the current entry with `try_get_full` before replacing only `ContractDataEntry.val`, then extends TTL.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:303-346` — `receive_balance` calls `is_authorized`, then reads the same contract balance again before calling `write_contract_balance`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:357-427` — `spend_balance` repeats the same authorization-read / mutation-read / write-read sequence.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:323-389,418-489,531-688` — indexed enforcing `get`, `put`, and TTL extension primitives that the mutator should reuse or factor so footprint enforcement and TTL checks stay equivalent.

## Evidence

- Current diagnostic trace path: `/mnt/nvme2/apply-load/9e61f0301cf2-20260525-143357/logs/9e61f0301cf2-20260525-143357-02-soroswap-tx-2000-t-8.tracy`.
- Timestamp filtering confirms these zones are inside `applyLedger`: `SAC transfer` totals **2,644.783 ms** over 16,005 calls, `storage get` totals **718.937 ms** over 328,819 calls, `storage put` totals **145.631 ms** over 40,092 calls, and `extend key` totals **309.747 ms** over 112,247 calls.
- The source-level repeated-read sequence is concrete and local: for an existing contract balance, `receive_balance` reads once for authorization, reads again for the amount, and `write_contract_balance` reads a third time to obtain the current entry/live-until before replacing `entry.val`. The spend path follows the same shape.
- This is not the same as the failed transfer-local context/journal PoC: that approach carried reusable slot state across SAC sub-helpers and cluster/native paths and regressed due to extra indirection/allocation. The proposed mutator is a single stack frame with no heap context, no cross-call cache, and no cluster journal; it should be benchmarked as a lower-overhead design specifically addressing the prior failure lesson.

## Anti-Evidence

- Prior `002-sac-transfer-balance-slot-context.md` was viable at reviewer but regressed soroswap at final review, so the reviewer should demand narrow counters proving the stack-only helper removes more lookup work than it adds in call/branch overhead.
- Prior `001-fuse-sac-balance-storage-ttl.md` rejected standalone TTL fusion as below threshold. This hypothesis must show the combined read/write/TTL fusion for contract balance endpoints, not TTL fusion alone.
- Budget accounting is protocol-visible. If the helper skips existing `Storage::get`, `Storage::put`, `extend_ttl`, metered clone, or bulk-copy charges, it must either reproduce equivalent charges or be explicitly protocol-gated with budget expectation updates.
- The helper must preserve all current error decoration and missing-balance behavior, especially the difference between authorization checks, zero-balance spends, missing entries, non-contract addresses, clawback flags, and classic account/trustline paths.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — related to prior `001-fuse-sac-balance-storage-ttl.md` and `002-sac-transfer-balance-slot-context.md`, but this stack-only local mutator variant was not previously recorded as an exact duplicate
**Failed At**: reviewer

### Trace Summary

The repeated same-key lookup pattern exists on the current closeLedger path: parallel Soroban apply reaches `InvokeHostFunctionOpFrame::doParallelApply`, enters the Rust host, dispatches `ContractExecutable::StellarAsset` through `StellarAssetContract`, and `transfer` calls `spend_balance` and `receive_balance`. For contract addresses, each side calls `is_authorized`/`read_contract_balance`, then reads the same balance again, then `write_contract_balance` re-fetches the full entry and calls `extend_contract_balance_ttl`, whose `Storage::extend_ttl` path fetches the same full entry again before applying TTL math. However, the removable portion is only a subset of the already-small `storage get`/`extend key` aggregate, and after T=8 cluster normalization it cannot reach the objective's 3% Medium floor.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:1462-1535` — `applyLedger` is the apply-thread closeLedger entry point.
- `src/ledger/LedgerManagerImpl.cpp:2784-3030` — `applyTransactions` dispatches parallel Soroban phases through `applyParallelPhase` and `applySorobanStages`.
- `src/ledger/LedgerManagerImpl.cpp:2488-2518,2530-2670` — each cluster worker calls `TransactionFrame::parallelApply`; worker totals must be normalized by cluster parallelism.
- `src/transactions/TransactionFrame.cpp:2385-2448` — successful Soroban transactions call the single operation's `parallelApply`.
- `src/transactions/OperationFrame.cpp:175-188` and `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1378` — InvokeHostFunction parallel apply constructs the host-function helper and executes the Rust host path.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:782-835` — `call_contract_fn` dispatches `ContractExecutable::StellarAsset` directly to `StellarAssetContract.call`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — SAC `transfer` extends instance/code TTL, then calls `spend_balance` and `receive_balance`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:150-178,235-299,303-427,431-441` — contract-balance authorization, mutation, write, and TTL extension perform repeated same-key storage access.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:323-389,418-489,531-688` — `try_get_full`, `put`, and `extend_ttl` enforce footprint access, clone entries, compute TTL threshold/clamping, and update the storage map; the current code already has indexed enforcing-map fast paths for get/put/TTL replacement.

### Why It Failed

The inefficiency is real, but it is below this objective's severity threshold. The hypothesis's own trace gives `storage get` at 718.937 ms across 328,819 calls and `extend key` at 309.747 ms across 112,247 calls for the traced run; the stack mutator can remove only the SAC balance subset of those aggregates, not all storage gets, all TTL extensions, `storage put`, event emission, auth, arithmetic, footprint validation, or ledger write work. Even an optimistic contract-transfer estimate of saving several same-key gets per 16,005 SAC transfers is only a few hundred milliseconds of aggregate worker CPU; divided by 8 clusters and the benchmark ledgers, this is sub-millisecond to low-single-millisecond per ledger, below the 3% Medium floor for a ~200-300 ms soroswap apply baseline. Removing or bypassing the Storage calls also has protocol-visible budget and error-decoration implications unless carefully factored or gated, so the practical removable wall time is smaller than the broad-zone upper bound.

### Lesson Learned

For SAC balance-storage hypotheses, proving duplicate local reads is not enough. The opportunity must be sized from narrow SAC-balance-only counters, normalized by Soroban cluster parallelism, and compared to the top-line apply-time floor; broad `storage get`/`extend key` aggregates include many mandatory non-balance accesses and overstate the impact of a local balance-slot helper.
