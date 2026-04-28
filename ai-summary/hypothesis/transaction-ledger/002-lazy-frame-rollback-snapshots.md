# H002: Make Soroban frame rollback snapshots lazy or delta-based for successful frames

**Date**: 2026-04-28
**Subsystem**: transaction-ledger / Soroban host frame management
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by avoiding eager storage/auth rollback copies on the overwhelmingly successful contract-call path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Every contract frame must still roll back storage, events, and authorization state exactly when the frame exits with an error. However, a successful frame should not have to eagerly clone the full host `StorageMap` and snapshot all authorization trackers just in case rollback is needed. The efficient apply path should create a cheap rollback token on frame entry, record only the mutations that occur inside the frame, and discard the token on success while preserving identical rollback state for error exits.

## Mechanism

`Host::with_frame` always calls `push_context`, and `push_context` eagerly constructs a `RollbackPoint` before the frame body runs. That rollback point clones `self.try_borrow_storage()?.map.metered_clone(self)?`, records event length, and calls `AuthorizationManager::push_frame`, which snapshots account and invoker-contract trackers. In the common soroswap path these frames succeed, so `with_frame` later calls `pop_context(None)` and drops the eager `RollbackPoint`; the storage map clone and auth snapshots were paid only for an error path that was not taken.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=4000, T=8`) and inspect the longest `applyLedger` interval. The interval contains 11,698 `push context` events totaling 125.383 ms of worker time, 11,698 `push auth frame` events totaling 93.620 ms, and 11,698 `snapshot auth` events totaling 55.323 ms, all under the parallel Soroban invoke path. Soroswap swaps are expected-success transactions, so nearly all of these rollback snapshots are discarded by `pop_context(None)`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:40-48` — `RollbackPoint` currently owns a full `StorageMap`, event length, and `AuthorizationManagerSnapshot`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:190-204` — `push_context` eagerly snapshots auth and clones the full storage map before every frame body.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:210-229` — `pop_context` restores the cloned storage map only when passed `Some(RollbackPoint)`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:404-562` — `with_frame` discards the rollback point on success via `pop_context(None)` and only uses it on errors.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1167-1220` — `AuthorizationManager::snapshot` copies all account tracker snapshots and invoker-contract tracker root snapshots per frame.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1222-1304` — `AuthorizationManager::rollback` consumes the snapshot only for error exits.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:25-27` and `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:14-42,357-365` — host storage uses `MeteredOrdMap` over a `Vec`; cloning the map copies the vector structure even though entries are `Rc`-backed.

## Evidence

- Tracy scope check: the cited `push context`, `push auth frame`, and `snapshot auth` events are descendants of the longest `applyLedger` window (`ledger/LedgerManagerImpl.cpp:1484`, 1,810.920 ms), reached through `applyParallelPhase` and `InvokeHostFunctionOpFrame doParallelApply`.
- The source shows the eager work is on every frame entry, independent of whether the frame mutates storage or eventually fails. On success, `with_frame` deliberately calls `pop_context(None)`, so the storage clone and authorization snapshot are not used.
- Soroswap is frame-heavy: the same apply window has 4,389 Wasm `Vm::invoke_function_raw` calls and 2,921 `SAC transfer` calls, each entering host frames and auth frames. This makes rollback bookkeeping a repeated per-call overhead rather than a one-time setup cost.
- A lazy rollback token is deterministic because it does not reorder contract execution or parallelism. It only changes the representation of the pre-frame state: from "clone everything on entry" to "record enough undo information as writes/auth mutations occur, then replay it if the frame fails".
- The combined frame-entry rollback bookkeeping is large enough for Medium severity. Even if only part of `push context`/`snapshot auth` is eliminated, a 20 ms wall-time reduction is plausible on the 620.996 ms soroswap baseline.

## Anti-Evidence

- This is a redesign, not a one-line micro-optimization. Storage rollback, instance-storage persistence, re-entrant instance reloads, auth tracker frames, event rollback, and diagnostic behavior must all remain byte-for-byte equivalent on failing frames.
- The storage clone is shallow for ledger entries because `StorageMap` stores `Rc<LedgerKey>` and `Rc<LedgerEntry>` values, so the clone cost may be lower than the total `push context` time suggests. Auth snapshots and metered clone charges may dominate instead.
- A delta-based rollback layer must still charge memory/CPU consistently. If eager snapshot metering is currently part of observable budget consumption, the PoC must either preserve equivalent deterministic charges or intentionally protocol-gate any metering change with tests.
- Some frame state can mutate before the contract body fails, including authorization tracker progress and instance storage. A lazy scheme must create undo records before each mutation, not after, or it can fail to restore the exact pre-frame state.
