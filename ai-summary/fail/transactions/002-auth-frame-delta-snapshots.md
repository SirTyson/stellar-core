# H002: Delta Snapshots for Native Auth Frames

**Date**: 2026-05-25
**Subsystem**: transactions / Soroban authorization frames
**Severity**: Medium
**Impact**: soroswap apply-time reduction in nested native contract frame push/pop
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Nested router, native pool, and SAC calls should push authorization and host frames, allow `require_auth` to match the same authorized invocation tree, and roll back storage/events/auth state identically on failure. Successful calls should produce the same auth consumption, event ordering, ledger changes, and diagnostics, and no execution order or worker parallelism should change.

## Mechanism

Every `Host::push_context` calls `AuthorizationManager::push_frame`, which then snapshots authorization state by iterating account trackers and cloning tracker snapshots even for native frames that mostly add one call-stack frame and one tracker frame. A delta checkpoint that records call-stack length, tracker-stack lengths, and per-tracker mutation cursors could roll back native frame pushes by truncation instead of cloning the full tracker snapshot on every nested SAC/pool call. This targets a combined apply-descendant frame/auth surface rather than a single sub-threshold micro-zone and preserves determinism because it changes only local rollback representation inside each worker.

## Trigger

Run the current `soroswap, TX=2000, T=8` workload with protocol-gated native Soroswap pool swap enabled. The optimization should apply to nested native `Frame::NativeContract` and `Frame::StellarAssetContract` pushes created during the router/pool/SAC call tree, while generic Wasm frames or any frame with unsupported auth mutation patterns should continue using the existing full snapshot.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:218-236` — `Host::push_context` snapshots storage/events/auth before pushing every context.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1336-1370` — `AuthorizationManager::push_frame` pushes the contract auth stack frame and immediately snapshots.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1167-1190` — `AuthorizationManager::snapshot` iterates account trackers and clones per-tracker snapshots in enforcing mode.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1373-1395` — `pop_frame` rolls back from the snapshot before popping call-stack frames.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1666-1730` — `call_n_internal` is the repeated nested-call entry point exercised by router, pool, and SAC calls.

## Evidence

Timestamp filtering against the current soroswap trace confirms the relevant zones are inside `applyLedger`: `push context` overlaps apply for 52,184 events and 533,787,131 ns total; `push auth frame` for 52,185 events and 395,868,465 ns; and `snapshot auth` for 52,185 events and 235,081,358 ns. Dividing the combined 1.164 s worker aggregate by T=8 gives roughly 145 ms of critical-path upper bound, about 3.3% of the 4.437 s Tracy `applyLedger` envelope, before accounting for native-frame specificity.

## Anti-Evidence

Prior single-zone frame rollback work was below threshold, so this is only viable if the delta representation removes a large fraction of the combined `push context`/`push auth frame`/`snapshot auth` path for the soroswap native call tree. The rollback model is subtle: it must preserve recursive auth, failed-call rollback, borrowed tracker behavior, and host object metering; if the safely delta-encoded subset is only a few vector length checks, it falls below the objective threshold.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — substantially overlaps `ai-summary/fail/transactions/023-auth-event-frame-microcosts-below-threshold.md`
**Failed At**: reviewer

### Trace Summary

`call_n_internal` dispatches the optimized Soroswap pool path and SAC calls through `call_contract_fn`, which still wraps each native/SAC invocation in `with_frame`. `with_frame` calls `push_context`; `push_context` enters `AuthorizationManager::push_frame`, pushes an auth call-stack frame and tracker frames, then takes an authorization snapshot before the contract body executes. On failure, `with_frame` calls `pop_context(Some(rp))`, which rolls storage/events back and invokes `AuthorizationManager::pop_frame`; auth rollback must happen before frame pop so invoker-contract trackers can interpret the current call stack correctly.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:781-834` — `call_contract_fn` creates `Frame::NativeContract` for the Soroswap pool fast path and `Frame::StellarAssetContract` for SAC, but both continue through `with_frame`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:433-594` — `with_frame` pushes a context, executes the call, persists/reloads instance storage as needed, and rolls back only on error.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:222-236` — `push_context` performs the full auth push/snapshot plus storage clone, event length snapshot, budget charge, and context-stack push.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1167-1220` — `AuthorizationManager::snapshot` allocates per-account tracker snapshots and snapshots all invoker-contract tracker roots.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1222-1304` — rollback restores account tracker snapshots and truncates/restores invoker-contract trackers.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1306-1370` — `push_frame` clones contract/function identity into the auth call stack, pushes one tracker frame per existing tracker, and then snapshots.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1373-1433` — `pop_frame` deliberately rolls back before popping the auth call-stack and tracker frames.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1672-1721` and `2193-2217` — `require_auth` mutates `is_exhausted` and `verified`, which explains why a snapshot or equivalent mutation log is semantically required.

### Why It Failed

The measured severity is below the objective's Medium threshold. The hypothesis sums `push context`, `push auth frame`, and `snapshot auth`, but these Tracy zones are nested by construction: `snapshot auth` occurs inside `push auth frame`, which occurs inside `push context`. The non-double-counted upper bound for the whole frame-push path is therefore the `push context` total, about 533.8 ms worker aggregate / T=8 = 66.7 ms, or roughly 1.5% of the 4.437 s apply envelope before subtracting mandatory work. The proposed delta snapshot can at most remove part of `snapshot auth` and some rollback-copy work; it cannot remove storage-map cloning, event snapshotting, auth call-stack pushes, tracker-frame pushes, contract-address host-object creation, budget charges, context-stack pushes, or success-path frame pops. That safely removable subset is well under the 3% acceptance floor and is also covered by the prior failed auth/frame micro-cost investigation.

### Lesson Learned

Do not add nested Tracy zones together when estimating apply critical-path impact. For `push_context`/`push_frame`/`snapshot`, use the outermost inclusive zone as the upper bound, then subtract the required frame/auth semantics before comparing to the objective threshold.
