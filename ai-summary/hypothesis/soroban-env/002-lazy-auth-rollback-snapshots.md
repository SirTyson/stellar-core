# H002: Lazy Auth Rollback Snapshots for Successful Frames

**Date**: 2026-05-22
**Subsystem**: soroban-env
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by replacing recursive per-frame authorization snapshots with a next-protocol rollback journal while preserving required auth frame advancement
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Every pushed contract frame must still advance the authorization call stack and every account/invoker tracker frame in the same observable order. If a frame fails, authorization state should roll back to the exact pre-frame state; if it succeeds, the frame should commit matched/exhausted authorization progress exactly as today. The optimized path should keep these semantics while avoiding eager recursive snapshots for frames that usually succeed.

## Mechanism

`AuthorizationManager::push_frame` currently pushes tracker frames and then calls `snapshot`, which recursively walks every account and invoker authorization tree to copy `is_exhausted` state into `AuthorizedInvocationSnapshot` before the frame body executes. In soroswap apply most frames succeed, so the snapshot is allocated and recursively populated only to be discarded on successful pop; the actual rollback need is rare and localized to nodes whose match state changes during the frame. A next-protocol rollback journal can preserve frame advancement but log old values lazily on first mutation of `is_exhausted`, `root_exhausted_frame`, `is_fully_processed`, and `verified`, replaying that journal only on error and doing no recursive tree clone on the common successful path.

## Trigger

Run the current soroswap apply-load benchmark. Each top-level router invocation enters multiple Wasm and SAC frames; every frame calls `AuthorizationManager::push_frame`, which pushes account/invoker tracker frames and snapshots authorization state even for no-failure paths. The hypothesis triggers on successful frames in enforcing mode, which dominate the benchmark.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1167-1220` — `AuthorizationManager::snapshot` eagerly snapshots account trackers and invoker contract tracker roots.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1307-1321` — `push_tracker_frame` must still run for every frame to preserve auth tree advancement.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1340-1370` — `push_frame` currently pushes the call-stack frame, pushes tracker frames, and immediately snapshots.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:730-740` and `src/rust/soroban/p26/soroban-env-host/src/auth.rs:2192-2205` — recursive `AuthorizedInvocation` and account-tracker snapshot construction to replace with journal checkpoints.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1681-1731` and `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1787-1797` — mutation and rollback points for exhausted invocation state.

## Evidence

The current accepted soroswap trace shows authorization frame overhead fully inside `applyLedger`: unwrap containment reports 54,270 `push auth frame` events totaling 402,098,282 ns, 54,270 `snapshot auth` events totaling 235,801,940 ns, and 54,270 `push context` events totaling 537,767,407 ns. Self-time also remains material after excluding children: `snapshot auth` is 176,060,644 ns and `push auth frame` is 117,838,779 ns. Source inspection shows `snapshot` recursively clones mutable auth tree state on every frame, while `pop_frame` only needs the snapshot when rollback is requested.

This differs from rejected no-auth-frame shortcuts: it does not skip `push_auth_frame`, `push_tracker_frame`, call-stack updates, or tracker-stack advancement for any frame. It also does not attempt to preserve p26 charge counts; it should be protocol-gated with a revised metering schedule for the cheaper journal representation.

## Anti-Evidence

Prior sparse-auth experiments regressed, so a PoC must prove the journal is simpler than the dense snapshot and does not add cache-unfriendly mutation bookkeeping on the hot match path. Rollback correctness is subtle for `try_call`, custom account authentication, invoker-contract auth, and source-account verification; every mutation that current rollback restores must be journaled before it changes. If most snapshot time is mandatory metering that must be recharged in the next protocol, or if journaling every matched node costs as much as the recursive snapshot, the improvement may fall below Medium.
