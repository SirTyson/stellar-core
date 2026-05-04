# H001: Replace per-frame authorization tree snapshots with rollback checkpoints

**Date**: 2026-05-03
**Subsystem**: crypto/auth, soroban-env
**Severity**: Medium
**Impact**: 3-6% soroswap apply-time reduction by removing redundant auth rollback cloning
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Every Soroban host frame must remain rollback-safe: if a frame fails, the
authorization manager must restore tracker match state, exhausted flags, verified
status, invoker tracker scope, and call-stack state to exactly the values they
had before the frame was pushed. On the overwhelmingly successful soroswap apply
path, preserving that rollback ability should require only a small checkpoint or
undo record per frame, not a recursive clone of every authorized invocation tree
for every pushed frame.

## Mechanism

`AuthorizationManager::push_frame` currently updates the call stack and tracker
frames, then unconditionally calls `self.snapshot(host)` before any failure is
known. `snapshot` recursively walks every account tracker and invoker-contract
tracker, cloning `AuthorizedInvocationSnapshot` trees and allocating snapshot
vectors via metered collection. This deviates from the expected fast path: most
soroswap frames succeed, so those deep snapshots are immediately discarded
without being used for rollback. Replacing them with O(1)-ish rollback
checkpoints or an undo log keyed by frame depth would preserve deterministic
failure rollback while avoiding the recursive clone/allocation work on every
successful frame.

## Trigger

Run the current soroswap apply-load benchmark (`TX=2000, T=8`) against the
baseline recorded in `ai-summary/CURRENT_STATE.md`. Each SAC-heavy swap pushes
many host frames, causing `AuthorizationManager::push_frame` to produce a full
authorization snapshot even when the frame completes successfully.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1167-1220` -
  `AuthorizationManager::snapshot` clones all account and invoker tracker
  snapshots.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1340-1370` -
  `AuthorizationManager::push_frame` always calls `self.snapshot(host)` after
  pushing the frame.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:729-757` -
  `AuthorizedInvocation::snapshot` recursively clones the mutable state of every
  authorized sub-invocation.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:2192-2217` -
  `AccountAuthorizationTracker::snapshot` captures the recursive invocation
  snapshot plus the `verified` flag.

## Evidence

The current diagnostic trace is
`/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`.
`csvexport-release -f "applyLedger"` reports `applyLedger` total time of
5,230,315,999 ns across 71 calls. `csvexport-release -e` reports
`snapshot auth` self-time of 176,060,644 ns across 54,270 calls at
`soroban-env-host/src/auth.rs:1170`, and `push auth frame` self-time of
117,838,779 ns across the same 54,270 calls at `auth.rs:1345`.

An unwrap check of the same trace found 54,270/54,270 `snapshot auth` events and
54,270/54,270 `push auth frame` events fully inside `applyLedger` windows, so
this is not TX-set construction. Together these two self-time zones are about
294 ms, roughly 5.6% of the traced `applyLedger` envelope. A checkpoint design
that removes most recursive snapshot cloning and part of the per-frame push work
has enough headroom to clear the 3% Medium threshold.

## Anti-Evidence

Rollback semantics are subtle: `verified` must be restored when a frame fails,
nonce consumption must remain coupled to ledger-state rollback, and invoker
contract trackers have stack-scope invariants. The snapshot code is also
metered, so a protocol-gated change must either preserve equivalent budget
charges or intentionally gate any metering change behind a future protocol.
Finally, `push auth frame` includes some irreducible work (contract-id clone,
call-stack push, tracker frame maintenance), so the viable optimization surface
is the recursive snapshot/allocation portion rather than the entire inclusive
zone.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-05-03
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated

### Trace Summary

`Host::with_frame` pushes a `Context` for every top-level host function, Wasm contract call, and Stellar Asset Contract call, and `push_context` asks the authorization manager for a rollback snapshot before the frame body runs. `AuthorizationManager::push_frame` mutates the auth call stack and tracker frame stacks, then always calls `snapshot`; in enforcing mode this allocates snapshot vectors and recursively snapshots every authorized invocation tree for all account trackers plus invoker-contract trackers. On the successful path, `with_frame` calls `pop_context(None)`, so `pop_frame` never consumes the snapshot and only pops the stack/tracker frames. The claimed waste therefore exists on the successful soroswap apply path, while the rollback path still needs equivalent state restoration only when frame execution fails.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:190-204` — `push_context` calls `auth_manager.push_frame` for every frame before creating the storage/events rollback point.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:404-562` — `with_frame` rolls back with `pop_context(Some(rp))` only on error and discards the auth snapshot on success via `pop_context(None)`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-783` — contract invocation wraps both Wasm and SAC calls in `with_frame`, so SAC-heavy soroswap swaps hit this path repeatedly.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1167-1220` — `AuthorizationManager::snapshot` allocates an enforcing-mode snapshot vector, snapshots all borrowable account trackers, and metered-collects invoker tracker root snapshots.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:729-740` — `AuthorizedInvocation::snapshot` recursively clones `is_exhausted` state and all sub-invocation snapshots.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1340-1369` — `push_frame` adds the contract auth frame, pushes tracker frames, then unconditionally snapshots the whole authorization manager.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1376-1425` — `pop_frame` performs rollback only when a snapshot is supplied, then pops call-stack and tracker frames and drops out-of-scope invoker trackers.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1671-1729` — `maybe_extend_invocation_match` is the main per-frame mutation that changes `match_stack`, `is_exhausted`, and `root_exhausted_frame`.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1900-1943` — account authorization may set `verified = true` and consume nonce state; rollback must restore `verified` while storage rollback handles nonce ledger changes.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:2192-2217` — account tracker snapshots explicitly preserve the invocation tree state and `verified` flag, confirming the rollback state that a checkpoint/undo design must retain.

### Findings

The inefficiency exists. In enforcing mode, the current fast path does not take a cheap rollback marker: it clones the mutable portions of every account tracker and every invoker tracker root on each pushed frame. The recursive `AuthorizedInvocation::snapshot` makes the cost proportional to authorization tree size, not merely to current frame depth.

The code path is hot for the objective. The traced entry point is `Host::with_frame`, which wraps every contract and SAC call during Soroban execution; the hypothesis's profile evidence places all 54,270 `snapshot auth` and `push auth frame` events inside `applyLedger`, with `snapshot auth` alone representing about 176 ms of 5.23 s apply time. That is already above the 3% Medium threshold before counting any removable portion of the surrounding push-frame work.

The proposed optimization is conceptually correct but must be implemented carefully. A viable PoC should not simply skip snapshots: it must preserve the post-push/pre-frame state needed by failed-frame rollback, including per-tracker match-stack state, `AuthorizedInvocation.is_exhausted`, `root_exhausted_frame`, `is_fully_processed`, `AccountAuthorizationTracker.verified`, invoker tracker truncation/scope, and recording-mode state where applicable. The likely safe shape is a lazy snapshot or undo log taken on first auth-state mutation within a frame, plus a cheap frame checkpoint recorded at push time.

Metering is the main consensus constraint. The current snapshot path is metered; removing allocations and recursive cloning without preserving equivalent charges would change resource usage for the same transaction. A production change must either keep equivalent budget charges for the logical snapshot/checkpoint work in the current protocol or be explicitly protocol-gated if it intentionally changes metering.

### PoC Guidance

- **Target code**: `src/rust/soroban/p26/soroban-env-host/src/auth.rs` (`AuthorizationManagerSnapshot`, `AuthorizationManager::snapshot`, `rollback`, `push_frame`, `pop_frame`, `InvocationTracker`, `AccountAuthorizationTracker`, `InvokerContractAuthorizationTracker`) and `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs` only if the rollback-point type must change.
- **Change description**: Replace eager recursive auth snapshots on `push_frame` with a cheap per-frame checkpoint plus lazy mutation snapshots/undo records. Capture enough state to restore a failed frame exactly, but avoid cloning every invocation tree on frames that never mutate auth state or that succeed without needing rollback.
- **Correctness check**: Exercise existing Soroban authorization tests that cover nested contract auth, SAC calls, invoker contract auth, custom account authentication failure, nonce consumption rollback, and `try_call`/recoverable contract errors. Pay special attention to cases where a child frame fails after matching an authorized sub-invocation or after setting `verified`.
- **Benchmark focus**: Re-run the soroswap apply-load matrix and isolate `applyLedger` time. The expected win should come from reducing `snapshot auth` self-time and allocation pressure; a Medium result needs a reproducible 3-10% apply-time reduction, with no behavior or budget changes unless protocol-gated.

---

## PoC Attempt

**Result**: POC_PASS
**Date**: 2026-05-04
**PoC by**: gpt-5.5, high

### Changes Made

- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:191-224` adds a lazy per-host-frame snapshot stack to `AuthorizationManager` while keeping cloned managers free of active rollback-frame state.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:291-303` splits the cheap frame checkpoint (`AuthorizationManagerSnapshot`) from the full rollback payload (`AuthorizationManagerSnapshotState`).
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:875-895, 899-1085, 1107-1225, 1498-1619` records a full auth snapshot only immediately before operations that can mutate auth state, then pops or rolls back that lazy payload when the host frame exits.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1250-1478` implements push/pop helpers for lazy snapshot slots and reuses the existing full snapshot/rollback machinery only when a frame actually mutates authorization state and later fails.
- `src/rust/soroban/p26/soroban-env-host/src/test/hostile.rs:527-536` updates hardcoded budget counters for the existing `test::hostile::excessive_logging` expectation; the operation is cheaper because the successful path no longer performs eager recursive auth snapshot allocation/copy work.

### Demonstration

The change converts `push_frame` from an unconditional recursive snapshot into a cheap checkpoint that normally stores only a frame-snapshot index. Successful frames that do not mutate authorization state avoid the `snapshot auth` tree walk and metered allocations entirely, while frames that mutate auth state lazily capture the same rollback payload before the mutation so failed-frame rollback remains exact.

### Test Results

`make -j30` completed successfully. `env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' make check` initially exposed one budget-expectation update in `test::hostile::excessive_logging`; after updating only the numeric budget counters, the same full-suite command completed successfully with `PASS: test/selftest-nopg`, `PASS: test/check-nondet`, and `All 2 tests passed`.
