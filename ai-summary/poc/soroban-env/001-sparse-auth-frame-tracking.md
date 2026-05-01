# H001: Replace dense auth match-stack snapshots with sparse frame tracking

**Date**: 2026-05-01
**Subsystem**: soroban-env
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by removing eager per-frame auth snapshot allocation and per-tracker unmatched-frame pushes from the hot Soroban frame path while preserving rollback behavior
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Authorization matching must remain deterministic and rollback-safe: a failed contract/SAC frame must restore every account and invoker authorization tracker to exactly the state it had before the frame, while a successful frame must leave the same exhausted invocation nodes and verified flags as today. The host should still charge the same protocol-visible auth-frame and snapshot metering, but it should not physically push `MatchState::Unmatched` into every tracker or recursively allocate a full `AuthorizationManagerSnapshot` for frames that usually succeed and discard the snapshot.

## Mechanism

`Host::push_context` calls `AuthorizationManager::push_frame` for every host frame; `push_frame` pushes the call-stack frame into every account/invoker tracker and then immediately calls `snapshot`. In enforcing mode, `snapshot` allocates a `Vec<Option<AccountAuthorizationTrackerSnapshot>>`, recursively snapshots every authorized-invocation tree, and snapshots every invoker tracker root, even though `with_frame` discards the snapshot on the overwhelmingly common success path. A sparse design can keep a global auth frame depth plus per-tracker matched-frame records or an undo journal, so unmatched frames are represented by absence rather than an explicit vector element, and rollback restores only trackers mutated since the frame marker while replaying the existing metering charges.

## Trigger

Run the current soroswap apply-load diagnostic trace from `ai-summary/CURRENT_STATE.md` (`soroswap, TX=2000, T=8`) and export self-time with `csvexport-release -e`. The trace reports `snapshot auth` at `soroban-env-host/src/auth.rs:1170` with 119,848,449 ns self-time over 40,872 calls and `push auth frame` at `soroban-env-host/src/auth.rs:1345` with 82,108,514 ns self-time over 40,872 calls. An unwrap timestamp check against the 70 `applyLedger` windows showed 40,716 of 40,872 events for each zone inside apply, with `snapshot auth` totaling 169,092,717 ns and `push auth frame` totaling 288,779,927 ns of in-apply execution time.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:190-205` — every frame push asks the auth manager for a rollback snapshot before doing any frame work.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1169-1219` — enforcing-mode `snapshot` eagerly snapshots all account trackers and invoker-contract tracker roots.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1307-1322` — `push_tracker_frame` iterates every tracker and pushes an unmatched frame marker.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1340-1370` — `push_frame` adds the auth stack frame, pushes tracker frames, and snapshots immediately.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1636-1645` — `InvocationTracker::push_frame` physically appends `MatchState::Unmatched` for every call-stack frame.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1681-1731` — matching only needs to know whether the current frame is already matched and where the matched path begins, which can be represented sparsely.

## Evidence

- The source-level eager work is exact: every `Frame::ContractVM` and `Frame::StellarAssetContract` pays `push_tracker_frame` and `snapshot`, and every successful frame later calls `pop_context(None)`, discarding the snapshot without rollback.
- The target is under the measured close-ledger apply path, not TX-set construction. The timestamp check placed nearly all auth push/snapshot events inside `applyLedger`.
- `InvocationTracker` documents that `match_stack` has one entry per `AuthorizationManager::call_stack` frame and that most entries are initially `MatchState::Unmatched`. Soroswap’s nested Wasm/SAC calls create many frames, while each authorization tree only matches a small subsequence of them.
- This is distinct from prior soroban-env failures: it does not target budget construction, budget charge tracking, storage-map lookup, Val/ScVal conversion, object visit caching, or wasmi instantiation. It targets the auth manager’s dense per-frame rollback representation.
- The aggregate self-time of `snapshot auth` plus `push auth frame` is about 202 ms in a trace whose aggregate `applyLedger` total is 5.092 s. A sparse representation that removes most physical snapshot allocation and unmatched-frame vector churn has a plausible Medium impact even after preserving existing metering.

## Anti-Evidence

- Rollback correctness is subtle. `verified`, exhausted invocation nodes, `root_exhausted_frame`, `is_fully_processed`, invoker-contract trackers, and recording-mode-only maps all have current rollback semantics; an implementation must either keep full snapshots for recording/test modes or provide equivalent undo records for each mutated field.
- Exact budget behavior constrains the design. Existing `Vec::<usize>::charge_bulk_init_cpy`, `with_metered_capacity`, and recursive snapshot metering must be replayed if the protocol-visible `cpu_insns`/`mem_bytes` are to remain unchanged.
- Some of the `push auth frame` total is required work: constructing `ContractInvocation`, pushing the real auth call-stack frame, and active tracker matching still need to happen. The removable subset is the dense unmatched-frame representation and eager full snapshots.
- If focused instrumentation shows that most soroswap frames actually mutate most trackers or that equivalent metering traversal costs dominate the allocation savings, this may fall below the 3% Medium threshold.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-05-01
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated in `fail/soroban-env` or `success/soroban-env`; cross-subsystem fail/success directories are absent

### Trace Summary

The close-ledger Soroban apply path enters `Host::with_frame` for contract VM and SAC calls, and every push goes through `Host::push_context` before the frame body executes. `push_context` asks `AuthorizationManager::push_frame` for a rollback snapshot, so enforcing-mode frames first append an auth call-stack entry, push an unmatched marker into every account and invoker tracker, and then recursively build an `AuthorizationManagerSnapshot`. On the normal success path `with_frame` calls `pop_context(None)`, causing `AuthorizationManager::pop_frame` to discard the previously built snapshot and merely pop the frame markers.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:404-562` — `with_frame` creates a `RollbackPoint` before executing frame work and only passes it back to `pop_context` on error; successful frames discard the auth snapshot.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:190-205` — `push_context` calls `AuthorizationManager::push_frame`, stores its `AuthorizationManagerSnapshot` in the rollback point, and then pushes the `Context`.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1169-1219` — enforcing-mode `snapshot` allocates an outer `Vec<Option<AccountAuthorizationTrackerSnapshot>>`, snapshots every borrowable account tracker, and collects recursive invoker tracker snapshots.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1224-1304` — rollback consumes the eager snapshot to restore account tracker exhaustion/verified state and truncate/restore invoker trackers on failed frames.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1307-1370` — `push_tracker_frame` iterates account and invoker trackers, and `push_frame` calls it before immediately snapshotting the whole auth manager.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1636-1731` — `InvocationTracker::push_frame` appends `MatchState::Unmatched`; later matching only checks whether the current frame is already matched and updates the current frame's match state if a root/sub-invocation matches.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1776-1798,2193-2216,2230-2274` — tracker snapshots/rollback cover exhausted invocation nodes, root exhaustion bookkeeping, `is_fully_processed`, and account `verified`; invoker trackers share the same invocation tracker mechanics.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_clone.rs:107-132,156-168` — existing auth snapshot and frame-push operations use `charge_bulk_init_cpy`, `with_metered_capacity`, and `metered_collect`, so a replacement must replay those metering effects rather than simply removing charge calls.
- `ai-summary/fail/soroban-env/summary.md:9-18` and individual fail records in `ai-summary/fail/soroban-env/` — prior failures cover budget construction/tracking, storage-map lookup/write, XDR serialization/decode, conversion, object visits, and wasmi instantiation; none cover auth frame tracking or eager auth snapshots.
- `ai-summary/success/soroban-env/002-specialize-storage-map-lookup-fast-path.md:9-26,44-53,88-97` — the only soroban-env success is a storage-map lookup specialization, not an authorization rollback representation change.

### Findings

The inefficiency exists and is in the objective's hot path. In enforcing mode, account trackers are initialized once from the transaction auth entries, but every nested contract/SAC frame still pushes `MatchState::Unmatched` into each active tracker and constructs a full recursive auth snapshot before any work occurs. Successful frames then call `pop_context(None)`, so the snapshot allocation, snapshot vectors, and copied mutable tree state are thrown away without rollback.

The sparse representation is technically viable if it is implemented as an internal auth-manager representation change rather than a semantic change. A global auth frame depth plus sparse per-tracker match records can preserve "current frame already matched" checks, and an undo journal can record the small set of fields that actually mutate in a frame: current-frame match state, exhausted invocation nodes, root-exhausted frame, `is_fully_processed`, account `verified`, and invoker-tracker vector length. Failed frames can replay the undo records and truncate invoker trackers before the auth call-stack frame is popped, preserving the ordering dependency documented in `pop_frame`.

The main correctness constraint is budget and failure-order compatibility. The PoC should keep recording mode and test-only behavior on the existing full-snapshot path unless it deliberately proves equivalent semantics there. In enforcing production mode it must still reproduce the current `Vec::<usize>::charge_bulk_init_cpy` frame-push charges and the recursive snapshot metering from `with_metered_capacity` / `metered_collect`, including budget-limit errors during frame push. It may replace physical snapshot allocation and dense unmatched-frame pushes with charge-only traversal or stored shape metadata, but it must not silently batch away protocol-visible charge counts or change the point at which budget exhaustion is reported.

The severity is plausibly Medium. The cited trace places almost all 40,872 `push auth frame` and `snapshot auth` events inside apply, with about 202 ms combined self-time against roughly 5.1 s aggregate apply time. Some of `push auth frame` is mandatory call-stack construction and all budget charges must remain, so the full zone is an upper bound; however, the removable work includes repeated per-tracker `match_stack` growth and full recursive snapshot materialization on every successful frame. That is broad enough to justify PoC work under the 3% objective floor, provided benchmark validation confirms the sparse design removes most of the physical allocation/vector churn.

### PoC Guidance

- **Target code**: `src/rust/soroban/p26/soroban-env-host/src/auth.rs`, especially `AuthorizationManager::push_frame`, `push_tracker_frame`, `snapshot`, `rollback`, `pop_frame`, `InvocationTracker`, `AccountAuthorizationTracker`, and `InvokerContractAuthorizationTracker`; `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs` should need little or no API change unless the rollback point stores a new sparse auth marker type.
- **Change description**: replace enforcing-mode dense `match_stack: Vec<MatchState>` and eager `AuthorizationManagerSnapshot` allocation with sparse frame-depth tracking plus an undo journal or per-frame mutation log. Keep recording mode on the existing representation initially if that is simpler. Push should record a frame marker and replay existing metering, while matches/authentication append undo records only when they mutate tracker state. Error pop should restore from the marker; success pop should discard the journal entries for that frame.
- **Correctness check**: existing auth tests must continue to cover nested account auth, custom account `__check_auth`, invoker-contract auth, failed subcalls, rollback of `verified` and nonce-consumption side effects, repeated auth attempts after recoverable contract errors, and recording-mode payload generation if that path is touched. Add targeted tests if no existing test fails a nested frame after partially matching a sub-invocation and then retries through another path.
- **Benchmark focus**: run non-Tracy `scripts/run_apply_load_matrix.py` three times against the current baseline and require a reproducible >=3% soroswap median apply-time improvement. Add temporary diagnostic counters for auth frames, tracker-frame pushes avoided, snapshot allocations avoided, undo records written, and rollback count so the measured delta can be attributed to successful-frame snapshot elision rather than noise.

---

## PoC Attempt

**Result**: POC_PASS
**Date**: 2026-05-01
**PoC by**: gpt-5.5, high

### Changes Made

- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:206-329` — added an enforcing-mode undo log, lightweight enforcing snapshot marker, tracker references, and mutation records for invocation exhaustion and account verification state.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:774-796` — added charge-only snapshot traversal and path-based authorized-invocation lookup so enforcing-mode rollback can restore mutated nodes without preallocating full recursive snapshots.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1236-1432` — changed enforcing-mode `AuthorizationManager::snapshot` to replay the old metering costs while storing only undo-log and invoker-tracker lengths, and changed enforcing-mode rollback to replay undo records and truncate invoker trackers.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1840-1971` — changed invocation matching to return an undo mutation describing the exhausted invocation path and prior root-processing state, plus a rollback helper for those mutations.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:2087-2162,2487-2518` — recorded undo entries when account or invoker authorization matching mutates tracker state, and recorded the prior account `verified` flag before setting it.

### Demonstration

The PoC removes the eager recursive enforcing-mode `AuthorizationManagerSnapshot` allocation from every auth frame and replaces it with an undo-log marker that is only replayed on failed frames. It preserves the existing dense match stack and its metering after a sparse-frame attempt exposed rollback/observation risks, so this demonstrates the snapshot-elision portion of the reviewed finding while leaving unmatched-frame push removal for a follow-up change.

### Test Results

Configured with `./configure --enable-ccache --enable-sdfprefs --enable-tracy --enable-tracy-capture --disable-postgres`, built with `make -j $(nproc)`, and ran the full suite with `env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' make check`. Result: all tests passed, including `test/selftest-nopg` and `test/check-nondet`.
