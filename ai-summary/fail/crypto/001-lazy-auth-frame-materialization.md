# H001: Lazy Source-Account Auth Frame Materialization

**Date**: 2026-05-22
**Subsystem**: crypto / Rust Soroban authorization
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by avoiding per-frame auth stack and snapshot work for frames that never call `require_auth`
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Every Soroban authorization must still match exactly the same `SorobanAuthorizationEntry` tree, consume the same source-account or address credentials, reject the same unmatched or reused invocations, and roll back the same mutable authorization state on traps. For protocol versions that do not enable the optimization, p26 behavior and metering must remain unchanged. In the optimized protocol, frames that never affect authorization should not eagerly mutate the authorization manager, but a later `require_auth` must see the same current invocation path and produce the same success or `ScErrorType::Auth` result as today.

## Mechanism

`Host::push_context` currently calls `AuthorizationManager::push_frame` for every host context frame before the frame body is known to need authorization. `push_frame` materializes an `AuthStackFrame`, pushes one `MatchState::Unmatched` into every account and invoker tracker, and snapshots every root authorized invocation so rollback can restore it, even though the current soroswap workload has far fewer `require_auth` calls than frame pushes. A lazy materialization path could keep a lightweight count of unsynchronized frames and only extend the auth call stack / tracker stacks when `require_auth` or `authorize_as_curr_contract` first needs the current path; frames that pop without touching auth would skip the eager push/snapshot/rollback work entirely while preserving deterministic matching for frames that do touch auth.

## Trigger

Run the current soroswap apply-load case from `ai-summary/CURRENT_STATE.md` (`soroswap, TX=2000, T=8`). The trace has 54,270 `push auth frame` / `snapshot auth` events in `applyLedger` but only 20,329 `require auth` events, so most frames pay authorization bookkeeping even when no authorization decision is made in that frame.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:Host::push_context:190-204` — eagerly calls `auth_manager.push_frame` and stores an auth rollback snapshot before every context push.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:AuthorizationManager::push_frame:1340-1369` — eagerly appends an auth call-stack frame, updates all trackers, and snapshots authorization state.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:AuthorizationManager::snapshot:1167-1220` — snapshots all enforcing account trackers and invoker-contract tracker roots for rollback.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:AuthorizationManager::require_auth:829-850` — first point where most frames actually need the materialized auth path.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:InvocationTracker::push_frame:1636-1640` — pushes `MatchState::Unmatched` per tracker per frame even when the frame never authorizes.

## Evidence

The current soroswap trace's `applyLedger` subtree reports `push context` at **537.767 ms / 54,270 calls**, `push auth frame` at **402.098 ms / 54,270 calls**, and `snapshot auth` at **235.802 ms / 54,270 calls**. These zones sit under the measured `applyLedger` window, not tx-set construction. By contrast, `require auth` fires only **20,329** times, so at least tens of thousands of frames appear to pay eager auth-stack and snapshot costs without making an auth decision. This differs from the rejected lazy-auth-snapshot hypothesis: it does not merely replace deep snapshots with checkpoints, it avoids materializing auth state for no-auth frames at all and should also reduce associated frame-address object creation and tracker stack mutation.

## Anti-Evidence

The auth zones run inside the parallel Soroban worker phase, so aggregate Tracy time must be normalized by `T=8` before claiming top-line savings. A viable PoC must show that enough of the `push context` / `push auth frame` / `snapshot auth` envelope is actually skipped, not just moved to `require_auth`, and must preserve rollback for frames that fail after having lazily synchronized auth state. If most soroswap frames eventually require auth indirectly, or if lazy synchronization needs to replay nearly all skipped frames on every `require_auth`, the improvement will fall below the Medium threshold.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS
**Failed At**: reviewer

### Trace Summary

`Host::with_frame` pushes every contract or SAC frame through `Host::push_context`, which immediately calls `AuthorizationManager::push_frame` before the frame body can prove it will need authorization. `push_frame` eagerly constructs an auth call-stack frame, pushes `MatchState::Unmatched` through all existing account and invoker trackers, and takes rollback snapshots of tracker roots. `require_auth` later consumes the current auth call stack to build the `AuthorizedFunction`, checks direct invoker-contract authorization, and then matches account trackers; for soroswap source-account entries, authentication itself short-circuits, so the real target is this frame bookkeeping. The inefficiency is real and a lazy synchronization design is plausible, but the measured target surface is below the optimize-soroswap Medium floor after normalizing parallel worker aggregate time.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:404-562` — `Host::with_frame` wraps frame execution, rolls back on error, and always enters `push_context` / `pop_context`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:190-204` — `push_context` calls `auth_manager.push_frame` before storage/event rollback setup and before the context frame is pushed.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1340-1369` — `AuthorizationManager::push_frame` clones the contract id, creates a contract-address host object, pushes an `AuthStackFrame`, calls `push_tracker_frame`, then snapshots authorization state.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1306-1320` and `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1636-1640` — every existing account and invoker tracker receives an eager `MatchState::Unmatched` push.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1167-1220` — enforcing-mode snapshots clone the mutable root state for every account tracker and every invoker-contract tracker.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:829-850` and `src/rust/soroban/p26/soroban-env-host/src/auth.rs:880-1004` — `require_auth` requires the materialized call stack for current-function construction, direct invoker lookup, and account tracker matching.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1801-1840` and `src/rust/soroban/p26/soroban-env-host/src/auth.rs:2076-2080` — source-account credentials create account trackers whose authentication path returns immediately once matched.
- `ai-summary/fail/crypto/summary.md:39` — prior final review of the same per-frame auth snapshot envelope found the cited aggregate `push context` auth work normalizes to about 1.3% serial impact with `T=8`, below the 3% Medium floor.

### Why It Failed

The optimization claim is below the objective severity threshold. The cited `push auth frame` and `snapshot auth` costs are nested in the 537.767 ms aggregate `push context` surface, and the Soroban apply stage runs across 8 worker clusters. Even an impossible elimination of the whole cited `push_context` auth envelope normalizes to roughly Low-tier impact, while a correct lazy implementation would only skip the no-auth subset and would replay/synchronize frames when `require_auth` or `authorize_as_curr_contract` needs the current invocation path. Under the optimize-soroswap review rules, Low/sub-3% findings are rejected rather than downgraded.

### Lesson Learned

Per-frame Soroban auth bookkeeping is a real inefficiency, but Tracy aggregate zones inside `applySorobanStageClustersInParallel` must be divided by worker count before sizing top-line apply-time impact. Future auth optimization hypotheses need either a larger synchronous surface than `push_context` auth materialization or benchmark evidence that the skipped work exceeds the previously established Low-tier ceiling.
