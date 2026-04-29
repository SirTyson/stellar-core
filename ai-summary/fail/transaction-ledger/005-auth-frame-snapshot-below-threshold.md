# H005: Skip successful auth frame snapshots for source-account-heavy SAC calls

**Date**: 2026-04-29
**Subsystem**: transaction-ledger / Soroban auth frame management
**Severity**: Low
**Impact**: Soroswap apply-time reduction by reducing authorization snapshot and push-frame work
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Soroswap SAC calls should preserve the same authorization matching, source-account authorization behavior, rollback on failed frames, and diagnostic behavior as today. If all relevant frames succeed and source-account credentials skip cryptographic authentication, auth snapshotting should not dominate apply time.

## Mechanism

`AuthorizationManager::push_frame` snapshots account and invoker-contract trackers for every contract/SAC frame, while `require_auth` clones current frame args and matches the authorization tracker. Since soroswap uses source-account credentials, `AccountAuthorizationTracker::authenticate` returns immediately for the source account, suggesting that snapshot/push work might be avoidable on successful frames. The expected deviation would be spending measurable critical-path time snapshotting state that is never rolled back.

## Trigger

Run the current soroswap Tracy trace from `ai-summary/CURRENT_STATE.md` and filter auth zones inside the longest `applyLedger` window. The window contains `push auth frame`, `snapshot auth`, and `require auth` events on Soroban worker threads during repeated SAC `transfer` calls.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:829-850` — `require_auth` builds the authorized function and invokes the enforcing auth matcher.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1167-1219` — `snapshot` clones auth tracker state for rollback.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1340-1370` — `push_frame` pushes the auth stack frame and immediately snapshots it.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:2076-2080` — source-account authentication returns without account-contract or signature verification.

## Evidence

The path is real and inside `applyLedger`: in the longest current trace window, the hottest worker spent 6.517 ms in `push auth frame`, 4.757 ms in `snapshot auth`, and 5.487 ms in `require auth`. Source inspection confirms source-account credentials skip `authenticate`, leaving frame push/snapshot/matching as the visible auth work.

## Anti-Evidence

The measured auth zones are too small. Even removing all `push auth frame` time from the hottest worker would save only about 6.5 ms in a Tracy outlier window, and a correctness-preserving implementation cannot remove all of it because it must still update the call stack, maintain tracker frames, and preserve rollback for `try_call` and failed nested frames.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated in transaction-ledger records

### Why It Failed

The current soroswap objective only accepts Medium and High hypotheses, and the auth-frame work is below the 3% Medium floor. `push auth frame`, `snapshot auth`, and `require auth` together are visible but not dominant; the hottest individual auth zone is single-digit milliseconds in a Tracy-enabled longest ledger. The design constraints are also strict: snapshots are required for failed-frame rollback, and source-account fast authentication already avoids the expensive signature/account-contract path.

### Lesson Learned

For source-account-heavy soroswap, auth cryptography is already skipped in enforcing mode; remaining auth frame bookkeeping is real but too small to target alone. Future auth optimizations need to combine with a broader frame/context redesign before they can plausibly reach Medium severity.
