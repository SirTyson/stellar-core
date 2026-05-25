# H043: Direct-Invoker Precheck Before Building `AuthorizedFunction` in `require_auth`

**Date**: 2026-05-25
**Subsystem**: soroban-env
**Severity**: Low
**Impact**: Below objective threshold; would only remove a small auth argument-clone/setup subset
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When a SAC transfer frame calls `from.require_auth()` and the previous contract frame is exactly the `from` address, authorization should succeed via the direct-invoker rule without needing account authorization-tree matching. The observable result should be `Ok(())`, with the same auth tracker state and same errors for all non-direct-invoker cases.

## Mechanism

`Host::require_auth` currently clones the current frame's argument vector before `AuthorizationManager::require_auth` can check the direct-invoker shortcut. For native pair output SAC transfers, `from` is normally the pair contract and the previous frame is the same pair contract, so the constructed `AuthorizedFunction` is not needed when `maybe_check_invoker_contract_auth` returns true. A precheck could avoid the argument clone and authorized-function construction for this subset.

## Trigger

Run the current soroswap benchmark and inspect native pair output SAC transfers. `Address::require_auth` calls `Host::require_auth`, which clones the current SAC frame args before the auth manager checks whether the direct invoker already authorizes the call.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host.rs:3629-3656` — clones current frame args before calling `AuthorizationManager::require_auth`.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:829-850` — builds `AuthorizedFunction` before `require_auth_internal`.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:875-935` — direct-invoker shortcut can return before account tracker matching.

## Evidence

The source has an ordering inefficiency: direct-invoker success does not need the current invocation args, but the args are cloned before the direct-invoker check. This is on the soroswap native pair/SAC transfer path.

## Anti-Evidence

The Tracy zone is too small for this objective. `require auth` at `soroban-env-host/src/auth.rs:835` has only 26,115 calls, 47,311,483 ns self-time, and 160,547,758 ns total time in the current trace; even removing the whole zone would be below the 3% Medium threshold after 8-way parallel apply normalization, and the actually removable arg-clone/precheck subset is much smaller.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated as a standalone direct-invoker precheck

### Why It Failed

The mechanism is real but far below the objective severity floor. The entire `require auth` zone is only a small fraction of the apply trace, and the proposed precheck would remove only the direct-invoker argument-clone/setup subset, not the surrounding SAC transfer, frame, storage, TTL, or event work.

### Lesson Learned

Auth shortcuts must be sized against the dedicated auth zone, not the full SAC transfer parent. Direct-invoker fast paths can be correctness-preserving but still too small for the soroswap Medium-or-High hypothesis stage.
