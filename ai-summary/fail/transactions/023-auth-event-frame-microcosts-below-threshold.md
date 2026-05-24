# H023: Auth/Event Frame Micro-Costs Below Threshold

**Date**: 2026-05-24
**Subsystem**: transactions
**Severity**: Low
**Impact**: soroswap worker-path auth/event micro-optimization
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Native Soroswap pool calls and SAC transfers should push the same authorization frames, snapshot/rollback the same auth state, emit the same contract events, and preserve event order and failure marking. Any optimization that prebuilds event topics/data or specializes auth-frame handling should produce identical `ContractEvent` XDR and identical authorization decisions for the current soroswap benchmark.

## Mechanism

The trace shows visible apply-descendant costs in `push auth frame`, `snapshot auth`, `push context`, and `contract_event`, suggesting that prebuilt Soroswap event objects or lighter native-frame auth handling might reduce worker time. However these are worker aggregates spread across T=8 clusters, and only a fraction of each zone is safely removable because the call stack and auth snapshots are consensus-visible for `require_auth` and error rollback.

## Trigger

Run the current protocol-27 `soroswap, TX=2000, T=8` workload and target only native Soroswap pool swap event construction plus SAC transfer auth/event paths.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:829-850` — `require_auth` converts current call stack and args into an authorized function.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1170,1345-1382` — auth snapshot/push/pop frame zones.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1268-1302` — native pool swap event topic/data construction.
- `src/rust/soroban/p26/soroban-env-common/src/vmcaller_env.rs:270` and `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:304` — VM `contract_event` import zones.

## Evidence

Timestamp filtering against `applyLedger` confirms all events in these zones are apply descendants: `push context` totals 479,321,421 ns, `push auth frame` totals 355,817,543 ns, `snapshot auth` totals 211,907,679 ns, and the two `contract_event` zones total about 84,750,979 ns. The source also shows native pool swap rebuilding fixed event topics and data on every swap.

## Anti-Evidence

After dividing worker aggregates by T=8, the whole auth/event/context family is roughly 141 ms against 4,802 ms of `applyLedger`, just under the 3% Medium floor before subtracting mandatory work. The safely removable subset is smaller: SAC `from.require_auth` needs the native pool frame on the call stack, snapshots are needed for rollback, and event XDR must still be constructed for result hashing.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Failed At**: hypothesis
**Novelty**: PASS — not previously recorded as an auth/event micro-cost bundle

### Why It Failed

This angle is below the objective severity threshold. Even combining the visible auth, context, and event zones does not clear Medium after T=8 critical-path conversion, and the actual removable subset is smaller than the combined zone total.

### Lesson Learned

Auth/event/context zones in soroswap traces can look large in aggregate, but they are parallel worker costs with substantial mandatory semantics. Do not promote standalone auth-frame or event-construction micro-optimizations unless a future trace shows this combined family substantially above the Medium floor.
