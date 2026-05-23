# H007: Direct SAC Transfer Event XDR Emission

**Date**: 2026-05-23
**Subsystem**: soroban, soroban-env-host
**Severity**: Low
**Impact**: Soroswap apply-time reduction by avoiding host-object event construction in SAC `transfer`
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For a Stellar Asset Contract `transfer`, the host should emit the exact same `ContractEvent` as the current built-in path: event type `Contract`, the active SAC contract ID, topics `["transfer", from, to, name]`, and data equal to the amount or muxed-amount map. The ledger changes, authorization checks, TTL extensions, balance mutations, event ordering, result hash, and diagnostic behavior should remain identical.

## Mechanism

The current SAC event path constructs event topics and data through host objects and then calls the generic `contract_event` host function. For built-in SAC code this is internal host work, so a specialized helper could build the `ContractEvent` XDR shape directly and append it to the event buffer without constructing temporary `HostVec`/`HostMap` objects or converting them back to `ScVal`. The expected deviation was that this temporary object path might account for a meaningful fraction of the in-apply `SAC transfer` self-time.

## Trigger

Run the current soroswap apply-load diagnostic trace from `ai-summary/CURRENT_STATE.md` (`soroswap, TX=2000, T=8`). Each accepted swap emits SAC transfer events on the apply path, so every `SAC transfer` call reaches `event::transfer_maybe_with_issuer` and then `event::transfer`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — `transfer` performs auth, TTL extension, balance mutation, and calls SAC event emission.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:47-65` — `transfer_maybe_with_issuer` chooses transfer/mint/burn shape.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:94-113` — `transfer` builds host-object topics/data and calls `contract_event`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:770-816` — C++ receives encoded events and validates total event bytes inside apply.

## Evidence

Timestamp filtering against the 71 `applyLedger` windows confirms the relevant parent path is in scope: `SAC transfer` has 15,665 in-apply events and 2.477s aggregate worker total, with 638.6ms self-time in the self-time export. The event subpath is visible but much smaller: `contract_event` accounts for 35.8ms self-time at `vmcaller_env.rs:270` and 21.8ms at `vm/dispatch.rs:304` across the full trace, and `collectEvents` on the C++ side is only 30.4ms self-time. This suggests direct SAC event construction is technically possible but attacks a narrow subset of a broad parent zone.

## Anti-Evidence

The exact event object shape is protocol-visible through the transaction result hash and metadata, so a direct builder must preserve ordering, contract IDs, muxed transfer data, issuer mint/burn classification, and metered conversion behavior. Prior retained failures already show that SAC address/metadata/event-object cleanup is below the objective threshold when separated from the broad `SAC transfer` zone. The measurable direct event surface is far below the 3% Medium floor once aggregate worker time is normalized by `NUM_CLUSTERS`.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Failed At**: hypothesis
**Novelty**: PASS — narrower than prior broad SAC transfer/native pipeline proposals; this isolates direct event construction only.

### Why It Failed

The removable event-construction slice is too small. Even fully eliminating the visible `contract_event` and C++ `collectEvents` self-time would recover roughly 88ms aggregate worker CPU across the diagnostic run; divided by 8 workers and 71 apply windows, this is about 0.15ms/ledger, or well under 1% of the 218ms soroswap median baseline. Any metering-preserving implementation would recover less.

### Lesson Learned

Do not size SAC event optimizations from the parent `SAC transfer` zone. Direct event emission is a plausible cleanup, but its isolated apply-time envelope is sub-Low for soroswap and overlaps the retained "SAC event-object cleanup below threshold" lesson.
