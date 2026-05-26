# H075: Fuse Contract-Event Externalization and XDR Encoding

**Date**: 2026-05-26
**Subsystem**: transaction-ledger / Soroban host event bridge
**Severity**: Low
**Impact**: Below objective threshold; avoids one intermediate event-vector materialization in the apply-mode event path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When an apply-mode Soroban invocation succeeds, the host must still externalize every non-failed, non-diagnostic contract event and serialize those events to XDR bytes because the bytes feed C++ event accounting, metadata, and the transaction success hash. The efficient path should perform this required externalization and XDR encoding without first building an intermediate `Events(Vec<HostEvent>)` object that `encode_contract_events` immediately filters and re-walks.

## Mechanism

`Host::try_finish` calls `InternalEventsBuffer::externalize` before unwrapping the host (`src/rust/soroban/p26/soroban-env-host/src/host.rs:771-777`, `src/rust/soroban/p26/soroban-env-host/src/events/internal.rs:211-234`). The apply bridge then calls `encode_contract_events`, which filters the externalized `Events` vector and serializes each surviving `ContractEvent` to XDR (`src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:556-580,955-969`). A fused apply-only helper could externalize successful contract events and write their XDR bytes in one pass, preserving event bytes and success-hash inputs while avoiding `HostEvent` allocation/push and the second event-vector walk.

## Trigger

Run the current soroswap apply-load scenario (`soroswap, TX=2000, T=8`) from `ai-summary/CURRENT_STATE.md`. Each successful swap emits SAC transfer events and a Soroswap pair swap event, then reaches `applyLedger -> applyParallelPhase -> InvokeHostFunctionOpFrame::doParallelApply -> invoke_host_function -> Host::try_finish -> encode_contract_events`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host.rs:771-777` — `Host::try_finish` externalizes events before returning them.
- `src/rust/soroban/p26/soroban-env-host/src/events/internal.rs:211-234` — `InternalEventsBuffer::externalize` allocates and fills the intermediate `Events` vector.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:556-580` — apply-mode success path calls `try_finish` and then event encoding.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:955-969` — `encode_contract_events` filters and serializes the externalized events.

## Evidence

The current diagnostic trace contains 8,013 successful apply-contained `invoke_host_function_or_maybe_panic` calls. Timestamp filtering to events contained in `applyLedger` shows `write xdr` at `soroban-env-host/src/host/metered_xdr.rs:72` contributes 173.079 ms across 232,097 events, and `SAC transfer` at `contract.rs:212` contributes 2.645 s across 16,005 calls. Source inspection confirms events are first externalized into `Events(Vec<HostEvent>)` and only then encoded into `Vec<Vec<u8>>`, so the intermediate event shape is real apply-path work and not TX-set construction.

## Anti-Evidence

The proposed fused path cannot remove event construction, metered event XDR serialization, event-size accounting, diagnostic filtering semantics, or success-hash input bytes. The entire apply-contained `write xdr` category is only about 173 ms aggregate worker time across the trace, roughly 0.30 ms/ledger after 71 apply windows and 8-way cluster normalization; event encoding is only a subset of that, and the intermediate `HostEvent` vector push is smaller still. Related prior records also establish that no-meta mode cannot skip event bytes because they are consensus input.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Failed At**: hypothesis
**Novelty**: PASS — distinct from prior event-byte skipping and SAC-event direct-XDR records because this only targets the intermediate externalized event vector

### Why It Failed

The only safely removable work is one intermediate vector materialization and one filter/walk over the event list. Mandatory event XDR serialization and success-hash bytes dominate the measurable event path, and the full enclosing `write xdr` ceiling is far below the optimize-soroswap Medium threshold.

### Lesson Learned

For event-path optimizations, first separate consensus-required event bytes from host-side shape plumbing. Removing a bridge shape can be correct, but if the enclosing mandatory XDR category is sub-millisecond per ledger after cluster normalization, the shape cleanup is not an objective-level performance hypothesis.
