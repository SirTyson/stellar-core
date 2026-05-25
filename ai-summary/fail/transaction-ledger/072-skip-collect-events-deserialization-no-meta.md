# H072: Skip ContractEvent XDR Decode in collectEvents When Meta Disabled

**Date**: 2026-05-25
**Subsystem**: transactions / soroban
**Severity**: Low
**Impact**: per-tx CPU in Soroban apply
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

When TX meta is disabled (`DISABLE_TX_META_FOR_TESTING`) and the operation
produces no `mProtocol23SACReconciliationEvents`, the apply path should
avoid materializing decoded `ContractEvent` structs from XDR opaque bytes
in `InvokeHostFunctionApplyHelper::collectEvents` —
- the **success-preimage hash** is computed in `finalizeSuccess`
  (`InvokeHostFunctionOpFrame.cpp:902-920`) directly over the raw
  `out.contract_events[i].data` bytes (and a length prefix) without ever
  reading the decoded vector, and
- the decoded events fed to `setEvents` (`InvokeHostFunctionOpFrame.cpp:874`)
  are immediately discarded by `OpEventManager::setEvents`
  (`EventManager.cpp:504-509`) which early-outs when `mEnabled == false`.

Under those conditions the apply path should retain only the raw byte
buffers, push them into the success preimage by reference, and skip the
per-event `xdr::xdr_from_opaque(buf.data, evt)` calls together with the
copy-into-`success.events` step.

## Mechanism

`collectEvents` (`InvokeHostFunctionOpFrame.cpp:769-817`) unconditionally
runs `ContractEvent evt; xdr::xdr_from_opaque(buf.data, evt);
success.events.emplace_back(evt);` for every event the host emitted. Each
decoded `ContractEvent` allocates several `xvector` payloads (topics,
body data, opt sub-objects), then is copied (not moved) into
`success.events`, only to be moved into `OpEventManager` and immediately
dropped when meta is disabled and no SAC reconciliation events exist. The
hash path in `finalizeSuccess` does not use the decoded form at all. The
deviation is that we spend allocate+decode+free cycles on data nobody
reads.

## Trigger

Run the soroswap apply-load benchmark (`apply-load` with
`DISABLE_TX_META_FOR_TESTING` / meta disabled, no SAC operations so
`mProtocol23SACReconciliationEvents` is empty), and profile
`collectEvents` self-time.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:769-817` —
  `InvokeHostFunctionApplyHelper::collectEvents`: per-event
  `xdr_from_opaque` + emplace_back.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:878-928` —
  `finalizeSuccess`: hashes raw bytes only.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:834-876` —
  `setEvents`: only needs decoded events when
  `mProtocol23SACReconciliationEvents` is non-empty.
- `src/transactions/EventManager.cpp:504-509` —
  `OpEventManager::setEvents`: early-out when `mEnabled == false`.

## Evidence

- Tracy zone `collectEvents` aggregate self-time on the diagnostic soroswap
  trace (`f5502210f4e4-20260525-011655-02-soroswap-tx-2000-t-8.tracy`):
  ~33.96 ms over 71 ledgers across 8 cluster workers = ~478 µs/ledger
  aggregate self-time.
- For soroswap, `mProtocol23SACReconciliationEvents` is empty (DEX
  contract calls do not produce SAC reconciliation events), so the only
  legitimate consumer of `success.events` is OpEventManager, which
  discards them when meta is disabled.
- `finalizeSuccess` (line 902-920) hashes
  `out.contract_events[i].data` directly without reading the decoded
  structs — verified by inspection.

## Anti-Evidence

- Per-event `ContractEvent` decode is needed when
  `mProtocol23SACReconciliationEvents` is non-empty (SAC paths,
  including max-sac benchmark), so any change must guard on that
  vector being empty + `OpEventManager::isEnabled() == false`.
- Even guarded, the savings are small: 478 µs/ledger ÷ 8 clusters =
  ~60 µs critical-path. With 2-3× amplification for allocator/free
  costs not captured in self-time (each `ContractEvent` carries
  several `xvector` payloads), an optimistic ceiling is ~150-200 µs
  CP, which is ~0.25-0.32% of Tracy's `applyLedger` budget.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated (no prior `collectEvents`
deserialization hypothesis in fail/hypothesis/reviewed/poc dirs).

### Why It Failed

Projected savings are well below the objective's 1% noise floor, never
mind the Medium 3% threshold. Aggregate `collectEvents` self-time on the
soroswap trace is ~478 µs/ledger across 8 cluster workers; the
critical-path saving is ~60 µs/ledger (~0.1% of Tracy `applyLedger`).
Even granting 2-3× for allocator/free costs that escape Tracy self-time,
the ceiling sits at ~0.3% — comfortably inside benchmark noise. Soroswap
events are short (mostly `transfer`-style 3-4 topic events), so per-event
decode work is modest in absolute terms.

### Lesson Learned

Apply-path code that looks "wasted with meta disabled" is often genuinely
wasted, but the per-tx footprint on soroswap is too small to clear the
Medium severity bar unless it touches a high-allocation-count hot loop.
`collectEvents` runs once per Soroban tx (not per-key), so its
aggregate cost is bounded by tx count × event count × decode cost, which
caps the optimization ceiling well below the noise floor. Apply this
calculus before proposing any meta-elision hypothesis: count = ops × txs,
not entries × txs.
