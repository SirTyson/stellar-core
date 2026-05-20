# H004: Residual Metered XDR Write Serialization After Host-Metering Coalescing

**Date**: 2026-05-20
**Subsystem**: soroban
**Severity**: Low
**Impact**: Below objective threshold; residual `write xdr` work is a sub-Medium slice of Soroban output/input serialization
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

After the accepted next-protocol host-metering coalescing, production Soroban apply should still serialize the same return values, events, ledger changes, and rent inputs, and should charge the same next-protocol coalesced `ValSer` budget at deterministic points. Any remaining optimization should remove only physical serialization overhead that is not needed for the C++ bridge output or for budget accounting, and should leave p26 exact metering untouched.

## Mechanism

The current accepted p26 source already routes `metered_write_xdr` through a coalesced path when `budget.coalesced_host_metering()` is enabled: it writes the XDR into a `Vec<u8>` under `Limited`, computes the total byte count, and charges one `ValSer` entry. A follow-up idea was to attack the remaining `write xdr` Tracy zone by reserving output buffers or writing directly into final bridge buffers so repeated `Vec` growth and intermediate copies disappear. The actual behavior does not provide enough removable work: the remaining zone is mostly mandatory XDR traversal and byte emission, and prior bridge/output investigations bound the surrounding surface below Medium.

## Trigger

Run the current soroswap apply-load diagnostic trace from `ai-summary/CURRENT_STATE.md`. The accepted trace still reports `write xdr` self-time (`150,911,171 ns` over `202,955` calls in the full self-time export), and an apply-window event overlap check found about `168,009,127 ns` of `write xdr` events inside `applyLedger`. This makes the residual serialization visible but not large enough for the objective after accounting for parallel worker aggregation and previously accepted coalescing.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:56-91` — accepted `metered_write_xdr` coalesces `ValSer` in next-protocol mode but still performs normal XDR traversal into a `Vec<u8>`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:get_ledger_changes` — builds host output changes that feed the residual serialization path.
- `src/rust/src/soroban_proto_any.rs:extract_ledger_effects` — filters the host output for the C++ bridge after Rust-side XDR work.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:recordStorageChanges` — consumes the returned XDR buffers and preserves the current deletion/coverage semantics.

## Evidence

The residual `write xdr` zone is a real `applyLedger` descendant in the diagnostic trace, so it is not a TX-set-construction trap. Source inspection shows the accepted coalesced path has already removed the main per-leaf budget-charge overhead for protocol 27 builds; the remaining candidate work is physical serialization and buffer management. This is a different angle from the already-accepted host-metering coalescing, because it does not try to change the charge count again.

## Anti-Evidence

The surrounding XDR bridge/output family has already been investigated repeatedly: old-entry XDR-size caching, cached contract-code body elision, dirty storage output tracking, meta-disabled output skipping, and generic bridge caching all failed or were bounded below Medium. The exact residual `write xdr` self-time is only about 151 ms across the whole soroswap trace before worker normalization; even deleting it entirely would not clear the 3% objective floor against the current 272.896 ms median, and a safe buffer-reserve/direct-write patch can only remove a fraction of it. Skipping XDR traversal outright is not available because the bytes are still the bridge output and because budget/limit semantics must remain deterministic.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-20
**Failed At**: hypothesis
**Novelty**: PASS — this specifically examined the residual post-coalescing `write xdr` path, not the already-accepted `ValSer` coalescing itself

### Why It Failed

The post-coalescing residual serialization is measurable but below the optimize-soroswap Medium threshold. The broad bridge/output family is already capped below Medium, and the remaining safe physical-buffer slice is smaller than the measured `write xdr` zone.

### Lesson Learned

After a successful metering coalescing change, do not re-promote the same XDR surface unless the proposal removes a newly isolated Medium-sized component. Residual serialization zones must be sized against actual self-time, not against earlier pre-coalescing budget-charge costs.
