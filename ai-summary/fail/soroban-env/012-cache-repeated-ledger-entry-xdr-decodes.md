# H012: Cache repeated ledger-entry XDR decodes while replaying `ValDeser` charges

**Date**: 2026-04-29
**Subsystem**: soroban-env
**Severity**: Low
**Impact**: Rust bridge / e2e storage-map construction decode overhead
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When the same serialized ledger entry or TTL entry is supplied to many Soroban invocations in one `closeLedger`, the host should charge the same `ValDeser` budget as today but should avoid physically decoding identical XDR buffers repeatedly if the decoded value is immutable and can be safely reused. Each invocation should still build its own enforcing `StorageMap`/`TtlEntryMap`, preserve all metered `Rc` allocation and key-derivation charges, and produce identical storage contents.

## Mechanism

`build_storage_map_from_xdr_ledger_entries` decodes every ledger-entry and TTL buffer via `metered_from_xdr_with_budget` before deriving a `LedgerKey` and inserting it into per-invocation storage maps. Soroswap repeatedly supplies common contract-code, contract-instance, and SAC metadata entries across many invocations, so a per-apply decoded-entry cache keyed by the XDR bytes or hash could replay the same `ValDeser` charge and return an immutable decoded object instead of re-running `ReadXdr`.

## Trigger

Run the current soroswap apply-load diagnostic trace and inspect `read xdr with budget` at `soroban-env-host/src/host/metered_xdr.rs:77`. The trace reports 63,706 calls; an unwrap timestamp check showed all 63,706 events fall inside `applyLedger` windows.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:959-1052` — `build_storage_map_from_xdr_ledger_entries` decodes every entry and TTL buffer for every invocation.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:73-82` — `metered_from_xdr_with_budget` charges `ValDeser` once and then performs unmetered XDR decoding.
- `src/rust/src/soroban_proto_any.rs:391-448` — Rust bridge invocation boundary where a shared decoded-entry cache would need to be threaded if this were pursued.

## Evidence

- The repeated decode pattern exists in source: each enforcing invocation reconstructs a fresh `StorageMap` from serialized ledger entries, and each buffer is passed through `metered_from_xdr_with_budget`.
- `read xdr with budget` is entirely inside the measured apply path for the reference trace, so it is not a TX-set-construction trap.
- A budget-preserving cache is conceptually possible because `ValDeser` is charged once from the input buffer length before decoding; a cache hit could charge the same amount and skip only physical `ReadXdr` work.

## Anti-Evidence

- The total target zone is too small for this objective. The current trace reports only 82.432 ms self-time (91.504 ms total execution time in unwrap mode) for all `read xdr with budget` calls, about 1.4-1.6% of the 5.774 s traced `applyLedger` envelope before accounting for the fact that not all buffers are repeated or safely cacheable.
- A correct implementation would still need to build per-invocation `StorageMap` and `TtlEntryMap` structures, derive ledger keys, perform metered `Rc` allocation or equivalent budget replay, validate footprint membership, and handle restored/expired entries. Those remaining costs are outside the removable XDR decode subset.
- Sharing decoded `LedgerEntry` values across worker threads would require careful `Send + Sync` ownership design because current storage maps use `Rc<LedgerEntry>` inside single-host execution. A thread-local or per-worker cache would reduce sharing benefits, while an `Arc`-backed cache would need conversion or storage-type changes.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Failed At**: hypothesis
**Novelty**: PASS — related Rust decode/bridge failures exist, but this specific decoded-entry cache angle was not separately recorded

### Why It Failed

Even an unrealistically perfect cache that removed all physical `read xdr with budget` work would save less than the objective's 3% Medium threshold in the current soroswap trace. The actually removable repeated-buffer subset is smaller than the whole zone, and the required per-invocation storage-map construction and metering remain mandatory.

### Lesson Learned

Rust XDR decode caching should not be promoted from the current trace unless focused instrumentation shows a much larger repeated-decode subset than the aggregate `read xdr with budget` zone suggests. For this objective, the whole-zone upper bound must clear Medium before a complex cross-invocation cache is worth PoC work.
