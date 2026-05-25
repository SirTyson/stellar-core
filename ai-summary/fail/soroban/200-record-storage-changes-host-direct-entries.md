# H200: Eliminate per-modified-entry `xdr_from_opaque` decode in `recordStorageChanges` via host-direct `LedgerEntry` handoff

**Date**: 2026-05-26
**Subsystem**: soroban (transactions bridge / soroban-env-host)
**Severity**: Low
**Impact**: bridge XDR roundtrip on apply path
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

After the host has finished executing a Soroban invocation it already owns
the modified `LedgerEntry` values as in-memory structures (via the
`storage_map` `OrdMap<LedgerKey, Option<(Rc<LedgerEntry>, Option<u32>)>>`).
The apply bridge should consume those values directly without
re-serializing them to opaque XDR in `e2e_invoke::get_ledger_changes_inner`
and then immediately re-deserializing them in
`InvokeHostFunctionOpFrame::recordStorageChanges` via
`xdr::xdr_from_opaque(buf.data, le)`. Eliminating the roundtrip would
remove a full XDR encode + decode per modified entry per Soroban op.

## Mechanism

`get_ledger_changes_inner` (e2e_invoke.rs, ~line 360 onward) calls
`metered_write_xdr` to serialize each modified `LedgerEntry` into
`encoded_new_value: Vec<u8>` even for the apply-only path (preserved
post-sparse-no-meta for metering equivalence; bytes themselves are now
only consumed for the C++ side). On the C++ side,
`recordStorageChanges` (InvokeHostFunctionOpFrame.cpp:641) loops over
`out.modified_ledger_entries` and decodes each `buf.data` back into a
`LedgerEntry` via `xdr_from_opaque`, then derives `LedgerEntryKey(le)`
and upserts it into the per-tx scope. The encode + decode is pure
bridge ceremony — both sides hold the same `LedgerEntry` value.

## Trigger

Run `scripts/run_apply_load_matrix.py` on the soroswap benchmark; every
successful swap modifies 4–8 ledger entries (pool reserves, two SAC
balance entries, two TTL extensions). Each round-trips through one
metered XDR encode and one un-metered XDR decode on the apply path.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:get_ledger_changes_inner:~360` — `metered_write_xdr` into `encoded_new_value` per kept entry.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:recordStorageChanges:641` — `xdr_from_opaque(buf.data, le)` per modified entry, then `LedgerEntryKey(le)` derivation.
- `src/rust/src/rust_bridge.rs` — `LedgerEntryRentChange` / `InvokeHostFunctionOutput` FFI structs that would need a richer cross-language handoff to avoid the round-trip.

## Evidence

- Tracy zone `recordStorageChanges` aggregate self-time = 124 ms across
  the 71-ledger soroswap apply window. Normalized by NUM_CLUSTERS=8 and
  71 ledgers, that is **0.22 ms/ledger** of critical-path work, i.e.
  **0.10% of the 207 ms soroswap baseline**.
- The corresponding host-side `metered_write_xdr` work in
  `get_ledger_changes` is already bounded by meta-pattern #4 ("XDR
  bridge prep cost capped at ~2.5%") — even eliminating the entire
  bridge XDR round-trip cannot exceed that ceiling, and the read-back
  half of the round-trip is a strict subset.
- Sparse-no-meta success #001 already proved this path responds to
  trimming, but the remaining "always keep `metered_write_xdr` for
  metering equivalence" pin is exactly what blocks further savings
  here.

## Anti-Evidence

- `metered_write_xdr` is retained intentionally to keep budget-charge
  totals identical across protocols (success #001 preserves this).
  Any "skip encode" approach must keep an equivalent metered cost
  bookkeeping path or risk a protocol-incompatible budget change
  (meta-pattern #9: "Host output XDR can't be skipped without
  metering change").
- The C++ side derives `LedgerEntryKey(le)` from the decoded entry —
  removing the decode requires the host to also surface the key, which
  is a wider bridge ABI change.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Failed At**: hypothesis
**Novelty**: PASS — no prior fail/hypothesis entry targets the
`recordStorageChanges` XDR decode half specifically; meta-pattern #4
bounds the full bridge but does not enumerate this exact split.

### Why It Failed

The maximum possible win is bounded both ways:
1. **Per-zone direct measurement**: `recordStorageChanges` is
   0.22 ms / 207 ms = **0.10%** of apply time — below the 1% noise
   floor, far below Medium (3%).
2. **Architectural cap**: even fusing the encode/decode away on both
   sides cannot exceed the ~2.5% bridge ceiling (meta-pattern #4),
   itself sub-Medium. And the encode half must be preserved for
   metering equivalence (meta-pattern #9 + success #001 design
   constraint), so the actually-removable portion is only the decode
   half — strictly below the 2.5% ceiling.

The proposal therefore cannot reach the Medium (3%) threshold under
any realistic implementation, and would require a cross-language
bridge ABI change to surface decoded entries directly — disproportionate
diff size for a sub-Low gain.

### Lesson Learned

When a hypothesis splits an already-capped aggregate (here, the ~2.5%
bridge cap from meta-pattern #4) into a halved subset (decode only),
the subset is mechanically smaller than the cap and cannot promote to
a higher severity tier. Compute the subset ceiling against meta-pattern
caps before proposing. Direct Tracy zone measurement
(`recordStorageChanges` = 0.10%) is the authoritative ceiling here.
