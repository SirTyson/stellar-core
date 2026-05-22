# H056: Typed TTL-Change Bridge Output Eliminating Synthetic TtlEntry Encode/Decode Lap

**Date**: 2026-05-21
**Subsystem**: crypto / Rust bridge / TTL change pipeline
**Severity**: Low
**Impact**: TTL-change bridge encode/decode overhead (sub-Medium)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

When the Soroban host produces a TTL extension for a contract-data entry, the
C++ apply path should upsert a `TTLEntry` keyed by `key_hash` with
`live_until_ledger_seq = new_live_until_ledger`. The host already represents
the change as a typed `LedgerEntryLiveUntilChange { key_hash: Vec<u8>,
old_live_until_ledger: u32, new_live_until_ledger: u32, ... }`, and C++ also
only needs the same three primitive fields to perform the upsert. No
intermediate `LedgerEntry` XDR encode/decode round trip should be required to
move that typed data across the FFI bridge.

## Mechanism

`extract_ledger_effects` in `src/rust/src/soroban_proto_any.rs:261-302`
inspects each `LedgerEntryChange`, and for each TTL change whose
`new_live_until_ledger > old_live_until_ledger` it synthesizes a brand-new
`LedgerEntry { last_modified_ledger_seq: 0, data: LedgerEntryData::Ttl(
TtlEntry { key_hash, live_until_ledger_seq: new_live_until_ledger }), ext:
V0 }` and calls `non_metered_xdr_to_rust_buf(&le)` to serialize it into a
`RustBuf`. The C++ side in `InvokeHostFunctionOpFrame::recordStorageChanges`
(`src/transactions/InvokeHostFunctionOpFrame.cpp:654-720`) then runs
`xdr::xdr_from_opaque(buf.data, le)` on every returned `RustBuf` — including
each synthesized TTL entry — and immediately extracts `key_hash` +
`live_until_ledger_seq` via `LedgerEntryKey(le)` and `le.data.ttl()`. A
typed bridge variant could return a `Vec<TtlChange { key_hash: [u8;32],
new_live_until_ledger: u32 }>` alongside the existing `modified_ledger_entries`
for contract-data/code, eliminating one encode and one decode per TTL
extension.

## Trigger

Run the current soroswap apply-load case (`soroswap, TX=2000, T=8`) from
`ai-summary/CURRENT_STATE.md`. Every successful swap returns at least one
TTL extension for the touched persistent contract-data entries, exercising
the `extract_ledger_effects` TTL-synthesis loop on every successful
invocation.

## Target Code

- `src/rust/src/soroban_proto_any.rs:extract_ledger_effects:261-302` — synthesizes a `LedgerEntry::Ttl` and `non_metered_xdr_to_rust_buf`-encodes it per TTL change.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:recordStorageChanges:654-720` — decodes every `out.modified_ledger_entries` buffer via `xdr::xdr_from_opaque`, including the synthesized TTL entries, and immediately extracts only the typed fields.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:get_ledger_changes:212-256` — original site that populated `ttl_change.key_hash` / `new_live_until_ledger` typed fields that are then re-wrapped in XDR by `extract_ledger_effects`.
- `src/rust/src/bridge.rs:InvokeHostFunctionOutput:35-55` — current bridge output struct holds `modified_ledger_entries: Vec<RustBuf>` without a separate typed-TTL channel.

## Evidence

This is a structurally redundant encode/decode lap on the apply path: the
Rust side has the typed `(key_hash, new_live_until_ledger)` values
immediately before `non_metered_xdr_to_rust_buf`, and the C++ side discards
the decoded full `LedgerEntry` after extracting exactly those two fields.
Each TTL `LedgerEntry` is small (~50 bytes), but every soroswap invocation
produces at least one such synthesized entry, so the work scales with
invocation count.

## Anti-Evidence

`recordStorageChanges` totals 98.487 ms across the whole soroswap trace
(6,776 calls, ~14.5µs/call). The TTL-decode share of `xdr::xdr_from_opaque`
inside that zone is at most a small fraction of those 14.5µs (TTL entries
are tiny and not the dominant decode in the loop — contract-data entries
are larger). The Rust-side `non_metered_xdr_to_rust_buf` of a 50-byte
`LedgerEntry::Ttl` is sub-microsecond. Combined apply-contained savings:
well under 30ms across the trace = <1% of the ~273ms apply baseline
(Meta-Pattern 8 already caps the entire FFI bridge overhead at ~50ms).
Additionally, eliminating only the TTL share leaves the contract-data
encode/decode lap intact, so this is a partial cleanup of an already-bounded
surface.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Failed At**: hypothesis
**Novelty**: PASS — prior H010 (`zero-copy-modified-ledger-entries-ffi`) targeted the *contract-data* side of `modified_ledger_entries`, not the TTL-synthesis sub-loop; prior H001 (this cycle) targeted the full output pipeline including bucket writes. Neither isolates the TTL-only synthesis lap.

### Why It Failed

Meta-Pattern 8 caps the total FFI bridge encode/decode overhead at ~50 ms
across the whole soroswap trace. The TTL synthesis lap is a fraction of
that already-bounded surface: each synthesized `LedgerEntry::Ttl` is ~50
bytes, and the per-entry encode in Rust plus decode in C++ together account
for substantially less than 1µs per TTL change. Even an optimistic
upper-bound estimate (30 ms total saved across the trace) is below 1% of
the ~273 ms soroswap apply baseline, which is below this objective's Low
floor. The work cannot reach Medium severity even if implementation cost
were free.

### Lesson Learned

The TTL-synthesis encode/decode lap is structurally redundant but
quantitatively bounded by Meta-Pattern 8. Do not propose typed-bridge
TTL-only optimizations unless future profiling shows the TTL-output share
of `recordStorageChanges` decode time individually exceeds the 3% Medium
floor. A typed TTL channel only becomes interesting if combined with the
broader typed contract-data output redesign, which prior H001/H010 reviews
established is a typed bucket pipeline redesign, not a bridge-local change.
