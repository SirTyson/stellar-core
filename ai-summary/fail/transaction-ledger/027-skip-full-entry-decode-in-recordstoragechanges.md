# H027: Skip Full LedgerEntry XDR Decode in recordStorageChanges by Carrying LedgerKey From Host

**Date**: 2026-05-20
**Subsystem**: transaction-ledger / Soroban storage writeback
**Severity**: Low
**Impact**: Per-modified-entry full XDR decode in `InvokeHostFunctionApplyHelper::recordStorageChanges` runs on parallel workers; only the `LedgerKey`, byte size, and whole-entry `LedgerEntry` are subsequently used.
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`recordStorageChanges` (`src/transactions/InvokeHostFunctionOpFrame.cpp:640-741`)
iterates `out.modified_ledger_entries` (an opaque XDR byte buffer per entry
returned from the Rust host) and for each buffer calls
`xdr::xdr_from_opaque(buf.data, le)` to materialize a full `LedgerEntry`.
The decoded entry is then used (a) to compute `LedgerEntryKey(le)` for
footprint bookkeeping, (b) to call `validateContractLedgerEntry`, (c) to
note write-byte metrics with `buf.data.size()`, and (d) to upsert the
LedgerEntry into the parallel ledger state via `upsertLedgerEntry(lk, le)`.
The expected efficient path would have the host return either the
`LedgerKey` separately (already known on the Rust side) or carry the
LedgerKey alongside the entry bytes so that C++ can avoid the full XDR
decode in the early footprint-coverage phase, deferring the heavyweight
decode only to the final `upsertLedgerEntry` step.

## Mechanism

For each modified entry the C++ worker walks the entire `LedgerEntry`
XDR, allocating discriminated-union members for `ContractData`/`ContractCode`
payloads (which can be tens of KB on real soroswap workloads). The
materialized `LedgerEntry` is then handed to `upsertLedgerEntry`, which on
the parallel path moves it into the per-tx entry map. If the host could
return both the `LedgerKey` and the still-encoded payload, footprint
matching, write-bytes accounting, and `validateContractLedgerEntry` could
be performed against the bytes/key directly, saving the per-entry decode
allocation cost.

## Trigger

Run the apply-load benchmark with `--mode soroswap-tps`. Each successful
soroswap `InvokeHostFunction` returns a small number (~3–5) of modified
ledger entries; the parallel worker decodes each one fully.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:640-741` —
  `recordStorageChanges`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:657-658` — full
  `xdr_from_opaque(buf.data, le)` followed by `LedgerEntryKey(le)`.
- `src/rust/src/contract.rs` (cxx bridge) and
  `soroban-env-host/src/e2e_invoke.rs` — host return type
  `InvokeHostFunctionOutput::modified_ledger_entries` only carries the
  encoded bytes.

## Evidence

- The host already knows each modified entry's `LedgerKey` because storage
  writeback iterates a keyed map; carrying that key out through the bridge
  would avoid the C++ rederive.
- `LedgerEntryKey(le)` requires materializing the whole entry just to read
  its discriminant + key fields, which is wasted work for large
  `ContractData` blobs.

## Anti-Evidence

- Tracy `recordStorageChanges` aggregate self-time across all 8 parallel
  workers is **98,486,607 ns ≈ 98.5 ms total** for the whole 71-ledger
  trace.
- Critical-path per-ledger cost = 98.5 ms / 8 workers / 71 ledgers ≈
  **0.17 ms/ledger ≈ 0.064% of the 272 ms apply window**.
- The XDR decode itself is only a fraction of `recordStorageChanges`
  self-time (the function also runs `validateContractLedgerEntry`, the
  inner footprint coverage loop, and `upsertLedgerEntry`). So the
  removable subset is even smaller than 0.17 ms/ledger.
- Changing the host bridge `InvokeHostFunctionOutput` shape requires
  protocol-careful coordination with the soroban-env Rust host, plus
  consensus-relevant audit, since `modified_ledger_entries` shape is part
  of the host↔core interface.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-20
**Failed At**: hypothesis
**Novelty**: PASS — the closest related fail entries are
`001-carry-initial-storage-metadata.md` (carrying *initial* storage
metadata to skip *old-entry* serialization in `get_ledger_changes`, a
metering-coupled change on the Rust side) and `004-recordstoragechanges-on2-ttlmatch-loop.md`
(the inner O(N×M) TTL match loop). Neither covered eliminating the
post-host C++ decode of `modified_ledger_entries` itself.

### Why It Failed

Direct measurement on the accepted Tracy trace
(`9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`) gives
aggregate-worker self-time for `recordStorageChanges` of 98.5 ms
across the entire 71-ledger benchmark. After cluster-parallelism
normalization (8-way), the critical-path bound is **~0.17 ms/ledger
(≈0.06% of apply time)**, far below the **3% Medium floor of
~8 ms/ledger**. Even an idealized removal of the full XDR decode
(which is only one component of the zone's self-time) cannot exceed
that bound. The optimization is also coupled to a host-bridge schema
change with non-trivial consensus-audit cost; the cost/benefit ratio
is decisively unfavorable.

The same lesson appears in fail summary meta-pattern #6 ("Aggregate
Worker Time ≠ Critical-Path Time") — aggregate worker self-time must
be divided by the cluster count before projecting wall-clock impact.

### Lesson Learned

For Soroban write-back hot paths under the soroswap 8-cluster shape,
any hypothesis targeting a Tracy zone whose **aggregate worker
self-time** is below ~600 ms is automatically sub-Medium after
cluster normalization. `recordStorageChanges` at ~98 ms aggregate is
nearly four times below this threshold; further per-entry
optimizations there must be combined with a much larger structural
change (e.g., eliminating the full host↔core entry-bytes round trip
by sharing decoded host objects across the boundary) to clear the
Medium bar.
