# H001: Cache Encoded Entry Byte Size in StorageMap to Avoid Re-Encoding Old Entries in get_ledger_changes

**Date**: 2026-05-21
**Subsystem**: soroban-env (e2e_invoke)
**Severity**: Medium
**Impact**: apply-time reduction in post-invocation diff/rent computation
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

After a Soroban host invocation, `get_ledger_changes` should compute the
per-entry `old_entry_size_bytes_for_rent` (the encoded XDR byte length of the
*input* LedgerEntry, used to compute rent deltas) without re-running a full
XDR serialization pass. The input entry was supplied to
`build_storage_map_from_xdr_ledger_entries` as an XDR byte buffer of *known
length* (`entry_buf.as_ref().len()`); that length is exactly the value the
function later needs. The expected behavior is: capture the input buffer
length when decoding, store it next to the `Rc<LedgerEntry>` in the storage
map, and read it back on the diff path — never re-encode.

## Mechanism

Today, `build_storage_map_from_xdr_ledger_entries`
(`e2e_invoke.rs:976-1043`) decodes each `entry_buf` into a `LedgerEntry` and
inserts only `(key, Some((le_rc, live_until)))` into the storage map — the
input buffer length is discarded. Then for *every* entry in the storage map
(read-only and read-write alike), `get_ledger_changes`
(`e2e_invoke.rs:226-231`) calls `metered_write_xdr(budget, old_entry, &mut
buf)` solely to compute `entry_size_for_rent` from `buf.len()`; the `buf` is
then dropped. This is a full XDR serialization round-trip — allocating a
`Vec<u8>`, walking the entire `LedgerEntry` struct, and metering — performed
once per footprint entry per op. The deviation: we already know the answer
(the input buffer's `len()`), but we throw it away and recompute it the most
expensive possible way. For a soroswap-heavy ledger this is the dominant
cost inside the e2e-invoke "self time" outside the VM.

## Trigger

Run the soroswap apply-load benchmark (`run_apply_load_matrix.py`,
`workload=soroswap`). Each of the ~6776 InvokeHostFunction ops in the
benchmark has a footprint of ~15-30 Soroban entries (token contract
code/instance plus several balance/allowance entries). For every one of those
entries, `get_ledger_changes` re-encodes the *old* entry on the apply
critical path. The total work is ~100k-200k `metered_write_xdr` invocations
per ledger; the work is per-op and scales with footprint size.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:976-1043`
  (`build_storage_map_from_xdr_ledger_entries`) — site that has the input
  buffer length and discards it.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:226-231`
  (`get_ledger_changes`, old-entry size computation) — site that re-encodes
  to recover the discarded length.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs` (StorageMap entry
  type) — would need a new "encoded size hint" field carried alongside
  `(Rc<LedgerEntry>, Option<u32>)`.
- `src/rust/soroban/p26/soroban-env-host/src/fees.rs::entry_size_for_rent` —
  consumer; signature would change from `(entry, encoded_size)` to accept
  either a cached size or a fallback compute path for newly-written entries.

## Evidence

1. The input buffer length is known and equal to the desired output: line
   980 reads `entry_buf.as_ref()` (known length) and decodes; line 228
   re-encodes the result back to compute the same length.
2. Tracy on the soroswap diagnostic trace
   (`9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`) shows
   `invoke_host_function` (e2e_invoke.rs:488) self-time of 741M ns / 6776
   calls = 109µs per op — large enough to host the suspected work and not
   accounted for by descendant zones (Vm::invoke_function_raw,
   instantiate_wasmi, etc., are tracked separately). The dominant
   un-zoned descendants of `invoke_host_function` are the e2e XDR
   serialization paths around `get_ledger_changes` / `encode_contract_events`.
3. `entry_size_for_rent` is also computed for **read-only** entries (line
   231 runs unconditionally inside the `if let Some(...)` for any entry that
   has a TTL durability). Read-only entries are by definition unmodified, so
   re-encoding them is pure waste.
4. Rough back-of-envelope: 150k entries/ledger × ~1.5µs per
   `metered_write_xdr` of a typical 200-400-byte LedgerEntry ≈ 225ms
   Tracy-time. Divided by 8 parallel workers, that is ~28ms wall-time
   savings against a 272.9ms soroswap baseline — ~10% wall reduction, solidly
   Medium.
5. The change is determinism-safe: the cached length is byte-identical to
   what re-encoding produces (it *is* the encoded length). Budget metering
   for the (now-eliminated) `metered_write_xdr` call must be preserved by
   charging the same dimensions/amounts against the budget without doing the
   actual serialization work — `metered_write_xdr` separates the metering
   `charge_budget` calls from the encoding bytes, so the protocol-visible
   budget state is unchanged.

## Anti-Evidence

1. The cached size is only correct for *unmodified* entries. For ReadWrite
   entries that the host has overwritten, `init_storage_snapshot.get(key)`
   returns the *old* entry (cached size still valid) while the *new* entry
   is encoded at line 266 (cache miss — must compute). The hypothesis only
   eliminates the old-entry encoding, not the new-entry one. That is the
   bulk of the savings because most footprint entries are read-only or
   read-but-not-modified in soroswap.
2. The size field would need to flow through `Rc<LedgerEntry>` storage —
   either as a separate map (`HashMap<Rc<LedgerEntry>, u32>` keyed by
   pointer) or by changing the StorageMap value type. The latter touches a
   pervasive type and risks ripple changes. A side-table keyed by
   `Rc::as_ptr` is more contained but introduces a second lookup.
3. The metering side-effect of `metered_write_xdr` must be preserved
   byte-for-byte to keep protocol determinism. The mechanism is to retain
   the budget charges but skip the actual byte writes; this requires
   confirming that the XDR write path is *deterministic in the amount
   charged* (i.e. only depends on input size, not on intermediate state).
   For `LedgerEntry` writes this is plausible — the charge is
   `MetadataXdrSerialize` proportional to byte length — but must be
   verified before claiming the optimization is determinism-safe.
4. Past failed angle "Skip unused xdr_size in addReads" (in
   fail/soroban-env/summary.md) is *related but distinct*: that targeted
   C++-side `xdr_size` on the *read* path, where the size IS used by
   downstream code. This hypothesis targets a different site (Rust-side
   `get_ledger_changes`) where the size is computed once via full encoding
   instead of read from a known length.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/soroban-env/summary.md` entry `004.md` ("Batch e2e footprint/storage/TTL map construction and avoid re-serializing old ledger entries in `get_ledger_changes`")
**Failed At**: reviewer

### Trace Summary

The traced hot path matches the hypothesis: `invoke_host_function` builds a storage map from encoded ledger-entry buffers, clones it as the initial snapshot, runs the host, then calls `get_ledger_changes`. In `get_ledger_changes`, every existing initial entry is serialized through `metered_write_xdr` only to recover `buf.len()` before calling `entry_size_for_rent`; read-write entries that still exist are serialized again for the new value. However, the same optimization target has already been investigated and rejected in the fail summary because removing the physical serialization while preserving exact p26 budget effects requires reproducing the same `ValSer` write-call metering, including per-write constant terms, not merely charging by total encoded byte length.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-520` — `invoke_host_function` builds the initial storage map, clones it for `StorageMapSnapshotSource`, invokes the host, and calls `get_ledger_changes` on successful invocation.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:183-292` — `get_ledger_changes` serializes each old entry into a discarded `Vec<u8>` to obtain `old_entry_size_bytes_for_rent`, then serializes read-write new entries for encoded output and new rent size.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:959-1052` — `build_storage_map_from_xdr_ledger_entries` decodes each `entry_buf` but stores only `Some((Rc<LedgerEntry>, live_until))`, discarding the original encoded byte length.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:25-28,165-183,252-390` — `StorageMap` value type is `Option<(Rc<LedgerEntry>, Option<u32>)>` and storage get/put paths pass entries without any encoded-size side channel.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:368-387` — `entry_size_for_rent` uses the supplied XDR byte length directly except for contract-code entries, where it adds Wasm memory cost.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:11-68` — `metered_write_xdr` meters through `MeteredWrite::write`, charging `ContractCostType::ValSer` on each writer callback before forwarding bytes to the `Vec<u8>`.
- `ai-summary/fail/soroban-env/summary.md:12` — prior failed investigation already covered avoiding old-ledger-entry reserialization in `get_ledger_changes` and rejected it due exact protocol-visible metering constraints.

### Why It Failed

This is not novel: the same old-entry reserialization target in `get_ledger_changes` is already recorded as failed in `fail/soroban-env/summary.md` entry `004.md`. The traced code also confirms the prior failure reason applies here: caching only the final encoded length would not reproduce the exact sequence of `ValSer` charges produced by `metered_write_xdr`, because metering occurs per `Write::write` callback and `ValSer` has a non-zero constant term in the p26 cost model. A correct optimization would need an already-investigated coordinated metering solution rather than a simple cached-size field in `StorageMap`.

### Lesson Learned

For p26 Soroban performance work, cached XDR lengths can replace physical serialization only when the protocol-visible budget side effects are either unnecessary or exactly reproducible. In `get_ledger_changes`, the old-entry buffer is physically discarded, but the metered XDR traversal is still part of observable budget accounting, so length-only caching is not sufficient and this specific angle is a duplicate of prior failed work.
