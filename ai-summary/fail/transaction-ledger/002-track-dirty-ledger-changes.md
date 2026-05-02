# H002: Track dirty and rent-relevant Soroban storage slots to avoid full-footprint ledger-change extraction

**Date**: 2026-05-02
**Subsystem**: transaction-ledger / Soroban host ledger-change extraction
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by skipping unchanged read-only footprint entries during Rust ledger-change extraction and C++ effect decoding
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

After a successful enforcing Soroban invocation, Core should receive exactly the modified ledger entries and TTL entries needed to update ledger state, and rent should be computed from exactly the entries whose size or live-until ledger changed. Read-only footprint entries whose value and TTL are unchanged should not require old-entry XDR serialization, key hashing, rent-size computation, Rust `LedgerEntryChange` construction, or C++ `recordStorageChanges` consideration. Transactions that update a read-only TTL, write a read-write entry, delete an entry, restore an entry, or increase rent-relevant size should still produce identical ledger effects and fees.

## Mechanism

`get_ledger_changes` currently iterates every entry in `storage.map`, writes the key XDR, fetches the initial snapshot, serializes the old entry to compute rent size, checks TTL metadata, and only later does `extract_rent_changes` and `extract_ledger_effects` discard read-only or no-op changes. For soroswap, the footprint includes read-only contract instances, code, SAC metadata, and other entries that frequently do not produce ledger effects. Adding dirty/rent-relevant tracking to enforcing `Storage` would mark slots when `put`, `del`, restore handling, or TTL extension changes a live-until value; `get_ledger_changes` could iterate that deterministic key list plus any rent-relevant read-only TTL bumps instead of the full storage map.

This is significant because the current accepted trace still shows ledger-change-adjacent work inside `applyLedger`: `write xdr` totals 147.207 ms, `read xdr with budget` totals 131.819 ms, `sha256` totals 256.073 ms, Rust storage-map lookup zones total over 1.0 s, and C++ `recordStorageChanges` totals 77.700 ms in the timestamp-filtered windows. The proposal avoids work before it reaches both `extract_ledger_effects` and C++ decoding, and preserves determinism by emitting dirty keys in the same sorted order as the existing `MeteredOrdMap` iteration.

## Trigger

Run the current soroswap apply-load benchmark from `ai-summary/CURRENT_STATE.md` (`soroswap, TX=2000, T=8`) using the accepted Tracy trace. Each successful `InvokeHostFunctionOpFrame::doParallelApply` calls Rust `get_ledger_changes`, then `extract_rent_changes` and `extract_ledger_effects`, then C++ `recordStorageChanges`; transactions with unchanged read-only footprint entries trigger full-footprint extraction even though only read-write entries and TTL bumps can modify ledger state.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:180-292` — `get_ledger_changes` iterates `storage.map` and builds a `LedgerEntryChange` for every footprint entry.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:324-366` — `extract_rent_changes` filters out no-op rent changes after `get_ledger_changes` has already serialized old entries and computed sizes.
- `src/rust/src/soroban_proto_any.rs:261-301` — `extract_ledger_effects` filters out read-only changes and emits only new ledger values and TTL entries for C++.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:332-389` — `put`/`del` are natural write-marking points for dirty storage slots.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:500-573` — `apply_ttl_extension` and `extend_ttl` are natural rent-relevant marking points for live-until changes.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:641-767` — C++ `recordStorageChanges` decodes only `out.modified_ledger_entries`, so Rust can keep read-only no-op entries out of the bridge output.

## Evidence

- Timestamp-filtered Tracy aggregation confirms the candidate chain is inside `applyLedger`: `InvokeHostFunctionOpFrame doParallelApply` totals **10.996 s** over 5,077 events, Rust `invoke_host_function` totals **10.535 s**, `recordStorageChanges` totals **77.700 ms**, `write xdr` totals **147.207 ms**, and `read xdr with budget` totals **131.819 ms** inside the 70 apply windows.
- The source has a clear late-filtering pattern: `get_ledger_changes` builds a change for every `storage.map` item, but `extract_ledger_effects` ignores `change.read_only` entries, and `extract_rent_changes` drops entries whose TTL and rent size did not change.
- The current implementation already has precise mutation points. `Storage::put`, `Storage::del`, and `Storage::apply_ttl_extension` know when a slot becomes dirty or rent-relevant, so the host does not need to rediscover this by diffing every footprint entry at the end of invocation.
- This is not the prior old-entry XDR size cache. The accepted cache reduces the cost of old-entry size computation for entries that still flow through `get_ledger_changes`; this hypothesis avoids visiting unchanged read-only entries in the first place.

## Anti-Evidence

- Some read-only entries are rent-relevant when TTL is extended, so a dirty-only list that tracks only read-write keys would be incorrect. The implementation must separately track read-only TTL bumps and restored entries.
- `LedgerEntryChange` ordering may be observable in tests and debug tooling. The dirty/rent-relevant list should be emitted in canonical `MeteredOrdMap` key order or otherwise prove that output ordering is not semantically observed.
- The broad XDR and hash zones include more than ledger-change extraction. A reviewer should instrument `get_ledger_changes` directly and count skipped read-only no-op entries before accepting the Medium severity claim.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-02
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — related ledger-change/XDR hypotheses exist in the failure summary, but this dirty/rent-relevant storage-slot tracking mechanism is not the same finding
**Failed At**: reviewer

### Trace Summary

The ledger-close apply path reaches `InvokeHostFunctionOpFrame::doApply`/parallel apply, calls the Rust bridge, and `invoke_host_function` builds enforcing storage from the full Soroban footprint before running `Host::invoke_function`. On success, `get_ledger_changes` iterates every entry in `storage.map`, including read-only unchanged entries inserted for missing or read-only footprint keys, and constructs `LedgerEntryChange` values before `extract_rent_changes` and `extract_ledger_effects` perform late filtering. However, this extraction occurs before the bridge reads `cpu_insns` and `mem_bytes`, so skipping metered XDR serialization, map lookup, and hashing changes protocol-visible resource accounting unless the optimization reproduces or protocol-gates those charges. The claimed C++ win is also not present for unchanged read-only entries: `extract_ledger_effects` already removes `change.read_only` values before `recordStorageChanges` decodes `out.modified_ledger_entries`.

### Code Paths Examined

- `src/transactions/InvokeHostFunctionOpFrame.cpp:982-1017` — the apply helper invokes the Rust host first, then calls `recordStorageChanges`, collects events, consumes refundable resources, and finalizes success.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:641-767` — C++ decodes only `out.modified_ledger_entries`; unchanged read-only `LedgerEntryChange` records never reach this loop because Rust filters them first.
- `src/rust/src/soroban_proto_any.rs:408-459` — the bridge measures `cpu_insns` and `mem_bytes` after `invoke_host_function_with_trace_hook_and_module_cache` returns, so successful ledger-change extraction contributes to visible budget totals.
- `src/rust/src/soroban_proto_any.rs:478-505` — on success, rent is computed from `res.ledger_changes`, then `extract_ledger_effects` converts only final ledger effects into bridge output.
- `src/rust/src/soroban_proto_any.rs:261-301` — `extract_ledger_effects` ignores `read_only` entry values and emits TTL entries only when `new_live_until_ledger > old_live_until_ledger`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-521` — enforcing invocation decodes resources, builds the full footprint and storage map, clones the initial storage map, runs the host function, and calls `get_ledger_changes` only for successful invocations.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:180-292` — `get_ledger_changes` allocates for `storage.map.len()`, iterates `storage.map`, writes each key XDR, reads initial state, serializes old entries for rent size, handles TTL metadata, serializes new read-write values, and only marks read-only status near the end.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:324-366` — `extract_rent_changes` drops no-op rent changes after old-entry serialization and size computation have already occurred.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:933-1052` — enforcing setup populates `StorageMap` with decoded entries and inserts `None` for every footprint key not present in the encoded ledger entries, so `storage.map` has full-footprint coverage.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:230-238` — enforcing storage is constructed from the footprint plus storage map and has no dirty/rent-relevant side structure today.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:332-389` — `put` and `del` funnel through `put_opt_helper`, enforce read-write footprint access, and update `self.map`, so they are plausible write-marking points.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:500-573,594-643` — TTL extension updates `self.map` only when the computed live-until value increases enough to pass the threshold/min-extension rule, so it is a plausible TTL-marking point.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:56-68` — `metered_write_xdr` charges `ValSer` for each write chunk; skipping old-entry/key serialization is not just a wall-clock optimization.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:168-235,294-304` — `MeteredOrdMap` lookup, access, and scan operations are budget-charged, so skipping entries also changes metered map costs.
- `ai-summary/fail/transaction-ledger/summary.md:57,90` — prior ledger-change XDR reviews already found that protocol-gated direct output is below the Medium threshold and that naive old-entry serialization elimination changes `ValSer` accounting.

### Why It Failed

The late-filtering inefficiency is real, but this hypothesis is not viable for the optimize-soroswap objective. A dirty/rent-relevant list that simply avoids unchanged read-only slots would change successful transaction `cpu_insns`/`mem_bytes`, because `get_ledger_changes` runs before those counters are read and its XDR/map/hash work is metered. Preserving p26 semantics would require either reproducing the skipped `ValSer`, map, hash, and size-computation charges or intentionally protocol-gating a metering change; the hypothesis does neither.

The projected Medium impact is also overstated. `read xdr with budget` is largely enforcing-input decoding before execution, not work that dirty tracking after execution can skip. `recordStorageChanges` already receives only `modified_ledger_entries`, so unchanged read-only entries do not cause C++ decoding today. The cited `sha256` total is a broad host zone, while `get_ledger_changes` only hashes a key when the initial TTL map lacks that key's hash; normal Soroban entries supplied with TTL entries reuse the existing `TtlEntry.key_hash`. After removing those non-removable and already-filtered categories, the remaining Rust-side full-footprint extraction subset is related to prior ledger-change XDR work that was already summarized as below the 3% Medium floor, and the safe charge-reproducing version would further reduce the wall-clock-only opportunity.

### Lesson Learned

For Soroban ledger-change extraction, late filtering in `get_ledger_changes` is a valid place to look, but budget accounting and bridge filtering must be traced before projecting wins. Unchanged read-only entries are already filtered before C++, and old-entry/key serialization is protocol-visible through `ValSer`; a future hypothesis needs narrow `get_ledger_changes` instrumentation plus an explicit protocol-gated or exact-charge-preserving design before it can clear the Medium review threshold.
