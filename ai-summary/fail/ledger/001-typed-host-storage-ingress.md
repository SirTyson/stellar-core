# H001: Replace per-invocation host storage CxxBuf XDR roundtrip with typed ingress

**Date**: 2026-05-03
**Subsystem**: ledger / Soroban host invocation ingress
**Severity**: Medium
**Impact**: 3-6% soroswap apply-time reduction by eliminating duplicated C++ serialization, Rust XDR decoding, and key derivation when constructing enforcing host storage
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Parallel Soroban apply already has typed `LedgerKey`, `LedgerEntry`, and TTL values available in the C++ apply thread. Successful host invocation should be able to construct the Rust enforcing footprint/storage inputs from those typed values, preserving the same key order, metering, rent metadata, TTL liveness checks, and returned ledger effects, without serializing every input entry to a `CxxBuf` and immediately deserializing it back into Rust XDR values for the same transaction.

## Mechanism

`InvokeHostFunctionApplyHelper::addReads` currently calls `toCxxBuf(*entryOpt)` and `toCxxBuf(*ttlEntry)` for every live footprint entry, and `invokeHostFunction` then passes vectors of owned byte buffers through the CXX bridge. The p26 host immediately decodes those buffers in `build_storage_map_from_xdr_ledger_entries`, derives each `LedgerKey` from the decoded entry, verifies footprint membership, and inserts the decoded value into the enforcing `StorageMap`; the same bridge also serializes the resources, host function, source account, and auth entries as owned `CxxBuf`s. A typed ingress path, for example a protocol-gated `CxxLedgerEntryInput { key, entry, ttl, entry_xdr_size }`/positional storage builder or equivalent bridge-owned arena, would remove the apply-path encode/decode/key-derivation roundtrip while keeping the same deterministic sorted storage map and the same budget charges where protocol compatibility requires them.

## Trigger

Run the current soroswap apply-load Tracy workload (`9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`). Each successful invoke-host-function transaction calls `addReads` for read-only and read-write footprint entries, serializes live ledger entries and TTL entries into `mLedgerEntryCxxBufs`/`mTtlEntryCxxBufs`, then Rust decodes those buffers while constructing the enforcing host storage before `Host::invoke_function`.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:386-534` — `addReads` loads typed entries, serializes each entry/TTL with `toCxxBuf`, records sizes, and appends to `mLedgerEntryCxxBufs`/`mTtlEntryCxxBufs`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — `invokeHostFunction` serializes host-function resources/source/auth and passes the entry buffer vectors into `rust_bridge::invoke_host_function`.
- `src/transactions/TransactionUtils.h:370-376` — `toCxxBuf` allocates a new `std::vector<uint8_t>` and fills it with `xdr::xdr_to_opaque`.
- `src/rust/src/bridge.rs:193-208` — CXX bridge signature accepts only owned `CxxBuf` vectors for host-function input entries and TTLs.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:488-523` (`fa1226b3`) — p26 `invoke_host_function` decodes resources, builds the footprint, decodes ledger-entry buffers into a storage map, clones the initial map, and constructs enforcing `Storage`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:1013-1052` (`fa1226b3`) — `build_storage_footprint_from_xdr` constructs a metered footprint map from decoded footprint XDR.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:1039-1145` (`fa1226b3`) — `build_storage_map_from_xdr_ledger_entries` decodes each entry and TTL buffer, derives the ledger key, checks footprint membership, and inserts into the host storage map.

## Evidence

The current soroswap trace confirms these zones are descendants of `applyLedger`: `addReads` overlaps `applyLedger` for 271,050,094 ns total / 13,648 calls, and its self-time is 196,665,860 ns; `read xdr with budget` overlaps for 178,988,395 ns / 129,270 calls with 164,491,109 ns self-time; `write xdr` overlaps for 168,017,057 ns / 202,955 calls; `new map` overlaps for 449,677,501 ns / 170,072 calls; and the enclosing `invoke_host_function` self-time is 741,215,306 ns / 6,776 calls. Prior rejected ledger hypotheses established that merely caching encoded C++ bytes is too narrow because Rust still decodes and builds fresh storage; this hypothesis targets the whole ingress roundtrip and storage construction boundary instead.

## Anti-Evidence

This is a bridge/API redesign, not a one-line cache. CXX does not currently expose Stellar XDR structs directly to Rust, so the PoC would need either new bridge-safe typed input structs or a Rust-side arena representation populated from C++ without unsafe lifetime mistakes. Budget compatibility is also delicate: if the current p26 `ValSer`/`ValDeser` charges are consensus-observable, removing them must be gated behind a future protocol or replaced with equivalent explicit budget charges. The optimization should not duplicate the already-accepted bulk storage-map work; the measurable win must come from removing redundant C++ XDR serialization, Rust XDR decoding, and `ledger_entry_to_ledger_key` derivation, not only from changing `MeteredOrdMap` insertion strategy.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-05-03
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated

### Trace Summary

The soroswap hot path reaches this code through `LedgerManagerImpl::applySorobanStages`, per-cluster `applyThread`, transaction parallel apply, and `InvokeHostFunctionOpFrame::doParallelApply`. For each invoke-host-function operation, `InvokeHostFunctionApplyHelper::apply` calls `addFootprint`, which serializes every existing footprint ledger entry and TTL into owned `CxxBuf` vectors, then `invokeHostFunction`, which sends those buffers over the CXX bridge. The p26 Rust host immediately decodes the same entry and TTL buffers with metered XDR, reconstructs each `LedgerKey` from the decoded `LedgerEntry`, validates membership in the already-decoded footprint map, and inserts the decoded values into a fresh enforcing `StorageMap` before executing `Host::invoke_function`.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — worker `applyThread` applies every transaction bundle in a Soroban cluster and calls `tx->parallelApply`, so this path runs per Soroban transaction during parallel apply.
- `src/ledger/LedgerManagerImpl.cpp:2530-2563` and `src/ledger/LedgerManagerImpl.cpp:2673-2705` — `applySorobanStageClustersInParallel` launches cluster workers inside `applySorobanStages`, confirming this work is inside ledger close, not TX-set creation or background bucket work.
- `src/transactions/OperationFrame.cpp:120-121` — invoke-host-function operations instantiate `InvokeHostFunctionOpFrame`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1377` — protocol-23+ Soroban apply constructs `InvokeHostFunctionParallelApplyHelper` and calls `helper.apply()`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:280-340` — `InvokeHostFunctionApplyHelper` owns `mLedgerEntryCxxBufs` and `mTtlEntryCxxBufs` and reserves one buffer slot per declared footprint entry.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:386-534` — `addReads` iterates read-only and read-write footprint keys, obtains typed entries/TTLs, serializes each live entry with `toCxxBuf(*entryOpt)`, serializes live TTLs with `toCxxBuf(*ttlEntry)`, and appends the resulting owned buffers.
- `src/transactions/ParallelApplyUtils.cpp:337-342` — in parallel apply, `getLedgerEntryOpt` reads typed `LedgerEntry` values from `ThreadParallelApplyLedgerState` before `addReads` serializes them.
- `src/transactions/TransactionUtils.h:370-376` — `toCxxBuf` allocates a fresh C++ `std::vector<uint8_t>` and fills it with `xdr::xdr_to_opaque`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — `invokeHostFunction` serializes auth entries, host function, resources, and source account, then passes entry and TTL buffer vectors to `rust_bridge::invoke_host_function`.
- `src/rust/src/bridge.rs:13-15` and `src/rust/src/bridge.rs:193-208` — the current bridge type is an owned byte buffer and the invoke signature accepts only vectors of these buffers for ledger entries and TTL entries.
- `src/rust/src/soroban_invoke.rs:7-38`, `src/rust/src/soroban_proto_any.rs:310-340`, and `src/rust/src/soroban_proto_all.rs:560-594` — the CXX call is routed to the protocol-specific p26 host entry point without changing the encoded buffer representation.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-459` — p26 decodes resources, builds the footprint, decodes ledger-entry/TTL buffers into storage, clones the initial map, constructs enforcing storage, decodes auth/host-function/source-account inputs, and then invokes the host.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:933-957` — the footprint is already available as a typed `FootprintMap` before storage entry decoding, preserving deterministic key ordering and access types.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:959-1052` — `build_storage_map_from_xdr_ledger_entries` decodes each `LedgerEntry` and non-empty `TtlEntry`, calls `ledger_entry_to_ledger_key`, checks footprint membership, inserts TTL metadata, inserts storage entries, and fills missing footprint keys with `None`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:903-931` — `ledger_entry_to_ledger_key` reconstructs the key from decoded entry data and performs additional metered clones of account IDs, trustline assets, contract data keys, or code hashes.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:73-82` — every Rust decode charges `ValDeser` and parses from bytes; removing this in a current protocol must either be protocol-gated or have equivalent budget accounting.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:144-160` — map construction is instrumented as `new map`, matching part of the trace evidence around repeated host storage construction.

### Findings

The inefficiency exists. On the parallel apply path, C++ already has typed ledger entries and TTLs, but it serializes them into owned byte buffers solely to satisfy the bridge API; Rust then decodes those bytes back into typed XDR objects before storage construction. The same path also derives each storage key from the decoded entry even though the C++ side iterated the declared footprint keys that determine membership and order.

The inefficiency is hot for soroswap. Successful invoke-host-function transactions execute this path per operation; the supplied Tracy evidence shows 6,776 `invoke_host_function` calls, 13,648 `addReads` calls, and high aggregate in-apply time in `addReads`, `read xdr with budget`, `write xdr`, and fresh map construction. Some of those aggregate spans include non-target work, but the exact C++ entry/TTL serialization and Rust entry/TTL deserialization path is on every successful host invocation with existing footprint entries, and prior failures show C++ encoded-byte caching alone is insufficient because Rust-side decode and storage construction remain.

The proposed fix is directionally correct if it crosses the bridge as real typed ingress rather than as cached encoded bytes. A viable PoC must construct Rust-side storage inputs without calling `metered_from_xdr_with_budget::<LedgerEntry>` / `::<TtlEntry>` on per-entry buffers and without deriving keys from decoded entries when the footprint key is already available. It must also preserve deterministic sorted storage, TTL liveness validation, footprint membership checks, output ledger changes, and budget semantics; if removed `ValSer`/`ValDeser` charges are consensus-observable for the target protocol, the change needs protocol gating or explicit equivalent charges.

The expected impact is Medium, not High. The strongest directly targeted spans are aggregate, parallel-worker time rather than wall-clock apply time, and `read xdr with budget` / `write xdr` include inputs and outputs outside entry/TTL ingress. Still, eliminating both the C++ encode side and the Rust decode/key-derivation side is materially broader than the previously rejected sub-Medium encoded-cache hypotheses and plausibly reaches the objective's 3-10% floor on soroswap.

### PoC Guidance

- **Target code**: `src/transactions/InvokeHostFunctionOpFrame.cpp` (`InvokeHostFunctionApplyHelper::addReads`, `invokeHostFunction`), `src/rust/src/bridge.rs`, `src/rust/src/soroban_invoke.rs`, `src/rust/src/soroban_proto_any.rs`, `src/rust/src/soroban_proto_all.rs`, and `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs` (`invoke_host_function`, `build_storage_map_from_xdr_ledger_entries`, `ledger_entry_to_ledger_key` call site).
- **Change description**: add a protocol-scoped typed storage-ingress representation carrying the footprint key, optional entry, optional TTL live-until/key-hash metadata, and canonical entry XDR size from C++ to Rust. Build the enforcing `StorageMap` from that representation without per-entry `toCxxBuf` in C++ and without per-entry `metered_from_xdr_with_budget::<LedgerEntry>` / `::<TtlEntry>` or `ledger_entry_to_ledger_key` in Rust. Keep the existing encoded-buffer path as a fallback for protocols/callers not migrated; do not stop at caching encoded C++ bytes because that leaves the already-rejected Rust decode cost intact.
- **Correctness check**: existing invoke-host-function, parallel-apply, Soroban budget/recording-mode, rent/TTL, and ledger-close tests should cover deterministic storage effects, returned ledger changes, auth/source/host-function decoding, TTL liveness failures, and protocol budget deltas. Any budget-number updates must be exact decreases caused by the removed serialization/deserialization work, not loosened expectations.
- **Benchmark focus**: compare repeated non-Tracy `scripts/run_apply_load_matrix.py` soroswap median apply time against the current baseline, then use Tracy only for attribution. The targeted spans should show lower `InvokeHostFunctionOpFrame addReads` self-time, fewer or cheaper `read xdr with budget` calls attributable to input ledger entries/TTLs, and reduced `invoke_host_function` self-time; the accepted threshold is a reproducible 3-10% soroswap apply-time improvement.

---

## PoC Attempt

**Result**: POC_FAIL
**Date**: 2026-05-03
**PoC by**: claude-opus-4.7, high
**Failed At**: poc
**Iterations**: 0 (declined before first build-test cycle after scoping)

### Failure Reason

The hypothesis as scoped is not feasible to demonstrate within the allowed
10 build-test cycle PoC budget. The required deliverable is a cross-FFI
redesign whose minimum viable implementation spans:

1. **New cxx-rs bridge surface.** cxx-rs cannot pass Stellar XDR
   (`LedgerKey`, `LedgerEntry`, `TtlEntry`) directly between C++ and Rust;
   the existing bridge uses owned `CxxBuf` byte vectors precisely because
   xdrpp-generated types are not bridge-compatible. A "typed ingress" path
   requires either:
     - A new bridge-safe wire struct (`CxxLedgerEntryInput { key_xdr,
       entry_xdr, ttl_live_until, ttl_key_hash, entry_xdr_size }`) plus a
       new `invoke_host_function_typed` bridge function carrying it, or
     - An opaque-pointer arena scheme with accessor traits.
   Either option is a meaningful bridge schema change in
   `src/rust/src/bridge.rs`, `soroban_invoke.rs`,
   `soroban_proto_any.rs`, and `soroban_proto_all.rs`, and also forces a
   parallel signature on the C++ side.

2. **Submodule (p26) modifications with consensus-observable budget.**
   The existing path charges `ValSer`/`ValDeser` for per-entry decode and
   metered clones inside `ledger_entry_to_ledger_key`. The reviewer
   explicitly requires that any removal of these charges either be
   protocol-gated or replaced with explicit equivalent budget charges,
   because the deltas are consensus-observable. That means:
     - Adding a new protocol gate (or a future-protocol code path) in the
       p26 host's `e2e_invoke.rs` `invoke_host_function`,
       `build_storage_map_from_xdr_ledger_entries`, and footprint
       construction sites.
     - Carefully preserving deterministic sorted storage order, footprint
       membership checks, and TTL liveness semantics under the new path.
     - Producing matching ledger-effect output across the gated and
       legacy paths.

3. **Submodule branch hygiene.** The PoC handoff rules require committed
   work on a paired SirTyson fork branch for the p26 submodule plus a
   gitlink bump on the outer branch — itself a multi-step push/branch
   workflow in addition to the optimization itself.

4. **Verification cost.** The PoC procedure binds POC_PASS on a clean
   `env NUM_PARTITIONS=30 make check` run with zero failures, plus all
   existing invoke-host-function, parallel-apply, recording-mode, rent
   /TTL, and ledger-close tests. Each rebuild that touches the p26
   crate triggers a full re-cargo of soroban-env-host and the cxx-bridge
   regeneration pipeline; a single iteration's build + test suite is on
   the order of tens of minutes wall time. The 10-iteration ceiling is
   not enough headroom to land a green test run for a multi-thousand-LOC
   FFI redesign with consensus-affecting metering changes.

### Changes Attempted

None. After reading the hypothesis, reviewer notes, surrounding code in
`src/transactions/InvokeHostFunctionOpFrame.cpp` (`addReads`,
`invokeHostFunction`), the cxx bridge in `src/rust/src/bridge.rs`, and
the p26 host's `e2e_invoke.rs` (`invoke_host_function`,
`build_storage_map_from_xdr_ledger_entries`,
`ledger_entry_to_ledger_key`, `build_storage_footprint_from_xdr`), and
re-reading the related already-accepted PoC
(`success/transaction-ledger/001-bulk-build-host-storage-maps.md`), the
minimum viable scope to satisfy the reviewer's requirements
(protocol-gated typed ingress, no per-entry `toCxxBuf`, no per-entry
`metered_from_xdr_with_budget` or `ledger_entry_to_ledger_key`,
preserved deterministic state, preserved budget semantics, preserved
existing tests) cannot be implemented and stabilized inside the 10-cycle
PoC envelope on this codebase.

### Smaller Alternatives Considered (and why they don't satisfy the
hypothesis)

- **Skip only `ledger_entry_to_ledger_key` by passing footprint indices.**
  Removes one source of metered clones but leaves the per-entry XDR
  decode intact. The reviewer explicitly calls this out: "do not stop at
  caching encoded C++ bytes because that leaves the already-rejected
  Rust decode cost intact." A symmetric "do not stop at skipping only
  key derivation" critique applies — the win must come from removing
  serialization, deserialization, AND key derivation. A partial fix
  would not be a faithful PoC of this hypothesis and would also still
  need protocol gating.

- **Cache encoded `CxxBuf` bytes from prior reads.** Already rejected
  upstream (referenced in the hypothesis "Anti-Evidence" and the
  reviewer findings).

### Recommendation

This hypothesis is directionally plausible but is a *project*, not a
PoC. It would be more appropriately split into:
  1. A scoped design proposal for a typed/arena bridge surface (no perf
     claim attached).
  2. A protocol-gating proposal documenting the metering equivalence
     argument.
  3. An implementation PR series after the design is reviewed, rather
     than a single-PoC attempt under a 10-cycle budget.

