# H002: Typed Host Storage Ingress With Metering Replay

**Date**: 2026-05-25
**Subsystem**: transaction-ledger / Soroban invoke bridge
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by removing the remaining per-invocation XDR decode/map-build boundary for host storage setup
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When `InvokeHostFunctionOpFrame` invokes the Rust host during parallel apply, Rust should receive the same footprint entries, TTL entries, old-entry XDR sizes, and restored-entry metadata that the existing encoded bridge provides. The host should build an enforcing `Storage` with identical key ordering, missing-entry handling, TTL validation, rent metadata, budget totals, diagnostics, and error behavior; released protocols should keep the existing XDR path unless the new ingress path is explicitly protocol-gated and budget-calibrated.

## Mechanism

The C++ apply path already holds typed `LedgerEntry`/`TTLEntry` objects when `addReads` loads the footprint, but it serializes each entry into `CxxBuf` (`InvokeHostFunctionOpFrame.cpp:474-498`) and Rust immediately decodes those buffers in `build_storage_map_from_xdr_ledger_entries` (`e2e_invoke.rs:1192-1304`). A typed ingress bridge could pass footprint-positioned entry records with cached XDR sizes and TTL metadata, then construct `StorageMap` entries from typed Rust XDR values while replaying the exact `ValDeser`/allocation charges from the cached byte lengths. This removes duplicate byte serialization, parsing, key derivation from decoded entries, and ordered-map construction scaffolding from every soroswap transaction while preserving deterministic per-tx ordering inside the existing worker.

## Trigger

Run the current `soroswap, TX=2000, T=8` apply-load workload. Every successful transaction executes `InvokeHostFunctionApplyHelper::addFootprint`, serializes the same shaped read-only/read-write footprint into `mLedgerEntryCxxBufs` and `mTtlEntryCxxBufs`, crosses `rust_bridge::invoke_host_function`, and calls `build_storage_map_from_xdr_ledger_entries` to decode and insert the entries before `Host::invoke_function`.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:386-535` — `addReads` loads typed entries, computes XDR sizes, and serializes entries/TTLs into `CxxBuf` vectors.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — generic bridge call passes only encoded host-function, resources, source account, auth, entries, and TTLs.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:641-680` — Rust decodes resources, footprint, entries, auth, host function, and source account before invocation.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:1192-1304` — `build_storage_map_from_xdr_ledger_entries` decodes every entry/TTL, derives keys, validates footprint membership, and inserts into `StorageMap`.

## Evidence

The apply-contained current trace leaves a large setup/finish envelope around actual host execution: `invoke_host_function` totals ~11.899s while child `Host::invoke_function` totals ~9.047s; even after accounting for `recordStorageChanges` (~124ms) and `collectEvents` (~34ms), the bridge/setup/output region remains on the order of seconds of aggregate worker time. Related in-apply zones are also still visible after the accepted bulk storage-map work: `ScVal to Val` ~970.8ms, `get_contract_data` ~814.7ms, `storage get` ~789.3ms, `map lookup` ~707.2ms, and `new map` ~499.5ms. The source confirms the residual double representation boundary: C++ serializes typed ledger entries into bytes, then Rust decodes them into fresh `Rc<LedgerEntry>`/`Rc<LedgerKey>` pairs and a `StorageMap` for each invocation.

## Anti-Evidence

This hypothesis is only Medium if the typed path removes more than the already-rejected narrow C++ encoding slice. Metering is the primary risk: `metered_from_xdr_with_budget`, `Rc::metered_new`, footprint membership lookups, and map inserts are protocol-visible today, so a correct design must either replay equivalent charges in the same failure order or be next-protocol gated with budget updates. A prior typed-ingress PoC encountered correctness blockers, so the reviewer should require a concrete bridge representation and narrow spans around C++ serialization, Rust entry decode, key derivation, and map insertion before accepting the projection.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — no exact prior typed host-storage ingress review found; adjacent CxxBuf caching and storage-map construction records cover important subsets
**Failed At**: reviewer

### Trace Summary

The protocol 23+ Soroban apply path reaches `InvokeHostFunctionOpFrame::doParallelApply`, builds an `InvokeHostFunctionParallelApplyHelper`, loads footprint entries through the typed parallel ledger state, serializes existing entries and TTLs into `CxxBuf`s, then calls the Rust `invoke_host_function` bridge. Rust decodes resources and footprint, builds an enforcing footprint, decodes every provided ledger/TTL entry with `metered_from_xdr_with_budget`, derives each key from the decoded entry, checks footprint membership, inserts storage entries, and only then constructs `Storage` and invokes the host. The encoded boundary is real and in the `closeLedger` hot path, but the hypothesis's Medium projection depends on counting storage-map construction that was already investigated and confirmed separately in `001-bulk-build-host-storage-maps.md`; the remaining C++ serialization plus Rust decode/key-derivation slice is below the optimize-soroswap Medium threshold.

### Code Paths Examined

- `ai-summary/fail/transaction-ledger/summary.md:18,20,55,140,211,215` — prior records bound CxxBuf precompute/cache variants as Low/sub-threshold, reject decoded-value reuse when it skips per-transaction metering, and require active-cluster normalization for aggregate worker time.
- `ai-summary/success/transaction-ledger/001-bulk-build-host-storage-maps.md:531-553` — the storage-map construction part of this hypothesis is already a confirmed separate optimization, measuring about 1.63% soroswap improvement; it cannot be counted again as novel residual typed-ingress impact.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:386-535` — `addReads` loads typed ledger/TTL entries from the footprint, computes `xdr_size(lk)`, serializes live entries with `toCxxBuf`, records `entrySize` from the encoded buffer, and appends entry/TTL buffers for Rust.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — `invokeHostFunction` serializes auth, host function, resources, source account, and PRNG seed, then passes only encoded buffers plus ledger info and module cache through `rust_bridge::invoke_host_function`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:982-1017` — the apply helper orders the hot path as `addFootprint`, Rust host invocation, returned storage-change recording, event collection, refundable-resource consumption, and success finalization.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1377` — protocol 23+ Soroban operations enter this helper from `doParallelApply`, so the target is inside parallel `closeLedger` apply rather than TX-set construction.
- `src/transactions/ParallelApplyUtils.cpp:337-341` — the parallel helper already receives typed entries from `TxParallelApplyLedgerState::getLiveEntryOpt`, confirming the C++ side has typed values before serialization.
- `src/rust/src/soroban_invoke.rs:7-39` — the outer Rust bridge dispatches to the selected protocol host module and forwards ledger-entry and TTL inputs as `Vec<CxxBuf>`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:472-514` — Rust decodes resources, restored-key indices, footprint, and then calls `build_storage_map_from_xdr_ledger_entries` before constructing enforcing storage.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:520-580` — host function, source account, auth, host execution, result encoding, ledger-change extraction, and event encoding remain required after storage ingress.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:1013-1037` — the enforcing footprint builder decodes/clones footprint keys into a `FootprintMap`; this is a separate setup cost from ledger-entry ingress.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:1039-1151` — the storage builder decodes every `LedgerEntry`/`TtlEntry`, derives the `LedgerKey`, validates footprint membership, records XDR-size/TTL metadata, and inserts existing and missing entries into the storage map.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:105-114` — `metered_from_xdr_with_budget` charges `ValDeser` from byte length before decoding, so a typed ingress would need either exact charge replay plus equivalent validation/error behavior or a protocol-gated metering change.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:117-160,196-224` — map one-shot construction and repeated insertion costs are distinct from XDR decode; the former is already covered by the prior bulk-build finding.

### Why It Failed

The core inefficiency exists, but it is not a Medium-severity finding for this objective after separating novel residual work from previously investigated work. The largest part of the claimed "decode/map-build boundary" is the enforcing `FootprintMap`/`StorageMap` construction pattern. That exact structural map-construction issue was already reviewed, PoC'd, and confirmed in `001-bulk-build-host-storage-maps.md`, and it produced about 1.63% soroswap improvement on the recorded baseline. This new typed-ingress review cannot count that same win again.

The remaining novel slice is narrower: avoid C++ `toCxxBuf` for footprint entries/TTLs, avoid Rust `ReadXdr` parsing of those buffers, and possibly avoid deriving the ledger key from the decoded entry when the footprint already supplies key order. Prior fail records already bound C++ CxxBuf-entry caching and dirty/shared-entry serialization variants as sub-threshold, sometimes regressive due to cache pressure. On the Rust side, a correct same-protocol path must still charge `ValDeser`, allocate `Rc<LedgerEntry>`/`Rc<LedgerKey>` or equivalent storage-owned values, validate TTL pairing/expiry and footprint membership, preserve missing-entry behavior, and preserve the final storage ordering. If it skips those metered operations it becomes a protocol-gated metering change; if it replays them, the removable wall-clock work is just byte encoding/parsing and some key derivation, not the full invoke setup envelope.

The hypothesis therefore over-projects by attributing broad `invoke_host_function`, `new map`, `map lookup`, `storage get`, and `ScVal to Val` worker totals to typed storage ingress. Most of those zones are either host execution, generic storage runtime, already-confirmed bulk map construction, or mandatory metered work that remains under an equivalent design. After active-cluster normalization, the novel residual is best treated as a Low/sub-Medium bridge cleanup, and the optimize-soroswap reviewer criteria require Low findings to be rejected rather than downgraded.

### Lesson Learned

For Soroban host-ingress hypotheses, split the setup envelope into separately accountable pieces: C++ serialization, bridge copy shape, Rust XDR parsing, key derivation, storage-map construction, and runtime storage access. Once a prior success has already claimed map construction and prior failures bound CxxBuf caching as sub-threshold, a typed-entry bridge needs narrow measurements proving the residual decode/key-derivation slice alone clears the 3% apply-time floor; broad invoke/setup Tracy totals are not enough.
