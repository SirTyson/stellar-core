# H002: Protocol-Gated Typed Storage Ingress for Soroban Invocation

**Date**: 2026-05-21
**Subsystem**: crypto / Rust bridge / storage XDR
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by removing duplicated C++ serialization and Rust metered XDR decode for host storage inputs
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Before a Soroban host invocation, the host should receive the same footprint entries, TTL entries, XDR sizes, live-until metadata, and restored-entry information that the current bridge supplies. The storage map and footprint map built in Rust must be identical in key order and contents, and p26 metering must remain unchanged; only a protocol >26 path may replace physical per-entry XDR round trips with equivalent typed/bulk metering.

## Mechanism

`InvokeHostFunctionOpFrame::addReads` loads typed `LedgerEntry` / `TTLEntry` values from the C++ ledger snapshot, immediately serializes them into `CxxBuf`s, and the Rust side decodes those buffers back into typed XDR values to build enforcing storage. The accepted baseline already carries positional old-entry XDR-size metadata through `get_ledger_changes`; the same positional model can be extended to pass typed storage ingress records and byte-size metadata, so Rust can bulk-build the storage/TTL maps without physically deserializing the same ledger entries on every invocation.

## Trigger

Run the current soroswap apply-load case (`soroswap, TX=2000, T=8`). Each invocation calls `addFootprint`/`addReads` for the read-only and read-write footprint, pushes `mLedgerEntryCxxBufs` and `mTtlEntryCxxBufs` through `invoke_host_function`, then Rust reconstructs host storage from those buffers before executing the contract.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:addReads:386-497` — loads typed entries, computes XDR sizes, serializes `LedgerEntry` and `TTLEntry` values into bridge buffers.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:invokeHostFunction:557-585` — passes the per-invocation ledger-entry and TTL buffers into Rust.
- `src/rust/src/soroban_proto_any.rs:invoke_host_function:408-430` — receives bridge buffers and dispatches to the protocol-specific host.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:build_storage_map_from_xdr_ledger_entries` and `build_storage_footprint_from_xdr` — decode bridge buffers and build enforcing storage maps.

## Evidence

Unwrap containment against the current trace's 71 `applyLedger` windows shows this ingress family is apply-contained: `read xdr with budget` at `soroban-env-host/src/host/metered_xdr.rs:109` totals 178.988 ms / 129,270 calls, `readOne` at `util/XDRStream.h:132` contributes 141.769 ms inside apply, and `addReads` contributes 196.666 ms self-time in the aggregate self-time export. The source path is structurally redundant: C++ has typed entries before `toCxxBuf`, while Rust needs typed entries after `metered_from_xdr_with_budget`; the serialized byte vector is an intermediate representation used mostly to cross the bridge and replay metering.

## Anti-Evidence

Several narrower ingress hypotheses failed because Rust still needed native XDR values and p26 `ValDeser` metering. This hypothesis therefore depends on a next-protocol metering rule and a complete typed bridge design for all footprint entry types; a partial field-level cleanup would fall below the Medium floor and should be rejected.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/crypto/summary.md` row `002-typed-host-input-xdr-deserialization.md`
**Failed At**: reviewer

### Trace Summary

The traced ingress path matches the prior failed typed-host-input XDR deserialization hypothesis. C++ loads typed footprint entries, serializes live `LedgerEntry` and optional `TTLEntry` values into `CxxBuf`s, and passes them through `rust_bridge::invoke_host_function`; Rust then charges `ValDeser`, decodes those buffers into native XDR values, derives keys, checks footprint membership, and inserts into `StorageMap`/`TtlEntryMap`. This confirms the local redundancy exists, but the same surface was already reviewed and rejected because correctly scoped typed inputs only address read-deserialization/input-bridge work, not unrelated output `write xdr` or broader storage-map costs, leaving the projected saving below the Medium threshold.

### Code Paths Examined

- `ai-summary/fail/crypto/summary.md:52-53` — records the prior failed `002-typed-host-input-xdr-deserialization.md` review: typed host-input bridge can target `read-xdr-with-budget`, but correctly scoped addressable work is below Medium.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:386-497` — `addReads` iterates footprint keys, loads ledger/TTL entries, serializes them with `toCxxBuf`, and stores them in `mLedgerEntryCxxBufs`/`mTtlEntryCxxBufs`.
- `src/transactions/TransactionUtils.h:370-376` — `toCxxBuf` materializes XDR bytes with `xdr::xdr_to_opaque`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-585` — `invokeHostFunction` passes the per-invocation ledger-entry and TTL `CxxBuf` vectors to the Rust bridge.
- `src/rust/src/bridge.rs:13-21` — the bridge type for C++-owned inputs is byte-oriented `CxxBuf`, not a shared typed XDR object.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-459` — host invocation decodes resources, builds the footprint, builds storage from encoded ledger/TTL entries, clones the initial storage map, and then decodes auth, host function, and source-account inputs.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:933-1044` — `build_storage_footprint_from_xdr` and `build_storage_map_from_xdr_ledger_entries` clone footprint keys, decode each ledger and TTL buffer with `metered_from_xdr_with_budget`, validate TTL/footprint invariants, and populate the maps.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:73-82` — host-less XDR decoding charges `ContractCostType::ValDeser` before parsing the bytes.

### Why It Failed

VERDICT: NOT_VIABLE — duplicate of `ai-summary/fail/crypto/summary.md` row `002-typed-host-input-xdr-deserialization.md`. The current hypothesis narrows the same typed-input bridge idea to storage ingress and adds protocol gating, but it does not change the prior sizing conclusion: a typed input path can plausibly remove C++ input serialization plus Rust `ValDeser` parsing for ledger/TTL inputs, but it cannot claim output `write xdr`, unrelated storage-map construction, or all `addReads` time as removable. Under this objective, Low-tier or sub-Medium bridge/input cleanup must be rejected rather than accepted with downgraded severity.

### Lesson Learned

Typed Soroban bridge-input ideas need to be sized only against input-buffer serialization and `read xdr with budget` calls on the ledger/TTL ingress path. Do not re-promote this surface unless a new trace isolates enough storage-ingress-only time to exceed the 3% Medium floor after excluding output serialization, metered map construction, footprint validation, and other host invocation work.
