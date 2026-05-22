# H001: Protocol-gated typed Soroban storage ingress

**Date**: 2026-05-22
**Subsystem**: ledger / Soroban parallel apply
**Severity**: Medium
**Impact**: 3-6% soroswap apply-time reduction by removing the per-invocation XDR encode/decode and storage-map reconstruction boundary for enforcing Soroban storage
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For next-protocol Soroban apply, C++ should pass the same footprint entries, TTL entries, restored-entry markers, and initial rent-size metadata to the Rust host without first converting every `LedgerEntry`, `TTLEntry`, `HostFunction`, resources object, source account, and auth entry through owned XDR byte buffers. The Rust host should construct enforcing storage with the same footprint access rules, same initial entry/TTL values, same resource limits, same deterministic ordering, and either an explicit next-protocol metering schedule for typed ingress or a metering replay that preserves the old p26 budget costs when not protocol-gated.

## Mechanism

The current bridge serializes each C++ footprint entry in `InvokeHostFunctionOpFrame::addReads`, then `e2e_invoke::invoke_host_function` immediately decodes those bytes into `LedgerEntry`/`TtlEntry`, reconstructs `LedgerKey`s, checks the footprint map, inserts into `StorageMap`, clones the initial storage snapshot, and later serializes output changes back across the bridge. The accepted `cache-old-entry-xdr-sizes` success removed one redundant old-entry serialization, but the dominant ingress boundary remains: read-only and read-write entries are still physically encoded in C++, decoded in Rust, converted into host `Val` trees, and inserted into persistent maps for every invoke. A next-protocol typed ingress API that carries typed entries plus precomputed keys/TTL metadata into Rust can remove the XDR buffer churn and much of the map-construction work while preserving deterministic execution because it does not add parallelism and all values are still taken from the already-ordered transaction footprint.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) from `ai-summary/CURRENT_STATE.md`. The trigger is every successful `InvokeHostFunctionOpFrame::doParallelApply`: C++ loads the fixed soroswap footprint into `mLedgerEntryCxxBufs`/`mTtlEntryCxxBufs`, crosses into `rust_bridge::invoke_host_function`, and Rust rebuilds enforcing storage before invoking the host.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:addReads:386-535` — serializes every loaded ledger entry and TTL into owned `CxxBuf`s and records read metrics before the Rust call.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:invokeHostFunction:557-584` — serializes host function, resources, source account, auth, ledger info, footprint entries, TTL entries, and base PRNG seed into the Rust bridge.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:invoke_host_function:408-452` — decodes resources/footprint, builds restored keys, calls `build_storage_map_from_xdr_ledger_entries`, clones the initial storage map, and constructs enforcing storage.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:build_storage_map_from_xdr_ledger_entries:959-1052` — decodes each `LedgerEntry`/`TtlEntry`, reconstructs keys, checks footprint membership, inserts into `StorageMap`, and fills absent footprint keys.

## Evidence

The current accepted soroswap trace places this path under `applyLedger`: timestamp overlap found `addReads` at **307.143 ms**, `read xdr with budget` at **192.932 ms**, `ScVal to Val` at **1,027.178 ms**, `map lookup*` at **1,119.826 ms**, `new map` visible in self-time, and `invoke_host_function` at **21.053 s total** across in-apply worker events. These are worker-thread aggregates, so they must be divided by the configured eight clusters, but the combined ingress/storage-construction family is large enough that removing a broad typed-boundary slice plausibly clears the ~6.9 ms/ledger Medium floor for the current 230.225 ms soroswap baseline. The source structure supports a single boundary fix rather than another single-site XDR micro-optimization: C++ already owns typed `LedgerEntry` values before `toCxxBuf`, and Rust immediately recovers typed entries only to construct enforcing storage.

This is intentionally broader than prior rejected CxxBuf-cache and per-site `xdr_size` ideas. A viable design would add a new next-protocol bridge representation for the supported footprint entry classes (`ACCOUNT`, `TRUSTLINE`, `CONTRACT_DATA`, `CONTRACT_CODE`, `TTL`) carrying typed values, `LedgerKey`, optional TTL, ingress XDR size for rent, and footprint position. Rust would build `StorageMap`/`TtlEntryMap` from this positional typed vector and charge an explicit protocol-next ingress cost; p26 would keep the current XDR path.

## Anti-Evidence

Adjacent attempts failed when they cached encoded bytes at the wrong layer or tried to reuse decoded host values without preserving protocol-visible metering. This hypothesis only remains viable if it is next-protocol-gated, covers every footprint entry type used by soroswap (including classic account/trustline keys in mixed SAC transfers), and avoids adding cache pressure that exceeds the saved encode/decode work. If the PoC merely skips C++ `toCxxBuf` while Rust still performs equivalent recursive `ScVal` conversion and map insertion per invocation, the result will fall below Medium like earlier read-side serialization hypotheses.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/ledger/summary.md` entry `001-typed-host-storage-ingress.md`
**Failed At**: reviewer

### Trace Summary

The current code still follows the described ingress path: C++ loads footprint entries, serializes each present entry and TTL into `CxxBuf`, passes those buffers through the `rust_bridge::invoke_host_function` CXX API, and the p26 Rust host decodes them to build the enforcing `StorageMap` and initial snapshot. That trace matches the prior condensed failure `001-typed-host-storage-ingress.md`, whose hypothesis was "Typed ingress to avoid XDR roundtrip when constructing enforcing host storage from Soroban parallel apply state." The new writeup adds protocol-gating language, but the prior final-review record already says future attempts need a concrete protocol-preserving design for every footprint entry type after the PoC failed on correctness blockers; this hypothesis restates that requirement rather than introducing a materially new mechanism.

### Code Paths Examined

- `src/transactions/InvokeHostFunctionOpFrame.cpp:386-535` — `addReads` obtains live footprint entries, converts each `LedgerEntry` and optional `TTLEntry` to owned XDR-backed `CxxBuf`, and stores them in `mLedgerEntryCxxBufs` / `mTtlEntryCxxBufs`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — `invokeHostFunction` serializes auth entries, host function, resources, source account, and passes the entry/TTL buffers to `rust_bridge::invoke_host_function`.
- `src/rust/src/bridge.rs:193-208` and `src/rust/src/soroban_invoke.rs:7-38` — the public CXX bridge and protocol dispatch API consume `Vec<CxxBuf>` entry and TTL arguments, preserving the existing encoded-XDR boundary.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-452` — `invoke_host_function` decodes resources, constructs the footprint, builds storage from encoded ledger/TTL entries, clones the initial storage map, and creates enforcing storage.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:959-1052` — `build_storage_map_from_xdr_ledger_entries` decodes each `LedgerEntry` / `TtlEntry`, reconstructs the `LedgerKey`, checks footprint membership, inserts the value into `StorageMap`, and inserts missing footprint keys as `None`.
- `ai-summary/success/ledger/002-cache-old-entry-xdr-sizes.md` — confirms only the old-entry rent-size reserialization was accepted and explicitly leaves the ingress decode/storage construction boundary in place.
- `ai-summary/fail/ledger/summary.md:34` — records the same typed XDR-free host-storage ingress idea as previously viable at review but rejected after PoC/final-review because the implementation could not be made correct.

### Why It Failed

This exact optimization direction has already been investigated. The prior condensed failure covers the same target boundary, same XDR-free typed ingress goal, and same need to preserve protocol metering and every supported footprint entry type. Because the new hypothesis does not supply a materially different design that resolves the recorded PoC correctness blockers, it is a duplicate rather than a novel review candidate.

### Lesson Learned

Typed Soroban host-storage ingress remains an architectural direction only if a future hypothesis provides a concrete, protocol-preserving implementation plan that addresses the previously failed PoC blockers. Merely adding protocol gating and restating typed entry/TTL metadata requirements is not enough to make the same XDR-free ingress idea novel.
