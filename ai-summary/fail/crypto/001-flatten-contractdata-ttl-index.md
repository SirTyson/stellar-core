# H001: Flatten ContractData TTL-key index to remove per-lookup SHA and virtual heap churn

**Date**: 2026-05-23
**Subsystem**: crypto, ledger
**Severity**: Medium
**Impact**: Soroswap apply-time reduction in hot storage lookup / TTL-key hashing path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

`InMemorySorobanState` should locate hot `CONTRACT_DATA` and associated `TTL`
entries by their already-derived TTL key hash without allocating a polymorphic
temporary entry for every lookup and without recomputing the stored entry's
`getTTLKey(LedgerEntryKey(*entry))` during hash/equality checks. A lookup by
`TTL` key should be a direct `uint256` keyed probe, and a lookup by
`CONTRACT_DATA` key should compute the TTL hash at most once before probing a
flat index.

## Mechanism

The current contract-data index is an `unordered_set<InternalContractDataMapEntry>`
whose entries hide either a `ValueEntry` or `QueryKey` behind a
`std::unique_ptr<AbstractEntry>`. `InMemorySorobanState::get(CONTRACT_DATA)`
constructs `InternalContractDataMapEntry(ledgerKey)`, which allocates a
`QueryKey` and computes `getTTLKey(ledgerKey)`; successful equality against the
stored `ValueEntry` then calls `ValueEntry::copyKey()`, which recomputes
`getTTLKey(LedgerEntryKey(*entry.ledgerEntry))`. Replacing this with a flat
representation that stores the TTL key hash in the value (for example,
`unordered_map<uint256, ContractDataMapEntryT>` or an `unordered_set` entry with
a concrete cached `uint256 keyHash`) would remove one SHA256/XDR materialization
from every successful contract-data probe and remove per-probe heap allocation
and virtual dispatch.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=2000, T=8`). The
swap path performs hundreds of thousands of host storage reads across the trace;
each balance, allowance, instance, and TTL lookup passes through
`Host::storage get` and then `InMemorySorobanState::get` for in-memory Soroban
state. The issue is triggered most strongly by successful `CONTRACT_DATA` and
`TTL` probes, where the current polymorphic index compares against stored
`ValueEntry` objects.

## Target Code

- `src/ledger/InMemorySorobanState.h:88-178` — `InternalContractDataMapEntry`,
  `AbstractEntry`, and `ValueEntry::copyKey()` recompute the TTL key hash from
  the stored ledger entry.
- `src/ledger/InMemorySorobanState.h:180-284` — `QueryKey` and
  `InternalContractDataMapEntry(LedgerKey const&)` allocate a polymorphic lookup
  object and route hash/equality through virtual calls.
- `src/ledger/InMemorySorobanState.cpp:206-238` — hot
  `InMemorySorobanState::get` probes the polymorphic set for `CONTRACT_DATA`
  and `TTL` reads.
- `src/ledger/LedgerTypeUtils.cpp:30-38` — `getTTLKey` materializes XDR bytes
  and calls `sha256` for each recomputation.

## Evidence

The latest accepted soroswap Tracy trace from `ai-summary/CURRENT_STATE.md` is
`/mnt/nvme2/apply-load/62ee1ffb5d05-20260523-010230/logs/62ee1ffb5d05-20260523-010230-02-soroswap-tx-2000-t-8.tracy`.
`csvexport-release -e` reports `storage get`
(`soroban-env-host/src/storage.rs:329`) at 224,247,260 ns self over 323,533
calls and C++ `sha256` (`src/crypto/SHA.cpp:33`) at 677,705,943 ns self over
498,218 calls in the whole trace. Timestamp-filtering individual events to
`applyLedger` windows confirms the target is apply-contained: `storage get`
contributes 672,084,842 ns total over 321,802 events inside `applyLedger`, and
C++ `sha256` contributes 306,449,379 ns over 339,407 events inside
`applyLedger`. `InMemorySorobanState.h` shows successful contract-data equality
must recompute the stored entry TTL hash via `ValueEntry::copyKey()`, so this
hypothesis targets a repeated SHA/XDR recomputation plus allocation/virtual
overhead on a hot storage-read path, not a primitive-only SHA micro-tweak.

## Anti-Evidence

Prior failures H003/H004/H062/H065 establish that TTL-key SHA256-only
optimizations are often below threshold, and this hypothesis must not be sized
as if it removes all apply-path SHA256. The viable part is broader and more
structural: eliminate the polymorphic heap representation and stored-entry
re-hashing from the hot in-memory index. A PoC must isolate the `CONTRACT_DATA`
success path and show that the removable equality/hash/allocation work, after
parallel-worker normalization and non-Tracy benchmark runs, clears the 3%
Medium floor.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS
**Failed At**: reviewer

### Trace Summary

The claimed local inefficiency is real: successful `CONTRACT_DATA` and `TTL`
probes through `mContractDataEntries.find(InternalContractDataMapEntry(...))`
allocate a lookup object and can force stored `ValueEntry::copyKey()` to rebuild
the TTL key with `sha256(xdr::xdr_to_opaque(...))`. However, the trigger is
mis-scoped. The close-ledger path loads footprint entries into C++ buffers before
the Rust host invocation; Rust `storage get` then runs inside
`e2e_invoke::invoke_function` over those preloaded entries and does not call back
into `InMemorySorobanState::get` per host storage read.

### Code Paths Examined

- `src/ledger/InMemorySorobanState.h:107-284` — confirmed polymorphic `InternalContractDataMapEntry`, heap-owned `QueryKey`/`ValueEntry`, virtual `hash()`/`copyKey()`, and stored-entry TTL-key recomputation in `ValueEntry::copyKey()`.
- `src/ledger/InMemorySorobanState.cpp:206-238` — confirmed `InMemorySorobanState::get` probes the contract-data set for `CONTRACT_DATA`, the contract-code map for `CONTRACT_CODE`, and delegates `TTL` to `getTTL`.
- `src/ledger/InMemorySorobanState.cpp:412-446` — confirmed `getTTL` probes the contract-data set for TTL keys, constructs synthetic TTL entries on success, and only then falls back to the contract-code map.
- `src/ledger/LedgerTypeUtils.cpp:30-38` — confirmed `getTTLKey` serializes the full `CONTRACT_DATA`/`CONTRACT_CODE` `LedgerKey` and hashes it with C++ `sha256`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:385-535` — traced `addReads`: for each declared footprint key, C++ loads the associated TTL and live entry once, serializes live entries and TTL entries into `mLedgerEntryCxxBufs`/`mTtlEntryCxxBufs`, and reserves those buffers for host invocation.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — confirmed the Rust bridge call passes prebuilt `ledger_entries` and `ttl_entries` vectors to `rust_bridge::invoke_host_function`.
- `src/rust/src/soroban_invoke.rs:7-38` and `src/rust/src/soroban_proto_any.rs:391-448` — confirmed Rust dispatches to the protocol host with iterators over those vectors; `e2e_invoke::invoke_function` executes after the C++ footprint load.
- `src/transactions/ParallelApplyUtils.cpp:646-718` and `src/transactions/ParallelApplyUtils.cpp:1084-1121` — confirmed parallel apply preloads read-only Soroban entries into global/thread maps and only falls back to `InMemorySorobanState::get` when a footprint key is absent from those maps, not per internal host storage access.
- `src/ledger/LedgerManagerImpl.cpp:2483-2521`, `src/ledger/LedgerManagerImpl.cpp:2673-2710`, and `src/ledger/LedgerManagerImpl.cpp:2966-3029` — traced the `applyParallelPhase`/`applySorobanStages`/worker-thread path that constructs the parallel ledger state, applies Soroban transactions, and commits changes back to `LedgerTxn`.

### Why It Failed

The hypothesis attributes the 323k Rust `storage get` events to
`InMemorySorobanState::get`, but the code path shows these are separated by the
FFI boundary: C++ `InMemorySorobanState` is used while loading declared
footprint entries, while Rust `storage get` is executed later against the
preloaded host storage map. Flattening the C++ contract-data index could remove
one stored-entry TTL-hash recomputation and one heap allocation from successful
C++ footprint probes, but it would not remove the measured Rust storage-get work
and cannot be sized from the full apply-path C++ `sha256` total. With the
dominant trigger invalid and the remaining optimization limited to footprint
load/probe overhead, the projected impact is below the objective's Medium floor
of 3% apply-time reduction.

### Lesson Learned

For Soroban apply performance, distinguish host-internal storage operations from
C++ footprint materialization. Optimizations to `InMemorySorobanState` may be
valid cleanup, but they should be sized only against C++ footprint loading and
TTL-entry materialization costs, not against Rust `storage get` samples inside
the host invocation.
