# H001: Cache pre-serialized XDR bytes in `InMemorySorobanState` to eliminate per-load `toCxxBuf(LedgerEntry)` serialization on the soroban apply hot path

**Date**: 2026-04-29
**Subsystem**: transaction-ledger (`InvokeHostFunctionOpFrame::addReads` ↔ `InMemorySorobanState`)
**Severity**: Medium (potentially High)
**Impact**: Apply-time reduction; soroswap (CONTRACT_DATA-heavy footprints) primary beneficiary
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

For protocol-23+ Soroban ledger entries that live in `InMemorySorobanState`,
the bytes the Rust host receives for a footprint key are a pure function of
the stored `LedgerEntry`. The expected efficient implementation is to compute
each `LedgerEntry`'s XDR encoding **exactly once** (when the entry is first
inserted into `InMemorySorobanState`, e.g. during `createContractDataEntry`
/ `updateContractData`) and to hand a pointer to those cached bytes back on
every subsequent read. Reading a footprint entry should not require
allocating a fresh `std::vector<uint8_t>` and walking the XDR encoder over
the entry on every `addReads` call.

## Mechanism

`InvokeHostFunctionApplyHelper::addReads`
(`src/transactions/InvokeHostFunctionOpFrame.cpp:484`) calls
`toCxxBuf(*entryOpt)` on every loaded footprint `LedgerEntry`.
`toCxxBuf` (`src/transactions/TransactionUtils.h:370-376`) is:

```cpp
template <typename T>
CxxBuf toCxxBuf(T const& t)
{
    return CxxBuf{std::make_unique<std::vector<uint8_t>>(xdr::xdr_to_opaque(t))};
}
```

Every call heap-allocates a `std::vector<uint8_t>` and walks the XDR
serializer over the entire `LedgerEntry`. For soroswap (CONTRACT_DATA-heavy
footprints, ~150–1000 bytes per entry serialized) this is on the order of
~1 μs per entry including the allocation, copy into the vector, and the
unique_ptr wrap.

`InMemorySorobanState::get(LedgerKey)`
(`src/ledger/InMemorySorobanState.cpp:206-238`) returns
`it->get().ledgerEntry`, a `std::shared_ptr<LedgerEntry const>` that lives
for the entry's full residency in the in-memory map. The map already caches
`sizeBytes` next to the entry (`ContractDataMapEntryT::sizeBytes`,
`InMemorySorobanState.h:53-54`), explicitly because "repeated `xdr_size()`
calls during updates" were measured as a problem. The same logic applies
to the full XDR bytes used by `toCxxBuf`: they are derivable once from the
entry, never change while the entry is in the map, and are re-computed on
every footprint load. The expected behavior is met by storing a
`std::shared_ptr<std::vector<uint8_t> const>` (or equivalent immutable
buffer) alongside `ledgerEntry` and `sizeBytes`, and exposing a getter
that returns it directly to `addReads` (and the equivalent
`handleArchivedEntry` / autorestore path at line 1126).

For a measured soroswap ledger the cost is: 4000 txs × ~10 footprint
entries each (typical: 5 RO + 5 RW CONTRACT_DATA, plus 1–2 CONTRACT_CODE)
= ~40 000 `toCxxBuf` calls per measured ledger. At ~1 μs each (allocation +
serialize) this is ~40 ms / ~6.5 % of the 620 ms median apply time.
Larger entries push this toward the upper end of Medium territory.

## Trigger

Run the soroswap apply-load benchmark
(`scripts/run_apply_load_matrix.py` with `model_tx="soroswap"`,
`docs/apply-load-benchmark-sac.cfg`-derived config, 4000 swaps / ledger
× 8 clusters). In a Tracy zone hierarchy under `applyLedger` →
`applyParallelPhase` → `applyThread` → `addReads`, time spent in
`toCxxBuf` and `xdr::xdr_to_opaque<LedgerEntry>` will be observable on
every loaded footprint entry.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:484` —
  `auto leBuf = toCxxBuf(*entryOpt);` per footprint entry. Hot path.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:493` —
  `toCxxBuf(*ttlEntry)` per loaded TTL entry. TTLEntry is small (~24 B
  serialized) but still allocates; the same caching approach applies to
  TTL data already stored inline in `ContractDataMapEntryT` /
  `ContractCodeMapEntryT`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1126,1186` —
  `handleArchivedEntry` autorestore path also calls `toCxxBuf(le)` and
  `toCxxBuf(ttlEntry.data.ttl())`; for hot-archive restores the entry
  came from `mStateSnapshot.loadArchiveEntry(lk)`, but the same caching
  mechanism could be plumbed there.
- `src/transactions/TransactionUtils.h:370-376` — `toCxxBuf` definition;
  if a `LedgerEntry`-aware overload returned a shared cached buffer
  wrapped in `CxxBuf`, all the call sites above could opt into the
  fast path with a one-line change.
- `src/ledger/InMemorySorobanState.h:46-86` — `ContractDataMapEntryT`
  and `ContractCodeMapEntryT` structures; add a
  `std::shared_ptr<std::vector<uint8_t> const> serializedBytes` (or
  inline `std::vector<uint8_t>`) field alongside `ledgerEntry` and
  `sizeBytes`. Existing `sizeBytes` field is conceptually the same
  optimization applied to a different downstream consumer.
- `src/ledger/InMemorySorobanState.cpp:206-238` — `get()` returns
  `shared_ptr<LedgerEntry const>`. Add a parallel `getSerialized()` /
  return a small struct with both pointers so `addReads` can pick the
  bytes directly.
- `src/ledger/InMemorySorobanState.cpp:240-...` —
  `createContractDataEntry`, `updateContractData`, `createContractCodeEntry`
  insertion paths: serialize once and store the bytes alongside the
  `LedgerEntry`.
- `src/transactions/ParallelApplyUtils.cpp:336-342` —
  `ParallelLedgerAccessHelper::getLedgerEntryOpt` returns
  `std::optional<LedgerEntry>` (a value copy). To preserve the cache
  benefit for entries that ultimately come from `InMemorySorobanState`,
  either thread the cached buffer through this layer or have
  `addReads` query `InMemorySorobanState` directly when a footprint
  read misses the per-tx / per-thread / global maps and is served by
  the in-memory state.

## Evidence

- `ContractDataMapEntryT` already caches `sizeBytes` for exactly this
  reason: the comment at `InMemorySorobanState.h:53-54` states "Cached
  XDR serialized size to avoid repeated `xdr_size()` calls". The same
  logic applies a fortiori to the *full* serialization that `toCxxBuf`
  performs on every footprint load, which is strictly more work than
  the size walk that was already worth caching.
- `getLedgerEntryOpt` returns by value (`std::optional<LedgerEntry>`)
  and `addReads` immediately serializes the value: the entire round-trip
  from "stored shared_ptr" → "value-copied LedgerEntry" → "fresh
  serialized vector" is per-load overhead the cache would eliminate.
- `addReads` calls `toCxxBuf(*entryOpt)` *unconditionally* for every
  footprint key that resolves to a live entry; there is no fast path for
  in-memory soroban entries. (`InvokeHostFunctionOpFrame.cpp:474-498`).
- For a soroswap measured ledger with 4000 swaps the call count
  saturates: ~10 footprint entries / tx × 4000 txs = ~40 000 fresh
  vector allocations + XDR walks per measured ledger, all on the
  applyThread critical path.
- Memory cost is bounded: soroswap's in-memory soroban state holds on
  the order of ~10 000 ContractData entries (4000 swaps + token-pair
  metadata + balances). Caching ~200–800 bytes of serialized form per
  entry adds ~2–8 MB to in-memory state — well within the typical
  in-memory soroban state budget (`SOROBAN_STATE_TARGET_SIZE_BYTES` ≫
  this) and trivial relative to per-host module cache pressure.
- `sizeBytes` is `uint32_t const` and the struct's `ledgerEntry` is
  `shared_ptr<LedgerEntry const> const` (fields declared `const` after
  construction): the entry is conceptually immutable for its residency,
  so cached bytes are equally safe to share across threads without
  synchronization once published.
- The existing `Tracy` zones in `addReads` will make the speedup
  directly visible in the same trace (the disappearance of allocator
  and serializer self-time inside the loop body).

## Anti-Evidence

- Storing serialized bytes increases per-entry memory by roughly the
  serialized size (~150–1000 B for typical CONTRACT_DATA, larger for
  CONTRACT_CODE wasm). For soroban state on the order of 10⁴–10⁵
  entries this is a few-MB to low-tens-of-MB increase. CONTRACT_CODE
  wasm is already large (10s–100s of KB per entry); duplicating it as
  serialized bytes meaningfully inflates that line item — the PoC
  should either (a) skip caching for CONTRACT_CODE and only cache
  CONTRACT_DATA / TTL (the soroswap-relevant path), or (b) reuse the
  contract-code wasm slice without copy.
- Some `addReads` consumers are not served by `InMemorySorobanState`
  — classic entries (no soroswap impact) and entries restored from
  the hot archive (`mStateSnapshot.loadArchiveEntry`) take the
  fall-through path. Those must continue to call `toCxxBuf(le)` (or
  serialize once into a fresh `CxxBuf`). The cache is opt-in: it only
  needs to fire on the dominant in-memory-soroban path.
- The serialized bytes must be invalidated whenever the entry is
  mutated. `InMemorySorobanState`'s update path already replaces the
  `ContractDataMapEntryT` wholesale (the field is `const`), so this
  is naturally enforced — but the PoC must verify that no mutation
  bypass exists.
- During parallel apply, modified footprint entries first land in
  `mTxEntryMap` / `mThreadEntryMap` (as `LedgerEntry` values, not
  cached bytes). When a same-tx read sees its own write, the cache
  cannot help — `toCxxBuf` is unavoidable for entries that were
  produced by the host on this tx. For soroswap each tx writes its
  small RW footprint (~5 keys) and reads a larger RO footprint (~5
  keys); the cache wins primarily on the RO side and on fresh reads
  by later txs in the same cluster against entries committed by
  earlier txs (via the global map → in-memory state fall-through).
  Even capturing only the RO half is on the order of 20 000 saved
  serializations per measured ledger.
- `CxxBuf` ownership semantics: today `CxxBuf` owns a unique_ptr to
  a vector. Returning a shared cached buffer requires either (a) a
  new `CxxBuf` flavor that holds a `shared_ptr<vector const>` (or
  `shared_ptr<vector>`) and is ABI-compatible with cxx.rs's
  expectation, or (b) a memcpy from the cached bytes into a new
  unique_ptr — the latter undoes most of the win, so the former is
  preferred. cxx.rs `Vec<u8>` interop is the binding contract; the
  current `CxxBuf` already uses raw `std::vector<uint8_t>` so a
  shared-pointer-backed variant is feasible without changing the
  Rust side.
- Determinism is preserved: the cached bytes are exactly
  `xdr::xdr_to_opaque(le)`, the same value `toCxxBuf` produces today.
  Concurrency is preserved: cached bytes are immutable after
  insertion and `shared_ptr` provides safe sharing.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-04-27
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated

### Trace Summary

The hot path is `InvokeHostFunctionOpFrame::doParallelApply` creating an `InvokeHostFunctionParallelApplyHelper`, calling `addFootprint`, and then serializing every live footprint entry in `addReads` before passing `Vec<CxxBuf>` to the Rust host. For p23+ parallel Soroban apply, `ParallelLedgerAccessHelper::getLedgerEntryOpt` reads through `TxParallelApplyLedgerState` and `ThreadParallelApplyLedgerState`; when no tx/thread/global override exists, thread state falls back to `InMemorySorobanState::get`, copies the `LedgerEntry`, and `addReads` immediately re-serializes it. The inefficiency is real and hot: the current bridge type owns a fresh `UniquePtr<CxxVector<u8>>`, and every `toCxxBuf(LedgerEntry)` call allocates and runs `xdr::xdr_to_opaque` even for immutable LCL Soroban entries.

### Code Paths Examined

- `src/transactions/InvokeHostFunctionOpFrame.cpp:386-535` — `addReads` computes TTL liveness, calls `getLedgerEntryOpt`, then unconditionally serializes live entries via `toCxxBuf(*entryOpt)` and TTLs via `toCxxBuf(*ttlEntry)` before appending to the host input buffers.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:982-1018` — `doApply` calls `addFootprint` before `invokeHostFunction`, so the serialization happens once per invocation on the apply hot path.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1378` — p23+ Soroban transactions enter the reviewed path through `doParallelApply`.
- `src/transactions/TransactionUtils.h:370-376` — `toCxxBuf` constructs a new `std::vector<uint8_t>` from `xdr::xdr_to_opaque(t)` for every call.
- `src/rust/src/bridge.rs:13-15` and `src/rust/src/common.rs:12-15` — `CxxBuf` is currently a unique-pointer-owned C++ byte vector viewed by Rust as a borrowed byte slice.
- `src/rust/src/soroban_proto_any.rs:391-448` and `src/rust/src/soroban_proto_all.rs:95-129` — the Rust host receives iterators over borrowed `CxxBuf` slices; it does not require C++ to allocate a new vector per entry if the bridge can expose stable immutable bytes for the duration of the call.
- `src/transactions/ParallelApplyUtils.cpp:337-342` — `ParallelLedgerAccessHelper::getLedgerEntryOpt` returns an `std::optional<LedgerEntry>` value, losing any source-side cached representation.
- `src/transactions/ParallelApplyUtils.cpp:646-718` — current code already preloads read-only Soroban entries and TTLs from `InMemorySorobanState` into `mGlobalEntryMap`; this avoids repeated in-memory hash lookups but still stores plain `LedgerEntry` values, so it does not mitigate the repeated XDR serialization in `addReads`.
- `src/transactions/ParallelApplyUtils.cpp:1084-1121` — `ThreadParallelApplyLedgerState::getLiveEntryOpt` falls back to `mInMemorySorobanState.get(key)` for Soroban entries and immediately wraps a copied entry in scoped state.
- `src/transactions/ParallelApplyUtils.cpp:1294-1314` — `TxParallelApplyLedgerState::getLiveEntryOpt` first checks tx-local writes, then adopts from thread state; this means any cached-byte fast path must preserve tx/thread override semantics.
- `src/ledger/InMemorySorobanState.h:46-86` and `src/ledger/InMemorySorobanState.cpp:94-144,240-304` — contract-data and contract-code entries are replaced wholesale on create/update and already carry cached size metadata, making immutable serialized-byte caching mechanically safe for resident LCL entries.
- `src/ledger/InMemorySorobanState.cpp:412-445` — TTL entries are synthesized from stored `TTLData`, so TTL byte caching would need to be derived/stored alongside the owning data/code entry rather than assuming a resident TTL `LedgerEntry`.
- `src/ledger/InMemorySorobanState.cpp:537-605` — the in-memory cache is advanced only after ledger close, so dirty entries produced during the current parallel apply stage are not covered by an LCL-only cache.

### Findings

The claimed inefficiency exists. `addReads` serializes every present footprint entry into a newly allocated `CxxBuf` on every invoke-host-function operation, and the p23+ soroswap apply path executes this per transaction inside `closeLedger`.

Existing optimizations do not cover this waste. The global/thread preloading in `ParallelApplyUtils` reduces repeated `InMemorySorobanState::get` lookups and copies for read-only Soroban keys, but it still stores scoped `LedgerEntry` values and therefore still forces `addReads` through `toCxxBuf` for every transaction.

The proposed optimization is correct only if the cached bytes are propagated through the same ledger-access path that chooses the entry value. A direct `addReads` side lookup into `InMemorySorobanState` would be unsafe for keys overridden in `mTxEntryMap`, `mThreadEntryMap`, or `mGlobalEntryMap`; the fast path should attach cached bytes to clean entries sourced from `InMemorySorobanState` and fall back to fresh serialization for tx-local/thread-dirty/global-dirty entries.

The impact plausibly meets the objective's Medium threshold. Even if the cache only covers unchanged read-only Soroban entries and TTLs, soroswap's 4000-tx ledger shape yields tens of thousands of avoided `xdr_to_opaque(LedgerEntry)` calls and heap allocations per ledger; this is materially larger than the previously rejected `xdr_size(LedgerKey)` micro-optimization and is expected to land in the 3-10% range if the bridge avoids copying cached bytes back into fresh vectors.

### PoC Guidance

- **Target code**: `src/ledger/InMemorySorobanState.h/.cpp`, `src/transactions/ParallelApplyUtils.h/.cpp`, `src/transactions/InvokeHostFunctionOpFrame.cpp`, `src/transactions/TransactionUtils.h`, and the CXX bridge declarations in `src/rust/src/bridge.rs` / `src/rust/src/common.rs`.
- **Change description**: cache immutable serialized bytes for resident `CONTRACT_DATA` entries, and optionally their synthesized TTL entries, when `InMemorySorobanState` creates or replaces map entries. Thread those cached bytes through `GlobalParallelApplyEntry`, `ThreadParallelApplyEntry`, and `TxParallelApplyLedgerState::getLiveEntryOpt` for clean entries sourced from in-memory state. Use the cached buffer in `addReads` only when it corresponds to the exact entry selected by the tx/thread/global lookup; otherwise keep `toCxxBuf`.
- **Correctness check**: preserve tx-local and thread/global override ordering, TTL liveness behavior, autorestore handling, and exact `xdr::xdr_to_opaque(LedgerEntry)` byte identity. Do not cache or reuse bytes for entries returned by the Rust host unless the PoC deliberately carries those RustBuf bytes through the dirty-entry maps with the decoded `LedgerEntry`.
- **Benchmark focus**: measure soroswap apply-load top-line apply time and Tracy self-time under `applyParallelPhase` / `applyThread` / `addReads`; the expected win is disappearance of most `toCxxBuf(LedgerEntry)` allocator/XDR-serializer time for unchanged read-only Soroban footprint entries, with a Medium target of 3-10% apply-time reduction.
