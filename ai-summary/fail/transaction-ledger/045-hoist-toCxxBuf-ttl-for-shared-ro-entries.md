# H045: Hoist `toCxxBuf(*ttlEntry)` for shared read-only footprint entries to a per-cluster cache

**Date**: 2026-05-21
**Subsystem**: transaction-ledger / Soroban host invocation setup (`addReads`)
**Severity**: Low
**Impact**: Sub-noise — projected ≤25 µs/ledger critical-path
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

For each invoke-host-function transaction, `InvokeHostFunctionOpFrame::HostInvoker::addReads`
loads each footprint key's TTL entry and serializes it via `toCxxBuf(*ttlEntry)` for the
Rust bridge. For shared read-only footprint entries (e.g. soroswap pair contract
instance, token code, code-hash entry) that appear in every cluster transaction's
read-only footprint, the resulting TTL CxxBuf bytes are byte-identical until the
entry's `liveUntilLedgerSeq` is bumped. The efficient path should reuse a single
cached `CxxBuf` per shared RO TTL entry across the cluster's transactions rather
than re-serializing the same 16-byte TTLEntry hundreds of times per cluster.

## Mechanism

`addReads` calls `toCxxBuf(*ttlEntry)` (`InvokeHostFunctionOpFrame.cpp:493`) for
every live Soroban footprint entry on every invoke transaction. For a soroswap
cluster of ~250 transactions where each tx footprint shares the same 4–6 read-only
Soroban entries (pair instance, code, code-hash, etc.), this yields ~250 × 5 ≈
1,250 redundant serializations of identical 16-byte TTLEntry payloads per cluster
worker. The actual deviation from expected behavior is that each call performs an
independent `xdr::xdr_to_opaque(*ttlEntry)` walk and a fresh `std::vector<uint8_t>`
allocation, when a single cached CxxBuf could serve all transactions until the
underlying TTLEntry's `liveUntilLedgerSeq` is bumped.

## Trigger

Run the current soroswap apply-load benchmark per `ai-summary/CURRENT_STATE.md`.
Each Soroban cluster worker iterates ~250 transactions, each calling `addReads`
twice (RO + RW footprints), each entering the `ttlEntry ? toCxxBuf(*ttlEntry) : ...`
branch (`InvokeHostFunctionOpFrame.cpp:491-494`) on every live soroban footprint key.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:491-497` — per-key `toCxxBuf(*ttlEntry)` and `mTtlEntryCxxBufs.emplace_back`
- `src/transactions/InvokeHostFunctionOpFrame.cpp:411` — `getLedgerEntryOpt(ttlKey)` load that feeds `ttlEntry`
- `src/rust/src/host_object.rs` (toCxxBuf) — XDR serialization + `std::vector<uint8_t>` allocation

## Evidence

- The bulk-build success (`success/transaction-ledger/001-bulk-build-host-storage-maps.md`)
  established that shared RO footprint entries cross all cluster transactions, so
  the redundancy is structurally real.
- Tracy `addReads` self-time on the current soroswap baseline is 196 ms aggregate
  across the trace (from `9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`).

## Anti-Evidence

- Per-cluster `CxxBuf` cache requires `std::vector<uint8_t>` retention until end
  of cluster apply, paralleling the pattern that already regressed in
  `001-cache-serialized-soroban-entries-in-memory-state` (PoC regressed soroswap
  apply time across all three benchmark runs due to L1/L2 cache pressure).
- TTLEntry is only 16 bytes (`Hash keyHash` + `uint32 liveUntilLedgerSeq`); the
  per-call XDR serialization cost is bounded by a handful of memcpys plus a small
  vector allocation — not a hotspot.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Failed At**: hypothesis
**Novelty**: PASS — narrower than `005-ttl-key-memoization-shared-ro.md` (that
hypothesis caches *TTL key construction*, not the serialized CxxBuf of the
loaded TTL entry) and orthogonal to `009-per-cluster-cxxbuf-cache-shared-ro-soroban-entries.md`
(which caches the *ledger entry* CxxBuf, not the TTL entry CxxBuf). However the
quantitative ceiling and the cache-pressure failure mode are identical.

### Why It Failed

Even in the most optimistic accounting:

- TTLEntry payload is 16 bytes; XDR serialization is ~50 ns per call (single
  memcpy + 2 uint32 writes + sized `std::vector` alloc/move).
- Soroswap cluster shape is ~250 tx × ~5 RO soroban entries = ~1,250 TTL CxxBuf
  constructions per cluster worker.
- Aggregate per-cluster removable cost upper bound: 1,250 × 50 ns ≈ 62 µs per
  worker. Critical-path per ledger: 62 µs / 1 cluster-of-interest ≈ 62 µs, and
  across 71 trace ledgers ≈ 4.4 ms aggregate (≈ 0.02% of measured `applyLedger`
  total).
- The objective floor is Medium = 3% apply time = ~8.2 ms/ledger. The TTL CxxBuf
  cache yields ~62 µs/ledger — three orders of magnitude below threshold.
- The cache-pressure failure mode is the same as the rejected
  `001-cache-serialized-soroban-entries-in-memory-state`: retaining serialized
  bytes for the cluster lifetime adds working-set pressure that the XDR-side
  savings cannot compensate for, even at this much smaller per-entry payload
  size.

### Lesson Learned

When considering CxxBuf caching for shared read-only Soroban footprint data,
size the per-cluster removable cost against both (a) the small per-entry
serialization cost (TTL entries are 16 bytes; even ledger entries are typically
<1 KB) and (b) the cache-pressure tax from retained `std::vector<uint8_t>`
buffers. Both vectors of optimization (global serialized cache, per-cluster
cache) hit the same ceiling: the bridge ABI's mandatory copy and the working-set
inflation negate the serialization savings. Future shared-RO CxxBuf caching
proposals must either (a) bridge zero-copy (no `std::vector` copy) or (b)
demonstrate a measurable critical-path saving above the 3% Medium floor before
being promoted to hypothesis.
