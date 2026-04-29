# H001: Replace O(rwKeys × modified_entries) Deep-XDR rwKey Scan in `recordStorageChanges` With Hashed Lookup

**Date**: 2026-04-29
**Subsystem**: soroban / transactions
**Severity**: Medium
**Impact**: Apply-time reduction in invoke-host writeback path (soroswap-heavy)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`InvokeHostFunctionOpFrame::ApplyHelper::recordStorageChanges`
(`src/transactions/InvokeHostFunctionOpFrame.cpp:641-767`) needs, per
modified host-output entry, to (a) determine which RW-footprint slot
that entry corresponds to and (b) mark that slot covered so any RW key
not produced by the host can be erased after the loop. With ~5–7 RW
keys per soroswap tx and ~5–30 modified entries per tx, the total work
should be O(modified_entries × hash_cost) — a single hash-table probe
per modified entry, not a linear deep-XDR equality scan over the entire
RW footprint plus a `getTTLKey(rwKeys[j])` reconstruction inside the
inner loop.

The cached `ParallelApplyLedgerKey` infrastructure landed by success #4
already keeps a primed hash and TTL key for every footprint key on
`TxBundle`; the writeback path simply does not consult it.

## Mechanism

Lines 672–695 of `recordStorageChanges` currently do:

```cpp
for (size_t j = 0; j < rwKeys.size(); ++j) {
    bool directMatch = rwKeys[j] == lk;          // deep XDR ==
    if (directMatch) { ... }
    else if (lk.type() == TTL && isSorobanEntry(rwKeys[j]) &&
             getTTLKey(rwKeys[j]) == lk) {       // SHA256 + deep ==
        relatedRwKey = j;
    }
    if (matchedRwKey != rwKeys.size() &&
        relatedRwKey != rwKeys.size()) break;
}
```

Each `rwKeys[j] == lk` is xdrpp-generated deep field-by-field equality.
For ContractData keys (the SAC balance/state keys soroswap touches on
every swap), the comparison walks the `SCAddress` and the `SCVec` topic
plus token-specific arguments. The TTL branch additionally calls
`getTTLKey(rwKeys[j])` — a SHA256 over the encoded inner key — for
every TTL output entry against every RW slot until a match is found.
The early-out helps but doesn't change the worst case.

For soroswap with ~48 invoke-host ops per ledger, ~6 RW keys per tx,
and ~10–15 modified entries per tx (data write + TTL bump per touched
contract data, plus the contract instance/code TTL bumps), this is on
the order of 50,000+ deep XDR comparisons and several thousand SHA256
TTL-key reconstructions per ledger. The latter is doubly wasteful
because `getTTLKey(rwKeys[j])` is the *same* key that the cached
`ParallelApplyLedgerKey::ttlKey` already holds.

The fix is to build a `unordered_map<LedgerKey, size_t, KeyHash>` (or
equivalent flat hash) once per call from `mResources.footprint.readWrite`
— actually re-using the already-cached hashes from `TxBundle` to avoid
rehashing — and replace the inner loop with two O(1) probes: one for
`lk` directly, one for `lk` viewed as a TTL key (mapped back to its
inner key, which is deterministic by structure). The "covered" tracking
remains via the same `BitSet`. Determinism is preserved because the
output (which entries get upserted, which get erased) depends only on
content, not iteration order.

## Trigger

Run the soroswap apply-load benchmark
(`scripts/run_apply_load_matrix.py --tracy`). Each invoke-host op on a
swap path produces 1 modified entry per touched balance/state plus its
TTL companion, against a footprint of 5–7 RW slots. The
`recordStorageChanges` zone — confirmed in the trace as a descendant of
`applyLedger > applySorobanStageClustersInParallel >
ParallelApplyHelper::doParallelApply > invokeHostFunction`-sibling —
will show measurable self-time on the apply thread and on the Soroban
worker threads.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:641-767` —
  `recordStorageChanges`, especially the inner loop at 672-695 and the
  `getTTLKey(rwKeys[j])` reconstruction at 685.
- `src/transactions/ParallelApplyStage.h:18-245` — `TxBundle` already
  caches `ParallelApplyLedgerKey` per footprint key including the TTL
  key; this is the natural place to thread the hash map through.
- `src/ledger/LedgerHashUtils.h` — `LedgerKeyHash` if a hash functor
  needs to be defined for `std::unordered_map<LedgerKey, size_t>`.

## Evidence

1. The inner scan is provably O(n*m): one deep XDR equality per
   (rwKey, modified_entry) pair, with the early-out only helping after
   a match is found. Soroswap's RW footprint and modified-entry counts
   per tx are both ~5–15, giving 25–225 deep comparisons per tx × ~48
   txs/ledger = ~1k–11k per ledger of work that should be ~96 hash
   probes (2 per modified entry × 48).
2. Success #4 (Cache parallel-apply LedgerKey hashes, +2.66%) explicitly
   notes that "Every apply-stage setup, add-read, writeback, TTL flush,
   and successful-tx commit over those immutable keys can otherwise
   redo lookup-side hashing or TTL-key derivation" — but the patch only
   touched `mTxEntryMap`/`mThreadEntryMap`/`mGlobalEntryMap` lookups,
   not this raw `==`-based linear scan inside `recordStorageChanges`.
   The hot path inside the writeback loop was missed.
3. `getTTLKey` calls `sha256` on every probe of the TTL branch (`src/ledger/LedgerTypeUtils.cpp`). The fail summary's
   "SHA256 budget ceiling" meta-pattern only applies to *budget-charged*
   sha256 done inside the host; this is an *unmetered* C++-side sha256
   on the apply path and is fully fair game for elimination.

## Anti-Evidence

- Footprint sizes are small (typically <10 entries), so a "linear scan
  is fine" defense is plausible. However, the per-comparison cost is
  not free for ContractData keys whose SCVal carries a multi-element
  `SCVec` topic; xdrpp `==` is roughly 200ns–1µs per pair on these.
  Combined with the SHA256 in the TTL branch (~500ns each), the
  cumulative cost lands in the Medium tier even for small footprints.
- The fix needs care around `mRwKeyExisted.get(relatedRwKey)` and the
  "matched vs related" distinction (line 718) — both must be preserved
  exactly. This is a refactor, not a wholesale rewrite.
- A previous fail (H006-style "tried to hoist constants out of the
  inner loop") was not specifically about this site; the only logged
  fail touching this region is H014 which addressed only `xdr_size(lk)`
  on line 701 and explicitly did not touch the `==` scan.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — related to success/soroban/004 and fail/soroban/014, but this exact `recordStorageChanges` RW-footprint scan was not previously rejected
**Failed At**: reviewer

### Trace Summary

The claimed linear scan exists: every encoded host ledger effect is decoded, converted to a `LedgerKey`, and compared against every read-write footprint key until the direct-entry coverage state is resolved. TTL output entries are worse than the hypothesis states because the loop does not break after finding only `relatedRwKey`; for TTL entries it continues through the whole RW footprint and calls `getTTLKey` for every Soroban RW key. However, the current checked-out `TxBundle` does not carry cached read-write footprint keys or cached TTL keys, so the proposed "reuse already-cached hashes from `TxBundle`" mechanism is not available in this source tree.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2673-2709` — `applySorobanStages` constructs `GlobalParallelApplyLedgerState`, applies each stage, then commits parallel results to `LedgerTxn`.
- `src/ledger/LedgerManagerImpl.cpp:2623-2636` and `2530-2574` — `applySorobanStage` launches `applySorobanStageClustersInParallel`, which runs clusters on worker futures and waits for them.
- `src/ledger/LedgerManagerImpl.cpp:2484-2511` — each worker calls `txBundle.getTx()->parallelApply`, then commits successful tx changes to the thread state.
- `src/transactions/TransactionFrame.cpp:2386-2430` and `src/transactions/OperationFrame.cpp:176-188` — a successful Soroban transaction dispatches its single operation through `OperationFrame::parallelApply`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1378` and `983-1015` — invoke-host parallel apply constructs the helper, runs `addFootprint`, `invokeHostFunction`, `recordStorageChanges`, event collection, refundable-resource consumption, and success finalization.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:641-767` — `recordStorageChanges` performs the RW-key coverage scan, writes non-TTL resource metrics, upserts modified entries, and erases RW keys not returned by the host.
- `src/ledger/LedgerTypeUtils.cpp:30-37` — `getTTLKey` computes TTL keys by XDR-encoding the inner Soroban key and SHA-256 hashing it.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:180-292` and `src/rust/src/soroban_proto_any.rs:261-301` — Rust emits ledger changes for storage-map footprint entries, and the bridge converts RW new values plus positive TTL changes into `modified_ledger_entries`.
- `src/transactions/ParallelApplyStage.h:74-114` and `src/transactions/TransactionFrameBase.h:47-80` — `TxBundle` only stores the tx/result/tx number/effects, while `ParallelApplyLedgerKey` has a lazy per-object hash but no TxBundle-level cached footprint/TTL-key collection.

### Why It Failed

The inefficiency is real, but it is below the optimize-soroswap review threshold and the proposed implementation premise is stale for the checked-out code. The removable work is confined to a very small per-transaction footprint scan: a handful of deep equality checks for direct RW entries and, when TTL changes are returned, repeated `getTTLKey` calls over roughly 5-7 Soroban RW keys. Prior objective records bound the broader TTL/SHA256-key-recomputation family as Low/sub-1% to Low-tier work, and the accepted parallel-apply key-cache success averaged only 2.66% while covering many more map-probe sites than this single writeback scan.

A fresh `unordered_map` built inside every `recordStorageChanges` call would also pay per-tx allocation, insertion, `LedgerKey` hashing, and TTL-key construction costs before any lookup, so with soroswap-sized footprints it is not clearly cheaper than the existing small linear scan. Without an existing `TxBundle` cached-key surface to reuse, and without trace evidence that `recordStorageChanges` self-time alone exceeds the current ~9 ms per 305 ms ledger Medium floor, this cannot credibly project to the required 3-10% apply-time reduction.

### Lesson Learned

Do not promote small-footprint C++ writeback scans to Medium severity solely from asymptotic shape. For soroswap, first confirm both that the cached-key infrastructure exists in the target checkout and that the specific `recordStorageChanges` zone has enough apply-window self-time to survive per-tx map-construction overhead; otherwise the opportunity is at most a Low cleanup and is rejected by this objective.
