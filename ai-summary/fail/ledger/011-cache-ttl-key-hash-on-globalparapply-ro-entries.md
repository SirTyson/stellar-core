# H011: Cache TTL key hash on read-only Soroban GlobalParApply entries to skip per-tx `getTTLKey` SHA256 + XDR re-encoding

**Date**: 2026-05-02
**Subsystem**: ledger / parallel apply / TTL key derivation
**Severity**: Medium
**Impact**: 3-4% soroswap apply-time reduction by eliminating tens of
thousands of redundant `xdr_to_opaque(LedgerKey)` + `sha256(...)`
computations per ledger when the same read-only Soroban footprint key is
visited by every transaction.
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

Within a single ledger close, the TTL key for an immutable read-only
Soroban entry should be computed **at most once** (and ideally retrieved
without recomputation, since its hash already serves as the index in
`InMemorySorobanState::mContractDataEntries` and
`mContractCodeEntries`). Every transaction that includes the same
read-only contract instance, contract code, or contract data key in its
footprint should observe a constant-time TTL-key lookup, not a fresh XDR
encoding plus SHA256 of the underlying `LedgerKey`.

## Mechanism

`InvokeHostFunctionOpFrame::HostFunctionMetricsHelper::addReads`
(`src/transactions/InvokeHostFunctionOpFrame.cpp:406`) calls
`getTTLKey(lk)` for every Soroban footprint key on every transaction.
`getTTLKey` (`src/ledger/LedgerTypeUtils.cpp:30-38`) calls
`xdr::xdr_to_opaque(e)` to encode the entire `LedgerKey` and then
`sha256(...)` over the encoded bytes. The same key derivation also
fires from `commitChangeFromSuccessfulTx` and from
`InvokeHostFunctionOpFrame::doApply` paths around handling auto-restore
and TTL bumps. For soroswap, every swap shares the same router-instance
key, two SAC-instance keys, and two SAC-code keys in its read-only
footprint — so each ledger recomputes the same TTL-key SHA256 thousands
of times.

The `InMemorySorobanState` *already* indexes these entries by the very
TTL-key hash that `getTTLKey` is recomputing
(`src/ledger/InMemorySorobanState.h:46-66`); the comment at
`InMemorySorobanState.h:25-27` notes that TTLData "stores both
liveUntilLedgerSeq and lastModifiedLedgerSeq for TTL entries [...] to
construct a LedgerEntry for TTLs without having to redundantly store the
keyHash". The hash is therefore *known* at the moment the entry is
inserted in the in-memory state, but is not passed forward to the
parallel-apply pipeline. Storing it once on the
`GlobalParallelApplyEntry` (alongside the LedgerEntry that is already
pre-loaded) and exposing a `getCachedTtlKey()` accessor lets `addReads`
and the upsert paths skip the per-tx re-encode + SHA256 entirely.

This deviates from expected behaviour because the TTL-key derivation is
*architecturally* a per-(LedgerKey)-once operation but is implemented
per-(tx, key)-pair. Soroswap amplifies the cost linearly with TPS: at
2000 TPS with ~5 RO Soroban keys per tx, ~10k extra `xdr_to_opaque +
sha256` calls land on the apply critical path per ledger.

## Trigger

Run `scripts/run_apply_load_matrix.py` soroswap scenario (TX=2000, T=8).
Each soroswap router and SAC contract appears in every swap's read-only
footprint, so `addReads` invokes `getTTLKey` ~5093 × 5 ≈ 25,000 times
per ledger for keys that have at most ~5 distinct values per ledger.

## Target Code

- `src/ledger/LedgerTypeUtils.cpp:30-38` — `getTTLKey(LedgerKey const&)`
  performs `xdr_to_opaque` + `sha256` on every call.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:406, 411, 491-497` —
  `addReads` uses `getTTLKey(lk)` per footprint key, then
  `getLedgerEntryOpt(ttlKey)`, then `toCxxBuf(*ttlEntry)`. All three
  steps are repeated per-tx for the same RO key.
- `src/ledger/InMemorySorobanState.h:46-66` —
  `ContractDataMapEntryT` already has the TTL-key hash as its index;
  `ContractCodeMapEntryT` (similar) likewise.
- `src/transactions/ParallelApplyUtils.h:81-100` —
  `GlobalParallelApplyEntry`: the natural place to add a
  `std::optional<Hash> mCachedTtlKeyHash` field populated when
  `GlobalParallelApplyLedgerState` pre-loads the entry (it walks
  `mInMemorySorobanState` already, where the hash is the index).
- `src/transactions/ParallelApplyUtils.cpp:646-718` — RO Soroban
  pre-load site; reads `mInMemorySorobanState.get(lk)` and discards
  the index hash that `InMemorySorobanState::get` returned-from. A
  parallel `getWithKeyHash` accessor would surface it.

## Evidence

1. Tracy soroswap trace `1e0b14a6b879-20260430-160627`:
   `sha256` zone shows 605,759,766 ns / 5.89% applyLedger across 396,740
   calls (mean 1,526 ns). A non-trivial fraction is from per-tx
   `getTTLKey` (per-call cost dominated by xdr+sha256).
2. The Soroban entry footprint structure: the `keyHash` for
   `CONTRACT_DATA` and `CONTRACT_CODE` keys is *defined* as
   `sha256(xdr::xdr_to_opaque(LedgerKey))` and is already used as the
   primary index in `InMemorySorobanState`. That hash is computed at
   most once per (key, ledger) when the entry is inserted, so the
   per-tx recomputation in `addReads` is provably redundant for keys
   already pre-loaded.
3. The `addReads` zone self-time is 149,142,123 ns / 1.45% applyLedger;
   inside it, `getTTLKey + getLedgerEntryOpt(ttlKey) + toCxxBuf(ttlEntry)`
   is the per-key TTL-handling triplet. The TTL-key SHA256 share is
   bounded above by the `addReads` parent and would shrink directly when
   the cached hash short-circuits.
4. `GlobalParallelApplyLedgerState` already justifies a similar
   pre-load for read-only Soroban entries (see comment at
   `ParallelApplyUtils.cpp:646-653`). Caching the TTL-key alongside the
   pre-loaded entry is a natural extension that costs O(RO-footprint)
   memory per ledger.
5. Determinism: the TTL key hash is a pure function of the LedgerKey;
   passing a cached hash along instead of recomputing it preserves
   exact ledger output and ordering.

## Anti-Evidence

- The `sha256` 5.89% figure is aggregate across the full process — not
  all is from `getTTLKey`. The hypothesis depends on the share
  attributable to `addReads`-originated TTL-key derivation being
  meaningful (3-5% of applyLedger). A PoC must add a dedicated
  `getTTLKey` Tracy span first to attribute precisely; if the dominant
  `sha256` share is elsewhere (signature work, bucket hashing,
  verifyEd25519), the upper bound shrinks proportionally.
- Read-write footprint keys must still go through `getTTLKey`
  (they're not in the RO pre-load). Soroswap's per-tx RW footprint is
  smaller (1-2 ContractData entries per swap) so the win is dominated
  by the RO side.
- The TTL key for keys NOT in `InMemorySorobanState` (e.g., classic
  Account/Trustline keys appearing in classic-tx footprints) cannot be
  pre-cached this way and must still recompute. Soroswap's classic
  ChangeTrust ops contribute a small share, so the optimization remains
  net-positive.
- Memory cost is small: one `Hash` (32 bytes) per pre-loaded RO
  Soroban entry, bounded by the RO footprint per ledger (dozens of
  entries for soroswap, even at 2000 TPS), so total overhead is on the
  order of a few KB.
- Risk of below-threshold result: this attacks a narrower slice than
  H010's encode-cache. If the TTL-key share of `getTTLKey + sha256` work
  on the apply path turns out below 3%, the hypothesis falls back to
  Low and should not be merged. PoC must measure the
  per-`getTTLKey`-call breakdown, not just total `sha256`.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-02
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — related H010 covered cached XDR-encoded ledger-entry buffers on `GlobalParallelApplyEntry`, but no prior ledger fail/success record covers this exact cached TTL-key-hash mechanism.
**Failed At**: reviewer

### Trace Summary

`getTTLKey` really does encode and hash the supplied `LedgerKey`, and `InvokeHostFunctionOpFrame::addReads` calls it for each Soroban footprint key before looking up the associated TTL entry. The parallel-apply preload path also computes TTL keys while inserting read-only Soroban entries and their TTLs into the global/thread maps, and successful-tx commit paths compute read-only TTL-key sets. However, the proposed optimization is narrower than the already rejected H010 `addReads` encode-cache idea: it removes only the TTL-key derivation subset of `addReads` plus small setup/commit bookkeeping, not the larger per-tx ledger-entry/TTL-entry encoding or Rust host decode costs.

### Code Paths Examined

- `src/ledger/LedgerTypeUtils.cpp:30-38` — `getTTLKey(LedgerKey const&)` asserts a Soroban code/data key, XDR-encodes the whole key, hashes it with SHA256, and stores the digest in a TTL `LedgerKey`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:386-497` — `addReads` loops over read-only and read-write footprint keys, calls `getTTLKey(lk)` for every Soroban key, then loads the TTL entry and serializes ledger/TTL entries into per-invocation `CxxBuf`s.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:684-686, 751-763, 1158-1181` — successful output processing, deletion, and autorestore paths also derive TTL keys, but these are tied to read-write/output handling or uncommon restore cases rather than the dominant shared read-only footprint.
- `src/transactions/ParallelApplyUtils.cpp:234-251` — `buildRoTTLSet` derives TTL keys for every read-only Soroban footprint entry after each successful tx so read-only TTL bumps can be buffered.
- `src/transactions/ParallelApplyUtils.cpp:646-718` — global parallel-apply construction preloads each distinct read-only Soroban key and its TTL; this computes `getTTLKey(lk)` only for keys not already present in `mGlobalEntryMap`, so repeated per-tx savings here are limited by the existing duplicate check.
- `src/transactions/ParallelApplyUtils.cpp:925-985` — thread-state construction walks every cluster footprint and derives TTL keys for Soroban keys before fetching preloaded global entries.
- `src/transactions/ParallelApplyUtils.cpp:1004-1038` — flushing read-only TTL bumps for write footprints derives TTL keys for read-write Soroban keys, which the proposed read-only global-entry cache does not eliminate.
- `src/ledger/InMemorySorobanState.h:100-120, 246-259` and `src/ledger/InMemorySorobanState.cpp:206-238, 412-445` — the in-memory state is indexed by TTL hash, but contract-data query/value wrappers still recompute or accept that hash internally and `get()` returns only a `LedgerEntry`, not the index hash.
- `src/transactions/TransactionFrameBase.h:47-80, 107-149` — `ParallelApplyLedgerKey` caches only `std::hash<LedgerKey>` for map lookups, and `ParallelApplyEntry` carries only scoped entry state plus dirty/new flags; there is no existing TTL-hash side channel.
- `ai-summary/fail/ledger/010-cache-encoded-bytes-on-globalparapply-entry.md:144-167` — a broader `addReads` cache hypothesis was rejected because the clearly removable C++ encode fraction was below the Medium objective floor; this hypothesis targets a smaller subset of that same hot path.

### Why It Failed

The inefficiency exists, but the projected impact does not meet the optimize-soroswap review threshold. The hypothesis's own evidence bounds the entire `addReads` zone at 1.45% of `applyLedger`, and cached TTL-key hashes would remove only the `getTTLKey` portion of that zone while leaving `getLedgerEntryOpt`, `toCxxBuf(*entryOpt)`, `toCxxBuf(*ttlEntry)`, bridge ownership, and Rust per-invocation decoding untouched. Additional `getTTLKey` calls in preload, thread setup, and read-only TTL-bump bookkeeping are real but either already deduplicated by `mGlobalEntryMap` for distinct read-only keys or are small setup/commit costs; together they are not enough to lift this narrower variant to the required 3-10% Medium tier. Under the objective-specific rule, Low or sub-1% optimizations must be marked NOT_VIABLE even when technically correct.

### Lesson Learned

For Soroban apply-path optimizations, do not attribute aggregate `sha256` time to a single `getTTLKey` caller without a dedicated trace span. A cached TTL hash is a plausible local cleanup, but Medium-tier soroswap improvements need to eliminate a larger end-to-end cost such as the whole per-invocation entry/TTL buffer construction and decode path, not just the TTL-key derivation that precedes it.
