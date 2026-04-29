# H003: Cache encoded XDR bytes for read-only Soroban footprint entries served from InMemorySorobanState

**Date**: 2026-04-30
**Subsystem**: ledger / transactions
**Severity**: Medium
**Impact**: apply-time CPU reduction in `applySorobanStageClustersInParallel`
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

When a transaction's `addReads` loop processes a read-only Soroban footprint
entry (e.g., the soroswap router `CONTRACT_CODE`), the code path needs to
hand the host an XDR-encoded byte buffer. Because that entry is served from
the immutable `InMemorySorobanState` cache and cannot mutate within the
ledger, the encoded bytes for a given `(ledgerSeq, key)` pair are constant.
Each unique read-only footprint key should be encoded **at most once per
ledger**, not once per transaction that reads it.

## Mechanism

In `InvokeHostFunctionApplyHelper::addReads` at
`src/transactions/InvokeHostFunctionOpFrame.cpp:484` we call
`auto leBuf = toCxxBuf(*entryOpt)` for every footprint entry of every tx.
The entry was just fetched via `ParallelLedgerAccessHelper::getLedgerEntryOpt`
→ `ThreadParallelApplyLedgerState::getLiveEntryOpt`, which for in-memory
Soroban types (CONTRACT_CODE, CONTRACT_DATA) terminates at
`InMemorySorobanState::get(key)` returning a `shared_ptr<LedgerEntry const>`
to an immutable, ledger-stable entry
(`src/transactions/ParallelApplyUtils.cpp:1110-1118`,
`src/ledger/InMemorySorobanState.cpp:207`). Because the entry is immutable
across the ledger, `xdr::xdr_to_opaque` produces an identical byte vector on
every call. The current code redoes the entire XDR encoding (an allocation
plus a recursive walk) for every tx that touches the same key. For the
soroswap workload — where every one of the ~145 tx/ledger reads the same
~5–10 KB router `CONTRACT_CODE` and a small set of shared per-pool data
entries — this is a large amount of repeated CPU spent inside the dominant
`applySorobanStageClustersInParallel` zone (4.13 s self-time, 40% of
`applyLedger` per the headline trace).

## Trigger

Run `scripts/run_apply_load_matrix.py` with the soroswap workload and
record the soroswap Tracy trace under `applyLedger` →
`applySorobanStageClustersInParallel` → `applyThread` → invoke-host-function
processing. Compare the current per-ledger CPU time spent inside `addReads`
/ `toCxxBuf` against a build that memoizes the encoded buffer keyed by
`(ledgerSeq, ledgerKey)` (or per-`shared_ptr` identity) for entries served
from `InMemorySorobanState`. Soroswap's router code entry alone — read by
every tx — should dominate the savings.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:484` —
  `auto leBuf = toCxxBuf(*entryOpt);` and the surrounding addReads loop
  (lines 386–535). This is where the per-tx XDR encoding happens.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:491-497` — same loop
  also encodes `*ttlEntry` per tx; same memoization opportunity, but TTLs
  for RO entries are tiny so the win is in the `LedgerEntry` encode.
- `src/transactions/ParallelApplyUtils.cpp:1085-1121` —
  `ThreadParallelApplyLedgerState::getLiveEntryOpt`: the place where we
  could thread a `shared_ptr<LedgerEntry const>` (and an associated cached
  `CxxBuf`) through, instead of forcing a value copy into
  `std::optional<LedgerEntry>`.
- `src/ledger/InMemorySorobanState.h` / `.cpp` (entry container around
  line 207) — natural home for an optional `shared_ptr<std::vector<uint8_t>>`
  per cache entry, populated lazily on first encode and discarded when the
  ledger advances and the entry is replaced. Or hang the cache off
  `GlobalParallelApplyLedgerState` (already per-ledger) if changing
  `InMemorySorobanState` is too invasive.

## Evidence

- Tracy headline trace `1695facd04c8-20260429-013014-02-soroswap-tx-2000-t-8.tracy`:
  `applySorobanStageClustersInParallel` self-time = 4.13 s (40% of
  `applyLedger`'s 5.77 s total). The per-tx invoke path is a descendant of
  this in-scope zone.
- Soroswap workload structure: every tx invokes the same router contract,
  whose read-only footprint always includes the (large) router
  `CONTRACT_CODE` entry plus a small handful of shared `CONTRACT_DATA`
  entries. Across 145 tx/ledger × 70 ledgers in the trace this re-encodes
  the same multi-KB XDR object roughly 10 000 times.
- The encoded bytes are deterministic — `xdr_to_opaque` is a pure function
  of the entry value — so a per-ledger memo is bit-for-bit equivalent.
  Determinism is preserved trivially.
- The in-memory cache already returns `shared_ptr<LedgerEntry const>`
  (immutable), so attaching a sibling `shared_ptr<std::vector<uint8_t>>`
  is a natural extension and does not break the existing invariants
  enforced in `ParallelApplyUtils.cpp:1093-1107`.
- The encode is in the *parallel* hot path; the savings sit on the
  critical wall-clock zone, not on a serial section that competes with
  it. Each cluster thread benefits independently.

## Anti-Evidence

- The encode work is parallelized 8-way already; only the per-thread
  share of the savings shows up on the wall-clock. Still, every cluster
  thread re-encodes the same RO entry independently, so the redundancy is
  per-tx-per-thread, not amortized across threads — the parallel
  speedup does not eliminate the redundancy.
- Some footprint entries are *not* served from `InMemorySorobanState`
  (e.g., the rarely-touched RW classic entries that flow through
  `mLCLSnapshot.loadLiveEntry`). Those continue to use today's per-tx
  encode; only the in-memory Soroban cache hits benefit. For the soroswap
  workload that is the overwhelming majority of footprint volume, but it
  caps the headline win.
- Care is needed for RW entries that mutate within the ledger — the cache
  must be invalidated (or only populated for RO keys). The conservative
  design is "only memoize for read-only-from-cache lookups," which is
  trivially safe.
- Memory cost: caching encoded bytes alongside every in-memory entry
  inflates RSS by roughly 1× the entry size. Soroswap's hot read set is
  small; the worst case is bounded by the live Soroban state size.
- A previous fail (`fail/ledger/006-reuse-host-encoded-bytes-in-addlivebatch.md`)
  attempted to reuse Soroban *output* bytes inside `addLiveBatch` and was
  blocked by `lastModifiedLedgerSeq` stamping. That hazard does not apply
  here because we are caching *input* (read-only) entries that the
  `lastModifiedLedgerSeq` rewriter never touches.

---

## Review

**Verdict**: NEEDS_REFINEMENT
**Date**: 2026-04-29
**Reviewed by**: gpt-5.5, high
**Failed At**: reviewer

### What's Wrong

The repeated XDR materialization in `InvokeHostFunctionApplyHelper::addReads` is real, but the specific "served from `InMemorySorobanState` and cache a sibling `CxxBuf` there" mechanism does not match the current parallel-apply path. `GlobalParallelApplyLedgerState` already preloads Soroban read-only footprint entries and TTLs into `mGlobalEntryMap`; each `ThreadParallelApplyLedgerState` then copies matching global entries into `mThreadEntryMap`, and `addReads` usually reads from the tx/thread scoped maps rather than calling `InMemorySorobanState::get` for every transaction. A cache stored only on `InMemorySorobanState` would therefore not be naturally available at the actual `toCxxBuf(*entryOpt)` call site without threading a new side-band encoded-buffer field through the global, thread, tx, and ledger-access layers.

The proposed `shared_ptr<std::vector<uint8_t>>`/cached-`CxxBuf` representation also conflicts with the existing bridge contract. `CxxBuf` is a cxx bridge struct containing `UniquePtr<CxxVector<u8>>`; `invoke_host_function` receives `&Vec<CxxBuf>`, and Rust treats each entry through `AsRef<[u8]>`. With the current API, reusing cached bytes still requires allocating and copying them into a fresh owned vector per transaction, preserving the large byte-copy and heap-allocation cost for the 34 KB router WASM and 27 KB pair WASM entries in the soroswap footprint. Eliminating the per-tx copy would require a broader borrowed-buffer bridge/API redesign, not just memoizing XDR bytes beside the immutable ledger entry.

Finally, the severity projection is not established at the objective's Medium threshold. The hypothesis cites the whole `applySorobanStageClustersInParallel` zone, but the removable work is only the C++ pre-host encoding portion of `addReads`; Rust still decodes every encoded ledger entry into a `StorageMap` for every invocation, and the current bridge would still need per-tx owned buffers. Without a direct measured `addReads`/`toCxxBuf` descendant cost showing a recoverable 3-10% top-line apply-time reduction after those remaining costs, this is not ready for PoC under the optimize-soroswap review criteria.

### Alternative Angle

A viable refinement would need to carry encoded read-entry bytes at the same abstraction level that currently carries copied `LedgerEntry` values: `GlobalParallelApplyEntry` / `ThreadParallelApplyEntry` / `TxParallelApplyLedgerState`, with invalidation whenever an entry becomes dirty or a read-only TTL bump is merged. To avoid simply replacing XDR serialization with an equally expensive vector copy, the Rust bridge would also need a borrowed-buffer representation (or an equivalent zero-copy view) that can safely reference per-ledger or per-thread cached bytes for the duration of `invoke_host_function`. Only after that bridge shape is defined should the hypothesis estimate impact from a Tracy measurement of `addReads`/`toCxxBuf` specifically, not from the entire parallel apply subtree.

### Additional Code Paths

- `src/transactions/InvokeHostFunctionOpFrame.cpp:386-497` — `addReads` loads each footprint entry, serializes it with `toCxxBuf`, computes `entrySize`, serializes TTLs, and appends owned buffers to `mLedgerEntryCxxBufs` / `mTtlEntryCxxBufs`.
- `src/transactions/TransactionUtils.h:370-376` — `toCxxBuf` always builds a new `std::vector<uint8_t>` from `xdr::xdr_to_opaque`.
- `src/transactions/ParallelApplyUtils.cpp:646-718` — `GlobalParallelApplyLedgerState` preloads Soroban read-only entries and TTLs from `InMemorySorobanState` or the snapshot into the global parallel map.
- `src/transactions/ParallelApplyUtils.cpp:925-1000` — thread state construction copies relevant global entries into `mThreadEntryMap` before worker execution.
- `src/transactions/ParallelApplyUtils.cpp:337-342,1084-1121` — `ParallelLedgerAccessHelper::getLedgerEntryOpt` reads through tx/thread scoped state and returns a value `std::optional<LedgerEntry>`, losing shared-entry identity and any cache that lives only in `InMemorySorobanState`.
- `src/rust/src/bridge.rs:13-15,193-208` — `CxxBuf` owns a `UniquePtr<CxxVector<u8>>`, and the host bridge receives vectors of these owned buffers.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:439-447,959-982` — Rust decodes the provided XDR ledger-entry buffers into a fresh storage map on every host invocation, so C++ input-byte memoization does not remove the per-invocation Rust decode cost.
- `src/simulation/ApplyLoad.cpp:2672-2678,3438-3456` — soroswap creates one pair per dependent cluster and each swap declares five read-only entries: router instance, two SAC instances, router code, and pair code.
