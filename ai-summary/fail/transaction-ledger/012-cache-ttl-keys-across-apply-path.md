# H012: Global Per-Ledger TTL-Key Cache Across All Apply-Path Call Sites

**Date**: 2026-05-23
**Subsystem**: transaction-ledger (Soroban TTL key derivation)
**Severity**: Low
**Impact**: Apply-time reduction from avoiding repeated `getTTLKey` SHA256+XDR work
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`getTTLKey(LedgerKey)` (src/ledger/LedgerTypeUtils.cpp:31) computes
`sha256(xdr_to_opaque(key))` for a `CONTRACT_CODE`/`CONTRACT_DATA` key. The
same footprint key has its TTL key derived independently across multiple
apply-path call sites within a single ledger: `addReads`,
`recordStorageChanges`, `flushRoTTLBumpsInTxWriteFootprint`,
`collectModifiedClassicEntries` Soroban RO preload, plus the
`InMemorySorobanState` and `ThreadParallelApplyLedgerState` accessors.
A single shared per-ledger cache (`unordered_map<LedgerKey, LedgerKey>`)
populated once during `GlobalParallelApplyLedgerState` construction and
read by every later call site would eliminate every duplicate SHA256.

## Mechanism

For the soroswap workload, every Soroban tx has ~5-7 footprint entries
that flow through ~3-4 distinct call sites that all call `getTTLKey`.
That's roughly 30-60 thousand redundant SHA256+XDR computations per
ledger. Caching them in a single map keyed on the contract data/code
LedgerKey would reduce this to one computation per unique footprint key
per ledger (~3000-6000 unique keys for 2000 txs).

## Trigger

Run the soroswap benchmark. `getTTLKey` is invoked from `addReads`
(~14 k events/run), `recordStorageChanges`, the RO-preload loop, RW-flush
loop, and various invariant/state helpers. None of these share results
today.

## Target Code

- `src/ledger/LedgerTypeUtils.cpp:31-39` — `getTTLKey(LedgerKey const&)`.
- `src/transactions/ParallelApplyUtils.cpp:646-718` — Soroban RO preload
  call site (covered by prior fail H052 in isolation).
- `src/transactions/ParallelApplyUtils.cpp:1004+` —
  `flushRoTTLBumpsInTxWriteFootprint`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:386-535` — `addReads`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:641-720` —
  `recordStorageChanges`.

## Evidence

- `getTTLKey` is unconditionally a SHA256 of an XDR-encoded LedgerKey —
  pure function of its input, trivially cacheable.
- The same Soroswap pool/instance contract-data keys appear in many txs'
  footprints, so RO preload alone exhibits duplication; cross-call-site
  duplication is strictly larger.
- A small `tsl::robin_map<LedgerKey, LedgerKey>` keyed on contract data
  LedgerKey identity would amortize to a near-zero hit cost.

## Anti-Evidence

- Prior fail H052 directly measured the RO preload loop's `getTTLKey`
  contribution at ~8 ms aggregate over the trace (~0.11 ms/L), already
  sub-Low.
- Scaling that observation to ~4 call sites still puts total cost in the
  ~0.5 ms/L range — below the 1% noise floor and far below the 3%
  Medium threshold.
- The cache itself adds per-lookup hashing of `LedgerKey` (which itself
  is a large XDR structure to hash unless we intern/identity it),
  diluting the win further.
- The threaded apply layer would need either thread-local caches or a
  read-mostly shared cache with synchronization — added complexity for
  marginal benefit.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Failed At**: hypothesis
**Novelty**: PARTIAL — H052 covered only the RO preload call site;
cross-call-site caching has not been written up, but the cost ceiling
is the same.

### Why It Failed

H052 already established that `getTTLKey` SHA256+XDR cost is dominated
by ~8 ms aggregate across the trace for the heaviest call site, which
extrapolates to a per-ledger budget far below the Medium severity floor.
Even summing all four apply-path call sites and assuming pessimistic
duplication (4x), the total recoverable time is at most ~0.5 ms/L, well
below the 1% benchmark-noise floor. The objective explicitly rejects
sub-Low (sub-1%) and sub-Medium (sub-3%) hypotheses at this stage.

### Lesson Learned

`getTTLKey` is structurally cacheable but its absolute cost is already
small enough that further optimization here cannot move the soroswap
apply-time needle. Bundling sub-Low C++ wins is also out per Meta-Pattern
24 (fail H001-bundled-cpp-apply-path). Future TTL-key work should
target the per-call SHA256 implementation itself (e.g. SIMD batching of
many small SHA256s) only if a single batched primitive can hit Medium
in aggregate alongside signature/hashing elsewhere.
