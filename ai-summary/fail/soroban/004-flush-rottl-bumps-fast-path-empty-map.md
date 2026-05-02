# H004: Skip per-tx footprint walk in `flushRoTTLBumpsInTxWriteFootprint` when `mRoTTLBumps` is empty

**Date**: 2026-05-02
**Subsystem**: soroban
**Severity**: Low
**Impact**: Apply-time reduction (per-tx parallel apply orchestration)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`ThreadParallelApplyLedgerState::flushRoTTLBumpsInTxWriteFootprint`
(`src/transactions/ParallelApplyUtils.cpp:1003-1039`) is invoked once per
TxBundle inside `LedgerManagerImpl::applyThread`
(`src/ledger/LedgerManagerImpl.cpp:2502`) on the parallel-apply worker
threads. Its job is to drain any RO TTL bumps held in `mRoTTLBumps` whose
keys overlap with the current tx's RW footprint, so a subsequent RW write
sees the elevated TTL. When `mRoTTLBumps` is empty, the function should be
a no-op with cost equivalent to one `unordered_map::empty()` check.

## Mechanism

The current implementation unconditionally walks every `readWrite`
footprint key, calling `getTTLKey(lk)` (which performs an XDR encode +
SHA256 of the underlying key — a real SHA256 even with the LedgerKey
hash cache from success #004, because `getTTLKey` materializes a fresh
`LedgerKey{TTL}` whose `keyHash` is `sha256(xdr_to_opaque(lk))`) and then
constructs a `ParallelApplyLedgerKey` to perform an `unordered_map::find`
that is guaranteed to fail if `mRoTTLBumps` is empty. For soroswap, RO
TTL bumps are produced by `extend_ttl` host calls executed against
read-only footprint entries; the soroswap `swap_exact_tokens_for_tokens`
path mostly extends instance/code TTL via the metered host functions,
which target keys that are also in the RW set or have already been
flushed in the same tx. If `mRoTTLBumps.empty()` were checked first, the
per-tx walk would short-circuit.

## Trigger

Run the soroswap apply-load benchmark and observe per-tx self-time of the
parallel apply path; instrument `mRoTTLBumps.size()` at entry to confirm
how often the map is empty for soroswap-shaped tx flows.

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:1003-1039` —
  `flushRoTTLBumpsInTxWriteFootprint` per-tx footprint walk
- `src/ledger/LedgerTypeUtils.cpp:30-38` — `getTTLKey(LedgerKey const&)`
  performs a real SHA256 each call

## Evidence

- `applyThread` calls `flushRoTTLBumpsInTxWriteFootprint` once per tx (
  `src/ledger/LedgerManagerImpl.cpp:2502`) inside the worker-thread loop.
- For 5093 invokes/benchmark with average ~3 RW footprint keys ≈ 15k
  per-tx getTTLKey SHA256 calls, all wasted if `mRoTTLBumps` is empty.
- `getTTLKey` performs a SHA256 of the XDR-encoded key (~1µs per call),
  giving an upper bound on wasted work of ~15ms worker-summed across
  the run, or ~5ms wall-clock with effective parallelism ~3.

## Anti-Evidence

- 5ms wall-clock = 0.07% of the 5092ms applyLedger window in the
  diagnostic Tracy trace. This is far below the 3% Medium severity
  threshold and below the 1% noise floor. The fail summary's
  Meta-Pattern #1 (TTL key SHA256 already capped by ~0.67% SHA256
  budget ceiling) applies.
- The function is not a top-N self-time zone in the trace — it does not
  appear in the csvexport output even at 0.01% — confirming the per-tx
  cost is microscopic.
- A correct fast path also requires confirming that the empty-map case
  is the common case for soroswap; even if it is, the absolute saving
  is pinned by the SHA256 budget ceiling.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-02
**Failed At**: hypothesis
**Novelty**: PASS — flushRoTTLBumps fast-path not previously investigated

### Why It Failed

The total work performed by `flushRoTTLBumpsInTxWriteFootprint` across the
benchmark is bounded above by the sum of getTTLKey SHA256 calls on
RW footprint keys. Per the existing fail-summary Meta-Pattern, this
falls below the 1% noise floor and cannot reach Medium severity.

### Lesson Learned

Per-tx orchestration zones whose body is dominated by an already-rejected
primitive (in this case, getTTLKey SHA256) inherit the rejected
primitive's severity ceiling. Before targeting a per-tx orchestration
loop, decompose the body into primitives and confirm each primitive's
severity ceiling against the fail-summary Meta-Patterns.
