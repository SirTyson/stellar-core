# H015: Stream-hash `txResultSet` per-result instead of full-set `xdrSha256` at end of apply

**Date**: 2026-04-29
**Subsystem**: crypto
**Severity**: Low
**Impact**: Apply-time reduction
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

At the end of `closeLedgerInternal`, computing
`txSetResultHash = xdrSha256(txResultSet)` should hash the XDR-serialized
TransactionResultSet exactly once with overhead proportional to the total
serialized size, dominated by libsodium SHA256 throughput.

## Mechanism

`xdrSha256(txResultSet)` runs at the very end of apply
(`src/ledger/LedgerManagerImpl.cpp:1704`) and hashes the entire
`TransactionResultSet` for the ledger. For soroswap with TX=2000 the result
set is ~200-400 KB. Although `xdrSha256` is the streaming, zero-buffer
variant via `XDRSHA256` (so no large intermediate allocation), the work
still scales linearly with TX count and runs after every transaction has
been applied. A potential optimization would be to incrementally feed each
`TransactionResultPair` to a per-ledger streaming SHA256 as transactions
finish (interleaved with other apply work), instead of waiting until the
end of apply and walking the entire result vector serially.

## Trigger

Run the soroswap apply-load benchmark with Tracy. The
`xdrSha256(txResultSet)` call lives in
`closeLedgerInternal` after the apply loop completes.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:1704` —
  `ltx.loadHeader().current().txSetResultHash = xdrSha256(txResultSet)`
- `src/crypto/SHA.cpp:158-188` — `XDRSHA256` streaming hasher
- `src/crypto/XDRHasher.h` — buffered XDR archiver feeding the hasher

## Evidence

For soroswap with 2000 transactions per ledger and result entries averaging
~150 bytes (TransactionResultPair contains 32-byte hash + result struct),
the hashed payload is roughly 300 KB per ledger. At libsodium SHA256
throughput of ~500 MB/s on x86-64, this is ~0.6 ms per ledger of pure
hashing work. Plus the overhead of the XDRSHA256 buffered archiver
(per-field call stack, byte-swap, 256-byte buffer flush) adds maybe
0.3-0.5 ms more for 2000 nested xdr objects.

## Anti-Evidence

Total cost: ~1 ms / ledger out of 313 ms median apply time = **~0.3% of
apply**. This is below the 1% Low floor and far below the 3% Medium floor.
Even fully eliminating the work (impossible — the hash is required for
ledger header consensus) would not reach severity threshold.

Additionally, the XDRSHA256 path is already the optimal streaming form
(no intermediate `vector<uint8_t>` allocation, 256-byte batched feeds).
Restructuring to incrementally hash per-tx as transactions complete would
introduce ordering/synchronization complexity in the parallel-apply path
(stages complete out of submission order; the hash must be deterministic
against the canonical `txResultSet` ordering) for a sub-1% gain. Net risk
to determinism vastly outweighs the projected savings.

This finding falls under Meta-Pattern 1 (SHA256 / Hashing Budget Ceiling)
in `ai-summary/fail/crypto/summary.md`: even a per-ledger ~1 ms SHA256
operation on bulk data is below the floor.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Failed At**: hypothesis
**Novelty**: PASS — `txResultSet` end-of-apply hashing is a distinct path
not previously investigated (prior fails covered `getTTLKey`, `subSha256`,
contents-hash, and bucket scan SipHash, not the result-set close hash).

### Why It Failed

The bulk SHA256 over the result set is approximately 1 ms per ledger
(~0.3% of apply), structurally below the objective's 1% Low floor and
the 3% Medium minimum. The current `xdrSha256` path is already the
optimal streaming form. Any alternative scheme (incremental per-tx
hashing) would introduce determinism risk for sub-1% return.

### Lesson Learned

Per-ledger bulk-XDR SHA256 operations on apply-path output (result sets,
header hashes) do not reach Medium severity individually. The total
in-apply SHA256 budget remains capped at ~1% even when all such bulk-hash
sites are summed. Future SHA256 hypotheses must find a path with
hundreds-of-MB per ledger to escape the budget ceiling.
