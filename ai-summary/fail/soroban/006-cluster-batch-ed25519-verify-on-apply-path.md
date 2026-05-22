# H006: Batch ed25519 signature verification across all txs in a parallel-apply cluster via `ed25519-dalek::verify_batch`

**Date**: 2026-05-22
**Subsystem**: soroban / cluster-worker signature verification
**Severity**: Low (sub-1% — not promoted)
**Impact**: Apply-time, ed25519 verification on the parallel-apply path
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

Each cluster worker thread in
`applySorobanStageClustersInParallel` processes a sequence of Soroban
txs that each carry one (occasionally a few) ed25519 transaction
signatures. The expected efficient verification path on the apply
thread is that, for a cluster of N txs, the worker performs a single
`ed25519-dalek::verify_batch` call over the combined
`(pubkey, signature, message)` triples instead of N independent
`verify_strict` calls, exploiting `verify_batch`'s shared-randomness
multi-exponentiation to amortize the per-signature point
decompression and scalar multiplication work.

## Mechanism

Today, every per-tx `SignatureChecker::checkSignature` invocation
issued during the apply path eventually reaches
`PubKeyUtils::verifySig`, which (after the verification-result cache
lookup) calls
`rust_bridge::verify_ed25519_signature_dalek`
(`src/rust/src/ed25519_verify.rs:23`) once per (pubkey, signature,
message) triple. The dalek crate provides a `verify_batch` API that
verifies a batch of N signatures with roughly N/log(N) the work of N
independent verifications by using a single multi-scalar
multiplication. The deviation from expected behavior is that we
serialize the verification calls per tx — even though within one
cluster worker, all txs are processed sequentially on the same
thread and could be deferred and verified as a batch at the start of
the cluster (before any `parallelApply` calls).

## Trigger

Run the current soroswap apply-load benchmark per
`ai-summary/CURRENT_STATE.md`. Each cluster worker thread processes a
sequence of soroswap-shaped Soroban txs and verifies their ed25519
signatures one at a time during `preParallelApplyReadOnly` and
operation-signature checks.

## Target Code

- `src/rust/src/ed25519_verify.rs:23` —
  `verify_ed25519_signature_dalek` (single-signature FFI entry point).
- `src/crypto/SecretKey.cpp` — `PubKeyUtils::verifySig` (calls the
  Rust bridge after cache miss).
- `src/transactions/SignatureChecker.cpp` — caller; iterates
  decorated signatures.
- `src/transactions/TransactionFrame.cpp:2145-2197` —
  `commonParallelPreApplyReadOnly` (where the SignatureChecker is
  constructed and used in the worker).
- A new cluster-level batch driver would need to live around the
  `applyThread` per-cluster loop in `LedgerManagerImpl`
  (`applySorobanStageClustersInParallel`) so that all per-tx
  signature triples are collected before any `parallelApply` call
  begins.

## Evidence

- `verify_ed25519_signature_dalek` aggregate self-time in the
  diagnostic Tracy trace is 1,834 ms across 32,945 calls (≈55 µs/call).
- `verify_batch` in dalek typically reaches a ≈2-3× speedup at
  batch-sizes of 8-16 signatures on x86_64.
- Soroswap cluster size is bounded by `NUM_CLUSTERS=8` at the
  configured pool count, and each cluster typically contains
  ≈12 txs (≈95 Soroban txs/ledger / 8 clusters), giving a viable
  batch-size for `verify_batch`.

## Anti-Evidence

- Per Meta-Pattern 7 (Classic-Tx Medida Is Not On Soroswap Hot Path —
  same logic for signature verification per fail
  `soroban/015-signature-validation-outside-apply.md`), the dominant
  fraction of `verify_ed25519_signature_dalek` time is **outside**
  the `applyLedger` measurement window: most of those 32,945 calls
  occur during TX-set construction and admission flood validation,
  not during apply.
- The `PubKeyUtils::verifySig` cache hit rate on the apply path is
  high — admitted transactions have typically had their signatures
  verified at admission time, so the apply-path cost is dominated by
  the cache lookup (fast hash-map hit), **not** the underlying dalek
  call. Batching therefore reclaims only the residual cache-miss
  signatures.
- Deferring signature verification to a cluster-level batch changes
  failure semantics: today, a tx with an invalid signature fails its
  `commonValid` check before any side effects; in a deferred batch
  scheme, the batch verifier reports only a single
  "at-least-one-bad" result and re-verification is required to
  identify which tx is invalid. That fallback negates the batch
  savings exactly in the worst case.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Failed At**: hypothesis
**Novelty**: PASS — `ed25519-dalek::verify_batch` and cluster-level
batching specifically has not been investigated; prior fails
(`soroban/015-signature-validation-outside-apply.md`,
`transaction-ledger/002-thread-local-signature-cache-metrics.md`,
`crypto/001-apply-signature-proof-reuse.md`) addressed different
caching/instrumentation angles.

### Why It Failed

The hypothesis fails both scope and severity filters.

1. **Scope (Meta-Pattern 7 / Tracy Trap):** The cited 1,834 ms of
   `verify_ed25519_signature_dalek` self-time is the **whole-trace**
   total, dominated by TX-set construction and admission flood
   verification. The fraction that lives inside `applyLedger` is small
   (the cluster-worker path) and is further attenuated by the
   `PubKeyUtils::verifySig` cache (admitted txs hit the cache, so
   their apply-path call returns without crossing the FFI boundary).
   The cached path is what dominates apply-window signature checks,
   not the underlying dalek verifications.

2. **Severity (after scope correction):** Estimating the apply-window
   cache-miss verifications: even granting a generous 10% miss rate
   on the apply-path signatures (~6,776 Soroban txs × 1 signature ≈
   ~680 misses) × 55 µs/verify = ~37 ms aggregate worker CPU
   across the whole run. Normalized by 8-way cluster parallelism and
   71 ledgers, this is ≈0.066 ms/ledger ≈ 0.024% of the 273 ms
   soroswap median apply time — about two orders of magnitude below
   the 3% Medium floor and well inside the 1% benchmark noise floor.
   Even an unrealistic 100% miss rate gives ≈0.66 ms/ledger ≈ 0.24%,
   still sub-Low.

3. **Correctness regression on bad-signature paths:** the
   batch-verify "single bad result" semantics force a fallback to
   per-signature verification on any batch containing an invalid
   signature, which is precisely the path the optimization is most
   needed for. In adversarial conditions (e.g. an attacker flooding
   one invalid signature into a cluster), the batch approach
   regresses the worst-case verification cost.

### Lesson Learned

When sizing ed25519-verify optimizations on the soroswap apply path,
the relevant denominator is **apply-window cache-miss signatures**,
not the global `verify_ed25519_signature_dalek` Tracy total. The
`PubKeyUtils::verifySig` cache effectively retires admission-time
verifications from the apply window; any apply-time batch-verify
hypothesis must isolate the residual miss rate first, and that
residual is structurally bounded well below 1% of soroswap apply
time at the current baseline.
