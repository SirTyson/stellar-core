# H034: Batch Ed25519 Signature Verification on Apply Path

**Date**: 2026-05-05
**Subsystem**: crypto
**Severity**: Medium
**Impact**: apply-time reduction
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

When `applyLedger` re-verifies transaction signatures (e.g.
`processSignatures`, `checkAllTransactionSignatures` and any descendants
that bypass the `gVerifySigCacheShards` cache), the verifier should batch
all eligible Ed25519 verifications into a single `verify_batch` call.
ed25519-dalek's `verify_batch` (and libsodium's batch verify) amortise
modular inversion across N signatures, achieving ~2–3× throughput vs.
serial `verify_strict` / `crypto_sign_verify_detached`. The expected
behaviour is that per-ledger apply-path verify cost drops by ~50–66%
when several signatures need verifying on the same ledger.

## Mechanism

The current implementation in `PubKeyUtils::verifySig`
(`SecretKey.cpp:475-516`) verifies one signature at a time, dispatching
either to `crypto_sign_verify_detached` (libsodium) or to the per-call
Rust `verify_ed25519_signature_dalek` shim. There is no batching primitive
exposed across the FFI. The actual deviation: the apply path treats each
signature as an independent verify even when many share a common ledger
boundary and could be aggregated into one batch call.

## Trigger

Any soroswap ledger where the cache miss rate is non-zero (e.g. a fresh
process, a new keypair, or after `clearVerifySigCache`) would expose
multiple back-to-back per-tx verifies that could be batched.

## Target Code

- `src/crypto/SecretKey.cpp:475-516` — single-signature `verifySig`
- `src/rust/src/ed25519_verify.rs:7-40` — single-signature dalek shim
- `src/transactions/TransactionFrame.cpp` — apply-path callers of
  `processSignatures` / `checkAllTransactionSignatures`

## Evidence

- ed25519-dalek exposes `verify_batch(messages, signatures, public_keys)`
  with documented ~2× speedup at N=64.
- libsodium does not expose a batch verify directly, but the Rust path
  could be extended to call `verify_batch` over a Vec of inputs.
- Soroswap generates ~30 transactions per ledger, so a per-ledger batch
  would have meaningful N.

## Anti-Evidence

The apply path predominantly hits `gVerifySigCacheShards` cache hits
because validator-replay reuses the same signatures previously seen during
validation. Cache miss verifications on the apply path are rare in steady
state.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-05
**Failed At**: hypothesis
**Novelty**: PASS — not previously written as its own file. Prior crypto
hypotheses (H008, H009, H021, H022, H033) targeted the cache layer and
prelude hash; none proposed batch verification.

### Why It Failed

Bounded by **Meta-Pattern 5** in `ai-summary/fail/crypto/summary.md`: the
apply-path share of `processSignatures` + `checkAllTransactionSignatures`
totalled ~46 ms across the 65-ledger soroswap run (~0.7 ms/ledger,
~0.2% of the 272 ms median apply). That ceiling already includes the
work that would be batched — and crucially, on the soroswap apply path the
overwhelming majority of those 46 ms is **cache-hit cost**
(BLAKE2 prelude + shard lookup), not actual signature verification. Cache
miss verifications are negligible in the measured run, so a batch
verification primitive applies to a vanishingly small slice of an already
sub-1% envelope. Even if every miss were batched at a 3× speedup, the
recovered apply time would be far below the 1% Low floor, let alone the
3% Medium threshold required by this objective.

Additionally:
- Reordering verifies into batches risks losing the per-signature error
  attribution stellar-core relies on for clear failure logging.
- The FFI restructure (Vec-of-inputs marshalling) would itself add bridge
  overhead bounded by Meta-Pattern 8 (~50 ms total bridge envelope is the
  cap on any rust-bridge-shape redesign).

### Lesson Learned

Batch ed25519 verification is a real algorithmic improvement, but on the
soroswap apply path the cache hit rate is so high that the verify
primitive itself almost never fires inside the measured window. Meta-
Pattern 5's verifySig ceiling applies regardless of whether the
optimization targets the cache layer, the prelude hash, or the underlying
primitive — all sub-paths share the same ~0.2% apply ceiling. Future
verifySig hypotheses must identify a callsite outside this envelope (for
example, a cold-start or catchup path that is not exercised by the
benchmark) to have any path to Medium severity.
