# H072: HashX and Signed-Payload Signer Paths Are Not Soroswap Apply Bottlenecks

**Date**: 2026-05-24
**Subsystem**: crypto
**Severity**: Low
**Impact**: apply-path signature-check hashing outside the accepted objective threshold
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

If soroswap apply were spending Medium-tier time in non-Ed25519 signer checks, the apply phase would repeatedly exercise `SIGNER_KEY_TYPE_HASH_X`, `SIGNER_KEY_TYPE_PRE_AUTH_TX`, or `SIGNER_KEY_TYPE_ED25519_SIGNED_PAYLOAD` branches while computing source-account signature weight. Optimizing those branches should then reduce measured `applyLedger` time without changing signature validity, signer-weight accumulation, or the requirement that every transaction signature be consumed exactly once.

## Mechanism

`SignatureChecker::checkSignature` still walks pre-auth, hash-x, Ed25519, and signed-payload signer groups during apply validation. A tempting optimization is to specialize or cache the hash-x `sha256(sig.signature)` path and signed-payload hint/verification path for soroswap accounts, but this only matters if the benchmark's source accounts actually carry those signer types. The actual soroswap workload uses ordinary source-account Ed25519 signatures, so the non-Ed25519 branches do not provide an apply-time crypto surface.

## Trigger

Run the current protocol-27 soroswap apply-load workload with the generated benchmark accounts using their default signer configuration. Then inspect apply-time signature validation: `SignatureChecker::checkSignature` is reachable from apply validation, but the non-Ed25519 signer vectors are empty for the benchmark accounts.

## Target Code

- `src/transactions/SignatureChecker.cpp:52-143` — signer-type dispatch for pre-auth, hash-x, Ed25519, and signed-payload checks.
- `src/transactions/SignatureUtils.cpp:83-91` — `verifyHashX` recomputes SHA256 over the supplied preimage signature.
- `src/transactions/SignatureUtils.cpp:48-61` — signed-payload verification delegates to `PubKeyUtils::verifySig`.
- `src/crypto/SignerKeyUtils.cpp:36-41` — hash-x signer construction hashes the preimage into a signer key.

## Evidence

Source review confirms the only crypto work unique to these branches is `verifyHashX`'s SHA256 over the decorated signature payload and signed-payload Ed25519 verification. The crypto failure summary already bounds the entire apply-path `verifySig` surface below 0.2% of apply and the entire in-apply SHA256 budget below 1%, so even a hypothetical non-Ed25519 signer workload would be bounded by existing ceilings unless it appeared at much higher call counts than soroswap's default source-account credentials. The current trace artifact recorded in `ai-summary/CURRENT_STATE.md` is not present on this machine, but existing timestamp-filtered records for the same run show signature verification work mostly outside `applyLedger` and apply-contained `processSignatures`/`checkAllTransactionSignatures` below Low.

## Anti-Evidence

The branch is not exercised by the benchmark shape. Soroswap source accounts do not install hash-x, pre-auth, or signed-payload signers in the hot apply-load path, and prior validation/signature records establish that even Ed25519 apply verification is already too small after cache hits and apply-window filtering.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Failed At**: hypothesis
**Novelty**: PASS — hash-x and signed-payload signer branches were not separately recorded in the crypto fail summary

### Why It Failed

The candidate branches are not a soroswap apply-path bottleneck: the benchmark's accounts use ordinary Ed25519 source-account signatures, while hash-x/pre-auth/signed-payload signer vectors are absent from the hot path. Any optimization here is further bounded by the existing apply-path signature and SHA256 ceilings, both below this objective's Medium threshold.

### Lesson Learned

Before proposing signer-type crypto optimizations, confirm the benchmark account signer configuration. Non-default signer branches can be reachable in Core generally but irrelevant to soroswap's source-account credential workload.
