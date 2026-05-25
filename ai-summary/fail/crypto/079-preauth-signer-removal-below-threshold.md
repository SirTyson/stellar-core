# H079: Pre-Auth Signer Removal Crypto Setup Is Below the Medium Floor

**Date**: 2026-05-25
**Subsystem**: crypto / transactions
**Severity**: Low
**Impact**: apply-path signer cleanup and pre-auth signer-key construction below objective threshold
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

After a transaction is applied, Core must preserve protocol semantics for one-time pre-authorized transaction signers: if any source account or operation source account has a signer whose key equals the current transaction's pre-auth hash, that signer must be removed exactly once with the same sponsorship and ledger-entry side effects as today. A viable optimization would skip unnecessary pre-auth signer-key construction and account scans for soroswap only if the removal path contributed Medium-tier apply time while still removing real pre-auth signers in non-soroswap workloads.

## Mechanism

`TransactionFrame::processSignatures` always calls `removeOneTimeSignerFromAllSourceAccounts`, which constructs `SignerKeyUtils::preAuthTxKey(*this)` from the transaction contents hash and then calls `removeAccountSigner` for the transaction source and every operation source. The soroswap workload uses ordinary Ed25519 source-account signatures and does not install one-time pre-auth signers, so this cleanup is usually a negative lookup. The tempting optimization would track whether the signature check saw any matching `SIGNER_KEY_TYPE_PRE_AUTH_TX` signer and skip the cleanup when no pre-auth signer was present, but the measured surface is too small to justify a Medium hypothesis.

## Trigger

Run the current accepted soroswap apply-load trace and timestamp-filter signature cleanup zones against `applyLedger`. The current trace shows apply-overlapping totals of about 67.8 ms for `processSignatures`, 27.0 ms for `removeAccountSigner`, and 151.7 ms for `getContentsHash` accessors across 71 ledgers. The cleanup call path is reached for every applied soroswap transaction, but the actual signer removal normally finds no matching pre-auth signer.

## Target Code

- `src/transactions/TransactionFrame.cpp:1583-1622` — `processSignatures` validates operation signatures and unconditionally calls `removeOneTimeSignerFromAllSourceAccounts`.
- `src/transactions/TransactionFrame.cpp:1846-1865` — `removeOneTimeSignerFromAllSourceAccounts` builds the per-transaction pre-auth signer key and iterates all source accounts.
- `src/transactions/TransactionFrame.cpp:1868-1890` — `removeAccountSigner` loads an account, scans its signer vector, and commits only if the pre-auth signer exists.
- `src/crypto/SignerKeyUtils.cpp:17-24` — `preAuthTxKey(TransactionFrame const&)` builds the `SIGNER_KEY_TYPE_PRE_AUTH_TX` key from `tx.getContentsHash()`.
- `src/transactions/SignatureChecker.cpp:52-72` — signature checking detects `SIGNER_KEY_TYPE_PRE_AUTH_TX` signers while accumulating signature weight.

## Evidence

The cleanup path is a real apply descendant and has a plausible redundant-work shape for soroswap: the benchmark accounts use normal Ed25519 source-account signatures, while pre-auth signer cleanup still constructs the key and probes accounts. The source also exposes a possible correctness-preserving gate: `SignatureChecker::checkSignature` already separates pre-auth signer groups and could in principle communicate whether any matching pre-auth signer participated.

## Anti-Evidence

The measured ceiling is far below Medium. Fully eliminating the entire `removeAccountSigner` overlap would save only about 0.38 ms per ledger on the current 207.6 ms baseline, and the whole `processSignatures` zone is only about 0.96 ms per ledger. The `getContentsHash` events are cache-hit accessors, and prior crypto records already reject contents-hash accessor and apply-signature proof reuse optimizations as below threshold. Any safe implementation would also need extra state plumbing from signature checking to cleanup, so realistic savings are smaller than the already sub-threshold ceiling.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Failed At**: hypothesis
**Novelty**: PASS — prior records covered non-Ed25519 signer branches, signature proof reuse, and contents-hash accessor costs, but not the unconditional pre-auth signer cleanup call path.

### Why It Failed

The pre-auth cleanup path is apply-reachable but too small. Even an unrealistically perfect skip of the cleanup and its crypto setup cannot reach the 3% Medium floor, and a correct change would still need to preserve one-time signer removal for accounts that actually use pre-auth transaction signers.

### Lesson Learned

For signature-adjacent apply work, size the whole caller before optimizing a crypto helper inside it. If the complete cleanup zone is below 1% of soroswap apply time, no narrower `preAuthTxKey` or contents-hash cache-hit optimization can be promoted.
