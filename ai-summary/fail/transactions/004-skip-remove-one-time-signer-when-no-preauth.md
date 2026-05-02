# H004: Skip removeOneTimeSignerFromAllSourceAccounts When No PreAuthTx Signer Exists

**Date**: 2026-05-02
**Subsystem**: transactions
**Severity**: Low
**Impact**: Eliminate unnecessary per-tx hash computation, account load, and
nested LedgerTxn for the (overwhelmingly common) case of accounts with no
PreAuthTx signer.

**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

For each Soroban (or classic) transaction whose source account and
operation source accounts contain **no** signers of type `PRE_AUTH_TX`,
post-apply cleanup should be a no-op. The expensive work of computing the
preAuthTx SignerKey hash, opening a child `LedgerTxn`, loading the source
account, and scanning its signer list should only run on the rare txs
whose source/op-source accounts have a PreAuthTx signer registered.

## Mechanism

`TransactionFrame::removeOneTimeSignerFromAllSourceAccounts`
(`src/transactions/TransactionFrame.cpp:1846-1866`) is called on every
applied transaction (any protocol ≠ 7). It unconditionally:

1. Builds an `UnorderedSet<AccountID>` of source + op-source accounts.
2. Calls `SignerKeyUtils::preAuthTxKey(*this)` — a SHA-256 over the
   contents hash + network — for every tx, even when no signer is going
   to be removed.
3. Calls `removeAccountSigner(ltx, accountID, signerKey)` per account,
   which opens a **child LedgerTxn**, loads the source account from it,
   and only short-circuits after `findSignerByKey` returns no match.

For soroswap, signer lists on synthetic accounts are uniformly empty of
`PRE_AUTH_TX` signers, so 100% of these calls produce zero state changes
yet pay the full cost. The expected fix is to track a per-account
"has any PreAuthTx signer" bit (e.g. lazily on signer mutation, or
cheaply at account-load time) and gate the work on that bit.

## Trigger

Run apply-load with `--mode soroswap` (any tx count). Every successful
soroban tx hits this path post-apply.

## Target Code

- `src/transactions/TransactionFrame.cpp:1846-1866` —
  `removeOneTimeSignerFromAllSourceAccounts`.
- `src/transactions/TransactionFrame.cpp:1868-1891` —
  `removeAccountSigner` (child LedgerTxn + load + scan).
- `src/crypto/SignerKey.h` / `SignerKeyUtils::preAuthTxKey` — SHA-256 over
  contents hash + network ID.
- Caller chain in `TransactionFrame::apply` (post-success cleanup).

## Evidence

- The function runs on every applied tx (5093 successful soroban tx in
  the trace).
- Each call performs at minimum one SHA-256 (preAuthTxKey) + one nested
  `LedgerTxn` construction + one account load + one signer-list scan,
  per source/op-source account.
- For typical soroswap txs (1 source, 1 op, same source) that's 1 hash
  + 1 child ltx + 1 account load per tx = ~5093 nested ltx loads per
  trace.

## Anti-Evidence (why it's NOT viable for this objective)

- The function is **not zoned** in Tracy and does not appear distinctly
  in the export. It rolls up under `parallelApply` /
  `InvokeHostFunctionOpFrame doApply` self-time. We can bound it from
  above by noting: the total `parallelApply,transactions/TransactionFrame.cpp,2392`
  self-time is 5103M ns − 11026M ns of the InvokeHostFunctionOpFrame
  child = ~5ms / 70 ledgers = 0.07ms/ledger.
- Even the most generous estimate — 5093 calls × ~5us per call (one
  hash + one child LedgerTxn + one snapshot load) = ~25ms across
  the entire trace = **0.36ms per ledger close** = 0.13% of soroswap
  close time.
- Reaching even the 1% noise floor is implausible; reaching Medium
  (3–10%) is impossible without a 25× change in attribution.

## Why filed as fail rather than hypothesis

The objective's severity floor is **Medium (3–10%)**. The maximum
addressable wall-clock impact of this optimization is well under 0.5%
of soroswap close time, even before considering that the hash
(`SHA-256 of contentsHash`) is fast and the nested LedgerTxn typically
short-circuits cheaply when no signer is present.

A clean version of this fix could be a tidy small PR for a
1%-class optimization, but this objective explicitly rejects sub-Medium
work at the hypothesis stage.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-02
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated.

### Why It Failed

Below objective severity threshold. Total addressable cost across all
soroswap txs in a ledger is well under 1ms wall-clock = far below the
3% Medium floor.

### Lesson Learned

Per-tx unzoned cleanup paths (post-apply hooks like
`removeOneTimeSignerFromAllSourceAccounts`) can only matter at scale if
they perform synchronous *I/O* or large allocations. A SHA-256 + child
LedgerTxn that short-circuits on `findSignerByKey` returning empty is
microseconds per call; even 5000 such calls per ledger is sub-millisecond
wall time and well under the noise floor for this objective.
