# H203: Short-circuit removeOneTimeSignerFromAllSourceAccounts for Soroban txs with no PreAuthTx signers on source account

**Date**: 2026-05-25
**Subsystem**: soroban / transactions
**Severity**: Low
**Impact**: avoid nested-LedgerTxn open/commit for Soroban txs whose source account has no `SIGNER_KEY_TYPE_PRE_AUTH_TX` signers
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`TransactionFrame::removeOneTimeSignerFromAllSourceAccounts` should only
do work when at least one source account in the tx actually has a
`PreAuthTx` signer that could be a one-time signer. For Soroban
transactions in the benchmark — where each source account is a newly
created funded keypair with only its master key, no `PreAuthTx` signers —
the function should be a no-op without opening a nested `LedgerTxn`.

## Mechanism

`removeOneTimeSignerFromAllSourceAccounts` (TransactionFrame.cpp:1584-1891
range) iterates the set of source accounts in the tx and calls
`removeAccountSigner` for each, which opens a nested `LedgerTxn`, loads
the account, walks the `signers` xvector looking for matches against
`hashTx`, and commits/closes. The walk and commit are skipped when no
match is found, but the nested LedgerTxn open + account load + xvector
iteration is paid unconditionally. For Soroban-benchmark accounts (master
key only), the function does no useful work, yet still pays the
LedgerTxn-open and account-load overhead per Soroban tx.

A short-circuit could check `sourceAccount.signers.empty() ||
none_of(signers, isPreAuthTx)` before opening the nested LedgerTxn.

## Trigger

Run the soroswap apply-load benchmark. Each Soroban tx in the workload
has a source account funded with just the master key (no extra signers).
The `removeAccountSigner` Tracy zone shows ~13.3ms total self-time across
~17500 calls (the benchmark's Soroban-tx count).

## Target Code

- `src/transactions/TransactionFrame.cpp:1584-1700` —
  `removeOneTimeSignerFromAllSourceAccounts` and `removeAccountSigner`
- `src/ledger/LedgerTxn.cpp` — nested LedgerTxn open/load/commit overhead
  for the per-account access

## Evidence

- Soroban txs in the benchmark have no `PreAuthTx` signers on their
  source accounts, so the function never modifies state.
- Function runs serially in `applyTransactions` after parallel Soroban
  apply, contributing directly to apply wall time (not 8-way parallelized).

## Anti-Evidence

- Tracy direct measurement: `removeAccountSigner` self-time **13.3ms /
  0.13% of total trace** across 17500 calls — ~0.76µs per call.
- Per-ledger wall impact: 13.3ms / 70 ledgers ≈ 0.19ms/ledger ≈
  **0.09% of apply** wall time at 207ms baseline — **well below
  Low (1%) and far below Medium (3%)**.
- The opening of the nested LedgerTxn is amortized very cheaply because
  the source-account entry is already hot from `processFeesSeqNums` —
  the load resolves from the LedgerTxn parent cache, not from the
  BucketList.
- Even if we eliminate this entirely, the saved ~190µs/ledger is below
  benchmark noise floor.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated; targets the
`removeOneTimeSignerFromAllSourceAccounts` serial post-apply pass which
no prior fail/success entry has examined.

### Why It Failed

Below objective severity threshold (sub-Low at ~0.09% apply wall time).
The function's per-call cost is already very small because nested
LedgerTxn loads resolve through the warm parent cache populated during
fee processing. The hypothetical guard would save a microsecond-scale
operation per Soroban tx that is invisible at benchmark resolution.

### Lesson Learned

When a serial post-Soroban-apply zone shows up in Tracy at <0.5% trace
self-time, do not bother proposing optimizations: even if eliminated
entirely, the wall-time saving is below benchmark noise. Compute
`trace_self_ms / N_ledgers / apply_baseline_ms` as a sanity check
before writing up any hypothesis targeting a small post-apply zone.
This applies to most post-apply serial cleanup paths
(`removeOneTimeSigner`, source-account merge processing, etc.).
