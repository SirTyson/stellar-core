# H004: Cache Soroban authorization payload hashes from original auth-entry XDR

**Date**: 2026-05-03
**Subsystem**: soroban
**Severity**: Low
**Impact**: Avoid reconstructing and hashing account-auth payload preimages during Soroban host apply
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Account authorization should authenticate the exact same signed payload, consume the same nonce entry, mark the same authorization tracker as verified, and reject the same malformed or expired credentials. The host should not rebuild a `HashIdPreimage::SorobanAuthorization` from an invocation tree when an equivalent canonical payload hash could be carried from the original `SorobanAuthorizationEntry`, as long as p26 metering is preserved or any accounting change is next-protocol-gated.

## Mechanism

`AccountAuthorizationTracker::from_authorization_entry` receives the transaction's `SorobanAuthorizationEntry`, converts its root invocation into the host's internal tracker form, and discards the original XDR structure. Later, `AccountAuthorizationTracker::authenticate` calls `get_signature_payload`, which converts the internal invocation tree back to XDR through `root_invocation_to_xdr` and hashes the reconstructed `HashIdPreimage`. A cached signed-payload hash, computed while the original XDR is still available after ledger info is installed, could bypass that reconstruction and reduce auth-path conversion/hash work for non-source account credentials.

## Trigger

Run the current soroswap apply-load benchmark from `ai-summary/CURRENT_STATE.md` with the diagnostic Tracy trace `/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`. The path is exercised when Soroban account authorization entries are matched by `require_auth` during `closeLedger` and the tracker has not yet been verified.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1801-1840` — `AccountAuthorizationTracker::from_authorization_entry` consumes the original authorization-entry XDR and keeps only internal tracker fields.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:2053-2074` — `get_signature_payload` rebuilds `HashIdPreimage::SorobanAuthorization` and hashes it during authentication.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:2076-2104` — `authenticate` calls `get_signature_payload` before checking account or contract credentials.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/account_contract.rs:171-260` — account authentication consumes the payload and validates the signatures/threshold.

## Evidence

The code shape is a real duplicate representation conversion: the signed invocation starts as XDR in `SorobanAuthorizationEntry`, is converted into `AuthorizedInvocation`, and is later converted back to XDR solely to produce the authentication hash. Timestamp filtering confirms the relevant zones are in the apply window: `hash xdr` has 20,341/20,341 events inside `applyLedger`, and `require auth` has 20,329/20,329 events inside `applyLedger`. The self-time CSV reports `hash xdr,soroban-env-host/src/host/metered_xdr.rs,45,11,649,601 ns` and `require auth,soroban-env-host/src/auth.rs,835,35,067,000 ns` in the current soroswap trace.

## Anti-Evidence

The trace bounds the whole target too tightly for the optimize-soroswap objective. Even removing all `hash xdr` self-time and a generous slice of `require auth` would save only tens of milliseconds of aggregate worker CPU across the full trace, which is far below the 3% Medium floor after accounting for eight parallel clusters and 71 `applyLedger` windows. A correct p26-preserving cache would also need to replay or preserve the existing metered XDR/hash charges; a next-protocol metering change would be a small follow-up to already accepted host-metering coalescing rather than a standalone Medium finding.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-03
**Failed At**: hypothesis
**Novelty**: PASS — not previously recorded in `ai-summary/fail/soroban/summary.md`

### Why It Failed

The optimization target is real but below the objective severity threshold. The current diagnostic trace shows only 11.6 ms of `hash xdr` self-time and 35.1 ms of `require auth` self-time across the entire soroswap run, all inside `applyLedger`. Distributed over the benchmark's 8 parallel clusters and 71 apply windows, the critical-path saving is far below 1% of the current ~273 ms non-Tracy soroswap median, so this cannot satisfy the Medium requirement.

### Lesson Learned

Authorization payload reconstruction should be valued from the narrow `hash xdr` / `require auth` zones, not from broad `ScVal to Val` or host execution totals. For source-account-heavy soroswap runs, account-auth payload hashing is a correctness-sensitive but small slice of the apply path.
