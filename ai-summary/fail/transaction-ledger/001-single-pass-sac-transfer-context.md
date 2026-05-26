# H001: Single-Pass SAC Transfer Context for Contract Balances

**Date**: 2026-05-26
**Subsystem**: transaction-ledger / Soroban SAC apply path
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by collapsing redundant SAC balance, authorization, metadata, and event-side storage work inside each transfer
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For a Soroswap SAC transfer involving contract balances, the SAC host path should derive each endpoint's balance key once, read/decode each contract balance once, make the authorization decision from that decoded value, apply the balance mutation, write the new value with the original live-until ledger, and build the canonical transfer/mint/burn event from the same transfer-local asset metadata. It should preserve the same `require_auth`, authorization/clawback semantics, transfer event bytes, TTL extensions, and deterministic success-hash inputs as the current path.

## Mechanism

`StellarAssetContract::transfer` currently delegates to independent helpers: `is_authorized`, `spend_balance`, `receive_balance`, and `event::transfer_maybe_with_issuer`. For contract endpoints, `is_authorized` reads and decodes the balance entry, `spend_balance_no_authorization_check` or `receive_balance` reads the same balance again, and `write_contract_balance` performs another `try_get_full` before the final `put`; event construction then re-reads asset/name metadata for issuer classification and event topics. A transfer-local context can carry the decoded `BalanceValue`, key, live-until ledger, asset info, and SAC name through this sequence so the apply path pays one storage lookup/decode per endpoint plus one final write, instead of repeated storage-map lookups and ScVal conversions for the same SAC transfer.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=2000, T=8`). Each swap performs SAC transfers on the apply path, including contract-balance endpoints for the pool/pair side. The optimization triggers when `StellarAssetContract::transfer` enters the `ScAddress::Contract` branch for either `from` or `to`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — SAC `transfer` calls auth, TTL, spend, receive, and event helpers independently.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:150-178` — `read_contract_balance` and balance TTL extension helpers.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:234-299` — `write_contract_balance` re-loads the current entry before writing.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:303-427` — `receive_balance` and `spend_balance` perform separate authorization and balance reads.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:431-440` — `is_authorized` reads the same contract balance used by mutation helpers.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:47-63,94-113` — event path repeats issuer/name metadata work after balance mutation.

## Evidence

The current soroswap Tracy trace from `ai-summary/CURRENT_STATE.md` was timestamp-filtered to events contained in `applyLedger`. It shows `SAC transfer` at 2.645s aggregate worker time across 16,005 in-window calls (~37.25ms aggregate/ledger), `storage get` at ~10.13ms aggregate/ledger, `get_contract_data` at ~10.83ms aggregate/ledger, `ScVal to Val` at ~12.45ms aggregate/ledger, and `map lookup` / `map lookup indexed` together at ~17.93ms aggregate/ledger. Source inspection shows the SAC transfer body repeatedly derives and probes the same contract-balance key across authorization, mutation, and writeback, making this a concrete duplicated-work path under `applyLedger`.

This is broader than a single balance-read cache: it collapses the transfer's endpoint state, authorization state, metadata, and final writeback into one typed transfer context while preserving canonical SAC behavior. Because soroswap executes this path for every swap and the optimization removes work across several hot zones (`SAC transfer`, `storage get`, `get_contract_data`, map lookup, and conversion), it has a plausible Medium ceiling if the transfer-local context is implemented without per-call cache overhead.

## Anti-Evidence

Prior narrow SAC ideas failed when they removed only one metadata read, one balance read, or generic dispatch scaffolding; this must be measured as a whole transfer-context redesign, not a micro-cache. The path must also preserve metering or be next-protocol gated: decoded balance reuse and metadata reuse can change visible budget counters if the old per-helper conversions are simply skipped under p26. A low-overhead implementation should avoid a general-purpose `HashMap` cache; it should pass explicit typed endpoint structs through the `transfer` call so lookup savings are not eaten by cache management.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/transaction-ledger/summary.md` entry `002-sac-transfer-balance-slot-context.md + 002-cluster-local-native-sac-transfer-journal.md`
**Failed At**: reviewer

### Trace Summary

The current p26 source still has the local duplicated work described here: `transfer` delegates to `spend_balance`, `receive_balance`, and `transfer_maybe_with_issuer`; contract endpoints cause `is_authorized` and the mutation helper to read/decode the same typed balance key, and `write_contract_balance` then reloads the full entry to preserve live-until metadata before writing. However, the novelty check found that this exact transfer-local balance-slot/context mechanism has already been reviewed and taken through final review: the condensed failure record says it was viable at reviewer but rejected after benchmarking because it regressed soroswap apply time by 1.99% while improving max-sac only 0.67%. The metadata/event portions are also covered by prior failed SAC records (`002-carry-sac-instance-metadata.md` and `002-build-sac-events-as-xdr.md`) that found the real local inefficiencies below the objective's Medium threshold.

### Code Paths Examined

- `ai-summary/fail/transaction-ledger/summary.md:53-56` — prior SAC event, instance metadata, and authorization/balance-read fusion records cover the same sub-helper fusion areas.
- `ai-summary/fail/transaction-ledger/summary.md:63` — explicitly notes that fusing all instance/metadata reads across authorization, balance, and event sub-helpers into a transfer-local context was already attempted in H002.
- `ai-summary/fail/transaction-ledger/summary.md:86` — records `002-sac-transfer-balance-slot-context.md + 002-cluster-local-native-sac-transfer-journal.md` as a prior transfer-local balance-slot context, rejected at final review after a 1.99% soroswap regression.
- `ai-summary/fail/transaction-ledger/summary.md:192` — a later balance-reuse hypothesis was rejected as the same mechanism as the already-failed `002-sac-transfer-balance-slot-context.md`.
- `ai-summary/success/transaction-ledger/001-typed-sac-balance-storage-fast-path.md:123-224` — confirms the existing typed SAC balance storage fast path already removed the generic Val/ScVal round-trip component; the remaining claim is the transfer-local context already failed.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — `transfer` checks auth, extends instance/code TTL, then calls `spend_balance`, `receive_balance`, and event emission independently.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:150-178` — `read_contract_balance` performs typed storage lookup/decode and `extend_contract_balance_ttl` separately extends the balance TTL.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:235-299` — `write_contract_balance` reconstructs the balance key/value and calls `try_get_full` before `put` so the existing entry's live-until ledger is preserved.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:303-427` — `receive_balance` and `spend_balance` each check authorization independently and then perform their own contract-balance reads before mutation.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:431-440` — `is_authorized` reads the same contract-balance entry used by the later mutation helper.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:47-63,94-113` — transfer event routing checks issuer status via asset metadata and reads the SAC name for event topics.

### Why It Failed

This is not a novel optimization hypothesis for the current pipeline. The described "single-pass transfer context" is substantially equivalent to the already-failed SAC transfer-local balance-slot/context work, and that prior PoC produced the decisive objective result: added carrier/indirection overhead exceeded the saved duplicate reads on soroswap. The current write-up does not provide a meaningfully different mechanism from that rejected design, and the objective accepts only Medium-or-higher projected soroswap apply-time wins.

### Lesson Learned

SAC transfer inclusive time is real and hot, but transfer-local context plumbing has already been measured as counterproductive for the soroswap shape. Future SAC hypotheses need a demonstrably lower-overhead carrier design or a different coarse-grained mechanism, not another restatement of balance-slot/context reuse across the same sub-helpers.
