# H002: Cache Decoded SAC Balance Values Within a Host Invocation

**Date**: 2026-05-25
**Subsystem**: crypto / rust / Soroban storage-value decoding
**Severity**: Medium
**Impact**: reduce soroswap apply time by avoiding repeated `ScVal` map validation and typed `BalanceValue` reconstruction for the same SAC balance keys
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Within one Soroban host invocation, repeated reads of the same SAC contract balance key should observe the current in-invocation value: the original ledger value until the helper writes a new value, and the newly written value afterward. The decoded `BalanceValue` representation should remain consistent with the canonical XDR `ScVal::Map` stored in `Storage`, and every final ledger entry, TTL update, error condition, and event should match the existing behavior.

## Mechanism

The accepted typed SAC fast path avoids generic host `Val` round-trips, but `read_contract_balance` still decodes a stored `ScVal::Map` into `BalanceValue` every time the same key is read. In a soroswap transfer and native pair swap, the same pair/token balance can be read for authorization, then read for mutation, then read again by native pair post-transfer balance checks. A small invocation-local, write-through cache keyed by the already constructed `Rc<LedgerKey>` (or a stable key hash plus equality guard) can store the decoded `BalanceValue` and invalidate/update it on `write_contract_balance`, removing repeated field-count checks, symbol comparisons, `Int128Parts` conversion, and storage-map value decoding for hot SAC balance keys.

## Trigger

Run the current accepted soroswap Tracy trace from `ai-summary/CURRENT_STATE.md` and timestamp-filter apply-contained storage/value conversion zones. The trace at `/mnt/nvme2/apply-load/f5502210f4e4-20260525-011655/logs/f5502210f4e4-20260525-011655-02-soroswap-tx-2000-t-8.tracy` shows `SAC transfer` overlapping `applyLedger` by about 2.91 s total, `storage get` by about 789 ms, `ScVal to Val` by about 411 ms, `Val to ScVal` by about 234 ms, `map lookup` by about 707 ms, and `map lookup indexed` by about 681 ms. The concrete trigger is a transfer-heavy soroswap invocation where the same contract balance entries are read multiple times before and after typed SAC writes.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:82-148` — `balance_value_from_scval` validates the three-field map and reconstructs `BalanceValue` on every read.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:150-168` — `read_contract_balance` reads storage and decodes `BalanceValue` without memoizing the decoded result.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:234-299` — `write_contract_balance` writes a new canonical `ScVal` but does not update any decoded typed state for later same-key reads.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:303-440` — receive, spend, and authorization paths repeatedly call the read helper for the same balance keys.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1484-1528` — native pair direct SAC balance reads can hit the same key after a SAC transfer has already read or written it.

## Evidence

The source still pays per-read typed decoding work even after the generic SAC `Val`/`ScVal` round-trip was removed. The benchmark shape makes same-key repetition plausible: each SAC transfer checks authorization and mutates balances, and the native pair path reads pair balances again to compute input amounts and the K invariant. Unlike a broad generic `get_contract_data` result cache, this cache can be narrow to SAC balance helpers, can be write-through on the only typed write helper, and can keep canonical ledger state in `Storage` as the source of final output while avoiding redundant typed reconstruction inside one invocation.

## Anti-Evidence

The cache must be scoped carefully so it does not return stale values after generic contract storage writes, authorization changes, or non-SAC callers; the safest initial PoC should only enable it inside the SAC helper module and update it through `write_contract_balance`. The broad `ScVal to Val` and map-lookup trace zones include non-SAC work and mandatory storage access, so the PoC needs counters for same-key SAC balance decode hits before claiming Medium severity. If the current workload's repeated reads are mostly eliminated by a simpler authorization-read fusion, this decoded-value cache may become redundant or fall below the objective threshold.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — related SAC duplicate-read fusion was previously reviewed, but this broader decoded-value/write-through cache was not an exact duplicate
**Failed At**: reviewer

### Trace Summary

The local repeated-read pattern is real: a contract-address SAC transfer can read the same balance key in `is_authorized`, read it again for mutation, write the new `BalanceValue`, and then the native Soroswap pair path can read the pair balance again for post-transfer invariant checks. However, the current accepted baseline has already moved SAC balance storage to typed XDR helpers, so the remaining repeated work is an indexed storage read plus a tiny three-field `ScVal::Map` decode, not the old generic `Val`/`ScVal` conversion chain. The cache-addressable surface is therefore below the optimize-soroswap Medium floor after normalizing aggregate worker trace time by 200 ledgers and 8 parallel clusters.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:82-148` — `balance_value_from_scval` validates exactly three map fields and reconstructs `BalanceValue`; this decode is real but small.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:150-168` — `read_contract_balance` performs `Storage::try_get` and decodes the returned `ContractData.val` on every call.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:234-299` — `write_contract_balance` rebuilds the canonical `ScVal`, calls `try_get_full` to preserve the existing entry/live-until value, writes through `Storage::put`, and extends TTL; these write-side operations remain mandatory.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:303-440` — `receive_balance`, `spend_balance_no_authorization_check`, `spend_balance`, and `is_authorized` create the same logical balance key on nearby reads, confirming the duplicate-read mechanism.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:452-490` — `write_authorization` also mutates contract balance authorization through the same read/write helpers, so any cache would need write-through updates here as well.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1178-1252` — native Soroswap pair swap performs output SAC transfers and then reads both token balances for invariant/accounting checks.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1484-1528` — direct native pair SAC balance reads call `read_contract_balance_for_contract_owner`, which reaches the same balance decode helper after validating the token is SAC and extending instance TTL.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:323-353` — current enforcing-mode reads already use precomputed footprint/storage indices and `get_at_known_position`, so repeated storage reads are cheaper than the broad map-lookup trace labels suggest.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:418-457` — writes also use an indexed replace path; decoded-value caching cannot remove the mandatory write and TTL side effects.

### Why It Failed

This does not meet the objective's Medium severity threshold. On the current non-Tracy baseline, 3% is about 6.23 ms per soroswap ledger (`207.589903 ms * 0.03`). Even the impossible upper bound of eliminating every cited broad trace row — `storage get` (789 ms), `ScVal to Val` (411 ms), `Val to ScVal` (234 ms), `map lookup` (707 ms), and `map lookup indexed` (681 ms) — normalizes to about `2.822s / 200 / 8 = 1.76 ms` per ledger, under 1% of apply time, and most of those rows are unrelated to `balance_value_from_scval` or are mandatory metering/storage work. The entire cited `SAC transfer` envelope similarly normalizes to only about `2.91s / 200 / 8 = 1.82 ms` per ledger, and a decoded-value cache can remove only a subset of that envelope while leaving authorization checks, key construction, amount arithmetic, writes, TTL extension, and event emission intact.

The proposed cache also has limited net upside because a correct implementation cannot simply key on `Rc` pointer identity: current callers rebuild fresh `Rc<LedgerKey>` values for logically identical balance keys, so a useful cache needs its own stable key hash/equality lookup. That lookup partially replaces the indexed storage lookup it tries to avoid, while the pure decode being avoided is just fixed-shape matching over three map entries. The inefficiency is real, but its realistic savings are Low/Informational and therefore below the optimize-soroswap acceptance floor.

### Lesson Learned

After the typed SAC balance storage fast path and direct native pair SAC balance reads, remaining SAC balance cache ideas must be sized against the post-fast-path read/decode subset, not the old generic `Val`/`ScVal` or whole `SAC transfer` envelopes. Aggregate worker-time storage and map labels must be divided by `NUM_CLUSTERS` and then narrowed to same-key SAC balance hits before claiming Medium severity.
