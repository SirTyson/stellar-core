# H026: Elide redundant `key.try_into_val(e)?` in SAC `write_contract_balance` and `read_balance`

**Date**: 2026-05-21
**Subsystem**: ledger / Soroban host SAC contract
**Severity**: Low
**Impact**: ~0.1-0.2% wall-clock savings per applyLedger
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

In `write_contract_balance`
(src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:74-97),
the `DataKey::Balance(addr)` is serialized into a host `Val` exactly once and
reused for both `put_contract_data` and the immediately following
`extend_contract_data_ttl`. Same for `read_balance` (line 44-71), where the
key is reused between `try_get_contract_data` and `extend_contract_data_ttl`.

## Mechanism

Currently `write_contract_balance` calls `key.try_into_val(e)?` twice on lines
85 and 91, and `read_balance` calls it twice on lines 50 and 53. Each
`try_into_val` on a `DataKey::Balance(Address)` is a metered XDR-style
conversion that allocates a host object slot (visible as `ScVal to Val` /
`add host object` self-time). The redundant second conversion produces an
identical Val that could be obtained by binding the first conversion to a
local variable and reusing it.

## Trigger

Every SAC transfer that touches a contract-address party. Soroswap pair
contracts hold balances as `ContractData`, so each swap exercises this path
when the pair contract spends or receives a non-native asset.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:74-97` —
  `write_contract_balance` calls `key.try_into_val(e)?` twice (lines 85, 91).
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:44-71` —
  `read_balance` (contract case) calls `key.try_into_val(e)?` twice (lines 50, 53).
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:233-254` —
  `is_authorized` (contract case) calls it on line 239 only (no internal
  redundancy, but is itself called from spend/receive paths that already
  read the key).
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:257-280` —
  `write_authorization` (contract case) calls `key.try_into_val(e)?` twice
  (lines 275, but second occurrence is delegated to `write_contract_balance`).

## Evidence

Tracy soroswap trace
`/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`:

- `ScVal to Val` (host/conversion.rs:436): 429 ms aggregate self / 691,521
  calls. Mean ~621 ns/call. Confirmed inside `applyLedger` windows.
- `add host object` (host_object.rs:450): 271 ms aggregate self / 935,719
  calls. Mean ~289 ns/call.
- `SAC transfer` (stellar_asset_contract/contract.rs:212): 558 ms aggregate
  self / 13,527 calls.
- Per ledger: 95 Soroban txs / 71 ledgers ≈ ~190 SAC transfers per ledger.
  Estimating ~2 contract-side balance writes per swap × 1 redundant
  `try_into_val` per write = ~380 redundant conversions per ledger.
- Per-conversion cost ≈ 1 µs aggregate (one `ScVal to Val` ~621 ns + one
  host-object allocation ~289 ns + small overheads). Aggregate per ledger:
  380 × 1 µs = 380 µs / 3.65 effective parallelism ≈ 104 µs wall, ~0.14% of
  the 73.7 ms applyLedger.

## Anti-Evidence

The redundancy is mechanically real and the fix is a trivially clean local
binding refactor, but:

- Per-call cost is already small (~1 µs aggregate including metering).
- `extend_contract_data_ttl` internally builds its own storage key
  (`storage_key_from_val`) from the supplied `Val`, which itself does
  metered work; the savings are limited to the second host-object
  allocation, not the entire downstream path.
- The previous fail 002-fuse-sac-balance-auth-storage-reads already targeted
  the broader "fuse SAC balance auth+spend/receive storage reads" approach
  and was rejected at final-review (benchmark regression), suggesting the
  SAC body is sensitive to seemingly-clean refactors.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Failed At**: hypothesis
**Novelty**: PASS — narrower than 002-fuse-sac-balance-auth-storage-reads
(which targeted balance-load fusion, not key-serialization fusion); not
previously investigated as a standalone hypothesis.

### Why It Failed

Below objective severity threshold (Low not accepted at hypothesis stage).
The aggregate redundant cost across all redundant `try_into_val` callsites in
SAC balance read/write paths is bounded at roughly 0.14% of `applyLedger`,
well below the 3% Medium floor and below the 1% Low floor. Even doubling the
per-call cost estimate to account for downstream effects only reaches ~0.3%
— still sub-Low. The broader fusion of auth+spend/receive balance reads
(which would attack the storage-get cost, an order of magnitude larger) was
already attempted via 002-fuse-sac-balance-auth-storage-reads and rejected
at final-review.

### Lesson Learned

`try_into_val(DataKey::Balance(addr))` redundancies in SAC balance helpers
appear visually obvious but cost only ~1 µs aggregate per redundant call.
With soroswap's ~190 SAC transfers/ledger, even eliminating all redundant
key serializations across all SAC callsites cannot clear the Medium floor.
Future SAC body optimizations must target the storage-get cost (orders of
magnitude larger than key serialization), but that path has already been
exhausted by 002-fuse-sac-balance-auth-storage-reads.
