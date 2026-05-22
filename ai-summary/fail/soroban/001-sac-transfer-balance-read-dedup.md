# H001: Deduplicate Balance Read in SAC `spend_balance` / `receive_balance`

**Date**: 2026-05-22
**Subsystem**: soroban (built-in SAC)
**Severity**: Medium
**Impact**: apply-time reduction (soroswap, contract-to-contract SAC transfer hot path)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

A single SAC `transfer(from, to, amount)` call on contract-to-contract paths
(which is exactly the soroswap pool↔user case) should read each side's
`BalanceValue` ledger entry at most **once** per side, since the entry's
contents are stable for the duration of one host invocation: `Storage` is the
only mutator and we hold the host's `RefCell`-guarded storage map across the
two reads. The `is_authorized` check is just an inspection of the
`authorized: bool` field of the same `BalanceValue` we are about to mutate;
the spend / receive bodies should reuse that value rather than re-issuing a
fresh `try_get_contract_data` for the identical key.

## Mechanism

Reading the current implementation in
`src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs`,
each contract-side `transfer` actually performs **four** storage reads of the
two `BalanceValue` entries — twice each — for no functional reason:

* `spend_balance(addr=from)` (line 220) calls `is_authorized(from)` (line 233)
  which executes `try_get_contract_data(DataKey::Balance(from))`, decodes the
  full `BalanceValue`, returns just `balance.authorized`, then drops the rest.
* `spend_balance` then immediately calls
  `spend_balance_no_authorization_check(from, amount)` (line 156) which calls
  the **same** `try_get_contract_data(DataKey::Balance(from))` again
  (line 176), decodes the `BalanceValue` again, mutates `.amount`, and writes
  it back via `write_contract_balance`.
* `receive_balance(to)` (line 100) does the same dance: `is_authorized(to)`
  on line 101 (full BalanceValue load discarding all but `.authorized`) and
  then `try_get_contract_data(DataKey::Balance(to))` again on line 122 to
  produce the value it actually mutates.

Each `try_get_contract_data` is not free: per the Tracy trace
(`get_contract_data,soroban-env-host/src/vm/dispatch.rs,304 = 142.5 ms agg,
67724 calls` and `get_contract_data,soroban-env-common/src/vmcaller_env.rs,270
= 594 ms agg, 67692 calls`), each call performs charge_budget × N, a
`metered_map` lookup keyed by `LedgerKey` (with full `Compare<HostObject>`
descent — see `Compare<HostObject>,host/comparison.rs,51 = 165 ms agg,
413,544 calls`), `ScVal->Val` materialization
(`ScVal to Val,host/conversion.rs,436 = 430 ms agg, 691,521 calls`), and
host-object allocations (`add host object,host_object.rs,450 = 271 ms agg,
935,719 calls`). The two redundant reads per transfer pay all of those
costs a second time even though the host-side storage state is provably
unchanged between them (no other code runs).

The fix is to factor out an internal
`load_balance_or_default(e, &addr) -> (BalanceValue, bool /* existed */)`
and a `check_authorized(&balance, &asset_info_flags) -> Result<()>` and have
`spend_balance` / `receive_balance` call them once, threading the loaded
`BalanceValue` (and a single resolved auth result) into the write path.

## Trigger

Run the soroswap apply-load benchmark
(`scripts/run_apply_load_matrix.py --workload soroswap --tx-per-ledger 2000`).
Soroswap pool swaps do contract-to-contract balance transfers — every one of
those hits this redundant-read path. Across the diagnostic Tracy trace there
are 13,527 `SAC transfer` zones spanning 71 ledgers ≈ 191 SAC transfers per
ledger, each currently doing 4 `try_get_contract_data` calls against the two
involved `BalanceValue` entries.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:44`
  — `read_balance` (reference structure for what a single-pass loader should
  return)
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:100`
  — `receive_balance`: the `is_authorized(addr.metered_clone(...))` on
  line 101 followed by `try_get_contract_data` on line 122 is the duplicate
  contract-path read.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:156`
  — `spend_balance_no_authorization_check`: the duplicate `try_get_contract_data`
  on line 176.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:220`
  — `spend_balance`: callsite that pairs `is_authorized` (line 221) with the
  immediately-following `spend_balance_no_authorization_check` (line 229).
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:233`
  — `is_authorized`: the function whose contract-path body does the redundant
  full-`BalanceValue` decode.
- Apply equivalent dedup to `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:272`
  (`burn_from` does `spend_allowance + spend_balance`; `spend_balance` does
  the duplicate read).
- Also touches `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206`
  (`transfer`) for callsite verification.

## Evidence

- The two read sites for the same key are within the same synchronous Rust
  call chain; nothing else can have mutated `Storage` between them, so a
  single load is provably equivalent.
- Aggregate trace cost of the underlying `get_contract_data` host-fn path is
  large and dominated by exactly the operations a redundant read repeats
  (charge, metered map lookup with `Compare<HostObject>`, `ScVal to Val`,
  `add host object`).
- Each SAC transfer mean wall is **159 µs** (Tracy
  `SAC transfer,builtin_contracts/.../contract.rs:212`). At ~191 transfers per
  ledger that is ~30 ms / 272.9 ms ≈ **11% of the soroswap apply window**.
  Halving the number of `try_get_contract_data` calls (from 4 to 2 per
  transfer) targets a measurable fraction of that 11% — projected
  3–5% apply-time reduction.
- Determinism: the change is a pure local algebraic refactor — same auth
  semantics, same write payloads, same TTL extension calls, same emitted
  events, same metering bookkeeping if `charge` calls inside the removed
  load are replicated explicitly to keep budget identical. (Budget identity
  is the only subtle constraint and must be preserved exactly.)

## Anti-Evidence

- Budget metering: the current code's charge accounting includes per-read
  costs (`charge` for the storage map lookup, ScVal decode and host-object
  alloc). To remain determinism-equivalent we must either (a) keep emitting
  the same `charge_budget` calls even though the load is skipped — pure
  bookkeeping with no actual work — or (b) gate the charge change behind a
  protocol-version bump. Meta-pattern #11 ("Budget charge accumulator needs
  exact rounding") demands care here.
- The optimization only fires on contract-to-contract paths
  (`ScAddress::Contract` in both `is_authorized` and `spend_balance`); the
  classic-account branch is unaffected. Soroswap is contract-to-contract so
  this matches the objective.
- `is_authorized` is also called from `write_authorization` and other
  admin paths; those callers must keep working unchanged. The refactor is
  purely additive (introduce a single-pass helper, keep `is_authorized`
  as-is, or change `is_authorized` to take a pre-loaded `BalanceValue`).
- Fail #003 (`cache-tf-footprint-dedup`) is about per-tx footprint dedup at
  the C++ layer, not per-call SAC balance reads. Fail #002
  (`cow-invoke-storage-snapshot`) is about cloning the entire storage_map for
  diff, not about per-call SAC patterns. No fail file targets the SAC
  balance.rs redundant-read pattern.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/soroban/summary.md:110` (`001-single-read-sac-transfer-balances.md`)
**Failed At**: reviewer

### Trace Summary

The current source still has the stated local duplicate: `StellarAssetContract::transfer` calls `spend_balance` and `receive_balance`, and each contract-address branch first calls `is_authorized` and then reads the same `DataKey::Balance` again before mutation. That path flows through `Host::try_get_contract_data`, whose implementation performs `has_contract_data` and then `get_contract_data` for present values, each converting the key and probing storage. However, this exact "single-read SAC transfer balance path" has already been investigated and rejected at final review after a PoC passed tests but regressed soroswap by 2.43% across all three non-Tracy benchmark runs.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — `transfer` requires auth, extends instance/code TTL, then calls `spend_balance` and `receive_balance` before emitting the transfer event.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:100-145` — `receive_balance` checks `is_authorized` and then, for `ScAddress::Contract`, performs a second `try_get_contract_data` for the same balance key before updating amount and writing.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:156-230` — `spend_balance` checks `is_authorized`, then `spend_balance_no_authorization_check` performs another `try_get_contract_data` for the same contract balance key.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:233-254` — `is_authorized` reads `DataKey::Balance` and converts the full `BalanceValue` only to return `authorized`, or falls back to asset auth-required state when absent.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/storage_utils.rs:4-14` — `try_get_contract_data` is itself `has_contract_data` followed by `get_contract_data` for present entries.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2211-2265` and `src/rust/soroban/p26/soroban-env-host/src/storage.rs:252-303,421-429` — durable storage reads convert `Val` keys to `LedgerKey`, enforce footprint access, probe `MeteredOrdMap`, clone entry state, and materialize contract-data values via `to_valid_host_val`.
- `ai-summary/fail/soroban/summary.md:110` — prior final-review record for `001-single-read-sac-transfer-balances.md` states this exact duplicate-read optimization was tried and rejected because the tested PoC regressed soroswap by 2.43%.

### Why It Failed

This is a duplicate of a previously investigated SAC single-read balance-transfer optimization. The underlying inefficiency is real, but the pipeline has already carried the same idea through PoC and final review; the measured result was a consistent soroswap regression, not a Medium apply-time improvement. The current hypothesis also repeats the earlier overprojection risk by using aggregate parallel Tracy SAC-transfer time as if it were serial apply-wall time; soroswap apply work must be normalized by cluster parallelism, and p26 storage/value-conversion metering further limits the removable implementation-only slice.

### Lesson Learned

For SAC balance-read ideas, check the condensed fail summary before promoting a local source-level duplicate. A redundant storage read can be correctness-removable and still fail the optimize-soroswap objective once replacement overhead, exact metering constraints, and multi-cluster wall-time normalization are included.
