# H002: Fuse SAC authorization and balance mutation reads for contract balances

**Date**: 2026-04-28
**Subsystem**: transaction-ledger / soroban SAC apply path
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by eliminating duplicate SAC balance storage gets and decodes
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For a Stellar Asset Contract transfer involving contract-address balances, the SAC should load each affected balance entry once per logical debit or credit, use that decoded `BalanceValue` for both authorization and amount/clawback checks, then write the updated value. The resulting authorization errors, insufficient-balance errors, balance values, TTL extensions, and events should be identical to the current path, but the apply path should not perform a separate persistent storage get just to read `authorized` and then immediately fetch and decode the same entry again to mutate `amount`.

## Mechanism

`receive_balance` first calls `is_authorized(e, addr.clone())`; for contract addresses this builds `DataKey::Balance(addr)`, calls `try_get_contract_data`, and decodes `BalanceValue` only to return the `authorized` flag. If authorized, `receive_balance` then builds the same balance key again, calls `try_get_contract_data` again, decodes the same `BalanceValue` again, updates `amount`, and writes it. `spend_balance` has the same pattern: it calls `is_authorized` and then `spend_balance_no_authorization_check`, which re-loads and re-decodes the same balance entry to check amount and preserve authorization/clawback fields.

On soroswap every swap invokes SAC `transfer` or `transfer_from`, which debit one balance and credit another. For contract-address holders this creates at least two duplicate get/decode pairs per transfer before considering allowance or event work. Refactoring the SAC helpers around an internal `read_contract_balance_value` / `checked_{spend,receive}_contract_balance` path can pass the already-decoded `BalanceValue` from the authorization check into the mutation, preserving all decisions while eliminating one generic storage get, one `DataKey::Balance` conversion, and one `BalanceValue` decode for each contract-side debit or credit.

## Trigger

Run the soroswap apply-load benchmark (`soroswap, TX=4000, T=8`) and inspect the largest `applyLedger` interval. The trigger is a SAC transfer where `from` or `to` is a contract address, which is the common soroswap pool/account path: `contract.rs:222-223` calls `spend_balance` and `receive_balance`, and each function first checks authorization through `is_authorized` before re-reading the same balance entry for mutation.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-224` — `transfer` calls `spend_balance` and `receive_balance` on every SAC transfer.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:228-248` — `transfer_from` repeats the same spend/receive path after allowance handling.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:100-145` — `receive_balance` calls `is_authorized`, then re-loads the same contract balance entry to update amount.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:156-229` — `spend_balance` calls `is_authorized`, then `spend_balance_no_authorization_check` re-loads the same contract balance entry.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:233-245` — `is_authorized` performs the first balance get/decode for contract addresses.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:253-267` — each duplicated `try_get_contract_data` reaches the `storage get` path.

## Evidence

- Tracy scope check: the relevant SAC and storage zones are inside the longest `applyLedger` window. That window contains 2,921 `SAC transfer` events totaling 1,141.833 ms of worker time, `storage get` totaling 401.174 ms, `ScVal to Val` totaling 342.097 ms, and `Val to ScVal` totaling 303.261 ms.
- The duplicate read pattern is explicit in source. `is_authorized` decodes `BalanceValue` at `balance.rs:237-242`; `receive_balance` immediately decodes `BalanceValue` again at `balance.rs:121-125`; and `spend_balance_no_authorization_check` decodes it again at `balance.rs:175-179`.
- Unlike the prior rejected generic host-object batching idea, this targets a concrete SAC semantic redundancy: the first decoded value contains the exact `authorized`, `amount`, and `clawback` fields needed by the second step, so no generic object-visit ordering needs to be changed.
- The optimization is deterministic and local to one SAC call stack. It does not add parallelism or reorder ledger effects; it only carries the loaded balance value forward within the same function before writing the same final entry.

## Anti-Evidence

- Account-address balances must continue using the classic account/trustline paths (`is_account_authorized`, `get_classic_balance`, `transfer_classic_balance`) and cannot share this contract-entry fast path.
- Missing contract balances need careful handling: `is_authorized` returns `!is_asset_auth_required(e)` on missing entries, while `receive_balance` creates an authorized balance when the authorization check passed and `spend_balance_no_authorization_check` allows missing balance only for zero spend. A fused helper must preserve those three cases exactly.
- Budget accounting is protocol-visible. Removing the duplicate storage get/decode outright lowers consumed resources; a viable implementation may need an equivalent deterministic charge for the elided read or a protocol-versioned metering update.
- The win depends on how many soroswap transfer endpoints are contract addresses and how much of `storage get`/conversion time belongs to SAC balances rather than user contract storage. The hypothesis is Medium because eliminating one balance get/decode per debit/credit across thousands of SAC transfer calls plausibly saves tens of milliseconds wall time, but a PoC must isolate it from the broader host conversion profile.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-04-28
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated

### Trace Summary

The apply path reaches the SAC through `HostFunction::InvokeContract`, `call_n_internal`, and `call_contract_fn`, which dispatches `ContractExecutable::StellarAsset` to `StellarAssetContract.call`. SAC `transfer` and `transfer_from` call `spend_balance` and `receive_balance`; for `ScAddress::Contract` balances, both mutation helpers first call `is_authorized` and then immediately perform a second `try_get_contract_data` on the same `DataKey::Balance`. In this tree `try_get_contract_data` is itself implemented as `has_contract_data` followed by `get_contract_data`, so an existing balance pays repeated key conversion, footprint/map lookup, storage map lookup, `ScVal` to `Val`, and `BalanceValue` decode work before the value is mutated. The soroswap benchmark footprint contains two read-write SAC `Balance[pair]` contract keys per swap, making this duplicate path a hot per-transaction cost rather than setup-only work.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1124-1148` — top-level invoke-contract host function converts args and calls `call_n_internal`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:749-784` — `call_contract_fn` dispatches `ContractExecutable::StellarAsset` through a `Frame::StellarAssetContract` and calls `StellarAssetContract.call`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-248` — `transfer` and `transfer_from` both run `spend_balance` and `receive_balance` after auth/allowance setup.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:100-145` — `receive_balance` checks `is_authorized`, then for contract addresses constructs the same balance key and decodes the same balance value again before adding amount.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:156-229` — `spend_balance` checks `is_authorized`, then `spend_balance_no_authorization_check` re-reads and re-decodes the same contract balance before subtracting amount.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:233-245` — `is_authorized` reads the contract balance and decodes `BalanceValue` only to return `authorized`, or falls back to `!is_asset_auth_required` when missing.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/storage_utils.rs:4-14` — `try_get_contract_data` performs `has_contract_data` and then `get_contract_data`, so the duplicate high-level call is not just one binary search.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2210-2244` — `has_contract_data` and `get_contract_data` both rebuild a storage key from the host `Val`; `get_contract_data` then converts the stored `ScVal` back to a host `Val`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:253-267,421-428` — storage `has` and `get` share `try_get_full_helper`, enforce footprint access, and perform the metered storage-map lookup under the `storage get`/`storage has` spans.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:168-241` — the storage/footprint maps use metered binary-search lookup and charge access on hits.
- `src/simulation/ApplyLoad.cpp:3447-3475` — every generated soroswap swap footprint includes token-in and token-out SAC instances plus two read-write `Balance[pair]` contract-balance keys, while the user-side balances are classic trustlines.

### Findings

The inefficiency exists as stated for contract-address SAC balances, and the lower-level trace makes it stronger than the hypothesis wording: each redundant `try_get_contract_data` for an existing balance repeats both a presence check and a value get. The already-decoded `BalanceValue` from `is_authorized` contains all fields needed by the mutation path (`authorized`, `amount`, and `clawback`), so carrying it into `receive_balance`/`spend_balance_no_authorization_check` can remove the second read/decode without changing the resulting balance or authorization decision.

The path is hot for the optimize-soroswap objective. A 4000-swap ledger has two pair-contract SAC balance mutations in the generated read-write footprint per transaction, while the account holder side is represented by classic trustlines. That yields roughly 8000 contract-balance endpoints per measured ledger where the current code performs an authorization read followed by a mutation read; the removed work is within SAC transfer execution, not transaction-set creation or benchmark warmup.

The proposed change is correctness-preserving if it is limited to contract addresses and preserves the missing-balance cases exactly: missing receive uses `authorized = true` only after the authorization rule passes, missing nonzero spend remains `BalanceError`, and missing zero spend remains a no-op. Account-address paths must continue through `is_account_authorized`, `transfer_classic_balance`, and trustline/account reserve checks. Budget metering is the main implementation constraint: the PoC must explicitly decide whether the reduced component charges are acceptable for p26, or whether to add a deterministic replacement charge / protocol-gated behavior while still avoiding the real storage and conversion work.

Severity is Medium, not High. The total `storage get`/conversion Tracy time includes non-balance storage, write-side reads, and other host conversions, and parallel worker-time savings do not translate one-for-one into top-line apply time. However, eliminating thousands of high-level SAC balance rereads that each include repeated key conversion, map probes, value conversion, and `BalanceValue` decode plausibly clears the objective's 3% apply-time floor and is concrete enough for a PoC benchmark.

### PoC Guidance

- **Target code**: `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs`, especially `receive_balance`, `spend_balance`, `spend_balance_no_authorization_check`, and `is_authorized`. Keep `contract.rs` call sites unchanged unless an internal helper signature requires a mechanical update.
- **Change description**: Add an internal contract-balance read helper that, after matching `ScAddress::Contract(id)`, returns the contract id plus `Option<BalanceValue>` from one balance lookup. Use that value to check authorization and then mutate amount in contract-address `receive_balance`/`spend_balance`; leave account-address logic on the existing classic path. Preserve missing-entry behavior for receive, nonzero spend, and zero spend, and initially leave `write_contract_balance` semantics unchanged unless the PoC separately proves a safe direct-storage write that preserves TTL/live-until behavior.
- **Correctness check**: Existing SAC coverage in `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/test_stellar_asset_contract.rs` and C++ invoke-host-function SAC tests should still cover authorized/deauthorized transfers, insufficient balance, missing balance, account/trustline paths, clawback-related fields, events, and TTL extension behavior.
- **Benchmark focus**: Run `scripts/run_apply_load_matrix.py` against the SAC/soroswap apply-load config and compare top-line apply time across repeated runs. Tracy should show lower `SAC transfer`, `storage has`/`storage get`, `ScVal to Val`, and `Val to ScVal` time under `applyLedger`; expect a Medium-sized 3-10% target only if the optimized contract-balance endpoints account for a large enough share of the current storage/conversion zones.

---

## PoC Attempt

**Result**: POC_PASS
**Date**: 2026-04-30
**PoC by**: gpt-5.5, high

### Changes Made

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:169-201` — added contract-balance helper functions that read a contract balance once and reuse the decoded `BalanceValue` for authorization checks.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:313-477` — split contract-address receive/spend mutation paths so `receive_balance` and `spend_balance` pass the already-read `Option<BalanceValue>` into the amount mutation, while account-address paths continue through classic trustline/account logic and `spend_balance_no_authorization_check` remains available for clawback.
- `src/rust/soroban/p26/soroban-env-host/observations/26/test__stellar_asset_contract__*.json` — regenerated 44 p26 SAC observation fixtures to reflect the intentional lower CPU/resource observations from the cheaper contract-balance path.

### Demonstration

The PoC removes the duplicate contract-balance read/decode in SAC `receive_balance` and authorized `spend_balance`: the contract path now reads `Option<BalanceValue>` once, checks `authorized` from that decoded value, then mutates `amount` from the same value. Missing-entry behavior is preserved: receive creates an authorized zero balance after the asset authorization rule passes, missing nonzero spend still fails with `BalanceError`, and missing zero spend remains a no-op.

### Test Results

Built successfully with `./configure --enable-ccache --enable-sdfprefs --enable-tracy --enable-tracy-capture --disable-postgres` and `make -j30`. Full suite passed with `env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' make check`: `PASS: test/selftest-nopg`, `PASS: test/check-nondet`, and all p26 Soroban host tests passed (`750 passed; 0 failed; 2 ignored; 1 filtered out` in the main p26 host test binary, plus integration/doc test binaries passed).

---

## Final Review — Needs Revision

**Date**: 2026-04-30
**Final review by**: gpt-5.5, high

### What Needs Fixing

The PoC handoff is not reproducible as a committed optimization. The p26 submodule is still checked out at the prior accepted baseline SHA `e6728024aed9bb39cac3c2f247579bfac5b8bc79`, while the optimization and observation updates are present only as dirty working-tree changes inside `src/rust/soroban/p26`. The outer worktree only records the submodule as modified and does not point its gitlink at a committed p26 PoC SHA. This violates the final-review handoff requirement that both the outer repo and p26 submodule be clean, committed branch tips before measurement.

There is also a branch/metadata mismatch: the outer branch is `poc/002-fuse-sac-authorization-balance-reads`, but the visible outer commits are named `viable poc 002-batch-host-object-visit-charges`, and the gitlink still resolves to the previous baseline. Final review cannot determine from a fresh checkout which source state should be validated, built, benchmarked, or promoted to `soroswap-perf`.

### Revision Instructions

Commit the p26 optimization and regenerated p26 observation fixtures to `github.com/SirTyson/rs-soroban-env` on branch `poc/002-fuse-sac-authorization-balance-reads`, then update the outer stellar-core submodule gitlink to that exact p26 commit and commit the gitlink on outer branch `poc/002-fuse-sac-authorization-balance-reads`. Push both branches. After `git submodule update --init --recursive src/rust/soroban/p26`, both the outer worktree and `src/rust/soroban/p26` must report clean `git status`, and the hypothesis file should record the exact outer commit SHA and p26 submodule SHA for the final reviewer.

Also ensure the outer commit naming matches this PoC (`002-fuse-sac-authorization-balance-reads`) rather than the unrelated `002-batch-host-object-visit-charges` label, or explain why those commits are intentionally part of this handoff.

### Checks Passed So Far

Handoff inspection reached the first required final-review gate and found the optimization as dirty p26 working-tree state: `balance.rs` plus 44 SAC observation JSON files were modified, but p26 remained at baseline SHA `e6728024aed9bb39cac3c2f247579bfac5b8bc79`. Because the handoff is unreproducible, build, full test, benchmark, safety, and performance-severity checks were not run.

---

## PoC Revision

**Result**: POC_PASS
**Date**: 2026-04-30
**PoC by**: claude-opus-4.7, high

### Revision Summary

Committed and pushed the previously-dirty p26 SAC fuse changes so the
handoff is reproducible from a fresh checkout, addressing the final
reviewer's revision instructions. No source-code logic changed in this
revision — the optimization itself (the `balance.rs` fused-read helpers
and the 44 regenerated p26 SAC observation fixtures from the prior PoC
attempt) is unchanged; only the git/submodule plumbing was completed.

### Branches and SHAs

- **p26 submodule** (`github.com/SirTyson/rs-soroban-env`)
  - Branch: `poc/002-fuse-sac-authorization-balance-reads`
  - Tip SHA: `f98f3665a3370c995b1278ed53c5c6a41d262497`
  - Parent: `e6728024aed9bb39cac3c2f247579bfac5b8bc79` (the prior accepted
    baseline `viable success 001-typed-sac-balance-storage-fast-path`)
  - Diff vs parent: `soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs`
    plus 44 `soroban-env-host/observations/26/test__stellar_asset_contract__*.json`
    fixtures.

- **Outer repo** (`github.com/SirTyson/stellar-core`)
  - Branch: `poc/002-fuse-sac-authorization-balance-reads`
  - Tip SHA: `d5edc3e557bfe1a8c503c2dfa8880b669b19a799`
  - Diff vs parent: bumps `src/rust/soroban/p26` gitlink to
    `f98f3665a3370c995b1278ed53c5c6a41d262497`.

### Reproducibility

After `git fetch origin && git checkout poc/002-fuse-sac-authorization-balance-reads`
on the outer repo, then `git submodule update --init --recursive
src/rust/soroban/p26`, both the outer worktree and `src/rust/soroban/p26`
report clean `git status`, and `src/rust/soroban/p26` is detached at
`f98f3665a3370c995b1278ed53c5c6a41d262497`. The two prior unrelated
documentation-only commits on this outer branch (`7ea9c80b9` and
`1edfb4b4d`, both labeled "viable poc 002-batch-host-object-visit-charges")
are pre-existing on this worktree's branch from earlier orchestrator
work and were not authored as part of this PoC; only the new top
commit `d5edc3e55` belongs to `002-fuse-sac-authorization-balance-reads`.

### Test Results

Tests were run during the original PoC attempt above and passed; this
revision only commits and pushes the existing source state, so no new
test run was required.
