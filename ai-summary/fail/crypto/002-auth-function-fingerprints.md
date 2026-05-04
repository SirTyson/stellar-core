# H002: Precompute exact authorization-function fingerprints to avoid repeated HostObject comparison

**Date**: 2026-05-03
**Subsystem**: crypto/auth, soroban-env
**Severity**: Medium
**Impact**: 3-7% soroswap apply-time reduction by reducing auth matching comparison work
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When a contract calls `require_auth`, the host must determine whether the current
authorized function exactly matches an unexhausted node in the relevant
authorization tree. That equality check must be deterministic, collision-free,
and budget-compatible, but it should not repeatedly dereference host objects and
walk the same contract address, symbol, and argument values for every candidate
sub-invocation when those authorized functions were already parsed at host
setup time.

## Mechanism

`InvocationTracker::maybe_extend_invocation_match` currently linearly scans
candidate `AuthorizedInvocation` children and calls `host.compare` on complete
`AuthorizedFunction` values for each candidate. For contract functions this
descends through `ContractFunction::compare`, which compares the contract
address host object, symbol, and argument vector. On soroswap this repeats for
many SAC `transfer` authorization checks against structurally stable auth trees.
An auth-only exact comparison key, built once for each authorized function when
auth entries are parsed and once for the current requested function, could
compare canonical bytes or typed fields directly and only fall back to
`Host::compare` if needed. This would keep deterministic matching semantics
while avoiding repeated host-object lookup/depth-limit/comparison machinery in a
hot apply descendant.

## Trigger

Run the soroswap apply-load benchmark at the current baseline. SAC `transfer`
calls invoke `from.require_auth()` for each swap leg, and each call asks the
authorization manager to match the current contract function against the
preauthorized invocation tree.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:524-541` -
  `ContractFunction::compare` compares contract address, function symbol, and
  arguments using generic host comparison.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:545-567` -
  `AuthorizedFunction::compare` dispatches contract-function comparisons.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1681-1731` -
  `InvocationTracker::maybe_extend_invocation_match` scans sub-invocations and
  repeatedly calls `host.compare`.
- `src/rust/soroban/p26/soroban-env-host/src/host/comparison.rs:46-95` -
  `Compare<HostObject>` enters the generic host-object comparison path.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` -
  SAC `transfer` calls `from.require_auth()` on the soroswap hot path.

## Evidence

The current diagnostic trace is
`/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`.
`csvexport-release -f "applyLedger"` reports `applyLedger` total time of
5,230,315,999 ns across 71 calls. `csvexport-release -e` reports
`Compare<HostObject>` self-time of 165,773,848 ns across 413,544 calls at
`soroban-env-host/src/host/comparison.rs:51`, plus `obj_cmp` self-time of
122,541,305 ns at `soroban-env-common/src/vmcaller_env.rs:270` and
80,728,242 ns at `soroban-env-host/src/vm/dispatch.rs:304`.

An unwrap check found 413,544/413,544 `Compare<HostObject>` events and
488,180/488,180 `obj_cmp` events fully inside `applyLedger` windows. The
comparison surface is therefore an apply-path cost, not benchmark setup. The
auth matching loop is a concrete source of repeated complete-function
comparison: for each `require_auth`, it walks candidate sub-invocations and
compares the same pre-parsed tree nodes against the current function. Removing
roughly half of the host-object comparison surface would exceed the 3% Medium
threshold on the 5.23 s traced apply envelope.

## Anti-Evidence

The cited comparison zones are shared by multiple Soroban components, including
metered maps and direct contract `obj_cmp` host calls, so the auth-matching
share must be isolated before implementation. A hashed fingerprint alone is not
sufficient unless collisions are impossible or guarded by an exact fallback;
authorization correctness cannot depend on probabilistic equality. The generic
comparison path also performs budget charging and depth limiting, so any
auth-only fast path must preserve equivalent metering or be protocol-gated.
If each `require_auth` has only one candidate child in realistic soroswap
authorization trees, the linear-scan portion may be smaller than the aggregate
comparison zones suggest.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-04
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS
**Failed At**: reviewer

### Trace Summary

SAC `transfer` reaches `Address::require_auth`, then `Host::require_auth`, `AuthorizationManager::require_auth`, and finally enforcing-mode tracker matching through `AccountAuthorizationTracker::maybe_authorize_invocation` and `InvocationTracker::maybe_extend_invocation_match`. The comparison path is real: matching calls `Host::compare` on `AuthorizedFunction`, which descends through `ContractFunction::compare`, `Compare<Val>`, `obj_cmp`, `visit_obj_untyped`, and `Compare<HostObject>`. However, the actual soroswap swap generator builds each transaction with a root `swap_exact_tokens_for_tokens` authorized invocation and exactly one child `transfer` authorized invocation, so the hypothesized repeated linear scan over many candidate SAC-transfer children is not present in the hot swap workload. This bounds the removable comparison work to a small number of exact comparisons per transaction, not a Medium-sized fraction of the global `Compare<HostObject>`/`obj_cmp` profile surface.

### Code Paths Examined

- `src/simulation/ApplyLoad.cpp:3477-3496` — each generated soroswap swap authorization has one root router invocation and exactly one `token_in.transfer(user, pair, amount)` sub-invocation.
- `src/simulation/ApplyLoad.cpp:3320-3349` — setup-time `add_liquidity` authorizations may have two transfer children, but setup is not the repeated swap hot path targeted by the objective.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — SAC `transfer` calls `from.require_auth()` before balance mutation.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/base_types.rs:363-379` — built-in `Address::require_auth` delegates to the host.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:3629-3655` — host `require_auth` clones the current frame arguments and dispatches to the authorization manager.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:829-850` — `AuthorizationManager::require_auth` converts the current call-stack frame and args to an `AuthorizedFunction`.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:938-1004` — enforcing mode scans account trackers by address and asks matching trackers to authorize the function.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1681-1731` — `maybe_extend_invocation_match` scans children only under the last matched authorized invocation; in generated swap transactions that child list has length one.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:524-567` — function equality uses generic host comparison of contract address, function name, and argument vector.
- `src/rust/soroban/p26/soroban-env-common/src/compare.rs:127-145` and `src/rust/soroban/p26/soroban-env-host/src/host.rs:1247-1305` — object-valued `Val` comparisons route through `obj_cmp`.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:460-496` and `src/rust/soroban/p26/soroban-env-host/src/host/comparison.rs:46-95` — `obj_cmp` visits host objects and performs the traced `Compare<HostObject>` work.

### Why It Failed

The inefficiency exists only as a small local cost, not at the claimed Medium severity. The measured soroswap swap auth tree does not contain many candidate child invocations: the benchmark generator creates one root and one transfer child per swap transaction, so `maybe_extend_invocation_match` usually compares against a single child rather than repeatedly walking a broad candidate set. A fingerprint fast path would also have to build keys for both parsed XDR authorizations and current requested functions, preserve exact collision-free semantics, and either preserve current comparison metering/depth-limit behavior or be protocol-gated; those constraints reduce the realistic removable surface further.

The profile evidence attributes 165.8 ms of `Compare<HostObject>` plus additional `obj_cmp` time to the entire apply path, but that surface is shared by host object comparisons from metered vectors/maps, storage and XDR conversions, and direct contract `obj_cmp` calls. Given the actual one-child swap auth shape, auth-function matching cannot plausibly own the roughly half of the global object-comparison surface needed to clear the objective's 3% Medium threshold. This is therefore below the optimize-soroswap severity floor, so Low/sub-1% cleanup is not accepted.

### Lesson Learned

Before promoting an authorization-matching optimization, inspect the generated `SorobanAuthorizedInvocation` trees for the benchmark workload. For current soroswap swaps, the hot auth path is narrow rather than broad; optimization candidates must either target a proven dominant auth cost across all frames or provide isolated measurements showing auth-function comparison, not generic host-object comparison, is a Medium-sized apply-time contributor.
