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
