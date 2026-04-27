# H005: SAC `transfer` calls `extend_contract_instance_and_code_ttl` on every transfer, doing redundant TTL load+extend per Soroban tx that hits the same SAC multiple times

**Date**: 2026-04-27
**Subsystem**: soroban
**Severity**: Low
**Impact**: per-Soroban-tx TTL bookkeeping overhead inside SAC built-in operations
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

A Soroban tx that invokes the same SAC contract multiple times (e.g. a soroswap
swap that calls `transfer` on the source-token SAC and again on the destination-
token SAC, possibly with `transfer_from` interleaved) should perform the
contract-instance-and-code TTL extension at most once per (tx, contract): once
the instance and code TTL have been extended past the high-watermark threshold
in the current tx, subsequent extension requests for the same contract should
short-circuit without paying full TTL-entry-load + budget-charge + write-back
cost again.

## Mechanism

`StellarAssetContract::transfer` (and `transfer_from`, `mint`, `burn`,
`clawback`, etc.) unconditionally call
`e.extend_current_contract_instance_and_code_ttl(INSTANCE_TTL_THRESHOLD,
INSTANCE_EXTEND_AMOUNT)` on every invocation
(`src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:217-220`).
That host function (`host.rs:2356-2374`) takes the current contract id, builds
an instance ledger key, then calls `extend_contract_instance_ttl_from_contract_id`
followed by `extend_contract_code_ttl_from_contract_id`, each of which loads
the corresponding TTL ledger entry, charges budget for the load and write,
checks the threshold, and writes a new TTL when needed. Per the Tracy
soroswap baseline, `extend_current_contract_instance_and_code_ttl` runs **6164
times for self-time 83.1 ms (mean 13.5 µs)** at
`vmcaller_env.rs:270`, plus **4687 dispatch invocations for 41.6 ms self** at
`vm/dispatch.rs`. With 1562 Soroban tx invocations in the trace, that is
roughly 3 instance/code-TTL extension dispatches per Soroban tx, and most of
the cost is the TTL ledger load + budget charge inside the host method.

A per-tx "already extended above threshold" cache keyed by `contract_id` (or
even by `(contract_id, kind)` for instance vs code) could short-circuit
follow-up calls in the same frame stack without loading the TTL entry. SAC
transfers in soroswap re-invoke the same SAC multiple times, so the optimisable
fraction is real.

## Trigger

Run the soroswap apply-load benchmark (`scripts/run_apply_load_matrix.py
--tracy`, soroswap TX=4000, T=8). Each swap invokes the source-token SAC and
the destination-token SAC; both `transfer` paths call
`extend_current_contract_instance_and_code_ttl`, plus the swap routes through
the soroswap contract whose instance TTL is also extended.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-227` — `transfer` calls extend TTL.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2356-2374` — host body that loads TTL twice and writes twice.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:267-330` — actual TTL load+write helpers.

## Evidence

Tracy soroswap baseline shows `extend_current_contract_instance_and_code_ttl`
self-time of 83.1 ms across 6164 calls (mean 13.5 µs); a per-tx cache that
elided ~half the calls would save ~40 ms of trace time. SAC `transfer` is
called multiple times per soroswap swap, and TTL extend always runs even when
the contract TTL is already at the same high-watermark.

## Anti-Evidence

The trace covers many ledgers; most of the 6164 calls are spread across
warmup/setup ledgers, not just the measured soroswap ledgers. Total trace
spans on the order of tens of seconds while the per-measured-ledger soroswap
apply time is 620 ms. A reasonable upper bound for what this saves in the
benchmarked window is ≤ 1 ms / ledger (≪ 0.5 % of 620 ms).

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-27
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated in soroban/soroban-env hypothesis/fail/reviewed/poc queues

### Why It Failed

Projected apply-time reduction is well below the 3 % Medium threshold for this
objective: even an idealised cache that removed every redundant extend call
within a tx would save at most a single-digit millisecond per soroswap ledger,
or under 1 % of the 620 ms baseline. Additionally, any per-tx cache lives
inside the protocol-versioned soroban-env-host (p26) — non-determinism risk is
high because TTL bookkeeping and budget charges are observable to contracts
via fee accounting; a cache that skipped budget charges would change fees,
and one that still charged budget would only save the storage-load fraction,
which is even smaller than the headline number.

### Lesson Learned

SAC built-in operations call into the protocol-versioned host on every
invocation. Optimisations that touch budget/fee accounting in the soroban
host are fundamentally constrained by determinism and observable-fee rules,
not just by raw CPU cost. Future TTL-related hypotheses should target either
(a) the C++/host bridge layer where determinism semantics are well-defined,
or (b) optimisations whose CPU savings clearly exceed the benchmark noise
floor without changing fee outputs.
