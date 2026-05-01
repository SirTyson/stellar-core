# H020: Skip contract-instance storage retrieval inside SAC code-TTL extension

**Date**: 2026-05-01
**Subsystem**: transaction-ledger / Soroban host SAC apply path
**Severity**: Low
**Impact**: below objective severity threshold (Low not accepted at hypothesis stage)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`extend_current_contract_instance_and_code_ttl` is invoked from every SAC
built-in entry point (`balance`, `allowance`, `transfer`, `transfer_from`,
`approve`, `authorized`, `mint`, `burn`, `clawback`, `set_admin`, etc.).
For a SAC contract there is no Wasm code entry, so the code-TTL extension
side of the call should be a no-op. The expected fast path is therefore:
extend the instance entry's TTL and immediately return, without performing
any additional storage map work for the (non-existent) code entry.

## Mechanism

The host always calls
`self.extend_contract_code_ttl_from_contract_id(key, threshold, extend_to)`
(`host.rs:2333`), which in turn unconditionally calls
`self.retrieve_contract_instance_from_storage(&instance_key)?`
(`host/data_helper.rs:254`) just to inspect the executable enum. For SAC
contracts the match arm is `ContractExecutable::StellarAsset => {}` and no
further work happens, but the retrieval already paid for: a metered
`MeteredOrdMap` lookup in instance storage, a `metered_clone` of
`InstanceData`, and the host-value -> contract-data conversion. The actual
mechanism that *should* be cheap (a plain `extend_ttl` on the instance
key) ends up being preceded by a full instance storage round-trip on
every SAC built-in entry, even though the executable type is immutable
for the lifetime of the contract.

## Trigger

Run the soroswap apply-load benchmark from `ai-summary/CURRENT_STATE.md`.
Soroswap's pair contract calls `token.transfer(...)`/`balance(...)` once
or twice per swap on each underlying SAC token; the trace records
`extend_current_contract_instance_and_code_ttl` at 250.6 ms across 20,335
calls and `SAC transfer` at 329.4 ms across 10,172 calls. The wasted
work fires on every SAC entry point.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2320-2335` —
  `extend_current_contract_instance_and_code_ttl` always invokes the
  code-TTL helper.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:247-265` —
  `extend_contract_code_ttl_from_contract_id` does
  `retrieve_contract_instance_from_storage` then matches `StellarAsset => {}`.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:114+` —
  `retrieve_contract_instance_from_storage` performs the metered map
  lookup and clone that is wasted for SAC.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:148-330` —
  every SAC built-in entry point calls
  `extend_current_contract_instance_and_code_ttl` near the top.

## Evidence

The fast path is structurally observable: SAC built-ins always run with
a `TokenContractFrame` on the context stack, which already knows the
contract identity and that there is no Wasm code. The host could short-
circuit `extend_current_contract_instance_and_code_ttl` whenever the
current frame is a built-in SAC frame, skipping
`retrieve_contract_instance_from_storage` entirely for the code side.
The Tracy zone shows ~12 µs per call across 20,335 calls.

## Anti-Evidence

The estimated worker self-time saved is at most ~120-150 ms aggregate
(half of 250 ms, since the instance-side `extend_ttl` is unavoidable).
That maps to at most ~150 / (8 × 19,600) ≈ 0.10% of soroswap apply time,
well under the 1% benchmark noise floor and far below the Medium
threshold. The change also crosses the metering boundary
(`retrieve_contract_instance_from_storage` performs metered work that is
currently observable), which would need a protocol-version gate on the
SAC fast path.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-01
**Failed At**: hypothesis
**Novelty**: PASS — distinct from 002-carry-sac-instance-metadata (which
focuses on `read_asset_info`/`read_name` reuse during transfer) and from
002-fuse-sac-authorization-balance-reads (which focuses on
authorization+balance load fusion). This hypothesis specifically targets
the wasted `retrieve_contract_instance_from_storage` inside the
code-TTL helper for SAC contracts.

### Why It Failed

Below objective severity threshold. The SAC code-TTL retrieval can save
at most ~150 ms of aggregate worker self-time across the 70-ledger
benchmark, which translates to ~0.1% of soroswap apply time — within
benchmark noise. Even combined with the SAC metadata-reuse angle from
H002 (already rejected), the total SAC short-circuit budget remains
under the Medium threshold without a deeper restructuring of
metered-storage charging.

### Lesson Learned

SAC apply-path optimizations that touch only one storage retrieval per
SAC entry point land below the noise floor. Future SAC work should
either fuse together *all* the instance/metadata reads done across the
authorization/balance/event sub-helpers into a transfer-local context
(already attempted in H002) or move to a coarser unit (e.g., precomputed
per-contract SAC descriptor cached at module-cache load time).
