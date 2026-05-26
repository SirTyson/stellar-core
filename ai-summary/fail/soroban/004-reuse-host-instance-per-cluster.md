# H004: Reuse `Host` Instance Across Same-Cluster Invocations to Amortize `invoke_host_function` Setup

**Date**: 2026-05-26
**Subsystem**: soroban
**Severity**: Low
**Impact**: Apply-time reduction via amortized host setup
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`invoke_host_function` in `e2e_invoke.rs:472` constructs a fresh `Host`,
decodes the source account / host-function / auth entries XDR, sets ledger
info, and seeds the base PRNG on every single invocation. The correct
optimization, if viable, would be to reuse a long-lived `Host` shell
allocated once per cluster worker thread and only re-set the per-call state
(source account, prng seed, storage, host function), avoiding repeated
allocation of the `HostImpl` RefCell shell, the budget Rc, the
authorization manager, the context stack, and the host object table backing
storage.

## Mechanism

Tracy zone `invoke_host_function` shows 877 ms self-time across 8039 calls
(~109 µs/call) in an 8-cluster trace of 71 ledgers. The non-XDR setup
overhead inside the zone — `Host::with_storage_and_budget` (RefCell + Rc
allocations + `AuthorizationManager::default`), `set_source_account`,
`set_ledger_info` (LedgerInfo clone + RefCell write), `set_authorization_entries`
(Vec<AuthEntry> push), `set_base_prng_seed` (ChaCha20 init) — is per-call
overhead that has no per-invocation semantic dependency on the previous
call's state once `try_finish` consumes the prior `Host`. Pooling Host
shells per worker-thread (with a `reset()` method that clears
`objects`/`context_stack`/`storage` but reuses the Rc<RefCell<HostImpl>>
allocation) would skip the RefCell + Rc alloc on every call.

## Trigger

Soroswap workload — every Soroban tx fires one `invoke_host_function` call
(8039 calls across 71 ledgers × 8 clusters). Each call allocates a fresh
`Host` and ~6 owned setup objects.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:472-555` —
  `invoke_host_function` body (calls Host::with_storage_and_budget,
  sets source_account / ledger_info / auth entries / prng).
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:HostImpl` —
  Rc<RefCell<HostImpl>> shell with ~12 RefCell fields per construction.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:Host::try_finish` —
  consumes the host and returns (Storage, Events).

## Evidence

- Tracy aggregate `invoke_host_function` self-time 877 ms.
- HostImpl contains 12+ RefCell fields, an `objects: Vec<HostObject>`
  table, and an `AuthorizationManager` substructure.
- A pool of pre-allocated Host shells per worker thread could amortize the
  RefCell/Rc allocation cost across all of that worker's invocations
  (~1000 calls/cluster × 71 ledgers / 8 clusters).

## Anti-Evidence

- The Soroban host is designed for single-shot use: `try_finish` consumes
  by `Rc::try_unwrap` (refcount=1 assertion) and returns Storage, then
  drops the rest. Adding a `reset()` API conflicts with the consume-by-move
  contract and requires verifying every `RefCell` field clears to its
  default — high risk for state-leak bugs across invocations.
- Determinism / soundness: any retained state across host instances (object
  table capacity reuse, AuthorizationManager nonce caches, module cache
  Arc<ModuleCache>) could subtly affect later invocations. The current
  fresh-host model is the safety boundary.
- Per fail meta-pattern #6 (async with immediate join) and existing fails
  on per-host setup, this area has been investigated for related
  optimizations. The aggregate self-time on `invoke_host_function`
  normalizes to:
  `877 ms / 8 / 71 / 207 ms = 0.74 %` of apply time. Even total elimination
  of all setup overhead (which is impossible — XDR decode must remain)
  cannot clear 3 % Medium.
- The XDR-decode portion of the zone's self-time is irreducible: source
  account / host_function / auth entries all arrive as opaque encoded
  buffers from C++ and must be decoded into typed Rust structs for host
  semantics. Per Meta-Pattern #4, XDR bridge caching caps at ~2.5 % total
  and is already largely realized (typed SAC balance, raw instance storage,
  XDR size cache).

## Severity Sizing

Per Meta-Pattern #14 formula:
`877 ms / NUM_CLUSTERS=8 / N_ledgers=71 / baseline=207 ms = 0.74 %` of
apply time as the absolute upper bound. Realistic savings after preserving
mandatory XDR decode and Storage::with_enforcing_footprint_and_map setup
would be in the 0.1–0.3 % range. Far below the 3 % Medium floor.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Failed At**: hypothesis
**Novelty**: PASS — host shell pooling was mentioned in fail summary
("per-cluster Host shell pool allocation (~0.1%)" inside Meta-Pattern #14),
confirming the sub-Medium ceiling. This file documents the absolute
upper bound from the full `invoke_host_function` zone self-time, not just
the shell allocation slice.

### Why It Failed

The entire `invoke_host_function` zone — including all mandatory XDR
decode, storage construction, and host setup — sums to 0.74 % of apply
time even at full elimination. The reducible portion (Host shell
allocation, RefCell init) is a small fraction of that 0.74 %, putting the
realistic ceiling at < 0.3 %. The current consume-by-move `try_finish`
contract is also a deliberate safety boundary that pooling would weaken.

### Lesson Learned

When evaluating "amortize per-invocation setup" hypotheses, first bound
the savings by the full Tracy zone self-time of the setup wrapper
(`invoke_host_function`, not its host-shell-allocation slice). For
soroswap at 8039 invocations across 71 ledgers and 8 clusters, any
per-invocation host-setup work below ~440 µs/call cannot reach Medium
even at full elimination. Extends Meta-Pattern #14 and clarifies the
per-cluster Host shell pool entry inside it.
