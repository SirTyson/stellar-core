# H003: Deduplicate `extend_current_contract_instance_and_code_ttl` Across Same-Contract Invocations Within a Stage

**Date**: 2026-05-26
**Subsystem**: soroban
**Severity**: Low
**Impact**: Apply-time reduction via avoided redundant TTL probes
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

In the soroswap workload every SAC `transfer` / `mint` / `burn` invocation
calls `e.extend_current_contract_instance_and_code_ttl(SAC_LIFETIME_THRESHOLD,
SAC_LIFETIME_EXTEND_TO)` (see `builtin_contracts/stellar_asset_contract/contract.rs`
lines 150, 169, 188, 198, 217, 240, 261, 285, 306, 326, 345, 361, 406). The
correct optimization, if viable, would be to recognize that all invocations
of the same SAC within a single apply window produce the same target
live-until ledger (since `extend_to` is a constant and `ledger_seq` is the
same), and therefore the second-and-later TTL extensions for the same
`(contract_id, key_kind)` pair can be short-circuited.

## Mechanism

Tracy zone `extend_current_contract_instance_and_code_ttl` (16098 calls,
self-time 227 ms across an 8-cluster trace of 71 ledgers) walks the
storage map for the contract instance and contract code keys plus their
TTL entries on every host call. After the first extension within a ledger
the storage map's TTL entry already has `current_ttl >= threshold`, so
`Storage::extend_ttl` enters the no-op branch at storage.rs:684. The work
that is NOT short-circuited and dominates the self-time is:
`get_current_contract_id_internal` (frame walk), `contract_instance_ledger_key`
(LedgerKey alloc + metered SHA), `metered_clone(Rc<LedgerKey>)` at
data_helper.rs:315, two storage-map lookups for TTL keys, and the v1
`Storage::extend_ttl` probe itself.

## Trigger

Soroswap workload — every SAC transfer (4 per swap: input transfer to pool,
output transfer to recipient, plus the matching balance updates) triggers
this host call. With 8039 top-level invocations and 16098 helper calls,
about 2 calls per top-level frame.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2344-2359` —
  `extend_current_contract_instance_and_code_ttl` entry point.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:307-321` —
  `extend_contract_instance_ttl_from_contract_id` (clones Rc<LedgerKey>,
  delegates to Storage::extend_ttl).
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:646-688` —
  `Storage::extend_ttl` (calls `prepare_extend_ttl` which probes storage
  every call before the threshold short-circuit at line 684).
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:150-406` —
  12+ call sites in the SAC.

## Evidence

- Tracy aggregate self-time 227 ms / 16098 calls = ~14 µs/call.
- The call is unconditional in every SAC entry point — no pre-existing
  cache.
- Each call does two storage-map TTL probes plus an Rc<LedgerKey> metered
  clone and a SHA-keyed lookup.

## Anti-Evidence

- The short-circuit at `Storage::extend_ttl:684` (`if current_ttl <=
  threshold { ... }`) already eliminates the actual TTL mutation on
  subsequent calls — what remains is only the probe overhead.
- The Rust-side dedup would need a per-host-instance cache, but each
  invocation runs in its own `Host` (created fresh in `invoke_host_function`
  at e2e_invoke.rs:523). A `Host`-scoped cache only helps if the same
  contract's TTL is bumped multiple times within ONE invocation — which
  for SAC happens only when multiple SAC ops fire from a single top-level
  Wasm call. Soroswap router calls `transfer` twice per swap on two
  DIFFERENT SACs (input + output token), so the within-invocation dedup
  has cardinality 1 per SAC and saves nothing.
- A cross-invocation cache would have to live in `LedgerInfo`-adjacent
  shared state, which is currently re-built per `invoke_host_function`
  call from XDR (see `host.set_ledger_info(ledger_info)` at
  e2e_invoke.rs:532). Adding shared mutable cache state across host
  invocations would break the host's "fresh per call" determinism
  contract and require protocol-level coordination.

## Severity Sizing

Per Meta-Pattern #14 formula:
`227 ms / NUM_CLUSTERS=8 / N_ledgers=71 / baseline=207 ms = 0.19%` of
apply time, even if the host function call were eliminated entirely. Far
below the 3 % Medium floor (which requires ≥ 3.5 s aggregate self-time
in the trace).

Even the optimistic case where the *non-mutating* probe portion is
eliminated (storage-map walks on the no-op path) caps at < 0.15 % of
apply time.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated as a TTL-extension dedup
hypothesis (Meta-Pattern #5 covered TTL key SHA caching, not bump-call
deduplication).

### Why It Failed

Aggregate Tracy self-time for `extend_current_contract_instance_and_code_ttl`
is only 0.19 % of apply time after 8-way cluster normalization. Even
complete elimination of every call cannot clear the 3 % Medium floor.
Cross-invocation deduplication is also blocked by the per-call `Host`
creation model in `invoke_host_function`.

### Lesson Learned

Per-invocation host functions called O(invocations) times with sub-20 µs
self-time per call cannot reach Medium under 8-way cluster normalization
unless aggregate Tracy self-time exceeds ~3.5 s. TTL extension is now
exhaustively covered: SHA caching (Meta-Pattern #5), per-bump dedup (this
file), and v2 min-extension short-circuit are all sub-Medium. Extends
Meta-Pattern #14.
