# H022: Cache `DataKey::Balance` Val conversion across SAC `read_balance` / `write_balance` / `extend_contract_data_ttl` triple

**Date**: 2026-05-01
**Subsystem**: soroban-env (stellar_asset_contract)
**Severity**: Low
**Impact**: redundant Val conversion / host-object allocation
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

In the SAC contract balance.rs, each contract-balance read/write/TTL-extend
sequence calls `key.try_into_val(e)?` on the same `DataKey::Balance(addr)`
multiple times — twice in `write_contract_balance` (for `put_contract_data`
at line 85 and `extend_contract_data_ttl` at line 91), and twice in
`read_balance` (for the `try_get_contract_data` at line 50 and the
`extend_contract_data_ttl` at line 53). Each call constructs a fresh host
object (a Vec/Map representation of the key), allocating into the host
object table and charging the budget.

A correctly-optimized implementation would compute the converted Val once
per balance operation and reuse it across the put/get and the
TTL-extension call, saving one host-object allocation and one
`try_into_val` traversal per balance touch.

## Mechanism

Each soroswap swap performs two SAC `transfer` calls. Each transfer does
`spend_balance` + `receive_balance`, and each of those does
`try_get_contract_data(key.try_into_val(e)?)` followed by either a write
or branch into `write_contract_balance` (which itself calls
`key.try_into_val(e)?` twice). So per-transfer there are roughly 4
redundant `try_into_val` calls on the same key. Over 5093 swaps × 2
transfers × ~4 redundant conversions = ~40,000 redundant key-object
allocations per ledger.

## Trigger

Soroswap apply benchmark — every swap triggers SAC transfer twice; this
fires the redundant `try_into_val` paths.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:74-97` —
  `write_contract_balance` calls `key.try_into_val(e)?` twice.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:44-71` —
  `read_balance` calls `key.try_into_val(e)?` twice (lines 50 and 53).
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:156-217` —
  `spend_balance_no_authorization_check` constructs the key once but
  branches into `write_contract_balance` which redoes the conversion.

## Evidence

Trace data (soroswap, current baseline):
- `SAC transfer` total = 2249ms (22% of trace) across 10172 calls
  (2 per swap × ~5093 swaps).
- `add host object` self-time = 188ms / ~700k calls.
- `ScVal to Val` = 728ms (7% trace).

Redundant key-Val construction is plausibly a non-trivial fraction of SAC
transfer cost.

## Anti-Evidence

`try_into_val` for `DataKey::Balance(addr)` is **metered** — each
allocation charges the budget for an `add host object` and the
key-construction cost. The total host-budget consumption is part of
protocol-visible state (`out.cpu_insns`, `out.mem_bytes`, refund
calculations, observation diffs). Removing one `try_into_val` per balance
write would reduce metered budget consumption, which changes the per-tx
fee refund and is therefore a **protocol change**.

The fail summary's repeated meta-pattern ("MeteredOrdMap rebuild work is
protocol-visible (metering); cannot eliminate without protocol change")
applies directly here. The Soroban host's metering is part of the
network-consensus rules and cannot be modified for a perf optimization
within the same protocol version.

Furthermore, even if metering changes were allowed, the per-call cost of
`try_into_val` for a small DataKey is on the order of low microseconds.
At ~40k redundant calls per ledger × ~1µs = ~40ms / ledger; aggregate
over 8-way parallelism ≈ 5ms wall-clock per ledger = ~0.7% of applyLedger
— below the 1% noise floor.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-01
**Failed At**: hypothesis
**Novelty**: PASS — not previously written up; closest priors targeted SAC
issuer/metadata caching (001-cache-sac-address-and-metadata.md) and TTL
extension memoization (005-extend-instance-and-code-ttl-redundant-per-call.md),
neither of which addressed redundant `key.try_into_val` calls in the
balance.rs read/write/extend triples.

### Why It Failed

The optimization is blocked by Soroban's metering: each `try_into_val`
charges the budget. Removing redundant calls reduces metered cost, which
is protocol-visible state contributing to fees and observation hashes.
Within a protocol version, every node must produce identical metered
costs, so this change cannot ship without a protocol bump. Even
disregarding the protocol constraint, the projected wall-clock saving
(~0.7%) is below benchmark noise.

### Lesson Learned

Any optimization targeting host-side allocation count or budget-charge
count in the Soroban environment is constrained by the
metering-is-protocol-visible meta-pattern. Future SAC-targeted
optimizations should aim at *implementation* details that don't change the
charge sequence — e.g., the layout of `HostObject` storage or per-thread
allocator pools — rather than reducing the *count* of metered operations.
