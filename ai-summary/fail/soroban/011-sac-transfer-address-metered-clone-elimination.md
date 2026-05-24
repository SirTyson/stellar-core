# H011: Eliminate Redundant Address `metered_clone` Pair In SAC `transfer`

**Date**: 2026-05-26
**Subsystem**: soroban
**Severity**: Low (below objective severity threshold)
**Impact**: per-SAC-transfer allocation/charge reduction
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`StellarAssetContract::transfer` (called for every native pool swap leg)
should perform the minimum cloning of the `from`/`to` `Address` values
required to dispatch `spend_balance` and `receive_balance` while still
having `from`/`to` available for the trailing `event::transfer_*` emit.
Today the function performs two explicit `Address::metered_clone` calls
(`from.metered_clone(e)?` and `to.metered_clone(e)?`) at
`contract.rs:222-223`, even though `Address` is a thin wrapper around an
object handle (`AddressObject`) — the clone is effectively a `u64` copy
plus a `Budget::charge(HostMemAlloc, AddressObject::SIZE)` call. The
ideal shape is to thread the *originals* into the spend/receive helpers
(passing by reference or by `Copy`) and only clone if a real persistent
binding is needed.

## Mechanism

`Address` is `Copy`-shaped (32-byte object-handle wrapper), and
`spend_balance` / `receive_balance` only need to read it once to derive
the balance key, then forward it as `&Address` into `read_contract_balance`
/ `write_contract_balance`. The explicit `metered_clone` calls force two
budget charges and two trivial copies per transfer. Removing them would
eliminate four `Budget::charge(HostMemAlloc, …)` calls per swap (two
transfers × from+to). The fix is a signature change on `spend_balance` /
`receive_balance` to take `Address` by value (with the call sites passing
the value directly) or by `&Address`.

## Trigger

Every soroswap native pool swap performs `SAC::transfer` twice (token in
and token out). Per run: ~28 swaps × 70 ledgers × 2 SAC transfers ×
2 metered_clones = ~7,840 redundant `metered_clone` calls / run.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-226` — `transfer` body with two redundant `Address::metered_clone` calls (lines 222-223).
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:303-354,418-428` — `receive_balance` / `spend_balance` signatures that take `Address` by value.

## Evidence

- Each `metered_clone<Address>` performs a `Budget::charge(HostMemAlloc, …)`
  call (post-VisitObject/ValSer coalescing, this is still the residual
  ~1.43% of apply path budget overhead per fail summary item 16).
- The `from`/`to` are still passed as owned values to
  `event::transfer_maybe_with_issuer(e, from, to, …)` at line 224 — so
  removing the clones requires either (a) reordering: pass `&from` /
  `&to` into spend/receive and consume the originals for the event, or
  (b) making `spend_balance` / `receive_balance` take `&Address`.

## Anti-Evidence

- Per-swap savings: ~4 × `Budget::charge` calls = ~4 × ~75 ns ≈ 300 ns/swap
  aggregate worker CPU.
- 28 swaps × 70 ledgers = 1,960 swaps/run → 588 µs aggregate worker CPU/run.
- Divided by 70 ledgers and 8-way parallelism = **~1.05 µs/ledger
  critical-path** = **0.0005% of the 211 ms baseline**. This is two
  orders of magnitude below the 1% Low floor.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Failed At**: hypothesis
**Novelty**: PASS — specific metered_clone pair in SAC `transfer` not
covered by prior fail records (fail #001 `fuse-sac-contract-balance-auth-reads`
targeted duplicate balance reads, not Address clones; fail #010
`hoist-scaddress-from-address-native-pool-swap` targeted the *outer*
native pool path, not the SAC `transfer` body itself).

### Why It Failed

The savings ceiling (~0.0005% of apply time after 8-way parallelism
normalization) is dwarfed by the per-swap mandatory host execution,
storage write, and auth-frame work. Even being generous about
`metered_clone` cost (assume 1 µs each rather than 75 ns), aggregate
worker savings cap at ~8 ms/run = ~14 µs/ledger / 8 = ~1.75 µs serial
critical path = 0.001% of baseline. The hypothesis fails the meta-pattern
"Sub-µs hot-path micro-opts blocked by 8-way parallelism normalization".

### Lesson Learned

Address-handle `metered_clone` is a 32-byte handle copy + a single
`Budget::charge` call — not the deep clone its name suggests. Removing
per-call `metered_clone` of `Copy`-shaped wrappers (Address, Symbol,
small Val wrappers) almost always lands in the sub-Low bucket after
parallelism division, even when the call count is high. Treat
`metered_clone` of any 8-byte handle as a near-noise micro-opt and
prefer aggregating *multiple* such removals into a single signature
refactor before producing a hypothesis.
