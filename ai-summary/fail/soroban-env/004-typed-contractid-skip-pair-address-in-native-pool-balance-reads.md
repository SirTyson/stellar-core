# H004: Typed-ContractId Native-Pool Balance Reads to Skip pair_address AddressObject Materialization

**Date**: 2026-05-23
**Subsystem**: soroban-env
**Severity**: Low
**Impact**: <1% soroswap apply-time reduction; sub-Medium and rejected under objective threshold
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

When the next-protocol native Soroswap pool swap reads its post-transfer pair balances for
token_0 and token_1 (`call_native_soroswap_pool_swap` lines 1175–1176), the host should perform
exactly the typed `read_contract_balance_for_contract_owner` storage read for owner =
current-contract-id without any intermediate `ScAddress::Contract` allocation, host-object
table push, AddressObject handle issuance, or subsequent `scaddress_from_address` reverse
conversion. The pair contract's id is already known as the current frame's contract id; the
typed balance helper accepts a `ContractId` directly and does not need an `AddressObject`.

## Mechanism

`call_native_soroswap_pool_swap` materializes the pair contract id as a heap-allocated
AddressObject once per swap:

```rust
let pair_address = self.add_host_object(ScAddress::Contract(
    contract_id.metered_clone(self)?,
))?;
```

It then passes `pair_address` to three call sites:
1. `soroswap_pool_invoke_sac_transfer(token_X, pair_address, to, amount_X_out)` — used as
   `from` for the typed args vec passed through `call_n_internal`.
2. `soroswap_pool_invoke_sac_balance(token_0, pair_address)` — which immediately calls
   `soroswap_pool_read_sac_contract_balance` which extracts back the ContractId via
   `scaddress_from_address(owner)`.
3. `soroswap_pool_invoke_sac_balance(token_1, pair_address)` — same pattern.

For the two balance reads, the round-trip is wholly redundant: the pair `ContractId` is already
known and is converted to AddressObject only to be converted back inside the typed read helper.
A typed variant `soroswap_pool_invoke_sac_balance_by_contract_id(token, &contract_id)` would
skip both the `add_host_object` materialization (used for these two reads) and the
`scaddress_from_address` reverse conversion (twice).

## Trigger

Run `PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py` on the next-protocol
soroswap workload (`soroswap, TX=2000, T=8`). Each accepted pair swap currently allocates
one `pair_address` AddressObject and pays two `scaddress_from_address` decodes inside the
balance reads.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1154-1176` — pair_address
  AddressObject materialization and the two balance-read call sites that decode it back.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1349-1393` —
  `soroswap_pool_invoke_sac_balance` and `soroswap_pool_read_sac_contract_balance` accept
  `AddressObject` only to extract `ContractId` immediately.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs`
  (`read_contract_balance_for_contract_owner`) — already accepts `&ContractId` directly.

## Evidence

- Tracy `add host object` self-time (`soroban-env-host/src/host_object.rs:450`) is 286 ms across
  1,002,406 calls (apply-contained), so per-call cost is ~285 ns. Per soroswap swap, the
  `pair_address` materialization contributes one call.
- The typed `read_contract_balance_for_contract_owner` already exists and takes `&ContractId`,
  so the typed entry point requires only a thin wrapper rather than a new helper.
- The SAC `transfer` call site (item 1 in the mechanism) still requires an AddressObject `from`
  because `call_n_internal` packs the args as `&[Val]`. So the `add_host_object` cannot be
  eliminated outright; only its use for the two balance reads is removable.

## Anti-Evidence

- `add_host_object` carries protocol-visible `MemAlloc`/`MemCpy` metering charges (fail/017
  showed that coalescing these is blocked by metering at the p26 level). The typed bypass
  similarly removes a `MemAlloc` charge, which is permitted under the next-protocol native
  gate but must be confirmed to not flip any `try_call` observable budget transition.
- The `scaddress_from_address` decode inside `soroswap_pool_read_sac_contract_balance` is a
  small typed match on the `HostObject::Address(ScAddress::Contract(_))` variant; per call
  cost is sub-µs.
- Per pair swap removable physical work: ~1 `add_host_object` (~285 ns) + 2
  `scaddress_from_address` decodes (~200 ns each) + 1 redundant `ScAddress::Contract`
  metered_clone for the `pair_address` body (~500 ns) = ~1.2 µs per swap.
- Pair swap count is ~7,900 in the soroswap benchmark. Total removable wall:
  ~9.5 ms aggregate / 8-way parallelism / ~71 measured `applyLedger` windows ≈ 0.017 ms per
  ledger wall, or **~0.03% of soroswap median apply time**.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Failed At**: hypothesis
**Novelty**: PASS — the specific "typed-ContractId pair-address bypass in native pool balance
reads" angle is not in any prior hypothesis, reviewed, poc, or fail entry. The adjacent
success/001-direct-sac-balance-for-native-pair eliminated the SAC `balance` subframe but kept
the AddressObject argument shape; this proposal would remove that residual handle materialization
at the typed callers.

### Why It Failed

Projected impact is ~0.03% wall-clock — over two orders of magnitude below the objective's
Medium acceptance floor of 3% and well below the 1% benchmark-noise floor. The removable
physical work per swap (~1.2 µs) is small; the call count (~7,900 swaps) is too low to
accumulate; and the `add_host_object` cannot be eliminated for the SAC transfer arg packing
(only for the two balance reads). The remaining `pair_address` allocation for SAC transfer
keeps most of the cost in place.

### Lesson Learned

When inspecting the residual cost surface of the accepted native pool swap path, removable
per-swap physical work is in the 1–10 µs range per identifiable shortcut. With ~7,900 swap
calls per benchmark and 8-way parallelism, individual shortcuts contribute sub-millisecond
wall savings. Future native-pool optimizations must aggregate multiple per-swap shortcuts
(typed-ContractId balance reads + static-wasm-hash code-TTL skip + instance metered_clone
reduction + obj_cmp dispatch elimination + add_host_object coalescing) into a single
coordinated next-protocol refactor and pre-quantify combined removable wall time. Adjacent
fail entries (fail/017 add-host-object coalescing, fail/023 instance-lookup dedup,
fail/H004-companion static-wasm-hash) repeatedly land at sub-Medium projected impact for the
same underlying reason: each native-pool fast-path component is individually too small.
