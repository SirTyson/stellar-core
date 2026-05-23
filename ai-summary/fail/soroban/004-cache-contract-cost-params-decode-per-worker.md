# H004: Per-Worker Cache of Decoded `ContractCostParams` Across Txs in a Ledger

**Date**: 2026-05-23
**Subsystem**: soroban-env, rust
**Severity**: Low
**Impact**: Soroswap apply-time reduction by caching per-ledger non-metered XDR decoding of `cpu_cost_params` / `mem_cost_params` per worker thread
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`Budget::try_from_configs` in `invoke_host_function_or_maybe_panic` (soroban_proto_any.rs:412) needs `ContractCostParams` for both CPU and memory dimensions. These values come from the `SorobanNetworkConfig` and are invariant for all transactions within a single ledger (and across many ledgers, since cost-model config upgrades are rare). The expected behavior is to decode each `ContractCostParams` XDR buffer once per ledger per worker, not once per transaction.

## Mechanism

For every Soroban transaction, `invoke_host_function_or_maybe_panic` runs:

```rust
let budget = Budget::try_from_configs(
    instruction_limit as u64,
    ledger_info.memory_limit as u64,
    non_metered_xdr_from_cxx_buf::<ContractCostParams>(&ledger_info.cpu_cost_params)?,
    non_metered_xdr_from_cxx_buf::<ContractCostParams>(&ledger_info.mem_cost_params)?,
)?;
```

The two `non_metered_xdr_from_cxx_buf::<ContractCostParams>` calls deserialize the entire CPU and memory cost-params XDR from C++-owned bytes every time. Since the LedgerInfo (and therefore these buffers) is identical for all transactions within a ledger, this is per-tx redundant work. A thread-local `(ledger_seq, ContractCostParams_cpu, ContractCostParams_mem)` cache keyed by ledger sequence would amortize these decodes across the worker's txs.

ACTUAL deviation from expected: two full XDR decodes of `ContractCostParams` per tx, totaling 2 × N_tx decodes per worker per ledger.

## Trigger

Run the soroswap apply-load benchmark. Each of the ~7,891 Soroban txs across 70 ledgers (≈28 txs/ledger/worker after 8-way clustering) decodes both `ContractCostParams` XDR buffers on entry to `invoke_host_function_or_maybe_panic`.

## Target Code

- `src/rust/src/soroban_proto_any.rs:391-420` — `invoke_host_function_or_maybe_panic` decodes both cost-param XDR buffers per-tx.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs` — `Budget::try_from_configs` consumes the decoded params.
- `src/rust/src/common.rs` — `non_metered_xdr_from_cxx_buf` definition (the per-decode work).

## Evidence

`ContractCostParams` in p26 is an `xdr::ScSpecVecCostParams`-style XDR vector with one entry per `ContractCostType` (≥28 cost types). Each non-metered XDR decode walks the buffer, allocates a `Vec`, and constructs a `ContractCostParamEntry` for each variant. Plausible per-decode cost is ~10-30µs depending on entry count.

Upper-bound aggregate estimate at 30µs/decode × 2 decodes × 7,891 txs ≈ 474 ms of worker CPU. After 8-way cluster parallelism: ~59 ms wall-clock per run. Over 70 ledgers: ~0.85 ms/ledger ≈ 0.39% of the 218ms baseline.

The decoded values are fully ledger-invariant — `SorobanNetworkConfig` only changes on config upgrades — so a per-(ledger_seq) thread-local cache trivially hits on every tx after the first in a worker.

## Anti-Evidence

- The decode is explicitly **non-metered** (so no Budget changes, no protocol-visible side effects).
- Even the optimistic upper bound is well below the 1% Low noise floor.
- Cache invalidation needs to handle ledger boundaries (cheap: check `ledger_info.sequence_number` and rebuild on mismatch), but the savings cannot reach Medium severity.
- This is closely related to fail entry `001-cache-budget-template-per-ledger.md`, which targeted the full `Budget::try_from_configs` result. That fail was rejected on the same severity grounds; the narrower decode-only slice has even less projected impact.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Failed At**: hypothesis
**Novelty**: PASS — distinct from `001-cache-budget-template-per-ledger.md`, which proposed caching the entire constructed `Budget`. This hypothesis targets only the upstream XDR decode of `cpu_cost_params`/`mem_cost_params` inputs. However the conclusion is the same: sub-Low.

### Why It Failed

**Sub-Low at the optimistic upper bound.** Even assuming a generous 30µs per decode (likely an overestimate for cached small XDR buffers without budget metering), total aggregate worker CPU is ~474ms. After 8-way cluster normalization and 70-ledger division, this is ~0.85 ms/ledger or **~0.39% of the 218ms baseline** — below the 1% Low floor and an order of magnitude below the 3% Medium threshold.

This matches the conclusion of fail `001-cache-budget-template-per-ledger.md` (full Budget caching was rejected without a direct measurement isolating `Budget::try_from_configs`). The narrower scope of "just the XDR decode of cost params" cannot exceed the broader scope, so it is also sub-threshold.

A direct Tracy measurement around `non_metered_xdr_from_cxx_buf::<ContractCostParams>` would be needed to confirm or refute the upper bound; absent such measurement, this hypothesis cannot be promoted.

### Lesson Learned

Per-tx non-metered XDR decoding of ledger-invariant inputs (cost params, network config) is real redundant work but bounded by `2 × decode_µs × N_tx / NUM_CLUSTERS / N_ledgers`. For soroswap's ~7,900 txs/run and small XDR buffers, even generous per-decode cost assumptions land sub-1%. Any future cost-params/network-config caching hypothesis must first add dedicated Tracy zones around the specific decode site and show direct evidence that the decode itself clears the 3% Medium floor.
