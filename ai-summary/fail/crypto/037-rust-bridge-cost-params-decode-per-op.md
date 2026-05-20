# H037: Eliminate Rust-Side ContractCostParams Re-Decode per InvokeHostFunctionOp

**Date**: 2026-05-20
**Subsystem**: crypto / rust
**Severity**: Low
**Impact**: apply-time reduction
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`CxxLedgerInfo::cpu_cost_params` and `CxxLedgerInfo::mem_cost_params` are
constant for the duration of a ledger (they come from `SorobanNetworkConfig`
which is updated only at protocol/upgrade boundaries). The C++ side already
caches the encoded `CxxLedgerInfo` per-ledger via the `thread_local`
`getCachedLedgerInfo` helper at
`src/transactions/InvokeHostFunctionOpFrame.cpp:75-94`, so the XDR encoding
work for these two `CxxBuf`s runs only once per ledger per worker thread.
The expected behaviour is symmetric on the Rust side: each
`invoke_host_function` should consume the already-encoded cost-params bytes
without paying a fresh `ReadXdr::read_xdr` deserialization cost per op.

## Mechanism

The current Rust dispatch path
(`src/rust/src/soroban_proto_any.rs:418-419`) calls
`non_metered_xdr_from_cxx_buf::<ContractCostParams>(&ledger_info.cpu_cost_params)`
and the matching mem variant on **every** `Budget::try_from_configs` setup,
i.e. once per `InvokeHostFunctionOp`. For soroswap (~2000 ops/ledger × 2
decodes) that is ~4000 fresh `ContractCostParams` deserializations per
ledger. A `ContractCostParams` is a `VecM<ContractCostParamEntry, 1024>`
containing ~30-40 entries of `(ext, cost_type, const_term i64,
linear_term i64)` — the in-source comment at `soroban_proto_any.rs:415-417`
explicitly acknowledges this is "non-metered" but claims the cost is "small
constant". The deviation from "decode once per ledger" is real but the
absolute cost per decode is on the order of a few hundred nanoseconds of
copy/iterate work per param × ~70 entries (cpu+mem) ≈ a few µs per op.

## Trigger

Apply soroswap ledgers (TX=2000, T=8). Each `invoke_host_function` re-decodes
both cost-params buffers when constructing the per-op `Budget`.

## Target Code

- `src/rust/src/soroban_proto_any.rs:415-420` — per-op
  `non_metered_xdr_from_cxx_buf::<ContractCostParams>` decode
- `src/transactions/InvokeHostFunctionOpFrame.cpp:75-94` — C++-side cached
  encoder; decode side is not symmetric

## Evidence

- Cost-params XDR bytes are constant per ledger; the C++ side already caches
  them via `thread_local` `cachedLedgerInfo`, so decoding them per op is
  strictly redundant within a ledger.
- Soroswap performs ~2000 ops/ledger, so the per-op redundancy compounds
  by 2000× per ledger.
- The decode is allocating: `VecM` allocation, plus per-entry struct decode.
- `Budget::try_from_configs` runs on every host setup before any contract
  code executes, so it is squarely on the apply critical path.

## Anti-Evidence

- The source comment at `soroban_proto_any.rs:415-417` explicitly flags this
  decode as "small constant cost", suggesting the soroban-env authors have
  already deemed it negligible.
- A bound from Meta-Pattern 8 (FFI bridge per-entry overhead is bounded at
  ~50ms total trace-wide, of which input encoding/decoding is a small share)
  applies: bridge-side overhead is structurally a few-percent fraction of
  apply, and `ContractCostParams` decode is one of many bridge decodes.
- The optimization would require either (a) caching the decoded
  `ContractCostParams` Rust-side in a `thread_local` keyed on
  `(network_id, ledger_seq)`, which crosses the FFI/host boundary and
  carries `Budget`-construction implications, or (b) extending the bridge
  to pass already-decoded primitives, which fragments the FFI surface.
- Actual measured per-decode cost is ~1µs × ~70 entries ≈ <100µs per op,
  totaling ~200ms across all 2000 ops per ledger; even total elimination
  is bounded at <1% of soroswap apply (273ms median).

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-20
**Failed At**: hypothesis
**Novelty**: PASS — no prior fail/hypothesis/reviewed/poc entry targets the
Rust-side per-op `ContractCostParams` decode specifically (H006 covered
small bridge-input borrow patterns; H010 covered output decode; this is a
distinct input-decode amortization angle that has not been recorded).

### Why It Failed

Sized against the soroswap apply-time envelope (~273ms median), the realistic
per-op decode cost for `ContractCostParams` is below the objective's 1% Low
floor and well below the 3% Medium minimum required for promotion. Even an
overly-generous estimate that attributes every byte of "small constant" XDR
walking work to the apply-path budget yields a per-ledger total in the
hundreds of microseconds to low single-digit ms range, dominated by ~70
trivial integer reads per op. The optimization carries non-trivial
implementation risk (per-thread Rust-side cache keyed on protocol+ledger,
plus invalidation when `SorobanNetworkConfig` changes mid-process) and the
absolute payoff is structurally bounded below the severity floor regardless
of implementation quality.

### Lesson Learned

Even when a per-ledger constant is re-decoded thousands of times, if the
underlying decode is ~30-70 trivial integer reads per call, the aggregate is
sub-millisecond per ledger and cannot reach Medium severity for soroswap
apply. The `non_metered_xdr_from_cxx_buf` helper is benign for cost-params
specifically; this lesson does NOT generalize to per-op decodes of
variable-sized inputs (footprint, ledger entries, auth entries), which scale
with workload and may warrant separate investigation.
