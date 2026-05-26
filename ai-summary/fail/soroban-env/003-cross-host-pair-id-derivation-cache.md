# H003: Cross-Host Process-Wide Pair-ID Derivation Cache

**Date**: 2026-05-25
**Subsystem**: soroban-env
**Severity**: Low
**Impact**: Apply-time reduction via SHA/XDR amortization
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

For soroswap, every router `swap` invocation in Wasm calls
`factory.pair_for(token0, token1)` which derives the pool contract ID by:
serializing `(SymbolStr("pair"), token0, token1)` to XDR via host
`serialize_to_bytes`, hashing via `compute_hash_sha256`, then computing
the contract ID via `get_contract_id`. The expected behavior is that this
derivation is computed once per `(factory_id, token0, token1)` tuple per
ledger / per cluster worker, since the inputs are stable across the entire
benchmark workload and across Host instances within a worker. A process-
wide memoization sitting next to `SorobanModuleCache` would let every Host
constructed in a worker reuse the precomputed pair ID without re-entering
the SHA/XDR host-function pipeline.

## Mechanism

The actual behavior performs SHA-256 + XDR serialization + contract-id
derivation inside the Wasm interpreter for every single swap, because each
Host is short-lived (one per tx) and `H024`'s per-Host pair-salt cache
does not survive Host destruction. Hoisting the cache one level up — to a
process-wide structure keyed by `(factory_id, token0, token1) → pair_id`,
populated lazily and read directly by a native router fast path or by a
SHA host-function shortcut — would amortize this per-pair work across all
~8k swaps in the benchmark instead of per-tx.

## Trigger

Run the soroswap apply-load benchmark. Inspect the Tracy profile for the
`compute_hash_sha256`, `serialize_to_bytes`, and `get_contract_id` host
function zones, plus the surrounding `pair_for` Wasm execution. Aggregate
their cost across all swaps.

## Target Code

- `src/rust/src/soroban_proto_any.rs:invoke_host_function_or_maybe_panic:430-510` — bridge wrapper that would host the cross-Host cache.
- `src/rust/soroban/p26/soroban-env-host/src/host/crypto.rs` — `compute_hash_sha256` host function (charged metering).
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs` — `serialize_to_bytes` / `get_contract_id`.
- `src/bucket/SorobanModuleCache.h` — natural home for a process-wide pair-id cache adjacent to the module cache.

## Evidence

- H024 quantified the SHA-zone upper bound at ~78 ms of apply across the
  benchmark = ~1.7% of soroswap wall.
- The bounded saving from also removing the XDR-serialize and
  contract-id-derive host functions (similarly costed) might push the
  upper bound to ~2.5–3%.
- Inputs are stable across the entire benchmark workload: factory,
  token0, token1 sets are small (the soroswap router routes among a
  fixed set of pools).

## Anti-Evidence

- Skipping the host-charged `compute_hash_sha256` /
  `serialize_to_bytes` / `get_contract_id` invocations is **protocol-
  visible**: their `charge()` calls participate in CPU/memory metering
  with `const_term > 0` (Meta-Pattern #2). Any such optimization
  requires next-protocol gating.
- The total achievable wall-time reduction is bounded above by the
  combined SHA+XDR+contract-id self-time, which by H024's measurement
  cannot exceed ~3% even with full elimination, and the actual
  achievable fraction (after factoring in residual Wasm execution of
  `pair_for`'s control flow and the cache-lookup cost itself) is
  closer to 1.5–2%.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Failed At**: hypothesis
**Novelty**: PASS — distinct from H024 (per-Host pair-salt cache) and
fail/002 (footprint-resolved native router swap, which closed the
"skip pair_for entirely" angle because pool entries are attacker-
controllable in the footprint).

### Why It Failed

Below objective severity threshold. The optimization's wall-time upper
bound (~1.5–2% after realistic accounting for residual `pair_for`
execution and cache overhead) lies in the Low band (1–3%). The
objective accepts only Medium (3–10%) and High (>10%) findings at
hypothesis stage. Additionally, the path requires next-protocol
gating because the eliminated host calls are protocol-visibly
metered (Meta-Pattern #2), which further reduces the near-term
impact on the current-protocol soroswap benchmark to zero.

### Lesson Learned

When cross-Host caching is proposed for protocol-charged host calls,
the metering-visibility constraint (Meta-Pattern #2) effectively
converts the proposal into a next-protocol-only optimization,
yielding zero current-protocol wall-time benefit. Combined with the
H024 SHA-zone ceiling of 1.7%, any pair-id-derivation cache cannot
clear the Medium floor on its own. Future investigations should
either (a) target a much hotter zone, or (b) combine pair-id caching
with several other amortizations into a single protocol-gated batch.
