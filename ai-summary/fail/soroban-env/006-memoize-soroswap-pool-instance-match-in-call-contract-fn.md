# H006: Memoize Per-Frame Soroswap-Pool Instance Match Decisions in `call_contract_fn`

**Date**: 2026-05-26
**Subsystem**: soroban-env
**Severity**: Low
**Impact**: Apply-time reduction via removed per-call native pool match work
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`Host::call_contract_fn`
(`src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:782-835`) is the
single dispatch point for every contract-to-contract call in the soroban host.
For each call, after retrieving the contract instance from storage, the
function must determine whether the call can take a native Soroswap pool
fast path (`match_native_soroswap_pool_getter`,
`match_native_soroswap_pool_swap`) or must fall through to ordinary Wasm
instantiation. The expected behavior is one match-check sequence per call
that returns the dispatch decision in O(1) amortized time.

## Mechanism

The two `match_native_*` functions today repeat the following work on every
call to a Soroswap pool contract: (a) a `get_ledger_protocol_version()?`
RefCell borrow on the host's `LedgerInfo`; (b) a 32-byte wasm-hash slice
compare against the vendored pool hash constant; (c) a symbol-matches host
call per allowlisted getter symbol (`symbol_matches` is implemented as
`compare(&SymbolStr::from_bytes(b)?, &func)?`, which itself acquires the
budget and may allocate a `SymbolStr`); (d) **a linear `iter().find(...)`
scan over `instance.storage` ScMap entries** for each layout-bit check,
called once per layout bit (one call for `Token0`/`Token1`/`Factory`/`KLast`,
two calls for `GetReserves`).

These per-call costs are paid for every native pool dispatch (~14,000
getter calls + ~7,000 swap matches in the soroswap benchmark window).
Caching the "is this contract instance a soroswap pool with layout L?"
decision once per `ScContractInstance` reference (or per `(contract_id,
wasm_hash)` tuple per frame stack) would reduce the per-call work to a
single equality check against the cached decision tag.

## Trigger

Run `scripts/run_apply_load_matrix.py` on the soroswap workload. Each router
swap transaction triggers ~3–5 pool getter calls and one pool swap call on
the same pool instance; each call re-executes the full match sequence
including the storage-layout linear scan.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:837-859` —
  `match_native_soroswap_pool_getter` body with protocol-version borrow,
  hash compare, symbol lookup, and layout check.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:881-917` —
  `soroswap_pool_instance_matches_getter` and `soroswap_pool_scmap_get`
  performing per-call O(N) linear scan of `ScContractInstance.storage`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:862-879` —
  `soroswap_pool_getter_for_symbol` iterating allowlisted symbols.

## Evidence

- `soroswap_pool_scmap_get` is a linear scan invoked once per layout bit
  per match; for `GetReserves` it runs twice per match.
- `Vm::instantiate_wasmi - instantiate` count (~8,113 events) bounds the
  remaining Wasm router calls; the rest of soroswap dispatch (~21K calls
  estimated by `extend_current_contract_instance_and_code_ttl` count
  ~16K) goes through the native fast paths and pays the match overhead
  per call.
- The match decision is structurally stable across all calls to the same
  Soroswap pool instance within a benchmark window — the protocol version,
  wasm hash, and instance storage layout do not change between calls.

## Anti-Evidence

- `instance.storage` is small (~5–6 entries for the vendored Soroswap pool).
  Each linear scan is ~30–60 ns total. With 21,000 native pool dispatches:
  21,000 × 60 ns × 2 (for `GetReserves`) = ~2.5 ms aggregate, normalized
  to ~4 µs/ledger wall after 8-way parallelism across 71 ledgers.
- The native pool match-functions already exit quickly for non-pool
  contracts (the `wasm_hash` slice compare at line 850 fails on the very
  first byte mismatch).
- A frame-keyed cache would need to handle invalidation when
  `update_current_contract_wasm` mutates the executable mid-frame, adding
  correctness scaffolding for a sub-noise-floor win.
- Memoization keyed by `(contract_id, wasm_hash)` across the call stack
  would also need to respect the `MIN_LEDGER_PROTOCOL_VERSION` gate per
  ledger, requiring per-ledger cache reset.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated; adjacent fails (H027,
H028) target the args-vec construction and id-clone in `call_contract_fn`,
not the match-decision linear scans.

### Why It Failed

Quantitative ceiling: ~21,000 native pool dispatches × ~120 ns of
removable match work per call (worst-case sum of `symbol_matches`,
linear scan, and protocol-version borrow) = ~2.5 ms aggregate per
benchmark window. Normalized by 8-way cluster parallelism across
71 ledgers: ~4 µs/ledger wall = ~0.002% of the 207 ms soroswap
apply baseline. Three orders of magnitude below the 1% noise floor
and four orders below the 3% Medium floor.

Matches Meta-Pattern #14 (Native Pool Micro-Optimizations Below
~10 µs/Swap Are Sub-Low After Normalization): the per-call removable
work is ~120 ns, and the entire `call_contract_fn` per-call cost
is sub-µs after subtracting the mandatory `retrieve_contract_instance_from_storage`
and `args.to_vec()` paths that this hypothesis does not touch.

The objective accepts only Medium (≥3%) and High (≥10% or
dominant-phase redesign) hypotheses. This is sub-Low and below the
objective severity threshold.

### Lesson Learned

The native Soroswap pool match functions (`match_native_soroswap_pool_*`)
have multiple per-call work components — protocol version borrow, hash
compare, symbol lookup, per-layout-bit linear scan — but each component is
≤60 ns. Aggregating to ~120 ns/call × 21K calls / 8 parallelism / 71
ledgers ≈ 4 µs/ledger wall. Future hypotheses around the native pool
match-decision overhead must demonstrate ≥4 µs/call of removable work to
clear Low, and ≥12 µs/call to clear Medium. The instance-layout linear
scan in `soroswap_pool_scmap_get` is the largest single component but
remains sub-100 ns due to the small ScMap size; replacing it with a
keyed access would not change the order of magnitude.
