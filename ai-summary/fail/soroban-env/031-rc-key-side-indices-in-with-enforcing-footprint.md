# H031: Use `Rc<LedgerKey>` (Not Deep-Cloned `LedgerKey`) as HashMap Key for the Enforcing-Mode Side Indices

**Date**: 2026-05-25
**Subsystem**: soroban-env
**Severity**: Low (projected ~0.2–0.4% apply-time)
**Impact**: Per-invocation host setup allocations
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`Storage::with_enforcing_footprint_and_map` (p26
`src/rust/soroban/p26/soroban-env-host/src/storage.rs:245-268`) is called once
per Soroban invocation to construct the `Storage` with two precomputed side
indices (`enforce_footprint_idx`, `enforce_storage_idx`) that map a `LedgerKey`
to its sorted position. Constructing those indices SHOULD avoid a deep
`LedgerKey` clone for every footprint entry, because the underlying
`MeteredOrdMap` already holds the keys behind `Rc<LedgerKey>` — the side
index can store `Rc<LedgerKey>` and lookups via `idx.get::<LedgerKey>(key)`
still work thanks to `Rc<T>: Borrow<T>`.

## Mechanism

Today both index loops deep-clone the key:

```rust
for (i, (k, _)) in footprint.0.map.iter().enumerate() {
    fp_idx.insert((**k).clone(), i);   // deep clone of LedgerKey
}
for (i, (k, _)) in map.map.iter().enumerate() {
    st_idx.insert((**k).clone(), i);   // deep clone of LedgerKey
}
```

For a `ContractData` key this clones an `ScAddress` + `ScVal` + `Hash`
(~50–200 bytes). For a `ContractCode` key this clones a `Hash`.

The fix is mechanical: change the maps to
`HashMap<Rc<LedgerKey>, usize>` and `Rc::clone(k)` into them. Hash/Eq of
`Rc<LedgerKey>` is implemented via `Borrow<LedgerKey>`, so the existing
`idx.get(key.as_ref())` lookup still compiles.

## Trigger

Every Soroban invocation in the soroswap or max-sac benchmark hits this
constructor exactly once via `e2e_invoke::invoke_host_function`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:252-260` —
  the two deep-clone loops.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:283-321`
  (`enforce_access_indexed`) — already uses `idx.get(key.as_ref())`, which
  remains valid under the `Rc<LedgerKey>` map type.

## Evidence

- 8705 soroswap invocations × ~10 footprint keys × 2 maps ≈ 174K deep
  `LedgerKey::clone()` calls per soroswap window.
- A `ContractData` LedgerKey deep clone is ~1µs (string copy of contract id +
  ScVal vector). Total ≈ 174 ms CPU / 8 workers / 71 ledgers per window ≈
  0.3 ms wall per ledger ≈ **0.15%** of the 207 ms soroswap baseline.
- Diff is small and risk-free; no protocol-visible metering changes (this
  setup work is not metered against the host budget).

## Anti-Evidence

- Projected impact is **below the Medium severity floor (3%)** and below
  the objective's Low floor (1%) — i.e. within benchmark noise.
- Side indices are an already-shipped `viable success` optimization
  (`success/soroban-env/...`); shaving construction cost is a second-order
  refinement, not a dominant phase reshuffle.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Failed At**: hypothesis
**Novelty**: PASS — `fail/soroban-env/summary.md` row
"002-rc-key-enforcing-storage-side-indices" documents a similar idea but its
actual content was about turning the Vec into an Rc-key Vec elsewhere; this
hypothesis specifically targets the HashMap key type in the same constructor.
Either way, sub-1%.

### Why It Failed

Below the objective severity threshold. The per-invocation deep-clone cost
across the entire soroswap window is on the order of a few hundred
microseconds of wall time per ledger close — well under the 1% noise floor,
let alone the Medium 3% threshold. The optimization is correct and safe but
does not move the apply-time needle.

### Lesson Learned

When index/cache construction code uses `(**rc).clone()` rather than
`Rc::clone(rc)`, it's almost always a missed shallow-clone opportunity — but
the population loop runs only once per invocation, so the savings scale only
linearly with footprint size and rarely cross the Medium threshold on this
benchmark. Reserve such tweaks for cleanup PRs, not optimization gates.
