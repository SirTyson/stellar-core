# H007: Cache MeteredOrdMap last-found insertion position to skip redundant binary searches on consecutive operations against the same key

**Date**: 2026-04-28
**Subsystem**: transaction-ledger / Soroban host storage map (`MeteredOrdMap`)
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by collapsing duplicate binary searches and budget charges across `Storage::get`/`has`/`extend_ttl`/`put` sequences that touch the same key
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`Host::Storage` is a `MeteredOrdMap<Rc<LedgerKey>, ...>` that backs every
contract-data, contract-code, and TTL access during a Soroban tx. The map
exposes `get`, `has`, `insert`, `remove`, and `extend_ttl`, each of which
calls `MeteredOrdMap::find` (`metered_map.rs:168-194`) which performs a
charged binary search (`charge_binsearch`) over the sorted entry vector.

For a typical SAC `transfer` and the surrounding soroswap pool flow, the
host hits the storage map several times in immediate succession against
the *same* `Rc<LedgerKey>`: e.g. `is_authorized` does a `get`, then
`spend_balance` does another `get` for the same balance key, then `insert`
to write the new balance, then `extend_ttl` on the same key — four
operations on the same key with four independent binary searches and four
charge calls. The expected efficient implementation should remember the
last `(key_pointer, found_position)` pair on the storage struct (or pass
a position hint through the helper API) and skip the second-and-later
binary searches, while charging an equivalent (or smaller, justified)
amount on the cache-hit path.

## Mechanism

`MeteredOrdMap::find` is invoked by every `get`/`has`/`insert`/`remove`
and indirectly by every `extend_ttl` call (which calls
`get_with_live_until_ledger`). On the soroswap baseline the
`map lookup,metered_map.rs:173` zone is **350 923 calls / 403.3 ms** of
worker self-time and the `obj_cmp,vmcaller_env.rs:270` zone is
**114 843 calls / 78.1 ms**. The `Compare` callback walks two
`Rc<LedgerKey>`s and recursively compares all fields; for
`LedgerKey::ContractData` (which dominates soroswap footprints) this
descends into `ScAddress` + `ScVal` comparison, which is pointer-chase
heavy and budget-charged. Adding a one-slot
`(last_key_ptr, last_pos): Option<(*const LedgerKey, usize)>` cache on
`Storage` (or an LRU-1 cache on `MeteredOrdMap` itself, gated to the
common case where the caller passes the same `Rc` whose `Rc::as_ptr()`
matches) would short-circuit every immediate-repeat lookup. Because the
caller in SAC always reuses the same `Rc<LedgerKey>` it constructed
once for the operation sequence (e.g. `DataKey::Balance(addr)` built
once, then used for `is_authorized`, then `spend_balance_no_authorization_check`,
then `extend_ttl`), the pointer-equality check is enough to safely skip
the binary search.

For determinism the cached path must still apply the equivalent
`charge_binsearch` cost (or an explicit smaller `MapEntry` access cost
that is identical across all nodes), keeping budget totals invariant.

## Trigger

Run the soroswap apply-load benchmark
(`scripts/run_apply_load_matrix.py`, `soroswap, TX=4000, T=8`) and inspect
the longest `applyLedger` window in the existing baseline trace. Each
SAC `transfer` issues at least four storage operations on the
`DataKey::Balance(from)` key (auth check, spend, write, ttl) and four
on `DataKey::Balance(to)` (auth, receive, write, ttl), plus pool-state
accesses on the Wasm side that follow the same load → modify → write
pattern.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:38-76`
  — `MeteredOrdMap` struct: add an interior-mutable
  `Cell<Option<(usize, *const u8)>>` last-position cache (or push the
  cache to the caller side via a position hint argument).
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:168-194`
  — `find`: consult the cache before binary search; on hit, charge a
  budget-equivalent `MapEntry` access amount and return the cached
  position; on miss, fall through to today's binary search and update
  the cache.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:196-225`
  — `insert`: when the new map is built from an existing position, propagate
  the position to the new map (one-slot cache transfer) so subsequent
  `extend_ttl` on the same key still hits.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:255-330` —
  `Storage::get` / `Storage::get_with_live_until_ledger`: ensure the
  cached position survives the wrapper layer (or thread it through as
  a parameter where SAC helpers know the key is still hot).
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs`
  (call sites that load + mutate balance) — naturally benefit from the
  host-side cache without source change.

## Evidence

Tracy soroswap baseline (longest `applyLedger` window):

- `map lookup,metered_map.rs:173` — **350 923 calls, 403.3 ms** worker
  self-time. Even a 30 % cache hit rate (a conservative lower bound
  given the auth-check → mutate sequence pattern) saves ~120 ms.
- `obj_cmp,vmcaller_env.rs:270` — **114 843 calls, 78.1 ms** worker
  self-time. Cache hits skip all `Compare` calls inside the binary
  search, removing the corresponding fraction of this zone.
- `charge,budget/dimension.rs:176` — **8 704 023 calls, 826.8 ms**.
  `charge_binsearch` is one source of these calls; replacing the
  per-comparison charge with a single per-cache-hit access charge
  reduces the call count proportionally to the cache hit rate.
- `storage get,storage.rs:258` — **82 208 calls, 86.7 ms**. The SAC
  `is_authorized` + `spend_balance` + `receive_balance` flow
  consistently re-fetches the same key two-to-three times in a row
  before mutating.
- `extend key,storage.rs:540` — **21 749 calls, 120.7 ms**. Each
  `extend_ttl` for a key that was just `get`-ed pays another full
  binary search.

Combined removable cost is plausibly 100–180 ms of worker self-time on
the soroswap apply window (≈2–4 % of the 4.59 s `applyLedger` total
captured in the baseline). The exact figure depends on the achieved
cache hit rate; instrumenting `find` with a hit/miss counter on a
prototype build would provide the precise number before implementation.

## Anti-Evidence

- **Pointer-equality is fragile**: SAC helpers sometimes
  `metered_clone` the `Rc<LedgerKey>` (e.g. balance.rs builds a fresh
  `Rc` per call site). The optimization only fires when the caller
  reuses the *same* `Rc` instance across operations. A profiling
  prototype is needed to measure achieved hit rate; the hypothesis
  may need to be combined with light-touch caller refactors that hold
  the constructed `Rc` across the load → mutate sequence.
- **Determinism / metering**: the cache-hit charge must be deterministic
  and identical across all nodes. Charging an explicit `MapEntry` cost
  (one access charge, fixed) on the hit path keeps budget totals
  network-stable. Skipping the charge entirely would change observable
  budget consumption and is unsafe.
- **Map mutation invalidates cache**: `insert`/`remove` produce a new
  `MeteredOrdMap` (the structure is persistent/immutable). Either the
  cache lives on the `Storage` wrapper (which holds the current map) and
  is invalidated on every mutation, or it is propagated by computing the
  new position in the new map (`replace_pos`/`insert_pos` is already
  computed in `insert`). The latter is preferred to keep the cache hot
  across `get → insert → extend_ttl` sequences.
- **Concurrency**: parallel apply distributes Soroban txs across
  worker threads, but each `Host` instance is single-threaded; the
  cache lives inside the host's `Storage` and never crosses thread
  boundaries.
- **Borrow rules**: `find` is `&self` because the map is persistent. A
  `Cell`/`RefCell` interior-mutable cache requires care not to violate
  the existing borrow patterns inside `MeteredOrdMap` consumers.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-28
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — no prior fail/success entry investigated this exact `MeteredOrdMap` last-position cache; H006 is related TTL-storage lookup coalescing, but targets a different redundant-call mechanism
**Failed At**: reviewer

### Trace Summary

The inefficient operation exists: durable host storage uses `MeteredOrdMap<Rc<LedgerKey>, ...>`, and `Storage::{get,has,put,extend_ttl}` route through charged binary searches in `MeteredOrdMap::find`. However, the proposed pointer-equality cache does not match the main SAC flow claimed by the hypothesis because the Host Env methods reconstruct a fresh `Rc<LedgerKey>` from the same `Val` for many consecutive calls. Even if a broader content-aware cache removed every cited storage-map lookup, the quoted time is aggregate worker time in the `T=8` parallel soroswap scenario, so the apply-wall-clock upper bound is below the objective's Medium threshold.

### Code Paths Examined

- `scripts/run_apply_load_matrix.py:417-425` — the scenario's `thread_count` is written to `APPLY_LOAD_LEDGER_MAX_DEPENDENT_TX_CLUSTERS`; the hypothesis trigger explicitly uses `T=8`.
- `src/simulation/ApplyLoad.cpp:2323-2332` — the benchmark asserts one Soroban stage and the configured maximum cluster count, so worker totals from this trace must be normalized against the parallel cluster count.
- `src/ledger/LedgerManagerImpl.cpp:2531-2574` — each Soroban cluster runs through `std::async` and the apply path waits on worker futures; aggregate worker self-time is not the same as apply critical-path time.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-585` — each Soroban operation enters `rust_bridge::invoke_host_function`, which invokes the Rust host for contract execution.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-485` — each invocation builds the storage footprint/map, constructs a fresh `Host`, runs `Host::invoke_function`, and finishes storage at the transaction boundary.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:25-27` and `179-183` — durable host storage is `MeteredOrdMap<Rc<LedgerKey>, Option<EntryWithLiveUntil>, Budget>` inside a per-host `Storage`.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:63-83` and `168-194` — `find` always charges binary-search access and performs a comparator-driven binary search over the vector.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:252-329`, `332-389`, and `431-573` — `get`/`has`, `put`, and `extend_ttl` all reach the storage map lookup path; `extend_ttl` calls `get_with_live_until_ledger` before optionally writing an updated TTL.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:156-166` — every persistent/temporary Env call converts the `Val` key into an `ScVal` and allocates a new `Rc<LedgerKey>`.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2211-2240` and `2293-2317` — `has_contract_data`, `get_contract_data`, and `extend_contract_data_ttl` each independently call `storage_key_from_val`, so immediate same-`Val` calls usually do not reuse the same `Rc<LedgerKey>` pointer.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/storage_utils.rs:3-14` — built-in `try_get_contract_data` is `has_contract_data` followed by `get_contract_data`, causing two storage lookups but through separately constructed ledger-key `Rc`s.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:44-63`, `74-97`, `100-145`, `156-230`, and `233-254` — SAC balance helpers build `DataKey::Balance` values and repeatedly call Env methods; these calls pass `Val`s, not a shared `Rc<LedgerKey>` through the sequence.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:509-563` — `put_contract_data_into_ledger` is one place where a single constructed `Rc<LedgerKey>` is reused across `has`/`get_with_live_until_ledger`/`put`, but this covers only a subset of the repeated operations and still must preserve equivalent metering.
- `src/rust/soroban/p26/soroban-env-host/src/host/comparison.rs:382-431` — `LedgerKey::ContractData` comparisons recurse through contract address, `ScVal` key, and durability, so avoiding a lookup can save real comparator work when a cache hit actually occurs.

### Why It Failed

The optimization fails the objective-specific Medium severity floor and the proposed mechanism overstates cacheability. The cited `map lookup` cost is 403.3 ms of worker self-time in a `T=8` parallel run. In the impossible best case where every `MeteredOrdMap::find` under that zone disappeared and work was balanced across the configured clusters, the apply critical-path reduction would be about 403.3 / 8 = 50.4 ms, roughly 1.1% of the 4.59 s apply window. A realistic last-position cache saves much less because it only hits immediate repeats, must retain deterministic budget charges, and the pointer-equality design misses common SAC sequences where `try_get_contract_data`, `put_contract_data`, and `extend_contract_data_ttl` reconstruct fresh `Rc<LedgerKey>` values from the same `Val`.

There is a narrower real redundancy inside `put_contract_data_into_ledger`: it constructs one `Rc<LedgerKey>` and then calls `has`, `get_with_live_until_ledger`, and `put` with that same pointer for existing entries. That subset is not enough to reach the 3% apply-time threshold, and broadening the idea into a content-aware position hint would be a different hypothesis that must account for metering equivalence and frame/storage rollback behavior. Under the optimize-soroswap review criteria, Low-tier and sub-1% projections are rejected rather than promoted.

### Lesson Learned

For Soroban host micro-optimizations, distinguish repeated logical keys from repeated `Rc<LedgerKey>` identities: Env-facing calls often convert a stable `Val` into a fresh ledger-key allocation. Also normalize Tracy worker-time totals from parallel Soroban apply by the active cluster count before comparing them to apply-wall-clock severity thresholds.
