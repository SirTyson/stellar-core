# H029: Cache SAC `transfer` Event Topics-Vec Per (Asset, Host Invocation)

**Date**: 2026-05-24
**Subsystem**: soroban-env
**Severity**: Low (sub-noise after parallelism)
**Impact**: Avoids repeated `host_vec![Symbol("transfer"), from, to, asset_name]`
construction in `transfer()` for SAC events emitted by every soroswap
swap (typically 2 SAC `transfer` calls per native pair swap).
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`stellar_asset_contract::event::transfer` (p26
`builtin_contracts/stellar_asset_contract/event.rs:94-114`) should be able
to skip the per-call construction of the topics `HostVec` for parts that
are invariant within a single host invocation. Specifically, the
`Symbol("transfer")` literal and `read_name(e)` (the asset name
`StringObject`) are constants for a given SAC asset within one
`invoke_host_function` call. The `from` and `to` `AddressObject` handles
*do* vary per transfer. A correctly-bounded optimization would reuse the
"transfer" `SymbolSmall` and the `read_name` `StringObject` handle while
still allocating fresh slots for `from`/`to`/data, charging the same
`Vec::<Val>::charge_bulk_init_cpy` budget as the current 4-slot
construction does.

## Mechanism

Today the function performs:

```rust
let topics = host_vec![
    e,
    Symbol::try_from_val(e, &"transfer")?,  // SymbolSmall — packs in-line, no alloc
    from,
    to,
    read_name(e)?                           // StringObject from instance storage
]?;
```

`host_vec!` allocates a fresh `MeteredVector<Val>` of length 4 and charges
`Vec::<Val>::charge_bulk_init_cpy(4, host)?`. The `Symbol::try_from_val`
for the static `"transfer"` literal compiles to a `SymbolSmall` packed
inline in the `Val`, so it does not allocate a host object. The
`read_name(e)?` call, however, performs:

1. A `try_borrow_objects` on the host frame's instance-storage map.
2. A `MeteredOrdMap::get` of the `"name"` symbol key against the asset's
   instance-storage map.
3. The returned `Val` payload is a `StringObject` handle which is then
   stored as a `Val` in the topics vec.

Step 2 charges `MapEntry::charge_bulk_init_cpy(1, host)` plus comparator
budget. Step 1+3 together hit `VisitObject` once. There is no fresh
allocation, but the borrow + map probe + comparator work is real and
repeats on every SAC `transfer` call.

A cache could hold `(asset_contract_id, name_string_object_handle)` per
host invocation so that subsequent `transfer()` calls for the *same* asset
in the *same* invocation skip the storage probe. Soroswap's native pair
swap path emits two SAC `transfer` events per swap (one for input token,
one for output token) and the router emits zero events itself but
triggers the pair's two SAC transfers. So per soroswap swap, only one
SAC asset (native XLM) is involved.

## Trigger

Apply-load `soroswap` scenario (`TX=2000,T=8`): each pair `swap` calls
SAC `transfer` ~2 times (router-to-pair input + pair-to-recipient
output). Per soroswap apply window (TX=2000, ~7,000 swaps), ~14,000 SAC
`transfer` invocations emit a `transfer` event, each calling
`read_name(e)` against the asset's instance-storage map.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:94-114`
  (`transfer`) — topics-vec construction.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/metadata.rs`
  (`read_name`) — the storage probe being repeated.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs` — the
  `add_host_object` path used by `host_vec!`.

## Evidence

Tracy soroswap trace
(`/mnt/nvme2/apply-load/8dd3f525748f-20260524-114704/logs/...-02-soroswap-tx-2000-t-8.tracy`):

- `SAC transfer` self-time: 668 ms across 16,738 events.
- `add host object`: 271 ms self / 964,774 events.
- `new vec`: 95 ms self / 117,253 events.
- `read_name` is not separately instrumented but is reached via
  `storage get` (236 ms self / 343,817 events) and
  `MeteredOrdMap::get` (covered by `map lookup` 365 ms self / 445,536
  events and `map lookup indexed` 459 ms self / 896,843 events).

## Anti-Evidence

`read_name` is not the dominant SAC transfer cost: storage charges,
auth/frame work, balance reads, and event-data XDR serialization all
remain. The `Symbol("transfer")` literal is already an inline
`SymbolSmall` with no allocation.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Failed At**: hypothesis
**Novelty**: PASS — adjacent to but distinct from fail
`001-cache-sac-asset-metadata-host-objects.md` (which targeted caching
the metadata `StringObject`s globally rather than per-asset-per-invocation
within the `transfer` event-emission path specifically).

### Why It Failed

Per-call removable physical work is the single `read_name` storage
probe (`try_borrow_objects` + `MeteredOrdMap::get` + comparator). After
the existing `coalesced_host_metering` protocol gate elides the
`VisitObject` Tracy span in the non-coalesced production path, the
removable work is essentially the borrow + binary-search probe of a
small (<= 5 entries) instance-storage map plus one symbol comparator
call.

Quantification:
- Per-call removable cost: estimated 200–500 ns (one `RefCell` borrow,
  one 5-entry binary search with `Symbol` comparator, one `Val` copy).
- Per-soroswap-apply-window call count: ~14,000 (two SAC transfers
  per ~7,000 swaps).
- Aggregate savings: 14,000 × ~350 ns ≈ 4.9 ms total trace self-time.
- After 8-way cluster parallelism: 4.9 / 8 ≈ 0.61 ms wall.
- Across the benchmark's ~71 measured ledgers: 0.61 / 71 ≈ 0.009 ms
  per ledger.
- Fraction of 211 ms soroswap apply baseline: ≈ 0.004 %.

That is roughly three orders of magnitude below the 1 % benchmark-noise
floor and four orders of magnitude below the 3 % Medium threshold this
objective requires. Additionally:

1. The `read_name` storage probe is the same one that fail
   `001-cache-sac-asset-metadata-host-objects.md` already noted is
   bounded by `MeteredOrdMap::get` overhead; the cited per-event cost
   in that fail (sub-microsecond) matches this independent estimate.
2. The pair's two SAC transfers use the same native asset within one
   host invocation — the cache hit rate is high — but the absolute
   savings remain too small.
3. A budget-preserving cache must still replay the `MapEntry::charge_bulk_init_cpy`
   that `host_vec!` performs and any `MemCpy` for the cached `Val`,
   shrinking the removable subset further.

### Lesson Learned

For SAC event-emission "skip the per-call constant lookup" hypotheses,
the per-call removable cost is bounded by the small instance-storage
map probe (~300 ns including borrow + binary search). With soroswap's
~14,000 SAC transfer events per benchmark window and 8-way cluster
parallelism, even a perfect cache cannot clear 0.01 % of apply time.
Future SAC event-path optimizations need to remove either the
`metered_write_xdr` final encoding work or the `contract_event` host
function dispatch itself — not the topic-vec assembly that precedes it,
which has already been driven near its physical lower bound.
