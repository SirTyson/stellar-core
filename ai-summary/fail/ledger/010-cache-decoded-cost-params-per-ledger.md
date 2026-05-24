# H010: Cache deserialized `cpu_cost_params` and `mem_cost_params` on the Rust host side across all transactions in a ledger to skip per-tx XDR decode in `Host::with_storage_and_budget`

**Date**: 2026-05-24
**Subsystem**: ledger / Soroban host budget setup
**Severity**: Low (claimed); actually below threshold
**Impact**: Eliminate the per-tx XDR deserialization of `ContractCostParams` (cpu + mem) inside the Rust host bridge by caching the decoded values per `(ledger_seq, ledger_version)` and reusing them across all parallel-apply worker invocations within a ledger.
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`CxxLedgerInfo` (`src/rust/src/bridge.rs:70-82`) carries `cpu_cost_params:
CxxBuf` and `mem_cost_params: CxxBuf` — XDR-serialized cost model tables —
across every `rust_bridge::invoke_host_function` call. Per fee/protocol
contract, these byte strings change only on a `SorobanNetworkConfig` upgrade
(typically zero times per ledger). Expected behavior: the Rust host should
deserialize each cost-params payload at most once per `(ledger_seq, payload
hash)` pair, then reuse the decoded `ContractCostParams` for every transaction
in that ledger.

## Mechanism

Inside `e2e_invoke::invoke_host_function`, every call constructs a fresh
`Host` with its `Budget` initialised from the supplied cost params. The
constructor path XDR-decodes both `cpu_cost_params` and `mem_cost_params`
each time, even when the same bytes were just decoded for the previous
transaction on the same worker. A per-thread `LRU<Hash, Arc<ContractCostParams>>`
keyed on a small fingerprint (e.g. first-8-bytes or a SHA256 stamp computed
once per ledger seq change) would let the host fetch the already-decoded value
on cache hit. The cached payload is immutable, so amortization is safe across
all 2000+ tx invocations per ledger.

## Trigger

`scripts/run_apply_load_matrix.py` soroswap TX=2000 T=8: each Soroban tx
calls `rust_bridge::invoke_host_function`, which builds a fresh `Host` and
decodes the cost params for the `Budget`. Within a ledger the cost-params
bytes are identical across all tx; under steady-state apply, the same bytes
are decoded ~250 times per worker per ledger.

## Target Code

- `src/rust/src/bridge.rs:70-82` — `CxxLedgerInfo` definition, carries the
  XDR-encoded cost params per call.
- `src/rust/src/soroban_invoke.rs` — host-side dispatch into
  `e2e_invoke::invoke_host_function`; candidate site for a thread-local
  decoded-params cache.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:472-593` —
  `invoke_host_function`, builds the Host with budget.
- `src/rust/soroban/p26/soroban-env-host/src/budget/...` — `Budget`
  construction that consumes the decoded cost params.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:75-94` — `getCachedLedgerInfo`
  thread_local cache on the C++ side (already caches the `CxxLedgerInfo`
  struct, but the Rust side still re-decodes its CxxBuf contents per call).

## Evidence

The C++ side already caches `CxxLedgerInfo` per `(ledger_seq)` via the
`thread_local cachedLedgerInfo` in `getCachedLedgerInfo`, so the cpu/mem
cost-params XDR bytes themselves are identical across all calls within a
ledger. The Rust host nevertheless rebuilds a fresh `Host` (including
`Budget`) per `invoke_host_function`. From the current Tracy trace
(`/mnt/nvme2/apply-load/62ee1ffb5d05-20260523-010230/logs/62ee1ffb5d05-20260523-010230-02-soroswap-tx-2000-t-8.tracy`)
the `invoke_host_function` zone (`soroban-env-host/src/e2e_invoke.rs:488`)
shows 828,296,243 ns self-time over 7,891 invocations, ~104 µs/call. The
cost-params decode is a small constant portion of that setup.

## Anti-Evidence

`ContractCostParams` is small — typically a fixed-length vector of
`ContractCostParamEntry` values, on the order of a few hundred bytes per
field. XDR decoding such a payload is dominated by allocation overhead, not
parsing, and runs in roughly 1-3 µs per call on typical hardware. For
soroswap at 2000 tx/ledger × 2 cost-params decodes ≈ 4,000 decodes/ledger
× 2 µs ≈ 8 ms aggregate / 8 cluster workers ≈ 1 ms wall = ~0.5% of the
218 ms soroswap median. That is below the 1% Low floor and well below the
3% Medium floor.

Furthermore, caching the decoded params on the Rust side requires either
exposing a stable fingerprint of the CxxBuf bytes (which itself requires
hashing them) or relying on the C++ side to pass a `seq_no` token. Both
add bookkeeping cost that eats into the small saving.

Finally, the host's `Budget` construction touches many fields beyond just
the decoded cost params (per-call metering counters, deadline, instruction
limit) — those *do* legitimately need to be per-tx, so the cache only
removes the cost-params decode subset of `Budget` construction, not all of
`Host::with_storage_and_budget`.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Failed At**: hypothesis
**Novelty**: PASS — fail history covers TTL-key SHA256 caches (fails
`011-cache-ttl-key-hash-on-globalparapply-ro-entries.md`,
`004-stage-level-ttl-key-sha256-cache.md`), `addReads` cached encoded bytes
(fails `003`, `010`), and host-side input metadata caching (success
`002-cache-old-entry-xdr-sizes.md`), but no prior investigation specifically
targets per-`Host` `cpu_cost_params`/`mem_cost_params` XDR decode amortization
across txs in a ledger.

### Why It Failed

Below this objective's Medium severity threshold (3-10%) and below the Low
floor (1%). `ContractCostParams` payloads are a few hundred bytes each, with
decode time on the order of 1-3 µs. Aggregate cost ceiling for ~4,000
decodes/ledger is ~8 ms / 8-way cluster parallelism = ~1 ms wall ≈ 0.5% of
soroswap median apply time. Even taking a generous 3× upper bound puts the
optimization at ~1.5%, still under the objective's Medium threshold and only
marginally over the Low floor. The cache itself adds fingerprint/lookup
overhead that eats further into the small saving. The remaining cost in
`Host` construction (per-tx Budget counters, storage map setup, auth state)
is unavoidably per-tx.

### Lesson Learned

Per-ledger immutable XDR payloads that are small (low hundreds of bytes) and
cheap to decode (single-digit µs) cannot reach Medium even when decoded
thousands of times per ledger after dividing by configured cluster
parallelism. Future host-side decode-amortization hypotheses must quantify
(decode µs × calls/ledger) / parallelism before proposing a cache; payloads
under ~1 kB rarely clear the 3% floor. The C++ `getCachedLedgerInfo` cache
already covers the struct-level reuse; further Rust-side cost-params caching
adds bookkeeping for sub-1% return.
