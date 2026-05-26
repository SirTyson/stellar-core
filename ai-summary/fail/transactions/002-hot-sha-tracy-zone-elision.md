# H002: Elide Hot SHA Tracy Zones in Apply Builds

**Date**: 2026-05-26
**Subsystem**: transactions / crypto
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction in the Tracy-enabled apply-load build by removing instrumentation overhead from extremely hot SHA helpers
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

All SHA-256 results used by transaction apply, bucket finalization, transaction result hashing, TTL-key derivation, and Soroban host helpers should remain byte-for-byte identical. Ledger output, transaction results, BucketList hashes, event hashes, and determinism must not change; only the profiling instrumentation around very small SHA helper calls should be reduced or moved to a coarser zone.

## Mechanism

The current apply-load baseline is built with `--enable-tracy`, and the crypto helpers wrap both one-shot and incremental SHA calls in per-call `ZoneScoped` regions. In the current soroswap trace, timestamp-filtered descendants of `applyLedger` contain 390,595 `sha256` events at `crypto/SHA.cpp:33` totaling 305,814,244 ns and 811,366 `SHA256::add` events at `crypto/SHA.cpp:65` totaling 96,361,072 ns from the C++ SHA implementation; together these are about 402 ms, or 9.1% of the 4.41 s traced `applyLedger` window before accounting for nested/parallel effects. Removing per-call Tracy zones from these leaf helpers, or gating them behind a higher-detail build flag while retaining coarser caller zones, should reduce apply time without touching consensus logic.

This is different from prior cached-getter Tracy-overhead failures: those zones were sub-1% after filtering. Here the timestamp-filtered SHA zones are apply descendants with hundreds of thousands of events in the current soroswap run, and they sit on paths used by parallel apply and synchronous finalization.

## Trigger

Build the current branch with the recorded baseline configuration (`--enable-tracy --enable-tracy-capture --enable-next-protocol-version-unsafe-for-production`) and run the soroswap apply-load matrix. The issue is triggered by the high volume of Soroban footprint, TTL, result-hash, and bucket/hash computations during `closeLedger`; each tiny SHA helper call opens its own Tracy zone.

## Target Code

- `src/crypto/SHA.cpp:29-38` — `sha256(ByteSlice const&)`; remove or feature-gate the per-call `ZoneScoped` around one-shot OpenSSL SHA-256.
- `src/crypto/SHA.cpp:62-71` — `SHA256::add(ByteSlice const&)`; remove or feature-gate the per-chunk `ZoneScoped` in the incremental hasher.
- `src/crypto/SHA.h:39-64` — `XDRSHA256` / `xdrSha256`; retain caller-level attribution where needed rather than instrumenting every `hashBytes` chunk through `SHA256::add`.
- `src/ledger/LedgerManagerImpl.cpp:1704` and `src/ledger/LedgerManagerImpl.cpp:3215-3265` — representative apply descendants that rely on SHA hashing and would keep their enclosing zones for attribution.

## Evidence

The current trace path is recorded in `ai-summary/CURRENT_STATE.md`. A timestamp-filtered unwrap against `applyLedger` measured:

- `sha256` at `crypto/SHA.cpp:33`: 390,595 calls, 332,770,684 ns total inside apply windows, with 305,814,244 ns from C++ `crypto/SHA.cpp`.
- `add` at `crypto/SHA.cpp:65`: 811,366 calls, 102,659,483 ns total inside apply windows, with 96,361,072 ns from C++ `crypto/SHA.cpp`.

The source confirms both helpers contain unconditional `ZoneScoped` instrumentation under the Tracy-enabled build. Since these functions are leaf wrappers around OpenSSL SHA calls and do not affect the bytes being hashed, eliding the zones is deterministic and low-risk.

## Anti-Evidence

Some of the reported self-time may be real SHA computation rather than Tracy overhead, and worker-thread SHA totals must be normalized by T=8 when projecting whole-ledger savings. This hypothesis is only valid if a PoC shows repeated non-Tracy apply-load improvement in the same Tracy-enabled build configuration; if the non-capture benchmark disables almost all `ZoneScoped` overhead, the improvement will fall below the Medium threshold. The change also reduces profiling granularity for SHA leaves, so caller-level zones must remain sufficient for future investigations.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated exactly; adjacent failures covered cached getter Tracy zones and TTL key-hash micro-opts, but not SHA leaf-zone elision
**Failed At**: reviewer

### Trace Summary

The SHA helpers are genuinely on `closeLedger` descendants: transaction/result hashing, per-Soroban sub-seeds, TTL-key derivation, bucket-list hashes, and bucket output hashing all route through `sha256`, `xdrSha256`, or `SHA256::add`. The proposed edit is deterministic because removing `ZoneScoped` does not change the bytes passed to OpenSSL. However, the evidence is from a diagnostic `--tracy` capture, while the objective's accepted apply-time metric is the non-`--tracy` apply-load runs. With `TRACY_ON_DEMAND`, non-capture `ZoneScoped` only checks connection state and returns, so the removable cost in the authoritative benchmark is not the 402 ms captured-zone total and is not plausibly Medium-tier.

### Code Paths Examined

- `src/crypto/SHA.cpp:29-38` — one-shot `sha256` has a `ZoneScoped` before the OpenSSL `::SHA256` call; removing it would not alter hash output.
- `src/crypto/SHA.cpp:62-71` — incremental `SHA256::add` has a `ZoneScoped` before the finished-state check and `SHA256_Update`; removing it would not alter hasher state transitions.
- `src/crypto/SHA.h:40-63` — `xdrSha256` streams XDR bytes through `XDRSHA256::hashBytes`, which calls `SHA256::add` for archive chunks.
- `src/ledger/LedgerManagerImpl.cpp:1462-1485,1678-1705,2448-2506,2673-3029` — `applyLedger` encloses fee processing, transaction apply, result-set hashing, and Soroban parallel apply; `applyThread` computes per-tx `subSha256`.
- `src/ledger/LedgerTypeUtils.cpp:30-37` — `getTTLKey` derives TTL key hashes with one-shot `sha256(xdr::xdr_to_opaque(e))`, and this is called from Soroban footprint and parallel-apply paths.
- `src/bucket/BucketOutputIterator.cpp:78-196` and `src/util/XDRStream.h:483-510` — synchronous bucket finalization writes XDR records and feeds the record bytes to `SHA256::add`.
- `src/bucket/BucketListBase.cpp:35-42,507-517` — BucketList hash composition uses incremental `SHA256::add` over level hashes.
- `configure.ac:486-500` and `lib/tracy/public/client/TracyScoped.hpp:24-39,98-106` — `--enable-tracy` defines `TRACY_ON_DEMAND`; a scoped zone is inactive unless `GetProfiler().IsConnected()`, and only connected zones enqueue begin/end events.
- `scripts/run_apply_load_matrix.py:236-242,498-557` and `ai-summary/CURRENT_STATE.md:56-67,87-136` — `--tracy` is an optional diagnostic capture mode; the recorded baseline explicitly treats the three non-`--tracy` runs as authoritative and ignores Tracy apply-time numbers for verdicts.

### Why It Failed

The hypothesis treats captured Tracy zone time as removable apply time, but this objective is gated by non-`--tracy` apply-load results. In those runs the binary is Tracy-enabled but on-demand zones are disconnected, so leaf zones do not emit begin/end events and the remaining branch/profiler-state check per SHA call is far below the 3% Medium threshold. The cited totals also include real SHA work and aggregate worker-thread time, neither of which is eliminated by deleting instrumentation.

### Lesson Learned

Use Tracy leaf-zone totals as attribution hints, not as direct savings projections. For this objective, every instrumentation-overhead hypothesis must be projected against the non-capture benchmark path and must account for `TRACY_ON_DEMAND`, nested zones, real work inside the measured function, and T=8 worker aggregation before claiming Medium impact.
