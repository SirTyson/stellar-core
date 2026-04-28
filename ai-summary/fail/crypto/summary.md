# Failed Investigations: Crypto Subsystem

Condensed failure summaries for investigations targeting the crypto subsystem (signature verification, hashing, XDR serialization, and Soroban host storage key conversion paths). Last updated 2026-04-28.

## Summary Table

| File | Hypothesis | Why Failed | Stage | Key Lesson |
|------|-----------|------------|-------|------------|
| 001-cache-storage-key-conversions.md | Cache storage-key `Val`→`ScVal` conversions within a host invocation | Below threshold — removing all in-apply `Val`→`ScVal` time would save less than 1% of apply time | reviewer | Val/ScVal conversions are not a dominant hotspot; the conversion overhead is tiny relative to host-object visit and ordered-map costs |
| 001-reuse-encoded-contract-events.md | Reuse encoded contract events instead of XDR-encoding them twice | False path — the claimed duplicate serialization pass (`invocation_metering.rs`) is test/SDK-style machinery not on the production soroswap apply path | reviewer | Profile soroswap specifically; instrumentation code in non-production codepaths does not appear in apply-time traces |
| 001-stream-transaction-contents-hash.md | Stream transaction contents hash without allocating XDR opaque buffers | Not on the measured critical path — contents hashes are precomputed and cached during tx-set preparation, outside the `closeLedger` apply window | reviewer | Transaction hash computation happens before apply; savings in that phase do not affect apply-time metrics |
| 001-verify-sig-mostly-outside-applyledger.md | Optimize signature verification cache for soroswap apply | Out of scope — the apparent hotspot is mostly outside `applyLedger`; the objective excludes tx-set construction and validation work | hypothesis | Verify that profiled symbols fall within the `closeLedger` apply window; aggregate process-level hotspots often include pre-apply phases |
| 002-memoize-host-storage-map-lookups.md | Memoize repeated host storage map lookups within a soroswap invocation | Below threshold and wrong target — `Storage::try_get_full_helper` is an XDR ledger-key ordered-map, not the host-object-visit path emphasized by the hypothesis | reviewer | Distinguish host object visits from storage map lookups; the dominant cost in the soroban storage path is host-object budget charging, not the map probe itself |
| 002-single-pass-try-get-contract-data.md | Make `try_get_contract_data` use one storage lookup instead of has-then-get | Below threshold — the redundant `has_contract_data` half of successful calls is too small to reach the 3% Medium floor | reviewer | Double-probe micro-optimizations in Soroban host storage are real but sub-1%; the double-probe is also intentional for metering semantics in p26 |
| 002-specialize-soroban-subseed-hash.md | Specialize Soroban PRNG sub-seed hashing to avoid per-tx XDR allocation | Below threshold — removes a real but tiny allocation in `subSha256`; savings are sub-1% even in the optimistic scenario | reviewer | PRNG seeding overhead is negligible relative to Soroban host execution; micro-allocations in infrequent cryptographic paths cannot reach Medium severity |
| 003-cache-ttl-key-in-inmemory-value-entry.md | Cache TTL key hash in `InMemorySorobanState` `ValueEntry` to skip per-lookup SHA256 recomputation | Below threshold — total in-apply SHA256 time is ~4.17 ms per soroswap ledger out of 621 ms median (~0.67%) | hypothesis | SHA256 for TTL key derivation is a tiny fraction of apply time; caching it cannot reach the 3% Medium floor regardless of implementation quality |
| 004-precompute-footprint-ttl-keys.md | Precompute per-tx footprint TTL keys to deduplicate cross-phase `getTTLKey()` calls | Below threshold — the complete in-apply SHA256 budget for soroswap is ~0.67% of apply time; deduplication recovers only a fraction of that | hypothesis | Cross-phase TTL key recomputation is real but sub-1%; caching at the tx level is blocked by the same SHA256 budget ceiling as H003 |

## Meta-Patterns

1. **SHA256 / Hashing Budget Ceiling**: The entire in-apply SHA256 budget for soroswap is ~4 ms per ledger (~0.67% of apply). Any hypothesis that targets only SHA256 recomputation or TTL key derivation is structurally capped below the 1% Low floor, let alone the 3% Medium floor. Do not write SHA256-only hypotheses for this objective.

2. **Signature Verification Scope**: Signature verification and contents-hash computation happen during tx-set preparation, not during `closeLedger` apply. These are explicitly excluded from the optimize-soroswap objective scope. Profile traces must show the target zone as a descendant of `applyLedger` before writing a hypothesis.

3. **Host-Object Visit vs. Storage Map**: The dominant Soroban storage cost is `VisitObject` budget charging (host object table indexed by 32-bit handle), not the `MeteredOrdMap` binary search over XDR ledger keys. Hypotheses that target the map-probe side will under-estimate the true hotspot and fail the severity floor.

4. **Test/SDK Paths vs. Production Paths**: Some XDR serialization and event-size encoding paths exist only in test, SDK-style, or preflight instrumentation code. Confirm that the target code is reachable during production `closeLedger` before attributing apply time to it.
