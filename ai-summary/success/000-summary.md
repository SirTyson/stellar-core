# Success Summary

- 2026-04-28 — [004: Cache parallel-apply footprint LedgerKey hashes](soroban/004-parallel-apply-ledgerkey-hash-recompute.md) — Low; soroswap median apply time improved 2.66% on average across three optimized runs, with the best accepted run improving 3.96%.
- 2026-04-29 — [002: Specialize storage map lookup fast path](soroban-env/002-specialize-storage-map-lookup-fast-path.md) — Low; soroswap median apply time improved 2.17% on average across three optimized runs, with p95 and p99 also lower.
- 2026-04-29 — [001: Bulk-build host footprint and storage maps](transaction-ledger/001-bulk-build-host-storage-maps.md) — Low; soroswap median apply time improved 1.63% on average and SAC median improved 4.48% on average by replacing per-key `MeteredOrdMap::insert` with a single `from_map` per map in the enforcing invoke setup path.
