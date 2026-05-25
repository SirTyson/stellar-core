# H002: TxBundle Footprint Apply-Key Cache

**Date**: 2026-05-25
**Subsystem**: transactions
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by combining repeated footprint key classification, TTL-key derivation, and parallel-key wrapping across setup and worker phases
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Each Soroban transaction footprint is immutable once the `TxBundle` is built. The apply path should derive physical helper data for each footprint key once per transaction — soroban/classic classification, TTL companion key, pre-wrapped `ParallelApplyLedgerKey`, and small sizing/classification metadata — then reuse those derived values in global setup, thread-state setup, worker reads, TTL flushing, and commit bookkeeping. Protocol-visible budget metering and XDR size charges must remain exactly where they are today; only repeated C++ helper derivations should be cached.

## Mechanism

The current parallel apply path repeatedly walks the same `sorobanResources().footprint` vectors in many phases: global-state reserve estimation and modified-classic collection, read-only entry preloading, per-cluster thread-state construction, per-tx RO TTL flushing, worker `addReads`, storage-change extraction, and stage commit read/write set construction. Each pass redoes small but high-frequency work such as `isSorobanEntry`, `getTTLKey`, `ParallelApplyLedgerKey` construction/hash lookup, and sometimes `xdr::xdr_size(lk)`.

Previous investigations rejected individual sites because each was below threshold. The new mechanism is a single `TxBundle`-owned `SorobanApplyFootprintCache` shared by all these call sites so the savings are cumulative: build derived key arrays once from the immutable footprint, then pass spans of precomputed read-only/read-write entries and TTL companions through `ParallelApplyUtils` and `InvokeHostFunctionOpFrame` helpers. This preserves determinism because the cache is a pure function of transaction XDR and ledger-version-independent key type checks; it does not reorder txs, change write commits, or skip metered host serialization.

## Trigger

Run the accepted soroswap apply-load benchmark (`soroswap, TX=2000, T=8`). Soroswap transactions have small footprints, but the same keys are revisited across 2000 txs per ledger and across multiple serial plus worker phases. A PoC should add per-bundle footprint-derived-key storage, convert the repeated C++ loops to consume it, and show lower `soroban_setup_glbl`, `addReads`/`addFootprint`, `recordStorageChanges`, and `commitChangesFromThreads`-adjacent key-derivation time with a reproducible 3-10% median soroswap improvement.

## Target Code

- `src/transactions/ParallelApplyStage.h:19-114` — `TxEffects` / `TxBundle` currently hold meta, result, and tx pointer but no reusable footprint-derived data.
- `src/transactions/ParallelApplyUtils.cpp:386-428` — global state setup pre-reserves by walking every transaction footprint.
- `src/transactions/ParallelApplyUtils.cpp:600-719` — `collectModifiedClassicEntries` and `fetchSorobanReadOnlyEntries from footprints` repeat footprint classification, map lookup, TTL derivation, and entry loading logic.
- `src/transactions/ParallelApplyUtils.cpp:925-1001` — `collectClusterFootprintEntriesFromGlobal` repeats `ParallelApplyLedgerKey` construction and `getTTLKey` for every cluster footprint.
- `src/transactions/ParallelApplyUtils.cpp:1004-1035` — `flushRoTTLBumpsInTxWriteFootprint` derives TTL keys again before every tx apply.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:386-534` — `addReads` repeats key-size, TTL-key, live/archived, and entry-buffer setup for the same footprint keys already traversed during setup.
- `src/transactions/ParallelApplyUtils.cpp:907-922` — `commitChangesFromThreads` rebuilds the stage read/write key set from footprints before committing thread states.

## Evidence

The current soroswap Tracy trace shows the target work is inside `applyLedger`: timestamp filtering reports `addReads` at `transactions/InvokeHostFunctionOpFrame.cpp:388` with 358.822ms contained in `applyLedger`, `sha256` at `crypto/SHA.cpp:33` with 338.859ms contained, `getReadWriteKeysForStage` at `transactions/ParallelApplyUtils.cpp:107` with 56.198ms total, and `collectModifiedClassicEntries` / `fetchSorobanReadOnlyEntries from footprints` at `ParallelApplyUtils.cpp:604` / `656` with 21.253ms and 8.389ms total. The non-Tracy logs show the enclosing `soroban_setup_glbl` median alone is about 24ms per ledger, so a cross-phase cache that reduces both setup and worker-side repeated key derivation has enough combined surface to exceed the Medium threshold.

Structurally, the same immutable footprint vectors are visible at every target site, and most helper values are pure derived data. A `TxBundle`-local cache avoids global mutable state and avoids cross-ledger lifetime issues: it is constructed after tx ordering is fixed, destroyed with `applyStages`, and consumed only by deterministic apply code.

## Anti-Evidence

Many individual footprint micro-optimizations are documented as sub-threshold, including addReads `toCxxBuf`, TTL-key memoization, read/write-key scans, xdr-size skip, and fused TTL+entry lookup. This hypothesis is viable only as a combined refactor with instrumentation showing cumulative savings; a PoC that optimizes one loop will likely be rejected under existing meta-patterns. It must also preserve Soroban budget behavior: cached physical key metadata may not replace metered XDR serialization or any resource-charge input that contracts can observe.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — no exact standalone TxBundle footprint-cache verdict found, but the component costs overlap prior failed records
**Failed At**: reviewer

### Trace Summary

The repeated footprint walks are real: the parallel Soroban apply path derives TTL companion keys, Soroban/classic classification, `ParallelApplyLedgerKey` wrappers, and sometimes key sizes in global setup, per-cluster thread setup, worker `addReads`, storage-change handling, TTL-bump flushing, and thread-state commit. However, tracing the actual call path shows that the proposed cache can only remove small helper derivations around mandatory work: entry loading, scoped-map reads/writes, budget-visible serialization and metering, host execution, restored-entry handling, and deterministic thread/global commits all remain. The serial setup portions are already bounded below the objective's 3% floor, and worker-side `addReads`/`recordStorageChanges` helper savings must be divided by T=8 parallelism and further narrowed to the removable helper subset. Building and storing the cache on every `TxBundle` would add allocation/storage and lookup overhead on very small soroswap footprints, so the cumulative removable surface does not support a Medium-tier 3-10% apply-time reduction.

### Code Paths Examined

- `src/transactions/ParallelApplyStage.h:19-114` — `TxEffects` and `TxBundle` contain metadata/result state, tx pointer, tx number, and no footprint-derived cache today.
- `src/transactions/TransactionFrameBase.h:47-91` — `ParallelApplyLedgerKey` copies a `LedgerKey` and lazily caches its hash; the map/set wrappers already avoid recomputing a wrapped key's hash after first use, but new wrappers are still constructed at many sites.
- `src/transactions/ParallelApplyUtils.cpp:104-132` — `getReadWriteKeysForStage` scans every stage RW footprint, wraps each key, and adds TTL keys for Soroban entries before `commitChangesFromThreads`.
- `src/transactions/ParallelApplyUtils.cpp:386-428` — `GlobalParallelApplyLedgerState` constructor reserves map capacity from all footprint sizes and then enters pre-parallel setup.
- `src/transactions/ParallelApplyUtils.cpp:600-719` — `collectModifiedClassicEntries` and Soroban RO preloading walk read-write and read-only footprints, classify keys, derive TTL keys for RO Soroban entries, and load entries; the entry loads and global map updates remain mandatory.
- `src/transactions/ParallelApplyUtils.cpp:925-1001` — thread-state construction pre-reserves from cluster footprints and fetches keys plus TTL companions from global state into the thread map, repeating wrapping/classification but also doing required state transfer.
- `src/transactions/ParallelApplyUtils.cpp:1004-1039` — `flushRoTTLBumpsInTxWriteFootprint` derives TTL keys for RW Soroban entries before each tx to preserve correct ordering and fee accounting around deferred RO TTL bumps.
- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — each cluster worker calls `flushRoTTLBumpsInTxWriteFootprint`, then `TransactionFrame::parallelApply`, then commits successful tx changes and flushes remaining RO TTL bumps.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:386-554` — `addReads` computes key size, derives TTL keys, loads TTL and entry state, serializes entry/TTL buffers, validates contract entry sizes, meters disk reads for relevant protocols, and increments read metrics; only a small subset is cacheable without changing metering.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:640-766` — `recordStorageChanges` linearly scans tiny RW footprints and derives TTL keys only when matching TTL output or deleting missing RW Soroban entries; prior summary bounds this parent zone and `getTTLKey` subset below Medium.
- `src/transactions/ParallelApplyUtils.cpp:1164-1251` — successful tx commit builds an RO TTL set from the tx footprint, then merges each modified entry into the thread state; the modified-entry walk and scoped entry adoption are mandatory.
- `src/ledger/LedgerManagerImpl.cpp:2622-2670` — after all cluster workers finish, `commitChangesFromThreads` is a serial stage-boundary step; prior failure records bound the full stage RW-key scan plus commit window below the objective floor.
- `ai-summary/fail/transactions/summary.md:76-79` — prior records bound stage-boundary RW-key scanning, `addReads` xdr-size skip, TTL/entry lookup fusion, and cross-site `getTTLKey` memoization below Medium.
- `ai-summary/fail/transactions/summary.md:100,118,130,140` — prior meta-patterns bound global setup footprint collection, distributed XDR/footprint costs, `addReads` read-side re-encoding, and apply-phase per-tx/per-key micro-costs below the objective threshold.

### Why It Failed

This fails the optimize-soroswap Medium severity threshold. The proposed combined cache is broader than any one prior micro-optimization, but the traced removable work is still composed of small helper derivations around mandatory apply-path work. Existing failure records already bound cross-site `getTTLKey` memoization at about 0.6% of apply time, global modified-classic/RO collection at about 0.67%, `xdr_size` skipping in `addReads` at ~0.003%, TTL/entry probe fusion at ~0.09%, and the full stage RW-key scan plus thread commit window at about 2.16% before narrowing to only key-derivation savings. Worker-side portions such as `addReads` and `recordStorageChanges` are aggregate parallel-lane time and must be divided by the T=8 cluster count, while serial portions include entry loads, map mutations, rescoping, and deterministic commit work that a footprint cache cannot remove. The realistic cumulative savings remain Low or sub-noise, not the required reproducible 3-10% soroswap apply-time reduction.

### Lesson Learned

Per-transaction footprint helper caches are attractive because the same immutable vectors appear at many layers, but small-footprint soroswap lanes make per-key derivations too cheap relative to mandatory host execution, ledger-state movement, and commit bookkeeping. Future combined-cache hypotheses need direct measurements showing the cacheable subset itself clears the Medium floor after T=8 critical-path normalization, not just a list of many individually sub-threshold loops.
