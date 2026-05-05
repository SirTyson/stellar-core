# H001: Use a post-fee classic overlay to keep Soroban pre-apply read-only validation parallel

**Date**: 2026-05-05
**Subsystem**: ledger / Soroban parallel apply setup
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by removing the serial p26 pre-apply fallback caused by fee-processing mutations
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

After `processFeesSeqNums` charges fees and before Soroban worker execution begins, Core should validate each Soroban transaction against the deterministic post-fee ledger view, update the same sequence/pre-auth-signer metadata, preserve transaction result ordering, and commit all pre-apply writes in transaction order. Transactions whose only classic-state divergence from the LCL is the already-deterministic fee/sequence state should still be able to run the read-only portion of `preParallelApply` in parallel; they should not be forced through the fully sequential `preParallelApply` path solely because their source or fee-source account was modified by fee processing.

## Mechanism

`GlobalParallelApplyLedgerState::preParallelApplyAndCollectModifiedClassicEntries` uses `requiresSequentialPreParallelApply` to compare the current `LedgerTxn` view with the LCL snapshot for the source account, fee source, op sources, and classic footprint keys. In the soroswap benchmark, `processFeesSeqNums` runs immediately before `applyTransactions` and charges every transaction's source/fee account, so the source/fee account comparison is expected to report "modified" and the code falls back to `txBundle.getTx()->preParallelApply(...)` sequentially for each transaction instead of sending the read-only validation work through `readOnlyPreParallelApply`.

The proposed optimization is to build an immutable post-fee classic overlay, or an equivalent `LedgerSnapshot` adapter, from the fee-processing `LedgerTxn` changes and any classic footprint entries that can affect validation. `preParallelApplyReadOnly` would run in parallel over that snapshot, while `preParallelApplyWrite` would still apply sequence/pre-auth-signer writes to the real `LedgerTxn` in deterministic tx order. This avoids changing ledger effects or exceeding `NUM_CLUSTERS`; it changes only how the read-only validation/account-view work is supplied to workers.

## Trigger

Run the current apply-load workload `soroswap, TX=2000, T=8` from `scripts/run_apply_load_matrix.py`. Each swap uses a unique source account, and `processFeesSeqNums` charges fees before `applyParallelPhase`; therefore the p26 setup path sees the post-fee source/fee account as different from the LCL source/fee account and serializes pre-apply setup for the Soroban phase.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:1678-1688` - `processFeesSeqNums` runs before `applyTransactions`, so the later parallel-apply setup observes already-mutated source/fee accounts.
- `src/ledger/LedgerManagerImpl.cpp:2303-2430` - fee processing mutates the parent `LedgerTxn` directly when metadata is disabled, which is the apply-load configuration.
- `src/transactions/ParallelApplyUtils.cpp:170-208` - `requiresSequentialPreParallelApply` treats any current-vs-LCL source, fee-source, op-source, or classic-footprint difference as a reason to avoid read-only parallel pre-apply.
- `src/transactions/ParallelApplyUtils.cpp:386-466` - `GlobalParallelApplyLedgerState` constructs the setup state and routes p26 transactions either to sequential `preParallelApply` or the parallel read-only + ordered-write split.
- `src/transactions/ParallelApplyUtils.cpp:525-598` - existing split read-only and write phases that could be reused if supplied with a deterministic post-fee read snapshot.
- `src/transactions/TransactionFrame.cpp:2145-2198` - `commonParallelPreApplyReadOnly` performs validation/signature work and records `ParallelPreApplyInfo` without mutating the real `LedgerTxn`.
- `src/transactions/TransactionFrame.cpp:2315-2370` - `preParallelApplyWrite` applies the buffered sequence/pre-auth-signer writes in the real ledger transaction.
- `src/simulation/ApplyLoad.cpp:3381-3505` - soroswap generates unique-account swap transactions with classic trustline RW keys and SAC/pair Soroban keys.

## Evidence

The current diagnostic soroswap trace is `/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`. `csvexport-release` reports the in-scope envelope as `applyLedger` total 5,230,315,999 ns at `ledger/LedgerManagerImpl.cpp:1484`, with `applyParallelPhase` total 3,842,725,964 ns at `ledger/LedgerManagerImpl.cpp:2973` and `applySorobanStages` total 3,835,000,197 ns at `ledger/LedgerManagerImpl.cpp:2678`, all reached from the measured apply path.

The same run's apply-load phase table reports `soroban_setup_glbl` median 24.08 ms and mean 24.28 ms inside `parallel_total`, while soroswap non-Tracy medians in `ai-summary/CURRENT_STATE.md` are roughly 270-276 ms. This setup phase is therefore about 8-9% of the soroswap close time. The source-level mechanism explains the cost: p26 supports a parallel read-only pre-apply path, but the current-vs-LCL source/fee account check is expected to fail after fee charging, so the benchmark takes the serial fallback for the whole Soroban phase.

## Anti-Evidence

The optimization must not parallelize writes to `LedgerTxn`; prior fee-processing parallelism failed because `LedgerTxn` permits only one active child. A post-fee overlay must faithfully expose the same source account balances, sequence numbers, signer changes, classic trustlines, and missing-entry behavior that sequential `preParallelApply` would see, including fee-bump and pre-auth-signer edge cases. Some setup work, especially ordered `preParallelApplyWrite` and collection of modified classic entries, is inherently serial, so the PoC must show that enough of the 24 ms setup phase moves to parallel read-only validation to clear the Medium threshold.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-05-05
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated

### Trace Summary

The close path calls `processFeesSeqNums` before `applyTransactions`, and fee processing mutates the source/fee account balances in the active `LedgerTxn`. The Soroban parallel phase then constructs `GlobalParallelApplyLedgerState`, whose p26 setup compares that post-fee `LedgerTxn` view against the LCL snapshot; because soroswap transactions use their source account as the fee source and pay positive fees, `requiresSequentialPreParallelApply` returns true before any transaction can enter `readOnlyPreParallelApply`. The existing split read-only/write implementation is real and already preserves ordered writes, so the missing piece is a read snapshot that exposes deterministic post-fee classic account state without treating the fee mutation itself as a dependency requiring sequential pre-apply.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:1655-1688` — `applyLedger` prefetches source accounts, calls `processFeesSeqNums`, then calls `applyTransactions` with the same mutated `LedgerTxn`.
- `src/ledger/LedgerManagerImpl.cpp:2303-2430` — `processFeesSeqNums` iterates all transactions and calls `processFeeSeqNum`; when meta is disabled it processes directly on the child `LedgerTxn` and commits all fee changes into the parent visible to apply.
- `src/transactions/TransactionFrame.cpp:1777-1817` — normal transaction fee processing deducts the charged fee from the source account balance and updates the fee pool; for protocol >=10 it leaves the sequence update for pre-apply.
- `src/transactions/FeeBumpTransactionFrame.cpp:764-795` — fee-bump fee processing analogously deducts the fee from the outer fee source account, so fee-source divergence is also real for fee-bump Soroban transactions.
- `src/ledger/LedgerManagerImpl.cpp:2840-3030` — `applyTransactions` builds parallel Soroban bundles, then `applyParallelPhase` calls `applySorobanStages` on the already-mutated `LedgerTxn`.
- `src/ledger/LedgerManagerImpl.cpp:2672-2710` — `applySorobanStages` constructs `GlobalParallelApplyLedgerState` before any worker execution, making `sorobanSetupGlobalMs` the relevant synchronous setup phase.
- `src/transactions/ParallelApplyUtils.cpp:151-208` — `isModifiedClassicKey` compares current and previous entries byte-for-byte for non-Soroban keys, and `requiresSequentialPreParallelApply` checks source, fee source, operation sources, and classic footprint keys.
- `src/transactions/ParallelApplyUtils.cpp:386-466` — p26 setup sends modified transactions through sequential `preParallelApply`; only unmodified transactions are batched into `readOnlyPreParallelApply` and followed by ordered `commitBufferedPreParallelApplyWrites`.
- `src/transactions/ParallelApplyUtils.cpp:525-598` — `readOnlyPreParallelApply` parallelizes over worker threads, while `commitBufferedPreParallelApplyWrites` applies `preParallelApplyWrite` back to the real `LedgerTxn` in transaction order.
- `src/transactions/TransactionFrame.cpp:2145-2198` — `commonParallelPreApplyReadOnly` runs validation/signature work against a `LedgerSnapshot` and records `ParallelPreApplyInfo` without mutating the real ledger transaction.
- `src/transactions/TransactionFrame.cpp:2315-2370` — `preParallelApplyWrite` performs sequence-number and one-time-signer writes in a nested `LedgerTxn`, pushes metadata, commits, and updates metrics after the read-only phase.
- `src/simulation/ApplyLoad.cpp:3381-3515` — soroswap swap generation uses one unique account per transaction, invokes a Soroban swap, includes two classic trustline read-write keys, and validates the generated transactions before apply.

### Findings

The inefficiency exists. For ordinary soroswap transactions, `TransactionFrame::getFeeSourceID()` returns the source account, `processFeeSeqNum` deducts a positive fee from that account, and `requiresSequentialPreParallelApply` immediately compares `current.load(accountKey(source))` from the post-fee `LedgerTxn` to `previous.load(accountKey(source))` from the LCL snapshot. That comparison must differ in balance for successful fee charging, so the transaction is routed to the sequential `preParallelApply` branch even though the fee mutation is already deterministic and already ordered before Soroban execution.

The path is hot for this objective. `GlobalParallelApplyLedgerState` construction sits inside `applySorobanStages` and is measured by `sorobanSetupGlobalMs`; the hypothesis's cited phase timing of roughly 24 ms is consistent with a per-ledger, per-Soroban-transaction setup path for the `soroswap, TX=2000, T=8` benchmark. Because `readOnlyPreParallelApply` can divide the read-only validation/signature/op-validity work across `LEDGER_CLOSE_WORKER_THREADS`, moving a substantial fraction of that setup out of the sequential fallback plausibly clears the 3% Medium threshold if the serial ordered-write and classic-entry collection portions remain modest.

The proposed direction is correctness-compatible but needs a guarded implementation. The overlay must not blindly parallelize all source-account divergence: transactions sharing a source account, transactions depending on prior pre-auth signer removal, or transactions whose operation sources/classic footprint entries were modified by earlier classic/Soroban pre-apply writes still need either the sequential path or a per-transaction overlay that exactly models prior deterministic writes. For the soroswap benchmark, the generated swap path uses unique source accounts, so a conservative implementation that only parallelizes transactions whose source/fee/op-source accounts have no earlier same-ledger pre-apply dependency and whose non-fee classic footprint changes are already represented in the overlay is viable.

Existing optimizations do not cover this. The p26 split path exists, but it currently feeds `readOnlyPreParallelApply` from `mLCLSnapshot`; the gating comparison is deliberately conservative and treats fee-processing account changes the same as arbitrary classic state changes. There is no current post-fee snapshot adapter or account overlay in the traced code path.

### PoC Guidance

- **Target code**: `src/transactions/ParallelApplyUtils.cpp` in `GlobalParallelApplyLedgerState::preParallelApplyAndCollectModifiedClassicEntries`, `requiresSequentialPreParallelApply`, and `readOnlyPreParallelApplyRange`; likely add a small read-only `LedgerSnapshot`/`AbstractLedgerStateSnapshot` adapter in `src/ledger/LedgerStateSnapshot.{h,cpp}` or an equivalent narrowly-scoped helper that overlays selected post-fee classic entries on top of `mLCLSnapshot`.
- **Change description**: collect the post-fee classic entries needed for read-only validation (at minimum source account, fee source account, operation source accounts, and relevant classic footprint entries) from the current `LedgerTxn`, and allow p26 transactions to use the parallel read-only path when the only current-vs-LCL divergence is deterministic fee-processing state that the overlay supplies. Keep `preParallelApplyWrite` ordered on the real `LedgerTxn`; do not parallelize `LedgerTxn` writes.
- **Correctness check**: preserve sequential fallback for same-source transaction sequences, fee-bump Soroban transactions until both outer fee-source and inner source semantics are covered, pre-auth signer removal dependencies, missing account/footprint behavior, and classic footprint keys changed by earlier phases. Existing coverage to run in PoC includes Soroban invoke-host-function tests around pre-auth signer removal and fee-bump handling, plus apply-load soroswap.
- **Benchmark focus**: measure `scripts/run_apply_load_matrix.py` for `soroswap, TX=2000, T=8` over multiple runs, with attention to top-line apply median and `soroban_setup_glbl`. A successful PoC should reduce `soroban_setup_glbl` by a large fraction and translate to a reproducible 3-10% apply-time reduction; if the setup drop is absorbed by ordered writes or overlay construction, the finding should be rejected at PoC.

---

## PoC Attempt

**Result**: POC_PASS
**Date**: 2026-05-05
**PoC by**: gpt-5.5, high

### Changes Made

- `src/ledger/LedgerStateSnapshot.h:10-14,250-254` and `src/ledger/LedgerStateSnapshot.cpp:274-279`: added a constructor that lets callers wrap a custom `AbstractLedgerStateSnapshot` in a `LedgerSnapshot`.
- `src/transactions/ParallelApplyUtils.h:21-26,232-236`: added shared post-fee overlay map types and threaded the overlay through read-only pre-apply.
- `src/transactions/ParallelApplyUtils.cpp:30-224`: added a read-only post-fee overlay snapshot plus conservative dependency collection for source, fee-source, op-source, and classic footprint keys.
- `src/transactions/ParallelApplyUtils.cpp:329-361,650-681,743-780`: routed eligible protocol-26 Soroban transactions through parallel read-only pre-apply against the post-fee overlay while preserving sequential fallback for fee-bump and repeated-dependency cases, then kept ordered `preParallelApplyWrite` on the real `LedgerTxn`.

### Demonstration

The change supplies read-only protocol-26 pre-apply with a deterministic post-fee classic ledger view, so source and fee-source account balance changes from fee processing no longer force unique-account Soroban transactions down the fully sequential pre-apply path. Writes that update sequence numbers and one-time signers still commit to the real `LedgerTxn` in transaction order, while fee-bump transactions and transactions sharing source/op/classic dependency keys retain the original sequential fallback.

### Test Results

`./autogen.sh && ./configure --enable-ccache --enable-sdfprefs --enable-tracy --enable-tracy-capture --disable-postgres && make -j $(nproc)` completed successfully. `set -o pipefail; env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' make check 2>&1 | tail -200` completed successfully; the captured tail includes `PASS: test/selftest-nopg`, `PASS: test/check-nondet`, and Rust test summaries with zero failures.

---

## Final Review — Needs Revision

**Date**: 2026-05-05
**Final review by**: gpt-5.5, high

### What Needs Fixing

Final review cannot benchmark or confirm this PoC because the handoff is not reproducible from committed state. The outer branch `poc/001-post-fee-overlay-parallel-preapply` is at commit `bd1487c0c` (`viable review 001-post-fee-overlay-parallel-preapply`), but the production source changes described in the PoC are still uncommitted working-tree modifications:

- `src/ledger/LedgerStateSnapshot.cpp`
- `src/ledger/LedgerStateSnapshot.h`
- `src/transactions/ParallelApplyUtils.cpp`
- `src/transactions/ParallelApplyUtils.h`

The p26 submodule is clean at `fa1226b3068605c5376efe56c6cf809ca225a036`, so the blocker is the dirty outer source state. Under the optimize-soroswap final-review handoff rules, final review must refuse a PoC whose source changes are left as uncommitted working-tree state; otherwise fresh worktrees and future benchmark runs would not inherit the exact implementation being measured.

### Revision Instructions

Commit the four outer source-file changes to the PoC branch `poc/001-post-fee-overlay-parallel-preapply`, push that branch, and leave both the outer repository and `src/rust/soroban/p26` submodule clean. The revised PoC notes should also record the committed outer SHA that contains the optimization. After that, final review can check out the committed PoC, run the full unit suite, and run the required three non-Tracy `scripts/run_apply_load_matrix.py` measurements against reproducible code.

### Checks Passed So Far

- The hypothesis and PoC notes identify an in-scope close-ledger optimization path: protocol-26 Soroban pre-apply setup after fee processing.
- The p26 submodule handoff is clean and points at an existing accepted baseline SHA.
- The source diff shape matches the PoC description at a high level, but it was not eligible for deeper correctness review or benchmarking because it was not committed.

---

## PoC Attempt (Revision)

**Result**: POC_PASS
**Date**: 2026-05-05
**PoC by**: claude-opus-4.7, high

### Revision Summary

Final review on the prior PoC attempt flagged that the four production
source-file changes were left as uncommitted working-tree state on the
PoC branch. This revision commits those exact changes to the PoC branch
so that fresh worktrees and benchmark runs reproduce the implementation.

No source modifications were introduced beyond what was already in the
working tree from the prior attempt; the diff is identical to what the
prior PoC notes describe.

### Committed State

- Outer branch `poc/001-post-fee-overlay-parallel-preapply` on
  `github.com/SirTyson/stellar-core` now contains the optimization at
  commit `675e5a4f1ad897d3e30bacd27556c7be653740e4`
  ("viable poc 001-post-fee-overlay-parallel-preapply").
- Submodule `src/rust/soroban/p26` is unchanged and clean at
  `fa1226b3068605c5376efe56c6cf809ca225a036` (the accepted baseline).
- Outer worktree and submodule are both clean (modulo the
  `ai-summary` symlink which points outside the repo and is not
  tracked by stellar-core).

### Files Changed in the PoC Commit

- `src/ledger/LedgerStateSnapshot.cpp`
- `src/ledger/LedgerStateSnapshot.h`
- `src/transactions/ParallelApplyUtils.cpp`
- `src/transactions/ParallelApplyUtils.h`

Total diff: 4 files changed, 249 insertions(+), 14 deletions(-).

### Test Results

- Build: `make -j $(nproc)` succeeded against the Tracy-enabled
  configure flags (`--enable-ccache --enable-sdfprefs --enable-tracy
  --enable-tracy-capture --disable-postgres`); incremental build was a
  no-op (binary already up to date for the committed source).
- Unit tests: `env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll
  fatal -r simple --abort --disable-dots' make check` ran to
  completion. Tail shows `PASS: test/selftest-nopg`,
  `PASS: test/check-nondet`, "All 2 tests passed", and Rust test
  summaries with zero failures (e.g. soroban-env-host: 751 passed;
  0 failed).
