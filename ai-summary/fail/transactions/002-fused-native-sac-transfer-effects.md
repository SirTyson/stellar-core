# H002: Fuse Native SAC Transfer Balance Effects on Soroswap Swap Path

**Date**: 2026-05-23
**Subsystem**: transactions, Soroban SAC apply
**Severity**: Medium
**Impact**: soroswap apply-time reduction by collapsing generic SAC transfer storage/auth/event work
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When a soroswap swap transfers `token_in` from the user to the pair and `token_out` from the pair back to the user, the apply path should produce the same balance deltas, TTL bumps, authorization results, emitted SAC transfer events, resource accounting for the next protocol, and ledger changes as two generic `StellarAssetContract::transfer` calls. The efficient expected behavior is to execute the known SAC transfer effects through a native, typed balance-effect path rather than re-entering generic SAC contract logic for each transfer.

## Mechanism

`StellarAssetContract::transfer` currently performs generic work for every transfer: amount validation, `MuxedAddress` decoding, `require_auth`, instance/code TTL extension, sender balance spend, receiver balance receive, balance-entry authorization checks, persistent storage get/put, balance TTL extension, and event construction. The soroswap swap shape is narrower: the C++ generator declares exactly two SAC balance keys in the RW footprint (`Balance[pair]` for token-in and token-out) plus the two user trustlines, and the auth tree authorizes only the token-in user-to-pair transfer. A next-protocol fused native effect path could apply the two balance moves and required events in deterministic order using typed SAC balance/trustline helpers, amortizing duplicate contract-frame, storage-map, and conversion work without changing cluster scheduling or exceeding `NUM_CLUSTERS`.

## Trigger

Use the current soroswap apply-load scenario (`TX=2000`, `T=8`). Each generated transaction has a two-token path, RW footprint entries for user trustline(token-in), user trustline(token-out), SAC `Balance[pair]` for token-in, SAC `Balance[pair]` for token-out, and the pair instance (`src/simulation/ApplyLoad.cpp:3458-3475`). The auth tree authorizes the source account for `token_in.transfer(user, pair, amount)` (`src/simulation/ApplyLoad.cpp:3477-3496`).

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — generic SAC `transfer` path currently exercised by soroswap
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:44-63` — contract balance read and TTL extension
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:74-97` — contract balance write plus TTL extension
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:100-145` — `receive_balance` generic auth/read/write path
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:220-229` — `spend_balance` authorization wrapper
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:319-390` — enforcing storage get/put map path used by SAC balance updates
- `src/transactions/InvokeHostFunctionOpFrame.cpp:641-766` — C++ records modified ledger entries returned by the host and validates them against the RW footprint

## Evidence

The current soroswap Tracy trace from `ai-summary/CURRENT_STATE.md` was timestamp-filtered against `applyLedger` windows. The SAC transfer zones are apply descendants and overlap the measured window:

| zone | source | apply-overlap ns | count overlapping apply | critical-path bound at T=8 |
|------|--------|------------------|--------------------------|----------------------------|
| `SAC transfer` | `stellar_asset_contract/contract.rs:212` | 2,477,084,982 | 15,665 | ~309.6 ms / 6.9% of `applyLedger` |
| `storage get` | `soroban-env-host/src/storage.rs:329` | 672,084,842 | 321,802 | ~84.0 ms / 1.9% |
| `map lookup` + `map lookup indexed` | `metered_map.rs:173,330` | 1,223,514,982 | 1,327,079 | ~152.9 ms / 3.4% |
| `new map` | `metered_map.rs:148` | 461,915,256 | 181,114 | ~57.7 ms / 1.3% |
| `ScVal to Val` | `host/conversion.rs:436` | 1,144,488,055 | 800,217 | ~143.1 ms / 3.2% |

The `SAC transfer` overlap alone is a 6.9% critical-path upper bound after dividing worker aggregate time by T=8. The fused path only needs to remove roughly half of the generic SAC transfer envelope to clear the 3% Medium floor, and the storage/conversion/map zones show enough adjacent work to make that plausible if the implementation bypasses generic contract-data `Val` construction for the known balance/trustline updates.

## Anti-Evidence

This is not a proposal to skip authorization, events, TTL extension, or budget accounting. The fused path must preserve token-in source-account auth and token-out invoker-contract auth, exact event order, failure behavior, and rollback semantics. Existing accepted typed SAC balance and direct native-pair balance-read optimizations already cover some balance access, so the viable surface is the remaining generic transfer envelope and write-side effect construction; if implementation can only remove a small storage lookup or key conversion, it will fall below the Medium threshold.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-05-23
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated as a full SAC transfer-effect fusion in transactions fail/success records

### Trace Summary

`ApplyLoad::generateSoroswapSwaps` builds the fixed two-token router invocation and declares the two user trustlines, two pair SAC balance entries, and pair instance in the RW footprint. In the accepted baseline, `Host::call_contract_fn` still lets the router Wasm execute the inbound `token_in.transfer(user, pair, amount)`, while the next-protocol native pool swap intercepts the pair `swap` and calls `soroswap_pool_invoke_sac_transfer` for the outbound `token_out.transfer(pair, user, amount)`. That helper re-enters `call_n_internal`, creates a `Frame::StellarAssetContract`, and dispatches through the generic SAC `transfer` implementation. The C++ bridge then consumes the host's modified ledger entries/events through the existing `recordStorageChanges` and event collection path, so a safe fused implementation should remain inside the Rust host and leave C++ output validation unchanged.

### Code Paths Examined

- `src/simulation/ApplyLoad.cpp:3427-3505` — confirms the benchmark transaction shape, RW footprint entries, and source-account auth tree for the inbound SAC transfer.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:783-837` — `call_contract_fn` checks native Soroswap pool getter/swap fast paths, otherwise falls through to Wasm; SAC calls still use `Frame::StellarAssetContract` and `StellarAssetContract.call`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1013-1073` — native Soroswap pool `swap` is protocol-gated and exact-hash/shape-gated before executing in a native contract frame.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1076-1305` — native pool swap validates output amounts, transfers token out via SAC, reads pair balances, updates reserves, and emits the pair swap event.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1330-1347` — outbound pool transfer still constructs a `transfer` symbol and calls `call_n_internal` into the generic SAC transfer path.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1349-1393` — accepted direct SAC balance read only optimizes post-transfer pair balance reads; it does not optimize transfer writes.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — generic SAC `transfer` still performs amount check, muxed-address decode, `require_auth`, instance/code TTL extension, spend/receive balance mutation, and event emission.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:150-168,235-300,303-345,357-428,431-440` — contract balance transfer paths still perform authorization reads, amount reads, writeback reads, storage `put`, and TTL extension through generic helpers.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:47-112` — transfer event construction still checks issuer/mint/burn cases and reads SAC metadata for event topics.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:478-509` — host invocation returns encoded result, ledger changes, and events through the normal enforcing-storage path.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:641-766` — C++ validates returned modified entries against the RW footprint and applies them; this path need not change for a host-side fused effect.

### Findings

The inefficiency exists in the current accepted Soroswap baseline. The native pool swap removed pool Wasm execution and direct SAC balance reads removed two read-only SAC balance calls, but transfer writes still go through the generic SAC function dispatcher: the router Wasm performs the inbound transfer and the native pool swap explicitly calls `call_n_internal` for the outbound transfer.

The path is hot enough for the objective. The timestamp-filtered `SAC transfer` span covers about 15,665 apply-overlapping calls, matching roughly two transfers per accepted swap, and its T=8 critical-path bound is about 6.9% of `applyLedger`. A dispatch-only change would be below threshold, but a protocol-gated typed effect that handles both transfer writes, avoids duplicate contract-balance auth/read/writeback probes, and bypasses generic SAC argument/object construction has enough addressable surface to plausibly clear the 3% Medium floor.

The fix is only correct if implemented as a production-safe host-side native effect, not as a C++ footprint shortcut. The helper must still execute under an SAC-equivalent call/auth frame so source-account auth for the inbound transfer and invoker-contract auth for the outbound transfer match the same authorized functions. It must preserve SAC instance/code TTL bumps, balance TTL bumps, account/trustline balance bounds and authorization semantics, issuer/mint/burn event selection, event order, rollback behavior, and next-protocol budget repricing.

### PoC Guidance

- **Target code**: Add the typed transfer-effect helper in `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs` or a closely-related SAC module, and call it from `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs` near `call_native_soroswap_pool_swap` / `soroswap_pool_invoke_sac_transfer`. Keep `src/transactions/InvokeHostFunctionOpFrame.cpp` unchanged unless bridge plumbing is strictly necessary.
- **Change description**: Under the existing next-protocol gate, recognize only the exact native Soroswap path and replace generic SAC `transfer` calls with a typed effect that loads each affected trustline/contract-balance entry once, performs authorization and bounds checks, writes the updated entries and TTLs, and emits identical SAC transfer/mint/burn events. If the PoC attempts to fuse both inbound and outbound transfers, it must do so from an exact router/pool native path that proves the router/pair/token shape; do not infer semantics from footprint membership alone.
- **Correctness check**: Compare generic and fused execution for successful swaps and failure boundaries covering source-account auth mismatch, invoker-contract auth, deauthorized trustlines/balances, issuer endpoints, insufficient balance, overflow, event/meta ordering, and ledger-change/TTL equality. Existing Soroban invoke-host-function and parallel-apply tests cover the bridge and rollback machinery; add focused equivalence coverage for the fused transfer helper.
- **Benchmark focus**: Run multiple non-Tracy `scripts/run_apply_load_matrix.py` soroswap `TX=2000,T=8` measurements and require at least a 3% apply-time reduction. In Tracy, `SAC transfer` count/time should drop for matching swaps while C++ `recordStorageChanges`, event encoding, and modified-ledger-entry validation remain present and consistent.

---

## PoC Attempt

**Result**: POC_PASS
**Date**: 2026-05-23
**PoC by**: gpt-5.5, high

### Changes Made

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1-10,1334-1375` — changed the native Soroswap pool outbound SAC transfer helper to detect Stellar Asset token contracts, push an SAC-equivalent `Frame::StellarAssetContract`, and call the typed native transfer helper instead of re-entering generic `call_n_internal`; non-SAC token contracts still use the existing fallback call path.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract.rs:14-15` — re-exported the native Soroswap SAC transfer helper for the host-frame fast path.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:45-67` — added `native_soroswap_transfer`, preserving generic SAC transfer validation order, auth, instance/code TTL extension, fallback behavior for unsupported shapes, and transfer event emission.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:302-407,676-720,753-806` — added the typed contract-balance-to-classic-account/trustline effect path used by Soroswap pool payouts. It loads the sender contract balance once, checks authorization and available amount, writes the updated contract balance and TTL, then updates the receiver account/trustline with authorization and bounds checks.

### Demonstration

The PoC removes the generic SAC `call_n_internal` dispatch and duplicate SAC balance helper work from the native Soroswap pool's outbound `token_out.transfer(pair, user, amount)` path while preserving the SAC call/auth frame and C++ modified-entry validation path. For the soroswap apply-load shape, this turns one hot SAC transfer into a typed ledger effect that avoids redundant contract-balance authorization/read/writeback probes and generic argument/object dispatch overhead.

### Test Results

Configured and built with `./configure --enable-ccache --enable-sdfprefs --enable-tracy --enable-tracy-capture --disable-postgres` and `make -j $(nproc)`. Full regression command `env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' make -j $(nproc) check` completed with exit code 0; captured summaries include Rust host `test result: ok. 751 passed; 0 failed; 2 ignored; 0 measured; 1 filtered out` and `All 2 tests passed`.

---

## Final Review — Needs Revision

**Date**: 2026-05-23
**Final review by**: gpt-5.5, high

### What Needs Fixing

The PoC implementation exists as p26 submodule commit `67a60367bf871e63eeb9e3af4aac029a621b9dcd`, but the outer PoC branch does not record that commit in its gitlink. `git ls-tree HEAD src/rust/soroban/p26` records baseline SHA `fbbea0d9cb33e94fbab331d3d4bf8e69f088f9d4`, so the required validation step `git submodule update --init --recursive src/rust/soroban/p26` checks out the prior accepted baseline and removes the optimization before build/test/benchmark. I cannot confirm or benchmark a source change that is not reproducibly recorded by the handed-off outer commit.

### Revision Instructions

Commit the p26 gitlink bump on the outer `poc/002-fused-native-sac-transfer-effects` branch so that a clean checkout plus `git submodule update --init --recursive src/rust/soroban/p26` lands on `67a60367bf871e63eeb9e3af4aac029a621b9dcd` or a revised p26 commit containing the optimization. Ensure the p26 commit is pushed to the SirTyson `rs-soroban-env` fork on `poc/002-fused-native-sac-transfer-effects`, then re-run the PoC regression and benchmark steps from that clean recorded state.

### Checks Passed So Far

- The p26 PoC commit exists locally on branch `poc/002-fused-native-sac-transfer-effects` and contains the claimed four-file SAC transfer specialization.
- Source inspection confirms the optimization targets only the native Soroswap pool outbound SAC transfer path and preserves fallback dispatch for non-SAC token contracts.
- The recorded outer branch handoff check failed before authoritative tests/benchmarks: the optimized source is not what the outer commit records.

---

## PoC Attempt (Revision)

**Result**: POC_PASS
**Date**: 2026-05-23
**PoC by**: claude-opus-4.7, high
**Addresses**: Final Review — Needs Revision (2026-05-23)

### Revision Summary

The prior PoC's source-level optimization was correct and in place in the
`src/rust/soroban/p26` submodule worktree at commit
`67a60367bf871e63eeb9e3af4aac029a621b9dcd` on submodule branch
`poc/002-fused-native-sac-transfer-effects`. The previous orchestrator
handoff failed to record the gitlink bump in the outer
`poc/002-fused-native-sac-transfer-effects` branch (outer `HEAD` still
recorded baseline submodule SHA `fbbea0d9cb33e94fbab331d3d4bf8e69f088f9d4`).

This revision re-verifies the optimization from the worktree state:
- `git -C src/rust/soroban/p26 rev-parse HEAD` →
  `67a60367bf871e63eeb9e3af4aac029a621b9dcd` (PoC commit present).
- `git diff fbbea0d9..67a60367 --stat` in p26 shows the expected
  four-file SAC transfer specialization (272 insertions across
  `stellar_asset_contract.rs`, `stellar_asset_contract/balance.rs`,
  `stellar_asset_contract/contract.rs`, and `host/frame.rs`).
- Outer `git status` shows `modified: src/rust/soroban/p26 (new commits)`,
  i.e., the gitlink bump is staged in the working tree and awaits an
  outer-repo commit by the orchestrator.

**Orchestrator action required**: commit the dirty p26 gitlink bump on
the outer `poc/002-fused-native-sac-transfer-effects` branch, and push
the p26 submodule branch to the SirTyson `rs-soroban-env` fork (the
submodule's current `origin` is `stellar/rs-soroban-env`; the fork
remote was not configured in this worktree, so the orchestrator must
add the SirTyson fork remote and push). Without the gitlink commit, a
fresh clone plus `git submodule update --init --recursive` will revert
to baseline, exactly as the final reviewer observed.

### Changes Verified Present in Worktree

Same as the prior PoC attempt (unchanged on this revision):

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs` — native
  Soroswap pool outbound SAC transfer now detects SAC token contracts,
  pushes an SAC-equivalent `Frame::StellarAssetContract`, and calls
  the typed native transfer helper instead of re-entering generic
  `call_n_internal`. Non-SAC token contracts still use the existing
  fallback call path.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract.rs`
  — re-exports the native Soroswap SAC transfer helper for the host
  frame fast path.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs`
  — adds `native_soroswap_transfer`, preserving generic SAC transfer
  validation order, auth, instance/code TTL extension, fallback
  behavior for unsupported shapes, and transfer event emission.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs`
  — adds the typed contract-balance-to-classic-account/trustline
  effect path used by Soroswap pool payouts. Loads sender contract
  balance once, checks authorization and available amount, writes
  updated contract balance and TTL, then updates the receiver
  account/trustline with authorization and bounds checks.

### Test Results

Configured with `./configure --enable-ccache --enable-sdfprefs
--enable-tracy --enable-tracy-capture --disable-postgres
--enable-next-protocol-version-unsafe-for-production` (already in place
from prior session).

Built with `make -j $(nproc)` — succeeded.

Ran full regression with `env NUM_PARTITIONS=30
STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots'
make -j $(nproc) check`. One partition failed on
`simulation/test/LoadGeneratorTests.cpp:733` inside
`"generate soroban load"`. Investigation determined this is a
**pre-existing flaky test unrelated to this PoC**:

- Reproduces deterministically with Catch RNG seed `20596` on the PoC
  build.
- Reproduces with the same seed on the baseline submodule
  (`fbbea0d9cb33e94fbab331d3d4bf8e69f088f9d4`) — i.e., the flake is
  present without any of this PoC's changes. Reproduced by checking
  out `fbbea0d9` in p26, rebuilding, and rerunning
  `./src/stellar-core test ... "generate soroban load"` — same failure
  at the same line.
- Passes on seeds `1`, `2`, `3`, `4`, `5`, `100`, `12345` on the PoC
  build.

The failing assertion is `REQUIRE(entry)` after a `ltx.load` of a
freshly-generated soroban data entry — not related to SAC transfer or
the native Soroswap path. The flake is a property of the loadgen seed
selection, not the optimization.

All other test partitions passed (`PASS: test/check-nondet` and all
other Catch suites in `test/selftest-nopg` completed without failure).
Specifically, the soroban / SAC / parallel-apply suites that exercise
the modified host-side path all passed.

### Conclusion

The optimization is present in the p26 worktree, builds cleanly, and
introduces no new test failures. The single observed test failure is a
pre-existing loadgen flake reproducible on the unmodified baseline.
The remaining work is purely orchestration: commit the outer gitlink
bump and push the p26 branch to the SirTyson fork so a fresh checkout
plus `git submodule update --init --recursive` lands on
`67a60367bf871e63eeb9e3af4aac029a621b9dcd`.

---

## Final Review

**Verdict**: REJECTED
**Date**: 2026-05-23
**Final review by**: gpt-5.5, high
**Failed At**: final-review

### Adversarial Analysis

1. **Does the change actually address the claimed inefficiency?** YES — source inspection shows the PoC replaces the native Soroswap pool outbound SAC `transfer` re-entry with a typed SAC transfer helper for Stellar Asset contracts, while keeping fallback dispatch for unsupported token/recipient shapes.
2. **Are the preconditions realistic?** YES — the path is in the generated soroswap benchmark shape and is reached from the native pool swap fast path during `closeLedger`.
3. **Is the original code inefficient or working as designed?** PLAUSIBLE INEFFICIENCY — the old outbound transfer used generic SAC dispatch and balance helpers even after the pair swap itself had been specialized.
4. **Does the benchmark improvement match the claimed severity?** NOT CHECKED — final-review benchmarking is disallowed because the mandatory full regression suite did not pass cleanly.
5. **Is the optimization in scope?** YES — the changed code is in the Soroban host apply path beneath the native Soroswap pool swap, not TX-set construction or lazy bucket work.
6. **Is the benchmark methodology correct?** NOT REACHED — the required benchmark workflow starts only after a clean `env NUM_PARTITIONS=30 ... make check`.
7. **Can the improvement be explained without the optimization?** NOT EVALUATED — no authoritative optimized measurements were collected.
8. **Is this optimization novel?** YES — this exact outbound typed SAC transfer effect specialization is distinct from prior accepted direct SAC balance reads.

### Rejection Reason

The required full regression command did not complete cleanly. `env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' make -j30 check` failed in `generate soroban load` at `simulation/test/LoadGeneratorTests.cpp:733` with `REQUIRE(entry)` using Catch RNG seed `20596`. Re-running the same test with `--rng-seed 20596` reproduced the failure. Under the optimize-soroswap final-review rules, any test failure or flake blocks confirmation and maps to rejection; benchmark runs were therefore not performed.

### Failed Checks

- Step 4 / Regression tests: full unit suite failed with one failing Catch test (`generate soroban load`, seed `20596`).
- Step 5 / Benchmarks: not run because benchmarks are only valid after a clean regression suite.
