# H001: Protocol-gated fused SAC transfer fast lane for soroswap token legs

**Date**: 2026-05-20
**Subsystem**: transaction-ledger / Soroban SAC apply path
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by replacing several repeated generic SAC transfer sub-pipelines with one typed, transfer-local execution path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For the built-in Stellar Asset Contract `transfer` entry point, the host should preserve the exact external contract-call semantics: push a SAC frame, validate typed arguments, require source authorization, update source/destination balances, extend required TTLs, emit the same transfer event, and return the same errors. On a next-protocol path, it should be possible to execute this known built-in function as one typed transfer pipeline rather than repeatedly crossing generic `Val`/`ScVal`, storage, authorization, TTL, and event helper boundaries that were designed for arbitrary contract calls.

## Mechanism

The current SAC `transfer` path enters the generic built-in dispatcher, converts arguments through the generated contracttype layer, then calls separate helpers for authorization, current-contract TTL extension, balance spend/receive, and event construction. Prior investigations rejected individual micro-optimizations in these subpaths because each isolated slice was below threshold or added overhead, but the source still shows that soroswap pays all of them together for every token leg. A protocol-gated `SAC transfer` fast lane that decodes the three transfer arguments once, carries a stack-local transfer context through auth/balance/event/TTL work, and emits the same XDR result should remove repeated helper entry, repeated key/value conversion, and repeated metadata lookups without caching cross-frame state or changing deterministic ordering.

## Trigger

Run the current soroswap apply-load Tracy benchmark from `ai-summary/CURRENT_STATE.md`:
`/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`.
Every swap invokes SAC token transfers from the router/pair path, hitting `Frame::StellarAssetContract` and `StellarAssetContract::transfer` inside `applyLedger`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:757-783` — generic `call_contract_fn` dispatches `ContractExecutable::StellarAsset` through a normal frame and the generic built-in call interface.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-224` — `transfer` sequences amount validation, `require_auth`, instance/code TTL extension, source balance spend, destination balance receive, and event creation as separate helper calls.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs` — balance helpers already have typed storage fast paths from the accepted baseline, but the transfer body still enters them separately for source and destination.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs` — transfer event construction remains a separate generic host-object/XDR path.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:835` — `require auth` is called separately from balance and event processing.

## Evidence

- Current trace self-time inside the apply window includes `SAC transfer,soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:212` at **558,183,960 ns self-time** over **13,527** calls; timestamp filtering shows **13,527** SAC transfer events totaling **2,153,411,257 ns** inside `applyLedger`.
- The same apply-window trace still reports SAC-adjacent work after accepted prior optimizations: `storage get` **215,980,007 ns self-time**, `storage put` **79,591,389 ns self-time**, `contract_event` **55,969,657 ns self-time**, `require auth` **35,067,000 ns self-time**, `SAC balance` **35,118,615 ns self-time**, and current-contract TTL extension events totaling **960,691,858 ns** inclusive.
- This hypothesis is intentionally not a repeat of the failed single-slice SAC ideas (`skip SAC code TTL lookup`, `build SAC events as XDR`, `SAC balance slot context`, or `specialize external SAC dispatch`). It targets a single protocol-gated transfer-local pipeline that removes the boundary overhead between those sub-helpers together, while avoiding persistent decoded caches that previously changed metering or regressed.

## Anti-Evidence

- The prior `002-sac-transfer-balance-slot-context` PoC regressed, so a viable version must avoid adding heap-allocated context objects or extra indirection. The context should be stack-local and should replace existing helper boundaries rather than wrap them.
- The fast lane must preserve authorization semantics, diagnostic events, transfer event XDR, budget accounting expectations, and frame rollback behavior. Any budget decrease from eliminated work must be protocol-gated and covered by observation/budget updates rather than silently changing p26 behavior.
- Inclusive `SAC transfer` time is not wholly removable; the PoC must add narrower counters around argument decode, metadata lookup, TTL, event, and balance substeps to prove that the fused path clears the 3% Medium threshold on top-line soroswap apply time.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-20
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — related SAC slices were previously investigated, but this exact fused-transfer bundle was not recorded as an individual fail/success
**Failed At**: reviewer

### Trace Summary

I traced the accepted soroswap baseline recorded in `ai-summary/CURRENT_STATE.md` (`p26` commit `fa1226b3068605c5376efe56c6cf809ca225a036`), because the checked-out submodule is upstream v26 while the benchmark baseline includes the accepted p26 optimization stack. The close-ledger path reaches `InvokeHostFunctionOpFrame::doParallelApply`, crosses into `e2e_invoke::invoke_host_function`, invokes the router/pair Wasm, then dispatches SAC calls through `call_n_internal` and `call_contract_fn`. The SAC `transfer` body is hot, but a correctness-preserving fast lane still has to push a SAC frame, preserve frame arguments for authorization, run the same auth matcher, perform the current-contract TTL extension, execute typed balance storage operations, classify issuer/non-issuer events, read event metadata, and record the same event payload. The remaining removable pieces are only dispatcher/helper glue and narrow residual conversions already covered by prior accepted or failed investigations, not enough for the objective's Medium threshold.

### Code Paths Examined

- `ai-summary/CURRENT_STATE.md:1-27,41-64,71-84` — establishes the accepted current baseline, p26 commit `fa1226b3`, 272.9 ms average soroswap median, and prior accepted typed SAC balance / host metering optimizations.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-585,1358-1377` — v23+ Soroban apply runs through the parallel helper and Rust bridge inside `closeLedger`.
- `src/rust/src/soroban_invoke.rs:7-38` and `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-481` — Rust bridge builds the enforcing host, installs auth/storage/ledger state, and invokes the host function.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs@fa1226b3:923-1121,749-785` — `call_n_internal` performs required call checks/diagnostics, then `call_contract_fn` loads the contract instance, copies frame args, pushes `Frame::StellarAssetContract`, and dispatches `StellarAssetContract.call`.
- `src/rust/soroban/p26/soroban-builtin-sdk-macros/src/derive_fn.rs:29-64` — generated built-in dispatch converts each transfer argument once before calling the typed Rust method; there is no repeated decode loop within `transfer` itself.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs@fa1226b3:206-225` — `transfer` sequences amount check, muxed destination extraction, source auth, current-contract TTL extension, source/destination balance updates, and transfer/mint/burn event selection.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs@fa1226b3:33-178,191-427` — accepted baseline already has typed SAC balance key/value helpers and direct storage access; remaining balance reads/writes are real storage/TTL/accounting work plus a previously rejected transfer-local context opportunity.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs@fa1226b3:3629-3656` and `src/rust/soroban/p26/soroban-env-host/src/auth.rs@fa1226b3:829-850,572-586` — `require_auth` clones the current frame args and constructs an `AuthorizedFunction` from the actual call frame, which is required for matching signed auth trees.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs@fa1226b3:2350-2358` — current-contract instance/code TTL extension must still derive the current contract id and extend instance/code TTLs; the previously proposed SAC code-TTL shortcut was below threshold.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs@fa1226b3:47-112`, `metadata.rs:192-198`, `asset_info.rs:20-24` — transfer event emission still has issuer classification and metadata reads, but these are the same categories rejected by the SAC event and metadata hypotheses.
- `ai-summary/fail/transaction-ledger/summary.md:51-56,63,69,86,95` — prior records reject external SAC dispatch specialization, direct SAC event XDR building, metadata carrying, SAC code TTL skipping, balance TTL fusion, balance-slot context, and optional-contract-data read variants as sub-threshold, duplicate, or regressive.

### Why It Failed

The inefficiency is real at the level of broad inclusive SAC transfer work, but the proposed fused lane does not identify a remaining Medium-sized removable operation. The accepted baseline already removed the large generic balance `Val`/`ScVal` round trips with typed SAC balance storage, so the balance portions left in `fa1226b3` are actual storage reads/writes, TTL checks, and ledger-entry updates. The frame and auth pieces are load-bearing: `Frame::StellarAssetContract` and its `args_vec` are needed for rollback, diagnostics, and `require_auth`'s `AuthorizedFunction` construction. The event path must still classify issuer cases, read metadata, and record equivalent event data; prior review of direct event-XDR construction found the local event-only slice below Medium.

Bundling the remaining rejected slices does not make the hypothesis viable. The prior transfer-local balance-slot PoC already tested the closest "carry context through SAC transfer" idea and regressed soroswap, while the other proposed components are individually documented as below threshold after cluster normalization or as mandatory protocol-visible work. A stack-local context might avoid that PoC's allocation overhead, but the surviving savings would still come from the same narrow residual auth/balance/event/TTL substeps and lacks a credible path to the objective's 3-10% apply-time floor.

### Lesson Learned

For the current soroswap baseline, inclusive `SAC transfer` timing should not be treated as removable fast-lane overhead. Future SAC hypotheses need a new, narrowly measured operation that remains after the typed balance and host-metering successes; simply fusing helper boundaries around auth, TTL, balance, and event code re-aggregates prior sub-threshold or regressive ideas.
