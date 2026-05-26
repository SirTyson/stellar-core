# H002: Apply-Mode Direct Rent and Ledger-Effect Output

**Date**: 2026-05-26
**Subsystem**: transaction-ledger / Soroban Rust-C++ apply bridge
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by fusing apply-mode ledger-change production, rent-change extraction, and modified-entry bridge output into one pass
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

In apply mode, the Rust host should return exactly the data the C++ apply path consumes: encoded modified ledger entries, TTL entries for actual TTL extensions, rent-change records sufficient for fee computation, encoded events, resource counters, and the result value. It should preserve all p26/next-protocol budget accounting and C++ footprint validation semantics, but it should not allocate intermediate `LedgerEntryChange` records for each relevant entry and then immediately re-iterate them in `extract_rent_changes` and `extract_ledger_effects`.

## Mechanism

The accepted sparse no-meta path already proves apply mode can diverge from recording/simulation output shape while preserving metering: `get_ledger_changes` takes `apply_mode`, omits `encoded_key`, reuses a scratch key buffer, and drops no-op read-only changes (`src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:224-356,568-586` at p26 `7aef8604`). However successful invocations still build `LedgerEntryChange` objects for every modified or rent-relevant entry, return `Vec<LedgerEntryChange>`, then `src/rust/src/soroban_proto_any.rs:481-487` runs `extract_rent_changes(&res.ledger_changes)` and `extract_ledger_effects(res.ledger_changes)` as separate passes before C++ deserializes the resulting modified entries in `InvokeHostFunctionOpFrame::recordStorageChanges`. An apply-only output builder could perform the same metered key/old/new serialization inside `get_ledger_changes` but append rent-change records and encoded modified/TTL entries directly to the bridge output vectors, eliminating the intermediate change allocation, option fields, vector growth, and two filter/map passes.

## Trigger

Run the current soroswap apply-load benchmark. Every successful Soroban transaction enters `invoke_host_function_for_apply`, calls `get_ledger_changes(..., apply_mode=true)`, then converts the returned changes into rent and modified-entry vectors before C++ applies them. The trigger is any successful swap that modifies SAC balances, pair reserves, or TTLs and therefore survives the sparse no-meta filter.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:224-356` — `get_ledger_changes` still materializes `LedgerEntryChange` objects after computing all fields needed for rent/effects.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:568-586` — apply-mode invocation path that currently returns `ledger_changes` to the bridge layer.
- `src/rust/src/soroban_proto_any.rs:261-301` — `extract_ledger_effects` re-walks changes to build encoded modified ledger entries and TTL entries.
- `src/rust/src/soroban_proto_any.rs:481-487` — success path computes rent changes and bridge effects as two passes over the same vector.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:640-766` — C++ consumer of encoded modified entries; validation/application semantics must remain unchanged.

## Evidence

The current trace shows the full apply bridge remains material: `invokeHostFunction` contributes 10.980s contained worker time under `applyLedger`, `write xdr` contributes 173ms self-time over 232,097 in-window events, `read xdr with budget` contributes 206ms, and C++ `recordStorageChanges` contributes 115ms over 8,013 calls. The sparse no-meta success removed read-only output while explicitly preserving metered serialization, leaving a narrower but still repeated shape-conversion path for modified/rent entries. Because the proposed direct output is one apply-mode-only builder, it can keep all metered XDR writes and rent-size computations intact while removing non-metered intermediate allocation and iteration that recording mode still needs.

## Anti-Evidence

This cannot skip metered `ValSer`/`ValDeser`, event XDR, TTL hash derivation, rent sizing, or C++ `recordStorageChanges` validation; those are consensus- or fee-visible. Prior direct-bridge hypotheses failed when they counted mandatory metered serialization as removable. This hypothesis is viable only if narrow profiling of the current sparse baseline shows the residual non-metered `LedgerEntryChange` construction plus `extract_rent_changes`/`extract_ledger_effects` passes account for at least ~6ms per soroswap ledger; otherwise it should be rejected as another sub-threshold bridge-shape cleanup.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/transaction-ledger/summary.md` entry `001-apply-direct-ledger-effects.md`
**Failed At**: reviewer

### Trace Summary

The successful Soroban apply path still crosses from C++ into Rust through `InvokeHostFunctionApplyHelper::invokeHostFunction`, finishes the host, calls `get_ledger_changes`, computes rent from `extract_rent_changes`, converts effects through `extract_ledger_effects`, and sends encoded modified entries back to C++ `recordStorageChanges`. That is the same direct Rust-to-C++ ledger-effect output fusion previously recorded as `001-apply-direct-ledger-effects.md` in the transaction-ledger fail summary. Source tracing confirms the proposed direct builder can only remove intermediate `LedgerEntryChange` shape allocation/iteration; it cannot remove the metered XDR, TTL hash/rent-size computation, restored-key handling, event serialization, or C++ footprint/resource validation that dominate the cited path.

### Code Paths Examined

- `ai-summary/fail/transaction-ledger/summary.md:200` — prior failed entry `001-apply-direct-ledger-effects.md` covers fusing `get_ledger_changes` Rust-to-C++ apply bridge output directly and rejects it as below the Medium threshold after mandatory metered work is preserved.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:107-127` — `LedgerEntryChange` is the intermediate shape containing read-only status, encoded key, optional encoded new value, rent sizes, and optional TTL change.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:224-356` — `get_ledger_changes` walks storage, computes key hashes, old/new rent sizes, TTL changes, restored-entry adjustments, and metered new-entry XDR before pushing `LedgerEntryChange` records.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:393-430` — `extract_rent_changes` filters the intermediate records to build rent inputs, skipping no-op TTL/size changes.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:569-585` — successful enforcing invoke returns `ledger_changes` plus encoded contract events after `host.try_finish`.
- `src/rust/src/soroban_proto_any.rs:261-301` — `extract_ledger_effects` consumes `Vec<LedgerEntryChange>`, forwards encoded modified entries, and synthesizes TTL `LedgerEntry` buffers for live-until extensions.
- `src/rust/src/soroban_proto_any.rs:478-506` — bridge success path computes rent changes and modified ledger entries as separate passes before constructing `InvokeHostFunctionOutput`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:640-766` — C++ must deserialize each returned entry, validate limits and footprint coverage, charge write resources, upsert/delete entries, and enforce new Soroban-entry/TTL pairing.

### Why It Failed

This is not novel: the fail summary already contains the same optimization target and conclusion under `001-apply-direct-ledger-effects.md`. The traced code also matches that conclusion. A correct direct-output path would still need to perform the consensus- and fee-visible work named in the hypothesis anti-evidence: metered key/new-entry serialization, TTL hash derivation, old/new rent-size computation, restored-entry handling, rent-fee input construction, event/result serialization, and C++ resource/footprint validation. The only clearly removable work is the non-metered intermediate `LedgerEntryChange` object/vector shape plus the two filter/map passes, which the prior review determined is below this objective's 3% Medium floor.

### Lesson Learned

For apply-bridge output hypotheses, first check whether the proposed win is the same `get_ledger_changes` direct-effect fusion already rejected in the fail summary. Only a new profile that isolates a different, multi-millisecond non-metered component outside mandatory XDR, rent, TTL, and C++ validation work would justify reopening this area.
